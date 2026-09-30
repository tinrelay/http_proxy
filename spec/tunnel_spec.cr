require "./spec_helper"
require "http/client"
require "../src/http_proxy"

ROOT = File.join(__DIR__, "support", "tunnel")

def client_context
  context = OpenSSL::SSL::Context::Client.new
  context.ca_certificates = "#{ROOT}/fixture.crt"
  context
end

def server_context
  context = OpenSSL::SSL::Context::Server.new
  context.certificate_chain = "#{ROOT}/fixture.crt"
  context.private_key = "#{ROOT}/fixture.key"
  context
end

def with_proxy(&block : HTTP::Proxy::Client, Channel(HTTP::Request), Channel(HTTP::Request) ->)
  listener = TCPServer.new("127.0.0.1", 0)
  connects = Channel(HTTP::Request).new(1)
  requests = Channel(HTTP::Request).new(1)
  done = Channel(Nil).new(1)
  spawn do
    socket = listener.accept
    socket.read_timeout = 1.second
    socket.write_timeout = 1.second
    begin
      connects.send(HTTP::Request.from_io(socket).as(HTTP::Request))
      socket << "HTTP/1.1 200 Connection established\r\n\r\n"
      socket.flush
      tls = OpenSSL::SSL::Socket::Server.new(socket, server_context, sync_close: true)
      requests.send(HTTP::Request.from_io(tls).as(HTTP::Request))
      tls << "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
      tls.flush
    rescue OpenSSL::Error | IO::Error
      # Certificate-rejection cases intentionally stop before an origin request.
    ensure
      socket.close
      done.send(nil)
    end
  end
  proxy = HTTP::Proxy::Client.new("127.0.0.1", listener.local_address.port,
    username: "fixture-user", password: "fixture-secret")
  yield proxy, connects, requests
ensure
  listener.try(&.close)
  if done
    select
    when done.receive
    when timeout(2.seconds)
      raise "fixture did not finish"
    end
  end
end

def open(proxy, host = "relay.invalid", context = client_context, read_timeout = 1.second)
  proxy.open(host, 443, context, dns_timeout: 1.second, connect_timeout: 1.second,
    read_timeout: read_timeout, write_timeout: 1.second)
end

describe "http_proxy low-level transport qualification" do
  it "tunnels without resolving the origin locally and keeps credentials out of its request" do
    WebMock.allow_net_connect = true
    with_proxy do |proxy, connects, requests|
      io = open(proxy)
      client = HTTP::Client.new(io, "relay.invalid", 443)
      client.get("/healthz?probe=1") do |response|
        response.body_io.gets_to_end.should eq("OK")
      end
      connect = connects.receive
      connect.method.should eq("CONNECT")
      connect.resource.should eq("relay.invalid:443")
      connect.headers["Proxy-Authorization"].should eq(
        "Basic #{Base64.strict_encode("fixture-user:fixture-secret")}")
      request = requests.receive
      request.resource.should eq("/healthz?probe=1")
      request.headers["Proxy-Authorization"]?.should be_nil
    ensure
      client.try(&.close)
    end
  ensure
    WebMock.allow_net_connect = false
  end

  it "rejects an otherwise trusted certificate with the wrong origin hostname" do
    with_proxy do |proxy, _connects, _requests|
      error = expect_raises(HTTP::Proxy::Error) { open(proxy, "wrong.invalid") }
      error.phase.should eq(:tls)
      error.retryable?.should be_false
    end
  end

  it "rejects an untrusted certificate with the correct origin hostname" do
    with_proxy do |proxy, _connects, _requests|
      error = expect_raises(HTTP::Proxy::Error) do
        open(proxy, context: OpenSSL::SSL::Context::Client.new)
      end
      error.phase.should eq(:tls)
      error.retryable?.should be_false
    end
  end

  it "refuses CONNECT without dialing a reachable origin directly" do
    origin = TCPServer.new("127.0.0.1", 0)
    listener = TCPServer.new("127.0.0.1", 0)
    spawn do
      socket = listener.accept
      HTTP::Request.from_io(socket)
      socket << "HTTP/1.1 407 Proxy authentication required\r\nContent-Length: 0\r\n\r\n"
      socket.flush
      socket.close
    end
    direct = Channel(Nil).new(1)
    spawn do
      socket = origin.accept?
      if socket
        direct.send(nil)
        socket.close
      end
    end
    proxy = HTTP::Proxy::Client.new("127.0.0.1", listener.local_address.port)
    expect_raises(IO::Error) do
      proxy.open("127.0.0.1", origin.local_address.port, client_context,
        dns_timeout: 1.second, connect_timeout: 1.second,
        read_timeout: 1.second, write_timeout: 1.second)
    end
    select
    when direct.receive
      fail "proxy refusal fell back to the direct origin"
    when timeout(100.milliseconds)
    end
  ensure
    origin.try(&.close)
    listener.try(&.close)
  end

  it "bounds a stalled CONNECT with the supplied read timeout" do
    listener = TCPServer.new("127.0.0.1", 0)
    done = Channel(Nil).new(1)
    spawn do
      socket = listener.accept
      HTTP::Request.from_io(socket)
      sleep 300.milliseconds
      socket.close
      done.send(nil)
    end
    proxy = HTTP::Proxy::Client.new("127.0.0.1", listener.local_address.port)
    started = Time.instant
    error = expect_raises(HTTP::Proxy::Error) { open(proxy, read_timeout: 100.milliseconds) }
    error.phase.should eq(:connect)
    error.reason.should eq(:timeout)
    error.retryable?.should be_true
    (Time.instant - started).should be < 250.milliseconds
    done.receive
  ensure
    listener.try(&.close)
  end

  it "bounds the whole CONNECT handshake even when response bytes keep arriving" do
    listener = TCPServer.new("127.0.0.1", 0)
    done = Channel(Nil).new(1)
    spawn do
      socket = listener.accept
      HTTP::Request.from_io(socket)
      begin
        "HTTP/1.1 200 OK\r\n\r\n".each_char do |char|
          socket << char
          socket.flush
          sleep 20.milliseconds
        end
      rescue IO::Error
      ensure
        socket.close
        done.send(nil)
      end
    end
    proxy = HTTP::Proxy::Client.new("127.0.0.1", listener.local_address.port)
    started = Time.instant
    error = expect_raises(HTTP::Proxy::Error) do
      proxy.open("relay.invalid", 443, client_context,
        dns_timeout: 1.second, connect_timeout: 1.second,
        read_timeout: 1.second, write_timeout: 1.second,
        handshake_timeout: 100.milliseconds)
    end
    error.reason.should eq(:timeout)
    (Time.instant - started).should be < 300.milliseconds
    done.receive
  ensure
    listener.try(&.close)
  end

  it "closes the unreturned socket after a malformed CONNECT response" do
    listener = TCPServer.new("127.0.0.1", 0)
    closed = Channel(Bool).new(1)
    spawn do
      socket = listener.accept
      HTTP::Request.from_io(socket)
      socket << "not an HTTP response\r\n\r\n"
      socket.flush
      socket.read_timeout = 200.milliseconds
      begin
        closed.send(socket.read_byte.nil?)
      rescue IO::TimeoutError
        closed.send(false)
      ensure
        socket.close
      end
    end
    proxy = HTTP::Proxy::Client.new("127.0.0.1", listener.local_address.port)
    expect_raises(Exception) { open(proxy) }
    closed.receive.should be_true
  ensure
    listener.try(&.close)
  end
end
