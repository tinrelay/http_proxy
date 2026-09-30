require "http"
require "../../ext/http/client"
require "socket"
require "base64"

{% if !flag?(:without_openssl) %}
  require "openssl"
{% end %}

module HTTP
  # :nodoc:
  module Proxy
    # Safe connection evidence: never includes proxy credentials, endpoints, or
    # the proxy's arbitrary response text.
    class Error < IO::Error
      getter phase : Symbol
      getter reason : Symbol
      getter status_code : Int32?

      def initialize(@phase, @reason, @status_code = nil)
        super("HTTP proxy #{@phase} #{@reason}")
      end

      def retryable? : Bool
        reason.in?({:timeout, :transport}) ||
          (reason == :rejected && status_code.in?({502, 503, 504}))
      end
    end

    # Represents a proxy client with all its attributes.
    # Provides convenient access and modification of them.
    class Client
      getter host : String
      getter port : Int32
      property username : String?
      property password : String?
      property headers : HTTP::Headers

      {% if flag?(:without_openssl) %}
        getter tls : Nil = nil
      {% else %}
        getter tls : OpenSSL::SSL::Context::Client?
      {% end %}

      # Creates a new socket factory that tunnels via the given host and port.
      # The following optional arguments are supported:
      #
      # * `:headers` - additional headers, which will be used for tls
      # * `:username` - the user name to use when authenticating to the proxy
      # * `:password` - the password to use when authenticating
      # * `:user_agent` - the User-Agent request header
      def initialize(
        @host,
        @port,
        *,
        headers : HTTP::Headers? = nil,
        @username = nil, @password = nil,
        user_agent = "Crystal, HTTP::Proxy/#{HTTP::Proxy::VERSION}",
      )
        @headers = headers || HTTP::Headers.new
        @headers["User-Agent"] ||= user_agent
      end

      # Returns a new socket connected to the given host and port via the
      # proxy that was requested when the socket factory was instantiated.
      def open(host, port, tls = nil, *, dns_timeout, connect_timeout,
               read_timeout, write_timeout, handshake_timeout : Time::Span? = nil) : IO
        phase = :tcp
        expired = false
        complete = false
        cancel = nil.as(Channel(Nil)?)
        socket = TCPSocket.new(@host, @port, dns_timeout, connect_timeout)
        socket.read_timeout = read_timeout if read_timeout
        socket.write_timeout = write_timeout if write_timeout
        socket.sync = false

        if tls
          phase = :connect
          if budget = handshake_timeout
            cancellation = Channel(Nil).new(1)
            cancel = cancellation
            tcp = socket
            spawn do
              select
              when cancellation.receive
              when timeout(budget)
                expired = true
                tcp.close
              end
            end
          end
          socket << "CONNECT #{host}:#{port} HTTP/1.1\r\n"

          @headers.each do |name, values|
            values.each do |value|
              socket << "#{name}: #{value}\r\n"
            end
          end

          socket << "Host: #{host}:#{port}\r\n"

          if username = @username
            if password = @password
              credentials = Base64.strict_encode("#{username}:#{password}")
              socket << "Proxy-Authorization: Basic #{credentials}\r\n"
            end
          end

          socket << "\r\n"
          socket.flush

          resp = HTTP::Client::Response.from_io?(socket, ignore_body: true) ||
                 raise Error.new(:connect, :transport)

          if resp.success?
            {% if !flag?(:without_openssl) %}
              if tls
                phase = :tls
                hostname = host.rchop('.')
                if hostname.starts_with?('[') && hostname.ends_with?(']')
                  hostname = hostname[1..-2]
                end
                socket = OpenSSL::SSL::Socket::Client.new(socket,
                  context: tls, sync_close: true, hostname: hostname)
              end
            {% end %}
          else
            socket.close

            raise Error.new(:connect, :rejected, resp.status_code)
          end
        end

        raise Error.new(phase, :timeout) if expired
        complete = true
        socket
      rescue error : Error
        raise error
      rescue error
        reason = case error
                 when IO::TimeoutError then :timeout
                 when Socket::Error    then :transport
                 when IO::Error
                   error.os_error ? :transport : :invalid_response
                 else
                   {% if !flag?(:without_openssl) %}
                     error.is_a?(OpenSSL::Error) ? :tls_failure : :invalid_response
                   {% else %}
                     :invalid_response
                   {% end %}
                 end
        raise Error.new(phase || :tcp, expired ? :timeout : reason)
      ensure
        cancel.try(&.send(nil))
        socket.try(&.close) unless complete
      end
    end
  end
end
