require "http/client"
require "openssl"
require "socket"
require "uri"

module Authz0
  module Scan
    # The outcome of a single HTTP probe. `error` is set (and status_code 0)
    # when the request never produced a response — DNS failure, connection
    # refused, timeout, etc.
    struct HttpResponse
      getter status_code : Int32
      getter body : String
      getter size : Int64
      getter error : String?

      def initialize(@status_code : Int32, @body : String, @size : Int64, @error : String? = nil)
      end

      def self.errored(message : String) : HttpResponse
        new(0, "", 0_i64, message)
      end

      def ok? : Bool
        @error.nil?
      end
    end

    # Issues one HTTP request per call (no keep-alive — each probe is
    # independent and may run on its own fiber). Supports TLS verification
    # skip and an upstream HTTP proxy (CONNECT tunneling for https targets,
    # absolute-form requests for http targets) so traffic can be routed
    # through Burp/ZAP.
    class HttpClient
      DEFAULT_USER_AGENT = "authz0/#{Authz0::VERSION}"

      def initialize(@timeout : Int32 = 10, @proxy : String? = nil, @insecure : Bool = true)
      end

      def request(method : String, url : String, headers : HTTP::Headers, body : String?) : HttpResponse
        uri = URI.parse(url)
        unless uri.scheme == "http" || uri.scheme == "https"
          return HttpResponse.errored("unsupported scheme: #{uri.scheme}")
        end
        apply_defaults(headers, uri)

        proxy = @proxy
        if proxy && !proxy.empty?
          proxied_request(method, uri, headers, body, proxy)
        else
          direct_request(method, uri, headers, body)
        end
      rescue ex : IO::TimeoutError
        HttpResponse.errored("timeout after #{@timeout}s")
      rescue ex : Socket::Addrinfo::Error
        HttpResponse.errored("dns/resolve error: #{ex.message}")
      rescue ex : Socket::ConnectError
        HttpResponse.errored("connection failed: #{ex.message}")
      rescue ex : OpenSSL::SSL::Error
        HttpResponse.errored("tls error: #{ex.message}")
      rescue ex : URI::Error
        HttpResponse.errored("malformed url: #{ex.message}")
      rescue ex
        HttpResponse.errored(ex.message || ex.class.name)
      end

      # --- direct (no proxy) --------------------------------------------

      private def direct_request(method, uri, headers, body) : HttpResponse
        client = HTTP::Client.new(uri, tls: tls_for(uri))
        begin
          client.connect_timeout = @timeout.seconds
          client.read_timeout = @timeout.seconds
          client.write_timeout = @timeout.seconds
          # We manage encoding ourselves (Accept-Encoding: identity below),
          # so disable the client's transparent gzip handling to keep the
          # body bytes == on-the-wire bytes for fail-size assertions.
          client.compress = false
          target = uri.request_target
          target = "/" if target.empty?
          response = client.exec(method, target, headers: headers, body: body)
          to_response(response)
        ensure
          client.close
        end
      end

      # --- proxied -------------------------------------------------------

      private def proxied_request(method, uri, headers, body, proxy_url) : HttpResponse
        proxy = URI.parse(proxy_url)
        unless proxy.host
          return HttpResponse.errored("invalid proxy url: #{proxy_url}")
        end
        proxy_port = proxy.port || (proxy.scheme == "https" ? 443 : 8080)
        socket = TCPSocket.new(proxy.host.not_nil!, proxy_port, connect_timeout: @timeout.seconds)
        socket.read_timeout = @timeout.seconds
        socket.write_timeout = @timeout.seconds

        io : IO = socket
        host = uri.host.not_nil!
        port = uri.port || (uri.scheme == "https" ? 443 : 80)

        if uri.scheme == "https"
          # Establish a CONNECT tunnel, then start TLS over the raw socket.
          socket << "CONNECT #{host}:#{port} HTTP/1.1\r\n"
          socket << "Host: #{host}:#{port}\r\n"
          socket << "\r\n"
          socket.flush
          tunnel = HTTP::Client::Response.from_io(socket, ignore_body: true)
          unless tunnel.status_code == 200
            socket.close
            return HttpResponse.errored("proxy CONNECT failed: #{tunnel.status_code}")
          end
          ssl = OpenSSL::SSL::Socket::Client.new(socket, context: insecure_context, sync_close: true, hostname: host)
          io = ssl
          resource = uri.request_target
          resource = "/" if resource.empty?
          write_request(io, method, resource, headers, body)
          to_response(HTTP::Client::Response.from_io(io))
        else
          # Plain HTTP through a proxy uses absolute-form request targets.
          absolute = uri.to_s
          write_request(socket, method, absolute, headers, body)
          to_response(HTTP::Client::Response.from_io(socket))
        end
      ensure
        socket.close if socket && !socket.closed?
      end

      # Serialize an HTTP/1.1 request onto an IO. Content-Length is set from
      # the body so the server knows when the request ends.
      private def write_request(io : IO, method : String, resource : String, headers : HTTP::Headers, body : String?)
        io << method << " " << resource << " HTTP/1.1\r\n"
        has_connection = false
        has_content_length = false
        headers.each do |name, values|
          lower = name.downcase
          has_connection = true if lower == "connection"
          has_content_length = true if lower == "content-length"
          values.each { |v| io << name << ": " << v << "\r\n" }
        end
        # Only add our own framing/Connection headers when the caller didn't
        # already supply them, so a user-provided "--header" can't produce a
        # duplicate (which violates RFC 7230 §3.3.2 and confuses some proxies).
        io << "Connection: close\r\n" unless has_connection
        if body && !body.empty? && !has_content_length
          io << "Content-Length: " << body.bytesize << "\r\n"
        end
        io << "\r\n"
        io << body if body && !body.empty?
        io.flush
      end

      # --- helpers -------------------------------------------------------

      private def to_response(response : HTTP::Client::Response) : HttpResponse
        body = response.body? || ""
        HttpResponse.new(response.status_code, body, body.bytesize.to_i64)
      end

      private def apply_defaults(headers : HTTP::Headers, uri : URI)
        headers["Host"] = host_header(uri) unless headers.has_key?("Host")
        headers["User-Agent"] = DEFAULT_USER_AGENT unless headers.has_key?("User-Agent")
        # Ask for an un-encoded body so size/regex assertions see real bytes.
        headers["Accept-Encoding"] = "identity" unless headers.has_key?("Accept-Encoding")
        headers["Accept"] = "*/*" unless headers.has_key?("Accept")
      end

      private def host_header(uri : URI) : String
        host = uri.host || ""
        port = uri.port
        default = uri.scheme == "https" ? 443 : 80
        port && port != default ? "#{host}:#{port}" : host
      end

      private def tls_for(uri : URI) : HTTP::Client::TLSContext
        return false unless uri.scheme == "https"
        @insecure ? insecure_context : true
      end

      private def insecure_context : OpenSSL::SSL::Context::Client
        ctx = OpenSSL::SSL::Context::Client.new
        ctx.verify_mode = OpenSSL::SSL::VerifyMode::NONE
        ctx
      end
    end
  end
end
