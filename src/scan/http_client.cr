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
      getter redirect_location : String?

      def initialize(@status_code : Int32, @body : String, @size : Int64,
                     @error : String? = nil, @redirect_location : String? = nil)
      end

      def self.errored(message : String) : HttpResponse
        new(0, "", 0_i64, message)
      end

      def ok? : Bool
        @error.nil?
      end

      # A followable redirect: a 3xx with a Location to chase.
      def redirect? : Bool
        {301, 302, 303, 307, 308}.includes?(@status_code) && !@redirect_location.nil?
      end
    end

    # Issues one HTTP request per call (no keep-alive — each probe is
    # independent and may run on its own fiber). Supports TLS verification
    # skip and an upstream HTTP proxy (CONNECT tunneling for https targets,
    # absolute-form requests for http targets) so traffic can be routed
    # through Burp/ZAP.
    class HttpClient
      DEFAULT_USER_AGENT = "authz0/#{Authz0::VERSION}"

      RETRY_BACKOFF_MS = 250

      def initialize(@timeout : Int32 = 10, @proxy : String? = nil, @insecure : Bool = true,
                     @follow_redirects : Int32 = 0, @retries : Int32 = 0, @user_agent : String? = nil)
      end

      # Issue the request, retrying transient failures (transport errors, 429,
      # 503) up to @retries times with linear backoff, then return the result.
      def request(method : String, url : String, headers : HTTP::Headers, body : String?) : HttpResponse
        attempt = 0
        loop do
          response = follow(method, url, headers, body)
          return response if attempt >= @retries || !retryable?(response)
          attempt += 1
          sleep((RETRY_BACKOFF_MS * attempt).milliseconds)
        end
      end

      # A failure worth retrying: a transport error, or a rate-limit/unavailable
      # status that commonly clears on a second attempt.
      private def retryable?(response : HttpResponse) : Bool
        return true unless response.ok?
        response.status_code == 429 || response.status_code == 503
      end

      # Issue the request, optionally chasing up to @follow_redirects hops. The
      # returned response is the final one in the chain (or the first error).
      private def follow(method : String, url : String, headers : HTTP::Headers, body : String?) : HttpResponse
        current_url = url
        current_method = method
        current_body = body
        hops = 0
        loop do
          response = perform(current_method, current_url, headers, current_body, hops)
          return response unless response.ok?
          return response unless @follow_redirects > 0 && response.redirect? && hops < @follow_redirects

          loc = response.redirect_location
          return response if loc.nil? || loc.empty?
          current_url = resolve_redirect(URI.parse(current_url), loc)

          # 303 → always GET; 301/302 downgrade a non-GET/HEAD method to GET
          # (matching browser behavior); 307/308 preserve method + body.
          status = response.status_code
          if status == 303 || ((status == 301 || status == 302) && current_method != "GET" && current_method != "HEAD")
            current_method = "GET"
            current_body = nil
          end
          hops += 1
        end
      end

      # One request, no redirect logic. All transport errors are caught here so
      # a failed hop terminates the chain as an errored response.
      private def perform(method : String, url : String, headers : HTTP::Headers, body : String?, hops : Int32) : HttpResponse
        uri = URI.parse(url)
        unless uri.scheme == "http" || uri.scheme == "https"
          return HttpResponse.errored("unsupported scheme: #{uri.scheme}")
        end
        # On a redirect hop, refresh Host to the new target; hop 0 keeps any
        # user-supplied Host.
        headers.delete("Host") if hops > 0
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

      # Resolve a Location header (absolute URL, absolute path, or relative)
      # against the request URI.
      private def resolve_redirect(base : URI, location : String) : String
        loc = location.strip
        return loc if loc.starts_with?("http://") || loc.starts_with?("https://")
        # Protocol-relative ("//host/path") inherits the current scheme.
        return "#{base.scheme}:#{loc}" if loc.starts_with?("//")
        origin = String.build do |s|
          s << base.scheme << "://" << base.host
          p = base.port
          s << ":" << p if p && p != (base.scheme == "https" ? 443 : 80)
        end
        return origin + loc if loc.starts_with?("/")
        dir = base.path
        idx = dir.rindex('/')
        dir = idx ? dir[0..idx] : "/"
        dir = "/" if dir.empty?
        origin + dir + loc
      rescue
        location
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
        HttpResponse.new(response.status_code, body, body.bytesize.to_i64,
          redirect_location: response.headers["Location"]?)
      end

      private def apply_defaults(headers : HTTP::Headers, uri : URI)
        headers["Host"] = host_header(uri) unless headers.has_key?("Host")
        headers["User-Agent"] = (@user_agent || DEFAULT_USER_AGENT) unless headers.has_key?("User-Agent")
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
