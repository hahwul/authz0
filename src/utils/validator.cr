require "./errors"

module Authz0
  # Input validation shared across commands. Each `*!` method raises a
  # ValidationError (with a hint where useful) and otherwise returns the
  # cleaned value, so call sites read as `name = Validator.session_name!(raw)`.
  module Validator
    extend self

    # Session names double as directory names, so they must be a single safe
    # path segment: no separators, no `.`/`..`, no leading dash, no shell
    # nasties. Kept deliberately strict — these become directories under
    # ~/.authz0/sessions/.
    SESSION_NAME_RE = /\A[A-Za-z0-9][A-Za-z0-9._-]*\z/
    UNSAFE_NAME_RE  = %r{[/\\ ]}

    def session_name!(raw : String) : String
      name = raw.strip
      if name.empty?
        raise ValidationError.new("session name is empty")
      end
      if name == "." || name == ".."
        raise ValidationError.new("invalid session name: #{name}")
      end
      if name.matches?(UNSAFE_NAME_RE)
        raise ValidationError.new("session name must not contain path separators or spaces: #{name}")
      end
      unless name.matches?(SESSION_NAME_RE)
        raise ValidationError.new(
          "invalid session name: #{name}",
          "use letters, digits, '.', '_', '-' (must start alphanumeric)"
        )
      end
      name
    end

    # A base URL must have an http(s) scheme and a host so paths can be
    # resolved against it.
    def base_url!(raw : String) : String
      url = raw.strip
      if url.empty?
        raise ValidationError.new("base URL is empty")
      end
      uri = parse_uri(url)
      unless uri.scheme == "http" || uri.scheme == "https"
        raise ValidationError.new(
          "base URL must start with http:// or https://: #{url}"
        )
      end
      if uri.host.nil? || uri.host.try(&.empty?)
        raise ValidationError.new("base URL has no host: #{url}")
      end
      url
    end

    # Validate an HTTP method, upcasing it. Unknown verbs are allowed (custom
    # methods exist) but must be a single bare token.
    KNOWN_METHODS = %w[GET POST PUT PATCH DELETE HEAD OPTIONS TRACE CONNECT]

    def http_method!(raw : String) : String
      m = raw.strip.upcase
      if m.empty?
        raise ValidationError.new("HTTP method is empty")
      end
      unless m.matches?(/\A[A-Z]+\z/)
        raise ValidationError.new("invalid HTTP method: #{raw}")
      end
      m
    end

    # Parse a "Key: Value" header string into a tuple. Tolerates extra spaces
    # around the colon and values that themselves contain colons.
    def header!(raw : String) : {String, String}
      idx = raw.index(':')
      unless idx
        raise ValidationError.new(
          "invalid header (expected 'Key: Value'): #{raw}"
        )
      end
      key = raw[0...idx].strip
      value = raw[(idx + 1)..].strip
      if key.empty?
        raise ValidationError.new("header name is empty: #{raw}")
      end
      {key, value}
    end

    # Parse a single "name=value" cookie pair.
    def cookie!(raw : String) : {String, String}
      idx = raw.index('=')
      unless idx
        raise ValidationError.new(
          "invalid cookie (expected 'name=value'): #{raw}"
        )
      end
      name = raw[0...idx].strip
      value = raw[(idx + 1)..].strip
      if name.empty?
        raise ValidationError.new("cookie name is empty: #{raw}")
      end
      {name, value}
    end

    # Split a comma-separated list into trimmed, non-empty, de-duplicated
    # items. Used for --allow-role / --deny-role / --tags.
    def csv(raw : String) : Array(String)
      raw.split(',').map(&.strip).reject(&.empty?).uniq!
    end

    # Validate a comma-separated status list like "200,201,204".
    def status_list!(raw : String) : Array(Int32)
      out = [] of Int32
      csv(raw).each do |part|
        code = part.to_i?
        unless code && (100..599).includes?(code)
          raise ValidationError.new("invalid HTTP status code: #{part}")
        end
        out << code
      end
      if out.empty?
        raise ValidationError.new("status list is empty: #{raw}")
      end
      out
    end

    # Like status_list! but also accepts status *classes* ("2xx", "4xx"), used
    # by assert rules. Returns the cleaned token list (lower-cased).
    STATUS_CLASS_RE = /\A[1-5]xx\z/

    def status_tokens!(raw : String) : Array(String)
      tokens = csv(raw).map(&.downcase)
      if tokens.empty?
        raise ValidationError.new("status list is empty: #{raw}")
      end
      tokens.each do |t|
        next if t.matches?(STATUS_CLASS_RE)
        code = t.to_i?
        unless code && (100..599).includes?(code)
          raise ValidationError.new("invalid HTTP status or class (use 200 or 2xx): #{t}")
        end
      end
      tokens
    end

    private def parse_uri(url : String) : URI
      URI.parse(url)
    rescue ex
      raise ValidationError.new("malformed URL: #{url}")
    end
  end
end
