require "./errors"

module Authz0
  # Extracts headers and cookies from a `curl` command line — the exact string
  # browsers and Burp produce via "Copy as cURL". Lets pentesters lift a real
  # authenticated request straight into an authz0 credential.
  #
  # Only the auth-relevant flags are read: -H/--header and -b/--cookie (plus
  # their `=value` forms). Method/body/URL are ignored — a credential is just
  # the identity material.
  module CurlParser
    extend self

    record Parsed, headers : Hash(String, String), cookies : Hash(String, String)

    # Characters a backslash may escape inside a double-quoted shell string.
    DOUBLE_QUOTE_ESCAPES = {'$', '`', '"', '\\', '\n'}

    def parse(command : String) : Parsed
      tokens = tokenize(command)
      headers = {} of String => String
      cookies = {} of String => String

      i = 0
      while i < tokens.size
        t = tokens[i]
        if (t == "-H" || t == "--header") && (val = tokens[i + 1]?)
          add_header(headers, val)
          i += 2
          next
        elsif t.starts_with?("--header=")
          add_header(headers, t["--header=".size..])
        elsif (t == "-b" || t == "--cookie") && (val = tokens[i + 1]?)
          add_cookies(cookies, val)
          i += 2
          next
        elsif t.starts_with?("--cookie=")
          add_cookies(cookies, t["--cookie=".size..])
        end
        i += 1
      end

      Parsed.new(headers, cookies)
    end

    private def add_header(headers : Hash(String, String), raw : String)
      idx = raw.index(':')
      return unless idx
      key = raw[0...idx].strip
      value = raw[(idx + 1)..].strip
      return if key.empty?
      # `-b`-style cookies sometimes arrive as a "Cookie:" header; those are
      # left as a header (still sent verbatim), which is correct.
      headers[key] = value
    end

    private def add_cookies(cookies : Hash(String, String), raw : String)
      raw.split(';').each do |pair|
        eq = pair.index('=')
        next unless eq
        name = pair[0...eq].strip
        value = pair[(eq + 1)..].strip
        cookies[name] = value unless name.empty?
      end
    end

    # Minimal POSIX-ish shell tokenizer: honors single/double quotes,
    # backslash escapes (incl. line-continuation `\`+newline that browsers
    # emit), and whitespace separation. Good enough for curl command lines.
    private def tokenize(s : String) : Array(String)
      tokens = [] of String
      buf = IO::Memory.new
      has_token = false
      in_single = false
      in_double = false

      chars = s.chars
      i = 0
      while i < chars.size
        c = chars[i]
        if in_single
          if c == '\''
            in_single = false
          else
            buf << c
          end
        elsif in_double
          if c == '"'
            in_double = false
          elsif c == '\\' && i + 1 < chars.size && DOUBLE_QUOTE_ESCAPES.includes?(chars[i + 1])
            # Inside double quotes a backslash is literal UNLESS it precedes one
            # of $ ` " \ or newline (bash semantics) — so a Windows path like
            # "C:\Users\me" keeps its backslashes instead of becoming "C:Usersme".
            buf << chars[i + 1]
            i += 1
          else
            buf << c
          end
        else
          case c
          when '\''
            in_single = true
            has_token = true
          when '"'
            in_double = true
            has_token = true
          when '\\'
            nxt = chars[i + 1]?
            if nxt && nxt != '\n' && nxt != '\r'
              buf << nxt
              has_token = true
              i += 1
            end
            # `\`+newline (line continuation) is just dropped
          when ' ', '\t', '\n', '\r'
            if has_token
              tokens << buf.to_s
              buf.clear
              has_token = false
            end
          else
            buf << c
            has_token = true
          end
        end
        i += 1
      end
      # An unterminated quote would otherwise swallow following arguments into
      # one token (leaking content into a header value). Surface it instead.
      if in_single || in_double
        raise ValidationError.new("unbalanced quote in curl command — check the pasted string")
      end
      tokens << buf.to_s if has_token
      tokens
    end
  end
end
