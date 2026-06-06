module Authz0
  # Credential masking for reports and `cred list`. Secrets are never written
  # to STDOUT (or report files) in full — only enough head/tail to recognize
  # which token is which.
  module Masking
    extend self

    # Mask a secret value. Short values are fully starred; longer ones keep a
    # few leading characters so the user can still tell two tokens apart.
    #   "1234"                       => "****"
    #   "Bearer abcdef123456"        => "Bear…3456"
    def mask(value : String) : String
      return value if value.empty?
      visible_head = 4
      visible_tail = 4
      if value.size <= visible_head + visible_tail
        return "*" * value.size
      end
      "#{value[0, visible_head]}…#{value[-visible_tail, visible_tail]}"
    end

    # Mask the value portion of a "Key: Value" header, leaving the key intact
    # so the report still shows *what* kind of auth is in play.
    def mask_header(key : String, value : String) : String
      "#{key}: #{mask(value)}"
    end

    # Mask every value in a header/cookie hash, returning "k: v, k2: v2".
    def mask_pairs(pairs : Hash(String, String), sep : String = ": ") : String
      pairs.map { |k, v| "#{k}#{sep}#{mask(v)}" }.join(", ")
    end
  end
end
