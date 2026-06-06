require "digest/sha1"

module Authz0
  # Stable short identifiers for target URLs. Derived from the request shape
  # (method + path + body) so the same endpoint keeps the same id across
  # re-imports.
  module ShortId
    extend self

    LENGTH = 8

    def for(*parts : String) : String
      Digest::SHA1.hexdigest(parts.join(" "))[0, LENGTH]
    end

    # The shortest hash prefix (>= LENGTH) of this request shape that isn't
    # already in `taken`. Normally returns the usual 8-char id; only a genuine
    # truncated-hash collision with a *different* endpoint lengthens it, so two
    # distinct endpoints can never silently collapse to one id (which would lose
    # one on import, or delete both on `url remove`). Existing 8-char ids are
    # untouched, so sessions stay backward-compatible.
    def unique(*parts : String, taken : Set(String)) : String
      full = Digest::SHA1.hexdigest(parts.join(" "))
      len = LENGTH
      while len < full.size
        candidate = full[0, len]
        return candidate unless taken.includes?(candidate)
        len += 1
      end
      full
    end

    # A token that *looks* like one of our ids: LENGTH hex chars, nothing else.
    def looks_like?(token : String) : Bool
      return false unless token.size == LENGTH
      token.each_char.all? { |c| c.ascii_number? || ('a'..'f').includes?(c) }
    end
  end
end
