require "digest/sha1"

module Authz0
  # Stable short identifiers for target URLs. Derived from the request shape
  # (method + path + body) so the same endpoint keeps the same id across
  # re-imports.
  module ShortId
    extend self

    LENGTH = 8

    def for(*parts : String) : String
      seed = parts.join(" ")
      Digest::SHA1.hexdigest(seed)[0, LENGTH]
    end

    # A token that *looks* like one of our ids: LENGTH hex chars, nothing else.
    def looks_like?(token : String) : Bool
      return false unless token.size == LENGTH
      token.each_char.all? { |c| c.ascii_number? || ('a'..'f').includes?(c) }
    end
  end
end
