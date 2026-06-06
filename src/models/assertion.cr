require "json"

module Authz0
  # An access-detection rule. The set of asserts on a session decides, for a
  # given HTTP response, whether the resource was *successfully accessed*
  # (the "accessible?" verdict the scanner compares against allow/deny roles).
  #
  # Types (compatible with v1):
  #   success-status   value="200,201,204"  → these codes mean accessible
  #   fail-status      value="403"          → this code means NOT accessible
  #   fail-regex       value="Access denied"→ body match means NOT accessible
  #   fail-size        value="1234"         → ~this byte size means NOT accessible
  #   fail-size-margin value="50"           → tolerance (bytes) for fail-size
  class Assertion
    include JSON::Serializable

    property type : String
    property value : String

    TYPES = %w[success-status fail-status fail-regex fail-size fail-size-margin]

    def initialize(@type : String, @value : String)
    end

    def valid_type? : Bool
      TYPES.includes?(@type)
    end
  end
end
