require "json"

module Authz0
  # An authenticated identity (a "role") used to probe each target. Persisted
  # as an element of creds.json, which is chmod 600 — these are secrets.
  #
  # An empty role name ("") represents the anonymous/unauthenticated baseline.
  class Credential
    include JSON::Serializable

    property role : String
    property headers : Hash(String, String) = {} of String => String
    property cookies : Hash(String, String) = {} of String => String
    # Optional descriptor, e.g. "bearer" / "cookie" / "apikey". Informational.
    property auth_type : String?

    def initialize(@role : String,
                   headers : Hash(String, String) = {} of String => String,
                   cookies : Hash(String, String) = {} of String => String,
                   @auth_type : String? = nil)
      @headers = headers
      @cookies = cookies
    end

    # True for the synthetic anonymous identity.
    def anonymous? : Bool
      @role.empty?
    end

    # Render cookies as a single "a=1; b=2" Cookie header value.
    def cookie_header : String?
      return nil if @cookies.empty?
      @cookies.map { |k, v| "#{k}=#{v}" }.join("; ")
    end

    # A human display name for reports (anonymous shows as "<anon>").
    def display_role : String
      anonymous? ? "<anon>" : @role
    end
  end
end
