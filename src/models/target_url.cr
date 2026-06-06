require "json"
require "uri"
require "../utils/short_id"

module Authz0
  # One endpoint under test. Persisted as an element of urls.json.
  #
  # `path` is either an absolute URL (http://…) or a path/relative reference
  # that resolves against the session's base_url at scan time. Keeping the
  # raw path lets the same session target a different host by editing only
  # the base_url.
  class TargetURL
    include JSON::Serializable

    property id : String
    property path : String
    property method : String = "GET"
    property headers : Hash(String, String) = {} of String => String
    property body : String?
    # "json" | "form" | nil — mirrors v1's contentType; drives the
    # Content-Type request header when a body is present.
    property content_type : String?
    property allow_roles : Array(String) = [] of String
    property deny_roles : Array(String) = [] of String
    property tags : Array(String) = [] of String
    # Human label shown in reports (v1 called this "alias").
    property alias : String?

    def initialize(@path : String, @method : String = "GET", @body : String? = nil,
                   @content_type : String? = nil,
                   allow_roles : Array(String) = [] of String,
                   deny_roles : Array(String) = [] of String,
                   headers : Hash(String, String) = {} of String => String,
                   tags : Array(String) = [] of String,
                   @alias : String? = nil, id : String? = nil)
      @allow_roles = allow_roles
      @deny_roles = deny_roles
      @headers = headers
      @tags = tags
      @id = id || ShortId.for(@method, @path, @body || "")
    end

    # Resolve this target's effective absolute URL against a base. Absolute
    # paths (with their own scheme) win outright; otherwise the path is
    # merged onto the base URL, preserving the base's path prefix.
    def resolve(base_url : String) : String
      p = path
      return p if p.starts_with?("http://") || p.starts_with?("https://")

      base = URI.parse(base_url)
      if p.starts_with?("/")
        # Absolute path replaces the base path entirely.
        base.path = p
        base.query = nil
        # Carry any query embedded in the path (URI.parse on a relative
        # ref would otherwise drop the host). Split manually.
        if qi = p.index('?')
          base.path = p[0...qi]
          base.query = p[(qi + 1)..]
        end
        base.to_s
      else
        # Relative path: append to the base path with exactly one slash.
        prefix = base.path
        prefix = "/" if prefix.empty?
        prefix += "/" unless prefix.ends_with?("/")
        joined = prefix + p
        if qi = joined.index('?')
          base.path = joined[0...qi]
          base.query = joined[(qi + 1)..]
        else
          base.path = joined
          base.query = nil
        end
        base.to_s
      end
    rescue
      # Fall back to naive concatenation rather than crashing a scan.
      path.starts_with?("http") ? path : "#{base_url.rstrip('/')}/#{path.lstrip('/')}"
    end

    # Display label: explicit alias, else the path.
    def label : String
      a = @alias
      a && !a.empty? ? a : path
    end

    # True when the path still carries an unfilled `{template}` segment (common
    # in OpenAPI/Postman imports), which would 404 if scanned as-is.
    def templated? : Bool
      @path.matches?(/\{[^}]+\}/)
    end
  end
end
