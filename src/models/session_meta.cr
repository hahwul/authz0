require "json"

module Authz0
  # Metadata for one test project. Persisted as session.json. The `base_url`
  # is the prefix that relative TargetURL paths resolve against.
  class SessionMeta
    include JSON::Serializable

    property name : String
    property base_url : String
    property description : String?
    property created_at : Time
    property updated_at : Time

    def initialize(@name : String, @base_url : String, @description : String? = nil,
                   created_at : Time? = nil, updated_at : Time? = nil)
      now = Time.utc
      @created_at = created_at || now
      @updated_at = updated_at || now
    end
  end
end
