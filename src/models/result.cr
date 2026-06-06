require "json"

module Authz0
  # The outcome of probing one target with one credential. The scanner emits
  # an array of these; reporters render them.
  #
  # `verdict`:
  #   "O" — observed access matched policy (expected)
  #   "X" — mismatch → a potential authorization flaw (the finding)
  #   "?" — could not be evaluated (request error / no policy to check)
  class Result
    include JSON::Serializable

    # How serious a finding is. The two `X` cases are very different:
    #   High — unauthorized access: a role reached a resource it should not
    #          (broken access control / privilege escalation). The real finding.
    #   Low  — over-restrictive: a role was denied access policy says it should
    #          have (a functional bug, not a security hole).
    enum Severity
      None
      High
      Low

      def label : String
        case self
        in None then "info"
        in High then "high"
        in Low  then "low"
        end
      end
    end

    property index : Int32
    property url : String
    property method : String
    property role : String
    property allow_roles : Array(String)
    property deny_roles : Array(String)
    # Whether the assertions judged the resource as successfully accessed.
    property accessible : Bool
    # Whether policy *expected* this role to have access.
    property expected_access : Bool
    property status_code : Int32
    property resp_size : Int64
    property alias : String?
    property verdict : String
    property error : String?
    # Round-trip time for this probe in milliseconds (whole chain incl.
    # retries/redirects).
    property elapsed_ms : Int32 = 0

    def initialize(@index : Int32, @url : String, @method : String, @role : String,
                   @allow_roles : Array(String), @deny_roles : Array(String),
                   @accessible : Bool, @expected_access : Bool,
                   @status_code : Int32, @resp_size : Int64,
                   @alias : String? = nil, @verdict : String = "O",
                   @error : String? = nil, @elapsed_ms : Int32 = 0)
    end

    def vulnerable? : Bool
      @verdict == "X"
    end

    # The dangerous finding: a role accessed something it wasn't expected to.
    def unauthorized? : Bool
      vulnerable? && !@expected_access && @accessible
    end

    # The benign finding: a role was blocked from something it should reach.
    def over_restrictive? : Bool
      vulnerable? && @expected_access && !@accessible
    end

    def severity : Severity
      return Severity::High if unauthorized?
      return Severity::Low if over_restrictive?
      Severity::None
    end

    def role_in_allow? : Bool
      @allow_roles.includes?(@role)
    end

    def role_in_deny? : Bool
      @deny_roles.includes?(@role)
    end

    def display_role : String
      @role.empty? ? "<anon>" : @role
    end

    def display_alias : String
      a = @alias
      a && !a.empty? ? a : ""
    end

    # One-line human summary of *why* a finding fired, used in reports.
    def reason : String
      return "request error: #{@error}" if @error
      return "could not evaluate policy" if @verdict == "?"
      if @verdict == "X"
        if @expected_access && !@accessible
          "expected access but was denied (broken/over-restrictive policy)"
        elsif !@expected_access && @accessible
          "unauthorized access: role '#{display_role}' reached a resource it should not"
        else
          "policy mismatch"
        end
      else
        @accessible ? "access allowed as expected" : "access denied as expected"
      end
    end
  end
end
