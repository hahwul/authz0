require "json"
require "../models/result"
require "../utils/version"
require "./reporter"

module Authz0
  module Report
    # SARIF 2.1.0 log for CI / GitHub code scanning. Only actionable rows are
    # emitted: verdict "X" → error, verdict "?" (unevaluable / request error)
    # → note. Expected-policy rows are omitted.
    class SarifReport
      RULE_ID   = "authz0/broken-access-control"
      INFO_URI  = "https://github.com/hahwul/authz0"
      RULE_NAME = "BrokenAccessControl"

      def render(results : Array(Result)) : String
        reportable = results.reject { |r| r.verdict == "O" }
        JSON.build(indent: "  ") do |json|
          json.object do
            json.field "$schema", "https://json.schemastore.org/sarif-2.1.0.json"
            json.field "version", "2.1.0"
            json.field "runs" do
              json.array do
                json.object do
                  tool(json)
                  json.field "results" do
                    json.array do
                      reportable.each { |r| sarif_result(json, r) }
                    end
                  end
                end
              end
            end
          end
        end
      end

      private def tool(json : JSON::Builder)
        json.field "tool" do
          json.object do
            json.field "driver" do
              json.object do
                json.field "name", "authz0"
                json.field "version", Authz0::VERSION
                json.field "informationUri", INFO_URI
                json.field "rules" do
                  json.array do
                    json.object do
                      json.field "id", RULE_ID
                      json.field "name", RULE_NAME
                      json.field "shortDescription" do
                        json.object { json.field "text", "Authorization / access-control mismatch" }
                      end
                      json.field "helpUri", INFO_URI
                      json.field "defaultConfiguration" do
                        json.object { json.field "level", "error" }
                      end
                    end
                  end
                end
              end
            end
          end
        end
      end

      private def sarif_result(json : JSON::Builder, r : Result)
        json.object do
          json.field "ruleId", RULE_ID
          json.field "level", r.verdict == "X" ? "error" : "note"
          json.field "message" do
            json.object do
              json.field "text", "#{r.method} #{r.url} as '#{r.display_role}': #{r.reason}"
            end
          end
          json.field "locations" do
            json.array do
              json.object do
                json.field "physicalLocation" do
                  json.object do
                    json.field "artifactLocation" do
                      json.object { json.field "uri", r.url }
                    end
                  end
                end
              end
            end
          end
          json.field "properties" do
            json.object do
              json.field "role", r.display_role
              json.field "method", r.method
              json.field "statusCode", r.status_code
              json.field "accessible", r.accessible
              json.field "expectedAccess", r.expected_access
              json.field "allowRoles", r.allow_roles
              json.field "denyRoles", r.deny_roles
            end
          end
        end
      end
    end
  end
end
