require "json"
require "../models/result"
require "../utils/version"
require "./reporter"

module Authz0
  module Report
    # Structured JSON: a top-level object with tool metadata, a summary block,
    # and the full result array. Stable shape for piping into jq / dashboards.
    class JsonReport
      def render(results : Array(Result)) : String
        summary = Summary.new(results)
        JSON.build(indent: "  ") do |json|
          json.object do
            json.field "tool", "authz0"
            json.field "version", Authz0::VERSION
            json.field "summary" do
              json.object do
                json.field "targets", summary.targets
                json.field "probes", summary.total
                json.field "findings", summary.findings
                json.field "unauthorized", summary.unauthorized
                json.field "over_restrictive", summary.over_restrictive
                json.field "expected", summary.expected
                json.field "errors", summary.errors
              end
            end
            json.field "results" do
              json.array do
                results.each do |r|
                  json.object do
                    # The struct's own fields, plus a derived severity so
                    # consumers don't have to recompute it.
                    json.field "index", r.index
                    json.field "url", r.url
                    json.field "method", r.method
                    json.field "role", r.role
                    json.field "allow_roles", r.allow_roles
                    json.field "deny_roles", r.deny_roles
                    json.field "accessible", r.accessible
                    json.field "expected_access", r.expected_access
                    json.field "status_code", r.status_code
                    json.field "resp_size", r.resp_size
                    json.field "elapsed_ms", r.elapsed_ms
                    json.field "alias", r.alias
                    json.field "verdict", r.verdict
                    json.field "severity", r.severity.label
                    json.field "reason", r.reason
                    json.field "error", r.error
                  end
                end
              end
            end
          end
        end
      end
    end
  end
end
