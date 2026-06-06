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
                json.field "expected", summary.expected
                json.field "errors", summary.errors
              end
            end
            json.field "results" do
              json.array do
                results.each { |r| r.to_json(json) }
              end
            end
          end
        end
      end
    end
  end
end
