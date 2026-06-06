require "csv"
require "../models/result"
require "./reporter"

module Authz0
  module Report
    # CSV report — one row per probe, RFC-4180 quoted (handled by stdlib CSV).
    # Convenient for spreadsheets, jq-less triage, and diffing across runs.
    class CsvReport
      HEADERS = %w[index status method url role accessible expected verdict severity reason error]

      def render(results : Array(Result)) : String
        CSV.build do |csv|
          csv.row HEADERS
          results.each do |r|
            csv.row([
              r.index.to_s,
              r.error ? "ERR" : r.status_code.to_s,
              r.method,
              r.url,
              r.display_role,
              r.accessible.to_s,
              r.verdict == "?" ? "" : r.expected_access.to_s,
              r.verdict,
              r.severity.label,
              r.reason,
              r.error || "",
            ])
          end
        end
      end
    end
  end
end
