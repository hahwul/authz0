require "csv"
require "../models/result"
require "./reporter"

module Authz0
  module Report
    # CSV report — one row per probe, RFC-4180 quoted (handled by stdlib CSV).
    # Convenient for spreadsheets, jq-less triage, and diffing across runs.
    class CsvReport
      HEADERS = %w[index status method url role accessible expected verdict severity elapsed_ms reason error]

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
              r.elapsed_ms.to_s,
              r.reason,
              r.error || "",
            ].map { |v| defang(v) })
          end
        end
      end

      # Defang spreadsheet formula injection: a cell beginning with =, +, -, @,
      # tab, or CR is evaluated as a live formula by Excel/LibreOffice/Sheets.
      # Imported URLs/roles can carry such payloads (e.g. =HYPERLINK(...)), so
      # prefix an apostrophe to force text (OWASP CSV-injection guidance).
      private def defang(value : String) : String
        return value if value.empty?
        case value[0]
        when '=', '+', '-', '@', '\t', '\r'
          "'#{value}"
        else
          value
        end
      end
    end
  end
end
