require "../models/result"
require "../utils/table"
require "./reporter"

module Authz0
  module Report
    # GitHub-flavored Markdown report: a summary line plus a pipe table.
    # Suitable for pasting into issues / PR comments or CI job summaries.
    class MarkdownReport
      HEADERS = ["#", "Status", "Method", "Target", "Role", "Access", "Expected", "RLT"]

      def render(results : Array(Result)) : String
        summary = Summary.new(results)
        String.build do |io|
          io << "# authz0 scan report\n\n"
          io << "- **targets:** #{summary.targets}\n"
          io << "- **probes:** #{summary.total}\n"
          io << "- **findings:** #{summary.findings}\n"
          io << "- **errors:** #{summary.errors}\n\n"

          if results.empty?
            io << "_no results_\n"
            next
          end

          table = Table.new(HEADERS)
          results.each { |r| table.add(row_for(r)) }
          io << table.render(Table::Style::Markdown) << "\n"

          findings = results.select(&.vulnerable?)
          unless findings.empty?
            io << "\n## Findings\n\n"
            findings.each do |r|
              # Replace backticks so a URL containing one can't break out of the
              # inline-code span; escape the trailing prose so a crafted role or
              # reason can't inject Markdown structure.
              code = "#{r.method} #{r.url}".gsub('`', "'")
              io << "- `#{code}` as **#{md_escape(r.display_role)}** — #{md_escape(r.reason)}\n"
            end
          end
        end
      end

      # Escape the Markdown control characters that matter in inline prose.
      private def md_escape(text : String) : String
        text.gsub(/([`*_\[\]<>|\\])/) { |m| "\\#{m}" }
      end

      private def row_for(r : Result) : Array(String)
        status = r.error ? "ERR" : r.status_code.to_s
        target = r.alias && !r.alias.try(&.empty?) ? r.alias.to_s : r.url
        [
          "#" + r.index.to_s,
          status,
          r.method,
          target,
          r.display_role,
          r.accessible ? "yes" : "no",
          r.verdict == "?" ? "-" : (r.expected_access ? "yes" : "no"),
          r.verdict,
        ]
      end
    end
  end
end
