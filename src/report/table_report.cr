require "colorize"
require "../models/result"
require "../utils/table"
require "./reporter"

module Authz0
  module Report
    # Renders results as a table — either Unicode box (terminal) or, when
    # `box` is false, a tab-separated grid that pipes cleanly into awk/grep.
    # Vulnerable rows are tinted red when color is on.
    class TableReport
      HEADERS = ["#", "Status", "Method", "Target", "Role", "Access", "Expected", "RLT"]

      def initialize(@box : Bool = true, @color : Bool = true)
      end

      def render(results : Array(Result)) : String
        return "no results" if results.empty?

        if @box
          render_box(results)
        else
          render_plain(results)
        end
      end

      private def render_box(results : Array(Result)) : String
        table = Table.new(HEADERS)
        table.align([:right, :right, :left, :left, :left, :center, :center, :center])
        results.each do |r|
          color = r.vulnerable? ? Colorize::ColorANSI::Red : nil
          table.add(row_for(r), color)
        end
        String.build do |io|
          io << table.render(Table::Style::Box, @color) << '\n'
          io << summary_line(Summary.new(results))
        end
      end

      private def render_plain(results : Array(Result)) : String
        String.build do |io|
          io << HEADERS.join("\t") << '\n'
          results.each do |r|
            io << row_for(r).join("\t") << '\n'
          end
          io << summary_line(Summary.new(results))
        end
      end

      private def row_for(r : Result) : Array(String)
        status = r.error ? "ERR" : r.status_code.to_s
        target = display_target(r)
        [
          "#" + r.index.to_s,
          status,
          r.method,
          target,
          r.display_role,
          bool_mark(r.accessible),
          r.verdict == "?" ? "-" : bool_mark(r.expected_access),
          r.verdict,
        ]
      end

      private def display_target(r : Result) : String
        a = r.alias
        label = a && !a.empty? ? a : r.url
        label.size > 60 ? label[0, 57] + "..." : label
      end

      private def bool_mark(value : Bool) : String
        value ? "yes" : "no"
      end

      private def summary_line(s : Summary) : String
        parts = [
          "#{s.targets} targets",
          "#{s.total} probes",
          "#{s.findings} findings",
        ]
        parts << "#{s.errors} errors" if s.errors > 0
        prefix = s.clean? ? "✓" : "✗"
        line = "#{prefix} #{parts.join(", ")}"
        if @color && @box
          (s.clean? ? line.colorize(:green) : line.colorize(:red).bold).to_s
        else
          line
        end
      end
    end
  end
end
