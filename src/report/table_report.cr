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
      HEADERS = ["#", "Status", "Method", "Target", "Role", "Access", "Expected", "Verdict"]

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
          # Red marks a genuine unauthorized-access finding; yellow marks the
          # benign over-restrictive case so the eye goes to real breaches first.
          color = case r.severity
                  in Result::Severity::High then Colorize::ColorANSI::Red
                  in Result::Severity::Low  then Colorize::ColorANSI::Yellow
                  in Result::Severity::None then nil
                  end
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
            # Flatten cells so an embedded newline/tab can't desync TSV columns.
            io << row_for(r).map { |c| Table.oneline(c) }.join("\t") << '\n'
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

      private def pluralize(count : Int, noun : String) : String
        "#{count} #{count == 1 ? noun : "#{noun}s"}"
      end

      private def summary_line(s : Summary) : String
        parts = [
          pluralize(s.targets, "target"),
          pluralize(s.total, "probe"),
          pluralize(s.findings, "finding"),
        ]
        # Break findings into the dangerous vs benign subsets so a wall of
        # over-restrictive rows doesn't read as a breach.
        if s.findings > 0
          parts << "#{s.unauthorized} unauthorized" << "#{s.over_restrictive} over-restrictive"
        end
        parts << pluralize(s.errors, "error") if s.errors > 0
        # A scan where every probe errored reached nothing — not a clean pass.
        all_errored = s.total > 0 && s.errors == s.total
        prefix = (s.clean? && !all_errored) ? "✓" : "✗"
        line = "#{prefix} #{parts.join(", ")}"
        if @color && @box
          if all_errored
            line.colorize(:red).to_s
          elsif s.clean?
            line.colorize(:green).to_s
          elsif s.breached?
            line.colorize(:red).bold.to_s
          else
            # Findings exist, but none are actual unauthorized access.
            line.colorize(:yellow).to_s
          end
        else
          line
        end
      end
    end
  end
end
