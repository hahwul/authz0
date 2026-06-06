require "../models/result"

module Authz0
  module Report
    # Output formats for scan results.
    enum Format
      Table    # Unicode box table (default, terminal)
      Plain    # tab-separated, grep/awk friendly
      Json     # structured {summary, results}
      Markdown # GitHub-flavored pipe table
      Sarif    # SARIF 2.1.0 (CI / code scanning)
      Html     # self-contained HTML page
      Csv      # RFC-4180 CSV, one row per probe

      def self.parse?(value : String) : Format?
        case value.downcase
        when "table"                then Table
        when "plain", "text", "txt" then Plain
        when "json"                 then Json
        when "markdown", "md"       then Markdown
        when "sarif"                then Sarif
        when "html"                 then Html
        when "csv"                  then Csv
        else                             nil
        end
      end

      def self.names : Array(String)
        %w[table plain json markdown sarif html csv]
      end
    end

    # Aggregate counts over a result set.
    struct Summary
      getter total : Int32
      getter findings : Int32
      # The dangerous subset of findings (role reached a resource it shouldn't).
      getter unauthorized : Int32
      # The benign subset (role denied access it should have).
      getter over_restrictive : Int32
      getter errors : Int32
      getter expected : Int32
      getter targets : Int32

      def initialize(results : Array(Result))
        @total = results.size
        @findings = results.count(&.vulnerable?)
        @unauthorized = results.count(&.unauthorized?)
        @over_restrictive = results.count(&.over_restrictive?)
        @errors = results.count { |r| !r.error.nil? }
        @expected = results.count { |r| r.verdict == "O" }
        @targets = results.map(&.index).uniq!.size
      end

      def clean? : Bool
        @findings == 0
      end

      # True when at least one genuine unauthorized-access finding exists.
      def breached? : Bool
        @unauthorized > 0
      end
    end

    # Render a result set in the requested format. `color` only affects the
    # Table format; the machine formats are always plain.
    def self.render(results : Array(Result), format : Format, color : Bool = false) : String
      case format
      in Format::Table    then TableReport.new(box: true, color: color).render(results)
      in Format::Plain    then TableReport.new(box: false, color: false).render(results)
      in Format::Markdown then MarkdownReport.new.render(results)
      in Format::Json     then JsonReport.new.render(results)
      in Format::Sarif    then SarifReport.new.render(results)
      in Format::Html     then HtmlReport.new.render(results)
      in Format::Csv      then CsvReport.new.render(results)
      end
    end

    # The file extension a format conventionally uses, for `scan --output`.
    def self.extension(format : Format) : String
      case format
      in Format::Table    then "txt"
      in Format::Plain    then "txt"
      in Format::Markdown then "md"
      in Format::Json     then "json"
      in Format::Sarif    then "sarif"
      in Format::Html     then "html"
      in Format::Csv      then "csv"
      end
    end
  end
end
