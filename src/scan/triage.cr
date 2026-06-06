require "../models/result"

module Authz0
  module Scan
    # Pure post-scan processing: baseline diff, view filtering, and ordering.
    # Extracted from the scan command so it can be unit-tested in isolation and
    # keeps the CLI thin.
    module Triage
      extend self

      # Identities of findings present now but absent from the baseline set.
      def new_finding_ids(results : Array(Result), baseline_ids : Set(String)) : Set(String)
        ids = Set(String).new
        results.each do |r|
          ids << r.identity if r.vulnerable? && !baseline_ids.includes?(r.identity)
        end
        ids
      end

      # Narrow which rows are displayed. `severity` is "high"/"low"/nil.
      def filter(results : Array(Result), only_findings : Bool, severity : String?,
                 only_new : Bool, new_ids : Set(String)) : Array(Result)
        out = results
        out = out.reject { |r| r.verdict == "O" } if only_findings
        out = out.select { |r| new_ids.includes?(r.identity) } if only_new
        case severity
        when "high" then out = out.select(&.unauthorized?)
        when "low"  then out = out.select(&.over_restrictive?)
        end
        out
      end

      # Order rows for triage. `field` is "severity"/"latency"/"status"/nil.
      def sort(results : Array(Result), field : String?) : Array(Result)
        case field
        when "severity" then results.sort_by { |r| {severity_rank(r), r.index} }
        when "latency"  then results.sort_by { |r| -r.elapsed_ms }
        when "status"   then results.sort_by { |r| {r.status_code, r.index} }
        else                 results
        end
      end

      # 0 unauthorized (high), 1 over-restrictive (low), 2 everything else.
      def severity_rank(r : Result) : Int32
        case r.severity
        in Result::Severity::High then 0
        in Result::Severity::Low  then 1
        in Result::Severity::None then 2
        end
      end
    end
  end
end
