require "../models/assertion"

module Authz0
  module Scan
    # Decides, for one HTTP response, whether the resource was *successfully
    # accessed* — the boolean the scanner compares against each role's
    # allow/deny policy.
    #
    # Semantics (a deliberate refinement of v1, whose result depended on the
    # order asserts appeared in): negative signals win. If any `fail-*`
    # assert matches, the resource is judged NOT accessible even when the
    # status looks like success — this is what catches "soft" 200-but-denied
    # pages. Only when no fail signal fires do we consult `success-status`
    # (or, absent any assert, the 2xx heuristic).
    module Asserter
      extend self

      def accessible?(response : HttpResponse, asserts : Array(Assertion)) : Bool
        # A request that never completed can't have accessed anything.
        return false unless response.ok?

        margin = fail_size_margin(asserts)

        asserts.each do |a|
          case a.type
          when "fail-status"
            each_code(a.value) do |code|
              return false if response.status_code == code
            end
          when "fail-regex"
            return false if body_matches?(response.body, a.value)
          when "fail-size"
            if target = a.value.strip.to_i64?
              return false if (response.size - target).abs <= margin
            end
          end
        end

        success = success_statuses(asserts)
        return success.includes?(response.status_code) unless success.empty?

        (200..299).includes?(response.status_code)
      end

      private def fail_size_margin(asserts : Array(Assertion)) : Int64
        asserts.each do |a|
          if a.type == "fail-size-margin"
            if m = a.value.strip.to_i64?
              return m
            end
          end
        end
        0_i64
      end

      private def success_statuses(asserts : Array(Assertion)) : Array(Int32)
        out = [] of Int32
        asserts.each do |a|
          next unless a.type == "success-status"
          each_code(a.value) { |code| out << code }
        end
        out
      end

      private def each_code(value : String, &)
        value.split(',').each do |v|
          if code = v.strip.to_i?
            yield code
          end
        end
      end

      # Match the response body against the assert value as a regex, falling
      # back to a plain substring test if the value isn't a valid pattern.
      private def body_matches?(body : String, pattern : String) : Bool
        re = Regex.new(pattern)
        body.matches?(re)
      rescue
        body.includes?(pattern)
      end
    end
  end
end
