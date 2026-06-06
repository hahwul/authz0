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

      # Precompile fail-regex patterns once (call before a scan) so the hot path
      # doesn't rebuild the same Regex for every response. Invalid patterns are
      # omitted — the matcher falls back to a substring test for those.
      def compile_regexes(asserts : Array(Assertion)) : Hash(String, Regex)
        cache = {} of String => Regex
        asserts.each do |a|
          next unless a.type == "fail-regex"
          next if cache.has_key?(a.value)
          begin
            cache[a.value] = Regex.new(a.value)
          rescue
            # leave uncached → substring fallback in body_matches?
          end
        end
        cache
      end

      # `regex_cache` (from #compile_regexes) lets the scanner avoid recompiling
      # fail-regex patterns per response; nil keeps the standalone behavior.
      def accessible?(response : HttpResponse, asserts : Array(Assertion),
                      regex_cache : Hash(String, Regex)? = nil) : Bool
        # A request that never completed can't have accessed anything.
        return false unless response.ok?

        margin = fail_size_margin(asserts)

        code = response.status_code
        has_success = false
        success_match = false

        asserts.each do |a|
          case a.type
          when "fail-status"
            return false if status_list_matches?(code, a.value)
          when "fail-regex"
            return false if body_matches?(response.body, a.value, regex_cache)
          when "fail-size"
            if target = a.value.strip.to_i64?
              return false if (response.size - target).abs <= margin
            end
          when "fail-header"
            return false if header_matches?(response.headers, a.value)
          when "success-status"
            has_success = true
            success_match ||= status_list_matches?(code, a.value)
          when "success-header"
            has_success = true
            success_match ||= header_matches?(response.headers, a.value)
          end
        end

        return success_match if has_success
        (200..299).includes?(code)
      end

      # Match a status against a comma list whose tokens are either exact codes
      # ("200") or status classes ("2xx", "4xx").
      private def status_list_matches?(status : Int32, value : String) : Bool
        value.split(',').any? { |t| status_matches?(status, t) }
      end

      # Match a response header. Value is "Name" (header present) or
      # "Name: substring" (present and value contains substring, case-insens).
      private def header_matches?(headers : Hash(String, String), value : String) : Bool
        idx = value.index(':')
        if idx
          name = value[0...idx].strip.downcase
          needle = value[(idx + 1)..].strip.downcase
          actual = headers[name]?
          return false if actual.nil?
          return true if needle.empty?
          # Repeated headers are stored newline-joined; test each value on its
          # own so a needle can't match across the join between two values.
          actual.downcase.split('\n').any?(&.includes?(needle))
        else
          headers.has_key?(value.strip.downcase)
        end
      end

      private def status_matches?(status : Int32, token : String) : Bool
        t = token.strip.downcase
        if m = t.match(/\A([1-5])xx\z/)
          return status // 100 == m[1].to_i
        end
        if code = t.to_i?
          return status == code
        end
        false
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

      # Match the response body against the assert value as a regex, falling
      # back to a plain substring test if the value isn't a valid pattern. Uses
      # the precompiled regex from `cache` when available to avoid recompiling
      # the same pattern for every response.
      private def body_matches?(body : String, pattern : String, cache : Hash(String, Regex)? = nil) : Bool
        if cache && (re = cache[pattern]?)
          return body.matches?(re)
        end
        body.matches?(Regex.new(pattern))
      rescue
        body.includes?(pattern)
      end
    end
  end
end
