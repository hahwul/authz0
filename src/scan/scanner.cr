require "http/headers"
require "../models/target_url"
require "../models/credential"
require "../models/assertion"
require "../models/result"
require "../utils/logger"
require "./http_client"
require "./asserter"

module Authz0
  module Scan
    # Tunable parameters for a scan run.
    struct Options
      property concurrency : Int32
      property timeout : Int32
      property proxy : String?
      property insecure : Bool
      # Per-request delay in milliseconds (rate limiting), applied per worker.
      property delay_ms : Int32
      property progress : Bool
      # Max redirect hops to follow (0 = don't follow — the default).
      property follow_redirects : Int32
      # Retries for transient failures (timeouts / 429 / 503).
      property retries : Int32
      # Override the default User-Agent on every request.
      property user_agent : String?
      # Headers added to every probe (lowest precedence — a target or
      # credential header of the same name still wins).
      property extra_headers : Hash(String, String)

      def initialize(@concurrency : Int32 = 20, @timeout : Int32 = 10,
                     @proxy : String? = nil, @insecure : Bool = true,
                     @delay_ms : Int32 = 0, @progress : Bool = true,
                     @follow_redirects : Int32 = 0, @retries : Int32 = 0,
                     @user_agent : String? = nil,
                     @extra_headers : Hash(String, String) = {} of String => String)
      end
    end

    # Concurrent authorization scanner. For every (target, credential) pair it
    # issues a request, asks the Asserter whether the resource was accessed,
    # then compares that against the target's allow/deny policy for the role
    # to produce an O (expected) / X (finding) / ? (unevaluable) verdict.
    class Scanner
      def initialize(@options : Options = Options.new)
        @client = HttpClient.new(@options.timeout, @options.proxy, @options.insecure,
          @options.follow_redirects, @options.retries, @options.user_agent)
        @total = 0
        @done = Atomic(Int32).new(0)
        @found = Atomic(Int32).new(0)
        # Serializes the live-counter writes so concurrent workers (notably
        # under -Dpreview_mt) can't interleave bytes into a garbled line.
        @progress_mutex = Mutex.new
        # Flipped off once the progress consumer closes the pipe, so a broken
        # `… | head` doesn't make every remaining probe re-hit EPIPE.
        @progress_alive = true
      end

      private record Job, ordinal : Int32, target_index : Int32, target : TargetURL, cred : Credential

      def run(targets : Array(TargetURL), creds : Array(Credential), asserts : Array(Assertion), base_url : String) : Array(Result)
        # No declared identities → probe anonymously so a bare scan still
        # produces output.
        creds = [Credential.new("")] of Credential if creds.empty?

        jobs = [] of Job
        ordinal = 0
        targets.each_with_index do |target, ti|
          creds.each do |cred|
            jobs << Job.new(ordinal, ti, target, cred)
            ordinal += 1
          end
        end

        slots = Array(Result?).new(jobs.size, nil)
        return [] of Result if jobs.empty?

        @total = jobs.size
        @done.set(0)
        @found.set(0)

        workers = @options.concurrency
        workers = 1 if workers < 1
        workers = jobs.size if workers > jobs.size

        ch = Channel(Job).new(jobs.size)
        done = Channel(Nil).new

        workers.times do
          spawn do
            begin
              while job = ch.receive?
                # Distinct slot per ordinal → safe to assign without a lock. A
                # probe is expected to capture its own transport errors, but if
                # anything (e.g. a broken progress pipe) still escapes, record an
                # errored result instead of letting the worker die — see below.
                slots[job.ordinal] =
                  begin
                    probe(job, base_url, asserts)
                  rescue ex
                    errored_result(job, base_url, ex)
                  end
                sleep(@options.delay_ms.milliseconds) if @options.delay_ms > 0
              end
            ensure
              # ALWAYS signal completion — even on an unexpected raise — or the
              # main fiber blocks on `done.receive` forever and the scan hangs.
              done.send(nil)
            end
          end
        end

        jobs.each { |j| ch.send(j) }
        ch.close
        workers.times { done.receive }
        clear_counter

        slots.compact
      end

      private def probe(job : Job, base_url : String, asserts : Array(Assertion)) : Result
        target = job.target
        cred = job.cred
        url = target.resolve(base_url)
        headers = build_headers(target, cred)
        started = Time.instant
        response = @client.request(target.method, url, headers, target.body, sensitive_headers(target, cred))
        elapsed = (Time.instant - started).total_milliseconds.round.to_i

        accessible = Asserter.accessible?(response, asserts)
        verdict, expected = evaluate(target, cred.role, accessible, response)

        result = Result.new(
          index: job.target_index,
          url: url,
          method: target.method,
          role: cred.role,
          allow_roles: target.allow_roles,
          deny_roles: target.deny_roles,
          accessible: accessible,
          expected_access: expected,
          status_code: response.status_code,
          resp_size: response.size,
          alias: target.alias,
          verdict: verdict,
          error: response.error,
          elapsed_ms: elapsed,
        )
        report_progress(result)
        result
      end

      # Build an errored "?" result for a probe that raised unexpectedly, so one
      # bad probe neither kills its worker nor vanishes from the report.
      private def errored_result(job : Job, base_url : String, ex : Exception) : Result
        target = job.target
        result = Result.new(
          index: job.target_index,
          url: target.resolve(base_url),
          method: target.method,
          role: job.cred.role,
          allow_roles: target.allow_roles,
          deny_roles: target.deny_roles,
          accessible: false,
          expected_access: false,
          status_code: 0,
          resp_size: 0_i64,
          alias: target.alias,
          verdict: "?",
          error: ex.message || ex.class.name,
          elapsed_ms: 0,
        )
        report_progress(result)
        result
      end

      # Core authorization logic. A target with no allow/deny roles has no
      # policy to verify, so it's never a finding. Otherwise the expected
      # access for a role is: present in allow (or allow is empty) AND not in
      # deny; a mismatch with the observed access is the finding.
      private def evaluate(target : TargetURL, role : String, accessible : Bool, response : HttpResponse) : {String, Bool}
        return {"?", false} unless response.ok?

        has_policy = !target.allow_roles.empty? || !target.deny_roles.empty?
        unless has_policy
          return {"O", accessible}
        end

        expected = target.allow_roles.empty? ? true : target.allow_roles.includes?(role)
        expected = false if target.deny_roles.includes?(role)

        verdict = (expected == accessible) ? "O" : "X"
        {verdict, expected}
      end

      # Merge target headers, the credential's headers, content-type and
      # cookies into one HTTP::Headers. Credential headers override target
      # headers on conflict (the identity is what we're testing).
      private def build_headers(target : TargetURL, cred : Credential) : HTTP::Headers
        headers = HTTP::Headers.new
        # Scan-wide headers first so a target/credential header can override.
        @options.extra_headers.each { |k, v| headers[k] = v }
        target.headers.each { |k, v| headers[k] = v }
        cred.headers.each { |k, v| headers[k] = v }

        # Content-Type for bodies, unless the target already set one.
        if body = target.body
          unless body.empty? || headers.has_key?("Content-Type")
            headers["Content-Type"] = content_type_header(target.content_type)
          end
        end

        # Merge cookies from target headers and the credential.
        cookies = [] of String
        if existing = headers["Cookie"]?
          cookies << existing
        end
        if ck = cred.cookie_header
          cookies << ck
        end
        headers["Cookie"] = cookies.join("; ") unless cookies.empty?

        headers
      end

      # Header names that carry this probe's credentials (so the client can drop
      # them on a cross-origin redirect). Credentials live in arbitrary header
      # names here, plus any scan-wide --extra-header and the cookie jar.
      private def sensitive_headers(target : TargetURL, cred : Credential) : Set(String)
        names = Set(String).new
        cred.headers.each_key { |k| names << k.downcase }
        @options.extra_headers.each_key { |k| names << k.downcase }
        names << "cookie" unless cred.cookies.empty?
        names
      end

      private def content_type_header(content_type : String?) : String
        case content_type
        when "json"
          "application/json"
        when "form"
          "application/x-www-form-urlencoded"
        else
          "application/x-www-form-urlencoded"
        end
      end

      # Progress reporting. Under -v (debug) we emit a permanent line per probe
      # (the old verbose behavior). Otherwise, on a TTY, a single in-place
      # counter is updated — far less noise for large scans.
      private def report_progress(result : Result)
        done = @done.add(1) + 1
        @found.add(1) if result.vulnerable?
        return unless @options.progress && @progress_alive

        # One writer at a time, and never let a closed progress pipe abort the
        # probe: if the consumer went away (EPIPE), stop trying to draw progress
        # — the real report still goes to stdout.
        @progress_mutex.synchronize do
          next unless @progress_alive
          begin
            if Logger.debug?
              log_line(result)
            elsif counter_tty?
              STDERR.print("\r\e[2Kscanning #{done}/#{@total}  (#{@found.get} findings)")
              STDERR.flush
            end
          rescue IO::Error
            @progress_alive = false
          end
        end
      end

      # The live counter is active only when progress is on, we're not in
      # verbose (per-line) mode, and stderr is an interactive terminal.
      private def counter_active? : Bool
        @options.progress && !Logger.debug? && counter_tty?
      end

      private def clear_counter
        return unless counter_active? && @progress_alive
        @progress_mutex.synchronize do
          STDERR.print("\r\e[2K")
          STDERR.flush
        rescue IO::Error
          @progress_alive = false
        end
      end

      private def counter_tty? : Bool
        STDERR.tty? && !Logger.quiet?
      end

      private def log_line(result : Result)
        status = result.error ? "ERR" : result.status_code.to_s
        role = result.role.empty? ? "<anon>" : result.role
        line = String.build do |io|
          io << "#" << result.index
          io << "  " << status.rjust(3)
          io << "  " << result.method << " " << result.url
          io << "  [" << role << "]"
          io << "  " << result.verdict
          io << "  (" << result.error << ")" if result.error
        end
        Logger.scan_line(line, !result.vulnerable?)
      end
    end
  end
end
