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

      def initialize(@concurrency : Int32 = 20, @timeout : Int32 = 10,
                     @proxy : String? = nil, @insecure : Bool = true,
                     @delay_ms : Int32 = 0, @progress : Bool = true,
                     @follow_redirects : Int32 = 0, @retries : Int32 = 0)
      end
    end

    # Concurrent authorization scanner. For every (target, credential) pair it
    # issues a request, asks the Asserter whether the resource was accessed,
    # then compares that against the target's allow/deny policy for the role
    # to produce an O (expected) / X (finding) / ? (unevaluable) verdict.
    class Scanner
      def initialize(@options : Options = Options.new)
        @client = HttpClient.new(@options.timeout, @options.proxy, @options.insecure, @options.follow_redirects, @options.retries)
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

        workers = @options.concurrency
        workers = 1 if workers < 1
        workers = jobs.size if workers > jobs.size

        ch = Channel(Job).new(jobs.size)
        done = Channel(Nil).new

        workers.times do
          spawn do
            while job = ch.receive?
              # Distinct slot per ordinal → safe to assign without a lock.
              slots[job.ordinal] = probe(job, base_url, asserts)
              sleep(@options.delay_ms.milliseconds) if @options.delay_ms > 0
            end
            done.send(nil)
          end
        end

        jobs.each { |j| ch.send(j) }
        ch.close
        workers.times { done.receive }

        slots.compact
      end

      private def probe(job : Job, base_url : String, asserts : Array(Assertion)) : Result
        target = job.target
        cred = job.cred
        url = target.resolve(base_url)
        headers = build_headers(target, cred)
        response = @client.request(target.method, url, headers, target.body)

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
        )
        log_progress(result)
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

      private def log_progress(result : Result)
        return unless @options.progress
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
