require "option_parser"
require "file_utils"
require "json"
require "../helpers"
require "../../models/credential"
require "../../scan/scanner"
require "../../report/reporter"
require "../../importers/v1_template"
require "../../store/session"
require "../../utils/config"
require "../../utils/errors"
require "../../utils/logger"
require "../../utils/suggester"
require "../../utils/validator"

module Authz0::CLI
  # `authz0 scan <session>` — probe every endpoint with every credential and
  # report authorization mismatches. Progress goes to stderr; the report goes
  # to stdout (so `--output json > out.json` stays clean).
  class ScanCommand
    include Helpers

    def run(args : Array(String))
      settings = Settings.current
      concurrency = settings.effective_concurrency
      timeout = settings.effective_timeout
      proxy = settings.proxy
      output_name = settings.effective_output
      output_explicit = false
      delay = 0
      follow = settings.follow_redirects || 0
      retries = settings.retries || 0
      user_agent = settings.user_agent
      include_anon = false
      dry_run = false
      tag_filter : String? = nil
      match_filter : String? = nil
      insecure = true
      progress = true
      only_findings = false
      severity_filter : String? = nil
      sort_by_field : String? = nil
      save_path : String? = nil
      save_results = true
      fail_on_findings = false
      baseline_path : String? = nil
      fail_on_new = false
      only_new = false
      template_path : String? = nil

      ad_hoc_role : String? = nil
      ad_hoc_headers = {} of String => String
      ad_hoc_cookies = {} of String => String
      extra_headers = {} of String => String
      positional = [] of String

      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 scan <session> [options]   |   authz0 scan --template <v1.yaml> [options]"
        p.on("--template FILE", "Scan a v1-compatible YAML template (no session needed)") { |v| template_path = v }
        p.on("--concurrency N", "Parallel workers (default #{concurrency})") do |v|
          concurrency = parse_int(v, "--concurrency", min: 1)
        end
        p.on("--timeout S", "Per-request timeout seconds (default #{timeout})") do |v|
          timeout = parse_int(v, "--timeout", min: 1)
        end
        p.on("--delay MS", "Delay between requests per worker (ms)") do |v|
          delay = parse_int(v, "--delay", min: 0)
        end
        p.on("--proxy URL", "Route through an HTTP proxy (e.g. Burp)") { |v| proxy = v }
        p.on("-L", "--follow-redirects", "Follow 3xx redirects (up to --max-redirects)") { follow = 10 if follow == 0 }
        p.on("--max-redirects N", "Max redirect hops to follow (0 = don't follow; >0 implies -L)") { |v| follow = parse_int(v, "--max-redirects", min: 0) }
        p.on("--retries N", "Retry transient failures (timeout/429/503) N times") { |v| retries = parse_int(v, "--retries", min: 0) }
        p.on("--user-agent UA", "Override the User-Agent header") { |v| user_agent = v }
        p.on("--anon", "Also probe each target anonymously (no credentials)") { include_anon = true }
        p.on("--dry-run", "Preview the probe matrix without sending requests") { dry_run = true }
        p.on("--tag TAG", "Scan only urls carrying this tag") { |v| tag_filter = v }
        p.on("--match GLOB", "Scan only urls whose path matches GLOB (e.g. /admin/*)") { |v| match_filter = v }
        p.on("-o FORMAT", "--output FORMAT", "table|plain|json|markdown|sarif|html|csv") { |v| output_name = v; output_explicit = true }
        p.on("--save FILE", "Also write the report to FILE") { |v| save_path = v }
        p.on("--no-save-results", "Don't archive results JSON in the session") { save_results = false }
        p.on("--only-findings", "Report only X (finding) / ? rows") { only_findings = true }
        p.on("--severity LEVEL", "Show only findings of this severity (high=unauthorized, low=over-restrictive)") do |v|
          s = v.downcase
          raise ValidationError.new("--severity must be 'high' or 'low': #{v}") unless ["high", "low"].includes?(s)
          severity_filter = s
        end
        p.on("--sort FIELD", "Order rows: severity | latency | status (default: scan order)") do |v|
          s = v.downcase
          raise ValidationError.new("--sort must be severity|latency|status: #{v}") unless ["severity", "latency", "status"].includes?(s)
          sort_by_field = s
        end
        p.on("--insecure", "Skip TLS verification (default)") { insecure = true }
        p.on("--secure", "Enforce TLS verification") { insecure = false }
        p.on("--no-progress", "Suppress live per-request progress") { progress = false }
        p.on("--fail-on-findings", "Exit non-zero when findings exist") { fail_on_findings = true }
        p.on("--baseline FILE", "Compare against a prior results JSON ('latest' = session's last scan)") { |v| baseline_path = v }
        p.on("--fail-on-new", "Exit non-zero only when NEW findings appear (needs --baseline)") { fail_on_new = true }
        p.on("--only-new", "Report only findings absent from the baseline") { only_new = true }
        p.on("-r NAME", "--role NAME", "Ad-hoc role for an inline credential") do |v|
          # -r defines a SINGLE inline role; repeating it silently kept only the
          # last, which read like multi-role support. Warn instead of guessing.
          Logger.warn "multiple -r/--role given; only the last ('#{v}') is used — add the others with `authz0 cred add`" unless ad_hoc_role.nil?
          ad_hoc_role = v
        end
        p.on("-H HEADER", "--header HEADER", "Header for the ad-hoc role (repeatable)") do |v|
          k, val = Validator.header!(v)
          ad_hoc_headers[k] = val
        end
        p.on("--cookie COOKIE", "Cookie for the ad-hoc role (repeatable)") do |v|
          k, val = Validator.cookie!(v)
          ad_hoc_cookies[k] = val
        end
        p.on("--extra-header HEADER", "Header sent with EVERY probe/role (repeatable)") do |v|
          k, val = Validator.header!(v)
          extra_headers[k] = val
        end
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, _| positional = before }
      end

      format = Report::Format.parse?(output_name)
      raise ValidationError.new(
        "unknown output format: #{output_name}",
        "one of: #{Report::Format.names.join(", ")}"
      ) if format.nil?

      # Two data sources: a persistent session, or a one-shot v1 YAML template
      # (ephemeral — nothing is read from or written to ~/.authz0).
      session : Store::Session? = nil
      if tpl = template_path
        parsed = Importers::V1Template.new.from_file(tpl)
        targets = parsed.targets
        asserts = parsed.asserts
        base_url = parsed.base_url
        creds = build_creds(parsed.creds, ad_hoc_role, ad_hoc_headers, ad_hoc_cookies, include_anon)
        source_label = "template #{File.basename(tpl)}"
        raise ValidationError.new("template '#{tpl}' has no urls to scan") if targets.empty?
        # No session directory to archive into.
        save_results = false
      else
        s = open_session(positional[0]?)
        session = s
        targets = s.urls
        raise ValidationError.new(
          "session '#{s.name}' has no urls to scan",
          "add some with `authz0 url add #{s.name} <path>` or `authz0 import ...`"
        ) if targets.empty?
        asserts = s.asserts
        base_url = s.meta.base_url
        creds = build_creds(s.creds, ad_hoc_role, ad_hoc_headers, ad_hoc_cookies, include_anon)
        source_label = "'#{s.name}'"
      end

      # Narrow the scan to a subset of urls (focused re-scans on big sessions).
      if tag = tag_filter
        targets = targets.select(&.tags.includes?(tag))
        raise ValidationError.new("no urls carry the tag '#{tag}'") if targets.empty?
      end
      if pat = match_filter
        targets = targets.select { |t| File.match?(pat, t.path) }
        raise ValidationError.new("no urls match '#{pat}'") if targets.empty?
      end

      raise ValidationError.new("--only-new/--fail-on-new need --baseline") if (only_new || fail_on_new) && baseline_path.nil?
      baseline_ids = (bp = baseline_path) ? load_baseline(bp, session) : Set(String).new

      via = base_url.empty? ? "" : " via #{base_url}"

      # Preview the probe matrix without sending any requests — useful before a
      # large or mutating (POST/DELETE) run.
      if dry_run
        probe_creds = creds.empty? ? [Credential.new("")] : creds
        Logger.info "dry run: #{source_label} — #{pluralize(targets.size, "url")} × #{creds_label(creds)} = #{pluralize(targets.size * probe_creds.size, "probe")}#{via}"
        # Surface config problems in the preview too, so they're caught before
        # the real run rather than after.
        warn_policy_gaps(targets, creds)
        targets.each do |t|
          resolved = t.resolve(base_url)
          probe_creds.each { |c| puts "#{t.method.ljust(6)} #{resolved}  [#{c.display_role}]" }
        end
        return
      end

      Logger.info "scanning #{source_label} — #{pluralize(targets.size, "url")} × #{creds_label(creds)}#{via}"
      maybe_warn_insecure_tls(insecure, targets, base_url)
      warn_policy_gaps(targets, creds)

      options = Scan::Options.new(
        concurrency: concurrency,
        timeout: timeout,
        proxy: proxy,
        insecure: insecure,
        delay_ms: delay,
        progress: progress && !Logger.quiet?,
        follow_redirects: follow,
        retries: retries,
        user_agent: user_agent,
        extra_headers: extra_headers,
      )
      scanner = Scan::Scanner.new(options)
      results = scanner.run(targets, creds, asserts, base_url)

      # Summary + archive always reflect the FULL scan; --only-findings /
      # --severity / --only-new only narrow what's *displayed*.
      summary = Report::Summary.new(results)

      # Findings whose identity wasn't in the baseline → newly introduced.
      new_ids = baseline_path ? Scan::Triage.new_finding_ids(results, baseline_ids) : Set(String).new

      display = Scan::Triage.filter(results, only_findings, severity_filter, only_new, new_ids)
      display = Scan::Triage.sort(display, sort_by_field)

      # Report → stdout. Color only for the interactive table. Pass the full
      # summary as scope so a filtered view's footer still reports true totals.
      color = format.table? && STDOUT.tty? && Logger.color_enabled?
      puts Report.render(display, format, color, scope: summary)

      # A scope-reduced scan (--tag/--match) only covered a subset of the
      # session, so don't let it become the "latest" archive — that would hide
      # findings from the un-scanned urls in `stats`, `results`, and
      # `--baseline latest`. Keep it with --save if you want a copy.
      if save_results && (tag_filter || match_filter)
        save_results = false
        Logger.info "partial scan (--tag/--match) — not archived as latest; use --save FILE to keep it"
      end
      # Archive a structured copy inside the session unless told not to.
      if save_results && (s = session)
        archive_results(s, results)
      end
      if path = save_path
        # Pick the file format from its extension unless -o was given
        # explicitly, so `--save report.html` writes HTML while stdout stays
        # a readable table.
        save_format = format
        unless output_explicit
          ext = File.extname(path).lchop('.')
          save_format = Report::Format.parse?(ext) || format
        end
        File.write(path, Report.render(display, save_format, false, scope: summary))
        Logger.success "report written to #{path} (#{save_format.to_s.downcase})"
      end

      hint_soft_denial(results, asserts)
      report_outcome(summary, baseline_path, new_ids, fail_on_findings, fail_on_new)
    end

    # The classic soft-denial false positive: an endpoint returns 200 with an
    # "Access Denied" body to a role that should be blocked. Status-only
    # detection scores that as an unauthorized finding. We can't be sure without
    # a body assert, but the tell is precise and low-noise: an "unauthorized"
    # finding whose body is much SMALLER than the body an authorized role got
    # for the same url. Only hint when no body/size assert is configured (the
    # user hasn't already handled it), and tie it to an actual finding so it
    # never fires on a clean scan.
    private def hint_soft_denial(results, asserts)
      return if Logger.quiet?
      return if asserts.any? { |a| {"fail-regex", "fail-size", "fail-header"}.includes?(a.type) }

      authorized_size = {} of String => Int64
      results.each do |r|
        next unless r.error.nil? && r.expected_access && r.accessible
        cur = authorized_size[r.url]?
        authorized_size[r.url] = r.resp_size if cur.nil? || r.resp_size > cur
      end

      suspect = results.find do |r|
        next false unless r.error.nil? && r.unauthorized?
        base = authorized_size[r.url]?
        !base.nil? && base >= 256 && r.resp_size * 2 <= base
      end
      return if suspect.nil?

      Logger.warn "a finding on #{suspect.url} returned a much smaller body than an authorized role got — " \
                  "if that's a 200 \"access denied\" page it's a false positive; add an " \
                  "`assert add <session> --fail-regex \"...\"` (or --fail-size) rule to detect soft denials"
    end

    # Final stderr summary + process exit code. Kept out of `run` so the option
    # parsing there stays within complexity limits.
    private def report_outcome(summary : Report::Summary, baseline_path : String?,
                               new_ids : Set(String), fail_on_findings : Bool, fail_on_new : Bool)
      if summary.findings > 0
        if baseline_path
          n = new_ids.size
          msg = "#{summary.findings} finding#{summary.findings == 1 ? "" : "s"} (#{n} new vs baseline)"
          n > 0 ? Logger.error(msg) : Logger.warn(msg)
        elsif summary.unauthorized > 0
          extra = summary.over_restrictive > 0 ? " (+#{summary.over_restrictive} over-restrictive)" : ""
          Logger.error "#{summary.unauthorized} unauthorized-access finding#{summary.unauthorized == 1 ? "" : "s"}#{extra} — review the red rows"
        else
          Logger.warn "#{summary.over_restrictive} over-restrictive finding#{summary.over_restrictive == 1 ? "" : "s"} (no unauthorized access) — likely a broken/over-tight policy"
        end
        exit 1 if fail_on_findings
        exit 1 if fail_on_new && new_ids.size > 0
      elsif summary.errors > 0 && summary.errors == summary.total
        # Every probe failed to reach the target — a totally failed scan must
        # NOT look like a clean pass (CI false-assurance otherwise).
        Logger.error "scan reached no targets — all #{pluralize(summary.errors, "probe")} errored (check the base URL, connectivity, or --proxy)"
        exit 1
      elsif summary.errors > 0
        Logger.warn "no authorization findings, but #{pluralize(summary.errors, "probe")} errored — results may be incomplete"
      else
        Logger.success "no authorization findings"
      end
    end

    # Set of finding identities from a prior results JSON. "latest" reads the
    # session's most recent archive (before this scan adds a new one).
    private def load_baseline(path : String, session) : Set(String)
      ids = Set(String).new
      content =
        if path == "latest"
          return ids if session.nil?
          latest = session.latest_result_file
          return ids if latest.nil?
          File.read(latest)
        else
          raise ValidationError.new("no such baseline file: #{path}") unless File.exists?(path)
          File.read(path)
        end
      doc = JSON.parse(content)
      arr = doc["results"]?.try(&.as_a?)
      return ids if arr.nil?
      Array(Result).from_json(arr.to_json).each { |r| ids << r.identity if r.vulnerable? }
      ids
    rescue ex : JSON::ParseException
      raise ValidationError.new("invalid baseline JSON (#{path}): #{ex.message}")
    end

    # Session credentials plus an optional inline (-r/-H/--cookie) identity and,
    # when requested, an anonymous baseline probe.
    private def build_creds(session_creds, role, headers, cookies, include_anon = false) : Array(Credential)
      creds = session_creds.dup
      if role && !role.empty?
        if existing = creds.find { |c| c.role == role }
          headers.each { |k, v| existing.headers[k] = v }
          cookies.each { |k, v| existing.cookies[k] = v }
        else
          creds << Credential.new(role, headers: headers, cookies: cookies)
        end
      elsif !headers.empty? || !cookies.empty?
        # Headers given with no role → an anonymous-but-authenticated probe.
        creds << Credential.new("inline", headers: headers, cookies: cookies)
      end
      # Prepend an unauthenticated probe so "reachable with no auth at all" is
      # tested alongside the real roles.
      creds.unshift(Credential.new("")) if include_anon && creds.none?(&.anonymous?)
      creds
    end

    private def archive_results(session, results)
      FileUtils.mkdir_p(session.results_dir)
      # Nanosecond precision + a collision guard so back-to-back scans don't
      # overwrite each other's archive. High precision also keeps the filename
      # lexically chronological (the '-N' collision suffix — which would sort
      # WRONG, '-' < '.' — effectively never fires).
      base = Time.utc.to_s("%Y%m%dT%H%M%S%9NZ")
      path = File.join(session.results_dir, "#{base}.json")
      n = 1
      while File.exists?(path)
        path = File.join(session.results_dir, "#{base}-#{n}.json")
        n += 1
      end
      File.write(path, Report.render(results, Report::Format::Json, false))
      Logger.debug "results archived to #{path}"
    end

    # Whether a policy role token refers to the anonymous (no-auth) probe.
    private def anon_role?(role : String) : Bool
      r = role.strip.downcase
      r.empty? || r == "anon" || r == "<anon>"
    end

    # Surface the two silent traps a fresh user/agent hits, since a security
    # tool returning a confidently-wrong "all clear" or a phantom finding is the
    # worst UX failure: (1) urls with no allow/deny policy can never produce a
    # finding (the scan only checks reachability), and (2) an allow/deny role
    # that matches no credential is almost always a typo — it goes unprobed and
    # skews verdicts. Both are advisory warnings, not errors.
    private def warn_policy_gaps(targets, creds)
      return if Logger.quiet?

      no_policy = targets.count { |t| t.allow_roles.empty? && t.deny_roles.empty? }
      if no_policy == targets.size
        Logger.warn "no url has an allow/deny policy — without one a scan can't flag an " \
                    "authorization mismatch (set --allow-role/--deny-role on your urls); " \
                    "this run only checks reachability"
      elsif no_policy > 0
        subject = no_policy == 1 ? "1 url has" : "#{no_policy} urls have"
        Logger.warn "#{subject} no allow/deny policy and can't produce a finding"
      end

      known = creds.map(&.role).reject(&.empty?).to_set
      referenced = Set(String).new
      targets.each do |t|
        t.allow_roles.each { |r| referenced << r }
        t.deny_roles.each { |r| referenced << r }
      end
      referenced.reject { |r| known.includes?(r) || anon_role?(r) }.each do |r|
        hint = Suggester.suggest(r, known.to_a)
        suffix = hint ? " (did you mean '#{hint}'?)" : ""
        Logger.warn "policy role '#{r}' has no matching credential#{suffix} — it won't be probed; a typo here can cause phantom findings"
      end
    end

    # Warn that TLS verification is off — but only when it actually applies:
    # the scan negotiates TLS for at least one target. A plain-HTTP-only scan
    # has no certificate to verify, so the warning would just be noise.
    private def maybe_warn_insecure_tls(insecure : Bool, targets, base_url) : Nil
      return unless insecure
      return if Logger.quiet?
      return unless targets.any?(&.resolve(base_url).starts_with?("https://"))
      Logger.warn "TLS verification disabled (--secure to enforce)"
    end

    private def creds_label(creds) : String
      if creds.empty?
        "anonymous"
      else
        "#{creds.size} role#{creds.size == 1 ? "" : "s"}"
      end
    end

    private def parse_int(value : String, flag : String, min : Int32) : Int32
      n = value.to_i?
      if n.nil? || n < min
        raise ValidationError.new("#{flag} must be an integer >= #{min}: #{value}")
      end
      n
    end
  end
end
