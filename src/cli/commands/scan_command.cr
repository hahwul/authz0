require "option_parser"
require "file_utils"
require "../helpers"
require "../../models/credential"
require "../../scan/scanner"
require "../../report/reporter"
require "../../importers/v1_template"
require "../../store/session"
require "../../utils/config"
require "../../utils/errors"
require "../../utils/logger"
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
      delay = 0
      insecure = true
      progress = true
      only_findings = false
      severity_filter : String? = nil
      save_path : String? = nil
      save_results = true
      fail_on_findings = false
      template_path : String? = nil

      ad_hoc_role : String? = nil
      ad_hoc_headers = {} of String => String
      ad_hoc_cookies = {} of String => String
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
        p.on("-o FORMAT", "--output FORMAT", "table|plain|json|markdown|sarif|html") { |v| output_name = v }
        p.on("--save FILE", "Also write the report to FILE") { |v| save_path = v }
        p.on("--no-save-results", "Don't archive results JSON in the session") { save_results = false }
        p.on("--only-findings", "Report only X (finding) / ? rows") { only_findings = true }
        p.on("--severity LEVEL", "Show only findings >= this severity (high|low)") do |v|
          s = v.downcase
          raise ValidationError.new("--severity must be 'high' or 'low': #{v}") unless ["high", "low"].includes?(s)
          severity_filter = s
        end
        p.on("--insecure", "Skip TLS verification (default)") { insecure = true }
        p.on("--secure", "Enforce TLS verification") { insecure = false }
        p.on("--no-progress", "Suppress live per-request progress") { progress = false }
        p.on("--fail-on-findings", "Exit non-zero when findings exist") { fail_on_findings = true }
        p.on("-r NAME", "--role NAME", "Ad-hoc role for an inline credential") { |v| ad_hoc_role = v }
        p.on("-H HEADER", "--header HEADER", "Header for the ad-hoc role (repeatable)") do |v|
          k, val = Validator.header!(v)
          ad_hoc_headers[k] = val
        end
        p.on("--cookie COOKIE", "Cookie for the ad-hoc role (repeatable)") do |v|
          k, val = Validator.cookie!(v)
          ad_hoc_cookies[k] = val
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
        creds = build_creds(parsed.creds, ad_hoc_role, ad_hoc_headers, ad_hoc_cookies)
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
        creds = build_creds(s.creds, ad_hoc_role, ad_hoc_headers, ad_hoc_cookies)
        source_label = "'#{s.name}'"
      end

      via = base_url.empty? ? "" : " via #{base_url}"
      Logger.info "scanning #{source_label} — #{targets.size} urls × #{creds_label(creds)}#{via}"
      Logger.warn "TLS verification disabled (--secure to enforce)" if insecure && !Logger.quiet?

      options = Scan::Options.new(
        concurrency: concurrency,
        timeout: timeout,
        proxy: proxy,
        insecure: insecure,
        delay_ms: delay,
        progress: progress && !Logger.quiet?,
      )
      scanner = Scan::Scanner.new(options)
      results = scanner.run(targets, creds, asserts, base_url)

      # Summary + archive always reflect the FULL scan; --only-findings /
      # --severity only narrow what's *displayed*.
      summary = Report::Summary.new(results)

      display = results
      display = display.reject { |r| r.verdict == "O" } if only_findings
      if sev = severity_filter
        display = sev == "high" ? display.select(&.unauthorized?) : display.select(&.vulnerable?)
      end

      # Report → stdout. Color only for the interactive table.
      color = format.table? && STDOUT.tty? && Logger.color_enabled?
      puts Report.render(display, format, color)

      # Archive a structured copy inside the session unless told not to.
      if save_results && (s = session)
        archive_results(s, results)
      end
      if path = save_path
        File.write(path, Report.render(display, format, false))
        Logger.success "report written to #{path}"
      end

      if summary.findings > 0
        if summary.unauthorized > 0
          extra = summary.over_restrictive > 0 ? " (+#{summary.over_restrictive} over-restrictive)" : ""
          Logger.error "#{summary.unauthorized} unauthorized-access finding#{summary.unauthorized == 1 ? "" : "s"}#{extra} — review the red rows"
        else
          Logger.warn "#{summary.over_restrictive} over-restrictive finding#{summary.over_restrictive == 1 ? "" : "s"} (no unauthorized access) — likely a broken/over-tight policy"
        end
        exit 1 if fail_on_findings
      else
        Logger.success "no authorization findings"
      end
    end

    # Session credentials plus an optional inline (-r/-H/--cookie) identity.
    private def build_creds(session_creds, role, headers, cookies) : Array(Credential)
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
      creds
    end

    private def archive_results(session, results)
      FileUtils.mkdir_p(session.results_dir)
      stamp = Time.utc.to_s("%Y%m%dT%H%M%SZ")
      path = File.join(session.results_dir, "#{stamp}.json")
      File.write(path, Report.render(results, Report::Format::Json, false))
      Logger.debug "results archived to #{path}"
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
