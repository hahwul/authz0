require "option_parser"
require "json"
require "base64"
require "../helpers"
require "../../models/credential"
require "../../utils/errors"
require "../../utils/logger"
require "../../utils/masking"
require "../../utils/runtime"
require "../../utils/validator"

module Authz0::CLI
  # `authz0 cred <add|list|remove|update>` — manage the authenticated
  # identities ("roles") used to probe each endpoint. Stored in creds.json
  # (chmod 600). Values are masked everywhere except `cred list --reveal`.
  #
  # Secret hygiene: a header/cookie value of "env:NAME" is read from the
  # environment variable NAME at add time, so tokens needn't appear in shell
  # history or process listings.
  class CredCommand
    include Helpers

    USAGE = <<-USAGE
    Usage: authz0 cred <action> [options]

    Actions:
      add <session> <role> [options]   Add/append a credential
      list <session> [--json] [--reveal]
      update <session> <role> [options]
      remove <session> <role>

    Options:
      --header "K: V"   Auth header (repeatable). Value "env:NAME" reads $NAME.
      --cookie "k=v"    Cookie (repeatable). Value "env:NAME" reads $NAME.
      --basic user:pass Set HTTP Basic auth (Authorization: Basic …)
      --from-curl CURL  Import headers + cookies from a 'copy as cURL' string
      --from-har FILE   Extract auth headers + cookies from a HAR capture
      --auth-type T     Informational label (bearer/cookie/apikey/…)
    USAGE

    def run(args : Array(String))
      action = args.shift?
      case action
      when "add"                    then add(args)
      when "list", "ls"             then list(args)
      when "update", "set"          then update(args)
      when "remove", "rm", "delete" then remove(args)
      when nil, "-h", "--help"
        puts USAGE
      else
        raise ValidationError.new("unknown cred action: #{action}", "see `authz0 cred --help`")
      end
    end

    private record CredOpts,
      headers : Hash(String, String),
      cookies : Hash(String, String),
      auth_type : String?,
      seen : Set(String),
      positional : Array(String)

    private def parse_cred_opts(args, banner) : CredOpts
      headers = {} of String => String
      cookies = {} of String => String
      auth_type : String? = nil
      seen = Set(String).new
      positional = [] of String

      OptionParser.parse(args) do |p|
        p.banner = banner
        p.on("--header HEADER", "Auth header 'K: V' (repeatable)") do |v|
          k, val = Validator.header!(v)
          headers[k] = resolve_env(val)
          seen << "headers"
        end
        p.on("--cookie COOKIE", "Cookie 'k=v' (repeatable)") do |v|
          k, val = Validator.cookie!(v)
          cookies[k] = resolve_env(val)
          seen << "cookies"
        end
        p.on("--basic USER:PASS", "Set HTTP Basic auth (Authorization: Basic …)") do |v|
          idx = v.index(':')
          raise ValidationError.new("--basic expects user:pass") unless idx
          user = v[0...idx]
          pass = resolve_env(v[(idx + 1)..])
          headers["Authorization"] = "Basic #{Base64.strict_encode("#{user}:#{pass}")}"
          seen << "headers"
        end
        p.on("--from-curl CURL", "Import headers + cookies from a 'copy as cURL' command") do |v|
          parsed = CurlParser.parse(v)
          parsed.headers.each { |k, val| headers[k] = val; seen << "headers" }
          parsed.cookies.each { |k, val| cookies[k] = val; seen << "cookies" }
          if parsed.headers.empty? && parsed.cookies.empty?
            raise ValidationError.new("no -H/--header or -b/--cookie found in the curl command")
          end
        end
        p.on("--from-har FILE", "Extract auth headers + cookies from a HAR capture") do |v|
          creds = Importers::Har.new.credentials_from_file(v)
          creds.headers.each { |k, val| headers[k] = val; seen << "headers" }
          creds.cookies.each { |k, val| cookies[k] = val; seen << "cookies" }
          raise ValidationError.new("no auth headers/cookies found in #{v}") if creds.empty?
        end
        p.on("--auth-type T", "Informational auth label") { |v| auth_type = v; seen << "auth_type" }
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, after| positional = before + after }
      end
      CredOpts.new(headers, cookies, auth_type, seen, positional)
    end

    # Resolve secrets from the environment so tokens needn't appear in shell
    # history or process args. Two forms:
    #   * whole value "env:NAME"          → ENV["NAME"]
    #   * embedded "${NAME}" interpolation → substituted anywhere in the value
    # Single-quote the value in your shell so it doesn't expand ${NAME} itself.
    private def resolve_env(value : String) : String
      if value.starts_with?("env:")
        return env_or_raise(value[4..])
      end
      value.gsub(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/) do
        env_or_raise($1)
      end
    end

    private def env_or_raise(name : String) : String
      ENV[name]? || raise ValidationError.new("environment variable not set: #{name}")
    end

    private def add(args)
      o = parse_cred_opts(args, "Usage: authz0 cred add <session> <role> [options]")
      session = open_session(o.positional[0]?)
      role = o.positional[1]?
      raise ValidationError.new("missing <role> argument") if role.nil? || role.empty?

      creds = session.creds
      if existing = creds.find { |c| c.role == role }
        # Append/merge onto the existing role rather than erroring — the
        # incremental "add another header" flow is the common case.
        o.headers.each { |k, v| existing.headers[k] = v }
        o.cookies.each { |k, v| existing.cookies[k] = v }
        existing.auth_type = o.auth_type if o.seen.includes?("auth_type")
        session.save_creds(creds)
        Logger.success "updated credential '#{role}' (#{existing.headers.size} headers, #{existing.cookies.size} cookies)"
      else
        cred = Credential.new(role.not_nil!, headers: o.headers, cookies: o.cookies, auth_type: o.auth_type)
        creds << cred
        session.save_creds(creds)
        Logger.success "added credential '#{role}' (#{cred.headers.size} headers, #{cred.cookies.size} cookies)"
      end
      # Advisory, not a problem to fix — keep it out of -q/CI logs.
      Logger.warn "secrets stored in plaintext at #{session.creds_path} (chmod 600)" unless Logger.quiet?
    end

    private def update(args)
      o = parse_cred_opts(args, "Usage: authz0 cred update <session> <role> [options]")
      session = open_session(o.positional[0]?)
      role = o.positional[1]?
      raise ValidationError.new("missing <role> argument") if role.nil?
      creds = session.creds
      cred = creds.find { |c| c.role == role }
      raise NotFoundError.new("no credential for role '#{role}' in session '#{session.name}'") if cred.nil?

      # update replaces the named collections wholesale (vs add's merge).
      cred.headers = o.headers if o.seen.includes?("headers")
      cred.cookies = o.cookies if o.seen.includes?("cookies")
      cred.auth_type = o.auth_type if o.seen.includes?("auth_type")
      session.save_creds(creds)
      Logger.success "updated credential '#{role}'"
    end

    private def list(args)
      json_mode = false
      reveal = false
      positional = [] of String
      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 cred list <session> [--json] [--reveal]"
        p.on("--json", "Output as JSON (masked unless --reveal)") { json_mode = true }
        p.on("--reveal", "Show secret values in full (dangerous)") { reveal = true }
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, _| positional = before }
      end
      session = open_session(positional[0]?)
      creds = session.creds

      if json_mode
        puts creds_json(creds, reveal)
        return
      end
      if creds.empty?
        Logger.info "no credentials — add one with `authz0 cred add #{session.name} <role> --header \"K: V\"`"
        return
      end
      creds.each do |c|
        puts "#{c.display_role}#{c.auth_type ? " (#{c.auth_type})" : ""}"
        c.headers.each { |k, v| puts "  header  #{reveal ? "#{k}: #{v}" : Masking.mask_header(k, v)}" }
        c.cookies.each { |k, v| puts "  cookie  #{k}=#{reveal ? v : Masking.mask(v)}" }
      end
    end

    private def remove(args)
      positional = [] of String
      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 cred remove <session> <role>"
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, _| positional = before }
      end
      session = open_session(positional[0]?)
      role = positional[1]?
      raise ValidationError.new("missing <role> argument") if role.nil?
      creds = session.creds
      unless creds.any? { |c| c.role == role }
        raise NotFoundError.new("no credential for role '#{role}' in session '#{session.name}'")
      end
      session.save_creds(creds.reject { |c| c.role == role })
      Logger.success "removed credential '#{role}'"
    end

    private def creds_json(creds : Array(Credential), reveal : Bool) : String
      JSON.build(indent: "  ") do |json|
        json.array do
          creds.each do |c|
            json.object do
              json.field "role", c.role
              json.field "auth_type", c.auth_type
              json.field "headers" do
                json.object do
                  c.headers.each { |k, v| json.field k, reveal ? v : Masking.mask(v) }
                end
              end
              json.field "cookies" do
                json.object do
                  c.cookies.each { |k, v| json.field k, reveal ? v : Masking.mask(v) }
                end
              end
            end
          end
        end
      end
    end
  end
end
