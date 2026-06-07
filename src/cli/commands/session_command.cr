require "option_parser"
require "json"
require "../helpers"
require "../../store/session_store"
require "../../utils/errors"
require "../../utils/logger"
require "../../utils/runtime"
require "../../utils/masking"
require "../../utils/secure_file"
require "../../utils/validator"

module Authz0::CLI
  # `authz0 session <new|list|show|delete|rename|clone>` — lifecycle of test
  # projects (directories under ~/.authz0/sessions/).
  class SessionCommand
    include Helpers

    USAGE = <<-USAGE
    Usage: authz0 session <action> [options]

    Actions:
      new <name> --base-url <url> [--description <text>]   Create a session
      list [--json]                                        List all sessions
      show <name> [--json]                                 Show one session's details
      set <name> [--base-url <url>] [--description <text>] Update a session
      delete <name> [-y]                                   Delete a session
      rename <old> <new>                                   Rename a session
      clone <source> <target>                              Copy a session
      use <name> | --clear                                 Set the default session for other commands
      backup <name> <file> [--redact]                      Save a session to one JSON file
      restore <file> [--name <name>]                       Recreate a session from a backup file

    (`backup`/`restore` were `export`/`import`; the old names still work. They
    move a WHOLE session as one file — distinct from the top-level `import`
    <type> / `export yaml`, which move endpoints/templates in and out.)
    USAGE

    def run(args : Array(String))
      action = args.shift?
      case action
      when "new", "create", "add"   then new_session(args)
      when "list", "ls"             then list(args)
      when "show", "info"           then show(args)
      when "set", "update"          then set_session(args)
      when "delete", "rm", "remove" then delete(args)
      when "rename"                 then rename(args)
      when "clone"                  then clone(args)
      when "use"                    then use_session(args)
      when "backup"                 then export_session(args)
      when "restore"                then import_session(args)
      when "export" # renamed → backup; kept so existing scripts don't break
        deprecate("session export", "session backup")
        export_session(args)
      when "import" # renamed → restore
        deprecate("session import", "session restore")
        import_session(args)
      when nil, "-h", "--help"
        puts USAGE
      else
        raise ValidationError.new("unknown session action: #{action}", "see `authz0 session --help`")
      end
    end

    # One-line nudge when a deprecated action alias is used.
    private def deprecate(old : String, replacement : String)
      Logger.warn "'#{old}' was renamed to '#{replacement}' — the old name still works for now" unless Logger.quiet?
    end

    # `session use <name>` sets the default session that url/cred/assert/scan/
    # results fall back to when you don't name one; `--clear` removes it; with
    # no name it prints the current default.
    private def use_session(args)
      clear = false
      positional = [] of String
      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 session use <name> | --clear"
        p.on("--clear", "Clear the active session") { clear = true }
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, _| positional = before }
      end
      if clear
        Store::SessionStore.clear_current
        Logger.success "cleared the active session"
        return
      end
      name = positional.first?
      if name.nil?
        if cur = Store::SessionStore.current
          Logger.info "active session: #{cur}"
        else
          Logger.info "no active session — set one with `authz0 session use <name>`"
        end
        return
      end
      Logger.success "active session → #{Store::SessionStore.use(name)}"
    end

    private def set_session(args)
      base_url : String? = nil
      description : String? = nil
      name : String? = nil
      seen = Set(String).new
      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 session set <name> [--base-url <url>] [--description <text>]"
        p.on("--base-url URL", "Change the base URL") { |v| base_url = Validator.base_url!(v); seen << "base_url" }
        p.on("--description TEXT", "Change the description") { |v| description = v; seen << "description" }
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, _| name = before.first? }
      end
      session = open_session(name)
      raise ValidationError.new("nothing to update", "pass --base-url and/or --description") if seen.empty?
      session.meta.base_url = base_url.not_nil! if seen.includes?("base_url")
      session.meta.description = description if seen.includes?("description")
      session.touch!
      Logger.success "updated session '#{session.name}'"
    end

    private def new_session(args)
      base_url : String? = nil
      description : String? = nil
      name : String? = nil
      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 session new <name> --base-url <url> [--description <text>]"
        p.on("--base-url URL", "Base URL paths resolve against (required)") { |v| base_url = v }
        p.on("--description TEXT", "Human description of this session") { |v| description = v }
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, _| name = before.first? }
      end
      raise ValidationError.new("missing <name> argument") if name.nil?
      raise ValidationError.new("--base-url is required", "e.g. --base-url https://api.example.com") if base_url.nil?

      session = Store::SessionStore.create(name.not_nil!, base_url.not_nil!, description)
      Logger.success "created session '#{session.name}' (#{session.meta.base_url})"
      Logger.info "  #{session.dir}"
      Logger.warn "creds.json stores credentials in plaintext (chmod 600) — keep this directory private" unless Logger.quiet?
    end

    private def list(args)
      json_mode = false
      names_only = false
      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 session list [--json] [--names]"
        p.on("--json", "Output as JSON") { json_mode = true }
        p.on("--names", "Print only session names, one per line (scripts/completion)") { names_only = true }
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
      end

      sessions = Store::SessionStore.list
      # Plain names for shell completion / scripting — no markers, no chatter,
      # empty output when there are none.
      if names_only
        sessions.each { |s| puts s.name }
        return
      end
      if json_mode
        puts sessions.map(&.meta).to_pretty_json
        return
      end

      if sessions.empty?
        Logger.info "no sessions yet — create one with `authz0 session new <name> --base-url <url>`"
        return
      end
      # Mark the active session ("session use") with * so an implicit default
      # is never a surprise.
      active = Store::SessionStore.current
      sessions.each do |s|
        marker = s.name == active ? "* " : "  "
        puts "#{marker}#{s.name}  (#{s.meta.base_url})  urls=#{s.urls.size} creds=#{s.creds.size}"
      end
    end

    private def show(args)
      json_mode = false
      name : String? = nil
      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 session show <name> [--json]"
        p.on("--json", "Output as JSON") { json_mode = true }
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, _| name = before.first? }
      end
      session = open_session(name)

      if json_mode
        puts({
          "meta"    => session.meta,
          "urls"    => session.urls.size,
          "creds"   => session.creds.map(&.role),
          "asserts" => session.asserts,
        }.to_pretty_json)
        return
      end

      m = session.meta
      print_kv([
        {"name", m.name},
        {"base_url", m.base_url},
        {"description", m.description || "-"},
        {"created", m.created_at.to_s},
        {"updated", m.updated_at.to_s},
        {"urls", session.urls.size.to_s},
        {"creds", session.creds.map(&.display_role).join(", ").presence || "-"},
        {"asserts", session.asserts.size.to_s},
        {"last_scan", last_scan(session) || "-"},
        {"path", session.dir},
      ])
      Logger.warn "creds.json is world-readable — run `chmod 600 #{session.creds_path}`" if session.creds_world_readable?
    end

    # Summarize the most recent archived scan (timestamp + finding counts), or
    # nil if the session has never been scanned.
    private def last_scan(session) : String?
      latest = session.latest_result_file
      return nil if latest.nil?
      doc = JSON.parse(File.read(latest))
      s = doc["summary"]?
      return nil if s.nil?
      findings = s["findings"]?.try(&.as_i?) || 0
      unauth = s["unauthorized"]?.try(&.as_i?) || 0
      "#{File.basename(latest, ".json")}  (#{findings} findings, #{unauth} unauthorized)"
    rescue
      nil
    end

    private def delete(args)
      name : String? = nil
      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 session delete <name> [-y]"
        p.on("-y", "--yes", "Skip confirmation") { Runtime.assume_yes = true }
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, _| name = before.first? }
      end
      raise ValidationError.new("missing <name> argument") if name.nil?
      unless Store::SessionStore.exists?(name.not_nil!)
        raise NotFoundError.new("no such session: #{name}")
      end
      unless Runtime.confirm?("delete session '#{name}' and all its data?")
        Logger.info "aborted"
        return
      end
      Store::SessionStore.delete(name.not_nil!)
      Logger.success "deleted session '#{name}'"
    end

    private def rename(args)
      positional = [] of String
      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 session rename <old> <new>"
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, _| positional = before }
      end
      raise ValidationError.new("usage: authz0 session rename <old> <new>") if positional.size < 2
      session = Store::SessionStore.rename(positional[0], positional[1])
      Logger.success "renamed '#{positional[0]}' → '#{session.name}'"
    end

    private def clone(args)
      positional = [] of String
      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 session clone <source> <target>"
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, _| positional = before }
      end
      raise ValidationError.new("usage: authz0 session clone <source> <target>") if positional.size < 2
      session = Store::SessionStore.clone(positional[0], positional[1])
      Logger.success "cloned '#{positional[0]}' → '#{session.name}'"
    end

    private def export_session(args)
      redact = false
      positional = [] of String
      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 session backup <name> <file> [--redact]"
        p.on("--redact", "Mask credential values (shareable, not runnable)") { redact = true }
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, _| positional = before }
      end
      session = open_session(positional[0]?)
      file = positional[1]?
      raise ValidationError.new("missing <file> argument", "use '-' for stdout") if file.nil?
      if file != "-"
        dir = File.dirname(file)
        raise ValidationError.new("output directory does not exist: #{dir}") unless dir.empty? || File.directory?(dir)
      end

      bundle = JSON.build(indent: "  ") do |json|
        json.object do
          json.field "version", Authz0::VERSION
          json.field "name", session.name
          json.field "base_url", session.meta.base_url
          json.field "description", session.meta.description
          json.field "urls" { session.urls.to_json(json) }
          json.field "asserts" { session.asserts.to_json(json) }
          json.field "creds" do
            json.array do
              session.creds.each do |c|
                json.object do
                  json.field "role", c.role
                  json.field "auth_type", c.auth_type
                  json.field "headers" do
                    json.object { c.headers.each { |k, v| json.field k, redact ? Masking.mask(v) : v } }
                  end
                  json.field "cookies" do
                    json.object { c.cookies.each { |k, v| json.field k, redact ? Masking.mask(v) : v } }
                  end
                end
              end
            end
          end
        end
      end

      if file == "-"
        print bundle
      else
        has_secrets = !redact && session.creds.any? { |c| !c.headers.empty? || !c.cookies.empty? }
        # A bundle carrying plaintext credentials must not land world-readable,
        # matching creds.json's chmod-600 treatment.
        if has_secrets
          SecureFile.write_private(file, bundle + "\n")
        else
          File.write(file, bundle + "\n")
        end
        Logger.success "backed up '#{session.name}' → #{file}"
        Logger.warn "bundle contains plaintext credentials (written chmod 600) — keep it private, or use --redact to mask" if has_secrets
      end
    end

    private def import_session(args)
      name_override : String? = nil
      positional = [] of String
      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 session restore <file> [--name <name>]"
        # Validate at parse time so `--name ""` fails fast with a clear message
        # (not an ambiguous "session name is empty" later).
        p.on("--name NAME", "Import under this name (instead of the bundle's)") { |v| name_override = Validator.session_name!(v) }
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, _| positional = before }
      end
      file = positional[0]?
      raise ValidationError.new("missing <file> argument") if file.nil?
      content = file == "-" ? STDIN.gets_to_end : File.read(file)
      raise ValidationError.new("session bundle is not valid UTF-8 text") unless content.valid_encoding?

      doc = JSON.parse(content)
      name = name_override || doc["name"]?.try(&.as_s?)
      base_url = doc["base_url"]?.try(&.as_s?)
      raise ValidationError.new("bundle is missing 'name' or 'base_url'") if name.nil? || base_url.nil?
      description = doc["description"]?.try(&.as_s?)

      # Deserialize everything BEFORE creating the session, so a schema error
      # (valid JSON, wrong shape) aborts with nothing written rather than
      # leaving an empty half-imported session that blocks a retry.
      urls = Array(TargetURL).from_json(bundle_array(doc, "urls"))
      creds = Array(Credential).from_json(bundle_array(doc, "creds"))
      asserts = Array(Assertion).from_json(bundle_array(doc, "asserts"))

      session = Store::SessionStore.create(name, base_url, description)
      session.save_urls(urls)
      session.save_creds(creds)
      session.save_asserts(asserts)
      Logger.success "restored session '#{session.name}' (#{session.urls.size} urls, #{session.creds.size} creds)"
      if creds.any? { |c| masked_credential?(c) }
        Logger.warn "this bundle appears to have been exported with --redact — credential values are masked and will NOT authenticate; set real values with `authz0 cred update #{session.name} <role> --header ...`"
      end
    rescue ex : JSON::ParseException
      raise ValidationError.new("session bundle is not valid JSON or does not match the expected schema: #{ex.message}")
    end

    # Heuristic: does this credential carry masked placeholder values (from a
    # --redact export)? Masking uses a U+2026 ellipsis or an all-asterisks run.
    private def masked_credential?(cred : Credential) : Bool
      (cred.headers.values + cred.cookies.values).any? do |v|
        v.includes?('…') || (!v.empty? && v.matches?(/\A\*+\z/))
      end
    end

    # Re-serialize a bundle array field as JSON, tolerating a missing or null
    # value (a JSON `null` becomes a truthy JSON::Any, so the bare `?` isn't
    # enough — use as_a? to fall back to an empty array).
    private def bundle_array(doc : JSON::Any, key : String) : String
      arr = doc[key]?.try(&.as_a?)
      arr ? arr.to_json : "[]"
    end
  end
end
