require "option_parser"
require "json"
require "../helpers"
require "../../store/session_store"
require "../../utils/errors"
require "../../utils/logger"
require "../../utils/runtime"
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
    USAGE

    def run(args : Array(String))
      action = args.shift?
      case action
      when "new", "create" then new_session(args)
      when "list", "ls"    then list(args)
      when "show", "info"  then show(args)
      when "set", "update" then set_session(args)
      when "delete", "rm"  then delete(args)
      when "rename"        then rename(args)
      when "clone"         then clone(args)
      when nil, "-h", "--help"
        puts USAGE
      else
        raise ValidationError.new("unknown session action: #{action}", "see `authz0 session --help`")
      end
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
      Logger.warn "creds.json stores credentials in plaintext (chmod 600) — keep this directory private"
    end

    private def list(args)
      json_mode = false
      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 session list [--json]"
        p.on("--json", "Output as JSON") { json_mode = true }
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
      end

      sessions = Store::SessionStore.list
      if json_mode
        puts sessions.map(&.meta).to_pretty_json
        return
      end

      if sessions.empty?
        Logger.info "no sessions yet — create one with `authz0 session new <name> --base-url <url>`"
        return
      end
      sessions.each do |s|
        urls = s.urls.size
        creds = s.creds.size
        puts "#{s.name}  (#{s.meta.base_url})  urls=#{urls} creds=#{creds}"
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
      dir = session.results_dir
      return nil unless File.directory?(dir)
      latest = Dir.glob(File.join(dir, "*.json")).sort.last?
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
  end
end
