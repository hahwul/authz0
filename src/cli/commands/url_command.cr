require "option_parser"
require "json"
require "../helpers"
require "../../models/target_url"
require "../../utils/errors"
require "../../utils/logger"
require "../../utils/runtime"
require "../../utils/validator"

module Authz0::CLI
  # `authz0 url <add|list|show|update|remove>` — manage endpoints under test.
  class UrlCommand
    include Helpers

    USAGE = <<-USAGE
    Usage: authz0 url <action> [options]

    Actions:
      add <session> <path> [options]      Add an endpoint
      list <session> [--role R] [--json]  List endpoints
      show <session> <id> [--json]        Show one endpoint
      update <session> <id> [options]     Modify an endpoint
      remove <session> <id|pattern> [-y]  Remove endpoint(s)

    Add/update options:
      --method M           HTTP method (default GET)
      --body TEXT          Request body
      --content-type T     json | form
      --allow-role R[,R]   Roles allowed (repeatable)
      --deny-role R[,R]    Roles denied (repeatable)
      --header "K: V"      Per-request header (repeatable)
      --alias TEXT         Display label
      --tag T[,T]          Tags (repeatable)
    USAGE

    def run(args : Array(String))
      action = args.shift?
      case action
      when "add"           then add(args)
      when "list", "ls"    then list(args)
      when "show", "info"  then show(args)
      when "update", "set" then update(args)
      when "remove", "rm"  then remove(args)
      when nil, "-h", "--help"
        puts USAGE
      else
        raise ValidationError.new("unknown url action: #{action}", "see `authz0 url --help`")
      end
    end

    # Shared flag set for add/update. Returns the parsed values plus the set
    # of flags actually supplied (so update only touches those).
    private record UrlOpts,
      method : String?,
      body : String?,
      content_type : String?,
      allow_roles : Array(String),
      deny_roles : Array(String),
      headers : Hash(String, String),
      alias_label : String?,
      tags : Array(String),
      seen : Set(String),
      positional : Array(String)

    private def parse_url_opts(args, banner) : UrlOpts
      method : String? = nil
      body : String? = nil
      content_type : String? = nil
      allow_roles = [] of String
      deny_roles = [] of String
      headers = {} of String => String
      alias_label : String? = nil
      tags = [] of String
      seen = Set(String).new
      positional = [] of String

      OptionParser.parse(args) do |p|
        p.banner = banner
        p.on("--method M", "HTTP method") { |v| method = Validator.http_method!(v); seen << "method" }
        p.on("--body TEXT", "Request body") { |v| body = v; seen << "body" }
        p.on("--content-type T", "json | form") { |v| content_type = v; seen << "content_type" }
        p.on("--allow-role R", "Roles allowed (repeatable, comma-ok)") { |v| allow_roles.concat(Validator.csv(v)); seen << "allow_roles" }
        p.on("--deny-role R", "Roles denied (repeatable, comma-ok)") { |v| deny_roles.concat(Validator.csv(v)); seen << "deny_roles" }
        p.on("--header HEADER", "Header 'K: V' (repeatable)") do |v|
          k, val = Validator.header!(v)
          headers[k] = val
          seen << "headers"
        end
        p.on("--alias TEXT", "Display label") { |v| alias_label = v; seen << "alias" }
        p.on("--tag T", "Tags (repeatable, comma-ok)") { |v| tags.concat(Validator.csv(v)); seen << "tags" }
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, after| positional = before + after }
      end

      UrlOpts.new(method, body, content_type, allow_roles.uniq, deny_roles.uniq,
        headers, alias_label, tags.uniq, seen, positional)
    end

    private def add(args)
      o = parse_url_opts(args, "Usage: authz0 url add <session> <path> [options]")
      session = open_session(o.positional[0]?)
      path = o.positional[1]?
      raise ValidationError.new("missing <path> argument") if path.nil? || path.empty?

      target = TargetURL.new(
        path: path,
        method: o.method || "GET",
        body: o.body,
        content_type: o.content_type,
        allow_roles: o.allow_roles,
        deny_roles: o.deny_roles,
        headers: o.headers,
        tags: o.tags,
        alias: o.alias_label,
      )
      urls = session.urls
      if urls.any? { |u| u.id == target.id }
        raise ConflictError.new("that endpoint is already in the session (#{target.id})")
      end
      urls << target
      session.save_urls(urls)
      Logger.success "added [#{target.id}] #{target.method} #{target.path}"
    end

    private def list(args)
      role : String? = nil
      json_mode = false
      positional = [] of String
      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 url list <session> [--role R] [--json]"
        p.on("--role R", "Only endpoints that name this role") { |v| role = v }
        p.on("--json", "Output as JSON") { json_mode = true }
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, _| positional = before }
      end
      session = open_session(positional[0]?)
      urls = session.urls
      if r = role
        urls = urls.select { |u| u.allow_roles.includes?(r) || u.deny_roles.includes?(r) }
      end

      if json_mode
        puts urls.to_pretty_json
        return
      end
      if urls.empty?
        Logger.info "no urls — add one with `authz0 url add #{session.name} <path>`"
        return
      end
      urls.each_with_index do |u, i|
        allow = u.allow_roles.empty? ? "<all>" : u.allow_roles.join(",")
        deny = u.deny_roles.empty? ? "-" : u.deny_roles.join(",")
        label = u.alias && !u.alias.try(&.empty?) ? " (#{u.alias})" : ""
        puts "##{i}  [#{u.id}]  #{u.method.ljust(6)} #{u.path}#{label}  allow=#{allow} deny=#{deny}"
      end
    end

    private def show(args)
      json_mode = false
      positional = [] of String
      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 url show <session> <id> [--json]"
        p.on("--json", "Output as JSON") { json_mode = true }
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, _| positional = before }
      end
      session = open_session(positional[0]?)
      id = positional[1]?
      raise ValidationError.new("missing <id> argument") if id.nil?
      url = session.find_url(id)
      raise NotFoundError.new("no url matching '#{id}' in session '#{session.name}'") if url.nil?

      if json_mode
        puts url.to_pretty_json
        return
      end
      print_kv([
        {"id", url.id},
        {"method", url.method},
        {"path", url.path},
        {"resolved", url.resolve(session.meta.base_url)},
        {"body", url.body || "-"},
        {"content_type", url.content_type || "-"},
        {"allow_roles", url.allow_roles.join(", ").presence || "<all>"},
        {"deny_roles", url.deny_roles.join(", ").presence || "-"},
        {"headers", url.headers.map { |k, v| "#{k}: #{v}" }.join(", ").presence || "-"},
        {"tags", url.tags.join(", ").presence || "-"},
        {"alias", url.alias || "-"},
      ])
    end

    private def update(args)
      o = parse_url_opts(args, "Usage: authz0 url update <session> <id> [options]")
      session = open_session(o.positional[0]?)
      id = o.positional[1]?
      raise ValidationError.new("missing <id> argument") if id.nil?
      urls = session.urls
      idx = urls.index { |u| u.id == id } || index_from_token(urls, id)
      raise NotFoundError.new("no url matching '#{id}' in session '#{session.name}'") if idx.nil?
      url = urls[idx]

      url.method = o.method.not_nil! if o.seen.includes?("method")
      url.body = o.body if o.seen.includes?("body")
      url.content_type = o.content_type if o.seen.includes?("content_type")
      url.allow_roles = o.allow_roles if o.seen.includes?("allow_roles")
      url.deny_roles = o.deny_roles if o.seen.includes?("deny_roles")
      url.alias = o.alias_label if o.seen.includes?("alias")
      url.tags = o.tags if o.seen.includes?("tags")
      o.headers.each { |k, v| url.headers[k] = v } if o.seen.includes?("headers")

      # Re-key the id when the request shape changed so it stays stable.
      url.id = ShortId.for(url.method, url.path, url.body || "")
      urls[idx] = url
      session.save_urls(urls)
      Logger.success "updated [#{url.id}] #{url.method} #{url.path}"
    end

    private def remove(args)
      positional = [] of String
      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 url remove <session> <id|pattern> [-y]"
        p.on("-y", "--yes", "Skip confirmation") { Runtime.assume_yes = true }
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, _| positional = before }
      end
      session = open_session(positional[0]?)
      token = positional[1]?
      raise ValidationError.new("missing <id|pattern> argument") if token.nil?

      urls = session.urls
      victims = match_urls(urls, token)
      raise NotFoundError.new("no url matching '#{token}' in session '#{session.name}'") if victims.empty?

      if victims.size > 1
        unless Runtime.confirm?("remove #{victims.size} urls matching '#{token}'?")
          Logger.info "aborted"
          return
        end
      end
      victim_ids = victims.map(&.id).to_set
      session.save_urls(urls.reject { |u| victim_ids.includes?(u.id) })
      Logger.success "removed #{victims.size} url#{victims.size == 1 ? "" : "s"}"
    end

    # Match by exact id, "#N" index, or a glob over the path.
    private def match_urls(urls : Array(TargetURL), token : String) : Array(TargetURL)
      if u = urls.find { |x| x.id == token }
        return [u]
      end
      if idx = index_from_token(urls, token)
        return [urls[idx]]
      end
      if token.includes?('*') || token.includes?('?')
        pattern = token
        return urls.select { |u| File.match?(pattern, u.path) }
      end
      [] of TargetURL
    end

    private def index_from_token(urls : Array(TargetURL), token : String) : Int32?
      t = token.lstrip('#')
      if idx = t.to_i?
        return idx if idx >= 0 && idx < urls.size
      end
      nil
    end
  end
end
