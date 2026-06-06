require "option_parser"
require "json"
require "../helpers"
require "../../models/assertion"
require "../../utils/errors"
require "../../utils/logger"
require "../../utils/validator"

module Authz0::CLI
  # `authz0 assert <add|list|remove>` — the access-detection rules a scan uses
  # to decide whether a response means "accessed". See Scan::Asserter for the
  # evaluation semantics (negative signals win).
  class AssertCommand
    include Helpers

    USAGE = <<-USAGE
    Usage: authz0 assert <action> [options]

    Actions:
      add <session> [rule options]   Add one or more detection rules
      list <session> [--json]        List rules
      remove <session> <index|type>  Remove rule(s)

    Rule options (each adds a rule; repeatable):
      --success-status "200,201,204"   Codes that mean accessible
      --fail-status 403                Code that means NOT accessible
      --fail-regex "Access denied"     Body match means NOT accessible
      --fail-size 1234                 ~byte size that means NOT accessible
      --fail-size-margin 50            Tolerance for --fail-size
      --type T --value V               Generic rule
    USAGE

    def run(args : Array(String))
      action = args.shift?
      case action
      when "add"          then add(args)
      when "list", "ls"   then list(args)
      when "remove", "rm" then remove(args)
      when nil, "-h", "--help"
        puts USAGE
      else
        raise ValidationError.new("unknown assert action: #{action}", "see `authz0 assert --help`")
      end
    end

    private def add(args)
      rules = [] of Assertion
      generic_type : String? = nil
      generic_value : String? = nil
      positional = [] of String

      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 assert add <session> [rule options]"
        p.on("--success-status LIST", "Codes that mean accessible") do |v|
          Validator.status_list!(v) # validate
          rules << Assertion.new("success-status", v)
        end
        p.on("--fail-status CODE", "Code that means NOT accessible") do |v|
          Validator.status_list!(v)
          rules << Assertion.new("fail-status", v)
        end
        p.on("--fail-regex PATTERN", "Body match means NOT accessible") do |v|
          rules << Assertion.new("fail-regex", v)
        end
        p.on("--fail-size N", "~byte size that means NOT accessible") do |v|
          raise ValidationError.new("--fail-size must be a number: #{v}") unless v.to_i64?
          rules << Assertion.new("fail-size", v)
        end
        p.on("--fail-size-margin N", "Tolerance for --fail-size") do |v|
          raise ValidationError.new("--fail-size-margin must be a number: #{v}") unless v.to_i64?
          rules << Assertion.new("fail-size-margin", v)
        end
        p.on("--type T", "Generic rule type") { |v| generic_type = v }
        p.on("--value V", "Generic rule value") { |v| generic_value = v }
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, _| positional = before }
      end

      session = open_session(positional[0]?)

      if generic_type || generic_value
        raise ValidationError.new("--type and --value must be given together") unless generic_type && generic_value
        rules << Assertion.new(generic_type.not_nil!, generic_value.not_nil!)
      end
      raise ValidationError.new("no rules given", "e.g. --success-status 200,201") if rules.empty?

      asserts = session.asserts
      added = 0
      rules.each do |rule|
        Logger.warn "unknown assert type '#{rule.type}' — it will be ignored by scan" unless rule.valid_type?
        # De-dupe identical rules.
        next if asserts.any? { |a| a.type == rule.type && a.value == rule.value }
        asserts << rule
        added += 1
      end
      session.save_asserts(asserts)
      Logger.success "added #{added} assert rule#{added == 1 ? "" : "s"} (#{asserts.size} total)"
    end

    private def list(args)
      json_mode = false
      positional = [] of String
      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 assert list <session> [--json]"
        p.on("--json", "Output as JSON") { json_mode = true }
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, _| positional = before }
      end
      session = open_session(positional[0]?)
      asserts = session.asserts
      if json_mode
        puts asserts.to_pretty_json
        return
      end
      if asserts.empty?
        Logger.info "no assert rules — scan will use the 2xx=accessible default"
        return
      end
      asserts.each_with_index do |a, i|
        puts "##{i}  #{a.type} = #{a.value}"
      end
    end

    private def remove(args)
      positional = [] of String
      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 assert remove <session> <index|type>"
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, _| positional = before }
      end
      session = open_session(positional[0]?)
      token = positional[1]?
      raise ValidationError.new("missing <index|type> argument") if token.nil?
      asserts = session.asserts

      if idx = token.lstrip('#').to_i?
        raise NotFoundError.new("no assert at index #{idx}") unless idx >= 0 && idx < asserts.size
        removed = asserts.delete_at(idx)
        session.save_asserts(asserts)
        Logger.success "removed ##{idx} (#{removed.type} = #{removed.value})"
      else
        before = asserts.size
        asserts.reject! { |a| a.type == token }
        raise NotFoundError.new("no assert of type '#{token}'") if asserts.size == before
        session.save_asserts(asserts)
        Logger.success "removed #{before - asserts.size} rule(s) of type '#{token}'"
      end
    end
  end
end
