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
      --success-header "X-Auth: ok"    Response header (name or name:substr) means accessible
      --fail-status 403                Code that means NOT accessible
      --fail-regex "Access denied"     Body match means NOT accessible
      --fail-header "WWW-Authenticate" Response header means NOT accessible
      --fail-size 1234                 ~byte size that means NOT accessible
      --fail-size-margin 50            Tolerance for --fail-size
      --type T --value V               Generic rule
    USAGE

    def run(args : Array(String))
      action = args.shift?
      case action
      when "add"                    then add(args)
      when "list", "ls"             then list(args)
      when "remove", "rm", "delete" then remove(args)
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
        p.on("--success-status LIST", "Codes/classes that mean accessible (200,201 or 2xx)") do |v|
          Validator.status_tokens!(v) # validate (exact codes or Nxx classes)
          rules << Assertion.new("success-status", v)
        end
        p.on("--fail-status LIST", "Codes/classes that mean NOT accessible (403 or 4xx)") do |v|
          Validator.status_tokens!(v)
          rules << Assertion.new("fail-status", v)
        end
        p.on("--fail-regex PATTERN", "Body match means NOT accessible") do |v|
          rules << Assertion.new("fail-regex", v)
        end
        p.on("--fail-header HEADER", "Response header 'Name' or 'Name: substr' means NOT accessible") do |v|
          rules << Assertion.new("fail-header", v)
        end
        p.on("--success-header HEADER", "Response header 'Name' or 'Name: substr' means accessible") do |v|
          rules << Assertion.new("success-header", v)
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

      name, _ = split_session(positional, needs: 0)
      session = open_session(name)

      if generic_type || generic_value
        raise ValidationError.new("--type and --value must be given together") unless generic_type && generic_value
        generic_rule = Assertion.new(generic_type.not_nil!, generic_value.not_nil!)
        validate_rule_value!(generic_rule)
        rules << generic_rule
      end
      raise ValidationError.new("no rules given", "e.g. --success-status 200,201") if rules.empty?

      session.lock do
        asserts = session.asserts
        added = 0
        rules.each do |rule|
          unless rule.valid_type?
            Logger.warn "unknown assert type '#{rule.type}' — it will be ignored by scan (valid: #{Assertion::TYPES.join(", ")})"
          end
          # De-dupe identical rules.
          next if asserts.any? { |a| a.type == rule.type && a.value == rule.value }
          asserts << rule
          added += 1
        end
        session.save_asserts(asserts)
        Logger.success "added #{added} assert rule#{added == 1 ? "" : "s"} (#{asserts.size} total)"
      end
    end

    # Type-specific value validation for generic --type/--value rules, so a bad
    # value (e.g. a non-numeric fail-size) is rejected at add time rather than
    # being silently dropped by the scanner, masking a real verdict.
    private def validate_rule_value!(rule : Assertion)
      case rule.type
      when "fail-size", "fail-size-margin"
        raise ValidationError.new("#{rule.type} must be a number: #{rule.value}") unless rule.value.strip.to_i64?
      when "success-status", "fail-status"
        Validator.status_tokens!(rule.value)
      end
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
      name, _ = split_session(positional, needs: 0)
      session = open_session(name)
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
      name, rest = split_session(positional, needs: 1)
      session = open_session(name)
      token = rest[0]?
      raise ValidationError.new("missing <index|type> argument") if token.nil?

      stripped = token.lstrip('#')
      forced_index = token.starts_with?('#')
      idx = stripped.to_i?

      session.lock do
        asserts = session.asserts
        if idx && idx >= 0 && idx < asserts.size
          removed = asserts.delete_at(idx)
          session.save_asserts(asserts)
          Logger.success "removed ##{idx} (#{removed.type} = #{removed.value})"
        elsif forced_index
          # An explicit '#N' is unambiguously an index — don't fall back to type.
          raise NotFoundError.new("no assert at index #{stripped}")
        else
          # A bare token (even a numeric one like a "200" rule type) falls back
          # to removing by type when it isn't an in-range index.
          before = asserts.size
          asserts.reject! { |a| a.type == token }
          raise NotFoundError.new("no assert at index or of type '#{token}'") if asserts.size == before
          session.save_asserts(asserts)
          Logger.success "removed #{before - asserts.size} rule(s) of type '#{token}'"
        end
      end
    end
  end
end
