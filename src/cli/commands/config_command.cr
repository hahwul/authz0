require "option_parser"
require "../helpers"
require "../../report/reporter"
require "../../utils/config"
require "../../utils/errors"
require "../../utils/logger"

module Authz0::CLI
  # `authz0 config <get|set|list>` — read/write the global config
  # (~/.authz0/config.json). Keys: proxy, concurrency, timeout, output, color.
  class ConfigCommand
    include Helpers

    KEYS = %w[proxy concurrency timeout output color retries follow_redirects user_agent]

    USAGE = <<-USAGE
    Usage: authz0 config <action>

    Actions:
      list                 Show all settings (and their effective values)
      get <key>            Show one setting
      set <key> <value>    Change a setting
      unset <key>          Clear a setting (revert to default)

    Keys: #{KEYS.join(", ")}
    USAGE

    def run(args : Array(String))
      action = args.shift?
      case action
      when "list", "ls" then list
      when "get"        then get(args)
      when "set"        then set(args)
      when "unset"      then unset(args)
      when nil, "-h", "--help"
        puts USAGE
      else
        raise ValidationError.new("unknown config action: #{action}", "see `authz0 config --help`")
      end
    end

    private def settings : Settings
      Settings.load(Config.config_path)
    end

    private def list
      s = settings
      puts "path: #{Config.config_path}"
      print_kv([
        {"proxy", s.proxy || "(unset)"},
        {"concurrency", value_with_default(s.concurrency, Settings::DEFAULT_CONCURRENCY)},
        {"timeout", value_with_default(s.timeout, Settings::DEFAULT_TIMEOUT)},
        {"output", s.output || "(unset → #{Settings::DEFAULT_OUTPUT})"},
        {"color", s.color.nil? ? "(unset → auto)" : s.color.to_s},
        {"retries", value_with_default(s.retries, 0)},
        {"follow_redirects", value_with_default(s.follow_redirects, 0)},
        {"user_agent", s.user_agent || "(unset)"},
      ])
    end

    private def get(args)
      key = args.shift?
      raise ValidationError.new("missing <key>") if key.nil?
      s = settings
      case key
      when "proxy"            then puts s.proxy || ""
      when "concurrency"      then puts(s.concurrency || Settings::DEFAULT_CONCURRENCY)
      when "timeout"          then puts(s.timeout || Settings::DEFAULT_TIMEOUT)
      when "output"           then puts s.output || Settings::DEFAULT_OUTPUT
      when "color"            then puts s.color.nil? ? "auto" : s.color.to_s
      when "retries"          then puts(s.retries || 0)
      when "follow_redirects" then puts(s.follow_redirects || 0)
      when "user_agent"       then puts s.user_agent || ""
      else                         raise ValidationError.new("unknown key: #{key}", "keys: #{KEYS.join(", ")}")
      end
    end

    private def set(args)
      key = args.shift?
      value = args.shift?
      raise ValidationError.new("usage: authz0 config set <key> <value>") if key.nil? || value.nil?
      s = settings
      case key
      when "proxy"
        s.proxy = value
      when "concurrency"
        s.concurrency = positive_int(value, key)
      when "timeout"
        s.timeout = positive_int(value, key)
      when "output"
        raise ValidationError.new("invalid output: #{value}", "one of: #{Report::Format.names.join(", ")}") unless Report::Format.parse?(value)
        s.output = value
      when "color"
        s.color = parse_bool(value)
      when "retries"
        s.retries = non_negative_int(value, key)
      when "follow_redirects"
        s.follow_redirects = non_negative_int(value, key)
      when "user_agent"
        s.user_agent = value
      else
        raise ValidationError.new("unknown key: #{key}", "keys: #{KEYS.join(", ")}")
      end
      s.save
      Logger.success "set #{key} = #{value}"
    end

    private def unset(args)
      key = args.shift?
      raise ValidationError.new("missing <key>") if key.nil?
      s = settings
      case key
      when "proxy"            then s.proxy = nil
      when "concurrency"      then s.concurrency = nil
      when "timeout"          then s.timeout = nil
      when "output"           then s.output = nil
      when "color"            then s.color = nil
      when "retries"          then s.retries = nil
      when "follow_redirects" then s.follow_redirects = nil
      when "user_agent"       then s.user_agent = nil
      else                         raise ValidationError.new("unknown key: #{key}", "keys: #{KEYS.join(", ")}")
      end
      s.save
      Logger.success "unset #{key}"
    end

    private def value_with_default(value : Int32?, default : Int32) : String
      value ? value.to_s : "(unset → #{default})"
    end

    private def positive_int(value : String, key : String) : Int32
      n = value.to_i?
      raise ValidationError.new("#{key} must be a positive integer: #{value}") if n.nil? || n < 1
      n
    end

    private def non_negative_int(value : String, key : String) : Int32
      n = value.to_i?
      raise ValidationError.new("#{key} must be an integer >= 0: #{value}") if n.nil? || n < 0
      n
    end

    private def parse_bool(value : String) : Bool
      case value.downcase
      when "true", "1", "on", "yes"  then true
      when "false", "0", "off", "no" then false
      else                                raise ValidationError.new("color must be true/false: #{value}")
      end
    end
  end
end
