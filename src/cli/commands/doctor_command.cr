require "option_parser"
require "colorize"
require "../helpers"
require "../../store/session_store"
require "../../utils/config"
require "../../utils/logger"

module Authz0::CLI
  # `authz0 doctor` — sanity & security check of the install: home dir, global
  # config, and every session's credential-file permissions. Exits non-zero if
  # any hard error is found (warnings don't fail).
  class DoctorCommand
    include Helpers

    enum Level
      Ok
      Warn
      Error
    end

    @warnings : Int32 = 0
    @errors : Int32 = 0

    def run(args : Array(String))
      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 doctor"
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
      end

      @warnings = 0
      @errors = 0
      color = Logger.color_enabled?

      report(Level::Ok, "authz0 v#{Authz0::VERSION}")
      check_home
      check_config
      check_sessions

      puts ""
      if @errors > 0
        puts "#{@errors} error(s), #{@warnings} warning(s)"
        exit 1
      elsif @warnings > 0
        puts "healthy with #{@warnings} warning(s)"
      else
        puts color ? "all checks passed".colorize(:green).to_s : "all checks passed"
      end
    end

    private def check_home
      home = Config.home
      if File.directory?(home)
        report(Level::Ok, "home: #{home}")
      elsif File.exists?(home)
        report(Level::Error, "home path is a file, not a directory: #{home}")
      else
        report(Level::Warn, "home does not exist yet: #{home} (created on first use)")
      end
    end

    private def check_config
      path = Config.config_path
      unless File.exists?(path)
        report(Level::Ok, "config: using defaults (no #{File.basename(path)})")
        return
      end
      begin
        Settings.load(path)
        report(Level::Ok, "config: #{path}")
      rescue ex : ConfigError
        report(Level::Error, "config invalid: #{ex.message}")
      end
    end

    private def check_sessions
      sessions = Store::SessionStore.list
      report(Level::Ok, "sessions: #{sessions.size}")
      sessions.each do |s|
        if s.creds_world_readable?
          report(Level::Warn, "#{s.name}: creds.json is group/other-readable — run `chmod 600 #{s.creds_path}`")
        end
        # Touch each collection so corrupt JSON surfaces here, not mid-scan.
        begin
          urls = s.urls
          creds = s.creds
          s.asserts

          if urls.empty?
            report(Level::Warn, "#{s.name}: no urls — add some or `authz0 import ...`")
          else
            templated = urls.count(&.templated?)
            report(Level::Warn, "#{s.name}: #{templated} url(s) have unfilled {templates}") if templated > 0
            if creds.empty?
              report(Level::Warn, "#{s.name}: no credentials — scans run anonymously only")
            end
          end
        rescue ex
          report(Level::Error, "#{s.name}: #{ex.message}")
        end
      end
    end

    private def report(level : Level, message : String)
      color = Logger.color_enabled?
      case level
      in Level::Ok
        STDOUT.puts(color ? "✓ #{message}".colorize(:green).to_s : "[ok]   #{message}")
      in Level::Warn
        @warnings += 1
        STDOUT.puts(color ? "! #{message}".colorize(:yellow).to_s : "[warn] #{message}")
      in Level::Error
        @errors += 1
        STDOUT.puts(color ? "✗ #{message}".colorize(:red).to_s : "[err]  #{message}")
      end
    end
  end
end
