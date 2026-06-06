require "colorize"
require "../utils/config"
require "../utils/errors"
require "../utils/logger"
require "../utils/runtime"
require "../utils/suggester"
require "../utils/version"
require "./helpers"
require "./commands/session_command"
require "./commands/url_command"
require "./commands/cred_command"
require "./commands/assert_command"
require "./commands/scan_command"
require "./commands/results_command"
require "./commands/stats_command"
require "./commands/import_command"
require "./commands/export_command"
require "./commands/doctor_command"
require "./commands/config_command"
require "./commands/completion_command"

module Authz0
  module CLI
    # Top-level dispatcher: pull global flags out of argv, route the first
    # token to a command class, and translate expected errors into clean
    # `✗ message` output with a sensible exit code.
    class Runner
      KNOWN_COMMANDS = %w[
        session url cred assert scan results stats import export doctor config completion
        version help -V --version -h --help
      ]

      def run(args : Array(String) = ARGV.dup)
        Runner.apply_globals!(args)
        # Honor a persisted `color` config setting (CLI flags / NO_COLOR still
        # win). Guarded so a corrupt config can't break unrelated commands.
        begin
          Logger.apply_color_setting(Settings.current.color)
        rescue
        end

        if args.empty?
          print_help
          return
        end

        command = args.shift
        case command
        when "-V", "--version", "version"
          puts Authz0::VERSION
        when "-h", "--help", "help"
          if command == "help" && !args.empty?
            run([args.shift, "--help"])
          else
            print_help
          end
        when "session"    then SessionCommand.new.run(args)
        when "url"        then UrlCommand.new.run(args)
        when "cred"       then CredCommand.new.run(args)
        when "assert"     then AssertCommand.new.run(args)
        when "scan"       then ScanCommand.new.run(args)
        when "results"    then ResultsCommand.new.run(args)
        when "stats"      then StatsCommand.new.run(args)
        when "import"     then ImportCommand.new.run(args)
        when "export"     then ExportCommand.new.run(args)
        when "doctor"     then DoctorCommand.new.run(args)
        when "config"     then ConfigCommand.new.run(args)
        when "completion" then CompletionCommand.new.run(args)
        else
          Logger.error "unknown command '#{command}'"
          if suggestion = Suggester.suggest(command, KNOWN_COMMANDS)
            STDERR.puts "  did you mean '#{suggestion}'?"
          end
          STDERR.puts "Run 'authz0 --help' to see all commands."
          exit 1
        end
      rescue ex : Authz0::Error
        Logger.error ex.message || "unknown error"
        if hint = ex.hint
          STDERR.puts "  #{hint}"
        end
        exit ex.exit_code
      rescue ex : OptionParser::InvalidOption | OptionParser::MissingOption
        flag = (ex.message || "").split(": ", 2).last
        msg = ex.is_a?(OptionParser::MissingOption) ? "option '#{flag}' needs a value" : "unknown option '#{flag}'"
        Logger.error msg
        exit 1
      rescue ex : Exception
        # A consumer closing the pipe (`authz0 … | head`) raises EPIPE on our
        # next write — exit cleanly (128 + SIGPIPE 13) rather than shouting.
        if ex.message.try(&.includes?("Broken pipe"))
          exit 141
        end
        Logger.error "internal error: #{ex.message}"
        STDERR.puts ex.backtrace.first(8).join("\n") if Logger.debug?
        exit 70
      end

      # Option flags (across all subcommands) whose *next* argv token is a
      # value. Used by apply_globals! so a value that happens to equal a
      # global flag — e.g. `url add s /x --body -q` — isn't mistaken for the
      # global and stripped. `--flag=value` forms are a single token and are
      # unaffected.
      VALUE_FLAGS = %w[
        --base-url --description --method --body --content-type --allow-role
        --deny-role --header -H --alias --tag --cookie --auth-type --role -r
        --concurrency --timeout --delay --proxy --output -o --save
        --success-status --fail-status --fail-regex --fail-size
        --fail-size-margin --type --value
        --baseline --basic --extra-header --fail-header --from-curl --from-har
        --match --max-redirects --name --path --retries --severity --sort
        --success-header --template --user-agent
      ]

      # Strip global flags from argv in place and apply them before the
      # subcommand parses anything. Tokens that are the value of a preceding
      # value-expecting flag are left untouched.
      def self.apply_globals!(argv : Array(String))
        kept = [] of String
        i = 0
        while i < argv.size
          arg = argv[i]
          prev = i > 0 ? argv[i - 1] : nil
          is_value = prev && VALUE_FLAGS.includes?(prev)
          if !is_value && apply_global(arg)
            # consumed as a global flag
          else
            kept << arg
          end
          i += 1
        end
        argv.clear
        argv.concat(kept)
      end

      # Apply a single token if it is a global flag; return whether it was.
      private def self.apply_global(arg : String) : Bool
        case arg
        when "-q", "--quiet"
          Logger.quiet = true
          true
        when "-v", "--verbose", "--debug"
          Logger.debug = true
          true
        when "--no-color"
          Logger.no_color = true
          true
        when "--color"
          Logger.no_color = false
          true
        when "-y", "--yes"
          Runtime.assume_yes = true
          true
        else
          false
        end
      end

      COMMAND_LISTING = [
        {"session <action>", "Create/list/show/delete/rename/clone test projects"},
        {"url <action>", "add / list / show / update / remove endpoints"},
        {"cred <action>", "add / list / update / remove credentials (roles)"},
        {"assert <action>", "add / list / remove access-detection rules"},
        {"scan <session>", "Run the authorization scan and report findings"},
        {"results <action>", "list / show / clean archived scans"},
        {"stats", "Cross-session overview + open findings"},
        {"import <type> ...", "Load urls from openapi/har/burp/postman/urls"},
        {"export yaml ...", "Write a v1-compatible YAML template"},
        {"doctor", "Check the install + credential file permissions"},
        {"config <action>", "get / set / list global settings"},
        {"completion <shell>", "bash / zsh / fish completion script"},
        {"version | help", "Show version / this help"},
      ]

      BANNER_ART = [
        "  __ _ _   _ ___| |_ ____  / _ \\ ",
        " / _` | | | |_  / __|_  / | | | |",
        "| (_| | |_| |/ /| |_ / /| | |_| |",
        " \\__,_|\\__,_/___|\\__/___|\\___/ ",
      ]

      private def print_help
        # Help is the explicitly requested output, not incidental progress
        # chatter, so print it even under -q/--quiet (otherwise `authz0 help -q`
        # is a silent no-op).
        color = Logger.color_enabled?

        puts ""
        BANNER_ART.each do |line|
          puts(color ? line.colorize(:magenta).to_s : line)
        end
        brand = color ? "authz0".colorize(:magenta).bold.to_s : "authz0"
        puts ""
        puts "  #{brand} v#{Authz0::VERSION} — automated authorization testing"
        puts "  Usage: authz0 <command> [options]"
        puts ""
        puts "Commands:"
        COMMAND_LISTING.each do |row|
          name, desc = row
          puts "  #{name.ljust(20)} #{desc}"
        end
        puts ""
        puts "Global flags:"
        puts "  -q, --quiet             Suppress info/success output"
        puts "  -v, --verbose, --debug  Print debug traces to stderr"
        puts "      --no-color/--color  Force color off / on"
        puts "  -y, --yes               Assume yes for confirmations (env: AUTHZ0_YES=1)"
        puts ""
        puts "Quickstart:"
        puts "  authz0 session new demo --base-url https://api.example.com"
        puts "  authz0 url add demo /admin --deny-role user"
        puts "  authz0 cred add demo user --header \"Authorization: Bearer …\""
        puts "  authz0 scan demo"
        puts ""
      end
    end
  end
end
