require "option_parser"
require "json"
require "../helpers"
require "../../models/result"
require "../../report/reporter"
require "../../utils/errors"
require "../../utils/logger"
require "../../utils/runtime"

module Authz0::CLI
  # `authz0 results <list|show|clean> <session>` — browse the timestamped scan
  # archives a session accumulates under results/.
  class ResultsCommand
    include Helpers

    USAGE = <<-USAGE
    Usage: authz0 results <action> <session>

    Actions:
      list <session>                       List archived scans (newest first)
      show <session> [<file>] [-o FORMAT]  Print a scan (default: latest)
      clean <session> [-y]                 Delete all archived scans
    USAGE

    def run(args : Array(String))
      action = args.shift?
      case action
      when "list", "ls"  then list(args)
      when "show"        then show(args)
      when "clean", "rm" then clean(args)
      when nil, "-h", "--help"
        puts USAGE
      else
        raise ValidationError.new("unknown results action: #{action}", "see `authz0 results --help`")
      end
    end

    # Archived scans newest-first (session.result_files is oldest→newest, sorted
    # by mtime so same-millisecond collisions still order correctly).
    private def archives(session) : Array(String)
      session.result_files.reverse!
    end

    private def list(args)
      positional = [] of String
      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 results list <session>"
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, _| positional = before }
      end
      name, _ = split_session(positional, needs: 0)
      session = open_session(name)
      files = archives(session)
      if files.empty?
        Logger.info "no archived scans for '#{session.name}'"
        return
      end
      files.each do |path|
        s = summary_of(path)
        name = File.basename(path, ".json")
        puts "#{name}  probes=#{s["probes"]} findings=#{s["findings"]} (#{s["unauthorized"]} unauthorized)"
      end
    end

    private def show(args)
      output_name : String? = nil
      positional = [] of String
      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 results show <session> [<file>] [-o FORMAT]"
        p.on("-o FORMAT", "--output FORMAT", "Re-render as table/json/csv/…") { |v| output_name = v }
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, _| positional = before }
      end
      # `<file>` is optional, so arity can't tell `show <session>` from
      # `show <file>`; fall back to the active session only when nothing was
      # named, otherwise keep positional[0]=session, positional[1]=file.
      if positional.empty? && (active = Store::SessionStore.current)
        session = open_session(active)
        file_name = nil
      else
        session = open_session(positional[0]?)
        file_name = positional[1]?
      end
      files = archives(session)
      raise NotFoundError.new("no archived scans for '#{session.name}'") if files.empty?

      target =
        if fname = file_name
          files.find { |f| File.basename(f, ".json") == fname || File.basename(f) == fname } ||
            raise(NotFoundError.new("no archived scan '#{fname}'"))
        else
          files.first # newest
        end

      content = File.read(target)
      # Default to a readable table (matching live `scan`), not the raw stored
      # JSON; `-o json` re-renders the structured form.
      format =
        if fmt_name = output_name
          Report::Format.parse?(fmt_name) ||
            raise(ValidationError.new("unknown output format: #{fmt_name}", "one of: #{Report::Format.names.join(", ")}"))
        else
          Report::Format::Table
        end
      results = parse_results(content)
      puts Report.render(results, format, format.table? && STDOUT.tty? && Logger.color_enabled?)
    end

    private def clean(args)
      positional = [] of String
      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 results clean <session> [-y]"
        p.on("-y", "--yes", "Skip confirmation") { Runtime.assume_yes = true }
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, _| positional = before }
      end
      name, _ = split_session(positional, needs: 0)
      session = open_session(name)
      files = archives(session)
      if files.empty?
        Logger.info "nothing to clean for '#{session.name}'"
        return
      end
      unless Runtime.confirm?("delete #{files.size} archived scan(s) for '#{session.name}'?")
        Logger.info "aborted"
        return
      end
      files.each { |f| File.delete(f) }
      Logger.success "deleted #{files.size} archived scan(s)"
    end

    # Pull the summary block out of an archived report; tolerate older/odd files.
    private def summary_of(path : String) : Hash(String, Int32)
      doc = JSON.parse(File.read(path))
      s = doc["summary"]?
      {
        "probes"       => s.try(&.["probes"]?).try(&.as_i?) || 0,
        "findings"     => s.try(&.["findings"]?).try(&.as_i?) || 0,
        "unauthorized" => s.try(&.["unauthorized"]?).try(&.as_i?) || 0,
      }
    rescue
      {"probes" => 0, "findings" => 0, "unauthorized" => 0}
    end

    private def parse_results(content : String) : Array(Result)
      doc = JSON.parse(content)
      arr = doc["results"]?
      return [] of Result if arr.nil?
      Array(Result).from_json(arr.to_json)
    rescue ex
      raise Authz0::Error.new("could not parse archived results: #{ex.message}")
    end
  end
end
