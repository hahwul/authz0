require "option_parser"
require "json"
require "../helpers"
require "../../store/session_store"
require "../../utils/logger"

module Authz0::CLI
  # `authz0 stats` — a cross-session overview: totals plus the latest-scan
  # finding counts per session, so you can see at a glance which sessions still
  # have unresolved unauthorized access.
  class StatsCommand
    include Helpers

    private record Row, name : String, urls : Int32, creds : Int32, scans : Int32,
      scanned : Bool, unauthorized : Int32, over : Int32

    def run(args : Array(String))
      json_mode = false
      OptionParser.parse(args) do |p|
        p.banner = "Usage: authz0 stats [--json]"
        p.on("--json", "Output as JSON") { json_mode = true }
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
      end

      rows = Store::SessionStore.list.map { |s| row_for(s) }

      if json_mode
        puts rows_json(rows)
        return
      end

      if rows.empty?
        Logger.info "no sessions yet — create one with `authz0 session new <name> --base-url <url>`"
        return
      end

      total_urls = rows.sum(&.urls)
      total_creds = rows.sum(&.creds)
      total_scans = rows.sum(&.scans)
      total_unauth = rows.sum(&.unauthorized)

      print_kv([
        {"sessions", rows.size.to_s},
        {"urls", total_urls.to_s},
        {"credentials", total_creds.to_s},
        {"archived scans", total_scans.to_s},
        {"open unauthorized", total_unauth.to_s},
      ])
      puts ""
      puts "per session (latest scan):"
      rows.each do |r|
        status =
          if !r.scanned
            "not scanned"
          elsif r.unauthorized > 0
            "#{r.unauthorized} unauthorized, #{r.over} over-restrictive"
          elsif r.over > 0
            "#{r.over} over-restrictive"
          else
            "clean"
          end
        puts "  #{r.name.ljust(20)} urls=#{r.urls} creds=#{r.creds}  #{status}"
      end
    end

    private def row_for(session) : Row
      urls = session.urls.size
      creds = session.creds.size
      files = scan_files(session)
      scanned = false
      unauth = 0
      over = 0
      if latest = files.last?
        if s = summary_of(latest)
          scanned = true
          unauth = s["unauthorized"]
          over = s["over_restrictive"]
        end
      end
      Row.new(session.name, urls, creds, files.size, scanned, unauth, over)
    rescue
      Row.new(session.name, 0, 0, 0, false, 0, 0)
    end

    private def scan_files(session) : Array(String)
      dir = session.results_dir
      return [] of String unless File.directory?(dir)
      Dir.glob(File.join(dir, "*.json")).sort
    end

    private def summary_of(path : String) : Hash(String, Int32)?
      doc = JSON.parse(File.read(path))
      s = doc["summary"]?
      return nil if s.nil?
      {
        "unauthorized"     => s["unauthorized"]?.try(&.as_i?) || 0,
        "over_restrictive" => s["over_restrictive"]?.try(&.as_i?) || 0,
      }
    rescue
      nil
    end

    private def rows_json(rows : Array(Row)) : String
      JSON.build(indent: "  ") do |json|
        json.object do
          json.field "sessions", rows.size
          json.field "urls", rows.sum(&.urls)
          json.field "credentials", rows.sum(&.creds)
          json.field "archived_scans", rows.sum(&.scans)
          json.field "open_unauthorized", rows.sum(&.unauthorized)
          json.field "per_session" do
            json.array do
              rows.each do |r|
                json.object do
                  json.field "name", r.name
                  json.field "urls", r.urls
                  json.field "credentials", r.creds
                  json.field "scans", r.scans
                  json.field "scanned", r.scanned
                  json.field "unauthorized", r.unauthorized
                  json.field "over_restrictive", r.over
                end
              end
            end
          end
        end
      end
    end
  end
end
