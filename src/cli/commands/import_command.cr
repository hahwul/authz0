require "option_parser"
require "../helpers"
require "../../importers/base"
require "../../importers/urls"
require "../../importers/har"
require "../../importers/burp"
require "../../importers/openapi"
require "../../importers/postman"
require "../../utils/errors"
require "../../utils/logger"

module Authz0::CLI
  # `authz0 import <type> <session> <file>` — load endpoints from an external
  # source into a session. Existing endpoints (same method+path+body) are
  # skipped so re-imports are idempotent.
  class ImportCommand
    include Helpers

    TYPES = %w[openapi har burp urls postman]

    USAGE = <<-USAGE
    Usage: authz0 import <type> <session> <file>

    Types:
      auto       Sniff the format from the file content
      openapi    OpenAPI / Swagger (JSON or YAML)
      har        HAR 1.2 archive (ZAP / Chrome / Burp)
      burp       Burp Suite "Save items" XML
      postman    Postman collection (v2.x)
      urls       Plain URL list (one per line, "METHOD url" ok)
    USAGE

    def run(args : Array(String))
      positional = [] of String
      OptionParser.parse(args) do |p|
        p.banner = USAGE
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, after| positional = before + after }
      end

      type = positional[0]?
      if type.nil? || type == "help"
        puts USAGE
        return
      end
      unless TYPES.includes?(type) || type == "auto"
        raise ValidationError.new("unknown import type: #{type}", "one of: auto, #{TYPES.join(", ")}")
      end
      session = open_session(positional[1]?)
      file = positional[2]?
      raise ValidationError.new("missing <file> argument", "use '-' to read from stdin") if file.nil?

      # "-" reads the document from stdin so imports can be piped
      # (e.g. `curl … | authz0 import openapi sess -`).
      content = file == "-" ? STDIN.gets_to_end : Importers.read_file(file)
      Importers.ensure_utf8!(content, file == "-" ? "stdin" : file)
      if type == "auto"
        type = detect_type(content)
        Logger.info "detected format: #{type}"
      end
      base = session.meta.base_url
      targets =
        case type
        when "urls"    then Importers::Urls.new.parse(content, base)
        when "har"     then Importers::Har.new.parse(content, base)
        when "burp"    then Importers::Burp.new.parse(content, base)
        when "openapi" then Importers::OpenAPI.new.parse(content, base)
        when "postman" then Importers::Postman.new.parse(content, base)
        else                raise ValidationError.new("unknown import type: #{type}")
        end

      source = file == "-" ? "stdin" : file
      if targets.empty?
        Logger.warn "no endpoints found in #{source}"
        return
      end
      added, skipped = Importers.merge(session, targets)
      Logger.success "imported #{added} url#{added == 1 ? "" : "s"} from #{type} (#{skipped} duplicate#{skipped == 1 ? "" : "s"} skipped)"

      # OpenAPI/Postman often carry path templates (/users/{id}); those hit the
      # literal "{id}" and 404 until the user substitutes a real value.
      templated = targets.count(&.templated?)
      if templated > 0
        subject = templated == 1 ? "1 url has" : "#{templated} urls have"
        Logger.warn "#{subject} unfilled path templates ({...}) — edit them with `authz0 url update` before scanning"
      end
    end

    # Sniff the import format from the document. XML → burp; JSON keyed by
    # openapi/swagger/item/log → the matching type; YAML with an openapi/swagger
    # key → openapi; otherwise a plain url list.
    private def detect_type(content : String) : String
      trimmed = content.lstrip
      return "burp" if trimmed.starts_with?("<")

      if trimmed.starts_with?('{')
        begin
          doc = JSON.parse(content)
          return "openapi" if doc["openapi"]? || doc["swagger"]?
          return "postman" if doc["item"]?
          return "har" if doc["log"]?
        rescue
          # fall through
        end
      end

      return "openapi" if content.matches?(/^\s*(openapi|swagger)\s*:/m)
      "urls"
    end
  end
end
