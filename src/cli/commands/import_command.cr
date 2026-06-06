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
      unless TYPES.includes?(type)
        raise ValidationError.new("unknown import type: #{type}", "one of: #{TYPES.join(", ")}")
      end
      session = open_session(positional[1]?)
      file = positional[2]?
      raise ValidationError.new("missing <file> argument") if file.nil?

      base = session.meta.base_url
      targets =
        case type
        when "urls"    then Importers::Urls.new.from_file(file, base)
        when "har"     then Importers::Har.new.from_file(file, base)
        when "burp"    then Importers::Burp.new.from_file(file, base)
        when "openapi" then Importers::OpenAPI.new.from_file(file, base)
        when "postman" then Importers::Postman.new.from_file(file, base)
        else                raise ValidationError.new("unknown import type: #{type}")
        end

      if targets.empty?
        Logger.warn "no endpoints found in #{file}"
        return
      end
      added, skipped = Importers.merge(session, targets)
      Logger.success "imported #{added} url#{added == 1 ? "" : "s"} from #{type} (#{skipped} duplicate#{skipped == 1 ? "" : "s"} skipped)"

      # OpenAPI/Postman often carry path templates (/users/{id}); those hit the
      # literal "{id}" and 404 until the user substitutes a real value.
      templated = targets.count(&.templated?)
      if templated > 0
        Logger.warn "#{templated} url#{templated == 1 ? "" : "s"} contain path templates ({...}) — edit them with `authz0 url update` before scanning"
      end
    end
  end
end
