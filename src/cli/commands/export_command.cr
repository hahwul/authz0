require "option_parser"
require "../helpers"
require "../../export/yaml_export"
require "../../utils/errors"
require "../../utils/logger"

module Authz0::CLI
  # `authz0 export yaml <session> <output> [--v1-compatible]` — write a session
  # as a v1-compatible YAML template. Use "-" as the output to stream to stdout.
  class ExportCommand
    include Helpers

    USAGE = <<-USAGE
    Usage: authz0 export yaml <session> <output.yaml> [--v1-compatible]

    Writes the session as a YAML template (authz0 v1 format). Use "-" for the
    output path to print to stdout. --v1-compatible (default) restricts the
    output to fields v1 understands; omit it to include v2 tags/headers.
    USAGE

    def run(args : Array(String))
      v1_compatible = true
      redact = false
      positional = [] of String
      OptionParser.parse(args) do |p|
        p.banner = USAGE
        p.on("--v1-compatible", "Restrict to v1 fields (default)") { v1_compatible = true }
        p.on("--v2", "Include v2-only fields (tags, headers)") { v1_compatible = false }
        p.on("--redact", "Mask credential values (shareable, not runnable)") { redact = true }
        p.on("-h", "--help", "Show help") { puts p; exit 0 }
        p.unknown_args { |before, after| positional = before + after }
      end

      format = positional[0]?
      if format.nil? || format == "help"
        puts USAGE
        return
      end
      unless format == "yaml" || format == "yml"
        raise ValidationError.new("unknown export format: #{format}", "only 'yaml' is supported")
      end
      session = open_session(positional[1]?)
      output = positional[2]?
      raise ValidationError.new("missing <output> argument", "use '-' to print to stdout") if output.nil?

      exporter = Export::YamlExport.new(session, v1_compatible, redact)
      if output == "-"
        print exporter.render
      else
        exporter.write(output)
        Logger.success "exported '#{session.name}' → #{output}"
        if exporter.carries_secrets?
          Logger.warn "this template contains plaintext credentials (written chmod 600) — do not commit it (use --redact to mask)"
        end
      end
    end
  end
end
