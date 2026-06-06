require "colorize"

module Authz0
  # Tiny leveled logger shared by the whole CLI. Human messages go to STDERR
  # so STDOUT stays clean for machine-readable output (`--json`, `export`,
  # piped reports). The one exception is `info`/`success`, which the commands
  # use for conversational progress and which therefore also land on STDERR —
  # never mix progress chatter into a stdout payload.
  module Logger
    extend self

    @@quiet : Bool = false
    @@debug : Bool = false
    # https://no-color.org/ is honored by default; the runner flips this via
    # --no-color / --color.
    @@no_color : Bool = ENV["NO_COLOR"]?.try(&.empty?.!) || false

    def quiet=(value : Bool)
      @@quiet = value
    end

    def quiet? : Bool
      @@quiet
    end

    def debug=(value : Bool)
      @@debug = value
    end

    def debug? : Bool
      @@debug
    end

    def no_color=(value : Bool)
      @@no_color = value
    end

    # Color is keyed off STDERR (where these messages go). Reports that target
    # STDOUT decide colorization separately based on STDOUT.tty?.
    def color_enabled? : Bool
      !@@no_color && STDERR.tty?
    end

    def info(msg : String)
      return if @@quiet
      STDERR.puts msg
    end

    def success(msg : String)
      return if @@quiet
      STDERR.puts(color_enabled? ? "✓ #{msg}".colorize(:green).to_s : "✓ #{msg}")
    end

    def warn(msg : String)
      STDERR.puts(color_enabled? ? "! #{msg}".colorize(:yellow).to_s : "! #{msg}")
    end

    def error(msg : String)
      STDERR.puts(color_enabled? ? "✗ #{msg}".colorize(:red).to_s : "✗ #{msg}")
    end

    def debug(msg : String)
      return unless @@debug
      STDERR.puts(color_enabled? ? "· #{msg}".colorize(:dark_gray).to_s : "· #{msg}")
    end

    # Bracketed per-target progress line used during scans, e.g.
    #   #3  200  GET https://… [admin] O
    def scan_line(msg : String, ok : Bool)
      return if @@quiet
      if color_enabled?
        STDERR.puts(ok ? msg.colorize(:dark_gray).to_s : msg.colorize(:red).bold.to_s)
      else
        STDERR.puts msg
      end
    end
  end
end
