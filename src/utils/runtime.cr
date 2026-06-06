module Authz0
  # Process-wide interaction state — currently just the "assume yes" toggle
  # that lets destructive commands run non-interactively (CI, scripts, AI
  # agents) without a TTY prompt.
  module Runtime
    extend self

    @@assume_yes : Bool = (ENV["AUTHZ0_YES"]? == "1")

    def assume_yes=(value : Bool)
      @@assume_yes = value
    end

    def assume_yes? : Bool
      @@assume_yes
    end

    # Ask a yes/no question. Returns true immediately when --yes/AUTHZ0_YES is
    # set. With no TTY (and no --yes) the safe default is "no" so an
    # unattended `delete` can't silently destroy data.
    def confirm?(prompt : String) : Bool
      return true if @@assume_yes
      return false unless STDIN.tty? && STDERR.tty?
      STDERR.print "#{prompt} [y/N] "
      STDERR.flush
      answer = STDIN.gets
      return false if answer.nil?
      a = answer.strip.downcase
      a == "y" || a == "yes"
    end
  end
end
