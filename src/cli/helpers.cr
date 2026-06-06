require "option_parser"
require "../store/session_store"
require "../utils/errors"
require "../utils/logger"

module Authz0
  module CLI
    # Small shared helpers for command classes.
    module Helpers
      # Open a session by name, surfacing a friendly NotFoundError. A nil/empty
      # name (missing positional) becomes a ValidationError pointing at usage.
      def open_session(name : String?) : Store::Session
        if name.nil? || name.empty?
          raise ValidationError.new(
            "missing <session> argument",
            "name it, or set a default with `authz0 session use <name>`"
          )
        end
        Store::SessionStore.open(name)
      end

      # Split the session name out of a command's positionals, honoring the
      # active session ("session use"). `needs` is how many NON-session
      # positionals the command takes (e.g. `url add <session> <path>` → 1).
      #
      # If there are more positionals than the command needs, the first is an
      # explicit session (and always wins). Otherwise, if an active session is
      # set, it's used and every positional is a real argument. With neither,
      # the session is nil and open_session raises a helpful error. Resolving by
      # arity keeps `url add /path` (active) unambiguous from `url add s /path`.
      def split_session(positionals : Array(String), needs : Int32) : {String?, Array(String)}
        if positionals.size > needs
          {positionals[0], positionals[1..]}
        elsif active = Store::SessionStore.current
          {active, positionals}
        else
          {nil, positionals}
        end
      end

      # The first non-flag positional, or nil. Used to grab the session name /
      # subaction after OptionParser has consumed the flags.
      def shift_positional(args : Array(String)) : String?
        args.shift?
      end

      # Count + noun with naive pluralization: "1 url" / "2 urls". Pass an
      # explicit plural for irregular nouns.
      def pluralize(count : Int, noun : String, plural : String? = nil) : String
        word = count == 1 ? noun : (plural || "#{noun}s")
        "#{count} #{word}"
      end

      # Print a block of "key: value" lines, padding keys to align values.
      def print_kv(pairs : Array({String, String}))
        width = pairs.max_of? { |k, _| k.size } || 0
        pairs.each do |k, v|
          puts "#{(k + ":").ljust(width + 1)} #{v}"
        end
      end
    end
  end
end
