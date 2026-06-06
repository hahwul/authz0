module Authz0
  # Base class for expected, user-facing errors. The CLI runner catches these
  # and prints them as `✗ <message>` (plus an optional hint) with no stack
  # trace. Anything that escapes as a non-Authz0::Error is treated as a bug
  # and shown verbatim under "internal error".
  class Error < Exception
    getter exit_code : Int32
    getter hint : String?

    def initialize(message : String, @exit_code : Int32 = 1, @hint : String? = nil)
      super(message)
    end
  end

  # Bad user input — a malformed flag value, an illegal session name, etc.
  class ValidationError < Error
    def initialize(message : String, hint : String? = nil)
      super(message, 2, hint)
    end
  end

  # A named session / url / credential / assert that doesn't exist.
  class NotFoundError < Error
    def initialize(message : String, hint : String? = nil)
      super(message, 3, hint)
    end
  end

  # The requested write would clobber something (rename onto an existing
  # session, add a duplicate role, ...).
  class ConflictError < Error
    def initialize(message : String, hint : String? = nil)
      super(message, 4, hint)
    end
  end

  # Global config (~/.authz0/config.json) is unreadable or invalid.
  class ConfigError < Error
    def initialize(message : String, hint : String? = nil)
      super(message, 5, hint)
    end
  end

  # An import file couldn't be parsed into TargetURLs.
  class ImportError < Error
    def initialize(message : String, hint : String? = nil)
      super(message, 6, hint)
    end
  end
end
