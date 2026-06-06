require "file_utils"
require "json"
require "./errors"

module Authz0
  # Path helpers and the global config file (~/.authz0/config.json). Session
  # data lives under <home>/sessions/<name>/; see Store::SessionStore.
  module Config
    extend self

    DEFAULT_DIR = "~/.authz0"

    # Resolve `~` to $HOME. A blank AUTHZ0_HOME ("") is treated as unset so
    # an exported-but-empty var doesn't scatter data into the cwd.
    def home : String
      raw = ENV["AUTHZ0_HOME"]?
      raw = nil if raw && raw.empty?
      expand(raw || DEFAULT_DIR)
    end

    def sessions_dir : String
      File.join(home, "sessions")
    end

    def cache_dir : String
      File.join(home, "cache")
    end

    def config_path : String
      File.join(home, "config.json")
    end

    # Expand a leading `~` / `~/...` to the user's home directory. If a path
    # needs expansion but $HOME is unset, fail loudly rather than silently
    # returning a literal "~" that would be created as a directory named "~"
    # in the cwd.
    def expand(path : String) : String
      return path unless path == "~" || path.starts_with?("~/")
      h = ENV["HOME"]?
      if h.nil? || h.empty?
        raise ConfigError.new(
          "cannot expand '~': $HOME is not set",
          "set HOME, or point AUTHZ0_HOME at an absolute path"
        )
      end
      path == "~" ? h : File.join(h, path[2..])
    end

    # Create <home> (and sessions/) if missing. Surfaces the common
    # "$AUTHZ0_HOME points at a file" misconfiguration as a clean ConfigError.
    def ensure_home!
      target = home
      if File.file?(target)
        raise ConfigError.new("AUTHZ0_HOME points at a file, not a directory: #{target}")
      end
      FileUtils.mkdir_p(sessions_dir)
    rescue ex : ConfigError
      raise ex
    rescue ex
      raise ConfigError.new("cannot create AUTHZ0_HOME (#{target}): #{ex.message}")
    end
  end

  # Persisted global preferences. Every field is optional so the loader can
  # tell "user chose this" from "fall back to built-in default".
  class Settings
    include JSON::Serializable

    property proxy : String? = nil
    property concurrency : Int32? = nil
    property timeout : Int32? = nil
    property output : String? = nil
    property color : Bool? = nil
    property retries : Int32? = nil
    property follow_redirects : Int32? = nil
    property user_agent : String? = nil

    def initialize
    end

    DEFAULT_CONCURRENCY = 20
    DEFAULT_TIMEOUT     = 10
    DEFAULT_OUTPUT      = "table"

    @@current : Settings? = nil

    def self.current : Settings
      @@current ||= load(Config.config_path)
    end

    # Test hook. Pass nil to fall back to disk lookup again.
    def self.current=(value : Settings?)
      @@current = value
    end

    def self.load(path : String) : Settings
      return new unless File.exists?(path)
      content = File.read(path)
      return new if content.strip.empty?
      from_json(content)
    rescue ex : JSON::ParseException
      raise ConfigError.new("invalid config (#{path}): #{ex.message}")
    end

    def save(path : String = Config.config_path)
      Config.ensure_home!
      File.write(path, to_pretty_json + "\n")
    end

    def effective_concurrency : Int32
      concurrency || DEFAULT_CONCURRENCY
    end

    def effective_timeout : Int32
      timeout || DEFAULT_TIMEOUT
    end

    def effective_output : String
      output || DEFAULT_OUTPUT
    end
  end
end
