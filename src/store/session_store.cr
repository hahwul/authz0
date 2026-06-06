require "json"
require "file_utils"
require "../utils/config"
require "../utils/errors"
require "../utils/validator"
require "./session"

module Authz0
  module Store
    # Lifecycle operations over the sessions/ root: create / open / list /
    # delete / rename / clone. A "session" is a directory whose name is the
    # session name; SessionStore never holds state itself.
    module SessionStore
      extend self

      def root : String
        Config.sessions_dir
      end

      def dir_for(name : String) : String
        File.join(root, name)
      end

      def exists?(name : String) : Bool
        File.directory?(dir_for(name))
      end

      # Create a fresh session directory with seed files and a .gitignore.
      def create(name : String, base_url : String, description : String? = nil) : Session
        name = Validator.session_name!(name)
        base_url = Validator.base_url!(base_url)
        if exists?(name)
          raise ConflictError.new(
            "session already exists: #{name}",
            "use a different name, or `authz0 session delete #{name}` first"
          )
        end
        Config.ensure_home!
        dir = dir_for(name)
        FileUtils.mkdir_p(dir)
        FileUtils.mkdir_p(File.join(dir, Session::RESULTS_DIR))
        FileUtils.mkdir_p(File.join(dir, Session::EXPORTS_DIR))

        meta = SessionMeta.new(name, base_url, description)
        session = Session.new(dir, meta)
        session.save_meta
        # Seed empty collection files so the directory is self-describing.
        File.write(session.urls_path, "[]\n")
        session.init_creds_file! # 0600 from creation, no world-readable window
        File.write(session.asserts_path, "[]\n")
        write_gitignore(dir)
        session
      end

      # Open an existing session, reading its metadata. Raises NotFoundError
      # with a hint when missing.
      def open(name : String) : Session
        # Validate before touching the filesystem so a crafted name like
        # "../../etc" can't escape the sessions root (every public entry
        # point applies the same guard — open/delete/rename/clone/create).
        name = Validator.session_name!(name)
        unless exists?(name)
          raise NotFoundError.new(
            "no such session: #{name}",
            "run `authz0 session list` to see sessions, or `authz0 session new #{name} --base-url <url>`"
          )
        end
        dir = dir_for(name)
        meta_path = File.join(dir, Session::META_FILE)
        unless File.exists?(meta_path)
          raise Authz0::Error.new("session '#{name}' is missing #{Session::META_FILE}")
        end
        meta = SessionMeta.from_json(File.read(meta_path))
        Session.new(dir, meta)
      rescue ex : JSON::ParseException
        raise Authz0::Error.new("corrupt #{Session::META_FILE} in session '#{name}': #{ex.message}")
      end

      # All sessions, sorted by name. Directories without a readable
      # session.json are skipped (with a debug note) rather than aborting.
      def list : Array(Session)
        return [] of Session unless File.directory?(root)
        sessions = [] of Session
        Dir.children(root).sort.each do |child|
          dir = File.join(root, child)
          next unless File.directory?(dir)
          meta_path = File.join(dir, Session::META_FILE)
          next unless File.exists?(meta_path)
          begin
            meta = SessionMeta.from_json(File.read(meta_path))
            sessions << Session.new(dir, meta)
          rescue
            # Surface (not silently swallow) a corrupt session.json — otherwise
            # a session with intact urls/creds just vanishes from `session list`
            # and the user assumes it was lost.
            Logger.warn "skipping session '#{child}': #{Session::META_FILE} is unreadable/corrupt"
          end
        end
        sessions
      end

      def delete(name : String)
        name = Validator.session_name!(name)
        unless exists?(name)
          raise NotFoundError.new("no such session: #{name}")
        end
        FileUtils.rm_rf(dir_for(name))
      end

      def rename(old_name : String, new_name : String) : Session
        old_name = Validator.session_name!(old_name)
        new_name = Validator.session_name!(new_name)
        unless exists?(old_name)
          raise NotFoundError.new("no such session: #{old_name}")
        end
        if exists?(new_name)
          raise ConflictError.new("session already exists: #{new_name}")
        end
        FileUtils.mv(dir_for(old_name), dir_for(new_name))
        session = open(new_name)
        session.meta.name = new_name
        session.save_meta
        session
      end

      def clone(src_name : String, dst_name : String) : Session
        src_name = Validator.session_name!(src_name)
        dst_name = Validator.session_name!(dst_name)
        unless exists?(src_name)
          raise NotFoundError.new("no such session: #{src_name}")
        end
        if exists?(dst_name)
          raise ConflictError.new("session already exists: #{dst_name}")
        end
        FileUtils.cp_r(dir_for(src_name), dir_for(dst_name))
        session = open(dst_name)
        session.meta.name = dst_name
        session.meta.created_at = Time.utc
        session.touch!
        session.secure_creds_file!
        session
      end

      private def write_gitignore(dir : String)
        File.write(File.join(dir, ".gitignore"), <<-GITIGNORE)
        # authz0 — never commit secrets or scan output
        creds.json
        results/
        exports/
        *.tmp
        GITIGNORE
      end
    end
  end
end
