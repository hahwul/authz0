require "json"
require "file_utils"
require "../models/session_meta"
require "../models/target_url"
require "../models/credential"
require "../models/assertion"
require "../models/result"
require "../utils/errors"

module Authz0
  module Store
    # An opened session directory. Wraps the on-disk JSON files
    # (session.json / urls.json / creds.json / asserts.json) and the
    # results/ + exports/ subdirectories. Collections are loaded lazily and
    # cached; mutators write through immediately and bump meta.updated_at.
    class Session
      META_FILE    = "session.json"
      URLS_FILE    = "urls.json"
      CREDS_FILE   = "creds.json"
      ASSERTS_FILE = "asserts.json"
      RESULTS_DIR  = "results"
      EXPORTS_DIR  = "exports"

      getter dir : String
      getter meta : SessionMeta

      def initialize(@dir : String, @meta : SessionMeta)
      end

      def name : String
        @meta.name
      end

      # --- paths ---------------------------------------------------------

      def meta_path : String
        File.join(@dir, META_FILE)
      end

      def urls_path : String
        File.join(@dir, URLS_FILE)
      end

      def creds_path : String
        File.join(@dir, CREDS_FILE)
      end

      def asserts_path : String
        File.join(@dir, ASSERTS_FILE)
      end

      def results_dir : String
        File.join(@dir, RESULTS_DIR)
      end

      def exports_dir : String
        File.join(@dir, EXPORTS_DIR)
      end

      # --- collections (lazy) -------------------------------------------

      @urls : Array(TargetURL)?
      @creds : Array(Credential)?
      @asserts : Array(Assertion)?

      def urls : Array(TargetURL)
        @urls ||= read_array(urls_path, TargetURL)
      end

      def creds : Array(Credential)
        @creds ||= read_array(creds_path, Credential)
      end

      def asserts : Array(Assertion)
        @asserts ||= read_array(asserts_path, Assertion)
      end

      # --- persistence ---------------------------------------------------

      def save_meta
        File.write(meta_path, @meta.to_pretty_json + "\n")
      end

      def save_urls(list : Array(TargetURL) = urls)
        @urls = list
        File.write(urls_path, list.to_pretty_json + "\n")
        touch!
      end

      # creds.json holds secrets, so it must never exist — even briefly — in a
      # world-readable state. We write to a sibling temp file created with
      # 0600 from the start, then atomically rename it into place (rename
      # preserves the mode and is atomic on POSIX). This closes the TOCTOU
      # window that a plain `File.write` + later `chmod` would leave open.
      def save_creds(list : Array(Credential) = creds)
        @creds = list
        write_secure(creds_path, list.to_pretty_json + "\n")
        touch!
      end

      # Create a fresh, empty, 0600 creds.json. Used when seeding a new
      # session so the seed file is born private too.
      def init_creds_file!
        write_secure(creds_path, "[]\n")
      end

      # Write `content` to `path` via a 0600 temp file + atomic rename.
      private def write_secure(path : String, content : String)
        tmp = "#{path}.tmp"
        begin
          File.open(tmp, "w") do |f|
            # chmod immediately after open so the secret bytes land in an
            # already-private file (open's perm arg is umask-masked anyway).
            begin
              File.chmod(tmp, 0o600)
            rescue
              # Filesystems without POSIX modes just skip this.
            end
            f.print(content)
          end
          File.rename(tmp, path)
        rescue ex
          File.delete(tmp) if File.exists?(tmp)
          raise ex
        end
      end

      def save_asserts(list : Array(Assertion) = asserts)
        @asserts = list
        File.write(asserts_path, list.to_pretty_json + "\n")
        touch!
      end

      # Bump updated_at and persist meta. Called after every mutation.
      def touch!
        @meta.updated_at = Time.utc
        save_meta
      end

      # chmod 0600 on creds.json (no-op on platforms without POSIX perms).
      def secure_creds_file!
        return unless File.exists?(creds_path)
        begin
          File.chmod(creds_path, 0o600)
        rescue
          # Best-effort: filesystems without POSIX modes simply skip this.
        end
      end

      # True if creds.json exists but is group/other readable — surfaced by
      # `doctor` and on load.
      def creds_world_readable? : Bool
        return false unless File.exists?(creds_path)
        info = File.info(creds_path)
        perm = info.permissions.value
        (perm & 0o077) != 0
      rescue
        false
      end

      # --- lookups -------------------------------------------------------

      def find_url(id_or_index : String) : TargetURL?
        # Exact id match first.
        if u = urls.find { |x| x.id == id_or_index }
          return u
        end
        # "#3" / "3" index form.
        token = id_or_index.lstrip('#')
        if idx = token.to_i?
          return urls[idx]? if idx >= 0 && idx < urls.size
        end
        nil
      end

      def find_cred(role : String) : Credential?
        creds.find { |c| c.role == role }
      end

      # Distinct role names declared across urls + creds, for validation hints.
      def known_roles : Array(String)
        roles = Set(String).new
        urls.each do |u|
          u.allow_roles.each { |r| roles << r }
          u.deny_roles.each { |r| roles << r }
        end
        creds.each { |c| roles << c.role unless c.role.empty? }
        roles.to_a.sort
      end

      # --- helpers -------------------------------------------------------

      private def read_array(path : String, klass : T.class) : Array(T) forall T
        return [] of T unless File.exists?(path)
        content = File.read(path)
        return [] of T if content.strip.empty?
        Array(T).from_json(content)
      rescue ex : JSON::ParseException
        raise Authz0::Error.new("corrupt #{File.basename(path)} in session '#{name}': #{ex.message}")
      end
    end
  end
end
