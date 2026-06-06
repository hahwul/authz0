module Authz0
  # Writing files that may contain secrets. Mirrors the chmod-600 discipline
  # used for creds.json so credential-bearing exports/backups never land in a
  # world-readable file (the default umask is typically 0644).
  module SecureFile
    extend self

    # Write `content` to `path`, restricting the file to owner read/write
    # (0600) *before* the secret bytes are written so they never touch a
    # world-readable file. The chmod is best-effort: filesystems without POSIX
    # modes simply keep their default behavior.
    def write_private(path : String, content : String)
      File.open(path, "w") do |f|
        begin
          File.chmod(path, 0o600)
        rescue
          # Filesystems without POSIX modes just skip this.
        end
        f.print(content)
      end
    end
  end
end
