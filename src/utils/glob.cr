module Authz0
  # Intuitive path globbing for `scan --match` and `url remove <glob>`.
  #
  # `File.match?` uses shell-glob semantics where `*` does NOT cross `/`, so a
  # pattern like `/admin*` silently skips nested paths such as `/admin/users`
  # (and `*admin*` matches nothing, defeated by the leading `/`). For a scanner
  # that's a dangerous, silent scope miss. Here `*` matches any run of
  # characters INCLUDING `/`, and `?` matches exactly one character — what a
  # user filtering URL paths actually expects. Every other character is a
  # literal (so `/a[b` is a literal path, never a "bad pattern" crash).
  module Glob
    extend self

    def match?(pattern : String, path : String) : Bool
      path.matches?(to_regex(pattern))
    end

    private def to_regex(pattern : String) : Regex
      source = String.build do |s|
        s << "\\A"
        pattern.each_char do |c|
          case c
          when '*' then s << ".*"
          when '?' then s << "."
          else          s << Regex.escape(c.to_s)
          end
        end
        s << "\\z"
      end
      Regex.new(source)
    end
  end
end
