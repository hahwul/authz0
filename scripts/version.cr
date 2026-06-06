# Check or bump the project version across every file that hardcodes it.
#
#   crystal run scripts/version.cr            # check all files agree (exit 1 if not)
#   crystal run scripts/version.cr -- 2.1.0   # set every file to 2.1.0
#
# The source of truth for `check` is src/utils/version.cr (the VERSION the
# binary reports). Release workflows that sed PKGBUILD/snapcraft at tag time
# stay valid; this keeps the committed defaults honest in between.

CANONICAL = "src/utils/version.cr"

# file => regex whose first capture group is the version string.
TARGETS = {
  "src/utils/version.cr" => /VERSION\s*=\s*"([^"]+)"/,
  "shard.yml"            => /^version:\s*(\S+)/m,
  "snap/snapcraft.yaml"  => /^version:\s*(\S+)/m,
  "aur/PKGBUILD"         => /^pkgver=(\S+)/m,
}

def extract(path : String, re : Regex) : String?
  return nil unless File.exists?(path)
  File.read(path).match(re).try(&.[1])
end

new_version = ARGV.first?

if new_version
  # --- update mode ---
  TARGETS.each do |path, re|
    next unless File.exists?(path)
    content = File.read(path)
    updated = content.sub(re) do |m|
      md = $~
      m.sub(md[1], new_version)
    end
    File.write(path, updated)
    puts "updated #{path} → #{new_version}"
  end
  puts "✓ version set to #{new_version}"
else
  # --- check mode ---
  canonical = extract(CANONICAL, TARGETS[CANONICAL])
  if canonical.nil?
    STDERR.puts "✗ could not read canonical version from #{CANONICAL}"
    exit 1
  end

  mismatched = [] of String
  TARGETS.each do |path, re|
    found = extract(path, re)
    if found.nil?
      STDERR.puts "! #{path}: version not found"
      mismatched << path
    elsif found != canonical
      STDERR.puts "✗ #{path}: #{found} (expected #{canonical})"
      mismatched << path
    else
      puts "✓ #{path}: #{found}"
    end
  end

  if mismatched.empty?
    puts "all files agree on version #{canonical}"
  else
    STDERR.puts "version mismatch in: #{mismatched.join(", ")}"
    STDERR.puts "fix with: crystal run scripts/version.cr -- #{canonical}"
    exit 1
  end
end
