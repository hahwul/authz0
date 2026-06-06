alias b := build
alias t := test
alias c := check

# List available tasks.
default:
    @just --list

# Build the authz0 binary into ./bin (zero runtime deps; no -Dpreview_mt —
# the scanner is IO-bound and runs on the single-thread fiber scheduler).
[group('build')]
build:
    shards install
    shards build

# Build an optimized release binary.
[group('build')]
release:
    shards install --production
    crystal build src/main.cr -o bin/authz0 --release --no-debug

# Remove build artifacts.
[group('build')]
clean:
    rm -rf bin/ lib/

# Run the spec suite (unit + live-server integration).
[group('development')]
test:
    crystal spec

# Run the suite under the multi-threaded runtime (proves scanner thread-safety).
[group('development')]
test-mt:
    CRYSTAL_WORKERS=4 crystal spec -Dpreview_mt

# Check formatting (the CI lint gate).
[group('development')]
check:
    crystal tool format --check src spec

# Auto-format the codebase.
[group('development')]
fix:
    crystal tool format src spec

# Check that the version agrees across shard.yml, version.cr, snapcraft, PKGBUILD.
[group('development')]
version-check:
    crystal run scripts/version.cr

# Bump the version across every file (e.g. `just version-update 2.1.0`).
[group('development')]
version-update version:
    crystal run scripts/version.cr -- {{version}}

# Build the Docker image locally.
[group('packaging')]
docker:
    docker build -f docker/Dockerfile -t authz0:dev .

# Build the snap locally (requires snapcraft).
[group('packaging')]
snap:
    snapcraft
