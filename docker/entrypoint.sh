#!/bin/sh
set -e

# Outside GitHub Actions the image is just the authz0 CLI: pass everything
# straight through so `docker run ghcr.io/hahwul/authz0 scan ...` works.
if [ -z "$GITHUB_ACTIONS" ]; then
    exec authz0 "$@"
fi

# ========================================
# GitHub Actions mode
# ========================================
# Inputs arrive as INPUT_* env vars (see action.yml). Primary mode scans a
# v1-compatible YAML template and writes a report file (SARIF by default) that
# the workflow can upload to code scanning. A free-form ARGS escape hatch is
# also supported for anything the template flow doesn't cover.

TEMPLATE="${INPUT_TEMPLATE:-}"
OUTPUT="${INPUT_OUTPUT:-sarif}"
OUTPUT_FILE="${INPUT_OUTPUT_FILE:-authz0.sarif}"
EXTRA_ARGS="${INPUT_ARGS:-}"

FAIL_FLAG=""
if [ "${INPUT_FAIL_ON_FINDINGS:-false}" = "true" ]; then
    FAIL_FLAG="--fail-on-findings"
fi

authz0 version >/dev/null 2>&1 && echo "authz0 $(authz0 version)"

if [ -n "$TEMPLATE" ]; then
    if [ ! -f "$TEMPLATE" ]; then
        echo "::error::template file not found: $TEMPLATE" >&2
        exit 1
    fi
    echo "Scanning template '$TEMPLATE' → $OUTPUT_FILE ($OUTPUT)"
    # word-splitting EXTRA_ARGS is intentional (it carries multiple flags)
    # shellcheck disable=SC2086
    exec authz0 scan --template "$TEMPLATE" \
        --output "$OUTPUT" --save "$OUTPUT_FILE" \
        $FAIL_FLAG $EXTRA_ARGS
elif [ -n "$EXTRA_ARGS" ]; then
    echo "Running: authz0 $EXTRA_ARGS"
    # shellcheck disable=SC2086
    exec authz0 $EXTRA_ARGS
else
    authz0 --help >&2
    echo "::error::authz0 action: provide a 'template' input (or free-form 'args')" >&2
    exit 1
fi
