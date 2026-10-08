#!/usr/bin/env bash
# Decides which ci.yml jobs and gates a change needs, printing `code=`, `proto=` and
# `deps=` lines for $GITHUB_OUTPUT. Only the Docs job always runs; the toolchain jobs are skipped for a
# pull request that cannot affect them, which is most of what a docs-only PR costs.
#
#   code=false  every changed path is documentation nothing builds or tests reads:
#               docs/, .claude/, and top-level *.md. Anything else — including a path
#               this script has never heard of — is code. So is every docs/ path a code
#               job reads: docs/api/ (the OpenAPI gates), and the files the Go and Rust
#               tests open — docs/design/console/ and docs/specs/accounts-and-access.md
#               (the Console's About-docs tests), docs/brand/ (the Console's brand-asset
#               test), docs/operations/demo-fleet.md (the daemon's dev-fleet fixtures).
#               A new test that reads under docs/ adds its path below.
#   proto=false nothing under proto/ or the generated relay/internal/relay/v1/ changed,
#               and neither did the Makefile, relay/go.mod (the proto job's Go version
#               and the Makefile's GOTOOLCHAIN), tools/buf/ (the pinned buf both proto
#               gates run), or the CI machinery that runs the proto gates.
#   deps=false  no dependency manifest or lockfile changed (relay/go.mod, relay/go.sum,
#               daemon/Cargo.toml, daemon/crates/*/Cargo.toml, daemon/Cargo.lock), nor either gate's
#               exceptions (daemon/deny.toml, relay/govulncheck-exceptions.txt,
#               scripts/vuln-gate.sh), nor tools/govulncheck/ or the Makefile that run the
#               scanners, nor the CI machinery. Gates the PR-time advisory scans (govulncheck, cargo-deny advisories): an advisory
#               published against an untouched dependency is the nightly scan's to report,
#               not a reason to turn every open PR red at once.
#
# Fails OPEN: a push (main is the backstop), a missing diff, or any error runs every job.
# A skipped gate is only safe when the change provably cannot reach it.
#
# Usage: ci-changed-paths.sh             derive the file list from the PR merge commit
#        ci-changed-paths.sh <path>...   classify the given paths (for testing by hand)
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

emit() {
  echo "code=$1"
  echo "proto=$2"
  echo "deps=$3"
  echo "ci-changed-paths: code=$1 proto=$2 deps=$3 — $4" >&2
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    echo "**Changed paths:** code=\`$1\` proto=\`$2\` deps=\`$3\` — $4" >>"$GITHUB_STEP_SUMMARY"
  fi
  exit 0
}

if [ $# -gt 0 ]; then
  files=$(printf '%s\n' "$@")
elif [ "${GITHUB_EVENT_NAME:-}" != "pull_request" ]; then
  emit true true true "not a pull request (${GITHUB_EVENT_NAME:-local}); running every job"
else
  # A pull_request checkout is the merge commit: its first parent is the base it
  # merges into, so this is exactly what the PR changes. Needs fetch-depth >= 2.
  # --no-renames: a rename must classify BOTH paths — moving a file the build reads
  # into docs/ would otherwise look like a docs-only change.
  files=$(git diff --no-renames --name-only HEAD^1 HEAD) \
    || emit true true true "cannot diff the merge commit against its base; running every job"
fi

code=false
proto=false
deps=false
while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in
    docs/api/* | docs/design/console/* | docs/brand/* | docs/operations/demo-fleet.md \
      | docs/specs/accounts-and-access.md)    code=true ;;
    docs/* | .claude/*)                       ;;
    */*)                                      code=true ;;
    *.md)                                     ;;
    *)                                        code=true ;;
  esac
  case "$f" in
    proto/* | relay/internal/relay/v1/* | Makefile | relay/go.mod | .github/workflows/ci.yml \
      | .github/actions/* | scripts/ci-changed-paths.sh | tools/buf/*)
      proto=true ;;
  esac
  case "$f" in
    relay/go.mod | relay/go.sum | daemon/Cargo.toml | daemon/crates/*/Cargo.toml \
      | daemon/Cargo.lock | daemon/deny.toml \
      | relay/govulncheck-exceptions.txt | scripts/vuln-gate.sh | tools/govulncheck/* \
      | Makefile | .github/workflows/ci.yml | .github/actions/* | scripts/ci-changed-paths.sh)
      deps=true ;;
  esac
done <<<"$files"

emit "$code" "$proto" "$deps" "classified $(grep -c . <<<"$files") changed path(s)"
