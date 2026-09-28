#!/usr/bin/env bash
# Decides which ci.yml jobs a change needs, printing `code=` and `proto=` lines for
# $GITHUB_OUTPUT. Only the Docs job always runs; the toolchain jobs are skipped for a
# pull request that cannot affect them, which is most of what a docs-only PR costs.
#
#   code=false  every changed path is documentation nothing builds or tests reads:
#               docs/ (except docs/api/, which the OpenAPI gates read), .claude/, and
#               top-level *.md. Anything else — including a path this script has never
#               heard of — is code.
#   proto=false nothing under proto/ or the generated relay/internal/relay/v1/ changed,
#               and neither did the Makefile or CI machinery that runs the proto gates.
#
# Fails OPEN: a push (main is the backstop), a missing diff, or any error runs every job.
# A skipped gate is only safe when the change provably cannot reach it.
#
# Usage: ci-changed-paths.sh             derive the file list from the PR merge commit
#        ci-changed-paths.sh <path>...   classify the given paths (for testing by hand)
set -uo pipefail
cd "$(dirname "$0")/.."

emit() {
  echo "code=$1"
  echo "proto=$2"
  echo "ci-changed-paths: code=$1 proto=$2 — $3" >&2
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    echo "**Changed paths:** code=\`$1\` proto=\`$2\` — $3" >>"$GITHUB_STEP_SUMMARY"
  fi
  exit 0
}

if [ $# -gt 0 ]; then
  files=$(printf '%s\n' "$@")
elif [ "${GITHUB_EVENT_NAME:-}" != "pull_request" ]; then
  emit true true "not a pull request (${GITHUB_EVENT_NAME:-local}); running every job"
else
  # A pull_request checkout is the merge commit: its first parent is the base it
  # merges into, so this is exactly what the PR changes. Needs fetch-depth >= 2.
  # --no-renames: a rename must classify BOTH paths — moving a file the build reads
  # into docs/ would otherwise look like a docs-only change.
  files=$(git diff --no-renames --name-only HEAD^1 HEAD) \
    || emit true true "cannot diff the merge commit against its base; running every job"
fi

code=false
proto=false
while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in
    docs/api/*)                               code=true ;;
    docs/* | .claude/*)                       ;;
    */*)                                      code=true ;;
    *.md)                                     ;;
    *)                                        code=true ;;
  esac
  case "$f" in
    proto/* | relay/internal/relay/v1/* | Makefile | .github/workflows/ci.yml | .github/actions/* | scripts/ci-changed-paths.sh)
      proto=true ;;
  esac
done <<<"$files"

emit "$code" "$proto" "classified $(grep -c . <<<"$files") changed path(s)"
