#!/usr/bin/env bash
# Decides which ci.yml jobs and gates a change needs, printing `code=`, `proto=`,
# `deps=`, `packaging=` and `release=` lines for $GITHUB_OUTPUT. Only the Docs job always
# runs; the toolchain jobs are skipped for a pull request that cannot affect them, which is
# most of what a docs-only PR costs.
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
#   packaging=false the change cannot reach the packages or the install matrix, which runs
#               on a pull request only when it can. Its inputs: all of daemon/ and relay/
#               (both binaries are package payload, and the packaged unit files, maintainer
#               scripts and nfpm manifests live under their packaging/ directories), proto/
#               (it compiles into both), the rest of the payload (the posture doc and
#               LICENSE), the pinned nfpm, the package build and version scripts, the
#               matrix's own scripts, images and workflow, release.yml, the Makefile (its
#               package-building targets) and the CI machinery. A docs-only or tooling-only
#               change (the lint and scan tools, the other scripts, the dev-fleet images,
#               deploy/) skips it, and a push to main always runs it.
#   release=true release.yml's pull_request path filter matches this change, so its dry run
#               runs the install matrix on the release's own packages and CI does not run a
#               second copy. The filter is read from release.yml itself, so the two cannot
#               drift. `true` only moves the matrix: ci.yml's CI OK still fails unless that
#               dry run's matrix passed for the PR's head commit (scripts/ci-release-matrix.sh).
#               Anything this script cannot model exactly — a trigger key other than `types`
#               and `paths`, a glob beyond `*` and `**`, more than 300 changed paths (past
#               which GitHub stops evaluating a filter) — is `false`, which runs CI's own matrix.
#
# Fails OPEN: a push (main is the backstop), a missing diff, or any error runs every job,
# with release=false, so CI runs its own install matrix. A skipped gate is only safe when
# the change provably cannot reach it.
#
# Usage: ci-changed-paths.sh             derive the file list from the PR merge commit
#        ci-changed-paths.sh <path>...   classify the given paths (for testing by hand)
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

emit() {
  echo "code=$1"
  echo "proto=$2"
  echo "deps=$3"
  echo "packaging=$4"
  echo "release=$5"
  echo "ci-changed-paths: code=$1 proto=$2 deps=$3 packaging=$4 release=$5 — $6" >&2
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    echo "**Changed paths:** code=\`$1\` proto=\`$2\` deps=\`$3\` packaging=\`$4\` release=\`$5\` — $6" >>"$GITHUB_STEP_SUMMARY"
  fi
  exit 0
}

# release_filter: release.yml's `on: pull_request: paths:` globs as anchored regexes, one per
# line, or nothing when the trigger holds anything this script cannot model exactly. Nothing
# means release=false: CI runs its own install matrix, the safe direction.
release_filter() {
  local wf=.github/workflows/release.yml block keys line pat re in_paths=0
  [ -f "$wf" ] || return 0
  # The pull_request block under the top-level `on:`, up to the next key at its indentation.
  block=$(awk '
    /^on:[[:space:]]*$/ { on = 1; next }
    on && /^[^[:space:]#]/ { exit }
    on && /^  pull_request:[[:space:]]*$/ { pr = 1; next }
    pr && /^  [^[:space:]]/ { exit }
    pr { print }
  ' "$wf")
  [ -n "$block" ] || return 0
  keys=$(grep -E '^    [^[:space:]#]' <<<"$block" | sed -E 's/^    ([^:]*):.*/\1/' | sort -u | tr '\n' ' ')
  [ "$keys" = "paths types " ] || return 0
  local out=""
  while IFS= read -r line; do
    case "$line" in
      "    paths:"*) in_paths=1; continue ;;
      "    "[!\ ]*) in_paths=0; continue ;;
    esac
    [ "$in_paths" = 1 ] || continue
    [[ $line =~ ^\ {6}-\ (.*)$ ]] || return 0
    pat=${BASH_REMATCH[1]}
    # `*` and `**` only: a quote, a comment, `?`, `[`, `+` or a `!` negation is not modelled.
    [[ $pat =~ ^[A-Za-z0-9._/*-]+$ ]] || return 0
    re=${pat//./\\.}
    re=${re//\*\*/$'\001'}
    re=${re//\*/[^/]*}
    re=${re//$'\001'/.*}
    out+="^$re\$"$'\n'
  done <<<"$block"
  printf '%s' "$out"
}

if [ $# -gt 0 ]; then
  files=$(printf '%s\n' "$@")
elif [ "${GITHUB_EVENT_NAME:-}" != "pull_request" ]; then
  emit true true true true false "not a pull request (${GITHUB_EVENT_NAME:-local}); running every job"
else
  # A pull_request checkout is the merge commit: its first parent is the base it
  # merges into, so this is exactly what the PR changes. Needs fetch-depth >= 2.
  # --no-renames: a rename must classify BOTH paths — moving a file the build reads
  # into docs/ would otherwise look like a docs-only change. core.quotePath=false prints a
  # non-ASCII name as itself; a name git still quotes fails open below.
  files=$(git -c core.quotePath=false diff --no-renames --name-only HEAD^1 HEAD) \
    || emit true true true true false "cannot diff the merge commit against its base; running every job"
fi

code=false
proto=false
deps=false
packaging=false
while IFS= read -r f; do
  [ -n "$f" ] || continue
  # git quotes a name holding a control character, a quote or a backslash, and a quoted
  # name matches none of the patterns below: it would read as a skippable change.
  case "$f" in
    \"*) emit true true true true false "a changed path git prints quoted ($f); running every job" ;;
  esac
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
  case "$f" in
    daemon/* | relay/* | proto/* \
      | docs/operations/daemon-privilege-posture.md | LICENSE | tools/nfpm/* \
      | scripts/build-packages.sh | scripts/build-version.sh \
      | scripts/install-matrix-*.sh | docker/install-matrix/* \
      | .github/workflows/install-matrix.yml | .github/workflows/release.yml \
      | Makefile | .github/workflows/ci.yml | .github/actions/* | scripts/ci-changed-paths.sh)
      packaging=true ;;
  esac
done <<<"$files"

# release=: GitHub evaluates a path filter over at most 300 changed files, so past that the
# dry run may not run, and CI keeps its own matrix.
release=false
count=$(grep -c . <<<"$files")
if [ "$count" -le 300 ]; then
  filter=$(release_filter)
  if [ -n "$filter" ]; then
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      while IFS= read -r re; do
        if [[ $f =~ $re ]]; then
          release=true
          break 2
        fi
      done <<<"$filter"
    done <<<"$files"
  fi
fi

emit "$code" "$proto" "$deps" "$packaging" "$release" "classified $count changed path(s)"
