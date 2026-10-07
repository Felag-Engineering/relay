#!/usr/bin/env bash
# Proves scripts/ci-changed-paths.sh classifies what its header claims: a docs/ path that a
# code job reads is code, every other docs/ path, .claude/ and top-level *.md are not, an
# unknown path is code, every input of the proto gates trips proto, and every dependency
# manifest, lockfile and scanner input trips deps — and that it fails OPEN, running every
# job and gate, when it is not a pull request or cannot diff the merge commit.
#
# A wrong `false` here is the dangerous direction: it skips a gate on a change that reaches
# it, and the PR goes green on a check that never ran. Before this test, a docs-only PR that
# broke a docs/ file a Go or Rust test reads skipped those tests and broke main instead.
#
# Runs against throwaway fixture repos built from the REAL script, so it proves the shipped
# classifier, not a synthetic one. Hermetic: bash and git only, no toolchain, no network, no
# writes outside its own `mktemp -d`. Touches nothing in this working tree.
#
# NOT `set -e`: every case must run and be reported, not stop at the first failure
# (security-surface-test.sh:12).
set -uo pipefail

# --- Safety preamble, the same idiom as proto-tools-check-test.sh: the only destructive
# operation is the trap's `rm -rf "$WORKDIR"`, which refuses anything but an absolute path.
# Every fixture path is derived from $WORKDIR, never from an argument or the environment.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
WORKDIR="$(mktemp -d)" || { echo "FAIL: mktemp -d failed" >&2; exit 1; }
trap 'case "${WORKDIR:-}" in /*) rm -rf "$WORKDIR" ;; esac' EXIT
case "$WORKDIR" in
  /*) ;;
  *) echo "FAIL: mktemp returned a non-absolute path: '$WORKDIR'" >&2; exit 1 ;;
esac

# The fixture repos' git must not read this host's config or be redirected at another repo
# (security-surface-test.sh:41-43, case 14). GITHUB_STEP_SUMMARY is cleared so a run inside a
# CI job does not append fixture verdicts to that job's summary.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GITHUB_STEP_SUMMARY
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=ci-changed-paths-test GIT_AUTHOR_EMAIL=ci-changed-paths-test@example.invalid
export GIT_COMMITTER_NAME=ci-changed-paths-test GIT_COMMITTER_EMAIL=ci-changed-paths-test@example.invalid

fail=0

# new_fixture <name>: a fresh directory holding the real script at scripts/, which is where
# the script's own `cd "$(dirname "$0")/.."` expects to find the repository root.
new_fixture() {
  local dir="$WORKDIR/$1"
  mkdir -p "$dir/scripts"
  cp "$REPO_ROOT/scripts/ci-changed-paths.sh" "$dir/scripts/ci-changed-paths.sh"
  printf '%s\n' "$dir"
}

# --- Capture harness. Globals only: `local out=$(cmd)` sets $? from `local`, not from the
# command (security-surface-test.sh:106-108).
CODE=""
PROTO=""
DEPS=""
RC=0

# classify <fixture> <GITHUB_EVENT_NAME, or "" for unset> [path...]
classify() {
  local fix=$1 event=$2 out
  shift 2
  if [ -n "$event" ]; then
    out="$(GITHUB_EVENT_NAME="$event" bash "$fix/scripts/ci-changed-paths.sh" "$@" 2>/dev/null)"
  else
    out="$(env -u GITHUB_EVENT_NAME bash "$fix/scripts/ci-changed-paths.sh" "$@" 2>/dev/null)"
  fi
  RC=$?
  CODE="$(sed -n 's/^code=//p' <<<"$out")"
  PROTO="$(sed -n 's/^proto=//p' <<<"$out")"
  DEPS="$(sed -n 's/^deps=//p' <<<"$out")"
}

# expect <case name> <want code> <want proto> <want deps>
expect() {
  if [ "$RC" -ne 0 ] || [ "$CODE" != "$2" ] || [ "$PROTO" != "$3" ] || [ "$DEPS" != "$4" ]; then
    echo "FAIL: $1: got rc=$RC code=$CODE proto=$PROTO deps=$DEPS, want rc=0 code=$2 proto=$3 deps=$4" >&2
    fail=$((fail + 1))
  fi
}

ARGS="$(new_fixture args)"

# --- 1. Each docs/ path a code job reads is code. These are real files today, checked
# against the checkout below, so a move or rename fails here and sends its author to the
# classifier rather than quietly leaving a stale pattern behind:
#   docs/design/console/ and docs/specs/accounts-and-access.md — the Console's About-docs
#     tests stat and read them (relay/internal/controlplane/console).
#   docs/brand/ — the Console's brand-asset test compares its copies byte for byte.
#   docs/operations/demo-fleet.md — the daemon's dev-fleet fixture test reads it.
#   docs/api/ — the OpenAPI contract and client-generation gates.
for p in \
  docs/design/console/01-fleet-view.md \
  docs/design/console/04-activity.md \
  docs/design/console/02-node-detail.md \
  docs/specs/accounts-and-access.md \
  docs/brand/relay-icon.svg \
  docs/brand/relay-wordmark-dark.svg \
  docs/operations/demo-fleet.md \
  docs/api/openapi.yaml; do
  if [ ! -e "$REPO_ROOT/$p" ]; then
    echo "FAIL: read-by-a-test path $p no longer exists — find what reads it now and update the classifier and this list" >&2
    fail=$((fail + 1))
  fi
  classify "$ARGS" "" "$p"
  expect "test-read docs path $p" true false false
done

# --- 2. Documentation nothing builds or tests reads stays skippable — including neighbours
# of the paths above, so a pattern widened by accident (docs/* as code) fails here.
for p in \
  docs/adr/0001-example.md \
  docs/specs/execution.md \
  docs/operations/relay-install.md \
  docs/design/plans/example.md \
  docs/design/console-notes.md \
  docs/dev-fleet.md \
  .claude/commands/dev-loop.md \
  README.md \
  GLOSSARY.md; do
  classify "$ARGS" "" "$p"
  expect "documentation path $p" false false false
done

# One read path among docs-only paths still makes the change code.
classify "$ARGS" "" docs/adr/0001-example.md README.md docs/brand/relay-icon.svg
expect "mixed docs change with one test-read path" true false false

# --- 3. Code, and paths the script has never heard of, are code.
for p in relay/cmd/relay/main.go daemon/src/main.rs scripts/check-docs.sh \
  docker-compose.demo.yml unknown-top-level-file daemon/fuzz/Cargo.lock; do
  classify "$ARGS" "" "$p"
  expect "code path $p" true false false
done

# --- 4. Every input of the proto gates trips proto: the contract and its generated Go, the
# Makefile that runs the gates, relay/go.mod (the proto job's Go version and the Makefile's
# GOTOOLCHAIN), proto-tools-check.sh (prerequisite of `make proto` and `make proto-breaking`),
# and the CI machinery including this classifier.
for p in proto/relay/v1/relay.proto proto/buf.yaml relay/internal/relay/v1/relay.pb.go \
  scripts/proto-tools-check.sh; do
  classify "$ARGS" "" "$p"
  expect "proto input $p" true true false
done
# The CI machinery, the Makefile and relay/go.mod are inputs of both the proto gates and
# the dependency scans.
for p in Makefile relay/go.mod scripts/ci-changed-paths.sh .github/workflows/ci.yml \
  .github/actions/go-tools/action.yml; do
  classify "$ARGS" "" "$p"
  expect "proto and deps input $p" true true true
done

# --- 4b. Every input of the PR-time advisory scans trips deps: the manifests and lockfiles
# they read and the cargo-deny policy. (The daemon's fuzz workspace is not one: cargo-deny
# checks the daemon workspace (--workspace), which the fuzz crate is not a member of.)
for p in relay/go.sum daemon/Cargo.toml daemon/crates/relay-policy/Cargo.toml daemon/Cargo.lock \
  daemon/deny.toml relay/govulncheck-exceptions.txt scripts/vuln-gate.sh; do
  classify "$ARGS" "" "$p"
  expect "deps input $p" true false true
done

# --- 5. Fail open: not a pull request runs every job, whatever the arguments would say.
classify "$ARGS" ""
expect "no event, no paths" true true true
classify "$ARGS" push
expect "push event" true true true

# --- 6. The pull_request path: diff the checked-out commit against its first parent, as on
# the merge commit CI checks out. A fixture repo, two commits.
# pr_fixture <name> <commit-2 action...>: base commit, then the action, then commit 2. Sets
# PR_FIX rather than printing it: a `$(...)` caller would run it in a subshell and lose `fail`.
PR_FIX=""
pr_fixture() {
  local fix
  fix="$(new_fixture "$1")"
  shift
  mkdir -p "$fix/docs/adr" "$fix/docs/brand" "$fix/relay"
  echo base >"$fix/docs/adr/0001-example.md"
  echo base >"$fix/docs/brand/relay-icon.svg"
  echo base >"$fix/relay/main.go"
  if ! { git init -q -b main "$fix" && git -C "$fix" add -A && git -C "$fix" commit -q -m base; }; then
    echo "FAIL: $fix: cannot build the base commit" >&2
    fail=$((fail + 1))
  fi
  if ! { (cd "$fix" && "$@") && git -C "$fix" add -A && git -C "$fix" commit -q -m change; }; then
    echo "FAIL: $fix: cannot build the change commit" >&2
    fail=$((fail + 1))
  fi
  PR_FIX="$fix"
}

pr_fixture pr-docs sh -c 'echo changed >>docs/adr/0001-example.md'
classify "$PR_FIX" pull_request
expect "pull_request touching only an unread doc" false false false

pr_fixture pr-brand sh -c 'echo changed >>docs/brand/relay-icon.svg'
classify "$PR_FIX" pull_request
expect "pull_request touching only docs/brand" true false false

pr_fixture pr-lockfile sh -c 'echo changed >relay/go.sum'
classify "$PR_FIX" pull_request
expect "pull_request touching a lockfile" true false true

# A rename classifies BOTH paths: moving a file the build reads into docs/ is a code change.
pr_fixture pr-rename git mv relay/main.go docs/adr/main.go
classify "$PR_FIX" pull_request
expect "pull_request renaming code into docs/" true false false

# No parent to diff against (a fetch-depth of 1): fail open.
ROOT_ONLY="$(new_fixture pr-root-only)"
if ! { git init -q -b main "$ROOT_ONLY" && git -C "$ROOT_ONLY" add -A && git -C "$ROOT_ONLY" commit -q -m only; }; then
  echo "FAIL: cannot build the single-commit fixture" >&2
  fail=$((fail + 1))
fi
classify "$ROOT_ONLY" pull_request
expect "pull_request with no parent commit" true true true

if [ "$fail" -ne 0 ]; then
  echo "FAIL: $fail case(s) failed" >&2
  exit 1
fi

echo "PASS: ci-changed-paths.sh runs the code jobs for every docs/ path a test reads and skips them only for documentation nothing reads, trips proto on every proto-gate input and deps on every dependency-scan input, and fails open off a pull request or without a parent commit."
