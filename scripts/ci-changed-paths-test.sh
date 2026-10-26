#!/usr/bin/env bash
# Proves scripts/ci-changed-paths.sh classifies what its header claims: a docs/ path that a
# code job reads is code, every other docs/ path, .claude/ and top-level *.md are not, an
# unknown path is code, every input of the proto gates trips proto, every dependency
# manifest, lockfile and scanner input trips deps, and every input of the packages and the
# install matrix trips packaging — and that it fails OPEN, running every job and gate, when
# it is not a pull request or cannot diff the merge commit.
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

# --- Safety preamble, the same idiom as security-surface-test.sh: the only destructive
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
PACKAGING=""
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
  PACKAGING="$(sed -n 's/^packaging=//p' <<<"$out")"
}

# expect <case name> <want code> <want proto> <want deps> <want packaging>
# Every case states all four: a wrong `false` is the dangerous direction, so none defaults.
expect() {
  if [ "$RC" -ne 0 ] || [ "$CODE" != "$2" ] || [ "$PROTO" != "$3" ] || [ "$DEPS" != "$4" ] \
    || [ "$PACKAGING" != "$5" ]; then
    echo "FAIL: $1: got rc=$RC code=$CODE proto=$PROTO deps=$DEPS packaging=$PACKAGING, want rc=0 code=$2 proto=$3 deps=$4 packaging=$5" >&2
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
  expect "test-read docs path $p" true false false false
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
  expect "documentation path $p" false false false false
done

# One read path among docs-only paths still makes the change code.
classify "$ARGS" "" docs/adr/0001-example.md README.md docs/brand/relay-icon.svg
expect "mixed docs change with one test-read path" true false false false

# --- 3. Code, and paths the script has never heard of, are code.
for p in relay/cmd/relay/main.go daemon/src/main.rs scripts/check-docs.sh \
  deploy/test/docker-compose.yml unknown-top-level-file daemon/fuzz/Cargo.lock; do
  classify "$ARGS" "" "$p"
  expect "code path $p" true false false false
done

# --- 4. Every input of the proto gates trips proto: the contract and its generated Go, the
# Makefile that runs the gates, relay/go.mod (the proto job's Go version and the Makefile's
# GOTOOLCHAIN), tools/buf (the pinned buf both proto gates run), and the CI machinery
# including this classifier.
for p in proto/relay/v1/relay.proto proto/buf.yaml relay/internal/relay/v1/relay.pb.go \
  tools/buf/go.mod; do
  classify "$ARGS" "" "$p"
  expect "proto input $p" true true false false
done
# The CI machinery, the Makefile and relay/go.mod are inputs of both the proto gates and
# the dependency scans. All but relay/go.mod also run the install matrix.
for p in Makefile scripts/ci-changed-paths.sh .github/workflows/ci.yml \
  .github/actions/go-cache-restore/action.yml; do
  classify "$ARGS" "" "$p"
  expect "proto, deps and packaging input $p" true true true true
done
classify "$ARGS" "" relay/go.mod
expect "proto and deps input relay/go.mod" true true true false

# --- 4b. Every input of the PR-time advisory scans trips deps: the manifests and lockfiles
# they read and the cargo-deny policy. (The daemon's fuzz workspace is not one: cargo-deny
# checks the daemon workspace (--workspace), which the fuzz crate is not a member of.)
# (The daemon's own manifests and lockfile also trip packaging: section 4c.)
for p in relay/go.sum daemon/deny.toml relay/govulncheck-exceptions.txt scripts/vuln-gate.sh \
  tools/govulncheck/go.sum; do
  classify "$ARGS" "" "$p"
  expect "deps input $p" true false true false
done
# The other pinned tools run a lint or scan gate, not a proto or advisory one: code only.
classify "$ARGS" "" tools/golangci-lint/go.mod
expect "tool pin tools/golangci-lint/go.mod" true false false false

# --- 4c. Every input of the packages and the install matrix trips packaging: the payload
# (manifests, the shipped unit, maintainer scripts, the default Policy, LICENSE), the pinned
# nfpm, the build and version scripts, the daemon's manifests and lockfile and its join code
# and the relay init command (which the matrix runs), and the matrix's own scripts, images
# and workflow, and release.yml, which builds the packages. These are real files today, checked below, so
# a move fails here and sends its author to the classifier.
for p in \
  daemon/packaging/relay-daemon.service \
  daemon/packaging/scripts/postinst.sh \
  relay/packaging/nfpm/relay.yaml \
  daemon/policy.default.toml \
  LICENSE \
  tools/nfpm/go.mod \
  scripts/build-packages.sh \
  scripts/build-version.sh \
  daemon/src/join.rs \
  relay/cmd/relay/init.go \
  daemon/Cargo.toml \
  daemon/crates/relay-policy/Cargo.toml \
  daemon/Cargo.lock \
  docs/operations/daemon-privilege-posture.md; do
  if [ ! -e "$REPO_ROOT/$p" ]; then
    echo "FAIL: package input $p no longer exists — find what builds the packages from it now and update the classifier and this list" >&2
    fail=$((fail + 1))
  fi
done
for p in \
  daemon/packaging/relay-daemon.service \
  daemon/packaging/scripts/postinst.sh \
  relay/packaging/nfpm/relay.yaml \
  daemon/policy.default.toml \
  LICENSE \
  tools/nfpm/go.mod \
  scripts/build-packages.sh \
  scripts/build-version.sh \
  daemon/src/join.rs \
  daemon/src/join/systemctl.rs \
  relay/cmd/relay/init.go \
  scripts/install-matrix-row.sh \
  docker/install-matrix/debian-13.Dockerfile \
  .github/workflows/install-matrix.yml \
  .github/workflows/release.yml; do
  classify "$ARGS" "" "$p"
  expect "packaging input $p" true false false true
done
# The daemon's manifests and lockfile are also dependency inputs, so deps and packaging trip.
for p in daemon/Cargo.toml daemon/crates/relay-policy/Cargo.toml daemon/Cargo.lock; do
  classify "$ARGS" "" "$p"
  expect "deps and packaging input $p" true false true true
done
# The posture doc is documentation, but a payload file: the package bytes change with it.
classify "$ARGS" "" docs/operations/daemon-privilege-posture.md
expect "packaging input docs/operations/daemon-privilege-posture.md" false false false true

# Neighbours that must not trip packaging: daemon source other than join (main's backstop
# covers it), the Relay's source other than the init command, the fuzz workspace's lockfile,
# the Relay's Docker image, the guard script (it reads packages but is not an input of them),
# and the example Policy (not the shipped default).
for p in daemon/src/main.rs daemon/src/dispatch.rs relay/cmd/relay/main.go \
  docker/relay.Dockerfile daemon/fuzz/Cargo.lock \
  scripts/package-guard.sh daemon/policy.example.toml; do
  if [ ! -e "$REPO_ROOT/$p" ]; then
    echo "FAIL: neighbour path $p no longer exists — pick a real neighbour of the packaging paths" >&2
    fail=$((fail + 1))
  fi
  classify "$ARGS" "" "$p"
  expect "packaging neighbour $p" true false false false
done
classify "$ARGS" "" docs/operations/relay-install.md
expect "packaging neighbour docs/operations/relay-install.md" false false false false

# --- 5. Fail open: not a pull request runs every job, whatever the arguments would say.
classify "$ARGS" ""
expect "no event, no paths" true true true true
classify "$ARGS" push
expect "push event" true true true true

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
expect "pull_request touching only an unread doc" false false false false

pr_fixture pr-brand sh -c 'echo changed >>docs/brand/relay-icon.svg'
classify "$PR_FIX" pull_request
expect "pull_request touching only docs/brand" true false false false

pr_fixture pr-packaging sh -c 'mkdir -p daemon/packaging && echo x >daemon/packaging/relay-daemon.service'
classify "$PR_FIX" pull_request
expect "pull_request touching the packaged unit" true false false true

pr_fixture pr-lockfile sh -c 'echo changed >relay/go.sum'
classify "$PR_FIX" pull_request
expect "pull_request touching a lockfile" true false true false

# A rename classifies BOTH paths: moving a file the build reads into docs/ is a code change.
pr_fixture pr-rename git mv relay/main.go docs/adr/main.go
classify "$PR_FIX" pull_request
expect "pull_request renaming code into docs/" true false false false

# No parent to diff against (a fetch-depth of 1): fail open.
ROOT_ONLY="$(new_fixture pr-root-only)"
if ! { git init -q -b main "$ROOT_ONLY" && git -C "$ROOT_ONLY" add -A && git -C "$ROOT_ONLY" commit -q -m only; }; then
  echo "FAIL: cannot build the single-commit fixture" >&2
  fail=$((fail + 1))
fi
classify "$ROOT_ONLY" pull_request
expect "pull_request with no parent commit" true true true true

if [ "$fail" -ne 0 ]; then
  echo "FAIL: $fail case(s) failed" >&2
  exit 1
fi

echo "PASS: ci-changed-paths.sh runs the code jobs for every docs/ path a test reads and skips them only for documentation nothing reads, trips proto on every proto-gate input, deps on every dependency-scan input and packaging on every package and install-matrix input, and fails open off a pull request or without a parent commit."
