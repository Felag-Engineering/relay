#!/usr/bin/env bash
# Proves scripts/catalog-ledger.sh (#1004, DI-30): the append-only rule between ledgers, the
# release refusal for a catalog Template name without an active entry, and the check against
# every release tag, including that withdrawing a name passes and re-adding one fails.
# Hermetic: bash, awk, git and a throwaway repository under its own `mktemp -d`.
#
# NOT `set -e`: every case must run and be reported, not stop at the first failure.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
GATE="$REPO_ROOT/scripts/catalog-ledger.sh"
FIX="$REPO_ROOT/scripts/testdata/catalog-ledger"
WORKDIR="$(mktemp -d)" || { echo "FAIL: mktemp -d failed" >&2; exit 1; }
trap 'case "${WORKDIR:-}" in /*) rm -rf "$WORKDIR" ;; esac' EXIT

fail=0
n=0

# expect <name> <want-rc> <grep-pattern-in-output> -- args...   (runs from the current directory)
expect() {
  local name=$1 want=$2 pattern=$3; shift 4
  local out rc
  out=$(bash "$GATE" "$@" 2>&1); rc=$?
  n=$((n + 1))
  if [ "$rc" -ne "$want" ]; then
    echo "FAIL: $name: rc=$rc want=$want: $out" >&2; fail=$((fail + 1)); return
  fi
  if ! grep -q -- "$pattern" <<<"$out"; then
    echo "FAIL: $name: output lacks '$pattern': $out" >&2; fail=$((fail + 1))
  fi
}

L="$FIX"
T="$FIX/templates"

# --- compare: the append-only rule -----------------------------------------------------------
expect "same ledger"                0 "ok"                    -- compare "$L/base.ledger" "$L/base.ledger"
expect "append"                     0 "1 appended"            -- compare "$L/base.ledger" "$L/appended.ledger"
expect "withdrawal passes"          0 "1 withdrawn"           -- compare "$L/base.ledger" "$L/withdrawn.ledger"
expect "empty baseline"             0 "2 appended"            -- compare /dev/null "$L/base.ledger"
expect "changed body"               1 "beta.two"              -- compare "$L/base.ledger" "$L/changed-body.ledger"
expect "changed class"              1 "beta.two"              -- compare "$L/base.ledger" "$L/changed-class.ledger"
expect "re-added by flipping"       1 "re-adding"             -- compare "$L/withdrawn.ledger" "$L/readded-flip.ledger"
expect "re-added by appending"      2 "repeats name beta.two" -- compare "$L/withdrawn.ledger" "$L/readded-append.ledger"
expect "dropped entry"              1 "dropped"               -- compare "$L/base.ledger" "$L/dropped.ledger"
expect "reordered"                  1 "reordered"             -- compare "$L/base.ledger" "$L/reordered.ledger"
expect "inline comment"             2 "not NAME CLASS"        -- compare "$L/base.ledger" "$L/malformed-comment.ledger"
sed 's/$/\r/' "$L/base.ledger" >"$WORKDIR/crlf.ledger"
expect "CRLF line endings"          2 "carriage return"       -- compare "$L/base.ledger" "$WORKDIR/crlf.ledger"

# --- names: the release refusal, failing closed -----------------------------------------------
# the ok/ pack holds a slot named "unit", which is never counted as a Template name
expect "catalog bound"              0 "2 names"               -- names "$T/ok" "$L/base.ledger"
expect "name missing from ledger"   1 "gamma.three"           -- names "$T/unledgered" "$L/base.ledger"
sed 's/^alpha.one read \(.*\) active$/alpha.one read \1 withdrawn/' "$L/base.ledger" >"$WORKDIR/alpha-withdrawn.ledger"
expect "withdrawn name in catalog"  1 "alpha.one"             -- names "$T/ok" "$WORKDIR/alpha-withdrawn.ledger"
expect "spaced header"              2 "line 1"                -- names "$T/spaced-header" "$L/base.ledger"
expect "indented header"            2 "line 1"                -- names "$T/indented-header" "$L/base.ledger"
expect "top-level inline array"     2 "before the first"      -- names "$T/inline-array" "$L/base.ledger"
expect "literal-string name"        2 "not a single-line"     -- names "$T/literal-name" "$L/base.ledger"
expect "multi-line body"            2 "not a single-line"     -- names "$T/multiline-body" "$L/base.ledger"
expect "other table"                2 "line 1"                -- names "$T/other-header" "$L/base.ledger"
expect "no Template at all"         2 "no \[\[template\]\]"   -- names "$T/empty" "$L/base.ledger"
expect "second pack file"           2 "pack file"             -- names "$T/extra-pack" "$L/base.ledger"
expect "pack file, no catalog"      2 "pack file"             -- names "$T/no-catalog" "$L/base.ledger"
# "." in a name is not a regex wildcard: withdrawn alpha.one must not hide behind active alpha_one
{
  echo "alpha_one read 1111111111111111111111111111111111111111111111111111111111111111 active"
  echo "alpha.one read 1111111111111111111111111111111111111111111111111111111111111111 withdrawn"
  echo "beta.two read 2222222222222222222222222222222222222222222222222222222222222222 active"
} >"$WORKDIR/dot-lookalike.ledger"
expect "withdrawn name, lookalike active" 1 "alpha.one"       -- names "$T/ok" "$WORKDIR/dot-lookalike.ledger"
expect "missing templates dir"      2 "not a directory"       -- names "$WORKDIR/absent" "$L/base.ledger"

# --- check: against every release tag, in a throwaway repository -------------------------------
git_in() { git -C "$WORKDIR/repo" -c user.name=t -c user.email=t@example.invalid "$@"; }
expect_in_repo() { # same as expect, but with the throwaway repository as the working directory
  local name=$1 want=$2 pattern=$3; shift 4
  local out rc
  out=$(cd "$WORKDIR/repo" && bash "$GATE" "$@" 2>&1); rc=$?
  n=$((n + 1))
  if [ "$rc" -ne "$want" ]; then
    echo "FAIL: $name: rc=$rc want=$want: $out" >&2; fail=$((fail + 1)); return
  fi
  if ! grep -q -- "$pattern" <<<"$out"; then
    echo "FAIL: $name: output lacks '$pattern': $out" >&2; fail=$((fail + 1))
  fi
}
commit_state() { # <ledger fixture or -> <message>: the daemon/packaging layout with the ok/ pack
  local led=$1 msg=$2
  mkdir -p "$WORKDIR/repo/daemon/packaging"
  rm -rf "$WORKDIR/repo/daemon/packaging/templates.d"
  cp -R "$T/ok" "$WORKDIR/repo/daemon/packaging/templates.d"
  if [ "$led" = - ]; then
    rm -f "$WORKDIR/repo/daemon/packaging/relay-read-catalog.ledger"
  else
    cp "$led" "$WORKDIR/repo/daemon/packaging/relay-read-catalog.ledger"
  fi
  git_in add -A && git_in commit -q --allow-empty -m "$msg"
}
fresh_repo() { rm -rf "$WORKDIR/repo"; mkdir "$WORKDIR/repo"; git -C "$WORKDIR/repo" init -q; }

fresh_repo
commit_state "$L/base.ledger" "c1"
expect_in_repo "no tags"                  3 "no release tag"      -- check

fresh_repo
commit_state - "c1"
git_in tag v0.0.5
commit_state "$L/base.ledger" "c2"
expect_in_repo "a low tag without the ledger is refused" 1 "v0.0.5 has no ledger" -- check

fresh_repo
commit_state - "c1"
git_in tag v0.1.0
commit_state "$L/base.ledger" "c2"
expect_in_repo "a tag without the ledger is refused" 1 "v0.1.0 has no ledger" -- check

fresh_repo
commit_state "$L/base.ledger" "c1"
git_in tag v0.9.0
commit_state "$L/changed-body.ledger" "c2"
git_in tag v0.10.0
expect_in_repo "older tag froze the entry" 1 "against v0.9.0: body digest of beta.two" -- check

fresh_repo
commit_state "$L/base.ledger" "c1"
git_in tag v0.9.0
commit_state "$L/withdrawn.ledger" "c2"
git_in tag v0.10.0
commit_state "$L/readded-flip.ledger" "c3"
expect_in_repo "re-added after a withdrawn tag" 1 "re-adding withdrawn name beta.two" -- check

fresh_repo
commit_state "$L/base.ledger" "c1"
git_in tag v0.9.0
commit_state "$L/appended.ledger" "c2"
git_in tag v0.10.0
expect_in_repo "tag on HEAD, appended" 0 "compared against 2 tags: v0.9.0 v0.10.0" -- check

fresh_repo
commit_state "$L/base.ledger" "c1"
git_in tag v0.9.0
mkdir -p "$WORKDIR/repo/daemon/packaging/templates.d/relay-read"
cp "$T/unledgered/relay-read/catalog.toml" "$WORKDIR/repo/daemon/packaging/templates.d/relay-read/catalog.toml"
expect_in_repo "unledgered Template"      1 "gamma.three"         -- check

# a shallow clone with both tags fetched compares against both
fresh_repo
commit_state "$L/base.ledger" "c1"
commit_state "$L/base.ledger" "c2"
git_in tag v0.9.0
commit_state "$L/appended.ledger" "c3"
git_in tag v0.10.0
rm -rf "$WORKDIR/shallow"
git clone -q --depth=2 "file://$WORKDIR/repo" "$WORKDIR/shallow"
git -C "$WORKDIR/shallow" fetch -q --depth=2 origin 'refs/tags/*:refs/tags/*'
out=$(cd "$WORKDIR/shallow" && bash "$GATE" check 2>&1); rc=$?
n=$((n + 1))
if [ "$rc" -ne 0 ] || ! grep -q "compared against 2 tags: v0.9.0 v0.10.0" <<<"$out"; then
  echo "FAIL: shallow checkout: rc=$rc: $out" >&2; fail=$((fail + 1))
fi

# --- the real repository --------------------------------------------------------------------
out=$(cd "$REPO_ROOT" && bash "$GATE" check 2>&1); rc=$?
n=$((n + 1))
case "$rc" in
  0 | 3) ;;
  *) echo "FAIL: real ledger: rc=$rc: $out" >&2; fail=$((fail + 1)) ;;
esac
out=$(cd "$REPO_ROOT" && bash "$GATE" names daemon/packaging/templates.d daemon/packaging/relay-read-catalog.ledger 2>&1); rc=$?
n=$((n + 1))
if [ "$rc" -ne 0 ]; then echo "FAIL: real catalog names: rc=$rc: $out" >&2; fail=$((fail + 1)); fi

if [ "$fail" -ne 0 ]; then
  echo "catalog-ledger-test: $fail of $n cases FAILED" >&2
  exit 1
fi
echo "catalog-ledger-test: PASS ($n cases)"
