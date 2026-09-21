#!/usr/bin/env bash
# Proves scripts/security-surface.sh sees what its header claims to see: an untracked
# file (#634 as filed), both halves of a rename off the surface, and refuses loudly
# rather than reporting a clean surface when <base> does not resolve — or resolves but
# cannot be diffed against HEAD (SEC1, no merge base). Nothing proved this before #634
# was filed — that is the whole reason it shipped blind.
#
# Runs against a throwaway fixture repo built from the real script, the real glob
# list and the real .gitignore, so it proves the SHIPPED pairing, not a synthetic one.
# Touches nothing in this working tree.
#
# NOT `set -e`: every case must run and be reported, not stop at the first failure.
set -uo pipefail

# --- Safety preamble: git -C "" clean is a documented no-op that runs in the CURRENT
# repo. With -e off, a failed mktemp would otherwise leave WORKDIR/FIX empty and let
# execution reach a destructive helper against this checkout — which would delete
# .dev-loop/, .claude/worktrees/, and on a developer's machine the LIVE control-plane
# credentials .gitignore keeps out of git (*.pem, *.key, /.dev-fleet/). Every
# destructive helper below asserts $FIX is absolute and is a real git worktree first.
#
# The cleanup trap is installed the instant mktemp succeeds — before the absoluteness
# check below — so every realistic exit removes WORKDIR; nothing here `exit`s ahead of
# it any more. The one case cleanup is not provably safe (WORKDIR came back non-absolute)
# is therefore a stated, commented leak: the trap's own guard refuses to `rm -rf` a
# non-absolute path rather than silently deleting one we can't be sure is ours.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
WORKDIR="$(mktemp -d)" || { echo "FAIL: mktemp -d failed" >&2; exit 1; }
trap 'case "${WORKDIR:-}" in /*) rm -rf "$WORKDIR" ;; esac' EXIT
case "$WORKDIR" in
  /*) ;;
  *) echo "FAIL: mktemp returned a non-absolute path: '$WORKDIR'" >&2; exit 1 ;;
esac
FIX="$WORKDIR/repo"

# --- Hermetic git. The env vars alone are NOT sufficient: ~/.config/git/ignore is a
# path default, not a config value, and survives GIT_CONFIG_GLOBAL=/dev/null. A
# developer with the probe name in their global ignore would suppress case 2; one
# with "notes.txt" in it would make cases 3/5 pass vacuously while CI stayed green.
# `core.excludesFile /dev/null`, set on the fixture after git init, closes that gap.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=security-surface-test GIT_AUTHOR_EMAIL=security-surface-test@example.invalid
export GIT_COMMITTER_NAME=security-surface-test GIT_COMMITTER_EMAIL=security-surface-test@example.invalid

fail=0

# --- Containment. The fixture-build block below is NOT a guarded helper — it runs once,
# unconditionally, before reset_fixture is ever reached — and it writes, `git init`s and
# `git commit`s wherever $FIX points. That is safe today only because $FIX is derived from
# a mktemp'd WORKDIR and never read from an argument or the environment; assert it anyway,
# so the block cannot be made dangerous by an edit that changes where $FIX comes from.
# (Found the hard way: a scratch copy with $FIX repointed at a real checkout committed that
# checkout's working tree before reset_fixture's own guard was reached.)
assert_contained() {
  case "$FIX" in
    "$WORKDIR"/*) ;;
    *) echo "FAIL: refusing to touch '$FIX' — outside $WORKDIR" >&2; exit 1 ;;
  esac
}
assert_contained

# --- Fixture: the real script, the real glob list, the real .gitignore. A synthetic
# list would prove the test harness works while proving nothing about the shipped
# surface definition.
mkdir -p "$FIX/scripts" "$FIX/docs/agents" "$FIX/relay/internal/capability"
cp "$REPO_ROOT/scripts/security-surface.sh" "$FIX/scripts/security-surface.sh"
cp "$REPO_ROOT/docs/agents/security-surface.txt" "$FIX/docs/agents/security-surface.txt"
cp "$REPO_ROOT/.gitignore" "$FIX/.gitignore"
chmod +x "$FIX/scripts/security-surface.sh"

git init -q -b main "$FIX"
git -C "$FIX" config core.excludesFile /dev/null
git -C "$FIX" config commit.gpgsign false

echo 'package capability' > "$FIX/relay/internal/capability/base.go"
echo '# fixture' > "$FIX/README.md"
git -C "$FIX" add -A
git -C "$FIX" commit -q -m "fixture: initial surface + non-surface file"
BASE_SHA="$(git -C "$FIX" rev-parse HEAD)"
git -C "$FIX" branch -q work
git -C "$FIX" checkout -q work

# The script cd's to its own `..`, so an absolute invocation needs no cwd juggling.
SS="$FIX/scripts/security-surface.sh"

# Do NOT create refs/remotes/origin/main here — cases 11 and 12 own it, and its
# absence is exactly what defect 3 (an unresolvable default base) needs to exercise.

# --- Reset must undo commits, not just the worktree. `checkout -f work && clean -qfdx`
# alone leaves `work` ahead of `main` after any case that commits, which silently
# poisons every later case regardless of table order. This restores commits, refs,
# worktree and ignored files, so no case depends on running after another.
reset_fixture() {
  # Two separate assertions, because they prove two separate things: containment (this is
  # somewhere under our own throwaway WORKDIR, not e.g. $REPO_ROOT) and shape (it is
  # actually a git worktree, not an empty directory `git -C` would silently walk up from).
  assert_contained
  [ -d "$FIX/.git" ] || { echo "FAIL: refusing to clean '$FIX' — not a git worktree" >&2; exit 1; }
  git -C "$FIX" checkout -q -f work
  git -C "$FIX" reset -q --hard "$BASE_SHA"
  git -C "$FIX" clean -qfdx
  git -C "$FIX" update-ref -d refs/remotes/origin/main 2>/dev/null
  return 0
}

# --- Capture harness. Globals only: `local out=$(cmd)` sets $? from `local`, not the
# command (measured: rc 0 for a command that exits 7). Every assertion below is an rc
# comparison, so that one slip would make the entire suite pass forever.
OUT=""
RC=0
ERRFILE="$WORKDIR/stderr"

capture() {
  OUT="$("$@" 2>"$ERRFILE")"
  RC=$?
}

capture_stdin() {
  OUT="$(printf '%s\n' "$1" | "$SS" - 2>"$ERRFILE")"
  RC=$?
}

# check <name> <want_rc> <stdout_mode: exact|contains> <want_stdout>
#       <stderr_mode: empty|nonempty|contains:<text>>
#
# `contains:` exists because `nonempty` cannot tell two refusals apart, and this script's
# three exit-2 paths are no longer independent: since SEC1 the diff guard also catches an
# unresolvable ref, so removing the rev-parse guard leaves every rc assertion green. Pinning
# each refusal to its own MESSAGE is what keeps that guard load-bearing against this suite —
# a guard no test can notice the loss of is the exact defect #634 was.
check() {
  local name=$1 want_rc=$2 stdout_mode=$3 want_stdout=$4 stderr_mode=$5
  local err ok want_err
  err="$(cat "$ERRFILE" 2>/dev/null)"
  ok=1

  if [ "$RC" -ne "$want_rc" ]; then
    echo "FAIL: $name: rc=$RC want=$want_rc (stdout=[$OUT] stderr=[$err])" >&2
    ok=0
  fi

  case "$stdout_mode" in
    exact)
      if [ "$OUT" != "$want_stdout" ]; then
        echo "FAIL: $name: stdout=[$OUT] want exactly [$want_stdout]" >&2
        ok=0
      fi
      ;;
    contains)
      case "$OUT" in
        *"$want_stdout"*) ;;
        *) echo "FAIL: $name: stdout=[$OUT] does not contain [$want_stdout]" >&2; ok=0 ;;
      esac
      ;;
    *)
      echo "FAIL: $name: unknown stdout_mode '$stdout_mode'" >&2
      ok=0
      ;;
  esac

  case "$stderr_mode" in
    empty)
      if [ -n "$err" ]; then
        echo "FAIL: $name: stderr not empty: [$err]" >&2
        ok=0
      fi
      ;;
    nonempty)
      if [ -z "$err" ]; then
        echo "FAIL: $name: stderr empty, wanted a refusal message" >&2
        ok=0
      fi
      ;;
    contains:*)
      want_err=${stderr_mode#contains:}
      case "$err" in
        *"$want_err"*) ;;
        *) echo "FAIL: $name: stderr=[$err] does not contain [$want_err]" >&2; ok=0 ;;
      esac
      ;;
    *)
      echo "FAIL: $name: unknown stderr_mode '$stderr_mode'" >&2
      ok=0
      ;;
  esac

  [ "$ok" -eq 1 ] || fail=$((fail + 1))
}

# --- Preconditions. If a human edit to the glob list or .gitignore moved these, the
# cases below would pass vacuously and the suite would stay green while proving
# nothing — so fail loudly here instead, naming exactly what moved.
grep -qx 'relay/internal/capability/\*\*' "$FIX/docs/agents/security-surface.txt" ||
  { echo "FAIL: precondition: 'relay/internal/capability/**' not in security-surface.txt — cases 2/4/6/6b/6c/7* assume it" >&2; fail=$((fail + 1)); }
grep -qx '\.claude/\*\*' "$FIX/docs/agents/security-surface.txt" ||
  { echo "FAIL: precondition: '.claude/**' not in security-surface.txt — case 4 assumes it" >&2; fail=$((fail + 1)); }
grep -qx '/\.claude/\*' "$FIX/.gitignore" ||
  { echo "FAIL: precondition: '/.claude/*' not in .gitignore — case 3 assumes it" >&2; fail=$((fail + 1)); }
grep -qx '!/\.claude/commands/' "$FIX/.gitignore" ||
  { echo "FAIL: precondition: '!/.claude/commands/' not in .gitignore — case 4 assumes it" >&2; fail=$((fail + 1)); }

for p in README.md notes.txt relay/internal/metrics/moved.go; do
  if printf '%s\n' "$p" | "$SS" - >/dev/null 2>&1; then
    echo "FAIL: precondition: '$p' matches a surface glob — cases 5/6b/8b assume it does not" >&2
    fail=$((fail + 1))
  fi
done

# --- Cases. Each preceded by reset_fixture; stderr asserted empty unless stated.

# 0: meta — proves capture() actually observes a non-zero exit and real stdout,
# rather than reporting rc 0 for everything regardless of what ran (see the
# `local out=$(...)` pitfall in the header above).
reset_fixture
capture bash -c 'echo x; exit 7'
check "case0-meta-capture-observes-nonzero" 7 exact "x" empty

# 1: clean tree — nothing on the surface.
reset_fixture
capture "$SS" main
check "case1-clean-tree" 1 exact "" empty

# 2: untracked new file on the surface — #634 as filed. Fails against the
# pre-fix script (git diff never sees an untracked path).
reset_fixture
touch "$FIX/relay/internal/capability/zz_probe_untracked.go"
capture "$SS" main
check "case2-untracked-new-file" 0 exact "relay/internal/capability/zz_probe_untracked.go" empty

# 3: untracked file suppressed by .gitignore's /.claude/*.
reset_fixture
mkdir -p "$FIX/.claude"
touch "$FIX/.claude/zz_probe_local.json"
capture "$SS" main
check "case3-ignored-untracked" 1 exact "" empty

# 4: untracked file under .claude/commands/, re-included by !/.claude/commands/ —
# non-vacuity control for case 3.
reset_fixture
mkdir -p "$FIX/.claude/commands"
touch "$FIX/.claude/commands/zz_probe.md"
capture "$SS" main
check "case4-reincluded-untracked" 0 exact ".claude/commands/zz_probe.md" empty

# 5: untracked file off the surface entirely.
reset_fixture
touch "$FIX/notes.txt"
capture "$SS" main
check "case5-nonsurface-untracked" 1 exact "" empty

# 6: deleting a surface file counts as a hit — chosen, not incidental (see header).
reset_fixture
rm "$FIX/relay/internal/capability/base.go"
capture "$SS" main
check "case6-deletion" 0 exact "relay/internal/capability/base.go" empty

# 6b: a staged (uncommitted) `git mv` of a surface file OFF the surface must report
# the OLD path — defect 2. With rename detection on, `--cached` alone reports only
# the new path and this case fails against the pre-fix script.
reset_fixture
mkdir -p "$FIX/relay/internal/metrics"
git -C "$FIX" mv relay/internal/capability/base.go relay/internal/metrics/moved.go
capture "$SS" main
check "case6b-staged-rename-off-surface" 0 contains "relay/internal/capability/base.go" empty

# 6c: same rename, committed — proves the base...HEAD arm also needs --no-renames.
reset_fixture
mkdir -p "$FIX/relay/internal/metrics"
git -C "$FIX" mv relay/internal/capability/base.go relay/internal/metrics/moved.go
git -C "$FIX" commit -q -m "move guard off the surface"
capture "$SS" main
check "case6c-committed-rename-off-surface" 0 contains "relay/internal/capability/base.go" empty

# 7a/7b/7c: pre-existing behaviour that the fix must not regress.
reset_fixture
echo '// modified' >> "$FIX/relay/internal/capability/base.go"
capture "$SS" main
check "case7a-modified-unstaged" 0 exact "relay/internal/capability/base.go" empty

reset_fixture
echo '// modified' >> "$FIX/relay/internal/capability/base.go"
git -C "$FIX" add relay/internal/capability/base.go
capture "$SS" main
check "case7b-staged" 0 exact "relay/internal/capability/base.go" empty

reset_fixture
echo 'package capability' > "$FIX/relay/internal/capability/new.go"
git -C "$FIX" add -A
git -C "$FIX" commit -q -m "add a new surface file on work"
capture "$SS" main
check "case7c-committed-since-base" 0 exact "relay/internal/capability/new.go" empty

# 8a/8b: stdin mode is deliberately untouched by any of the above.
reset_fixture
capture_stdin "relay/internal/capability/x.go"
check "case8a-stdin-surface" 0 exact "relay/internal/capability/x.go" empty
capture_stdin "README.md"
check "case8a-stdin-readme" 1 exact "" empty
capture_stdin "notes.txt"
check "case8a-stdin-notes" 1 exact "" empty

reset_fixture
touch "$FIX/relay/internal/capability/zz_probe_untracked.go"
capture_stdin "notes.txt"
check "case8b-stdin-worktree-independence" 1 exact "" empty

# 9: the glob list itself missing — a pre-existing refusal, still exit 2.
reset_fixture
rm "$FIX/docs/agents/security-surface.txt"
capture "$SS" main
check "case9-missing-glob-list" 2 exact "" "contains:security-surface.txt missing"

# 10: an explicit base ref that does not resolve — defect 3.
reset_fixture
capture "$SS" typo-ref
check "case10-bad-base-ref" 2 exact "" "contains:base ref 'typo-ref' does not resolve"

# 11: the default base (origin/main), absent — the pr-respond.md:59 no-argument
# invocation, live before this fix.
reset_fixture
capture "$SS"
check "case11-default-base-absent" 2 exact "" "contains:base ref 'origin/main' does not resolve"

# 12: the default base, present — the happy path defect 3 must not break.
reset_fixture
git -C "$FIX" update-ref refs/remotes/origin/main "$BASE_SHA"
touch "$FIX/relay/internal/capability/zz_probe_default.go"
capture "$SS"
check "case12-default-base-present" 0 exact "relay/internal/capability/zz_probe_default.go" empty

# 13: a base ref that RESOLVES but has NO MERGE BASE with HEAD (a shallow clone, or
# unrelated histories) — SEC1. `git diff <base>...HEAD` itself fatals, and losing that
# arm silently would be worse than #634: in Stage 6.5's actual usage it carries the
# ENTIRE change. Reproduced with a real orphan branch, no network required. The branch
# is deleted afterwards so it cannot leak into a later case (git-mv or commit cases
# would otherwise pick up a stray ref left on the fixture).
reset_fixture
git -C "$FIX" checkout -q --orphan unrelated
touch "$FIX/relay/internal/capability/orphan_surface.go"
git -C "$FIX" add -A
git -C "$FIX" commit -q -m "surface file on an unrelated history (no merge base with main)"
capture "$SS" main
check "case13-no-merge-base" 2 exact "" "contains:failed (no merge base"
git -C "$FIX" checkout -q -f work
git -C "$FIX" branch -q -D unrelated

# 14: GIT_DIR/GIT_WORK_TREE in the environment must not redirect the check at another
# repository (SEC5). Without the `unset`, every git call below the `cd` reads the OTHER
# repo's history and index, so the script reports that repo's surface as this one's — and
# an empty result there reads as "clean" here. The fixture is clean at this point and the
# decoy repo has an untracked surface file, so the two answers are distinguishable.
reset_fixture
OTHER="$WORKDIR/decoy"
rm -rf "$OTHER"
mkdir -p "$OTHER/relay/internal/capability"
git init -q -b main "$OTHER"
git -C "$OTHER" config core.excludesFile /dev/null
git -C "$OTHER" config commit.gpgsign false
echo '# decoy' > "$OTHER/README.md"
git -C "$OTHER" add -A
git -C "$OTHER" commit -q -m "decoy repo"
touch "$OTHER/relay/internal/capability/decoy_leak.go"
capture env GIT_DIR="$OTHER/.git" GIT_WORK_TREE="$OTHER" "$SS" main
check "case14-git-dir-redirect" 1 exact "" empty
rm -rf "$OTHER"

if [ "$fail" -ne 0 ]; then
  echo "FAIL: $fail case(s) failed" >&2
  exit 1
fi

echo "PASS: security-surface.sh sees untracked files, both halves of a rename, and refuses (never 'clean') on an unresolvable base ref or an undiffable one (#634)."
