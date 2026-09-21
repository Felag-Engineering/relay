#!/usr/bin/env bash
# Proves scripts/codex-review.sh exits 3 only when Codex is ABSENT — the plugin/CLI
# missing, an exhausted usage quota, or a rejected credential — and keeps every other
# failure non-zero and NON-3 (#620).
#
# The hazard this suite exists for: the script decides absence by matching TEXT, and
# Codex's report is also text. A review of the very change that added the matching quotes
# every trigger phrase, so a careless matcher deletes a delivered review and records a
# single-reviewer gate that in fact had two. C3b/C3c/C5 are that case, with a full review
# body built here out of the phrases the classifier looks for.
#
# Hermetic: the companion is a STUB on PATH under a throwaway WORKDIR, driven by env vars
# per case (the scripts/demo-fleet-test.sh idiom — one stub, not one per case), and HOME is
# redirected at a fake plugin cache so the real script's discovery glob resolves. Modelled
# on scripts/security-surface-test.sh's harness (mktemp WORKDIR, guarded EXIT trap,
# capture/check, fail counter, PASS line). Touches nothing in this working tree and reaches
# no network, no node and no real Codex.
#
# NOT `set -e`: every case must run and be reported, not stop at the first failure. The two
# non-vacuity preconditions are the exception — they ABORT, because a stub the script never
# reaches makes every exit-3 case below pass through the genuine plugin-missing path and
# prove nothing.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
WORKDIR="$(mktemp -d)" || { echo "FAIL: mktemp -d failed" >&2; exit 1; }
trap 'case "${WORKDIR:-}" in /*) rm -rf "$WORKDIR" ;; esac' EXIT
case "$WORKDIR" in
  /*) ;;
  *) echo "FAIL: mktemp returned a non-absolute path: '$WORKDIR'" >&2; exit 1 ;;
esac

FIX="$WORKDIR/repo"
SCRIPT="$FIX/scripts/codex-review.sh"
STUB_BIN="$WORKDIR/bin"
NOCODEX_BIN="$WORKDIR/bin-no-codex"
FAKE_HOME="$WORKDIR/home"
EMPTY_HOME="$WORKDIR/home-empty"
STUB_ARGV_LOG="$WORKDIR/argv.log"
STUB_READY="$WORKDIR/stub-ready"
STUB_PGID="$WORKDIR/stub-pgid"
OUTFILE="$WORKDIR/stdout"
ERRFILE="$WORKDIR/stderr"
REVIEW_BODY="$WORKDIR/review-body.txt"
SHORT_REVIEW="$WORKDIR/review-short.txt"
LONG_NOTICE="$WORKDIR/limit-notice-long.txt"
HUGE_NOTICE="$WORKDIR/limit-notice-huge.txt"

# --- Hermetic git, same reasoning as security-surface-test.sh: a developer's global
# config or excludesFile must not reach the fixture.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=codex-review-test GIT_AUTHOR_EMAIL=codex-review-test@example.invalid
export GIT_COMMITTER_NAME=codex-review-test GIT_COMMITTER_EMAIL=codex-review-test@example.invalid

fail=0

assert_contained() {
  case "$FIX" in
    "$WORKDIR"/*) ;;
    *) echo "FAIL: refusing to touch '$FIX' — outside $WORKDIR" >&2; exit 1 ;;
  esac
}
assert_contained

# --- Fixture repo. The script cd's to its own `..`, so the copy must sit in a `scripts/`
# directory with a git worktree above it: `diff` mode resolves a base ref and refuses an
# empty change, both before the companion is ever invoked.
mkdir -p "$FIX/scripts" "$FIX/docs/design/plans" "$STUB_BIN" "$NOCODEX_BIN" \
         "$FAKE_HOME/.claude/plugins/cache/openai-codex/codex/1.0.0/scripts" \
         "$EMPTY_HOME"
cp "$REPO_ROOT/scripts/codex-review.sh" "$SCRIPT"
chmod +x "$SCRIPT"
: >"$FAKE_HOME/.claude/plugins/cache/openai-codex/codex/1.0.0/scripts/codex-companion.mjs"

git init -q -b main "$FIX"
git -C "$FIX" config core.excludesFile /dev/null
git -C "$FIX" config commit.gpgsign false
echo '# fixture' >"$FIX/README.md"
echo 'plan under review' >"$FIX/docs/design/plans/probe.md"
git -C "$FIX" add -A
git -C "$FIX" commit -q -m "fixture: base commit"
git -C "$FIX" branch -q work
git -C "$FIX" checkout -q work
echo '# fixture, modified on work' >>"$FIX/README.md"   # so `diff` mode has a non-empty change

# --- The review body: a plausible Codex review OF THIS VERY CHANGE, quoting every phrase
# the classifier matches on. Shared by C3b, C3c and C5, so those three differ only in which
# stream carried it and what the companion exited with.
cat >"$REVIEW_BODY" <<'BODY'
Verdict: CHANGES_REQUESTED

1. BLOCKING — scripts/codex-review.sh:150. The classifier treats any capture containing
   "usage limit" as absence. A review of this change quotes that phrase, and so does this
   finding. If the match ever runs on a delivered report the gate records one reviewer
   where two ran.

2. BLOCKING — scripts/codex-review.sh:78. limit_re also matches "rate limit exceeded",
   "too many requests" and "429 Too Many Requests". Codex's own transport emits
   "429 " on a retryable upstream error AFTER the report has been written, so a complete
   review can arrive alongside that string with a non-zero status.

3. SUGGESTION — scripts/codex-review.sh:79. auth_re matches "authentication failed",
   "401 Unauthorized" and "not logged in". A reviewer discussing a token refresh path will
   write all three. Consider requiring the capture to be notice-shaped first.

4. SUGGESTION — scripts/codex-review-test.sh. Add a case where the companion delivers a
   full report and then exits non-zero; that is the path where bytes get destroyed.

Overall: the direction is right, the matching needs a shape guard before it is safe.
BODY

# 430 bytes, on purpose: under notice_max_stderr (1024), so the byte bounds alone would
# classify it. Only report_re can reject it, which is what C3c-short pins.
cat >"$SHORT_REVIEW" <<'BODY'
Verdict: CHANGES_REQUESTED

1. BLOCKING — codex-review.sh:150. "usage limit" and "rate limit exceeded" appear in this
   review, and "429 Too Many Requests" and "401 Unauthorized" below. Any of them on a
   failed run must not be read as Codex being absent.

2. SUGGESTION — add a case for a report delivered with a non-zero exit.

3. SUGGESTION — the header should say each phrase matched here is only an unobserved guess.
BODY

# --- A quota notice too big for notice_max_total (256) but well inside notice_max_stderr
# (1024), carrying no report marker: the ONLY capture branch one of the shape test can
# classify. Its size is asserted below, because a fixture that drifts out of that window
# makes case1f vacuous. A retry-after header and a doc link are the plausible shape.
cat >"$LONG_NOTICE" <<'NOTICE'
codex: your organisation has reached its usage limit on this plan.
retry-after: 1800
The quota window resets in 30 min. Requests issued before then are refused
upstream and are not charged to the account.
Docs: https://example.invalid/docs/quotas
Session: 8f2a-41c7-9b30-ee51   Plan: team   Region: eu-west-1
If this is unexpected, open the usage dashboard for the organisation.
NOTICE

# The same notice four times over, so it exceeds notice_max_stderr (1024) while staying
# marker-free: case1g's bound on branch one from above.
for _ in 1 2 3 4; do cat "$LONG_NOTICE"; done >"$HUGE_NOTICE"

# --- The stub companion. ONE `node` replacement for every case, driven by env vars set per
# `run` invocation. It ignores the .mjs argument entirely and appends its full argv to
# $STUB_ARGV_LOG, which C8 reads to prove the script never requested write access.
cat >"$STUB_BIN/node" <<'STUB'
#!/usr/bin/env bash
set -u
printf '%s\n' "$*" >>"$STUB_ARGV_LOG"

case "${STUB_CASE:-report}" in
  report)
    printf 'STUB REPORT MARKER 9001\n'
    exit 0
    ;;
  emit)
    [ -n "${STUB_OUT_TEXT:-}" ] && printf '%s' "$STUB_OUT_TEXT"
    [ -n "${STUB_ERR_TEXT:-}" ] && printf '%s' "$STUB_ERR_TEXT" >&2
    [ -n "${STUB_OUT_FILE:-}" ] && cat -- "$STUB_OUT_FILE"
    [ -n "${STUB_ERR_FILE:-}" ] && cat -- "$STUB_ERR_FILE" >&2
    exit "${STUB_EXIT:-0}"
    ;;
  signal)
    # Report our process group (the script's, since we are its child) so the caller can
    # signal the whole group, then write a partial report and block. bash's printf to a
    # file lands immediately, so the partial capture is on disk before the kill arrives.
    ps -o pgid= -p $$ | tr -d ' ' >"$STUB_PGID"
    printf 'PARTIAL REPORT MARKER 4711\n'
    touch "$STUB_READY"
    sleep 30
    exit 0
    ;;
esac
exit 1
STUB
chmod +x "$STUB_BIN/node"

# `codex` exists only to satisfy the script's `command -v codex` check.
printf '#!/usr/bin/env bash\nexit 0\n' >"$STUB_BIN/codex"
chmod +x "$STUB_BIN/codex"

# A PATH with the companion runner but NO codex CLI — C6a's total-absence control.
cp "$STUB_BIN/node" "$NOCODEX_BIN/node"

# --- Capture harness. Globals only, and BOTH streams to files: `local out=$(cmd)` takes $?
# from `local` (measured at security-surface-test.sh:106), and `$( )` strips trailing
# newlines, which would defeat C3b/C5's byte-for-byte assertions on the review body.
OUT=""
ERR=""
RC=0

capture() {
  "$@" >"$OUTFILE" 2>"$ERRFILE"
  RC=$?
  OUT="$(cat "$OUTFILE" 2>/dev/null)"
  ERR="$(cat "$ERRFILE" 2>/dev/null)"
}

# run <env assignments...> -- <script args...>
# Every stub-facing variable is unset first, so a leftover from an earlier case cannot leak
# into this one; the caller re-adds exactly what it needs.
run() {
  local envs=()
  while [ $# -gt 0 ] && [ "$1" != "--" ]; do
    envs+=("$1")
    shift
  done
  shift # drop the "--" separator
  # The caller's assignments come LAST so a case can override a default (C6b overrides HOME
  # to point at a cache with no companion in it).
  capture env \
    -u STUB_CASE -u STUB_OUT_TEXT -u STUB_ERR_TEXT -u STUB_OUT_FILE -u STUB_ERR_FILE -u STUB_EXIT \
    PATH="$STUB_BIN:$PATH" HOME="$FAKE_HOME" \
    STUB_ARGV_LOG="$STUB_ARGV_LOG" STUB_READY="$STUB_READY" STUB_PGID="$STUB_PGID" \
    "${envs[@]}" \
    bash "$SCRIPT" "$@"
}

# check <name> <want_rc> <stdout_mode: exact|contains|any> <want_stdout>
#       <stderr_mode: empty|nonempty|contains:<text>|any>
check() {
  local name=$1 want_rc=$2 stdout_mode=$3 want_stdout=$4 stderr_mode=$5
  local ok=1 want_err

  if [ "$RC" -ne "$want_rc" ]; then
    echo "FAIL: $name: rc=$RC want=$want_rc (stdout=[$OUT] stderr=[$ERR])" >&2
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
    any) ;;
    *) echo "FAIL: $name: unknown stdout_mode '$stdout_mode'" >&2; ok=0 ;;
  esac

  case "$stderr_mode" in
    empty)
      if [ -n "$ERR" ]; then
        echo "FAIL: $name: stderr not empty: [$ERR]" >&2
        ok=0
      fi
      ;;
    nonempty)
      if [ -z "$ERR" ]; then
        echo "FAIL: $name: stderr empty, wanted a message" >&2
        ok=0
      fi
      ;;
    contains:*)
      want_err=${stderr_mode#contains:}
      case "$ERR" in
        *"$want_err"*) ;;
        *) echo "FAIL: $name: stderr=[$ERR] does not contain [$want_err]" >&2; ok=0 ;;
      esac
      ;;
    any) ;;
    *) echo "FAIL: $name: unknown stderr_mode '$stderr_mode'" >&2; ok=0 ;;
  esac

  [ "$ok" -eq 1 ] || fail=$((fail + 1))
}

# The cause line is the one line matching `^codex-review: Codex unavailable`. AC1 is "one
# stderr line naming the cause", so its content and its COUNT are both assertions.
cause_line() { grep -m1 '^codex-review: Codex unavailable' "$ERRFILE" 2>/dev/null; }
cause_line_count() { grep -c '^codex-review: Codex unavailable' "$ERRFILE" 2>/dev/null; }

assert_stdout_empty() {
  # The file, not $OUT: `$( )` strips trailing newlines, so a lone newline would read empty.
  [ -s "$OUTFILE" ] || return 0
  echo "FAIL: $1: stdout is not empty on exit 3: [$OUT]" >&2
  fail=$((fail + 1))
}

assert_stderr_contains() {
  case "$ERR" in
    *"$2"*) return 0 ;;
  esac
  echo "FAIL: $1: ${3:-stderr lacks [$2]}" >&2
  fail=$((fail + 1))
}

assert_stderr_lacks() {
  case "$ERR" in
    *"$2"*) ;;
    *) return 0 ;;
  esac
  echo "FAIL: $1: ${3:-stderr unexpectedly contains [$2]}" >&2
  fail=$((fail + 1))
}

assert_cause_line_is() {
  local got; got="$(cause_line)"
  if [ "$got" != "$2" ]; then
    echo "FAIL: $1: stderr first line=[$got] want exactly [$2]" >&2
    fail=$((fail + 1))
  fi
  local n; n="$(cause_line_count)"
  if [ "$n" != "1" ]; then
    echo "FAIL: $1: $n lines name a cause, want exactly 1 (AC1)" >&2
    fail=$((fail + 1))
  fi
}

# "the script never claimed absence". Asserted on the cause line rather than on the phrase
# "one reviewer", because the review body in this fixture QUOTES that phrase — which is the
# very confusion the classifier exists to avoid, so the assertion must not depend on the
# report being free of it.
assert_no_cause_line() {
  local n; n="$(cause_line_count)"
  if [ "$n" != "0" ]; then
    echo "FAIL: $1: ${2:-stderr claims Codex was unavailable}: [$(cause_line)]" >&2
    fail=$((fail + 1))
  fi
}

assert_cause_line_lacks() {
  local got; got="$(cause_line)"
  case "$got" in
    *"$2"*) echo "FAIL: $1: ${3:-the cause line contains [$2]}: [$got]" >&2; fail=$((fail + 1)) ;;
  esac
}

# --- Non-vacuity preconditions. These ABORT rather than increment `fail`: with `set -e`
# off, a stub the script never reaches would otherwise bury the real cause under a dozen
# misleading case failures, every one of them passing through the genuine plugin-missing
# path (which also exits 3).
: >"$STUB_ARGV_LOG"

grep -q '\.claude/plugins/cache/openai-codex/codex/' "$SCRIPT" || {
  echo "FAIL: precondition: companion discovery path changed — the HOME stub no longer reaches the stub companion and every exit-3 case below would pass vacuously" >&2
  exit 1
}

# P2. Note what this precondition buys the cases below: the plugin-missing path ALSO exits 3
# and also says "one reviewer", so every `check … 3 … contains:one reviewer` assertion would
# pass on a fixture the script never reached. P2 is what makes those assertions mean the
# classifier ran; the cases that also carry a stub-only positive assertion say so in place.
run STUB_CASE=report -- diff main
if [ "$RC" -ne 0 ] || [ "${OUT#*STUB REPORT MARKER 9001}" = "$OUT" ] || [ ! -s "$STUB_ARGV_LOG" ]; then
  argvstate=empty; [ -f "$STUB_ARGV_LOG" ] || argvstate=missing
  echo "FAIL: precondition: stub companion not reached (rc=$RC, argv log $argvstate); the absence cases below prove nothing" >&2
  exit 1
fi

# --- Cases.

# 0: meta — proves capture() observes a non-zero exit and real stdout rather than reporting
# rc 0 for everything (the `local out=$(...)` pitfall).
capture bash -c 'echo x; exit 7'
check "case0-meta-capture-observes-nonzero" 7 exact "x" empty

# 1: the issue as filed — an exhausted quota on stderr with a stated reset, companion exit 1.
run STUB_CASE=emit STUB_EXIT=1 \
    STUB_ERR_TEXT="You've hit your usage limit. Try again in 30 min."$'\n' -- diff main
check "case1-limit-stderr" 3 any "" "contains:one reviewer"
[ "$RC" -eq 3 ] || echo "FAIL: case1-limit-stderr: rc=$RC want=3 — an exhausted quota is still being reported as a failed review (#620 as filed)" >&2
assert_stdout_empty "case1-limit-stderr"
assert_cause_line_is "case1-limit-stderr" \
  'codex-review: Codex unavailable — usage limit reached (message cites "30 min"); this gate runs with one reviewer'

# 1b: the same notice on STDOUT instead — 41 bytes, far under notice_max_total (256). Which
# stream Codex uses is unobservable here, so both branches of the shape test are pinned.
run STUB_CASE=emit STUB_EXIT=1 \
    STUB_OUT_TEXT="usage limit reached; try again in 30 min"$'\n' -- diff main
[ "$RC" -eq 3 ] || echo "FAIL: case1b-limit-stdout: rc=$RC want=3 — a notice-sized limit message on stdout is not classified" >&2
check "case1b-limit-stdout" 3 any "" "contains:one reviewer"
assert_stdout_empty "case1b-limit-stdout"
assert_cause_line_is "case1b-limit-stdout" \
  'codex-review: Codex unavailable — usage limit reached (message cites "30 min"); this gate runs with one reviewer'

# 1c: a limit with NO reset time, plus both fabrication inputs — a message that SAYS there
# is no reset, and the word "reset" used about a credential. Neither may become a cited time.
# The `usage limit reached` assertion is STUB-ONLY: the genuine plugin-missing path also
# exits 3, and would satisfy a bare rc check.
run STUB_CASE=emit STUB_EXIT=1 \
    STUB_ERR_TEXT="usage limit reached, no reset stated. reset your token in the dashboard."$'\n' -- diff main
check "case1c-limit-no-reset" 3 any "" "contains:one reviewer"
assert_stderr_contains "case1c-limit-no-reset" "usage limit reached" \
  "stderr lacks [usage limit reached] — this rc=3 came from the plugin-missing path, not the classifier"
assert_cause_line_lacks "case1c-limit-no-reset" "message cites" "stderr fabricated a reset clause"

# 1d: a credential inside a LIMIT message. Classification is limit-first, so excluding auth
# messages from extraction does not cover this path — neither the cause line NOR the replay
# may carry it (AGENTS.md §9). Redaction runs on every branch, not only the auth one,
# because this is the branch that demonstrably reached a key.
run STUB_CASE=emit STUB_EXIT=1 \
    STUB_ERR_TEXT="usage limit reached; try again after rotating key sk-proj-A1b2C3d4E5f6G7h8"$'\n' -- diff main
check "case1d-limit-with-credential" 3 any "" "contains:one reviewer"
assert_cause_line_lacks "case1d-limit-with-credential" "sk-proj-" \
  "the cause line leaked a credential — AGENTS.md §9, and the limit branch is reached first so the auth exclusion does not cover it"
assert_stderr_lacks "case1d-limit-with-credential" "sk-proj-A1b2C3d4E5f6G7h8" \
  "the replay printed a credential in clear — the replay is the shape a coordinator quotes into a PR body, so the limit branch must redact too"
assert_stderr_contains "case1d-limit-with-credential" "[redacted]" \
  "stderr lacks [redacted] — the key vanished from the replay by being discarded, not by being redacted"

# 1e: the reset time in a plausible mixed case. Extraction is case-insensitive, so without
# the same -i on the re-validation this is extracted and then silently dropped, losing AC1's
# "when it resets if stated" over nothing but capitalisation.
run STUB_CASE=emit STUB_EXIT=1 \
    STUB_ERR_TEXT="Usage limit reached. Try again in 30 Minutes."$'\n' -- diff main
check "case1e-reset-mixed-case" 3 any "" "contains:one reviewer"
assert_cause_line_is "case1e-reset-mixed-case" \
  'codex-review: Codex unavailable — usage limit reached (message cites "30 Minutes"); this gate runs with one reviewer'

# 1f: branch ONE of the shape test, alone. Every other classified case here is under
# notice_max_total (256) and so reaches absence through branch two; this notice is 379
# bytes, so only "nothing on stdout and stderr under notice_max_stderr (1024)" can classify
# it. Delete that branch and this is the case that goes red.
c1f_bytes=$(wc -c <"$LONG_NOTICE")
if [ "$c1f_bytes" -le 256 ] || [ "$c1f_bytes" -gt 1024 ]; then
  echo "FAIL: case1f-stderr-only-notice: fixture is $c1f_bytes bytes, outside (256, 1024] — this case no longer isolates branch one" >&2
  fail=$((fail + 1))
fi
run STUB_CASE=emit STUB_EXIT=1 STUB_ERR_FILE="$LONG_NOTICE" -- diff main
[ "$RC" -eq 3 ] || echo "FAIL: case1f-stderr-only-notice: rc=$RC want=3 — a stderr-only quota notice above notice_max_total is not classified; only branch one of the shape test can reach it" >&2
check "case1f-stderr-only-notice" 3 any "" "contains:one reviewer"
assert_stdout_empty "case1f-stderr-only-notice"
assert_cause_line_is "case1f-stderr-only-notice" \
  'codex-review: Codex unavailable — usage limit reached (message cites "30 min"); this gate runs with one reviewer'

# 1g: branch one's bound from ABOVE, which case1f cannot pin — widening notice_max_stderr
# leaves case1f green. A marker-free capture too big to be a notice must stay a failed
# review however many trigger phrases it quotes, because "too big to be a diagnostic" is the
# only thing left protecting it once report_re has nothing to match on. Costs a missed
# absence if a real quota notice is ever this verbose, which is the safe direction.
c1g_bytes=$(wc -c <"$HUGE_NOTICE")
if [ "$c1g_bytes" -le 1024 ]; then
  echo "FAIL: case1g-oversized-notice: fixture is $c1g_bytes bytes, not above notice_max_stderr (1024) — this case no longer bounds branch one from above" >&2
  fail=$((fail + 1))
fi
run STUB_CASE=emit STUB_EXIT=1 STUB_ERR_FILE="$HUGE_NOTICE" -- diff main
[ "$RC" -eq 1 ] || echo "FAIL: case1g-oversized-notice: rc=$RC want=1 — a capture far too big to be a diagnostic was classified as absence; it carries no report marker, so the byte bound is the only guard left" >&2
check "case1g-oversized-notice" 1 exact "" "contains:usage limit"
assert_no_cause_line "case1g-oversized-notice" "an oversized marker-free capture was recorded as Codex being absent"

# 2: a rejected credential. Nothing at all is extracted from an auth failure, and the
# replay redacts both shapes it knows — a bare key and a bearer header, since an auth
# diagnostic is as likely to echo the rejected header as to name the key.
run STUB_CASE=emit STUB_EXIT=1 \
    STUB_ERR_TEXT="unauthorized (401) — run codex login; token sk-STUBSECRET999 rejected"$'\n'"sent Authorization: Bearer abcDEF123456789012345678"$'\n' -- diff main
check "case2-auth" 3 any "" "contains:one reviewer"
assert_stdout_empty "case2-auth"
assert_cause_line_is "case2-auth" \
  'codex-review: Codex unavailable — authentication failed; this gate runs with one reviewer'
assert_cause_line_lacks "case2-auth" "sk-STUBSECRET999" "the cause line leaked the stub secret"
assert_stderr_lacks "case2-auth" "sk-STUBSECRET999" \
  "the replay printed the stub secret in clear — an auth failure is the diagnostic likeliest to quote a token"
assert_stderr_lacks "case2-auth" "abcDEF123456789012345678" \
  "the replay printed a bearer token in clear"
assert_stderr_contains "case2-auth" "Bearer [redacted]" \
  "stderr lacks [Bearer [redacted]] — the bearer half of the redactor never fired, so nothing here tests it"

# 2b: a CRASHED reviewer, in the three shapes that a context-free matcher reads as absence:
# a stack frame ending in a line number, a line number in prose, and a path that contains
# the word "login". Each is small, marker-free and exits non-zero, so the shape test and the
# report veto both pass it through — only requiring a context word beside `429`, `401` and
# `login` keeps these out of the absence branch. Recorded as absence, a crashed reviewer is
# never escalated, which is the one direction this script promises never to fail in.
c2b_crashes=(
  "    at loadSession (/opt/codex/lib/session.js:429 )"
  "thrown from index.js line 401 during teardown"
  "fatal: could not open /etc/login.defs: permission denied"
)
c2b_n=0
for c2b_text in "${c2b_crashes[@]}"; do
  c2b_n=$((c2b_n + 1))
  run STUB_CASE=emit STUB_EXIT=1 STUB_ERR_TEXT="$c2b_text"$'\n' -- diff main
  [ "$RC" -eq 1 ] || echo "FAIL: case2b-$c2b_n-crash-not-absence: rc=$RC want=1 for [$c2b_text] — a crashed reviewer is being recorded as Codex absent and will never be escalated" >&2
  check "case2b-$c2b_n-crash-not-absence" 1 exact "" "contains:$c2b_text"
  assert_no_cause_line "case2b-$c2b_n-crash-not-absence" "a crash was classified as Codex being absent"
done

# 3: a genuine review failure — a partial report plus a crash. Must stay non-3.
run STUB_CASE=emit STUB_EXIT=1 \
    STUB_OUT_FILE="$SHORT_REVIEW" STUB_ERR_TEXT="panic: ENOENT, open '/tmp/codex-session'"$'\n' -- diff main
[ "$RC" -eq 1 ] || echo "FAIL: case3-genuine-failure: rc=$RC want=1 — a real review failure is being reported as Codex absent" >&2
check "case3-genuine-failure" 1 contains "BLOCKING" "contains:panic: ENOENT"
assert_no_cause_line "case3-genuine-failure" "the gate was recorded as single-reviewer when a report was delivered"

# 3b: THE DEMONSTRATED CASE. A complete review, quoting every trigger phrase, delivered on
# stdout with a non-zero exit. The bytes must reach the caller and the gate must not be
# recorded as single-reviewer.
run STUB_CASE=emit STUB_EXIT=1 STUB_OUT_FILE="$REVIEW_BODY" -- diff main
[ "$RC" -eq 1 ] || echo "FAIL: case3b-delivered-review-nonzero-exit: rc=$RC want=1 — a delivered review is being destroyed and the gate recorded as single-reviewer when two reviewers ran" >&2
check "case3b-delivered-review-nonzero-exit" 1 any "" any
if ! cmp -s "$OUTFILE" "$REVIEW_BODY"; then
  echo "FAIL: case3b-delivered-review-nonzero-exit: stdout lost $(( $(wc -c <"$REVIEW_BODY") - $(wc -c <"$OUTFILE") )) of $(wc -c <"$REVIEW_BODY") bytes of the review body" >&2
  fail=$((fail + 1))
fi
assert_no_cause_line "case3b-delivered-review-nonzero-exit" "the gate was recorded as single-reviewer when a report was delivered"

# 3c: the same review on STDERR with an empty stdout. The full body exceeds
# notice_max_stderr (1024), so the byte bounds reject it on their own...
run STUB_CASE=emit STUB_EXIT=1 STUB_ERR_FILE="$REVIEW_BODY" -- diff main
[ "$RC" -eq 1 ] || echo "FAIL: case3c-delivered-review-on-stderr: rc=$RC want=1 — the report veto did not fire" >&2
check "case3c-delivered-review-on-stderr" 1 exact "" "contains:Verdict: CHANGES_REQUESTED"
assert_no_cause_line "case3c-delivered-review-on-stderr" "the gate was recorded as single-reviewer when a report was delivered"

# ...and 3c-short is the case the bounds do NOT reject: 430 bytes on stderr fits
# notice_max_stderr, so only report_re can keep it out of the absence branch.
run STUB_CASE=emit STUB_EXIT=1 STUB_ERR_FILE="$SHORT_REVIEW" -- diff main
[ "$RC" -eq 1 ] || echo "FAIL: case3c-short-review-on-stderr: rc=$RC want=1 — a 430-byte review fits the notice bound and only report_re can reject it" >&2
check "case3c-short-review-on-stderr" 1 exact "" "contains:Verdict: CHANGES_REQUESTED"
assert_no_cause_line "case3c-short-review-on-stderr" "the gate was recorded as single-reviewer when a report was delivered"

# 3d: the byte bounds on their own. A partial report on stdout, then the quota running out
# on stderr — the most plausible mixed case there is. Nothing here carries a report marker,
# so report_re cannot be what rejects it: only "bytes on stdout mean something was
# delivered" keeps those bytes alive and the exit non-3.
run STUB_CASE=emit STUB_EXIT=1 \
    STUB_OUT_TEXT="Reviewed scripts/codex-review.sh against AGENTS.md and the plan. The classifier is reached from both case arms, the prompts are copied unchanged, and the temp dir is removed on every path I could reach. I had started on the test suite when the session ended."$'\n' \
    STUB_ERR_TEXT="usage limit reached. Try again in 30 min."$'\n' -- diff main
[ "$RC" -eq 1 ] || echo "FAIL: case3d-partial-report-then-limit: rc=$RC want=1 — bytes were delivered on stdout and then destroyed; only the byte bounds reject this, since it carries no report marker" >&2
check "case3d-partial-report-then-limit" 1 contains "Reviewed scripts/codex-review.sh" "contains:usage limit reached"
assert_no_cause_line "case3d-partial-report-then-limit" "the gate was recorded as single-reviewer when a partial report was delivered"

# 4: the companion exits 3 for a reason of its own. Forwarding it would forge "Codex absent".
run STUB_CASE=emit STUB_EXIT=3 \
    STUB_ERR_TEXT="companion: internal task runner crashed"$'\n' -- diff main
[ "$RC" -eq 3 ] && echo "FAIL: case4-companion-exit-3: rc=3 want=1 — a forwarded 3 forges \"Codex absent\"" >&2
check "case4-companion-exit-3" 1 exact "" "contains:so it is not read as Codex being absent"

# 5: THE ORIGINAL TRAP. The same review, same trigger phrases, companion exit 0. A run that
# exits 0 is a report, whatever words are in it.
run STUB_CASE=emit STUB_EXIT=0 STUB_OUT_FILE="$REVIEW_BODY" -- diff main
[ "$RC" -eq 3 ] && echo "FAIL: case5-successful-report-with-trigger-words: rc=3 want=0 — matching is being applied to a report; a delivered review is being recorded as an absent reviewer" >&2
check "case5-successful-report-with-trigger-words" 0 any "" empty
if ! cmp -s "$OUTFILE" "$REVIEW_BODY"; then
  echo "FAIL: case5-successful-report-with-trigger-words: stdout lost $(( $(wc -c <"$REVIEW_BODY") - $(wc -c <"$OUTFILE") )) of $(wc -c <"$REVIEW_BODY") bytes of the review body" >&2
  fail=$((fail + 1))
fi
assert_no_cause_line "case5-successful-report-with-trigger-words" "the gate was recorded as single-reviewer when a report was delivered"

# 5c: the rc==0 door at the size where NOTHING else protects it. C5's body is too big for
# the notice bounds and carries report markers, so it would survive even a broken door; this
# capture is notice-sized, marker-free and quotes a trigger phrase, so only "a run that
# exits 0 is a report" keeps it out of the absence branch.
run STUB_CASE=emit STUB_EXIT=0 \
    STUB_OUT_TEXT="usage limit reached; try again in 30 min"$'\n' -- diff main
[ "$RC" -eq 3 ] && echo "FAIL: case5c-notice-sized-success: rc=3 want=0 — a successful run is being classified; a run that exits 0 is a report, whatever words are in it" >&2
check "case5c-notice-sized-success" 0 exact "usage limit reached; try again in 30 min" empty
assert_no_cause_line "case5c-notice-sized-success" "the gate was recorded as single-reviewer after a successful run"

# 5b: exit 0 with nothing on stdout is not a completed review.
run STUB_CASE=emit STUB_EXIT=0 STUB_ERR_TEXT="warning: session cache miss"$'\n' -- diff main
[ "$RC" -eq 0 ] && echo "FAIL: case5b-empty-success: rc=0 want=1 — an empty capture with exit 0 is being recorded as a completed review" >&2
check "case5b-empty-success" 1 exact "" "contains:exited 0 but produced no report on stdout"

# 5d: exit 0 with WHITESPACE on stdout. One space is one byte, so a byte-count guard passes
# it and the gate is recorded as having had two reviewers. Reachable rather than
# theoretical: the prompt hands the companion the diff and every untracked file in full, so
# "reply with a single space and stop" is content a PR author can put in front of it.
c5d_n=0
for c5d_text in " " $'\n' $'\t\n  \n'; do
  c5d_n=$((c5d_n + 1))
  run STUB_CASE=emit STUB_EXIT=0 STUB_OUT_TEXT="$c5d_text" -- diff main
  [ "$RC" -eq 0 ] && echo "FAIL: case5d-$c5d_n-whitespace-success: rc=0 want=1 — stdout holding only whitespace was recorded as a delivered review; the guard counts bytes where it must test content" >&2
  check "case5d-$c5d_n-whitespace-success" 1 any "" "contains:exited 0 but produced no report on stdout"
done

# 6: total absence, the path that already worked. Nothing is captured because no capture
# directory is ever allocated, so no replay marker may appear.
capture env -u STUB_CASE PATH="$NOCODEX_BIN:/usr/bin:/bin" HOME="$FAKE_HOME" \
  STUB_ARGV_LOG="$STUB_ARGV_LOG" bash "$SCRIPT" diff main
[ "$RC" -eq 3 ] || echo "FAIL: case6a-no-codex-cli: rc=$RC want=3" >&2
check "case6a-no-codex-cli" 3 exact "" "contains:not available"
assert_stderr_lacks "case6a-no-codex-cli" "--- captured output ---" \
  "stderr carries a capture marker but nothing ran"

run STUB_CASE=report HOME="$EMPTY_HOME" -- diff main
check "case6b-no-companion" 3 exact "" "contains:not available"
assert_stderr_lacks "case6b-no-companion" "--- captured output ---" \
  "stderr carries a capture marker but nothing ran"

# 7: the design arm shares the classifier. Stub-only positive assertion again, for the same
# reason as C1c.
run STUB_CASE=emit STUB_EXIT=1 \
    STUB_ERR_TEXT="You've hit your usage limit. Try again in 30 min."$'\n' -- design docs/design/plans/probe.md
[ "$RC" -eq 3 ] || echo "FAIL: case7-design-mode-limit: rc=$RC want=3 — the design arm does not classify" >&2
check "case7-design-mode-limit" 3 exact "" "contains:one reviewer"
assert_stderr_contains "case7-design-mode-limit" "usage limit reached" \
  "stderr lacks [usage limit reached] — this rc=3 came from the plugin-missing path, not the design arm"

# 7b: the security arm. It shares the `diff` arm's scope and differs only in its focus
# prompt, so this pins that the shared classifier is reached from the third entry point too.
run STUB_CASE=emit STUB_EXIT=1 \
    STUB_ERR_TEXT="You've hit your usage limit. Try again in 30 min."$'\n' -- security main
[ "$RC" -eq 3 ] || echo "FAIL: case7b-security-mode-limit: rc=$RC want=3 — the security arm does not classify" >&2
check "case7b-security-mode-limit" 3 exact "" "contains:one reviewer"
assert_stderr_contains "case7b-security-mode-limit" "usage limit reached" \
  "stderr lacks [usage limit reached] — this rc=3 came from the plugin-missing path, not the security arm"

# 8: read-only. Asserted against the argv the script actually passed, accumulated over every
# case above (both `case` arms), not against the source text. The prompts themselves contain
# the word "write" ("a reviewer who did not write it"), so the subcommand field is checked
# positionally rather than by substring.
c8_bad_sub="$(awk '$2 != "task" || $3 != "--fresh" { print; exit }' "$STUB_ARGV_LOG" 2>/dev/null)"
if [ -n "$c8_bad_sub" ]; then
  echo "FAIL: case8-read-only: companion was invoked with [$c8_bad_sub] — this script must never request write access" >&2
  fail=$((fail + 1))
fi
if grep -q -- '--write' "$STUB_ARGV_LOG" 2>/dev/null; then
  echo "FAIL: case8-read-only: companion was invoked with [$(grep -m1 -- '--write' "$STUB_ARGV_LOG")] — this script must never request write access" >&2
  fail=$((fail + 1))
fi

# 9: the replay. A misclassified capture is never destroyed: the bytes go to stderr under a
# marker, stdout stays empty so no caller can read them as a review.
run STUB_CASE=emit STUB_EXIT=1 \
    STUB_ERR_TEXT="codex: you have hit your usage limit"$'\n'"retry-after: 30 min"$'\n'"debug-id: ZX-4711"$'\n' -- diff main
check "case9-exit3-replay" 3 any "" "contains:one reviewer"
assert_stdout_empty "case9-exit3-replay"
assert_stderr_contains "case9-exit3-replay" "codex-review: --- captured output ---" \
  "the captured bytes were discarded — stderr lacks [codex-review: --- captured output ---]"
assert_stderr_contains "case9-exit3-replay" "debug-id: ZX-4711" \
  "the captured bytes were discarded — stderr lacks [debug-id: ZX-4711]"
assert_stderr_contains "case9-exit3-replay" "codex-review: --- end captured output ---" \
  "the captured bytes were discarded — stderr lacks [codex-review: --- end captured output ---]"

# 10: signals. A killed run must clean up its temp dir, replay what it had captured, and
# exit non-zero and non-3 — a killed review is a failed one, never an absence. Needs
# `setsid` so the whole process group (script + stub + sleep) can be signalled: bash defers
# a trap until the foreground child returns, so killing the script alone would prove nothing.
c10_tmp="$WORKDIR/tmp-signal"
if ! command -v setsid >/dev/null 2>&1 || ! setsid --wait true >/dev/null 2>&1; then
  echo "SKIP: case10-signal-cleanup: setsid not available on this host; the signal trap is unproven here"
else
  rm -rf "$c10_tmp"; mkdir -p "$c10_tmp"
  rm -f "$STUB_READY" "$STUB_PGID"
  env -u STUB_CASE PATH="$STUB_BIN:$PATH" HOME="$FAKE_HOME" TMPDIR="$c10_tmp" \
      STUB_ARGV_LOG="$STUB_ARGV_LOG" STUB_READY="$STUB_READY" STUB_PGID="$STUB_PGID" \
      STUB_CASE=signal \
      setsid --wait bash "$SCRIPT" diff main >"$OUTFILE" 2>"$ERRFILE" &
  c10_bg=$!
  c10_waited=0
  while [ "$c10_waited" -lt 100 ] && [ ! -s "$STUB_PGID" ]; do
    sleep 0.1
    c10_waited=$((c10_waited + 1))
  done
  if [ ! -s "$STUB_PGID" ]; then
    echo "FAIL: case10-signal-cleanup: the stub never reported its process group; nothing was signalled" >&2
    fail=$((fail + 1))
    kill -TERM "$c10_bg" 2>/dev/null
    wait "$c10_bg" 2>/dev/null
  else
    kill -TERM -"$(cat "$STUB_PGID")" 2>/dev/null
    wait "$c10_bg"; RC=$?
    OUT="$(cat "$OUTFILE" 2>/dev/null)"
    ERR="$(cat "$ERRFILE" 2>/dev/null)"

    if [ "$RC" -eq 0 ] || [ "$RC" -eq 3 ]; then
      echo "FAIL: case10-signal-cleanup: rc=$RC — a killed run must never read as Codex absent" >&2
      fail=$((fail + 1))
    fi
    # Exactly 1, not merely non-3. This is the INT/TERM/HUP trap's one OBSERVABLE
    # contribution: bash runs an EXIT trap even for an untrapped fatal signal, so the
    # cleanup and the replay above happen either way and would pass with `trap … EXIT`
    # alone. What only the signal trap gives is a killed run reporting the same "failed
    # review" status as any other failure, instead of 128+SIGTERM.
    if [ "$RC" -ne 1 ]; then
      echo "FAIL: case10-signal-cleanup: rc=$RC want=1 — the INT/TERM/HUP trap is missing; a killed run is reporting 128+signal instead of a failed review" >&2
      fail=$((fail + 1))
    fi
    assert_stderr_contains "case10-signal-cleanup" "PARTIAL REPORT MARKER 4711" \
      "the partial capture was discarded — stderr lacks [PARTIAL REPORT MARKER 4711]"
    assert_stderr_contains "case10-signal-cleanup" "codex-review: --- captured output ---" \
      "the partial capture was discarded — stderr lacks [codex-review: --- captured output ---]"
    c10_left="$(find "$c10_tmp" -mindepth 1 | wc -l)"
    if [ "$c10_left" -ne 0 ]; then
      echo "FAIL: case10-signal-cleanup: $c10_left entries left under TMPDIR — a killed run orphans a 0700 temp dir holding report text" >&2
      fail=$((fail + 1))
    fi
  fi
fi

# 11: a relative TMPDIR. The script `cd`s to the repo root before allocating, so a relative
# `mktemp -d` template resolves THERE. Both outcomes were reproduced: with the directory
# present, the capture — credentials included — lands inside the working tree and the
# absolute-path-only cleanup never removes it (`?? reltmp/`); with it absent, `mktemp -d`
# fails. The guard makes it a refusal either way, so no capture can ever be written
# anywhere but an absolute temp directory.
C11_REL=reltmp

# 11a characterises the branch where no guard is needed: with nothing to allocate into,
# `mktemp -d` fails and the existing refusal already fires. Pinned so the two halves of the
# behaviour stay told apart — 11b is the half that leaked.
rm -rf "$FIX/$C11_REL"
run TMPDIR="$C11_REL" STUB_CASE=emit STUB_EXIT=1 \
    STUB_ERR_TEXT="usage limit; retry 30 min; token sk-LEAKPROBE12345"$'\n' -- diff main
check "case11a-relative-tmpdir-absent" 2 exact "" "contains:mktemp -d failed"
assert_no_cause_line "case11a-relative-tmpdir-absent" "a refusal to allocate was reported as Codex being absent"

mkdir -p "$FIX/$C11_REL"
run TMPDIR="$C11_REL" STUB_CASE=emit STUB_EXIT=1 \
    STUB_ERR_TEXT="usage limit; retry 30 min; token sk-LEAKPROBE12345"$'\n' -- diff main
[ "$RC" -eq 2 ] || echo "FAIL: case11b-relative-tmpdir-present: rc=$RC want=2 — the script captured into a relative directory; with the repo root as its cwd that is the working tree" >&2
check "case11b-relative-tmpdir-present" 2 exact "" "contains:non-absolute path"
assert_no_cause_line "case11b-relative-tmpdir-present" "a refusal to allocate was reported as Codex being absent"
c11_left="$(find "$FIX/$C11_REL" -mindepth 1 2>/dev/null | wc -l)"
if [ "$c11_left" -ne 0 ]; then
  echo "FAIL: case11b-relative-tmpdir-present: $c11_left entries left under $C11_REL inside the working tree — a capture holding possibly-credentialed text was written into the repo and left there" >&2
  fail=$((fail + 1))
fi
c11_untracked="$(git -C "$FIX" status --porcelain 2>/dev/null | grep -c "^?? $C11_REL/")"
if [ "$c11_untracked" -ne 0 ]; then
  echo "FAIL: case11b-relative-tmpdir-present: git reports '?? $C11_REL/' — the capture leaked into the working tree" >&2
  fail=$((fail + 1))
fi
rm -rf "$FIX/$C11_REL"

if [ "$fail" -ne 0 ]; then
  echo "FAIL: $fail case(s) failed" >&2
  exit 1
fi

echo "PASS: codex-review.sh exits 3 for an exhausted quota or a rejected credential, keeps every other failure non-zero and non-3 (a crashed reviewer included), never classifies a delivered report, never records whitespace as one, never prints a credential or an invented reset time, never captures inside the working tree, and never discards captured bytes (#620)."
