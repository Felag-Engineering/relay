#!/usr/bin/env bash
# Run a Codex review as the second reviewer on one of the workflow's adversarial gates.
# See "Reviewers" in docs/agents/workflow.md.
#
#   scripts/codex-review.sh diff     [<base-ref>]      review of the working tree against base (committed + uncommitted + untracked)
#   scripts/codex-review.sh security [<base-ref>]      the same diff, focused on the security surface
#   scripts/codex-review.sh design   <design-file>     read-only critique of a design plan
#
# Prints Codex's report on stdout. The exit contract:
#
#   0                   a report on stdout.
#   2                   this script refused (bad usage, unresolvable base, empty change,
#                       unreadable design file, `mktemp -d` failing or returning a
#                       non-absolute path).
#   3                   Codex is ABSENT: the plugin, the CLI or node is missing, OR the
#                       companion reported an exhausted usage quota, OR it reported an
#                       authentication failure. The caller records the gate as
#                       single-reviewer, never as passed.
#   any other non-zero  the review FAILED and must be escalated; never treated as absence.
#
# Codex is a reviewer only: every mode here is read-only (no --write), and this script never
# invokes `task` with write access.
#
# --- How absence is told apart from failure (#620) -------------------------------------
#
# Absence is detected only on a FAILED run (rc != 0). A run that exits 0 is a report,
# whatever words are in it — a review of a change about quotas, rate limits or
# authentication contains every phrase matched below.
#
# rc != 0 is not sufficient. A real review can fail after delivering its report, and a
# review of THIS script quotes every trigger phrase. So classification also requires the
# capture to be notice-shaped (small, and with nothing on stdout unless the whole capture is
# tiny) and to carry no report marker. Everything a delivered report could make ambiguous
# resolves toward "failed review", which is the pre-#620 behaviour.
#
# Captured bytes are never discarded by a CLASSIFICATION decision. On exit 3, and on a
# signal, they are replayed to STDERR under a marker; stdout stays empty so no caller can
# read them as a review. Stated that way rather than as "never destroyed": a signal landing
# in the narrow window after a delivery path claims the bytes and before it writes them
# loses the replay, which is the trade the comment above replay_capture's call sites makes
# deliberately (doubling a replay is worse than losing one). The
# replay passes through a redactor for the obvious API-key and bearer-token shapes, on
# EVERY branch rather than only the auth one — a limit message can carry a credential just
# as an auth failure can. That redaction is BEST-EFFORT PATTERN MATCHING, NOT A GUARANTEE:
# a secret in a shape it does not know reaches stderr in clear. A replay block is therefore
# diagnostic output for a human at a terminal, and is never material to quote verbatim into
# a PR body, an issue comment, or anything else durable and public.
#
# Codex is not installed in the environment this was written in, so the companion's real
# limit and auth output was not observed: every claim about its wording below is a design
# assumption, and each is arranged so that being wrong costs a missed absence (exit
# non-zero, which is today's behaviour) and never a false absence.
#
# Four residuals are stated rather than denied:
#   (i)  a failed run whose short, marker-free diagnostic quotes a limit phrase is recorded
#        as absence rather than as failure. Both mean no review completed, and the bytes are
#        replayed to stderr, so nothing is lost but the label.
#   (ii) a short review delivered entirely on stderr, with a non-zero exit and no report
#        marker anywhere, is recorded as absence. All three have to coincide, and the bytes
#        still reach stderr.
#  (iii) `notice_max_total` is bought at a price: a failed run carrying up to ~200 bytes of
#        partial report on stdout alongside a short marker-free notice on stderr (256 bytes
#        together) is classified as absence, and those stdout bytes are relabelled and
#        moved to the stderr replay.
#  (iv)  the whitespace guard below tests POSIX [[:space:]] in the C locale, so stdout
#        holding nothing but a UTF-8 non-breaking space or a BOM still counts as a
#        delivered review. Far more contrived than the single space it closes, and it is
#        named here rather than claimed away.
# A fifth is closed outright: an exit-0 run whose stdout holds nothing but ASCII whitespace
# used to be recorded as a completed review, and is now a failure.
#
# Accepted cost of capturing to files rather than streaming: the report is delivered at
# process exit rather than as it arrives. All three call sites read the completed output,
# and a killed run's partial capture is replayed by the signal trap.
set -uo pipefail
cd "$(dirname "$0")/.."

mode=${1:-}; arg=${2:-origin/main}
# Usage is the header through the exit contract (lines 2-22), so a caller that gets the
# invocation wrong also sees what each exit code means.
[ -n "$mode" ] || { sed -n '2,22p' "$0"; exit 2; }

companion=$(ls -d "$HOME"/.claude/plugins/cache/openai-codex/codex/*/scripts/codex-companion.mjs 2>/dev/null | sort -V | tail -1)
if [ -z "$companion" ] || ! command -v codex >/dev/null 2>&1 || ! command -v node >/dev/null 2>&1; then
  echo "codex-review: Codex plugin or CLI not available; this gate runs with one reviewer" >&2
  exit 3
fi

repo_rules="Constraints come from AGENTS.md (the fourteen invariants and the escalation list), GLOSSARY.md, docs/agents/workflow.md and the governing docs/specs/<capability>.md. Read them before judging. A change that would make an invariant, an ADR or a bound spec claim untrue is a blocking finding, never a suggestion. Cite file and line for every finding. Do not edit anything."

# --- The absent-vs-failed classifier (#620) ---------------------------------------------
#
# `limit_re` and `auth_re` are the unobservable-signal ASSUMPTIONS named in the header: the
# real wording was never seen, so a wrong guess here costs a missed absence (a non-zero exit,
# which is the pre-#620 behaviour) and never a false one.
#
# Every alternative here needs a context word, because the short things that would otherwise
# match are exactly what a CRASHED reviewer prints, and a crash misread as absence is the
# one direction this script promises never to fail in. A bare `429 `/`401 ` matches a stack
# frame (`session.js:429 `) and a line number (`line 401 during teardown`); a bare `login`
# matches a path (`/etc/login.defs`). So the numeric codes are accepted only as `http 429 `
# or `status 401 ` — with a space on BOTH sides — and the login wording only in a sentence
# that is about logging in.
#
# The trailing space is load-bearing and narrows this further than it first reads:
# `HTTP/2 429`, `status 429:`, `codex: 429`, `Error: 401` and a bare `HTTP 429` at end of
# line are all MISSED. That is the safe direction (a missed absence is a non-zero exit,
# which is the pre-#620 behaviour), and in practice these two alternatives fire almost
# never on their own — `429 Too Many Requests` and `HTTP/1.1 401 Unauthorized` classify via
# `too many requests` and `unauthorized` instead.
limit_re='usage limit|rate limit|quota (exceeded|exhausted)|too many requests|resource[_ ]exhausted|(http |status )429 '
auth_re='not logged in|codex login|please log ?in|authentication (failed|error)|unauthorized|invalid api key|expired (token|session)|re-?authenticate|(http |status )401 '
# `report_re` is the one matcher here that is NOT a guess about output we have never seen:
# every word in it is one this script's own prompts demand of the report ("Output: Verdict …",
# "tagged BLOCKING or SUGGESTION" — see the `case` arms below). It is a veto: a capture
# carrying any of them is a report, not a notice, so it is never classified as absence.
report_re='verdict|changes_requested|blocking|suggestion'

# Byte bounds for "this is a diagnostic, not a report". Branch one is grounded in this
# script's own contract — the report goes to stdout, so bytes on stdout mean something was
# delivered. Branch two covers a notice that arrives on stdout instead (which we cannot rule
# out) at a bound no report the prompts demand could fit inside.
notice_max_stderr=1024   # a diagnostic on stderr with nothing at all on stdout
notice_max_total=256     # the whole capture, whichever stream it came on

capture_dir=""
capture_consumed=0
cleanup_done=0
out_bytes=0
err_bytes=0

# Measured on demand rather than read from out_bytes/err_bytes: a signal can arrive before
# the companion returns, when the only record of a partial report is the files themselves.
capture_bytes() {
  local n=0 f
  for f in "$capture_dir/out" "$capture_dir/err"; do
    [ -f "$f" ] || continue
    n=$(( n + $(wc -c <"$f" 2>/dev/null || echo 0) ))
  done
  printf '%s' "$n"
}

# Captured bytes reach a human even when this script has decided they are not a review.
# stdout stays exactly empty on every path that calls this, so no caller can read the
# replay as a report.
#
# `redact_re` is applied to every replay, not only to the auth branch: a limit message can
# quote a credential too, and classification is limit-first. It is a pattern list, so it
# catches the shapes it knows and nothing else — see the header on why a replay block is
# for a terminal and not for a PR body.
# The prefix is kept and only what follows it is replaced, so the replay still says WHICH
# credential was rejected without saying what it was.
redact_re='s/(sk-|bearer +)[A-Za-z0-9._-]{8,}/\1[redacted]/gI'
replay_capture() {
  [ -n "$capture_dir" ] || return 0
  [ "$(capture_bytes)" -gt 0 ] || return 0
  { echo "codex-review: --- captured output --- ($1)"
    cat -- "$capture_dir/out" "$capture_dir/err" 2>/dev/null | sed -E "$redact_re"
    echo "codex-review: --- end captured output ---"; } >&2
}

# Idempotent, because the signal trap's `exit` re-enters the EXIT trap. `capture_consumed`
# is set by every path that has already delivered the bytes, so nothing is replayed twice.
codex_review_cleanup() {
  [ "$cleanup_done" -eq 0 ] || return 0
  cleanup_done=1
  if [ "$capture_consumed" -eq 0 ]; then
    replay_capture "run interrupted before completion"
  fi
  case "${capture_dir:-}" in /*) rm -rf "$capture_dir" ;; esac
}

# run_companion <prompt> — the last statement of every `case` arm, so the classification
# cannot exist on one arm and not the other. Never returns.
run_companion() {
  # Allocated here rather than at the top, so the no-companion and refusal paths above
  # allocate nothing and install no trap.
  capture_dir=$(mktemp -d) || { echo "codex-review: mktemp -d failed" >&2; exit 2; }

  # A relative TMPDIR that happens to exist under the repo root makes `mktemp -d` return a
  # relative path, and this script has already `cd`-ed to the repo root — so the capture,
  # credentials and all, lands INSIDE the working tree and the cleanup below (absolute
  # paths only) never removes it. Measured: `TMPDIR=reltmp` with `reltmp/` present leaves
  # `?? reltmp/` holding the captured text; with it absent, `mktemp -d` fails instead.
  # Refuse either way rather than capture anywhere but an absolute temp directory.
  case "$capture_dir" in
    /*) ;;
    *) rm -rf "$capture_dir"
       echo "codex-review: mktemp -d returned a non-absolute path ('$capture_dir'); refusing to capture inside the working tree" >&2
       exit 2 ;;
  esac

  # Two traps over one handler, deliberately: a single combined `trap … EXIT INT TERM HUP`
  # cannot both leave a normal exit status alone and stop a signalled run resuming into the
  # rest of the script. `exit 1` on a signal is non-zero and non-3 — a killed run is a
  # failed review, never an absence.
  trap 'codex_review_cleanup' EXIT
  trap 'codex_review_cleanup; exit 1' INT TERM HUP

  # Redirection to FILES, not a pipe, not `$( )` and not `local x=$(…)`: a pipeline makes
  # $? depend on pipefail and the last stage, `$( )` buffers and strips trailing newlines,
  # and `local x=$(cmd)` takes $? from `local`. With files, $rc is the companion's own
  # status and a partial report survives a crash or a kill.
  node "$companion" task --fresh "$1" >"$capture_dir/out" 2>"$capture_dir/err"
  rc=$?
  out_bytes=$(( $(wc -c <"$capture_dir/out" 2>/dev/null || echo 0) ))
  err_bytes=$(( $(wc -c <"$capture_dir/err" 2>/dev/null || echo 0) ))

  # A success with nothing on stdout is not a report. Tested on CONTENT, not on byte count:
  # the prompt hands the companion the working-tree diff and every untracked file in full,
  # so an injected "reply with a single space and stop" would otherwise pass a zero-byte
  # test by one whitespace byte and be recorded as a delivered review — a two-vendor gate
  # with one reviewer, which is the outcome this whole script exists to make impossible.
  # Exit 1 is non-3, so it is a failure, not an absence.
  if [ "$rc" -eq 0 ] && ! grep -q '[^[:space:]]' "$capture_dir/out" 2>/dev/null; then
    echo "codex-review: companion exited 0 but produced no report on stdout; treating this as a failed review, not a report" >&2
    capture_consumed=1
    cat -- "$capture_dir/err" >&2 2>/dev/null
    exit 1
  fi

  # The success door, first among the delivery paths: a run that exits 0 is a report.
  if [ "$rc" -eq 0 ]; then
    capture_consumed=1
    cat -- "$capture_dir/out"
    cat -- "$capture_dir/err" >&2 2>/dev/null
    exit 0
  fi

  # Notice shape, computed BEFORE any trigger-phrase match.
  notice_shaped=0
  if [ "$out_bytes" -eq 0 ] && [ "$err_bytes" -le "$notice_max_stderr" ]; then
    notice_shaped=1
  elif [ $((out_bytes + err_bytes)) -le "$notice_max_total" ]; then
    notice_shaped=1
  fi

  # The report veto catches the one case the bounds miss: a short review delivered entirely
  # on stderr. A false veto costs a missed absence (safe); it can never cause one.
  if [ "$notice_shaped" -eq 1 ] && grep -qiE "$report_re" "$capture_dir/out" "$capture_dir/err" 2>/dev/null; then
    notice_shaped=0
  fi

  # Limit first (the case observed on #614), auth second. `-q` suppresses matches, not
  # errors, hence the 2>/dev/null on every read of a capture file.
  cause=""
  if [ "$notice_shaped" -eq 1 ]; then
    if grep -qiE "$limit_re" "$capture_dir/out" "$capture_dir/err" 2>/dev/null; then
      cause=limit
    elif grep -qiE "$auth_re" "$capture_dir/out" "$capture_dir/err" 2>/dev/null; then
      cause=auth
    fi
  fi

  if [ "$cause" = limit ]; then
    # A TIME SHAPE, not a charset bound: `grep -o` emits only the matched token and the `-x`
    # re-validation requires the whole survivor to BE a time shape, so the only bytes that
    # can reach stderr are digits, a colon, a space and a few lowercase unit letters. A
    # charset bound wide enough for a reset clause is a superset of the bearer/API-key
    # charset, and classification is limit-first, so a message carrying both a limit phrase
    # and a credential reaches this line (AGENTS.md §9 — never log secrets). Nothing at all
    # is extracted from an auth failure. A message that states no reset time yields the
    # empty string and the parenthetical is dropped, never filled with what followed "reset".
    #
    # Each of the three steps does separate work; none is decoration:
    #   - extraction takes the FIRST time-shaped token anywhere in the capture. It is not
    #     anchored near the word "reset", so a message carrying an unrelated time cites that
    #     one. Harmless (the shape is all that reaches stderr) but worth knowing.
    #   - the `-x` re-validation requires the whole survivor to BE a time shape. This is
    #     what holds if extraction ever stops using `-o`: measured with `-o` dropped,
    #     `limit; key sk-AB 3 min` passes the cap and only `-x` rejects the line.
    #   - the 24-char cap bounds the unbounded space run in `[0-9]{1,3} *`. `30`+40
    #     spaces+`min` is a 45-char token that `-x` accepts, because the pattern allows the
    #     run; the cap is the only thing that rejects it.
    reset_re='[0-9]{1,3} *(sec|min|hour|day)[a-z]{0,4}|[0-9]{1,2}:[0-9]{2}'
    reset=$(grep -shoiE "$reset_re" "$capture_dir/out" "$capture_dir/err" 2>/dev/null | head -1 | tr -d '\r\n')
    # `-i` here as well as on extraction: without it a plausible `30 Minutes` is extracted
    # and then silently discarded, losing AC1's reset time for a wording difference.
    printf '%s' "$reset" | grep -qxiE "$reset_re" 2>/dev/null || reset=""
    [ "${#reset}" -le 24 ] || reset=""
    if [ -n "$reset" ]; then
      printf 'codex-review: Codex unavailable — usage limit reached (message cites "%s"); this gate runs with one reviewer\n' "$reset" >&2
    else
      echo "codex-review: Codex unavailable — usage limit reached; this gate runs with one reviewer" >&2
    fi
  elif [ "$cause" = auth ]; then
    echo "codex-review: Codex unavailable — authentication failed; this gate runs with one reviewer" >&2
  fi

  # AC1's "one stderr line naming the cause" is the FIRST line above, and the only line
  # matching `^codex-review: Codex unavailable`; the replay below is delimited evidence, not
  # a second cause.
  #
  # `capture_consumed` is set BEFORE the bytes are delivered, on every path: set after, a
  # signal arriving mid-delivery re-enters cleanup and replays the whole block a second
  # time. Losing a replay to a signal that already got one is cheaper than doubling it.
  if [ -n "$cause" ]; then
    capture_consumed=1
    replay_capture "classified as Codex absent; these bytes are not a review"
    exit 3
  fi

  # Not absence: forward every byte unchanged — no redaction here, because these bytes are
  # a delivered review and mangling one is a worse failure than the replay's is.
  capture_consumed=1
  cat -- "$capture_dir/out"
  cat -- "$capture_dir/err" >&2 2>/dev/null
  if [ "$rc" -eq 3 ]; then
    echo "codex-review: companion exited 3 for a reason that is not a usage limit or an authentication failure; reporting 1 so it is not read as Codex being absent" >&2
    exit 1
  fi
  exit "$rc"
}

case "$mode" in
  diff|security)
    # Not `adversarial-review --base`: with a base ref the companion reviews COMMITTED history
    # only, and the dev-loop commits at Stage 7 — after these reviews — so Codex saw a partial or
    # empty diff. `git diff <base>` (two dots, working tree against base) plus the untracked files
    # is the whole change whether or not any of it is committed yet.
    base=$arg
    git rev-parse --verify --quiet "$base" >/dev/null || { echo "codex-review: base $base not found" >&2; exit 2; }
    changed=$( { git diff --name-only "$base"; git ls-files --others --exclude-standard; } | sort -u)
    if [ -z "$changed" ]; then
      echo "codex-review: nothing differs from $base (committed or not); refusing to review an empty change" >&2
      exit 2
    fi
    scope="The change under review is the working tree against $base: read it with \`git diff $base\` (committed and uncommitted edits together) and read each untracked file listed by \`git ls-files --others --exclude-standard\` in full. Changed paths: $(echo "$changed" | tr '\n' ' '). Review nothing outside this change except to trace its callers and callees."
    if [ "$mode" = diff ]; then
      focus="Review this change as a senior reviewer who did not write it. Priorities: correctness, readability for a reader with no plan or issue in front of them, plan compliance (the plan is .dev-loop/plan.md if present), tests that test behaviour, and no change beyond the issue's scope. Output: Verdict APPROVE or CHANGES_REQUESTED; then findings, each tagged BLOCKING or SUGGESTION with file:line."
    else
      focus="Adversarial security review. This change touches the security surface (scripts/security-surface.sh lists which paths). Assume it is unsafe until proven otherwise: for each invariant in AGENTS.md the change could touch, walk the hostile path and say whether a crafted input, a forged label, a stolen credential or a compromised Node could defeat it. Classes to check: command or argument composition, trust-boundary errors, authn/authz gaps, Policy or deny-by-default erosion, secret handling, TLS weakening, hand-edited generated code. Output: Verdict PASS, CONCERNS or FAIL; then findings with severity and file:line."
    fi
    run_companion "$scope $focus $repo_rules Read-only: make no edits." ;;
  design)
    f=$arg
    [ -r "$f" ] || { echo "codex-review: $f not readable" >&2; exit 2; }
    run_companion \
      "Adversarial review of the design plan at $f (docs/design/plans/README.md says what one is for). Do not take it at face value: verify every claim it makes about the codebase against the code, check it covers every acceptance criterion or spec claim it names, find what it misses, what it over-reaches, and where it would violate a repo constraint. Output: Verdict APPROVE or REVISE; Issues numbered, each tagged BLOCKING or SUGGESTION with file and line evidence; if REVISE, the specific corrections. $repo_rules Read-only: make no edits." ;;
  *) echo "codex-review: unknown mode $mode" >&2; exit 2 ;;
esac
