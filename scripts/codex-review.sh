#!/usr/bin/env bash
# Run a Codex review as the second reviewer on one of the workflow's adversarial gates.
# See "Reviewers" in docs/agents/workflow.md.
#
#== usage ==
#   scripts/codex-review.sh diff     [<base-ref>]   adversarial review of the UNCOMMITTED working
#                                                    tree (staged + unstaged + untracked).
#                                                    <base-ref> is used only to note committed work
#                                                    that falls outside that scope.
#   scripts/codex-review.sh security [<base-ref>]   the same review with the security-surface pass
#                                                    ADDED to the focus.
#   scripts/codex-review.sh design   <design-file>  critique of a design plan, which must itself be
#                                                    uncommitted.
#
# Classification is STRUCTURAL, not textual: the companion's --json payload is PARSED, and the
# only thing that makes a run a review is result.verdict holding one of the schema's two values
# (approve, needs-attention). No message text and no byte count is ever consulted. Four runs
# (#617, #674, #675, #673) were misclassified by text- and size-matching before this change
# (#694).
#
# The companion's own process exit status decides nothing: a delivered verdict beside a
# non-zero exit is still a delivered review, and is reported as one (exit 0), with a warning
# naming the companion's exit status.
#
# RELAY_CODEX_MODEL (default gpt-5.6-terra) selects the model; it must be a literal model slug
# — the review subcommand does not resolve aliases (only `task` does). --background and --wait
# are parsed by the companion but ignored for adversarial-review, which always runs in the
# foreground.
#
# Codex is a reviewer only: every mode here is read-only (no --write), and this script never
# invokes `task`.
#
# A captured-output replay on stderr (exit 3 and a killed run) passes through a best-effort
# redactor for the obvious API-key and bearer-token shapes — NOT A GUARANTEE, a secret in a
# shape it does not know reaches stderr in clear. That replay is terminal diagnostics for a
# human at a keyboard, and is never material to quote verbatim into a PR body, an issue
# comment, or anything else durable and public.
#
# Prints Codex's report on stdout. The exit contract:
#
#   0   a report on stdout: a parsed result.verdict came back, whatever the companion's own
#       process exit status was.
#   1   the run FAILED (killed by a signal, or the output classifier itself failed) and must be
#       escalated, never read as absence.
#   2   this script REFUSED before ever invoking Codex (bad usage, unresolvable base ref,
#       nothing uncommitted to review, an unreadable or committed design file, a `mktemp -d`
#       failure or a non-absolute temp path, a malformed RELAY_CODEX_MODEL).
#   3   Codex ABSENT: no structured verdict came back, for any reason — the plugin, the Codex
#       CLI or node missing, an exhausted usage quota, a rejected credential, or any other
#       shape that is not the schema's verdict. The caller records this gate as
#       single-reviewer, and NEVER as a pass.
#== end usage ==
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

usage() { sed -n '/^#== usage ==$/,/^#== end usage ==$/{ /^#== /d; p; }' "$0"; }

mode=${1:-}; arg=${2:-origin/main}
# The sentinel pair above is load-bearing: it is what keeps this refusal printing a correct
# contract even after the header is edited. case-usage-refusal in codex-review-test.sh is what
# stops the sentinels themselves being deleted or renamed out from under it.
[ -n "$mode" ] || { usage; exit 2; }

companion=$(ls -d "$HOME"/.claude/plugins/cache/openai-codex/codex/*/scripts/codex-companion.mjs 2>/dev/null | sort -V | tail -1)
if [ -z "$companion" ] || ! command -v codex >/dev/null 2>&1 || ! command -v node >/dev/null 2>&1; then
  echo "codex-review: Codex unavailable — the plugin, the Codex CLI or node is not installed; this gate runs with one reviewer" >&2
  exit 3
fi

# `-` rather than `:-`: RELAY_CODEX_MODEL set to the empty string must fall through to the
# emptiness check below rather than silently take the default, because "refuse an empty
# value" is one of the acceptance cases this validates.
model=${RELAY_CODEX_MODEL-gpt-5.6-terra}
# Defence in depth, not the only guard: parseArgs (lib/args.mjs) takes the token after --model
# unconditionally, so a hostile value cannot become a second flag, and executeReviewRun
# hardcodes sandbox read-only regardless of what --model says — but a script on the security
# surface does not forward an unvalidated environment value into an argv it builds. Length is
# checked FIRST so a pathological value is never handed to the regex.
#
# `[[ =~ ]]`, not `grep -qxE`: grep's `-x` anchors each LINE, not the whole string, so a
# multi-line value whose first line is a valid slug would pass while the rest of it forges a
# `codex-review:` line into this script's own stderr on both the exit-3 and exit-0 paths below
# (both interpolate $model with %s). Bash's regex match anchors ^/$ to the real start/end of
# the string, so any value containing a newline is rejected outright.
if [ "${#model}" -gt 64 ] || [[ ! "$model" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]*$ ]]; then
  echo "codex-review: RELAY_CODEX_MODEL is not a model slug; refusing" >&2
  exit 2
fi

repo_rules="Constraints come from AGENTS.md (the fourteen invariants and the escalation list), GLOSSARY.md, docs/agents/workflow.md and the governing docs/specs/<capability>.md. Read them before judging. A change that would make an invariant, an ADR or a bound spec claim untrue is a blocking finding, never a suggestion. Cite file and line for every finding. Do not edit anything."

capture_dir=""
capture_consumed=0
cleanup_done=0

# Captured bytes reach a human even when this script has decided the run is not a review.
# stdout stays exactly empty on every path that calls this, so no caller can read the replay
# as a review.
#
# `redact_re` is applied to every replay: a quota message can quote a credential too, and
# it's a pattern list, so it catches the shapes it knows and nothing else — see the header on
# why a replay block is for a terminal and never for a PR body. The prefix is kept and only
# what follows it is replaced, so the replay still says WHICH credential was rejected without
# saying what it was.
redact_re='s/(sk-|bearer +)[A-Za-z0-9._-]{8,}/\1[redacted]/gI'
# Every replayed line is prefixed with "codex-review: > " AFTER redaction (so redaction still
# sees the original line shape, unprefixed). The body between the two banner lines is untrusted
# — a hostile payload could otherwise put a line inside it that mimics this script's own
# output, including its own "Codex review complete" success line — and the prefix guarantees no
# such line can begin with a bare `codex-review:`.
replay_capture() {
  [ -n "$capture_dir" ] || return 0
  local n=0 f
  for f in "$capture_dir/out" "$capture_dir/err"; do
    [ -f "$f" ] || continue
    n=$(( n + $(wc -c <"$f" 2>/dev/null || echo 0) ))
  done
  [ "$n" -gt 0 ] || return 0
  { echo "codex-review: --- captured output --- ($1)"
    cat -- "$capture_dir/out" "$capture_dir/err" 2>/dev/null | sed -E "$redact_re" | sed 's/^/codex-review: > /'
    # A capture whose final byte is not a newline leaves the pipeline above without one either,
    # which would glue this terminator onto the last replayed line instead of starting its own.
    printf '\n'
    echo "codex-review: --- end captured output ---"; } >&2
}

# Idempotent, because the signal trap's `exit` re-enters the EXIT trap. `capture_consumed` is
# set by every path that has already delivered the bytes, so nothing is replayed twice.
codex_review_cleanup() {
  [ "$cleanup_done" -eq 0 ] || return 0
  cleanup_done=1
  if [ "$capture_consumed" -eq 0 ]; then
    replay_capture "run interrupted before completion"
  fi
  case "${capture_dir:-}" in /*) rm -rf "$capture_dir" ;; esac
}

# The classifier: parses the companion's --json payload and prints only fixed literals, the
# two verdict enum values, one of six reason tokens, or an integer that passed a guard. Every
# value in result (findings included) is MODEL-CONTROLLED, UNVALIDATED text — the schema is
# advice to the model, never a local guarantee (lib/codex.mjs's JSON.parse does no schema
# validation) — so nothing derived from an untrusted .length or an untrusted string is ever
# printed: that is what keeps this script's own output a closed vocabulary a hostile payload
# cannot forge a line into.
classify_js='
const raw = require("fs").readFileSync(0, "utf8");

function fail(reason) {
  process.stderr.write(reason + "\n");
  process.exit(4);
}

if (!raw || !raw.trim()) fail("reason=no-output");

let payload;
try {
  payload = JSON.parse(raw);
} catch {
  fail("reason=not-json");
}
if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
  fail("reason=not-json");
}

const count = (v) => (Array.isArray(v) ? v.length : -1);
const int = (n) => (Number.isInteger(n) && n >= -1 && n <= 999999 ? n : -1);
const companionStatus = int(payload.codex && payload.codex.status);

const result = payload.result;
if (typeof result !== "object" || result === null || Array.isArray(result)) {
  fail("reason=no-result companion-status=" + companionStatus);
}

if (typeof result.verdict !== "string") {
  fail("reason=no-verdict companion-status=" + companionStatus);
}
const verdict = result.verdict.trim().toLowerCase();
if (verdict !== "approve" && verdict !== "needs-attention") {
  // The rejected value is NEVER echoed — it is untrusted text; the redacted replay carries
  // the evidence.
  fail("reason=unknown-verdict companion-status=" + companionStatus);
}

const findings = int(count(result.findings));
const blocking =
  count(result.findings) < 0
    ? -1
    : int(
        result.findings.filter(
          (f) => f && typeof f === "object" && (f.severity === "critical" || f.severity === "high")
        ).length
      );

process.stdout.write(JSON.stringify(result, null, 2));
// process.exit() right after a write is safe ONLY because both classifier streams are
// redirected to FILES by the caller (synchronous writes); if these are ever piped instead,
// switch to process.exitCode and let node drain.
process.stderr.write(
  "verdict=" + verdict + " findings=" + findings + " blocking=" + blocking + " companion-status=" + companionStatus + "\n"
);
process.exit(0);
'

# run_companion <focus> — the last statement of every `case` arm, so the classification
# cannot exist on one arm and not the other. Never returns.
run_companion() {
  # Allocated here rather than at the top, so the refusal paths above allocate nothing and
  # install no trap.
  capture_dir=$(mktemp -d) || { echo "codex-review: mktemp -d failed" >&2; exit 2; }

  # A relative TMPDIR that happens to exist under the repo root makes `mktemp -d` return a
  # relative path, and this script has already `cd`-ed to the repo root — so the capture lands
  # INSIDE the working tree and the cleanup below (absolute paths only) never removes it.
  # Refuse either way rather than capture anywhere but an absolute temp directory.
  case "$capture_dir" in
    /*) ;;
    *) rm -rf "$capture_dir"
       echo "codex-review: mktemp -d returned a non-absolute path ('$capture_dir'); refusing to capture inside the working tree" >&2
       exit 2 ;;
  esac

  # Two traps over one handler, deliberately: a single combined `trap … EXIT INT TERM HUP`
  # cannot both leave a normal exit status alone and stop a signalled run resuming into the
  # rest of the script. `exit 1` on a signal is non-zero and non-3 — a killed run is a failed
  # review, never an absence.
  trap 'codex_review_cleanup' EXIT
  trap 'codex_review_cleanup; exit 1' INT TERM HUP

  # Redirection to FILES, not a pipe, not `$( )` and not `local x=$(…)`: a pipeline makes $?
  # depend on pipefail and the last stage, `$( )` buffers and strips trailing newlines, and
  # `local x=$(cmd)` takes $? from `local`. With files, $rc is the companion's own status and
  # a partial payload survives a crash or a kill.
  #
  # Argv-only, no shell: --scope working-tree, --json, and the model this script validated
  # above. Never task, never --write, never --base — the -- makes the focus text a positional
  # whatever it starts with (lib/args.mjs's passthrough).
  #
  # `env -u NODE_OPTIONS -u NODE_PATH` on BOTH invocations: either variable can `--require` or
  # resolve arbitrary code into the interpreter, and the second invocation is the one that
  # decides whether this gate passed — it must not be reachable through an environment variable
  # this script otherwise never validates. Defence in depth, not a new capability: an ambient
  # NODE_OPTIONS already implies the caller's environment is untrusted, same as a shadowed
  # `node` earlier in PATH.
  env -u NODE_OPTIONS -u NODE_PATH \
    node "$companion" adversarial-review --scope working-tree --model "$model" --json -- "$1" \
    >"$capture_dir/out" 2>"$capture_dir/err"
  rc=$?

  env -u NODE_OPTIONS -u NODE_PATH \
    node -e "$classify_js" <"$capture_dir/out" >"$capture_dir/report" 2>"$capture_dir/classify"
  crc=$?

  case "$crc" in
    0)
      capture_consumed=1
      cat -- "$capture_dir/report"
      printf 'codex-review: Codex review complete (model %s) — %s\n' \
        "$model" "$(cat -- "$capture_dir/classify")" >&2
      if [ "$rc" -ne 0 ]; then
        printf 'codex-review: warning — the companion exited %s alongside a delivered verdict; reporting the review\n' "$rc" >&2
      fi
      exit 0
      ;;
    4)
      capture_consumed=1
      printf 'codex-review: Codex unavailable — the companion returned no structured verdict (%s, model %s, companion exit %s); this gate runs with one reviewer\n' \
        "$(cat -- "$capture_dir/classify")" "$model" "$rc" >&2
      replay_capture "classified as Codex absent; these bytes are not a review"
      exit 3
      ;;
    *)
      capture_consumed=1
      printf 'codex-review: the output classifier failed (node exit %s); reporting a failed review, not an absence\n' "$crc" >&2
      cat -- "$capture_dir/classify" >&2 2>/dev/null
      replay_capture "classifier failed"
      exit 1
      ;;
  esac
}

case "$mode" in
  diff|security)
    base=$arg
    git rev-parse --verify --quiet "$base" >/dev/null || { echo "codex-review: base $base not found" >&2; exit 2; }
    # Exactly the three commands the companion's own --scope working-tree uses
    # (lib/git.mjs:122-133, :309-323), so the script's view and the companion's cannot
    # disagree.
    changed=$( { git diff --cached --name-only; git diff --name-only; git ls-files --others --exclude-standard; } | sort -u)
    if [ -z "$changed" ]; then
      echo "codex-review: nothing is uncommitted; --scope working-tree would hand Codex an empty diff, and an empty diff can still come back approve. Run this before the change is committed." >&2
      exit 2
    fi
    committed_only=$(git diff --name-only "$base" -- 2>/dev/null | grep -vFxf <(printf '%s\n' "$changed") || true)
    if [ -n "$committed_only" ]; then
      k=$(printf '%s\n' "$committed_only" | sed '/^$/d' | wc -l | tr -d ' ')
      # `wc -l` output is always digits, but the guard costs nothing and keeps this token as
      # closed a vocabulary as the classifier's own integers — never print an unvalidated
      # number into a line a caller is told to require.
      case "$k" in
        ''|*[!0-9]*) k=0 ;;
      esac
      # scope-partial is a REQUIRED, machine-readable token, not just the human note below it:
      # the narrowing from "the whole change vs base" to "uncommitted only" is otherwise
      # recorded nowhere durable, and a caller greps for this exact prefix to know the PR body
      # must say which committed files Codex never saw.
      echo "codex-review: scope-partial files=$k" >&2
      echo "codex-review: note — $k file(s) that differ from $base are already committed and are outside this review's working-tree scope: $(printf '%s\n' "$committed_only" | tr '\n' ' ')" >&2
    fi
    scope="The change under review is the UNCOMMITTED working tree (staged + unstaged + untracked): read it with \`git diff --cached\` and \`git diff\`, and read each untracked file listed by \`git ls-files --others --exclude-standard\` in full. Changed paths: $(echo "$changed" | tr '\n' ' '). Review nothing outside this change except to trace its callers and callees."
    if [ "$mode" = diff ]; then
      focus="Review this change as a senior reviewer who did not write it. Priorities: correctness, readability for a reader with no plan or issue in front of them, plan compliance (the plan is .dev-loop/plan.md if present), tests that test behaviour, and no change beyond the issue's scope. Severity: use critical or high only for a finding that must block the merge."
    else
      focus="Review this change as a senior reviewer who did not write it. Priorities: correctness, readability for a reader with no plan or issue in front of them, plan compliance (the plan is .dev-loop/plan.md if present), tests that test behaviour, and no change beyond the issue's scope. Severity: use critical or high only for a finding that must block the merge. ALSO run an adversarial security pass: this change touches the security surface (scripts/security-surface.sh lists which paths). Assume it is unsafe until proven otherwise: for each invariant in AGENTS.md the change could touch, walk the hostile path and say whether a crafted input, a forged label, a stolen credential or a compromised Node could defeat it. Classes to check: command or argument composition, trust-boundary errors, authn/authz gaps, Policy or deny-by-default erosion, secret handling, TLS weakening, hand-edited generated code."
    fi
    run_companion "$scope $focus $repo_rules Read-only: make no edits." ;;
  design)
    f=$arg
    [ -r "$f" ] || { echo "codex-review: $f not readable" >&2; exit 2; }
    changed=$( { git diff --cached --name-only; git diff --name-only; git ls-files --others --exclude-standard; } | sort -u)
    if ! printf '%s\n' "$changed" | grep -qxF "$f"; then
      echo "codex-review: $f is not part of the uncommitted working tree; the review scope would not contain the plan. Pass a repo-root-relative path and run this before the plan is committed." >&2
      exit 2
    fi
    run_companion \
      "Adversarial review of the design plan at $f (docs/design/plans/README.md says what one is for). The working-tree change under review IS that plan. Do not take it at face value: verify every claim it makes about the codebase against the code, check it covers every acceptance criterion or spec claim it names, find what it misses, what it over-reaches, and where it would violate a repo constraint. Issues numbered, each tagged BLOCKING or SUGGESTION with file and line evidence; if REVISE, the specific corrections. Severity: use critical or high only for a finding that must block the merge. $repo_rules Read-only: make no edits." ;;
  *) echo "codex-review: unknown mode $mode" >&2; exit 2 ;;
esac
