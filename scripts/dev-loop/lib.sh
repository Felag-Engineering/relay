# shellcheck shell=bash
# scripts/dev-loop/lib.sh — shared helpers. Sourced by tick.sh / loop.sh / etc.
# No top-level side effects beyond function definitions.

# Resolve our own directory so scripts can source siblings regardless of CWD.
DEV_LOOP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$DEV_LOOP_DIR/../.." && pwd)"
# shellcheck source=./config.sh
source "$DEV_LOOP_DIR/config.sh"

# Make toolchains resolvable under non-login shells (cron/scheduler) — prepend
# any configured toolchain dir that exists and isn't already on PATH.
_old_ifs="$IFS"; IFS=':'
for _d in $TOOLCHAIN_PATHS; do
  [[ -d "$_d" && ":$PATH:" != *":$_d:"* ]] && PATH="$_d:$PATH"
done
IFS="$_old_ifs"; export PATH; unset _old_ifs _d

# --- Logging ------------------------------------------------------------------
# Structured, timestamped, to stderr so stdout stays parseable when needed.
_ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log()  { printf '%s [loop] %s\n'  "$(_ts)" "$*" >&2; }
warn() { printf '%s [loop][WARN] %s\n' "$(_ts)" "$*" >&2; }
err()  { printf '%s [loop][ERR] %s\n'  "$(_ts)" "$*" >&2; }
die()  { err "$*"; exit 1; }

# --- Preconditions ------------------------------------------------------------
require_clean_main() {
  cd "$REPO_ROOT"
  [[ -z "$(git status --porcelain)" ]] || die "working tree is dirty; refusing to run"
  git fetch --quiet origin "$MAIN_BRANCH" || warn "git fetch failed (offline?)"
  git checkout --quiet "$MAIN_BRANCH"
  git pull --quiet --ff-only origin "$MAIN_BRANCH" || warn "ff-only pull failed; using local $MAIN_BRANCH"
}

require_tools() {
  for t in gh jq git claude; do
    command -v "$t" >/dev/null 2>&1 || die "missing required tool: $t"
  done
}

# --- GitHub helpers (thin wrappers, repo pinned) ------------------------------
gh_() { gh "$@" --repo "$REPO_SLUG"; }

# Lowest-numbered open issue in ACTIVE_MILESTONE carrying LABEL_READY.
# Prints the issue number, or nothing if the queue is empty.
#
# NOTE: we deliberately do NOT use `gh issue list --label/--milestone`. Those
# server-side filters go through GitHub's *search* index, which lags issue
# creation by seconds-to-minutes — a freshly decomposed backlog could look empty
# and stall the loop. We fetch the open issues directly and filter client-side
# with jq, which is immediate and deterministic.
_open_issues() {
  gh_ issue list --state open --limit 200 \
    --json number,labels,milestone 2>/dev/null
}

select_next_issue() {
  _open_issues | jq -r --arg lbl "$LABEL_READY" --arg ms "$ACTIVE_MILESTONE" '
    [ .[] | select((.milestone.title==$ms) and (any(.labels[]; .name==$lbl))) ]
    | sort_by(.number) | .[0].number // empty'
}

# Count of open issues still in the active milestone (any loop state).
open_issues_in_milestone() {
  _open_issues | jq --arg ms "$ACTIVE_MILESTONE" \
    '[ .[] | select(.milestone.title==$ms) ] | length' 2>/dev/null || echo 0
}

# Issue numbers (newline-separated) carrying a given label, in the active
# milestone. Used by the serial stale-lock guard. Client-side filtered.
issues_with_label() { # issues_with_label <label>
  _open_issues | jq -r --arg lbl "$1" --arg ms "$ACTIVE_MILESTONE" \
    '.[] | select((.milestone.title==$ms) and (any(.labels[]; .name==$lbl))) | .number'
}

issue_title() { gh_ issue view "$1" --json title --jq .title; }
issue_body()  { gh_ issue view "$1" --json body  --jq .body; }

relabel() { # relabel <issue> <remove> <add>
  gh_ issue edit "$1" --remove-label "$2" --add-label "$3" >/dev/null
}

notify() { # notify <issue-or-pr> <message>
  local num="$1"; shift
  case "$NOTIFY_CHANNEL" in
    gh) gh_ issue comment "$num" --body "$*" >/dev/null 2>&1 || true ;;
    *)  log "NOTIFY[$num]: $*" ;;
  esac
}

# slugify <text> -> kebab, ascii, trimmed
slugify() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' \
    | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//' | cut -c1-40
}

# --- The claude headless (implement) invocation -------------------------------
# Centralized so the sandbox flags live in exactly one place. Reads the prompt on
# stdin, runs in REPO_ROOT, streams claude's output to the given log file, and
# returns claude's exit code. The subprocess can edit files + build; it cannot
# merge or push (the allowlist + the fact that the driver owns git enforce that).
# Fail closed if running this would incur metered API billing the user didn't ask
# for. With subscription (OAuth) auth and no key present, claude -p uses the plan.
assert_billing_ok() {
  if [[ -n "${ANTHROPIC_API_KEY:-}${ANTHROPIC_AUTH_TOKEN:-}" && "$LOOP_ALLOW_API_BILLING" != "1" ]]; then
    die "an API key is set → claude -p would bill as metered API usage. Refusing. \
Unset ANTHROPIC_API_KEY/ANTHROPIC_AUTH_TOKEN to use your subscription, or set \
LOOP_ALLOW_API_BILLING=1 to accept metered charges deliberately."
  fi
}

run_claude() { # run_claude <logfile> [model]
  local logfile="$1" model="${2:-$CLAUDE_IMPL_MODEL}"
  assert_billing_ok
  cd "$REPO_ROOT"
  timeout "${CLAUDE_TIMEOUT_SECS}s" \
    claude -p \
      --model "$model" \
      --permission-mode "$CLAUDE_PERMISSION_MODE" \
      --allowedTools "$CLAUDE_ALLOWED_TOOLS" \
      2>&1 | tee -a "$logfile"
  return "${PIPESTATUS[0]}"
}

# run_claude_json <logfile> [model] — like run_claude but extracts the model's
# JSON verdict (used by the review step). Prints the JSON object to stdout, or
# nothing if the model emitted no parseable object (caller then fails closed).
#
# Strategy: take the LAST line that contains a valid JSON object. Tolerant of
# surrounding prose and ```json code fences, since models append both. The review
# prompt asks for a single-line object as the last line, so per-line scanning is
# sufficient and robust (an empty result is the fail-closed signal).
# extract_last_json — read text on stdin, print the LAST line containing a valid
# JSON object (nothing if none). Pure (no claude); unit-tested in parse.test.sh.
# Always exits 0 — emptiness is signalled by empty output, never a non-zero exit,
# so it's safe under `set -e`/pipefail (a no-match grep must not abort the loop).
extract_last_json() {
  local _line _result=""
  while IFS= read -r _line; do
    printf '%s' "$_line" | jq -e 'type=="object"' >/dev/null 2>&1 && _result="$_line"
  done < <(tr -d '\r' | grep -oE '\{.*\}' || true)
  printf '%s' "$_result"
}

run_claude_json() {
  local logfile="$1" model="${2:-$CLAUDE_REVIEW_MODEL}" out
  out="$(run_claude "$logfile" "$model")" || true
  printf '%s\n' "$out" | extract_last_json
}

# --- Build / verify -----------------------------------------------------------
# Returns 0 iff build+test+lint all pass. Appends combined output to logfile.
verify() { # verify <logfile>
  local logfile="$1" rc=0
  cd "$REPO_ROOT"
  { echo "### make build"; make build; echo "### make test"; make test; \
    echo "### make lint"; make lint; } >>"$logfile" 2>&1 || rc=$?
  return "$rc"
}
