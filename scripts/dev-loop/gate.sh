#!/usr/bin/env bash
# scripts/dev-loop/gate.sh
#
# The merge gate. PURE and DETERMINISTIC — no LLM in the decision path. Given the
# set of changed files, the diff size, and the review verdict, it decides whether
# a change may auto-merge or must be ESCALATED to a human.
#
# Decision rule (deny-beats-allow; any single trigger forces escalation):
#   ESCALATE if  build/test/lint did not pass
#            or  any changed file matches a SECURITY_GLOB         (config.sh)
#            or  the review verdict reports a high-severity finding
#            or  the added-line count exceeds MAX_AUTO_MERGE_LINES
#            or  there are zero changed files (nothing to merge — anomaly)
#   else AUTO.
#
# Usage (CLI, for the driver and for testing):
#   gate.sh --files <file-with-paths|-> [--added N] [--build-ok 0|1] \
#           [--review <verdict.json|->]
# Prints a JSON object: {"decision":"AUTO"|"ESCALATE","reasons":[...]}
# Always exits 0 (the decision is in the payload, not the exit code).

set -euo pipefail
DEV_LOOP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./config.sh
source "$DEV_LOOP_DIR/config.sh"

# classify <changed_files_newline> <added_lines> <build_ok 0|1> <review_high 0|1>
# Echoes the decision JSON.
classify() {
  local changed="$1" added="${2:-0}" build_ok="${3:-1}" review_high="${4:-0}"
  local -a reasons=()
  local decision="AUTO"

  # 1. Machine signal first: never merge red.
  if [[ "$build_ok" != "1" ]]; then
    reasons+=("build/test/lint did not pass")
  fi

  # 2. Anything touching a security-sensitive path.
  if [[ -n "$changed" ]]; then
    local f g
    while IFS= read -r f; do
      [[ -z "$f" ]] && continue
      for g in "${SECURITY_GLOBS[@]}"; do
        if grep -Eq "$g" <<<"$f"; then
          reasons+=("security-sensitive path: $f (matched /$g/)")
          break
        fi
      done
    done <<<"$changed"
  else
    reasons+=("no changed files detected (anomaly)")
  fi

  # 3. Reviewer flagged something high-severity.
  if [[ "$review_high" == "1" ]]; then
    reasons+=("review reported a high-severity finding")
  fi

  # 4. Oversized diff — too big to wave through.
  if [[ "$added" -gt "$MAX_AUTO_MERGE_LINES" ]]; then
    reasons+=("diff adds $added lines (> MAX_AUTO_MERGE_LINES=$MAX_AUTO_MERGE_LINES)")
  fi

  [[ ${#reasons[@]} -gt 0 ]] && decision="ESCALATE"

  # Emit JSON (jq builds the reasons array safely).
  printf '%s\n' "${reasons[@]}" | jq -R . | jq -s \
    --arg decision "$decision" '{decision:$decision, reasons:(if .==[null] then [] else map(select(.!="")) end)}'
}

# --- CLI ----------------------------------------------------------------------
main() {
  local files_src="" added=0 build_ok=1 review_src=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --files)    files_src="$2"; shift 2 ;;
      --added)    added="$2"; shift 2 ;;
      --build-ok) build_ok="$2"; shift 2 ;;
      --review)   review_src="$2"; shift 2 ;;
      *) echo "gate.sh: unknown arg: $1" >&2; exit 2 ;;
    esac
  done

  local changed=""
  if [[ -n "$files_src" ]]; then
    if [[ "$files_src" == "-" ]]; then changed="$(cat)"; else changed="$(cat "$files_src")"; fi
  fi

  local review_high=0
  if [[ -n "$review_src" ]]; then
    local rjson
    if [[ "$review_src" == "-" ]]; then rjson="$(cat)"; else rjson="$(cat "$review_src")"; fi
    # Reviewer reports {"max_severity":"none|low|medium|high","findings":[...]}.
    if [[ "$(jq -r '.max_severity // "none"' <<<"$rjson" 2>/dev/null)" == "high" ]]; then
      review_high=1
    fi
  fi

  classify "$changed" "$added" "$build_ok" "$review_high"
}

# Run main only if executed directly (so the file can also be sourced for tests).
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
