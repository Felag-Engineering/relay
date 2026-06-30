#!/usr/bin/env bash
# scripts/dev-loop/parse.test.sh — unit tests for extract_last_json (the review
# verdict parser). A silent failure here once made every change escalate, so the
# happy path AND the fail-closed path are both pinned.

set -euo pipefail
DEV_LOOP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "$DEV_LOOP_DIR/lib.sh"
pass=0; fail=0

# check <name> <expected-max_severity-or-EMPTY> <input...>
check() {
  local name="$1" want="$2" input="$3"
  local got sev
  got="$(printf '%s' "$input" | extract_last_json)"
  if [[ "$want" == "EMPTY" ]]; then
    sev="$([[ -z "$got" ]] && echo EMPTY || echo "$got")"
  else
    sev="$(printf '%s' "$got" | jq -r '.max_severity // "PARSE_FAIL"' 2>/dev/null)"
  fi
  if [[ "$sev" == "$want" ]]; then printf '  ok   %-42s → %s\n' "$name" "$sev"; (( pass++ )) || true
  else printf '  FAIL %-42s → got %s, want %s\n' "$name" "$sev" "$want"; (( fail++ )) || true; fi
}

echo "extract_last_json unit tests:"
check "bare single-line object"  none \
  '{"max_severity":"none","findings":[]}'
check "fenced json after prose"  none \
  $'review done.\n```json\n{"max_severity":"none","summary":"ok","findings":[]}\n```'
check "prose with braces, then verdict" high \
  $'the map {x} is fine\nlots of (parens) and text\n{"max_severity":"high","summary":"bug","findings":[]}'
check "two objects — takes the last" medium \
  $'{"max_severity":"none"}\nmore text\n{"max_severity":"medium","findings":[]}'
check "no JSON at all → empty (fail-closed)" EMPTY \
  $'I was unable to complete the review.'
check "malformed braces only → empty"        EMPTY \
  $'here is {not json} for you'

echo "—— $pass passed, $fail failed ——"
[[ "$fail" -eq 0 ]]
