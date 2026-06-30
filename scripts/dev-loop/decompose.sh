#!/usr/bin/env bash
# scripts/dev-loop/decompose.sh — milestone → draft issues. HUMAN SEAM #1.
#
#   decompose.sh [milestone]            # draft issues, write JSON, print for review
#   decompose.sh [milestone] --apply    # create the issues on GitHub (loop:ready)
#
# Without --apply this is read-only: it asks claude to propose an issue breakdown
# and writes it to scripts/dev-loop/logs/decompose-<milestone>.json for you to
# inspect/edit. Re-run with --apply (or edit the JSON and pass it via --from) to
# create the issues. Nothing is created until you say so.

set -euo pipefail
DEV_LOOP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "$DEV_LOOP_DIR/lib.sh"
require_tools

MILESTONE="${1:-$ACTIVE_MILESTONE}"; [[ "${MILESTONE:0:2}" == "--" ]] && MILESTONE="$ACTIVE_MILESTONE"
APPLY=0; FROM=""
for a in "$@"; do
  case "$a" in
    --apply) APPLY=1 ;;
    --from=*) FROM="${a#--from=}" ;;
  esac
done
export ACTIVE_MILESTONE="$MILESTONE" MAIN_BRANCH
mkdir -p "$DEV_LOOP_DIR/logs"
DRAFT="$DEV_LOOP_DIR/logs/decompose-${MILESTONE}.json"
RUNLOG="$DEV_LOOP_DIR/logs/decompose-${MILESTONE}.log"

if [[ -n "$FROM" ]]; then
  cp "$FROM" "$DRAFT"; log "using issue list from $FROM"
elif [[ "$APPLY" == "1" && -s "$DRAFT" ]]; then
  log "using previously-drafted $DRAFT"
else
  log "drafting issues for milestone $MILESTONE (claude -p)…"
  : >"$RUNLOG"
  tpl="$(cat "$DEV_LOOP_DIR/prompts/decompose.md")"
  tpl="${tpl//\{\{ACTIVE_MILESTONE\}\}/$MILESTONE}"
  arr="$(printf '%s' "$tpl" \
    | run_claude "$RUNLOG" \
    | tr -d '\r' | grep -v '^```' \
    | jq -cs 'map(select(type=="array")) | last // empty' 2>/dev/null || true)"
  # Fallback: pull the last [...] block out of the prose.
  if [[ -z "$arr" || "$arr" == "null" ]]; then
    arr="$(grep -ozP '(?s)\[\s*\{.*\}\s*\]' "$RUNLOG" | tr -d '\0' | jq -c . 2>/dev/null | tail -n1 || true)"
  fi
  [[ -n "$arr" ]] || die "could not parse an issue array from claude output (see $RUNLOG)"
  printf '%s\n' "$arr" | jq . >"$DRAFT"
fi

count="$(jq 'length' "$DRAFT")"
log "drafted $count issue(s) → $DRAFT"
jq -r 'to_entries[] | "  [\(.key)] \(.value.title)"' "$DRAFT"

if [[ "$APPLY" != "1" ]]; then
  cat <<EOF

Review/edit the draft above, then create the issues with:
    scripts/dev-loop/decompose.sh $MILESTONE --apply
(or edit $DRAFT and apply it with --from=$DRAFT)
EOF
  exit 0
fi

log "creating $count issues on GitHub (milestone $MILESTONE, label $LABEL_READY)…"
n="$(jq 'length' "$DRAFT")"
for ((k=0; k<n; k++)); do
  title="$(jq -r ".[$k].title" "$DRAFT")"
  body="$(jq -r ".[$k].body" "$DRAFT")"
  url="$(gh_ issue create --title "$title" --body "$body" \
        --label "$LABEL_READY" --milestone "$MILESTONE")"
  log "  created: $url"
done
log "done. The loop will pick these up lowest-number-first."
