#!/usr/bin/env bash
# scripts/dev-loop/loop.sh — run up to MAX_TICKS serial ticks, then stop.
#
# This is the entry point a scheduler (cron / Claude routine) invokes. It is
# deliberately serial: one issue is fully resolved (merged or escalated) before
# the next begins, so the shared /proto contract never has two open writers.
#
# Stops early when a tick reports idle (10) or milestone-complete (20), so a
# scheduled run does no useless work once the ready queue drains.

set -euo pipefail
DEV_LOOP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "$DEV_LOOP_DIR/lib.sh"

notify_milestone_complete() {
  # Best-effort heads-up. Customize for your channel of choice.
  log "🎉 Milestone $ACTIVE_MILESTONE has no open issues left. A human should run"
  log "   the milestone acceptance criteria (some require real hardware), then bump"
  log "   ACTIVE_MILESTONE in scripts/dev-loop/config.sh and decompose the next one."
}

log "=== dev-loop start (milestone $ACTIVE_MILESTONE, max $MAX_TICKS tick(s), DRY_RUN=${DRY_RUN:-0}) ==="

worked=0
for ((i=1; i<=MAX_TICKS; i++)); do
  log "--- tick $i/$MAX_TICKS ---"
  rc=0
  bash "$DEV_LOOP_DIR/tick.sh" || rc=$?
  case "$rc" in
    0)  (( worked++ )) || true ;;
    10) log "queue idle — stopping early"; break ;;
    20) log "milestone $ACTIVE_MILESTONE complete — human acceptance review needed; stopping"
        notify_milestone_complete; break ;;
    *)  err "tick failed (rc=$rc) — stopping to avoid compounding a bad state"; exit "$rc" ;;
  esac
done

log "=== dev-loop done: $worked issue(s) processed ==="
