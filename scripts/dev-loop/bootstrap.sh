#!/usr/bin/env bash
# scripts/dev-loop/bootstrap.sh — one-time setup. Idempotent; safe to re-run.
# Creates the loop:* state labels and the roadmap milestones in GitHub.

set -euo pipefail
DEV_LOOP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "$DEV_LOOP_DIR/lib.sh"
require_tools

ensure_label() { # ensure_label <name> <color> <desc>
  if gh_ label create "$1" --color "$2" --description "$3" >/dev/null 2>&1; then
    log "label created: $1"
  else
    gh_ label edit "$1" --color "$2" --description "$3" >/dev/null 2>&1 && log "label exists: $1"
  fi
}

ensure_milestone() { # ensure_milestone <title>  (gh api takes the repo in the URL, not --repo)
  local existing
  existing="$(gh api "repos/$REPO_SLUG/milestones?state=all" --jq ".[] | select(.title==\"$1\") | .number" 2>/dev/null || true)"
  if [[ -n "$existing" ]]; then log "milestone exists: $1 (#$existing)"; return; fi
  gh api "repos/$REPO_SLUG/milestones" -f title="$1" >/dev/null && log "milestone created: $1"
}

log "creating state labels…"
ensure_label "$LABEL_READY"       "0e8a16" "dev-loop: eligible to be picked up"
ensure_label "$LABEL_INPROGRESS"  "fbca04" "dev-loop: currently being worked"
ensure_label "$LABEL_NEEDS_HUMAN" "d93f0b" "dev-loop: escalated — human must review/merge"
ensure_label "$LABEL_BLOCKED"     "5319e7" "dev-loop: waiting on a dependency"
ensure_label "$LABEL_DONE"        "c5def5" "dev-loop: merged"

log "creating roadmap milestones…"
for m in v0.0.1 v0.0.2 v0.0.3 v0.0.4 v0.1.0-beta; do ensure_milestone "$m"; done

log "bootstrap complete. Next: scripts/dev-loop/decompose.sh $ACTIVE_MILESTONE"
