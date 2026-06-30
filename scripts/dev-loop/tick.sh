#!/usr/bin/env bash
# scripts/dev-loop/tick.sh — ONE iteration of the autonomous dev-loop.
#
#   select → claim → implement → verify → review → GATE → merge | escalate
#
# This driver is the sole authority over git history and merging. The creative
# work (implement, review) runs as sandboxed `claude -p` subprocesses that can
# edit files and build, but cannot commit, push, or merge. The gate (gate.sh) is
# deterministic and non-LLM. See README.md.
#
# Exit codes:  0 worked an issue   10 idle (nothing ready)   20 milestone looks
# complete (needs human acceptance)   1 error.

set -euo pipefail
DEV_LOOP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "$DEV_LOOP_DIR/lib.sh"

LOG_DIR="$DEV_LOOP_DIR/logs"; mkdir -p "$LOG_DIR"
DRY_RUN="${DRY_RUN:-0}"   # DRY_RUN=1 → do everything except push/merge/relabel

# Render a prompt template: replace {{KEY}} with $KEY for a fixed key set.
render() { # render <template> ; expects ISSUE_NUMBER/TITLE/BODY, ACTIVE_MILESTONE, MAIN_BRANCH in env
  local tpl; tpl="$(cat "$1")"
  tpl="${tpl//\{\{ISSUE_NUMBER\}\}/$ISSUE_NUMBER}"
  tpl="${tpl//\{\{ISSUE_TITLE\}\}/$ISSUE_TITLE}"
  tpl="${tpl//\{\{ISSUE_BODY\}\}/$ISSUE_BODY}"
  tpl="${tpl//\{\{ACTIVE_MILESTONE\}\}/$ACTIVE_MILESTONE}"
  tpl="${tpl//\{\{MAIN_BRANCH\}\}/$MAIN_BRANCH}"
  printf '%s' "$tpl"
}

main() {
  require_tools
  require_clean_main

  # Serial invariant: never run two issues at once. A lingering in-progress label
  # means a previous tick crashed mid-flight — stop and let a human inspect.
  local stuck
  stuck="$(gh_ issue list --state open --label "$LABEL_INPROGRESS" --json number --jq '.[].number' 2>/dev/null || true)"
  [[ -n "$stuck" ]] && die "issue(s) #$stuck still labelled $LABEL_INPROGRESS (stale lock); resolve before running"

  # --- SELECT ---------------------------------------------------------------
  local issue; issue="$(select_next_issue || true)"
  if [[ -z "$issue" ]]; then
    if [[ "$(open_issues_in_milestone)" == "0" ]]; then
      log "no open issues left in milestone $ACTIVE_MILESTONE — looks complete; human acceptance review needed."
      return 20
    fi
    log "no $LABEL_READY issues in $ACTIVE_MILESTONE (work may be blocked or awaiting humans); idle."
    return 10
  fi

  export ISSUE_NUMBER="$issue"
  export ISSUE_TITLE; ISSUE_TITLE="$(issue_title "$issue")"
  export ISSUE_BODY;  ISSUE_BODY="$(issue_body "$issue")"
  local slug branch log
  slug="$(slugify "$ISSUE_TITLE")"
  branch="loop/issue-${issue}-${slug}"
  log="$LOG_DIR/issue-${issue}.log"
  : >"$log"
  log "▶ issue #$issue — $ISSUE_TITLE  (branch $branch)"

  # --- CLAIM ----------------------------------------------------------------
  [[ "$DRY_RUN" == "1" ]] || relabel "$issue" "$LABEL_READY" "$LABEL_INPROGRESS"
  git checkout --quiet -b "$branch"
  # Always return to main on exit, whatever happens.
  trap 'git checkout --quiet "$MAIN_BRANCH" 2>/dev/null || true' RETURN

  # --- IMPLEMENT ------------------------------------------------------------
  log "implementing (sandboxed claude -p, model=$CLAUDE_IMPL_MODEL)…"
  render "$DEV_LOOP_DIR/prompts/implement.md" | run_claude "$log" "$CLAUDE_IMPL_MODEL" || warn "implement step exited non-zero"

  if [[ -z "$(git status --porcelain)" ]]; then
    escalate "$issue" "$branch" "$log" "implement step produced no changes" 0 ""
    return 0
  fi

  # The driver — not the subprocess — commits the working tree.
  git add -A
  git commit --quiet -m "feat: ${ISSUE_TITLE} (#${issue})

Implements #${issue} via the autonomous dev-loop.
Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"

  # --- VERIFY ---------------------------------------------------------------
  local build_ok=1 attempt=0
  while :; do
    log "verify: make build/test/lint (attempt $((attempt+1)))…"
    if verify "$log"; then build_ok=1; break; fi
    build_ok=0
    (( attempt++ )) || true
    [[ "$attempt" -gt "$IMPL_REPAIR_ATTEMPTS" ]] && break
    log "build red — one repair pass…"
    printf 'The build is failing. Fix it. Output of the failing build:\n\n%s' \
      "$(tail -n 120 "$log")" | run_claude "$log" "$CLAUDE_IMPL_MODEL" || true
    if [[ -n "$(git status --porcelain)" ]]; then
      git add -A && git commit --quiet -m "fix: repair build for #${issue}"
    fi
  done
  log "verify result: build_ok=$build_ok"

  # --- DIFF FACTS (deterministic inputs to the gate) ------------------------
  local changed added
  changed="$(git diff --name-only "${MAIN_BRANCH}...HEAD")"
  added="$(git diff --numstat "${MAIN_BRANCH}...HEAD" | awk '{s+=$1} END{print s+0}')"
  log "diff: $(wc -l <<<"$changed") files, +$added lines"

  # A DECISION_NEEDED.md from the implementer forces a human.
  local forced_review='{"max_severity":"none","summary":"ok","findings":[]}'
  if git diff --name-only "${MAIN_BRANCH}...HEAD" | grep -qx 'DECISION_NEEDED.md'; then
    forced_review='{"max_severity":"high","summary":"implementer flagged an architecture decision","findings":[]}'
    log "DECISION_NEEDED.md present — forcing escalation"
  fi

  # --- REVIEW (adversarial, JSON verdict) -----------------------------------
  local review="$forced_review"
  if [[ "$build_ok" == "1" && "$(jq -r .max_severity <<<"$forced_review")" != "high" ]]; then
    log "review (adversarial claude -p, model=$CLAUDE_REVIEW_MODEL)…"
    local rv; rv="$(render "$DEV_LOOP_DIR/prompts/review.md" | run_claude_json "$log" "$CLAUDE_REVIEW_MODEL" || true)"
    if [[ -n "$rv" ]] && jq -e . >/dev/null 2>&1 <<<"$rv"; then
      review="$rv"
    else
      warn "review produced no parseable verdict — treating as high severity"
      review='{"max_severity":"high","summary":"unparseable review","findings":[]}'
    fi
  fi
  log "review verdict: $(jq -c '{max_severity,summary}' <<<"$review")"

  # --- GATE (deterministic) -------------------------------------------------
  local decision_json decision
  decision_json="$(printf '%s\n' "$changed" \
    | "$DEV_LOOP_DIR/gate.sh" --files - --added "$added" --build-ok "$build_ok" \
        --review <(printf '%s' "$review"))"
  decision="$(jq -r .decision <<<"$decision_json")"
  log "GATE → $decision"

  if [[ "$decision" == "AUTO" ]]; then
    automerge "$issue" "$branch" "$log" "$review"
  else
    escalate "$issue" "$branch" "$log" \
      "$(jq -r '.reasons | map("- "+.) | join("\n")' <<<"$decision_json")" \
      "$added" "$review"
  fi
  return 0
}

# --- AUTO: push, open PR, squash-merge, mark done ------------------------------
automerge() { # automerge <issue> <branch> <log> <review-json>
  local issue="$1" branch="$2" log="$3" review="$4"
  if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: would auto-merge #$issue ($branch)"; return 0
  fi
  git push --quiet -u origin "$branch"
  local body; body="$(printf 'Closes #%s\n\nAuto-merged by the dev-loop (gate: AUTO).\n\nReview verdict:\n```json\n%s\n```' "$issue" "$review")"
  gh_ pr create --base "$MAIN_BRANCH" --head "$branch" \
     --title "feat: $(issue_title "$issue") (#$issue)" --body "$body" >/dev/null
  if gh_ pr merge "$branch" --squash --delete-branch >/dev/null 2>&1; then
    log "✓ auto-merged #$issue"
    # Issue is closed by "Closes #". Re-open is unnecessary; just record state.
    gh_ issue edit "$issue" --add-label "$LABEL_DONE" --remove-label "$LABEL_INPROGRESS" >/dev/null 2>&1 || true
    require_clean_main   # pull the squash commit back into local main
  else
    warn "squash-merge failed; leaving PR open and escalating"
    escalate "$issue" "$branch" "$log" "auto-merge attempted but \`gh pr merge\` failed" 0 "$review"
  fi
}

# --- ESCALATE: push, open PR, hand to a human ---------------------------------
escalate() { # escalate <issue> <branch> <log> <reasons-text> <added> <review-json>
  local issue="$1" branch="$2" log="$3" reasons="$4" review="${6:-}"
  err "ESCALATING #$issue:"$'\n'"$reasons"
  if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY_RUN: would escalate #$issue ($branch)"; return 0
  fi
  # Push the branch if it has commits beyond main; otherwise just flag the issue.
  if git rev-parse --verify --quiet "$branch" >/dev/null && \
     [[ -n "$(git log "${MAIN_BRANCH}..${branch}" --oneline 2>/dev/null)" ]]; then
    git push --quiet -u origin "$branch" 2>/dev/null || warn "push failed"
    local body; body="$(printf '**Needs human review** (gate: ESCALATE)\n\nReasons:\n%s\n\nReview verdict:\n```json\n%s\n```\n\n_Do not merge until a human has reviewed the security-sensitive surface._' "$reasons" "${review:-{}}")"
    gh_ pr create --base "$MAIN_BRANCH" --head "$branch" \
       --title "[needs-human] $(issue_title "$issue") (#$issue)" --body "$body" \
       --label "$LABEL_NEEDS_HUMAN" >/dev/null 2>&1 || true
  fi
  gh_ issue edit "$issue" --add-label "$LABEL_NEEDS_HUMAN" --remove-label "$LABEL_INPROGRESS" >/dev/null 2>&1 || true
  notify "$issue" "$(printf '🚦 dev-loop escalated this to a human.\n\n%s' "$reasons")"
}

main "$@"
