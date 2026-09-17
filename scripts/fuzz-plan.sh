#!/usr/bin/env bash
# Decides whether tonight's scheduled fuzz jobs run, printing `run=true|false` for
# $GITHUB_OUTPUT (security-nightly.yml). Fuzzing code that has not changed since it
# was last fuzzed buys little per minute; the persisted corpora make the runs that do
# happen resume where the last one stopped.
#
# Runs when any of these holds, and fails OPEN (runs) on any doubt:
#   - the run was not scheduled (workflow_dispatch always fuzzes);
#   - it is Wednesday or Sunday (UTC): a floor that keeps coverage-guided search going
#     on quiet weeks, and keeps the corpus caches inside GitHub's 7-day eviction window;
#   - anything the fuzzers exercise changed since the last successful scheduled run.
#
# "Last successful scheduled run" is sound as the baseline even when that run skipped
# fuzzing: it skipped only because nothing changed since the run before it, and a run
# whose fuzzing found a crash is not successful, so the next night fuzzes again.
set -uo pipefail
cd "$(dirname "$0")/.."

fuzzed_paths=(relay daemon proto Makefile .github/workflows/security-nightly.yml scripts/fuzz-plan.sh)

decide() {
  echo "run=$1"
  echo "fuzz-plan: run=$1 — $2" >&2
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    echo "**Fuzz plan:** run=\`$1\` — $2" >>"$GITHUB_STEP_SUMMARY"
  fi
  exit 0
}

[ "${GITHUB_EVENT_NAME:-}" = "schedule" ] \
  || decide true "not a scheduled run (${GITHUB_EVENT_NAME:-local})"

case "$(date -u +%u)" in
  3 | 7) decide true "twice-weekly floor (Wednesday/Sunday UTC)" ;;
esac

last=$(gh run list --workflow security-nightly.yml --branch main --event schedule \
  --status success --limit 1 --json headSha --jq '.[0].headSha // empty' 2>/dev/null) || last=""
[ -n "$last" ] || decide true "no earlier successful scheduled run found"
git cat-file -e "${last}^{commit}" 2>/dev/null \
  || decide true "last successful run's commit ${last} is not in this checkout"

if git diff --quiet "$last" HEAD -- "${fuzzed_paths[@]}"; then
  decide false "nothing under ${fuzzed_paths[*]} changed since ${last}"
fi
decide true "fuzzed code changed since ${last}"
