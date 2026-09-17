#!/usr/bin/env bash
# Print the changed paths that fall on the security and architecture surface.
#
#   scripts/security-surface.sh [<base-ref>]        diff base..HEAD plus the working tree
#   git diff --name-only ... | scripts/security-surface.sh -   read paths from stdin
#
# Exit 0 and print matches (one per line) if any path matches a glob in
# docs/agents/security-surface.txt; exit 1 with no output otherwise. The glob
# list is the single source of truth — see docs/agents/workflow.md.
set -uo pipefail
cd "$(dirname "$0")/.."
shopt -s globstar extglob nullglob

list=docs/agents/security-surface.txt
[ -r "$list" ] || { echo "security-surface: $list missing" >&2; exit 2; }

if [ "${1:-}" = "-" ]; then
  paths=$(cat)
else
  base=${1:-origin/main}
  paths=$( { git diff --name-only "$base"...HEAD 2>/dev/null; git diff --name-only; git diff --name-only --cached; } | sort -u)
fi

mapfile -t globs < <(grep -vE '^\s*(#|$)' "$list")
hit=0
while IFS= read -r p; do
  [ -n "$p" ] || continue
  for g in "${globs[@]}"; do
    # shellcheck disable=SC2053
    if [[ "$p" == $g ]]; then echo "$p"; hit=1; break; fi
  done
done <<< "$paths"
[ "$hit" -eq 1 ]
