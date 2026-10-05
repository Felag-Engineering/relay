#!/usr/bin/env bash
# Print the changed paths that fall on the security and architecture surface.
#
#   scripts/security-surface.sh [<base-ref>]   the whole change this checkout represents
#   git diff --name-only ... | scripts/security-surface.sh -   read paths from stdin
#
# Ref mode unions four sources, so a path counts however it arrives. The union is the point:
# three separate false negatives (#634) all rendered as "clean", the one answer nobody checks.
#
#   git diff --no-renames --name-only <base>...HEAD   committed on this branch since <base>
#   git diff --no-renames --name-only                 tracked, modified in the working tree
#   git diff --no-renames --name-only --cached        staged
#   git ls-files --others --exclude-standard          untracked and not ignored
#
# Untracked files are load-bearing: a NEW FILE IS HOW NEW SURFACE ARRIVES, and git diff never
# sees one. That was #634 as filed.
#
# --no-renames is load-bearing: with rename detection on, `git mv` of a surface file to a path
# off the surface reports ONLY the destination — a guard moved off the surface, reported as
# nothing. Both halves of a rename must be reported. (scripts/ci-changed-paths.sh does the
# same, for the same reason.)
#
# An unresolvable <base> is load-bearing: it makes every diff above empty, which used to exit
# 1 and silent — identical to a clean surface, on any checkout that never fetched the remote.
# It is now a refusal (exit 2, stderr), never a clean report.
#
# A base ref that DOES resolve can still fail to diff: with no merge base (a shallow clone,
# unrelated history) `git diff <base>...HEAD` fatals to stderr. Losing that arm silently would
# be worse than #634, not equivalent to it — in Stage 6.5's actual usage (after `make verify`,
# on a committed clean tree) that arm carries the ENTIRE change. It is captured separately and
# refused on (exit 2, stderr), never folded into a union that can silently lose an arm.
#
# Deletions count, by choice: the diff sources report a removed path, and deleting a guard is
# a surface change.
#
# Ignored files are NOT surface, by choice: .gitignore, .git/info/exclude and the user's global
# excludes are honoured (--exclude-standard), so generated artifacts — relay/bin/,
# relay/internal/apiclient/client.gen.go, daemon/target/ — never register. Anything
# committable does.
#
# Stdin mode is deliberately untouched by all of the above: a caller piping paths in supplies
# its own set (the dev-loop scope gate, dev-loop.md Stage 2.5).
#
# Residual limits, stated so they are not mistaken for coverage:
#   - an untracked NESTED GIT REPO lists as its directory with a trailing slash. If that
#     directory sits ABOVE a surface glob (`git init` inside relay/, say), files new beneath
#     it are not reported: [[ "relay/" == relay/internal/capability/** ]] does not match.
#   - paths with control or non-ASCII characters are quoted by git (core.quotePath) in
#     ls-files and in diff alike, and may not match a glob. Pre-existing; unchanged here.
#
# Exit 0 and print matches (one per line) if any path matches a glob in
# docs/agents/security-surface.txt. Exit 1, silent, if it ran and matched nothing. Exit 2,
# with a reason on stderr, IF IT COULD NOT RUN — the glob list is missing, <base> does not
# resolve to a commit, or <base>...HEAD could not be diffed (no merge base). EXIT 2 IS NEVER
# "CLEAN": a caller that reads silence as "continue" must treat it as a skipped gate. The glob
# list is the single source of truth — see docs/agents/workflow.md.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
# GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE in the environment would silently redirect every git
# call below to a different repository's history and index (SEC5).
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE
shopt -s globstar extglob nullglob

list=docs/agents/security-surface.txt
[ -r "$list" ] || { echo "security-surface: $list missing" >&2; exit 2; }

if [ "${1:-}" = "-" ]; then
  paths=$(cat)
else
  base=${1:-origin/main}
  # A base that does not resolve made every diff below empty and the whole check exit 1 —
  # indistinguishable from a clean surface (#634). Refuse loudly instead; dev-loop treats
  # silence as "continue". This also catches "not a git repository at all".
  if ! git rev-parse --verify -q "$base^{commit}" >/dev/null; then
    echo "security-surface: base ref '$base' does not resolve — refusing to report a clean surface" >&2
    exit 2
  fi
  # A resolvable base can still fail to diff — no merge base (a shallow clone, unrelated
  # history) makes this fatal to stderr. Capture it on its own and refuse rather than let a
  # failed arm silently drop out of the union (SEC1): in Stage 6.5's actual usage this arm
  # carries the ENTIRE change.
  if ! committed=$(git diff --no-renames --name-only "$base"...HEAD); then
    echo "security-surface: 'git diff $base...HEAD' failed (no merge base — a shallow clone, or unrelated histories) — refusing to report a clean surface" >&2
    exit 2
  fi
  paths=$( { printf '%s\n' "$committed"; \
             git diff --no-renames --name-only; \
             git diff --no-renames --name-only --cached; \
             git ls-files --others --exclude-standard; } | sort -u)
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
