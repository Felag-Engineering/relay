#!/usr/bin/env bash
# Run a Codex review as the second reviewer on one of the workflow's adversarial gates.
# See "Reviewers" in docs/agents/workflow.md.
#
#   scripts/codex-review.sh diff     [<base-ref>]      review of the working tree against base (committed + uncommitted + untracked)
#   scripts/codex-review.sh security [<base-ref>]      the same diff, focused on the security surface
#   scripts/codex-review.sh design   <design-file>     read-only critique of a design plan
#
# Prints Codex's report on stdout. Exit 0 on a report, 3 if Codex is not available —
# the caller then records the gate as single-reviewer, never as passed. Codex is a
# reviewer only: every mode here is read-only (no --write), and this script never
# invokes `task` with write access.
set -uo pipefail
cd "$(dirname "$0")/.."

mode=${1:-}; arg=${2:-origin/main}
[ -n "$mode" ] || { sed -n '2,11p' "$0"; exit 2; }

companion=$(ls -d "$HOME"/.claude/plugins/cache/openai-codex/codex/*/scripts/codex-companion.mjs 2>/dev/null | sort -V | tail -1)
if [ -z "$companion" ] || ! command -v codex >/dev/null 2>&1 || ! command -v node >/dev/null 2>&1; then
  echo "codex-review: Codex plugin or CLI not available; this gate runs with one reviewer" >&2
  exit 3
fi

repo_rules="Constraints come from AGENTS.md (the fourteen invariants and the escalation list), GLOSSARY.md, docs/agents/workflow.md and the governing docs/specs/<capability>.md. Read them before judging. A change that would make an invariant, an ADR or a bound spec claim untrue is a blocking finding, never a suggestion. Cite file and line for every finding. Do not edit anything."

case "$mode" in
  diff|security)
    # Not `adversarial-review --base`: with a base ref the companion reviews COMMITTED history
    # only, and the dev-loop commits at Stage 7 — after these reviews — so Codex saw a partial or
    # empty diff. `git diff <base>` (two dots, working tree against base) plus the untracked files
    # is the whole change whether or not any of it is committed yet.
    base=$arg
    git rev-parse --verify --quiet "$base" >/dev/null || { echo "codex-review: base $base not found" >&2; exit 2; }
    changed=$( { git diff --name-only "$base"; git ls-files --others --exclude-standard; } | sort -u)
    if [ -z "$changed" ]; then
      echo "codex-review: nothing differs from $base (committed or not); refusing to review an empty change" >&2
      exit 2
    fi
    scope="The change under review is the working tree against $base: read it with \`git diff $base\` (committed and uncommitted edits together) and read each untracked file listed by \`git ls-files --others --exclude-standard\` in full. Changed paths: $(echo "$changed" | tr '\n' ' '). Review nothing outside this change except to trace its callers and callees."
    if [ "$mode" = diff ]; then
      focus="Review this change as a senior reviewer who did not write it. Priorities: correctness, readability for a reader with no plan or issue in front of them, plan compliance (the plan is .dev-loop/plan.md if present), tests that test behaviour, and no change beyond the issue's scope. Output: Verdict APPROVE or CHANGES_REQUESTED; then findings, each tagged BLOCKING or SUGGESTION with file:line."
    else
      focus="Adversarial security review. This change touches the security surface (scripts/security-surface.sh lists which paths). Assume it is unsafe until proven otherwise: for each invariant in AGENTS.md the change could touch, walk the hostile path and say whether a crafted input, a forged label, a stolen credential or a compromised Node could defeat it. Classes to check: command or argument composition, trust-boundary errors, authn/authz gaps, Policy or deny-by-default erosion, secret handling, TLS weakening, hand-edited generated code. Output: Verdict PASS, CONCERNS or FAIL; then findings with severity and file:line."
    fi
    node "$companion" task --fresh "$scope $focus $repo_rules Read-only: make no edits." ;;
  design)
    f=$arg
    [ -r "$f" ] || { echo "codex-review: $f not readable" >&2; exit 2; }
    node "$companion" task --fresh \
      "Adversarial review of the design plan at $f (docs/design/plans/README.md says what one is for). Do not take it at face value: verify every claim it makes about the codebase against the code, check it covers every acceptance criterion or spec claim it names, find what it misses, what it over-reaches, and where it would violate a repo constraint. Output: Verdict APPROVE or REVISE; Issues numbered, each tagged BLOCKING or SUGGESTION with file and line evidence; if REVISE, the specific corrections. $repo_rules Read-only: make no edits." ;;
  *) echo "codex-review: unknown mode $mode" >&2; exit 2 ;;
esac
