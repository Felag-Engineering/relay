#!/usr/bin/env bash
# Proves the two-layer checks in scripts/check-docs.sh (ADR-0046, checks 4 and 5) and the
# generator they lean on, scripts/spec-proof.sh: a spec in the two-layer shape passes with a
# fresh Proof block and fails with a stale one or a retired section; an ADR fails on a missing
# Decision, an over-budget length or a second amendment unless the ratchet waives it; a
# proposal fails on a bad status, a missing section or an accepted status with no Outcome; a
# claim or a source comment that cites a proposal fails; and the generator attributes a test to
# the claim named in the comment directly above it, by seam, listing unproven and
# Designed-but-cited claims.
#
# Runs the REAL scripts inside a throwaway fixture repo. Hermetic: bash, grep, awk, find, diff;
# no toolchain, no network, no writes outside its own `mktemp -d`. NOT `set -e`: every case must
# run and be reported (security-surface-test.sh:13).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
WORKDIR="$(mktemp -d)" || { echo "FAIL: mktemp -d failed" >&2; exit 1; }
trap 'case "${WORKDIR:-}" in /*) rm -rf "$WORKDIR" ;; esac' EXIT
case "$WORKDIR" in
  /*) ;;
  *) echo "FAIL: mktemp returned a non-absolute path: '$WORKDIR'" >&2; exit 1 ;;
esac
FIX="$WORKDIR/repo"
fail=0

mkdir -p "$FIX/scripts" "$FIX/docs/adr" "$FIX/docs/specs" "$FIX/docs/proposals" "$FIX/docs/agents" \
         "$FIX/relay/internal/controlplane/mcp" "$FIX/relay/internal/capability" "$FIX/daemon/src"
cp "$REPO_ROOT/scripts/check-docs.sh" "$REPO_ROOT/scripts/spec-proof.sh" "$FIX/scripts/"
chmod +x "$FIX/scripts/"*.sh
: > "$FIX/docs/agents/docs-ratchet.txt"

cat > "$FIX/relay/internal/controlplane/mcp/thing_test.go" <<'GO'
package mcp

import "testing"

// Proves TH-1: the tool refuses an empty selector.
func TestThingRefusesEmptySelector(t *testing.T) {}

// Mentions TH-9, which is still Designed.
func TestThingDesignedAlready(t *testing.T) {}

// A comment separated by a blank line is not evidence (TH-2).

func TestThingUnattributed(t *testing.T) {}
GO
cat > "$FIX/relay/internal/capability/thing_test.go" <<'GO'
package capability

import "testing"

// Proves TH-1 at the capability seam.
func TestThingCapability(t *testing.T) {}
GO
cat > "$FIX/daemon/src/thing.rs" <<'RS'
#[cfg(test)]
mod tests {
    /// Proves TH-3: the daemon refuses it.
    #[test]
    fn daemon_refuses_thing() {}

    #[test]
    // Proves TH-3 as well, comment between attribute and fn.
    fn daemon_refuses_thing_again() {}

    fn helper_mentioning_th_1_is_not_a_test() {}
}
RS

# ---- fixture writers -------------------------------------------------------------------------
# write_spec <proof block text> [extra section]
write_spec() {
  {
    cat <<'MD'
# Thing

**Status:** designed, not built, as of `2026-10-22`.
**Claim prefix:** `TH`
**Governed by:** ADR-0001; invariant 1.

## Purpose

A fixture.

## Surfaces

MCP `thing`.

## Behaviour

- **TH-1** The tool refuses an empty selector.
- **TH-2** Nothing cites this one.

## Refusals

- **TH-3** The daemon refuses it.

## Designed, not built

| Claim | Statement | Milestone |
|---|---|---|
| TH-9 | It will be true later. | v9.9.9 — Fixture |

## Out of scope

Everything else.

## Proof

MD
    printf '%s\n' "$1"
    printf '\n## Retired\n\n- **TH-4** — `2026-10-22` — dropped (#1)\n- **TH-5** — `2026-10-22` — dropped (#1)\n- **TH-6** — `2026-10-22` — dropped (#1)\n- **TH-7** — `2026-10-22` — dropped (#1)\n- **TH-8** — `2026-10-22` — dropped (#1)\n'
    [ -n "${2:-}" ] && printf '\n%s\n' "$2"
  } > "$FIX/docs/specs/thing.md"
}
write_adr() {                       # write_adr <file> <first heading> <amendment count> <line count>
  local f=$1 h=$2 a=$3 n=$4 i
  {
    printf '# ADR fixture\n\n**Status:** Accepted\n\n## %s\n\nShort.\n' "$h"
    for ((i = 0; i < a; i++)); do printf '\n## Amendment (2026-10-%02d)\n\ntext\n' "$((i + 1))"; done
    printf '\n## Why\n\n'
  } > "$f"
  while [ "$(wc -l < "$f")" -lt "$n" ]; do echo "pad" >> "$f"; done
}
write_proposal() {                  # write_proposal <file> <status line 3> [omit section] [outcome text]
  local f=$1 st=$2 omit=${3:-} out=${4:-}
  {
    printf '# A proposal\n\n%s\n' "$st"
    for s in Problem Proposal Changes Objections; do
      [ "$s" = "$omit" ] || printf '\n## %s\n\ntext\n' "$s"
    done
    [ -z "$out" ] || printf '\n## Outcome\n\n%s\n' "$out"
  } > "$f"
}
run_check() { OUT=$(cd "$FIX" && ./scripts/check-docs.sh 2>&1); RC=$?; }
fresh_block() { (cd "$FIX" && ./scripts/spec-proof.sh docs/specs/thing.md); }
assert_rc() { [ "$RC" -eq "$2" ] || { echo "FAIL: $1: rc=$RC want $2; output=[$OUT]" >&2; fail=$((fail + 1)); }; }
assert_contains() { case "$OUT" in *"$2"*) ;; *) echo "FAIL: $1: output=[$OUT] lacks [$2]" >&2; fail=$((fail + 1)) ;; esac; }
assert_not_contains() { case "$OUT" in *"$2"*) echo "FAIL: $1: output=[$OUT] unexpectedly contains [$2]" >&2; fail=$((fail + 1)) ;; esac; }
reset_fixture() {
  rm -f "$FIX"/docs/adr/*.md "$FIX"/docs/proposals/*.md
  echo "# ADR-0001: fixture" > "$FIX/docs/adr/0001-fixture.md"
  printf '**Status:** Accepted\n\n## Decision\n\nShort.\n' >> "$FIX/docs/adr/0001-fixture.md"
  : > "$FIX/docs/agents/docs-ratchet.txt"
  write_spec "$(fresh_block)"
}

# ---- the generator ---------------------------------------------------------------------------
write_spec "x"
OUT=$(fresh_block); RC=$?
assert_rc "gen-runs" 0
assert_contains "gen-th1-both-tests" '| TH-1 | `TestThingCapability`, `TestThingRefusesEmptySelector` | MCP, capability |'
assert_contains "gen-th3-rust" '| TH-3 | `daemon_refuses_thing`, `daemon_refuses_thing_again` | daemon |'
assert_contains "gen-unproven" 'Unproven: TH-2.'
assert_contains "gen-designed-cited" 'Designed claims a test already cites: TH-9 (`TestThingDesignedAlready`).'
assert_not_contains "gen-blank-line-not-evidence" 'TestThingUnattributed'
assert_not_contains "gen-helper-not-test" 'helper_mentioning'

# ---- specs in the two-layer shape --------------------------------------------------------------
reset_fixture; run_check
assert_rc "v2-fresh-passes" 0

write_spec "$(fresh_block | sed 's/TestThingCapability/TestRenamed/')"; run_check
assert_rc "v2-stale-block" 1; assert_contains "v2-stale-block" "Proof block is stale"

write_spec "$(fresh_block)" $'## Future work\n\ntext'; run_check
assert_rc "v2-retired-section" 1; assert_contains "v2-retired-section" "has no place in the two-layer shape"

write_spec "$(fresh_block)"; sed -i '/^\*\*Governed by/d' "$FIX/docs/specs/thing.md"; run_check
assert_rc "v2-no-governed-by" 1; assert_contains "v2-no-governed-by" "Governed by"

write_spec "$(fresh_block)"
sed -i 's/^- \*\*TH-2\*\* .*/- **TH-2** Nothing cites this one, see docs\/proposals\/thing.md./' "$FIX/docs/specs/thing.md"; run_check
assert_rc "v2-claim-cites-proposal" 1; assert_contains "v2-claim-cites-proposal" "a claim cites a proposal"

# ---- ADRs -------------------------------------------------------------------------------------
reset_fixture
write_adr "$FIX/docs/adr/0002-fixture.md" "Context" 0 10; run_check
assert_rc "adr-no-decision" 1; assert_contains "adr-no-decision" "first section must be '## Decision'"
echo "docs/adr/0002-fixture.md decision" > "$FIX/docs/agents/docs-ratchet.txt"; run_check
assert_rc "adr-no-decision-waived" 0

reset_fixture
write_adr "$FIX/docs/adr/0002-fixture.md" "Decision" 2 20; run_check
assert_rc "adr-two-amendments" 1; assert_contains "adr-two-amendments" "amended at most once"
echo "docs/adr/0002-fixture.md amendments" > "$FIX/docs/agents/docs-ratchet.txt"; run_check
assert_rc "adr-two-amendments-waived" 0

reset_fixture
write_adr "$FIX/docs/adr/0002-fixture.md" "Decision" 0 151; run_check
assert_rc "adr-over-budget" 1; assert_contains "adr-over-budget" "at most 150"
echo "docs/adr/0002-fixture.md budget" > "$FIX/docs/agents/docs-ratchet.txt"; run_check
assert_rc "adr-over-budget-waived" 0

reset_fixture
write_adr "$FIX/docs/adr/0002-fixture.md" "Context" 3 200
sed -i '3s/.*/**Status:** Superseded by ADR-0001./' "$FIX/docs/adr/0002-fixture.md"; run_check
assert_rc "adr-superseded-is-exempt" 0

reset_fixture
echo "docs/adr/0099-gone.md budget" > "$FIX/docs/agents/docs-ratchet.txt"; run_check
assert_rc "ratchet-stale-path" 1; assert_contains "ratchet-stale-path" "which does not exist"

# ---- proposals ---------------------------------------------------------------------------------
reset_fixture
write_proposal "$FIX/docs/proposals/p.md" '**Status:** idea (`2026-10-22`). Origin: #1.'; run_check
assert_rc "proposal-idea-passes" 0

write_proposal "$FIX/docs/proposals/p.md" '**Status:** draft (`2026-10-22`).'; run_check
assert_rc "proposal-bad-status" 1; assert_contains "proposal-bad-status" "line 3 must be"

write_proposal "$FIX/docs/proposals/p.md" '**Status:** idea (`2026-10-22`).' Objections; run_check
assert_rc "proposal-missing-section" 1; assert_contains "proposal-missing-section" "missing section '## Objections'"

write_proposal "$FIX/docs/proposals/p.md" '**Status:** accepted (`2026-10-22`).'; run_check
assert_rc "proposal-accepted-no-outcome" 1; assert_contains "proposal-accepted-no-outcome" "no '## Outcome'"

write_proposal "$FIX/docs/proposals/p.md" '**Status:** accepted (`2026-10-22`).' "" "Became ADR-0001 and TH-1."; run_check
assert_rc "proposal-accepted-with-outcome" 0

write_proposal "$FIX/docs/proposals/p.md" '**Status:** accepted (`2026-10-22`).' "" "Decided."; run_check
assert_rc "proposal-accepted-names-nothing" 1; assert_contains "proposal-accepted-names-nothing" "names neither an ADR nor a claim"

# ---- source comments ------------------------------------------------------------------------------
reset_fixture
printf '// see docs/proposals/p.md\nfn x() {}\n' > "$FIX/daemon/src/cites.rs"; run_check
assert_rc "source-cites-proposal" 1; assert_contains "source-cites-proposal" "cites docs/proposals/"
rm -f "$FIX/daemon/src/cites.rs"

if [ "$fail" -eq 0 ]; then echo "check-docs-shape-test: all cases pass"; else echo "check-docs-shape-test: $fail failure(s)" >&2; fi
exit "$fail"
