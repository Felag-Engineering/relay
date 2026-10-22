#!/usr/bin/env bash
# Generate a capability spec's Proof block from the tests that cite its claims (ADR-0046).
#
# A test proves a claim by naming the claim's ID in the comment block directly above the test
# function: `// Proves EN-30.` above a Go `func Test…`, or a `///`, `//!` or `//` line above (or
# between) a Rust `#[test]` / `#[tokio::test]` attribute and its fn. IDs anywhere else — in a test
# body, an assertion message, a blank-line-separated comment — are not evidence. The seam is read
# from the test's path. The block ends with the current claims no test cites and the Designed
# claims a test already cites, so neither list is kept by hand.
#
#   scripts/spec-proof.sh <spec>     print the Proof block for one spec
#   scripts/spec-proof.sh --write    rewrite the block in every spec that has one
#
# Only a spec in the two-layer shape (one with a `## Proof` section and the proof markers) is
# touched; scripts/check-docs.sh fails such a spec whose committed block differs from this
# output. SPEC_DIR and SPEC_SRC_DIRS override the directories for self-tests.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
SPEC_DIR=${SPEC_DIR:-docs/specs}
read -r -a SRC_DIRS <<<"${SPEC_SRC_DIRS:-relay daemon}"
BEGIN='<!-- proof:begin -->'; END='<!-- proof:end -->'

section() { awk -v h="## $2" '$0==h{f=1;next} /^## /{f=0} f' "$1"; }

seam() {                               # seam <test file path>
  case "$1" in
    */controlplane/mcp/*)     echo MCP ;;
    */controlplane/api/*)     echo API ;;
    */controlplane/console/*) echo Console ;;
    */controlplane/*)         echo "control plane" ;;
    */internal/capability/*)  echo capability ;;
    */internal/relaytest/*)   echo e2e ;;
    */internal/transport/*)   echo "Node plane" ;;
    relay/internal/*)         local p=${1#relay/internal/}; echo "${p%%/*}" ;;
    relay/*)                  echo Relay ;;
    daemon/*)                 echo daemon ;;
    *)                        echo "—" ;;
  esac
}

# Every (claim ID, test name, file) triple in the source trees, computed once.
evidence() {
  local f
  while IFS= read -r f; do
    awk -v file="$f" '
      /^[[:space:]]*\/\// { blk = blk " " $0; next }
      /^func (Test|Benchmark|Fuzz)[A-Za-z0-9_]*\(/ {
        name = $2; sub(/\(.*/, "", name)
        n = split(blk, w, /[^A-Za-z0-9-]+/)
        for (i = 1; i <= n; i++) if (w[i] ~ /^[A-Z][A-Z][A-Z]?-[0-9]+$/) print w[i] "\t" name "\t" file
      }
      { blk = "" }' "$f"
  done < <(find "${SRC_DIRS[@]}" -name target -prune -o -name '*_test.go' -type f -print 2>/dev/null | sort)
  while IFS= read -r f; do
    awk -v file="$f" '
      /^[[:space:]]*\/\// { blk = blk " " $0; next }
      /^[[:space:]]*#\[(tokio::)?test(\]|\()/ { t = 1; next }
      t && /^[[:space:]]*(#\[|$)/ { next }
      t && match($0, /fn[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/) {
        name = substr($0, RSTART, RLENGTH); sub(/fn[[:space:]]+/, "", name)
        n = split(blk, w, /[^A-Za-z0-9-]+/)
        for (i = 1; i <= n; i++) if (w[i] ~ /^[A-Z][A-Z][A-Z]?-[0-9]+$/) print w[i] "\t" name "\t" file
      }
      { blk = ""; t = 0 }' "$f"
  done < <(find "${SRC_DIRS[@]}" -name target -prune -o -name '*.rs' -type f -print 2>/dev/null | sort)
}

# render <spec> <evidence>  — the block, markers included.
render() {
  local spec=$1 ev=$2 prefix current designed id tests seams
  prefix=$(grep -m1 -oE '^\*\*Claim prefix:\*\* *`[A-Z]{2,3}`' "$spec" | grep -oE '[A-Z]{2,3}')
  current=$( { section "$spec" Behaviour; section "$spec" Refusals; } \
             | grep -oE "\*\*$prefix-[0-9]+\*\*" | tr -d '*' | sort -t- -k2,2n -u)
  designed=$(section "$spec" "Designed, not built" | grep -E "^\| *$prefix-[0-9]+ *\|" \
             | awk -F'|' '{gsub(/ /,"",$2); print $2}' | sort -t- -k2,2n -u)
  echo "$BEGIN"
  echo '| Claim | Proven by | Seam |'
  echo '|---|---|---|'
  local unproven=() cited=()
  for id in $current; do
    tests=$(awk -F'\t' -v id="$id" '$1==id {print $2}' <<<"$ev" | sort -u | sed 's/.*/`&`/' | paste -sd, - | sed 's/,/, /g')
    if [ -z "$tests" ]; then unproven+=("$id"); continue; fi
    seams=$(awk -F'\t' -v id="$id" '$1==id {print $3}' <<<"$ev" | while IFS= read -r f; do seam "$f"; done | sort -u | paste -sd, - | sed 's/,/, /g')
    echo "| $id | $tests | $seams |"
  done
  for id in $designed; do
    tests=$(awk -F'\t' -v id="$id" '$1==id {print $2}' <<<"$ev" | sort -u | sed 's/.*/`&`/' | paste -sd, - | sed 's/,/, /g')
    [ -n "$tests" ] && cited+=("$id ($tests)")
  done
  echo
  if [ ${#unproven[@]} -eq 0 ]; then echo "Unproven: none."
  else echo "Unproven: $(printf '%s, ' "${unproven[@]}" | sed 's/, $//')."; fi
  [ ${#cited[@]} -eq 0 ] || echo "Designed claims a test already cites: $(printf '%s; ' "${cited[@]}" | sed 's/; $//')."
  echo "$END"
}

has_block() { grep -qxF "$BEGIN" "$1" && grep -qxF "$END" "$1"; }

case "${1:-}" in
  --write)
    ev=$(evidence)
    for spec in "$SPEC_DIR"/*.md; do
      case "$spec" in */README.md|*/TEMPLATE.md) continue;; esac
      has_block "$spec" || continue
      block=$(render "$spec" "$ev")
      awk -v b="$BEGIN" -v e="$END" -v block="$block" '
        $0==b { print block; skip=1; next }
        $0==e { skip=0; next }
        !skip' "$spec" > "$spec.tmp" && mv "$spec.tmp" "$spec"
      echo "spec-proof: wrote $spec"
    done ;;
  "")  echo "usage: scripts/spec-proof.sh <spec> | --write" >&2; exit 2 ;;
  *)   [ -f "$1" ] || { echo "spec-proof: no such spec: $1" >&2; exit 2; }
       render "$1" "$(evidence)" ;;
esac
