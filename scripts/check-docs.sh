#!/usr/bin/env bash
# Documentation invariants that CI enforces on every PR. Fast, no toolchain: shell + grep + awk.
#
#   1. ADR numbers are unique.
#   2. Every test a spec cites exists: a Go `Test*`, `Benchmark*` or `Fuzz*` name anywhere in
#      the spec; and, in a "What proves each claim" row, every snake_case name (one with an
#      underscore, optionally `path::`-qualified), which is read as a Rust test — a fn under
#      #[test] or #[tokio::test] in daemon/ — or a cargo-fuzz target in daemon/fuzz/Cargo.toml.
#   3. A migrated spec (Status current/designed) has the claim shape docs/specs/TEMPLATE.md
#      describes: a declared prefix, unique across specs; every claim ID uses it and is defined
#      once; proof rows cite defined Behaviour/Refusals claims; Designed rows carry a milestone;
#      Status agrees with whether Designed has rows; the required sections exist; every
#      `<name>.md` a spec mentions resolves.
#   4. The two-layer shape (ADR-0046). A migrated spec with a `## Proof` section has exactly the
#      sections docs/specs/TEMPLATE.md names, a `**Governed by:**` line, a Purpose of at most
#      120 words, at most 250 lines outside the generated Proof block, and a Proof block equal
#      to what scripts/spec-proof.sh generates. A migrated spec still in the earlier shape must
#      be listed in docs/agents/docs-ratchet.txt with `shape`. Every ADR opens with
#      `## Decision` of at most 120 words, runs at most 150 lines and carries at most one
#      `## Amendment`; each rule is waived per file by `decision`, `budget` or `amendments` in
#      the ratchet. Every path the ratchet lists exists.
#   5. Proposals (docs/proposals/) have the shape docs/proposals/TEMPLATE.md describes: a Status
#      of idea/shaping/accepted/rejected on line 3, the four sections, Outcome once decided,
#      at most 120 lines. No spec claim and no Go or Rust comment cites a proposal.
#
# Legacy specs (Status aspirational/stub) get checks 1 and 2 only — they are unmigrated intent,
# see "The establishing phase" in docs/specs/README.md. SPEC_DIR, ADR_DIR, PROPOSAL_DIR and
# RATCHET override the paths for self-tests.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
SPEC_DIR=${SPEC_DIR:-docs/specs}
ADR_DIR=${ADR_DIR:-docs/adr}
PROPOSAL_DIR=${PROPOSAL_DIR:-docs/proposals}
RATCHET=${RATCHET:-docs/agents/docs-ratchet.txt}
fail=0
err() { echo "check-docs: $*" >&2; fail=1; }

# The ratchet: `<path> <rule>…` per line, `#` comments. exempt <path> <rule> is true when the
# file is listed with that rule. A listed file is the visible backlog; the PR that touches it
# brings it into shape and drops its line (ADR-0046).
exempt() {
  [ -f "$RATCHET" ] || return 1
  awk -v p="$1" -v r="$2" '$1==p { for (i = 2; i <= NF; i++) if ($i == r) found = 1 } END { exit !found }' \
    <(sed -E 's/#.*//' "$RATCHET")
}
words() { tr -s '[:space:]' '\n' | grep -c .; }

# 1. ADR numbers unique
dupes=$(find docs/adr -name '[0-9][0-9][0-9][0-9]-*.md' -printf '%f\n' | cut -c1-4 | sort | uniq -d)
for n in $dupes; do err "duplicate ADR number $n: $(ls docs/adr/"$n"-* | tr '\n' ' ')"; done

required_sections=("Purpose" "Surfaces" "Behaviour" "Refusals" "Governing ADRs and invariants" \
                   "Seams and proof" "Out of scope" "Open questions" "Retired")
# The two-layer shape: these sections, in this order, and no others except Designed.
v2_sections=("Purpose" "Surfaces" "Behaviour" "Refusals" "Out of scope" "Proof" "Retired")
declare -A prefix_owner=()

# Print the body of one "## Heading" section (up to the next "## ").
section() { awk -v h="## $2" '$0==h{f=1;next} /^## /{f=0} f' "$1"; }

# Print a spec's proof rows: the "### What proves each claim" table in the earlier shape, or
# the generated block between the proof markers in the two-layer shape.
proof_rows() {
  awk '/^### What proves each claim/{f=1;next} /^###? /{f=0} f && /^\|/' "$1"
  awk '/^<!-- proof:begin -->$/{f=1;next} /^<!-- proof:end -->$/{f=0} f && /^\|/' "$1"
}
v2_shape() { grep -qxF '## Proof' "$1"; }
# Lines outside the generated Proof block.
own_lines() { awk '/^<!-- proof:begin -->$/{s=1} !s{n++} /^<!-- proof:end -->$/{s=0} END{print n+0}' "$1"; }

# The names a proof row may cite as Rust evidence, computed once: every fn declared under a
# #[test] or #[tokio::test] attribute in daemon/ (other attributes, doc comments and blank lines
# may sit between the two; build output under target/ is not source), plus every cargo-fuzz
# target, whose name is its [[bin]] name rather than a fn.
rust_evidence=$(
  find daemon -name target -prune -o -name '*.rs' -type f -print 2>/dev/null | sort | while IFS= read -r f; do
    awk '
      FNR == 1 { t = 0 }
      /^[[:space:]]*#\[(tokio::)?test(\]|\()/ { t = 1; next }
      t && /^[[:space:]]*(#\[|\/\/|$)/ { next }
      t && match($0, /^[[:space:]]*(pub(\([a-z]+\))?[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/) {
        s = substr($0, RSTART, RLENGTH); sub(/.*fn[[:space:]]+/, "", s); print s
      }
      { t = 0 }' "$f"
  done
  [ -f daemon/fuzz/Cargo.toml ] && awk '
    /^\[\[bin\]\]/ { b = 1; next }
    /^\[/ { b = 0 }
    b && /^[[:space:]]*name[[:space:]]*=/ { s = $0; sub(/^[^"]*"/, "", s); sub(/".*/, "", s); print s }' daemon/fuzz/Cargo.toml
)

for spec in "$SPEC_DIR"/*.md; do
  case "$spec" in */README.md|*/TEMPLATE.md) continue;; esac
  name=$(basename "$spec")

  # 2. Cited tests exist
  for t in $(grep -oE '`(Test|Benchmark|Fuzz)[A-Za-z0-9_]+`' "$spec" | tr -d '`' | sort -u); do
    grep -rqF "func $t(" --include='*_test.go' . || grep -rqE "fn $t\(" --include='*.rs' . \
      || err "$name cites $t, which does not exist"
  done
  # 2b. Rust tests and fuzz targets a proof row cites exist. A `path::` qualifier is dropped:
  # the fn name is what must resolve. Matched through a here-string, never `printf | grep -q`
  # (see 3h).
  for t in $(proof_rows "$spec" | grep -oE '`([a-z][a-z0-9_]*::)*[a-z][a-z0-9]*(_[a-z0-9]+)+`' \
             | tr -d '`' | sed 's/.*:://' | sort -u); do
    grep -qxF "$t" <<<"$rust_evidence" \
      || err "$name: a proof row cites $t, which is neither a Rust test (#[test]/#[tokio::test] fn in daemon/) nor a cargo-fuzz target — a snake_case name in a proof row is read as one"
  done

  status=$(grep -m1 -E '^\*\*Status:\*\*' "$spec" | sed -E 's/^\*\*Status:\*\* *//')
  case "$status" in
    aspirational*|stub*) continue ;;                       # legacy: unmigrated, not enforced
    "current as of "*|"designed, not built, as of "*) ;;
    *) err "$name: Status must be 'current as of <date>', 'designed, not built, as of <date>', 'aspirational — …' or 'stub — …' (got: ${status:-none})"; continue ;;
  esac
  echo "$status" | grep -qE '`?[0-9]{4}-[0-9]{2}-[0-9]{2}`?\.?$' || err "$name: Status carries no ISO date"

  # 3a. Declared prefix, unique across specs
  prefix=$(grep -m1 -oE '^\*\*Claim prefix:\*\* *`[A-Z]{2,3}`' "$spec" | grep -oE '[A-Z]{2,3}')
  if [ -z "$prefix" ]; then err "$name: migrated spec declares no **Claim prefix:** \`XX\`"; continue; fi
  if [ -n "${prefix_owner[$prefix]:-}" ]; then err "$name: claim prefix $prefix already used by ${prefix_owner[$prefix]}"; fi
  prefix_owner[$prefix]=$name

  # 3b / 4. Required sections, by shape. A spec with a `## Proof` section is in the two-layer
  # shape (ADR-0046): the template's sections and nothing else, a Governed by line, a short
  # Purpose, a length budget, and a Proof block that matches the generator. Anything else is
  # the earlier shape, allowed only while the ratchet lists it.
  if v2_shape "$spec"; then
    for sec in "${v2_sections[@]}"; do
      grep -qxF "## $sec" "$spec" || err "$name: missing section '## $sec'"
    done
    while IFS= read -r sec; do
      case "$sec" in Purpose|Surfaces|Behaviour|Refusals|"Designed, not built"|"Out of scope"|Proof|Retired) ;;
        *) err "$name: section '## $sec' has no place in the two-layer shape (docs/specs/TEMPLATE.md)";; esac
    done < <(grep -oE '^## .*' "$spec" | sed 's/^## //')
    grep -qE '^\*\*Governed by:\*\* ' "$spec" || err "$name: no **Governed by:** line naming its ADRs and invariants"
    pw=$(section "$spec" Purpose | words)
    [ "$pw" -le 120 ] || err "$name: Purpose is $pw words; the plain top is at most 120"
    ol=$(own_lines "$spec")
    [ "$ol" -le 250 ] || exempt "$spec" budget || err "$name: $ol lines outside the Proof block; the budget is 250"
    if grep -qxF '<!-- proof:begin -->' "$spec" && grep -qxF '<!-- proof:end -->' "$spec"; then
      if ! diff -q <(awk '/^<!-- proof:begin -->$/{f=1} f; /^<!-- proof:end -->$/{f=0}' "$spec") \
                   <(scripts/spec-proof.sh "$spec") >/dev/null; then
        err "$name: the Proof block is stale; run make spec-proof"
      fi
    else
      err "$name: ## Proof has no <!-- proof:begin --> / <!-- proof:end --> markers"
    fi
  else
    for sec in "${required_sections[@]}"; do
      grep -qxF "## $sec" "$spec" || err "$name: missing section '## $sec'"
    done
    exempt "$spec" shape || err "$name: is in the earlier spec shape and not listed with 'shape' in $RATCHET; migrate it to docs/specs/TEMPLATE.md or list it"
  fi

  # 3c. Every ID in the file uses the declared prefix
  # ADR-NNNN, SHA-256, RFC-NNNN and MCP SEP-NNNN are citations, not claim IDs.
  foreign=$(grep -oE '\b[A-Z]{2,3}-[0-9]+\b' "$spec" | grep -vE "^($prefix|ADR|SHA|RFC|SEP)-" | sort -u | tr '\n' ' ')
  [ -z "$foreign" ] || err "$name: claim IDs with a foreign prefix: $foreign"

  # 3d. Definitions: bold IDs in Behaviour/Refusals, first cell of Designed rows. Each once.
  current_ids=$( { section "$spec" Behaviour; section "$spec" Refusals; } | grep -oE "\*\*$prefix-[0-9]+\*\*" | tr -d '*')
  designed_ids=$(section "$spec" "Designed, not built" | grep -E "^\| *$prefix-[0-9]+ *\|" | awk -F'|' '{gsub(/ /,"",$2); print $2}')
  dup=$(printf '%s\n%s\n' "$current_ids" "$designed_ids" | grep . | sort | uniq -d | tr '\n' ' ')
  [ -z "$dup" ] || err "$name: claim defined more than once: $dup"
  [ -n "$current_ids" ] || err "$name: Behaviour/Refusals define no **$prefix-n** claims"

  # 3e. Proof rows cite defined, current claims
  proof_ids=$(awk '/^### What proves each claim/{f=1;next} /^###? /{f=0} f' "$spec" \
              | grep -E "^\| *$prefix-[0-9]+ *\|" | awk -F'|' '{gsub(/ /,"",$2); print $2}')
  for id in $proof_ids; do
    grep -qx "$id" <<<"$(printf '%s\n' $current_ids)" || {
      if grep -qx "$id" <<<"$(printf '%s\n' $designed_ids)"; then err "$name: proof row cites $id, which is still Designed, not built"
      else err "$name: proof row cites $id, which no claim defines"; fi; }
  done

  # 3f. Designed rows carry a milestone; Status agrees with the table
  while IFS='|' read -r _ id _ milestone _; do
    id=$(echo "$id" | tr -d ' '); milestone=$(echo "$milestone" | sed -E 's/^ +| +$//g')
    [ -n "$milestone" ] || err "$name: Designed claim $id names no milestone"
  done < <(section "$spec" "Designed, not built" | grep -E "^\| *$prefix-[0-9]+ *\|")
  if [ -n "$designed_ids" ]; then
    case "$status" in current*) err "$name: Status is 'current' but Designed, not built has rows";; esac
  else
    case "$status" in designed*) err "$name: Status is 'designed, not built' but Designed, not built has no rows";; esac
  fi

  # 3h. IDs are never reused: every gap below the highest defined ID is listed under Retired,
  # and nothing listed there is still defined.
  retired_ids=$(section "$spec" Retired | grep -oE "\*\*$prefix-[0-9]+\*\*" | tr -d '*')
  max=$(printf '%s\n' $current_ids $designed_ids | grep . | cut -d- -f2 | sort -n | tail -1)
  # The ID lists are matched through a here-string, never `printf | grep -q`: under pipefail,
  # grep -q exits on its first match while printf may still be writing, printf dies of
  # SIGPIPE, and the pipeline fails although the ID was found — a false "neither defined
  # nor listed" that only fires when the scheduler loses the race (seen in CI on #809).
  all_ids=$(printf '%s\n' $current_ids $designed_ids $retired_ids)
  live_ids=$(printf '%s\n' $current_ids $designed_ids)
  for i in $(seq 1 "${max:-0}"); do
    grep -qx "$prefix-$i" <<<"$all_ids" \
      || err "$name: $prefix-$i is neither defined nor listed under ## Retired"
  done
  for id in $retired_ids; do
    grep -qx "$id" <<<"$live_ids" && err "$name: $id is listed under ## Retired but still defined"
  done

  # 3g. Every `<name>.md` mentioned resolves to a spec or a known root doc
  for ref in $(grep -oE '`[a-z0-9-]+\.md`' "$spec" | tr -d '`' | sort -u); do
    [ -f "$SPEC_DIR/$ref" ] || [ -f "$ref" ] || [ -f "docs/$ref" ] || err "$name: mentions $ref, which does not exist"
  done
done

# 4. ADRs: a plain top, a length budget, at most one amendment (ADR-0046). Each rule is waived
# per file by the ratchet, which is the visible backlog of ADRs still in the earlier shape.
for f in "$ADR_DIR"/[0-9][0-9][0-9][0-9]-*.md; do
  [ -f "$f" ] || continue
  n=$(wc -l < "$f")
  [ "$n" -le 150 ] || exempt "$f" budget || err "$f: $n lines; an ADR is at most 150 (rewrite it, or list it with 'budget' in $RATCHET)"
  a=$(grep -c '^## Amendment' "$f")
  [ "$a" -le 1 ] || exempt "$f" amendments || err "$f: $a amendment sections; an ADR is amended at most once and then rewritten"
  if ! exempt "$f" decision; then
    first=$(grep -m1 -E '^## ' "$f")
    [ "$first" = "## Decision" ] || err "$f: the first section must be '## Decision' (got: ${first:-none})"
    dw=$(section "$f" Decision | words)
    [ "$dw" -le 120 ] || err "$f: Decision is $dw words; the plain top is at most 120"
  fi
done
# Every path the ratchet names exists, so a line does not outlive its file.
if [ -f "$RATCHET" ]; then
  for p in $(sed -E 's/#.*//' "$RATCHET" | awk 'NF {print $1}'); do
    [ -e "$p" ] || err "$RATCHET lists $p, which does not exist; drop the line"
  done
fi

# 5. Proposals: the shape docs/proposals/TEMPLATE.md describes, and never cited as authority.
for p in "$PROPOSAL_DIR"/*.md; do
  [ -f "$p" ] || continue
  case "$p" in */README.md|*/TEMPLATE.md) continue;; esac
  pn=$(basename "$p")
  st=$(awk 'NR==3' "$p" | grep -oE '^\*\*Status:\*\* (idea|shaping|accepted|rejected)\b' | awk '{print $2}')
  [ -n "$st" ] || err "$pn: line 3 must be '**Status:** idea|shaping|accepted|rejected (<date>). Origin: …'"
  for sec in Problem Proposal Changes Objections; do
    grep -qxF "## $sec" "$p" || err "$pn: missing section '## $sec'"
  done
  case "$st" in
    accepted|rejected)
      grep -qxF "## Outcome" "$p" || err "$pn: status is $st and there is no '## Outcome'"
      if [ "$st" = accepted ]; then
        section "$p" Outcome | grep -qE 'ADR-[0-9]{4}|\b[A-Z]{2,3}-[0-9]+\b' \
          || err "$pn: accepted, and Outcome names neither an ADR nor a claim ID"
      fi ;;
  esac
  n=$(wc -l < "$p")
  [ "$n" -le 120 ] || err "$pn: $n lines; a proposal is at most 120"
done
# A claim never cites a proposal: a bullet claim or a Designed row that mentions the directory.
# (Process substitution, not a pipe into `while`: err must set fail in this shell.)
for spec in "$SPEC_DIR"/*.md; do
  case "$spec" in */README.md|*/TEMPLATE.md) continue;; esac
  while IFS=: read -r ln _; do
    err "$(basename "$spec"):$ln: a claim cites a proposal, which never binds (ADR-0046)"
  done < <(grep -nE '^(- \*\*[A-Z]{2,3}-[0-9]+\*\*|\| *[A-Z]{2,3}-[0-9]+ *\|).*proposals/' "$spec")
done
# Nor does shipped code: a proposal is not a reason.
for d in relay daemon; do
  [ -d "$d" ] || continue
  while IFS=: read -r file ln _; do
    err "$file:$ln: cites docs/proposals/, which never binds; cite the ADR or the spec claim"
  done < <(grep -rnIE 'docs/proposals' "$d" --include='*.go' --include='*.rs' --exclude='*.pb.go' --exclude-dir=target 2>/dev/null)
done

[ "$fail" -eq 0 ] && echo "check-docs: ADR numbers unique; every cited test exists; migrated specs, ADRs and proposals are well-formed."
exit "$fail"
