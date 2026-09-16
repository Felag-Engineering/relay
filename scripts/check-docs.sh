#!/usr/bin/env bash
# Documentation invariants that CI enforces on every PR. Fast, no toolchain: shell + grep + awk.
#
#   1. ADR numbers are unique.
#   2. Every test a spec cites exists.
#   3. A migrated spec (Status current/designed) has the claim shape docs/specs/TEMPLATE.md
#      describes: a declared prefix, unique across specs; every claim ID uses it and is defined
#      once; proof rows cite defined Behaviour/Refusals claims; Designed rows carry a milestone;
#      Status agrees with whether Designed has rows; the required sections exist; every
#      `<name>.md` a spec mentions resolves.
#
# Legacy specs (Status aspirational/stub) get checks 1 and 2 only — they are unmigrated intent,
# see "The establishing phase" in docs/specs/README.md. SPEC_DIR overrides the directory for
# self-tests.
set -uo pipefail
cd "$(dirname "$0")/.."
SPEC_DIR=${SPEC_DIR:-docs/specs}
fail=0
err() { echo "check-docs: $*" >&2; fail=1; }

# 1. ADR numbers unique
dupes=$(find docs/adr -name '[0-9][0-9][0-9][0-9]-*.md' -printf '%f\n' | cut -c1-4 | sort | uniq -d)
for n in $dupes; do err "duplicate ADR number $n: $(ls docs/adr/"$n"-* | tr '\n' ' ')"; done

required_sections=("Purpose" "Surfaces" "Behaviour" "Refusals" "Governing ADRs and invariants" \
                   "Seams and proof" "Out of scope" "Open questions" "History")
declare -A prefix_owner=()

# Print the body of one "## Heading" section (up to the next "## ").
section() { awk -v h="## $2" '$0==h{f=1;next} /^## /{f=0} f' "$1"; }

for spec in "$SPEC_DIR"/*.md; do
  case "$spec" in */README.md|*/TEMPLATE.md) continue;; esac
  name=$(basename "$spec")

  # 2. Cited tests exist
  for t in $(grep -oE '`(Test|Benchmark)[A-Za-z0-9_]+`' "$spec" | tr -d '`' | sort -u); do
    grep -rqF "func $t(" --include='*_test.go' . || grep -rqE "fn $t\(" --include='*.rs' . \
      || err "$name cites $t, which does not exist"
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

  # 3b. Required sections
  for sec in "${required_sections[@]}"; do
    grep -qxF "## $sec" "$spec" || err "$name: missing section '## $sec'"
  done

  # 3c. Every ID in the file uses the declared prefix
  foreign=$(grep -oE '\b[A-Z]{2,3}-[0-9]+\b' "$spec" | grep -vE "^$prefix-" | sort -u | tr '\n' ' ')
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
    printf '%s\n' $current_ids | grep -qx "$id" || {
      if printf '%s\n' $designed_ids | grep -qx "$id"; then err "$name: proof row cites $id, which is still Designed, not built"
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

  # 3g. Every `<name>.md` mentioned resolves to a spec or a known root doc
  for ref in $(grep -oE '`[a-z0-9-]+\.md`' "$spec" | tr -d '`' | sort -u); do
    [ -f "$SPEC_DIR/$ref" ] || [ -f "$ref" ] || [ -f "docs/$ref" ] || err "$name: mentions $ref, which does not exist"
  done
done

[ "$fail" -eq 0 ] && echo "check-docs: ADR numbers unique; every cited test exists; migrated specs are well-formed."
exit "$fail"
