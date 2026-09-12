#!/usr/bin/env bash
# Documentation gates for `make verify`. Two checks, both cheap, both catching a
# class of drift that has actually happened in this repo:
#
#   1. ADR numbers are unique. Citation-by-number is the repo's whole scheme
#      (docs/adr/, CLAUDE.md's invariants, 220+ source comments). Two files once
#      claimed ADR-0015, making every bare citation to it ambiguous.
#   2. Every test a capability spec names in its proof table exists. A spec cites
#      tests by name deliberately (docs/specs/TEMPLATE.md); a rename during
#      ordinary refactoring would otherwise break the citation silently.
#
# What check 2 CANNOT do: verify that a named test still asserts the claim beside
# it. A test can be gutted and kept green. The template says so; this script only
# catches renames and deletions.
set -uo pipefail
cd "$(dirname "$0")/.."
fail=0

dupes=$(find docs/adr -name '[0-9][0-9][0-9][0-9]-*.md' -printf '%f\n' \
        | cut -c1-4 | sort | uniq -d)
if [ -n "$dupes" ]; then
  echo "check-docs: duplicate ADR numbers:" >&2
  for n in $dupes; do ls docs/adr/"$n"-* >&2; done
  fail=1
fi

missing=0
for spec in docs/specs/*.md; do
  case "$spec" in */README.md|*/TEMPLATE.md) continue;; esac
  # Backticked Go test identifiers cited anywhere in the spec.
  for t in $(grep -oE '`Test[A-Za-z0-9_]+`' "$spec" | tr -d '`' | sort -u); do
    if ! grep -rqF "func $t(" --include='*_test.go' .; then
      echo "check-docs: $spec cites $t, which does not exist" >&2
      missing=1
    fi
  done
done
[ "$missing" -eq 0 ] || fail=1

[ "$fail" -eq 0 ] && echo "check-docs: ADR numbers unique; every cited test exists."
exit "$fail"
