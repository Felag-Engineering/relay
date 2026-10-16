#!/usr/bin/env bash
# Proves scripts/license-change-date.sh accepts a Change Date three to four years after the
# release and refuses one outside that window, a malformed one and a missing one, and that
# --warn downgrades only the window check. Hermetic: bash and GNU date, no network, no writes
# outside its own `mktemp -d`.
#
# NOT `set -e`: every case must run and be reported, not stop at the first failure.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
GATE="$REPO_ROOT/scripts/license-change-date.sh"
WORKDIR="$(mktemp -d)" || { echo "FAIL: mktemp -d failed" >&2; exit 1; }
trap 'case "${WORKDIR:-}" in /*) rm -rf "$WORKDIR" ;; esac' EXIT

fail=0
n=0

license_with() {
  printf 'Licensor:             Felag Engineering\nChange Date:          %s\nChange License:       Apache License, Version 2.0\n' "$1" >"$WORKDIR/LICENSE"
}

# expect <name> <want-rc> <grep-pattern-in-output> -- args...
expect() {
  local name=$1 want=$2 pattern=$3; shift 4
  local out rc
  out=$(bash "$GATE" "$@" 2>&1); rc=$?
  n=$((n + 1))
  if [ "$rc" -ne "$want" ]; then
    echo "FAIL: $name: rc=$rc want=$want: $out" >&2; fail=$((fail + 1)); return
  fi
  if ! grep -q -- "$pattern" <<<"$out"; then
    echo "FAIL: $name: output lacks '$pattern': $out" >&2; fail=$((fail + 1))
  fi
}

license_with 2029-10-15
expect "exactly three years"      0 "ok"            -- 2026-10-15 "$WORKDIR/LICENSE"
expect "within the 7-day slack"   0 "ok"            -- 2026-10-20 "$WORKDIR/LICENSE"
expect "stale: release a year on" 1 "less than three years" -- 2027-10-15 "$WORKDIR/LICENSE"
expect "stale under --warn"       0 "::warning::"   -- --warn 2027-10-15 "$WORKDIR/LICENSE"
expect "past the four-year cap"   1 "four-year limit" -- 2025-10-14 "$WORKDIR/LICENSE"
expect "bad release date"         2 "not YYYY-MM-DD" -- 2026-13-40 "$WORKDIR/LICENSE"

license_with 2029-02-30
expect "impossible Change Date"   2 "no YYYY-MM-DD"  -- 2026-10-15 "$WORKDIR/LICENSE"
expect "malformed under --warn"   2 "no YYYY-MM-DD"  -- --warn 2026-10-15 "$WORKDIR/LICENSE"

printf 'Licensor: Felag Engineering\n' >"$WORKDIR/LICENSE"
expect "no Change Date line"      2 "no YYYY-MM-DD"  -- 2026-10-15 "$WORKDIR/LICENSE"

# The committed LICENSE parses: whatever its date, the gate reads it and does not exit 2.
out=$(bash "$GATE" --warn "$(date -u +%F)" "$REPO_ROOT/LICENSE" 2>&1); rc=$?
n=$((n + 1))
[ "$rc" -eq 0 ] || { echo "FAIL: committed LICENSE does not parse: rc=$rc: $out" >&2; fail=$((fail + 1)); }

if [ "$fail" -ne 0 ]; then
  echo "license-change-date-test: $fail of $n case(s) failed" >&2
  exit 1
fi
echo "PASS: license-change-date.sh accepts a Change Date 3-4 years after the release, refuses a stale, over-long, malformed or missing one, and --warn downgrades only the window ($n cases)."
