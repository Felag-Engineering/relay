#!/usr/bin/env bash
# Proves scripts/vuln-gate.sh judges a govulncheck JSON stream the way its header claims:
# a reachable (symbol-level) finding fails unless excepted; package- and module-level
# findings do not count; an exception the scan no longer reports fails; and output that is
# not a completed scan fails closed.
#
# Hermetic: bash and jq, fixture streams only — no govulncheck, no network. Writes nothing
# outside its own `mktemp -d`.
#
# NOT `set -e`: every case must run and be reported (security-surface-test.sh:12).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
WORKDIR="$(mktemp -d)" || { echo "FAIL: mktemp -d failed" >&2; exit 1; }
trap 'case "${WORKDIR:-}" in /*) rm -rf "$WORKDIR" ;; esac' EXIT
case "$WORKDIR" in
  /*) ;;
  *) echo "FAIL: mktemp returned a non-absolute path: '$WORKDIR'" >&2; exit 1 ;;
esac

fail=0
GATE="$REPO_ROOT/scripts/vuln-gate.sh"

CONFIG='{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck"}}'
OSV_A='{"osv":{"id":"GO-2026-0001","summary":"reached vuln A"}}'
OSV_B='{"osv":{"id":"GO-2026-0002","summary":"imported-only vuln B"}}'
# A symbol-level finding: the first frame names a function.
REACHED_A='{"finding":{"osv":"GO-2026-0001","fixed_version":"v1.2.3","trace":[{"module":"example.com/m","version":"v1.2.2","package":"example.com/m/p","function":"Vuln"},{"module":"relay","package":"relay/cmd","function":"main"}]}}'
# Package- and module-level findings: imported or required, never called.
PKG_B='{"finding":{"osv":"GO-2026-0002","trace":[{"module":"example.com/n","version":"v0.1.0","package":"example.com/n/q"}]}}'
MOD_B='{"finding":{"osv":"GO-2026-0002","trace":[{"module":"example.com/n","version":"v0.1.0"}]}}'

# stream <name> <json line>...: one fixture file, one message per line, as govulncheck writes.
stream() {
  local f="$WORKDIR/$1.json"
  shift
  printf '%s\n' "$@" >"$f"
  printf '%s\n' "$f"
}
exceptions() {
  local f="$WORKDIR/$1.exceptions"
  shift
  printf '%s\n' "# header comment" "$@" >"$f"
  printf '%s\n' "$f"
}

# expect <case> <want rc: 0|1> <stream file> <exceptions file>
expect() {
  local out rc
  out="$(VULN_EXCEPTIONS="$4" bash "$GATE" "$3" 2>&1)"
  rc=$?
  if [ "$rc" -ne "$2" ]; then
    echo "FAIL: $1: got rc=$rc, want rc=$2. Output:" >&2
    sed 's/^/    /' <<<"$out" >&2
    fail=$((fail + 1))
  fi
}

NONE="$(exceptions none)"
EXC_A="$(exceptions exc-a "GO-2026-0001  #1  accepted for the test")"
EXC_AB="$(exceptions exc-ab "GO-2026-0001  #1  reached" "GO-2026-0002  #2  never reached")"

expect "clean scan" 0 "$(stream clean "$CONFIG")" "$NONE"
expect "reached and not excepted" 1 "$(stream reached "$CONFIG" "$OSV_A" "$REACHED_A")" "$NONE"
expect "reached and excepted" 0 "$(stream reached-exc "$CONFIG" "$OSV_A" "$REACHED_A")" "$EXC_A"
expect "package- and module-level findings only" 0 \
  "$(stream imported "$CONFIG" "$OSV_B" "$PKG_B" "$MOD_B")" "$NONE"
# GO-2026-0002 is only imported, so its exception is stale: the list must not outlive it.
expect "stale exception for an imported-only finding" 1 \
  "$(stream stale "$CONFIG" "$OSV_A" "$REACHED_A" "$OSV_B" "$PKG_B")" "$EXC_AB"
expect "stale exception on a clean scan" 1 "$(stream stale-clean "$CONFIG")" "$EXC_A"
# Fail closed: no config message means the scan did not complete.
expect "no scan configuration" 1 "$(stream noconfig "$OSV_A")" "$NONE"
expect "empty output" 1 "$(stream empty "")" "$NONE"
expect "not JSON" 1 "$(stream garbage "govulncheck: fetching vulnerabilities: Forbidden")" "$NONE"
# A missing exceptions file is an empty list, not an error: a reached finding still fails.
expect "missing exceptions file" 1 "$(stream reached2 "$CONFIG" "$OSV_A" "$REACHED_A")" "$WORKDIR/absent"

if [ "$fail" -ne 0 ]; then
  echo "FAIL: $fail case(s) failed" >&2
  exit 1
fi
echo "PASS: vuln-gate.sh fails on reachable unexcepted findings and on stale exceptions, ignores imported-only findings, and fails closed when the scan did not complete."
