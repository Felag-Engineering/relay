#!/usr/bin/env bash
# The pull-request govulncheck gate (ci.yml: the relay job, on deps=; `make vuln-relay-gate`).
#
# Fails when the Relay's code reaches a known vulnerability (govulncheck's symbol-level
# findings: a call path from this code into the vulnerable function) that is not listed in
# relay/govulncheck-exceptions.txt — and when an exception is listed that the scan no longer
# reports, so the list cannot quietly outlive the reason for it.
#
# Why exceptions exist at all: a vulnerability already on main (a Go toolchain patch release
# not yet adopted, a module with no released fix) would otherwise turn every dependency PR
# red, Dependabot's included, on a finding none of them introduced. An exception is the
# reviewed, visible alternative: the file is on the security surface, each line names its
# tracking reference, and a new finding still fails. The nightly scan (`make vuln-relay`)
# reports everything, excepted or not.
#
# Fails CLOSED: govulncheck erroring, or output with no scan configuration in it, fails.
#
# Usage: vuln-gate.sh               run govulncheck over relay/ (needs network)
#        vuln-gate.sh <json-file>   judge a captured `govulncheck -format json` stream (tests)
# VULN_EXCEPTIONS overrides the exceptions file (tests).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

exceptions="${VULN_EXCEPTIONS:-relay/govulncheck-exceptions.txt}"

if [ $# -gt 0 ]; then
  json="$(cat "$1")" || { echo "vuln-gate: cannot read $1" >&2; exit 1; }
else
  # -format json exits 0 whatever it finds; a non-zero exit is the scan itself failing.
  json="$(cd relay && govulncheck -format json ./...)"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "vuln-gate: govulncheck failed (exit $rc); refusing to report a clean scan" >&2
    exit 1
  fi
fi

if ! jq -e -s 'any(.[]; has("config"))' <<<"$json" >/dev/null 2>&1; then
  echo "vuln-gate: no govulncheck scan configuration in the output; refusing to report a clean scan" >&2
  exit 1
fi

# Symbol-level findings only: the first trace frame names a function this code calls.
reached="$(jq -r -s '[.[] | select(has("finding")) | .finding
  | select((.trace[0].function // "") != "") | .osv] | unique | .[]' <<<"$json")"
listed="$(grep -oE '^GO-[0-9]{4}-[0-9]+' "$exceptions" 2>/dev/null | sort -u)"

summary() {
  jq -r -s --arg id "$1" 'first(.[] | select(.osv.id? == $id) | .osv.summary) // "(no summary)"' <<<"$json"
}

fail=0
while IFS= read -r id; do
  [ -n "$id" ] || continue
  if grep -qxF -- "$id" <<<"$listed"; then
    echo "vuln-gate: EXCEPTED $id — $(summary "$id") (see $exceptions)"
  else
    echo "vuln-gate: FAIL $id — $(summary "$id"): reached from this code and not excepted" >&2
    fail=1
  fi
done <<<"$reached"

while IFS= read -r id; do
  [ -n "$id" ] || continue
  if ! grep -qxF -- "$id" <<<"$reached"; then
    echo "vuln-gate: FAIL stale exception $id — no longer reported; delete its line from $exceptions" >&2
    fail=1
  fi
done <<<"$listed"

if [ "$fail" -eq 0 ]; then
  echo "vuln-gate: no unexcepted vulnerability is reachable from the Relay's code"
fi
exit "$fail"
