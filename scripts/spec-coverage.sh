#!/usr/bin/env bash
# Reverse drift, the mechanical half: which of the code's enumerable surfaces does no
# capability spec mention? Printed as a report, never a failure — an unmentioned surface is
# either a missing claim or dead weight, and a human decides which (docs/agents/workflow.md).
# Also prints the three numbers the migration tracks: legacy specs, proof rows, packages.
#
#   scripts/spec-coverage.sh            full report
#   scripts/spec-coverage.sh --summary  the three numbers only
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
SPECS=(docs/specs/*.md)
mentioned() { grep -qF -- "$1" "${SPECS[@]}"; }

if [ "${1:-}" != "--summary" ]; then
  echo "SPEC COVERAGE — surfaces in the code that no spec names"
  echo

  echo "## MCP tools"
  n=0; m=0
  for t in $(grep -rhoE 'Name:\s*"[a-z_]+"' relay/internal/controlplane/mcp/*.go | grep -oE '"[a-z_]+"' | tr -d '"' | sort -u); do
    n=$((n+1)); mentioned "$t" || { m=$((m+1)); echo "  - $t"; }
  done; echo "  ($m of $n unmentioned)"; echo

  echo "## Control API paths  (a path counts as mentioned if the spec names it with or without its {id} segments)"
  n=0; m=0
  for p in $(grep -oE '^  /[a-zA-Z0-9/{}_-]+:' docs/api/openapi.yaml | tr -d ' :' | sort -u); do
    n=$((n+1)); k=$(echo "$p" | sed -E 's#\{[^}]+\}##g; s#/+#/#g; s#/$##')
    mentioned "$p" || mentioned "$k" || { m=$((m+1)); echo "  - $p"; }
  done; echo "  ($m of $n unmentioned)"; echo

  echo "## Console routes  (docs/design/console/ counts until console.md exists)"
  # Routes are not mux.HandleFunc calls: console.go registers them from a table of
  # {"METHOD", "/console/...", ...} entries (Register, via r.Pattern()), so read the table.
  n=0; m=0
  while IFS=' ' read -r method r; do
    [ -n "$r" ] || continue
    n=$((n+1)); k=$(echo "$r" | sed -E 's#\{[^}]+\}##g; s#/+#/#g; s#/$##')
    grep -qF -- "$k" "${SPECS[@]}" docs/design/console/*.md || { m=$((m+1)); echo "  - $method $r"; }
  done < <(find relay/internal/controlplane/console -maxdepth 1 -name '*.go' ! -name '*_test.go' \
             -exec grep -hoE '\{"(GET|POST)", "/console[^"]*"' {} + \
           | sed -E 's/^\{"([A-Z]+)", "([^"]*)"$/\1 \2/' | sort -u)
  echo "  ($m of $n unmentioned)"; echo

  echo "## Audit record kinds"
  n=0; m=0
  for k in $(grep -rhoE 'Kind[A-Za-z]+\s*=\s*"[a-z_.]+"' relay/internal/audit/*.go | grep -oE '"[a-z_.]+"' | tr -d '"' | sort -u); do
    n=$((n+1)); mentioned "\`$k\`" || mentioned "$k" || { m=$((m+1)); echo "  - $k"; }
  done; echo "  ($m of $n unmentioned)"; echo

  echo "## Relay settings (RELAY_* in main.go and the packaging example)"
  n=0; m=0
  for e in $(grep -rhoE 'RELAY_[A-Z0-9_]+' relay/cmd/relay/main.go relay/packaging/relay.env.example | sort -u); do
    n=$((n+1)); mentioned "$e" || { m=$((m+1)); echo "  - $e"; }
  done; echo "  ($m of $n unmentioned)"; echo

  echo "## Proto: RPCs and Operation names"
  n=0; m=0
  for r in $(grep -rhoE '^\s*rpc [A-Za-z]+' proto | awk '{print $2}' | sort -u) \
           $(grep -rhoE '^\s*(OPERATION|OP)_[A-Z_]+' proto | sed -E 's/^\s*//' | sort -u); do
    n=$((n+1)); mentioned "$r" || { m=$((m+1)); echo "  - $r"; }
  done; echo "  ($m of $n unmentioned)"; echo
fi

legacy=$(grep -lE '^\*\*Status:\*\* *(aspirational|stub)' "${SPECS[@]}" | wc -l)
total=$(find docs/specs -maxdepth 1 -name '*.md' ! -name 'README.md' ! -name 'TEMPLATE.md' | wc -l)
rows=$(grep -hcE '^\| .*\| *`(Test|Benchmark)[A-Za-z0-9_]+`' "${SPECS[@]}" | awk "{s+=\$1} END {print s+0}")
pkgs=$(find relay/internal -mindepth 1 -maxdepth 1 -type d | wc -l)
mods=$(ls daemon/src/*.rs daemon/crates/*/src/*.rs | wc -l)
echo "SUMMARY  legacy specs: $legacy of $total   proof rows: $rows   relay packages: $pkgs   daemon modules: $mods"
