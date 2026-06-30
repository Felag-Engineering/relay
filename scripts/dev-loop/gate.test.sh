#!/usr/bin/env bash
# scripts/dev-loop/gate.test.sh — unit tests for the deterministic merge gate.
# The gate is the security-load-bearing piece; it must keep behaving exactly.

set -euo pipefail
DEV_LOOP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$DEV_LOOP_DIR/gate.sh"
pass=0; fail=0

# check <name> <expected AUTO|ESCALATE> <files> <added> <build-ok> [review-json]
check() {
  local name="$1" want="$2" files="$3" added="$4" bok="$5" review="${6:-}"
  local args=(--files - --added "$added" --build-ok "$bok") rf=""
  if [[ -n "$review" ]]; then
    rf="$(mktemp)"; printf '%s' "$review" >"$rf"; args+=(--review "$rf")
  fi
  local got; got="$(printf '%s\n' "$files" | "$GATE" "${args[@]}" | jq -r .decision)"
  [[ -n "$rf" ]] && rm -f "$rf"
  if [[ "$got" == "$want" ]]; then
    printf '  ok   %-45s → %s\n' "$name" "$got"; (( pass++ )) || true
  else
    printf '  FAIL %-45s → got %s, want %s\n' "$name" "$got" "$want"; (( fail++ )) || true
  fi
}

echo "gate.sh unit tests:"
check "clean non-security, small, green"  AUTO     "relay/internal/registry/store.go" 120 1
check "proto change"                      ESCALATE "proto/relay.proto"                 30 1
check "daemon Policy code"                ESCALATE "daemon/src/policy/engine.rs"       50 1
check "exec path"                         ESCALATE "daemon/src/ops/exec.rs"            40 1
check "mTLS / cert code"                  ESCALATE "relay/internal/ca/cert.go"         60 1
check "enrollment / auth"                 ESCALATE "relay/internal/enroll/token.go"    25 1
check "ADR added"                         ESCALATE "docs/adr/0009-foo.md"              80 1
check "CLAUDE.md edited"                  ESCALATE "CLAUDE.md"                          5 1
check "loop self-modification"            ESCALATE "scripts/dev-loop/gate.sh"          5 1
check "build red (non-security)"          ESCALATE "relay/internal/log/log.go"        10 0
check "oversized diff"                    ESCALATE "relay/internal/foo.go"           999 1
check "review high severity"              ESCALATE "relay/internal/foo.go"            10 1 '{"max_severity":"high"}'
check "review medium severity"            AUTO     "relay/internal/foo.go"            10 1 '{"max_severity":"medium"}'
check "no files (anomaly)"                ESCALATE ""                                   0 1

echo "—— $pass passed, $fail failed ——"
[[ "$fail" -eq 0 ]]
