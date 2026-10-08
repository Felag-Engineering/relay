#!/usr/bin/env bash
# Proves the Makefile's dev-fleet guards (#893, carried over from #622's security review):
# demo-fault refuses an injected or globbed DEMO_FAULT_NODES before any compose call; the
# relay-demo-owner guard refuses a foreign checkout, a non-local engine and a failing
# `docker ps` before any compose call; and STATE_DIR/BASE never reach dev-fleet-mcp.sh.
#
# Hermetic: a stub `docker` on PATH, no Docker engine, no python. The stub appends every
# invocation to a log and dumps its environment on `compose cp` (the call dev-fleet-mcp.sh
# makes), so the script's environment is observed without replacing the script.
#
# The glob case does not prove `set -f` on its own: a glob expands to repo-root names, none
# of which is a web Node, so `set -f` is defence in depth that is not covered here.
#
# NOT `set -e`: every case must run and be reported.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)" || exit 1
WORK="$(mktemp -d)" || { echo "FAIL: mktemp -d failed" >&2; exit 1; }
trap 'case "${WORK:-}" in /*) rm -rf "$WORK" ;; esac' EXIT
mkdir "$WORK/bin" "$WORK/other"
LOG="$WORK/calls.log"

cat > "$WORK/bin/docker" <<'STUB'
#!/bin/sh
echo "docker $*" >> "$STUB_LOG"
case "$1" in
    context) echo "unix:///var/run/docker.sock" ;;
    ps) [ -z "${STUB_PS_FAIL:-}" ] || exit 1; printf '%s\n' "$STUB_PS_DIRS" ;;
    compose)
        case " $* " in
            *" cp "*) env | grep -E '^(BASE|STATE_DIR)=' >> "$STUB_LOG.env"; exit 1 ;;
            *" status "*) exit 3 ;;
        esac ;;
esac
exit 0
STUB
chmod +x "$WORK/bin/docker"

FAILS=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; FAILS=$((FAILS + 1)); }

# run_make <ps-dirs> <make args...>: runs make in the repo with the stub; rc in $RC.
run_make() {
    local dirs="$1"; shift
    : > "$LOG"; rm -f "$LOG.env"
    STUB_LOG="$LOG" STUB_PS_DIRS="$dirs" PATH="$WORK/bin:$PATH" \
        make -s -C "$REPO_ROOT" "$@" >"$WORK/out" 2>&1
    RC=$?
}
compose_calls() { grep -c '^docker compose' "$LOG"; }

# expect_refusal <name> <ps-dirs> <make args...>: non-zero, and no compose call at all.
expect_refusal() {
    local name="$1"; shift
    run_make "$@"
    if [ "$RC" -ne 0 ] && [ "$(compose_calls)" -eq 0 ]; then pass "$name"
    else fail "$name (rc=$RC, compose calls=$(compose_calls))"; fi
}

# Positive control: the stub setup lets a legitimate demo-fault reach compose, so the
# refusals below are the guards' doing and not a broken stub.
run_make "$REPO_ROOT" demo-fault DEMO_FAULT_NODES=daemon-4
if [ "$RC" -eq 0 ] && [ "$(compose_calls)" -gt 0 ]; then pass "demo-fault with a valid Node reaches compose"
else fail "demo-fault with a valid Node reaches compose (rc=$RC)"; fi

expect_refusal "demo-fault refuses a shell-metacharacter value" "$REPO_ROOT" \
    demo-fault "DEMO_FAULT_NODES=x;touch $WORK/PWN"
[ ! -e "$WORK/PWN" ] && pass "injected command did not run" || fail "injected command ran"
expect_refusal "demo-fault refuses a glob" "$REPO_ROOT" demo-fault 'DEMO_FAULT_NODES=*'
expect_refusal "demo-fault refuses a non-web Node" "$REPO_ROOT" demo-fault DEMO_FAULT_NODES=daemon-3
expect_refusal "demo-fault refuses an empty value" "$REPO_ROOT" demo-fault DEMO_FAULT_NODES=

# Positive control for the owner/engine guard: the checkout's own path, a unix engine and a
# working `docker ps` get through, so the refusals below are the guard's doing.
run_make "$REPO_ROOT" demo-down
if [ "$RC" -eq 0 ] && [ "$(compose_calls)" -gt 0 ]; then pass "owner guard admits the checkout's own path"
else fail "owner guard admits the checkout's own path (rc=$RC)"; fi

expect_refusal "owner guard refuses a foreign checkout" "$WORK/other" demo-down
expect_refusal "owner guard refuses a missing checkout" "$WORK/gone" demo-down

: > "$LOG"
DOCKER_HOST=tcp://attacker:2375 STUB_LOG="$LOG" STUB_PS_DIRS="$REPO_ROOT" PATH="$WORK/bin:$PATH" \
    make -s -C "$REPO_ROOT" demo-down >"$WORK/out" 2>&1
if [ $? -ne 0 ] && [ "$(compose_calls)" -eq 0 ]; then pass "owner guard refuses a tcp:// DOCKER_HOST"
else fail "owner guard refuses a tcp:// DOCKER_HOST"; fi

: > "$LOG"
STUB_PS_FAIL=1 STUB_LOG="$LOG" STUB_PS_DIRS="" PATH="$WORK/bin:$PATH" \
    make -s -C "$REPO_ROOT" demo-down >"$WORK/out" 2>&1
if [ $? -ne 0 ] && [ "$(compose_calls)" -eq 0 ]; then pass "owner guard refuses when docker ps fails"
else fail "owner guard refuses when docker ps fails"; fi

# The scrub: BASE/STATE_DIR set by the caller must not reach dev-fleet-mcp.sh. The script
# creates .dev-fleet/ before its first compose call; remove it if this run made it.
had_state=0; [ -e "$REPO_ROOT/.dev-fleet" ] && had_state=1
: > "$LOG"; rm -f "$LOG.env"
BASE=https://attacker.invalid STATE_DIR="$WORK/elsewhere" STUB_LOG="$LOG" STUB_PS_DIRS="$REPO_ROOT" \
    PATH="$WORK/bin:$PATH" make -s -C "$REPO_ROOT" dev-fleet-creds >"$WORK/out" 2>&1
[ "$had_state" -eq 1 ] || rm -rf "$REPO_ROOT/.dev-fleet"
if ! grep -q 'compose.* cp ' "$LOG"; then fail "dev-fleet-mcp.sh ran (positive control)"
elif [ -s "$LOG.env" ]; then fail "BASE/STATE_DIR leaked into dev-fleet-mcp.sh: $(cat "$LOG.env")"
else pass "BASE and STATE_DIR are scrubbed before dev-fleet-mcp.sh"; fi

if [ "$FAILS" -ne 0 ]; then echo "FAIL: $FAILS case(s) failed" >&2; exit 1; fi
echo "PASS: all dev-fleet Makefile guard cases"
