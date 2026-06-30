#!/usr/bin/env bash
# End-to-end handshake smoke test: boot Relay + relay-daemon, assert Hello→Ping.
# Assumes 'make build' has already produced both binaries (or runs from make test-integration,
# which depends on build). Exits non-zero on any failed assertion or timeout.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELAY_BIN="${REPO_ROOT}/relay/bin/relay"
DAEMON_BIN="${REPO_ROOT}/daemon/target/debug/relay-daemon"
RELAY_ADDR="127.0.0.1:17654"
RELAY_URL="http://${RELAY_ADDR}"
STARTUP_TIMEOUT=10
DAEMON_WINDOW=5

relay_log=""
daemon_log=""
relay_pid=""

cleanup() {
    if [[ -n "${relay_pid}" ]]; then
        kill "${relay_pid}" 2>/dev/null || true
        wait "${relay_pid}" 2>/dev/null || true
    fi
    [[ -n "${relay_log}" ]] && rm -f "${relay_log}"
    [[ -n "${daemon_log}" ]] && rm -f "${daemon_log}"
}
trap cleanup EXIT

relay_log="$(mktemp)"
daemon_log="$(mktemp)"

if [[ ! -x "${RELAY_BIN}" ]]; then
    echo "ERROR: relay binary not found at ${RELAY_BIN}; run 'make build' first" >&2
    exit 1
fi
if [[ ! -x "${DAEMON_BIN}" ]]; then
    echo "ERROR: relay-daemon binary not found at ${DAEMON_BIN}; run 'make build' first" >&2
    exit 1
fi

echo "Starting Relay on ${RELAY_ADDR}..."
"${RELAY_BIN}" --addr "${RELAY_ADDR}" >"${relay_log}" 2>&1 &
relay_pid=$!

echo "Waiting for Relay to report listening (up to ${STARTUP_TIMEOUT}s)..."
deadline=$(( $(date +%s) + STARTUP_TIMEOUT ))
while ! grep -q "relay listening" "${relay_log}" 2>/dev/null; do
    if ! kill -0 "${relay_pid}" 2>/dev/null; then
        echo "ERROR: Relay process exited unexpectedly" >&2
        echo "--- relay log ---" >&2
        cat "${relay_log}" >&2
        exit 1
    fi
    if [[ "$(date +%s)" -ge "${deadline}" ]]; then
        echo "ERROR: Relay did not start within ${STARTUP_TIMEOUT}s" >&2
        echo "--- relay log ---" >&2
        cat "${relay_log}" >&2
        exit 1
    fi
    sleep 0.2
done
echo "Relay is listening."

echo "Running relay-daemon for ${DAEMON_WINDOW}s..."
timeout "${DAEMON_WINDOW}" "${DAEMON_BIN}" --relay "${RELAY_URL}" >"${daemon_log}" 2>&1 || true

echo "Asserting Relay received Hello (checking for node_id in relay log)..."
if ! grep -q "node_id" "${relay_log}"; then
    echo "FAIL: Relay log does not contain node_id — Hello not received" >&2
    echo "--- relay log ---" >&2
    cat "${relay_log}" >&2
    exit 1
fi

echo "Asserting relay-daemon received Ping (checking daemon log)..."
if ! grep -q "received Ping from Relay" "${daemon_log}"; then
    echo "FAIL: daemon log does not contain 'received Ping from Relay'" >&2
    echo "--- daemon log ---" >&2
    cat "${daemon_log}" >&2
    exit 1
fi

echo "PASS: Hello→Ping handshake confirmed."
