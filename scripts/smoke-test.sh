#!/usr/bin/env bash
# End-to-end mTLS-rejection smoke test: boot the (mTLS-required) Relay + the still-plaintext
# relay-daemon, and assert the Relay REJECTS the certless daemon — no Hello is processed and
# no Ping is delivered.
#
# This captures the transition state after Relay mTLS (#26): the Relay now requires & verifies
# client certs, but the daemon does not yet have an mTLS client. Once the daemon gains one (#28)
# this assertion will be upgraded back to a positive Hello→Ping handshake.
#
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
ca_dir=""

cleanup() {
    if [[ -n "${relay_pid}" ]]; then
        kill "${relay_pid}" 2>/dev/null || true
        wait "${relay_pid}" 2>/dev/null || true
    fi
    [[ -n "${relay_log}" ]] && rm -f "${relay_log}"
    [[ -n "${daemon_log}" ]] && rm -f "${daemon_log}"
    [[ -n "${ca_dir}" ]] && rm -rf "${ca_dir}"
}
trap cleanup EXIT

relay_log="$(mktemp)"
daemon_log="$(mktemp)"
ca_dir="$(mktemp -d)"

if [[ ! -x "${RELAY_BIN}" ]]; then
    echo "ERROR: relay binary not found at ${RELAY_BIN}; run 'make build' first" >&2
    exit 1
fi
if [[ ! -x "${DAEMON_BIN}" ]]; then
    echo "ERROR: relay-daemon binary not found at ${DAEMON_BIN}; run 'make build' first" >&2
    exit 1
fi

echo "Starting Relay (mTLS) on ${RELAY_ADDR}..."
"${RELAY_BIN}" --addr "${RELAY_ADDR}" --ca-dir "${ca_dir}" >"${relay_log}" 2>&1 &
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

echo "Running the (plaintext) relay-daemon against the mTLS Relay for ${DAEMON_WINDOW}s..."
timeout "${DAEMON_WINDOW}" "${DAEMON_BIN}" --relay "${RELAY_URL}" >"${daemon_log}" 2>&1 || true

# The Relay now requires & verifies client certs (#26). The still-plaintext daemon cannot
# complete the TLS handshake, so no Hello ever reaches the handler and no Ping is returned.
echo "Asserting the Relay rejected the certless daemon (no node_id in relay log)..."
if grep -q "node_id" "${relay_log}"; then
    echo "FAIL: Relay processed a Hello from a certless daemon — mTLS is not being enforced" >&2
    echo "--- relay log ---" >&2
    cat "${relay_log}" >&2
    exit 1
fi

echo "Asserting the daemon did NOT receive a Ping (checking daemon log)..."
if grep -q "received Ping from Relay" "${daemon_log}"; then
    echo "FAIL: certless daemon received a Ping — the handshake was not rejected" >&2
    echo "--- daemon log ---" >&2
    cat "${daemon_log}" >&2
    exit 1
fi

echo "PASS: mTLS Relay correctly rejected the certless daemon (no Hello, no Ping)."
