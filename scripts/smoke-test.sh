#!/usr/bin/env bash
# End-to-end mTLS smoke test (invariant 6; ADR-0005, ADR-0006): boot the real Relay binary and
# prove, from an independent client on the wire, that its daemon listener refuses a caller
# that presents no client certificate.
#
# What "refused" means here. The daemon listener deliberately ACCEPTS a certless TLS handshake
# (tls.VerifyClientCertIfGiven): Enrollment is the one certless method, and a daemon has no
# certificate until it has enrolled. The refusal is therefore per-RPC, by the transport
# interceptors' default-deny allowlist. So this script dials the listener over TLS 1.3 + HTTP/2
# with NO client certificate and makes three gRPC calls:
#
#   positive control  Enrollment/Enroll (the certless method), empty request. Must come back
#                     from the Enroll HANDLER itself: InvalidArgument. That proves the dial path
#                     works end to end — the listener is up, the TLS handshake succeeds against
#                     the CA this Relay just minted (so it is this Relay, not some other process
#                     on the port), HTTP/2 and gRPC framing are understood — so the refusals
#                     below cannot be "nothing listening" or "the client is broken".
#   refusal (unary)   Enrollment/Renew. Must be Unauthenticated "client certificate required",
#                     the unary interceptor's own refusal. The message is load-bearing: with the
#                     interceptor bypassed, Renew's handler ALSO answers Unauthenticated (with a
#                     different message), so a status-code-only check would pass with mTLS off.
#   refusal (stream)  Tunnel/Open, the stream a daemon actually connects on. Must be refused by
#                     the stream interceptor with the same status and message.
#
# This replaced an assertion that ran the relay-daemon and checked that no Hello reached the
# Relay. A daemon with no enrolled identity refuses to dial at all ("no enrolled identity in
# state dir; refusing to connect"), so that assertion held whether or not mTLS was enforced,
# and whether or not anything was listening. The cert-presenting positive path — a real daemon
# connecting with its enrolled certificate — is proved by the integration and cross-binary
# suites, not here.
#
# The Relay is started with --config on a read-only relay.toml this script writes.
#
# Needs the Relay binary ('make build', or run from make test-integration, which depends on
# build) and curl built with HTTP/2. A missing prerequisite is an error, never a skip.
# Exits non-zero on any failed assertion or timeout.
#
# Environment:
#   RELAY_SMOKE_PORT      port for the Relay's daemon listener (default 17654), so parallel
#                         `make verify` runs in several worktrees do not reach one another.
#   RELAY_SMOKE_RELAY_BIN the Relay binary to test (default relay/bin/relay). A seam for
#                         scripts/smoke-test-test.sh; nothing in the Makefile or CI sets it.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
relay_bin="${RELAY_SMOKE_RELAY_BIN:-${REPO_ROOT}/relay/bin/relay}"
RELAY_PORT="${RELAY_SMOKE_PORT:-17654}"
smoke_addr="127.0.0.1:${RELAY_PORT}"
# The Relay's server certificate is issued for tls.hostname in its configuration file; curl is pointed at that name and
# --resolve pins it to the loopback address, so certificate verification is real, not skipped.
smoke_hostname="localhost"
STARTUP_TIMEOUT=10
CALL_TIMEOUT=5

relay_pid=""
work_dir=""

cleanup() {
    if [[ -n "${relay_pid}" ]]; then
        kill "${relay_pid}" 2>/dev/null || true
        wait "${relay_pid}" 2>/dev/null || true
    fi
    case "${work_dir}" in /*) rm -rf "${work_dir}" ;; esac
}
trap cleanup EXIT

work_dir="$(mktemp -d)"
relay_log="${work_dir}/relay.log"
ca_dir="${work_dir}/ca"
frame="${work_dir}/empty-grpc-frame"

if [[ ! -x "${relay_bin}" ]]; then
    echo "ERROR: relay binary not found at ${relay_bin}; run 'make build' first" >&2
    exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: curl not found; the certless dial needs curl with HTTP/2" >&2
    exit 1
fi
if ! curl --version | grep -qw HTTP2; then
    echo "ERROR: this curl has no HTTP/2 support; the certless dial needs it (gRPC is HTTP/2)" >&2
    exit 1
fi

relay_dump_log() {
    echo "--- relay log ---" >&2
    cat "${relay_log}" >&2 || true
}

echo "Starting Relay (mTLS) on ${smoke_addr}..."
# The Relay reads its settings from one read-only file and nothing from flags or the
# environment, and it refuses to start if a retired RELAY_* setting variable is set. So it
# runs under a filtered environment: a variable the developer has exported must not decide
# whether this test starts.
relay_config="${work_dir}/relay.toml"
cat >"${relay_config}" <<EOF
[node_plane]
listen_address = "${smoke_addr}"

[ca]
dir = "${ca_dir}"

[store]
path = "${work_dir}/store/relay.db"

[tls]
hostname = "${smoke_hostname}"
EOF
chmod 0400 "${relay_config}"
child_env=(PATH="${PATH}" HOME="${HOME:-/}")
[[ -n "${TMPDIR:-}" ]] && child_env+=(TMPDIR="${TMPDIR}")
[[ -n "${GOCOVERDIR:-}" ]] && child_env+=(GOCOVERDIR="${GOCOVERDIR}")
env -i "${child_env[@]}" "${relay_bin}" --config "${relay_config}" >"${relay_log}" 2>&1 &
relay_pid=$!

echo "Waiting for Relay to report listening (up to ${STARTUP_TIMEOUT}s)..."
deadline=$(( $(date +%s) + STARTUP_TIMEOUT ))
while ! grep -q "relay listening" "${relay_log}" 2>/dev/null; do
    if ! kill -0 "${relay_pid}" 2>/dev/null; then
        echo "ERROR: Relay process exited unexpectedly" >&2
        relay_dump_log
        exit 1
    fi
    if [[ "$(date +%s)" -ge "${deadline}" ]]; then
        echo "ERROR: Relay did not start within ${STARTUP_TIMEOUT}s" >&2
        relay_dump_log
        exit 1
    fi
    sleep 0.2
done
echo "Relay is listening."

ca_cert="${ca_dir}/ca-cert.pem"
if [[ ! -s "${ca_cert}" ]]; then
    echo "ERROR: Relay reported listening but wrote no CA certificate at ${ca_cert}" >&2
    relay_dump_log
    exit 1
fi

# One gRPC message frame carrying an empty protobuf message: compressed-flag 0, length 0. An
# empty message is valid for every request type, so each call reaches its interceptor, and —
# where the interceptor lets it through — its handler.
printf '\x00\x00\x00\x00\x00' >"${frame}"

# grpc_call <method> — one certless gRPC call. Sets globals (never `local x=$(cmd)`, which
# reports local's status, not the command's): CALL_RC (curl's exit status), CALL_HTTP (the
# HTTP status code), CALL_STATUS and CALL_MSG (the grpc-status and grpc-message headers or
# trailers), CALL_ERR (curl's stderr).
#
# -q is first so no ~/.curlrc can add a client certificate (or anything else) to a dial that
# must be certless; no --cert/--key is ever passed. --noproxy '*' keeps the dial on loopback.
grpc_call() {
    local method=$1 headers
    set +e
    headers="$(curl -q -sS --http2 --noproxy '*' --max-time "${CALL_TIMEOUT}" \
        --cacert "${ca_cert}" --resolve "${smoke_hostname}:${RELAY_PORT}:127.0.0.1" \
        -H 'content-type: application/grpc' -H 'te: trailers' \
        --data-binary @"${frame}" -o /dev/null -D - \
        "https://${smoke_hostname}:${RELAY_PORT}/${method}" 2>"${work_dir}/curl.err")"
    CALL_RC=$?
    set -e
    # Here-strings, never `printf | awk ... exit`: under pipefail an early-exiting reader can
    # SIGPIPE the writer and fail the assignment (the race scripts/check-docs.sh records).
    headers="${headers//$'\r'/}"
    CALL_ERR="$(cat "${work_dir}/curl.err")"
    CALL_HTTP="$(awk '/^HTTP\// {print $2; exit}' <<<"${headers}")"
    CALL_STATUS="$(awk -F': ' 'tolower($1)=="grpc-status" {print $2; exit}' <<<"${headers}")"
    CALL_MSG="$(awk 'tolower($0) ~ /^grpc-message: / {sub(/^[^:]*: /, ""); print; exit}' <<<"${headers}")"
}

call_summary() {
    echo "curl exit=${CALL_RC} http=${CALL_HTTP:-none} grpc-status=${CALL_STATUS:-none} grpc-message=[${CALL_MSG}] curl-stderr=[${CALL_ERR}]"
}

GRPC_INVALID_ARGUMENT=3
GRPC_UNAUTHENTICATED=16
CERT_REQUIRED_MSG="client certificate required"

echo "Positive control: a certless call to Enrollment/Enroll must reach its handler..."
grpc_call "relay.v1.Enrollment/Enroll"
if [[ "${CALL_RC}" -ne 0 || "${CALL_HTTP}" != "200" ]]; then
    echo "FAIL: positive control: the certless dial itself did not work ($(call_summary))." >&2
    echo "      Nothing is listening, the TLS handshake failed, or HTTP/2 was not negotiated —" >&2
    echo "      so a refusal below would prove nothing about mTLS." >&2
    relay_dump_log
    exit 1
fi
if [[ "${CALL_STATUS}" != "${GRPC_INVALID_ARGUMENT}" ]]; then
    echo "FAIL: positive control: certless Enroll did not reach the Enroll handler; want" >&2
    echo "      grpc-status ${GRPC_INVALID_ARGUMENT} (InvalidArgument) ($(call_summary))." >&2
    echo "      If the certless method is refused too, the refusals below cannot tell mTLS" >&2
    echo "      enforcement from a listener that refuses everything." >&2
    relay_dump_log
    exit 1
fi
echo "  ok: $(call_summary)"

fail=0
# Tunnel/Open is the stream a daemon connects on (stream interceptor); Renew is a unary method
# that is not on the certless allowlist (unary interceptor). Each interceptor is checked.
for method in "relay.v1.Enrollment/Renew" "relay.v1.Tunnel/Open"; do
    echo "Asserting a certless call to ${method} is refused..."
    grpc_call "${method}"
    if [[ "${CALL_RC}" -ne 0 || "${CALL_HTTP}" != "200" \
          || "${CALL_STATUS}" != "${GRPC_UNAUTHENTICATED}" || "${CALL_MSG}" != "${CERT_REQUIRED_MSG}" ]]; then
        echo "FAIL: certless ${method} was not refused with grpc-status ${GRPC_UNAUTHENTICATED}" >&2
        echo "      (Unauthenticated) \"${CERT_REQUIRED_MSG}\" — mTLS is not being enforced" >&2
        echo "      ($(call_summary))." >&2
        fail=1
        continue
    fi
    echo "  ok: $(call_summary)"
done

if ! kill -0 "${relay_pid}" 2>/dev/null; then
    echo "FAIL: the Relay exited during the smoke test" >&2
    fail=1
fi

if [[ "${fail}" -ne 0 ]]; then
    relay_dump_log
    exit 1
fi

echo "PASS: the Relay's daemon listener refused certless Renew and Tunnel/Open with \"${CERT_REQUIRED_MSG}\", while the same certless dial reached the Enroll handler (positive control)."
