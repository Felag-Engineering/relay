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
# The Relay runs as a separate uid where the host allows it: the same harness, and the same
# layout, as the Go suites (relay/internal/relaytest/separateuid.go). Fixtures are root-owned
# and built through `sudo -n`; the Relay starts through `sudo -n setpriv` as relaytest with
# relaytest-io as its one supplementary group; its log is in a relaytest:relaytest-io 2770
# directory, the only thing this script reaches through that group; the CA certificate is
# copied out through sudo. Without passwordless sudo, setpriv, the accounts
# (scripts/relaytest-user.sh) or the group, the Relay runs as this user and the missing
# separate uid is recorded in make verify's skip ledger; RELAY_E2E_SUDO_REQUIRED=1 (CI only)
# makes that a failure.
#
# Needs the Relay binary ('make build', or run from make test-integration, which depends on
# build) and curl built with HTTP/2. A missing prerequisite is an error, never a skip.
# Exits non-zero on any failed assertion or timeout.
#
# Environment:
#   RELAY_SMOKE_PORT        port for the Relay's daemon listener (default 17654), so parallel
#                           `make verify` runs in several worktrees do not reach one another.
#   RELAY_SMOKE_RELAY_BIN   the Relay binary to test (default relay/bin/relay). A seam for
#                           scripts/smoke-test-test.sh; nothing in the Makefile or CI sets it.
#   RELAY_E2E_SUDO_REQUIRED "1" makes a missing separate uid a failure instead of a skip.
#   RELAY_VERIFY_SKIPS      make verify's skip ledger, set by the Makefile.
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

# The separate uid's accounts and its one drop: relaytest's own uid and gid, every
# supplementary group cleared except relaytest-io (setpriv refuses --clear-groups beside
# --groups), no inheritable capabilities.
TEST_USER="relaytest"
TEST_IO_GROUP="relaytest-io"
SETPRIV=(setpriv --reuid="${TEST_USER}" --regid="${TEST_USER}" --groups="${TEST_IO_GROUP}" --inh-caps=-all)

relay_pid=""     # the Relay's own process
started_pid=""   # the process this script started: the Relay, or sudo in front of it
work_dir=""
layout_dir=""    # root-owned, separate uid only

# alive <pid>: true while the process exists. Not `kill -0`: as the separate uid the Relay is
# another user's process, which this script may not signal.
alive() { ps -p "$1" -o pid= >/dev/null 2>&1; }

# signal_relay <signal>: to the Relay itself. sudo cannot relay SIGKILL, and this script may
# not signal another uid, so as the separate uid it goes through `sudo -n -u relaytest kill`:
# as relaytest and not root, so a pid reused after the Relay exited is refused, never killed.
signal_relay() {
    if [[ -n "${layout_dir}" ]]; then
        sudo -n -u "${TEST_USER}" kill -s "$1" "${relay_pid}" 2>/dev/null || true
    else
        kill -s "$1" "${relay_pid}" 2>/dev/null || true
    fi
}

cleanup() {
    if [[ -n "${relay_pid}" ]]; then
        signal_relay TERM
    elif [[ -n "${started_pid}" && -n "${layout_dir}" ]]; then
        # sudo never handed over; it runs as root, which this script may not signal itself.
        sudo -n kill -s KILL "${started_pid}" 2>/dev/null || true
    elif [[ -n "${started_pid}" ]]; then
        kill "${started_pid}" 2>/dev/null || true
    fi
    if [[ -n "${started_pid}" ]]; then
        wait "${started_pid}" 2>/dev/null || true
    fi
    case "${layout_dir}" in /tmp/relaytest.*) sudo -n rm -rf -- "${layout_dir}" ;; esac
    case "${work_dir}" in /*) rm -rf "${work_dir}" ;; esac
}
trap cleanup EXIT

work_dir="$(mktemp -d)"
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

# separate_uid_reason: prints why the Relay cannot run as the separate uid here, or nothing.
separate_uid_reason() {
    local io_gid
    if ! command -v sudo >/dev/null 2>&1; then echo "sudo is not installed"; return; fi
    if ! sudo -n true >/dev/null 2>&1; then echo "sudo -n is not passwordless here"; return; fi
    if ! sudo -n setpriv --version >/dev/null 2>&1; then echo "setpriv is not installed"; return; fi
    if ! getent passwd "${TEST_USER}" >/dev/null; then
        echo "no ${TEST_USER} user (sudo scripts/relaytest-user.sh \"\$USER\" creates it)"; return
    fi
    if ! io_gid="$(getent group "${TEST_IO_GROUP}" | cut -d: -f3)" || [[ -z "${io_gid}" ]]; then
        echo "no ${TEST_IO_GROUP} group (sudo scripts/relaytest-user.sh \"\$USER\" creates it)"; return
    fi
    if [[ "$(id -u)" == "$(id -u "${TEST_USER}")" ]]; then echo "this test already runs as ${TEST_USER}"; return; fi
    if [[ "$(id -u)" != 0 ]] && ! id -G | tr ' ' '\n' | grep -qx "${io_gid}"; then
        echo "this process is not in ${TEST_IO_GROUP} (start a new login after relaytest-user.sh, or run under sg ${TEST_IO_GROUP})"
    fi
}

reason="$(separate_uid_reason)"
if [[ -n "${reason}" ]]; then
    if [[ "${RELAY_E2E_SUDO_REQUIRED:-}" == "1" ]]; then
        echo "FAIL: the Relay cannot run as a separate uid: ${reason} — and RELAY_E2E_SUDO_REQUIRED=1, so this is a failure, not a skip" >&2
        exit 1
    fi
    echo "smoke-test: SKIPPING the Relay as a separate uid (${reason}); it runs as this user"
    if [[ -n "${RELAY_VERIFY_SKIPS:-}" ]]; then
        echo "test-integration: smoke test, the Relay as a separate uid (${reason})" >> "${RELAY_VERIFY_SKIPS}"
    fi
    relay_log="${work_dir}/relay.log"
    state_dir="${work_dir}/state"
    conf_dir="${work_dir}"
else
    layout_dir="$(sudo -n mktemp -d /tmp/relaytest.XXXXXXXX)"
    case "${layout_dir}" in
        /tmp/relaytest.*) ;;
        *) echo "ERROR: sudo mktemp returned an unexpected path '${layout_dir}'" >&2; layout_dir=""; exit 1 ;;
    esac
    sudo -n chmod 0755 "${layout_dir}"
    conf_dir="${layout_dir}/etc"
    state_dir="${layout_dir}/state"
    sudo -n install -d -o root -g "${TEST_USER}" -m 0750 "${conf_dir}"
    sudo -n install -d -o root -g root -m 0755 "${layout_dir}/bin"
    sudo -n install -d -o "${TEST_USER}" -g "${TEST_USER}" -m 0700 "${state_dir}"
    sudo -n install -d -o "${TEST_USER}" -g "${TEST_IO_GROUP}" -m 2770 "${layout_dir}/io"
    sudo -n install -o root -g root -m 0755 -- "${relay_bin}" "${layout_dir}/bin/relay"
    relay_bin="${layout_dir}/bin/relay"
    relay_log="${layout_dir}/io/relay.log"
    echo "The Relay runs as ${TEST_USER} over root-owned fixtures in ${layout_dir}."
fi
ca_dir="${state_dir}/ca"

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
path = "${state_dir}/store/relay.db"

[tls]
hostname = "${smoke_hostname}"
EOF
chmod 0400 "${relay_config}"
if [[ -n "${layout_dir}" ]]; then
    # root:relaytest 0640: the Relay reads it, nobody but root writes it, and the IO group
    # cannot read it.
    sudo -n install -o root -g "${TEST_USER}" -m 0640 -- "${relay_config}" "${conf_dir}/relay.toml"
    relay_config="${conf_dir}/relay.toml"
    # Nothing of this user's own temp or coverage directories, which the Relay cannot write.
    # The redirect is this user's, deliberately: the log is opened here, in the IO directory,
    # and the Relay writes through the descriptor it inherits.
    # shellcheck disable=SC2024
    sudo -n "${SETPRIV[@]}" env -i PATH="${PATH}" HOME=/ \
        "${relay_bin}" --config "${relay_config}" >"${relay_log}" 2>&1 </dev/null &
    started_pid=$!
    # The Relay's own pid: the descendant of sudo running as relaytest (a direct child, or a
    # grandchild when sudo interposes a pty monitor).
    relay_uid="$(id -u "${TEST_USER}")"
    pid_deadline=$(( $(date +%s) + STARTUP_TIMEOUT ))
    while [[ -z "${relay_pid}" ]]; do
        relay_pid="$(ps -e -o pid=,ppid=,ruid= | awk -v root="${started_pid}" -v u="${relay_uid}" '
            { pid[NR] = $1; ppid[NR] = $2; uid[NR] = $3 }
            END {
                under[root] = 1
                for (grew = 1; grew; ) {
                    grew = 0
                    for (i = 1; i <= NR; i++)
                        if ((ppid[i] in under) && !(pid[i] in under)) { under[pid[i]] = 1; grew = 1 }
                }
                for (i = 1; i <= NR; i++)
                    if (pid[i] != root && (pid[i] in under) && uid[i] == u) { print pid[i]; exit }
            }')"
        [[ -n "${relay_pid}" ]] && break
        if ! alive "${started_pid}" || [[ "$(date +%s)" -ge "${pid_deadline}" ]]; then
            echo "ERROR: the Relay did not start as ${TEST_USER}" >&2
            relay_dump_log
            exit 1
        fi
        sleep 0.05
    done
else
    child_env=(PATH="${PATH}" HOME="${HOME:-/}")
    [[ -n "${TMPDIR:-}" ]] && child_env+=(TMPDIR="${TMPDIR}")
    [[ -n "${GOCOVERDIR:-}" ]] && child_env+=(GOCOVERDIR="${GOCOVERDIR}")
    env -i "${child_env[@]}" "${relay_bin}" --config "${relay_config}" >"${relay_log}" 2>&1 &
    started_pid=$!
    relay_pid="${started_pid}"
fi

echo "Waiting for Relay to report listening (up to ${STARTUP_TIMEOUT}s)..."
deadline=$(( $(date +%s) + STARTUP_TIMEOUT ))
while ! grep -q "relay listening" "${relay_log}" 2>/dev/null; do
    if ! alive "${relay_pid}"; then
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
if [[ -n "${layout_dir}" ]]; then
    # The CA directory is the Relay's alone; its public certificate is copied out, read as
    # relaytest (never root, so nothing the Relay plants there, a symlink, can make root read
    # for it) into a file this user owns (so the redirect is deliberately not sudo's).
    # shellcheck disable=SC2024
    sudo -n -u "${TEST_USER}" cat -- "${ca_cert}" >"${work_dir}/ca-cert.pem" 2>/dev/null || true
    ca_cert="${work_dir}/ca-cert.pem"
fi
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

if ! alive "${relay_pid}"; then
    echo "FAIL: the Relay exited during the smoke test" >&2
    fail=1
fi

if [[ "${fail}" -ne 0 ]]; then
    relay_dump_log
    exit 1
fi

echo "PASS: the Relay's daemon listener refused certless Renew and Tunnel/Open with \"${CERT_REQUIRED_MSG}\", while the same certless dial reached the Enroll handler (positive control)."
