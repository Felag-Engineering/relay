#!/usr/bin/env bash
# Proves scripts/smoke-test.sh's mTLS verdict cannot be vacuous: it passes only when the certless
# positive control reached the Enroll handler AND both certless refusals came from the transport
# interceptors; and it fails when nothing is listening, when mTLS is off (one interceptor or
# both), when a refusal carries the right code but not the interceptor's message, when the
# listener refuses everything, when the answer is not gRPC at all, when the Relay never comes
# up, and when curl cannot speak HTTP/2. It also proves the dial is certless by construction:
# curl is invoked with -q (no ~/.curlrc) and never with a client certificate or key.
#
# Hermetic: the REAL smoke-test.sh runs against a stub Relay (bash; binds nothing) and a stub
# curl that replays responses. The response SHAPE is a recorded real capture — real curl 8.5
# against the real Relay on 2026-10-02, CRLFs included (the codex-review-test.sh "recorded real
# capture" idiom); only the status and message vary per case. No Go, no Rust, no network, no
# writes outside its own `mktemp -d`. The real Relay half of the proof is `make
# test-integration`, which runs smoke-test.sh against the built binary.
#
# NOT `set -e`: every case must run and be reported, not stop at the first failure
# (security-surface-test.sh:13).
set -uo pipefail

# --- Safety preamble, the same idiom as proto-tools-check-test.sh: the trap's `rm -rf` only
# ever targets an absolute $WORKDIR from mktemp, never an argument or the environment.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
WORKDIR="$(mktemp -d)" || { echo "FAIL: mktemp -d failed" >&2; exit 1; }
trap 'case "${WORKDIR:-}" in /*) rm -rf "$WORKDIR" ;; esac' EXIT
case "$WORKDIR" in
  /*) ;;
  *) echo "FAIL: mktemp returned a non-absolute path: '$WORKDIR'" >&2; exit 1 ;;
esac

SCRIPT="$REPO_ROOT/scripts/smoke-test.sh"
fail=0

# --- Stub Relay. Writes a CA certificate where --ca-dir says, prints the line smoke-test.sh
# waits for, and sleeps; it binds nothing, so only the stub curl ever answers.
# STUB_RELAY_MODE=exit makes it die before reporting listening.
mkdir -p "$WORKDIR/stub"
cat > "$WORKDIR/stub/relay" <<'STUB'
#!/usr/bin/env bash
ca=""
while [ $# -gt 0 ]; do
  case "$1" in --ca-dir) ca=$2; shift ;; esac
  shift
done
if [ "${STUB_RELAY_MODE:-}" = "exit" ]; then
  echo "stub relay: refusing to start" >&2
  exit 1
fi
mkdir -p "$ca" && echo "stub CA certificate" > "$ca/ca-cert.pem"
echo "level=INFO msg=\"relay listening\" (stub)"
exec sleep 30
STUB
chmod +x "$WORKDIR/stub/relay"

# --- Stub curl. `--version` answers with the recorded real feature line (HTTP2 dropped when
# STUB_NO_HTTP2 is set). Any other call appends its argv to $STUB_ARGV_LOG, then replays the
# response recorded for the method the URL names, from $STUB_RESPONSES/<Service>_<Method>:
# `.hdr` to stdout (smoke-test.sh asks for -D - and -o /dev/null), `.err` to stderr, and `.rc`
# as the exit status.
cat > "$WORKDIR/stub/curl" <<'STUB'
#!/usr/bin/env bash
if [ "${1:-}" = "--version" ]; then
  echo "curl 8.5.0 (x86_64-pc-linux-gnu) libcurl/8.5.0 OpenSSL/3.0.13 nghttp2/1.59.0"
  if [ -n "${STUB_NO_HTTP2:-}" ]; then
    echo "Features: alt-svc AsynchDNS IPv6 Largefile SSL TLS-SRP UnixSockets"
  else
    echo "Features: alt-svc AsynchDNS HTTP2 IPv6 Largefile SSL TLS-SRP UnixSockets"
  fi
  exit 0
fi
printf '%s\n' "$*" >> "${STUB_ARGV_LOG:?}"
url="${!#}"
method="${url##*/relay.v1.}"
key="${STUB_RESPONSES:?}/${method//\//_}"
[ -f "$key.hdr" ] && cat "$key.hdr"
[ -f "$key.err" ] && cat "$key.err" >&2
if [ -f "$key.rc" ]; then exit "$(cat "$key.rc")"; fi
exit 0
STUB
chmod +x "$WORKDIR/stub/curl"

# --- Response writers. grpc_resp writes the recorded real shape with a chosen status and
# message; http_resp writes a non-gRPC HTTP answer; down_resp writes curl's recorded
# connection-refused failure.
grpc_resp() { # <dir> <Service_Method> <grpc-status> <grpc-message>
  printf 'HTTP/2 200 \r\ncontent-type: application/grpc\r\ngrpc-status: %s\r\ngrpc-message: %s\r\n\r\n' \
    "$3" "$4" > "$1/$2.hdr"
}
http_resp() { # <dir> <Service_Method> <http status>
  printf 'HTTP/2 %s \r\ncontent-type: text/plain; charset=utf-8\r\n\r\n' "$3" > "$1/$2.hdr"
}
down_resp() { # <dir> <Service_Method>
  echo "curl: (7) Failed to connect to localhost port 65000 after 0 ms: Couldn't connect to server" \
    > "$1/$2.err"
  echo 7 > "$1/$2.rc"
}

# The three responses of a correctly enforcing Relay, as recorded.
good_responses() { # <dir>
  grpc_resp "$1" Enrollment_Enroll 3 "enrollment_token and csr are required"
  grpc_resp "$1" Enrollment_Renew 16 "client certificate required"
  grpc_resp "$1" Tunnel_Open 16 "client certificate required"
}

new_case() { # <name> -> sets CASE_DIR, an empty response directory
  CASE_DIR="$WORKDIR/case-$1"
  mkdir -p "$CASE_DIR"
}

# --- Capture harness. Globals only: `local out=$(cmd)` sets $? from `local`, not the command
# run inside it (security-surface-test.sh:106-108).
OUT=""
RC=0
ARGV_LOG=""

# run_smoke [VAR=value ...] — the real smoke-test.sh against the stubs, responses from CASE_DIR.
run_smoke() {
  ARGV_LOG="$CASE_DIR/argv"
  : > "$ARGV_LOG"
  OUT="$(env PATH="$WORKDIR/stub:/usr/bin:/bin" RELAY_SMOKE_PORT=65000 \
         RELAY_SMOKE_RELAY_BIN="$WORKDIR/stub/relay" STUB_RESPONSES="$CASE_DIR" \
         STUB_ARGV_LOG="$ARGV_LOG" "$@" bash "$SCRIPT" 2>&1)"
  RC=$?
}

assert_rc() {
  local name=$1 want=$2
  if [ "$RC" -ne "$want" ]; then
    echo "FAIL: $name: rc=$RC want=$want; output:" >&2
    printf '%s\n' "$OUT" | sed 's/^/    /' >&2
    fail=$((fail + 1))
  fi
}

assert_contains() {
  local name=$1 needle=$2
  case "$OUT" in
    *"$needle"*) ;;
    *) echo "FAIL: $name: output does not contain [$needle]" >&2; fail=$((fail + 1)) ;;
  esac
}

assert_not_contains() {
  local name=$1 needle=$2
  case "$OUT" in
    *"$needle"*) echo "FAIL: $name: output unexpectedly contains [$needle]" >&2; fail=$((fail + 1)) ;;
    *) ;;
  esac
}

# A failing case must fail without printing the PASS verdict.
assert_refused() { # <name> <needle in the failure>
  assert_rc "$1" 1
  assert_contains "$1" "$2"
  assert_not_contains "$1" "PASS:"
}

# --- Cases ---

# 1: a correctly enforcing Relay -> exit 0 with the PASS verdict, all three calls made, and every
# call certless by construction: -q first (no ~/.curlrc), --noproxy, and no cert or key flag.
new_case good
good_responses "$CASE_DIR"
run_smoke
assert_rc "case1-enforcing" 0
assert_contains "case1-enforcing" "PASS:"
if [ "$(grep -c . "$ARGV_LOG")" -ne 3 ]; then
  echo "FAIL: case1-enforcing: want 3 curl calls, got $(grep -c . "$ARGV_LOG")" >&2
  fail=$((fail + 1))
fi
for m in Enrollment/Enroll Enrollment/Renew Tunnel/Open; do
  grep -q "/relay.v1.$m\$" "$ARGV_LOG" \
    || { echo "FAIL: case1-enforcing: no call to $m" >&2; fail=$((fail + 1)); }
done
while IFS= read -r argv; do
  case "$argv" in
    "-q "*) ;;
    *) echo "FAIL: case1-enforcing: curl's first argument is not -q: [$argv]" >&2; fail=$((fail + 1)) ;;
  esac
  case " $argv " in
    *" --noproxy "*) ;;
    *) echo "FAIL: case1-enforcing: curl call without --noproxy: [$argv]" >&2; fail=$((fail + 1)) ;;
  esac
  case " $argv " in
    *" --cert "* | *" -E "* | *" --key "* | *" --cert="* | *" --key="*)
      echo "FAIL: case1-enforcing: a certless dial passed a client cert or key: [$argv]" >&2
      fail=$((fail + 1)) ;;
  esac
done < "$ARGV_LOG"

# 2: nothing listening (the dial fails) -> the positive control fails, and no refusal is read as
# a pass. This is what the replaced assertion passed on.
new_case down
down_resp "$CASE_DIR" Enrollment_Enroll
down_resp "$CASE_DIR" Enrollment_Renew
down_resp "$CASE_DIR" Tunnel_Open
run_smoke
assert_refused "case2-nothing-listening" "positive control: the certless dial itself did not work"

# 3: mTLS off — both interceptors bypassed, each call reaches its handler. These two responses
# are the real Relay's answers with its interceptors patched out (2026-10-02). The replaced
# assertion passed on this too.
new_case mtls-off
grpc_resp "$CASE_DIR" Enrollment_Enroll 3 "enrollment_token and csr are required"
grpc_resp "$CASE_DIR" Enrollment_Renew 3 "csr is required"
grpc_resp "$CASE_DIR" Tunnel_Open 3 "expected Hello as first message"
run_smoke
assert_refused "case3-mtls-off" "certless relay.v1.Enrollment/Renew was not refused"
assert_contains "case3-mtls-off" "certless relay.v1.Tunnel/Open was not refused"

# 4: only the stream interceptor broken -> fails, naming Tunnel/Open and not Renew. Each
# interceptor is checked on its own.
new_case stream-off
good_responses "$CASE_DIR"
grpc_resp "$CASE_DIR" Tunnel_Open 3 "expected Hello as first message"
run_smoke
assert_refused "case4-stream-interceptor-off" "certless relay.v1.Tunnel/Open was not refused"
assert_not_contains "case4-stream-interceptor-off" "certless relay.v1.Enrollment/Renew was not refused"

# 5: only the unary interceptor broken -> fails, naming Renew and not Tunnel/Open.
new_case unary-off
good_responses "$CASE_DIR"
grpc_resp "$CASE_DIR" Enrollment_Renew 3 "csr is required"
run_smoke
assert_refused "case5-unary-interceptor-off" "certless relay.v1.Enrollment/Renew was not refused"
assert_not_contains "case5-unary-interceptor-off" "certless relay.v1.Tunnel/Open was not refused"

# 6: the right CODE without the interceptor's MESSAGE -> fails. With the interceptor bypassed,
# Renew's own handler answers Unauthenticated "no node identity"; a code-only check would pass.
new_case code-only
good_responses "$CASE_DIR"
grpc_resp "$CASE_DIR" Enrollment_Renew 16 "no node identity"
run_smoke
assert_refused "case6-code-without-message" "certless relay.v1.Enrollment/Renew was not refused"

# 7: the listener refuses everything, the certless Enroll included -> the positive control fails.
# Refusals from such a listener cannot tell mTLS enforcement from a broken one.
new_case refuse-all
good_responses "$CASE_DIR"
grpc_resp "$CASE_DIR" Enrollment_Enroll 16 "client certificate required"
run_smoke
assert_refused "case7-refuses-everything" "positive control: certless Enroll did not reach the Enroll handler"

# 8: something answers, but not gRPC (HTTP 404, no grpc-status) -> the positive control fails.
new_case not-grpc
good_responses "$CASE_DIR"
http_resp "$CASE_DIR" Enrollment_Enroll 404
run_smoke
assert_refused "case8-not-grpc" "positive control: the certless dial itself did not work"

# 9: the Relay dies before it reports listening -> exit 1, no call is made.
new_case relay-exits
good_responses "$CASE_DIR"
run_smoke STUB_RELAY_MODE=exit
assert_refused "case9-relay-exits" "Relay process exited unexpectedly"
if [ -s "$ARGV_LOG" ]; then
  echo "FAIL: case9-relay-exits: curl was called although the Relay never came up" >&2
  fail=$((fail + 1))
fi

# 10: curl without HTTP/2 -> an error, never a skip and never a pass.
new_case no-http2
good_responses "$CASE_DIR"
run_smoke STUB_NO_HTTP2=1
assert_refused "case10-no-http2" "no HTTP/2 support"

if [ "$fail" -ne 0 ]; then
  echo "FAIL: $fail assertion(s) failed" >&2
  exit 1
fi

echo "PASS: smoke-test.sh passes only on a reached certless Enroll plus interceptor refusals of certless Renew and Tunnel/Open, and fails when nothing listens, when either interceptor is off, on the right code with the wrong message, when everything is refused, on a non-gRPC answer, when the Relay never starts, and without HTTP/2; every dial is certless by construction."
