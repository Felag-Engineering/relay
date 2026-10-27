#!/usr/bin/env bash
# The enroll -> connect -> execute syscall trace of the packaged relay-daemon unit, run as a CI
# job on the runner VM (docs/specs/daemon-installation.md DI-3's check of the packaged unit;
# the procedure is docs/operations/daemon-privilege-posture.md, "Live tracing procedure").
#
#   install-matrix-vm-trace.sh <pkgdir> <outdir>      both absolute; run as root (sudo)
#
# It installs the new .deb set for this architecture on the VM, enrolls the Node with
# `relay-daemon join` by reusing the install-matrix row's `join` phase, attaches strace to
# the running packaged unit, restarts the Relay so the daemon reconnects (connect) while
# traced, dispatches one of each kind of Operation (execute), then compares every traced
# syscall with systemd's @system-service set, which is what the unit's SystemCallFilter
# allows. A syscall outside the filter kills the daemon with SIGSYS, so a clean run is
# evidence on its own; the strace union adds the exact list for the human who signs it off.
#
# Scope: the strict, packaged unit only. The pkg-install drop-in and its
# MemoryDenyWriteExecute=no are never shipped (DI-5), so they stay the posture document's
# manual step; pkg.install is dispatched here and must FAIL under the strict unit, with the
# sandbox's refusal in its stderr.
#
# Coupling: the mutate and Raw Exec dispatches below expect the packaged configuration not to
# gate them (HTTP 200). When the packaged Relay gates every mutate and Raw Exec (RC-37), they
# return 202 and this script fails naming the approval gate: the trace then needs an approval
# step added here.
#
# Secrets: strace runs with -s 0, which keeps no read or write buffer content, and its raw log
# stays in a root-only directory that is never uploaded. <outdir> holds only derived files
# (the syscall names and the report), which carry no secret.
set -euo pipefail

usage() {
  echo "usage: $0 <pkgdir> <outdir>   (absolute paths; run as root)" >&2
  exit 2
}
[ "$#" -eq 2 ] || usage
PKGDIR=$1 OUT=$2
case "$PKGDIR" in /*) ;; *) usage ;; esac
case "$OUT" in /*) ;; *) usage ;; esac
if [ "$(id -u)" -ne 0 ] || [ ! -d /run/systemd/system ]; then
  echo "install-matrix-vm-trace: must run as root on a host where systemd is running" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
ROW="$SCRIPT_DIR/install-matrix-row.sh"
SHIPPED_UNIT="$REPO/daemon/packaging/relay-daemon.service"
INSTALLED_UNIT=/usr/lib/systemd/system/relay-daemon.service
RELAY_TOML=/etc/relay/relay.toml
CA_CERT=/var/lib/relay/ca/ca-cert.pem
API_HEADER=/root/install-matrix/api-header
FIXTURE_HOST=relay-matrix.test
CAPCHECK=/etc/relay-trace-capcheck
CAPCHECK_LINE=relay-trace-capability-ok
DUMMY_UNIT=relay-trace-dummy.service
SELECTOR='tag:env=matrix'

export DEBIAN_FRONTEND=noninteractive
umask 022
install -d -m 0755 "$OUT"
RAW="$(mktemp -d /root/vm-trace.XXXXXX)"

# The derived files hold no secret and the runner user uploads them: make them readable
# whatever the umask was. Any non-zero exit with no report yet (a setup step failing under
# `set -e`) writes the minimal one, so the human always has a report.md saying the run stopped.
publish_outputs() {
  local status=$?
  if [ "$status" -ne 0 ] && [ ! -e "$OUT/report.md" ]; then
    {
      echo "# relay-daemon syscall trace, packaged unit ($(uname -m))"
      echo
      echo "**Result: FAIL.** The run stopped before the trace (exit status $status); the job log names the step."
    } >"$OUT/report.md"
  fi
  chmod 0755 "$OUT"
  find "$OUT" -type f -exec chmod 0644 {} +
}
trap publish_outputs EXIT

fail_reasons=()
fail() { fail_reasons+=("$1"); echo "FAIL $1"; }

# abort_with_report <reason>: a run that stops before the trace still leaves the report the
# human reads at sign-off, saying where and why it stopped.
abort_with_report() {
  fail "$1"
  {
    echo "# relay-daemon syscall trace, packaged unit ($(uname -m))"
    echo
    echo "**Result: FAIL.** The run stopped before the trace: $1"
  } >"$OUT/report.md"
  exit 1
}

# --- setup ------------------------------------------------------------------------------

apt-get update
apt-get install -y strace jq

new_debs=()
for name in relay-daemon relay-read relay; do
  for f in "$PKGDIR/new/${name}_"*.deb; do
    if [ -e "$f" ]; then new_debs+=("$f"); break; fi
  done
done
[ "${#new_debs[@]}" -ge 2 ] || { echo "install-matrix-vm-trace: no new .deb set under $PKGDIR/new" >&2; exit 1; }
apt-get install -y "${new_debs[@]}"

# The generated relay.toml carries this VM's own name or none. The trace needs a name the
# daemon dials, so the hostname line is rewritten in place, keeping the owner and mode the
# package placed.
tmp="$(mktemp /etc/relay/.relay-trace.XXXXXX)"
sed -E "s|^#? *hostname = \".*\"\$|hostname = \"$FIXTURE_HOST\"|" "$RELAY_TOML" >"$tmp"
chown root:relay "$tmp"
chmod 0640 "$tmp"
mv -f "$tmp" "$RELAY_TOML"
grep -qx "hostname = \"$FIXTURE_HOST\"" "$RELAY_TOML"
echo "127.0.0.1 $FIXTURE_HOST" >>/etc/hosts

systemctl start relay

api_host() { sed -n 's/^hostname = "\(.*\)"$/\1/p' "$RELAY_TOML" | head -n 1; }

wait_api() {
  local i code
  for ((i = 0; i < ${1:-60}; i++)); do
    if [ -f "$CA_CERT" ]; then
      code="$(curl -sS -o /dev/null --connect-timeout 1 --max-time 5 -w '%{http_code}' \
        --cacert "$CA_CERT" --resolve "$FIXTURE_HOST:9443:127.0.0.1" \
        "https://$FIXTURE_HOST:9443/api/v1/ping" 2>/dev/null || true)"
      if [ -n "$code" ] && [ "$code" != 000 ]; then return 0; fi
    fi
    sleep 1
  done
  return 1
}
wait_api 90 || abort_with_report "the Relay's Control API never answered"

# The join phase is reused, not reimplemented: it is self-contained and needs only the inputs
# set up above. It leaves the API header this script uses for every dispatch below.
PKG_ROOT="$PKGDIR" ROW_FAMILY=deb bash "$ROW" join || abort_with_report "the join phase failed; its log above names the claim or precondition"

# --- the unit is the shipped one ----------------------------------------------------------

unit_cmp="differs"
if cmp -s "$INSTALLED_UNIT" "$SHIPPED_UNIT"; then
  unit_cmp="identical"
else
  fail "the installed unit differs from daemon/packaging/relay-daemon.service"
fi

# --- dispatch helper ------------------------------------------------------------------------

API_STATUS=""
API_BODY=""
vm_api() {
  local method=$1 path=$2 body=${3:-} host out args
  host="$(api_host)"
  args=(-sS --max-time 120 --cacert "$CA_CERT" --resolve "$host:9443:127.0.0.1"
    -X "$method" -H "@$API_HEADER" -w $'\n%{http_code}')
  if [ -n "$body" ]; then args+=(-H 'Content-Type: application/json' -d "$body"); fi
  out="$(curl "${args[@]}" "https://$host:9443$path" 2>/dev/null || true)"
  API_STATUS=${out##*$'\n'}
  case "$out" in
    *$'\n'*) API_BODY=${out%$'\n'*} ;;
    *) API_BODY="" ;;
  esac
  if [ -z "$API_STATUS" ]; then API_STATUS=000; fi
}

op_rows=()
LAST_STDOUT=""

# dispatch <label> <success|failure> <path> <json body> [stderr regex]: 200 records the Task
# outcome; 202 fails naming the approval gate; any other status fails with the status. `failure`
# means the Task outcome is exactly "failure", not merely "not success": a denied_by_policy,
# timeout or unreachable result says the Operation never ran, so it proves nothing about the
# sandbox. The optional regex (jq, case-insensitive) must also match the first result's stderr.
dispatch() {
  local label=$1 expect=$2 path=$3 body=$4 stderr_re=${5:-} outcomes detail="" ok=no
  LAST_STDOUT=""
  vm_api POST "$path" "$body"
  case "$API_STATUS" in
    200) ;;
    202)
      fail "the approval gate parked $label: the packaged config gates this Operation (see RC-37), so the trace needs an approval step"
      op_rows+=("| $label | $expect | parked by the approval gate (202) | FAIL |")
      return 0
      ;;
    *)
      fail "$label: HTTP $API_STATUS"
      op_rows+=("| $label | $expect | HTTP $API_STATUS | FAIL |")
      return 0
      ;;
  esac
  outcomes="$(printf '%s' "$API_BODY" | jq -r '[.results[].outcome] | join(",")' || true)"
  LAST_STDOUT="$(printf '%s' "$API_BODY" | jq -r '.results[0].stdout // ""' || true)"
  if [ "$expect" = success ]; then
    if printf '%s' "$API_BODY" | jq -e '(.results | length) > 0 and all(.results[]; .outcome == "success")' >/dev/null; then
      ok=yes
    fi
  else
    # Recorded verbatim for the human: the outcome and the first of stderr.
    detail="$(printf '%s' "$API_BODY" | jq -r '.results[0].stderr // "" | .[0:300] | gsub("[|\n\r]"; " ")' || true)"
    if printf '%s' "$API_BODY" | jq -e '(.results | length) > 0 and all(.results[]; .outcome == "failure")' >/dev/null; then
      ok=yes
    fi
    if [ "$ok" = yes ] && [ -n "$stderr_re" ] \
      && ! printf '%s' "$API_BODY" | jq -e --arg re "$stderr_re" 'all(.results[]; (.stderr // "") | test($re; "i"))' >/dev/null; then
      ok=no
    fi
  fi
  if [ "$ok" = yes ]; then
    op_rows+=("| $label | $expect | $outcomes $detail | ok |")
  else
    fail "$label: wanted $expect, got $outcomes"
    op_rows+=("| $label | $expect | $outcomes $detail | FAIL |")
  fi
}

op() { printf '{"selector":"%s","operation":"%s"}' "$SELECTOR" "$1"; }
op_args() { printf '{"selector":"%s","operation":"%s","args":%s}' "$SELECTOR" "$1" "$2"; }

wait_facts() {
  local i
  for ((i = 0; i < ${1:-60}; i++)); do
    vm_api POST /api/v1/operations "$(op system.facts)"
    if [ "$API_STATUS" = 200 ] \
      && printf '%s' "$API_BODY" | jq -e '(.results | length) > 0 and all(.results[]; .outcome == "success")' >/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# --- fixtures ---------------------------------------------------------------------------------

cat >/etc/systemd/system/$DUMMY_UNIT <<'EOF'
[Unit]
Description=Relay install-matrix trace dummy

[Service]
Type=oneshot
ExecStart=/bin/true
RemainAfterExit=yes
EOF
systemctl daemon-reload

# The capability fixture: a file the daemon's own uid-0 permission bits cannot read, only
# CAP_DAC_READ_SEARCH can (docs/operations/daemon-privilege-posture.md, Verification step 3).
printf '%s\n' "$CAPCHECK_LINE" >"$CAPCHECK"
chown nobody:nogroup "$CAPCHECK"
chmod 0600 "$CAPCHECK"

install -d -m 0755 /etc/relay-daemon/policy.d
cat >/etc/relay-daemon/policy.d/90-vm-trace.toml <<EOF
[[operation]]
name = "service.restart"
allowed_args = [["$DUMMY_UNIT"]]

[[operation]]
name = "pkg.install"
# Exactly `hello`, unversioned: the daemon sends "" as the version when none is requested.
allowed_args = [["hello"], [""]]

[raw_exec]
allow = ["^/usr/bin/true\$"]
EOF
chmod 0644 /etc/relay-daemon/policy.d/90-vm-trace.toml

# Policy loads at start (DI-15).
systemctl restart relay-daemon
wait_facts 90 || abort_with_report "the Node never came back online after the Policy fragment"

# --- attach the trace ---------------------------------------------------------------------------

pid="$(systemctl show -p MainPID --value relay-daemon)"
[ -n "$pid" ] && [ "$pid" != 0 ] || abort_with_report "relay-daemon has no main PID"
seccomp_mode="$(awk '/^Seccomp:/ {print $2}' "/proc/$pid/status")"
no_new_privs="$(awk '/^NoNewPrivs:/ {print $2}' "/proc/$pid/status")"
cap_bnd="$(awk '/^CapBnd:/ {print $2}' "/proc/$pid/status")"
[ "$seccomp_mode" = 2 ] || fail "Seccomp is '$seccomp_mode', not 2: the unit's SystemCallFilter is not in force"
[ "$no_new_privs" = 1 ] || fail "NoNewPrivs is '$no_new_privs', not 1"
# DI-3: the bounding set is CAP_DAC_READ_SEARCH (capability 2, mask 0x4) and nothing else, so any
# extra or missing capability fails. capsh, where installed, decodes the mask for the report.
cap_bnd_want=0000000000000004
cap_bnd_decoded="$cap_bnd"
if command -v capsh >/dev/null 2>&1 && [ -n "$cap_bnd" ]; then
  cap_bnd_decoded="$(capsh --decode="$cap_bnd" 2>/dev/null | sed 's/^[^=]*=//')"
fi
[ "$cap_bnd" = "$cap_bnd_want" ] || fail "CapBnd is '$cap_bnd' ($cap_bnd_decoded), not $cap_bnd_want (CAP_DAC_READ_SEARCH only): the unit's CapabilityBoundingSet is not in force"

strace -f -qq -s 0 -o "$RAW/trace.log" -p "$pid" &
strace_pid=$!
sleep 2

# Connect: the daemon redials the Relay (TLS, tunnel) while it is traced.
systemctl restart relay
wait_facts 120 || fail "no system.facts dispatch succeeded after the Relay restarted"

# --- execute --------------------------------------------------------------------------------------

dispatch system.facts success /api/v1/operations "$(op system.facts)"
dispatch "file.read /etc/hostname" success /api/v1/operations "$(op_args file.read '{"path":"/etc/hostname"}')"
dispatch proc.list success /api/v1/operations "$(op proc.list)"
dispatch disk.usage success /api/v1/operations "$(op disk.usage)"
dispatch net.listening success /api/v1/operations "$(op net.listening)"
dispatch pkg.inventory success /api/v1/operations "$(op pkg.inventory)"
dispatch "service.status $DUMMY_UNIT" success /api/v1/operations "$(op_args service.status "{\"unit\":\"$DUMMY_UNIT\"}")"
dispatch "log.tail $DUMMY_UNIT" success /api/v1/operations "$(op_args log.tail "{\"unit\":\"$DUMMY_UNIT\"}")"
dispatch "file.checksum /etc/hostname" success /api/v1/operations "$(op_args file.checksum '{"path":"/etc/hostname"}')"

dispatch "file.read $CAPCHECK (capability confirmation)" success /api/v1/operations \
  "$(op_args file.read "{\"path\":\"$CAPCHECK\"}")"
cap_row="ok"
if [[ $LAST_STDOUT != *"$CAPCHECK_LINE"* ]]; then
  cap_row="FAIL"
  fail "file.read of $CAPCHECK did not return its content: CAP_DAC_READ_SEARCH is not doing its work"
fi

dispatch "service.restart $DUMMY_UNIT" success /api/v1/operations \
  "$(op_args service.restart "{\"unit\":\"$DUMMY_UNIT\"}")"
dispatch "raw exec /usr/bin/true" success /api/v1/raw-exec \
  "$(printf '{"selector":"%s","argv":["/usr/bin/true"]}' "$SELECTOR")"
# The posture document says pkg.install succeeds only under the pkg-install drop-in, never
# under the strict baseline. The row passes only when the Operation ran and failed (outcome
# "failure") and its stderr shows the sandbox refusing a write under the package manager's
# state: a policy denial or an unreachable Node would otherwise read as a held sandbox.
dispatch "pkg.install hello (strict unit)" failure /api/v1/operations \
  "$(op_args pkg.install '{"name":"hello"}')" \
  '(/var/lib/dpkg|/var/cache/apt|/var/lib/apt).*(read-only file system|permission denied)|(read-only file system|permission denied).*(/var/lib/dpkg|/var/cache/apt|/var/lib/apt)'

kill -INT "$strace_pid" 2>/dev/null || true
wait "$strace_pid" 2>/dev/null || true

# --- compare with the filter ------------------------------------------------------------------------

# The posture document's `[a-z_]` would drop wait4, pipe2, dup3, clone3 and accept4.
sed -nE 's/^([0-9]+ +)?([a-z0-9_]+)\(.*/\2/p' "$RAW/trace.log" | sort -u >"$OUT/syscalls.txt"

declare -A visited=()
# expand_group <@group>: every syscall the group allows, groups expanded recursively. The
# tool prints a colour reset before each group name even when not on a terminal, so those
# escape sequences are stripped.
expand_group() {
  local g=$1 line tok
  if [ -n "${visited[$g]:-}" ]; then return 0; fi
  visited[$g]=1
  while IFS= read -r line; do
    line=${line%%#*}
    tok=""
    read -r tok _ <<<"$line" || true
    [ -n "$tok" ] || continue
    case "$tok" in
      @*) expand_group "$tok" ;;
      *) printf '%s\n' "${tok%%:*}" ;;
    esac
  done < <(systemd-analyze syscall-filter "$g" | sed 's/\x1b\[[0-9;]*m//g')
}
expand_group @system-service | sort -u >"$RAW/allowed.txt"
[ -s "$RAW/allowed.txt" ] || fail "could not expand systemd's @system-service syscall set"

comm -23 "$OUT/syscalls.txt" "$RAW/allowed.txt" >"$OUT/out-of-filter.txt"
if [ -s "$OUT/out-of-filter.txt" ]; then
  fail "syscalls outside @system-service: $(tr '\n' ' ' <"$OUT/out-of-filter.txt")"
fi
[ -s "$OUT/syscalls.txt" ] || fail "the trace recorded no syscalls"

n_restarts="$(systemctl show -p NRestarts --value relay-daemon)"
if [ "${n_restarts:-0}" -gt 0 ]; then fail "relay-daemon restarted $n_restarts time(s) during the trace"; fi
journal="$(journalctl -u relay-daemon -b --no-pager 2>&1 || true)"
sigsys="none"
if grep -qE 'SIGSYS|status=31' <<<"$journal"; then
  sigsys="MATCHED"
  fail "this boot's relay-daemon journal records SIGSYS"
fi

# --- report -------------------------------------------------------------------------------------------

{
  echo "# relay-daemon syscall trace, packaged unit ($(uname -m))"
  echo
  echo "- kernel: $(uname -r)"
  echo "- systemd: $(systemctl --version | head -n 1)"
  echo "- packages: $(dpkg-query -W -f '${Package} ${Version}; ' relay-daemon relay-read relay 2>/dev/null)"
  echo "- installed unit vs daemon/packaging/relay-daemon.service: $unit_cmp"
  echo "- Seccomp: $seccomp_mode (want 2); NoNewPrivs: $no_new_privs (want 1); CapBnd: $cap_bnd, decoded $cap_bnd_decoded (want $cap_bnd_want, CAP_DAC_READ_SEARCH only)"
  echo "- NRestarts at the end: ${n_restarts:-0}; SIGSYS in this boot's journal: $sigsys"
  echo
  echo "## Operations"
  echo
  echo "| Operation | Expected | Outcome | Result |"
  echo "|---|---|---|---|"
  printf '%s\n' "${op_rows[@]}"
  echo "| capability confirmation (content returned) | $CAPCHECK_LINE | | $cap_row |"
  echo
  echo "## Syscalls"
  echo
  echo "Traced: $(wc -l <"$OUT/syscalls.txt") distinct syscalls. Outside @system-service (expected none): $(wc -l <"$OUT/out-of-filter.txt")."
  echo
  if [ -s "$OUT/out-of-filter.txt" ]; then
    echo "Outside the filter:"
    echo
    sed 's/^/- /' "$OUT/out-of-filter.txt"
    echo
  fi
  echo "<details><summary>Every traced syscall</summary>"
  echo
  echo '```'
  cat "$OUT/syscalls.txt"
  echo '```'
  echo
  echo "</details>"
  echo
  if [ "${#fail_reasons[@]}" -eq 0 ]; then
    echo "**Result: pass.**"
  else
    echo "**Result: FAIL.**"
    echo
    printf -- '- %s\n' "${fail_reasons[@]}"
  fi
} >"$OUT/report.md"

cat "$OUT/report.md"
[ "${#fail_reasons[@]}" -eq 0 ]
