#!/usr/bin/env bash
# Runs the relay_daemon Ansible role against a systemd container Node and a real Relay, and
# proves the join string reaches no file, argument list or log on the Node
# (docs/specs/daemon-installation.md DI-45).
#
#   install-matrix-ansible-role.sh <pkgdir>
#
# <pkgdir> is absolute and holds old/, new/ and VERSION as the install-matrix workflow's build
# job lays them out, the old package sorting below the new one. Needs docker, ansible-playbook,
# ansible-vault, jq, ssh-keygen, dpkg-deb, base64, head and grep on the runner. Nothing here runs outside CI: it starts a privileged
# container and installs packages in it.
#
# One Debian 13 container runs the Relay and the Node. The role reaches the Node over ssh and
# sudo from the runner, so the Node is the role's own target. Four runs follow:
#   A  the old package, pipelining forced off: the role installs it, then its guard must refuse
#      before the join task writes anything;
#   L  a sudoers drop-in sets log_input: the role must refuse before the join task, then the
#      drop-in is removed;
#   B  the second run on that Node, given the new package: the role leaves the installed
#      daemon at the old version and joins;
#   C  the enrolled Node again, given the new package: the role changes nothing.
# A strace on the ssh daemon records every execve and every write on the Node's ssh side from
# before the first connection, so a transient file Ansible would delete is still seen.
#
# Secrets. The join string (JOIN), the Enrollment Token (TOKEN) and the API token (API_TOKEN)
# live only in this shell's variables. A secret reaches another process only through the printf
# builtin into a pipe, as standard input, or as a pattern file through process substitution; it
# is never an argv element on the runner or on the Node. The one other output is the echo builtin
# of the runner's add-mask command, which hides the value in this job's log from then on. The
# only files that hold one are the encrypted vault file and the strace trace (the positive control reads the join string in it),
# both inside a 0700 directory that the EXIT trap deletes. NEVER add `set -x`.
#
# Every assertion prints "ok   ID description" or "FAIL ID description", where ID is the spec
# claim it is evidence for. A `precondition` failure ends the script at once. The container is
# always removed. On failure the journal, the failed units and the run logs are printed; the
# vault file, the vault password, the ssh key and the trace never are.
set -euo pipefail

NAME=relay-ansible-role
IMAGE=relay-install-matrix:debian-13
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CA_CERT=/var/lib/relay/ca/ca-cert.pem
DAEMON_STATE=/var/lib/relay-daemon
ROLE_DIR="$REPO/daemon/packaging/ansible"

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <pkgdir>" >&2
  exit 2
fi
PKGDIR=$1
case "$PKGDIR" in /*) ;; *) echo "install-matrix-ansible-role: pkgdir must be absolute" >&2; exit 2 ;; esac
for tool in docker ansible-playbook ansible-vault jq ssh-keygen dpkg-deb base64 head grep; do
  command -v "$tool" >/dev/null 2>&1 || { echo "install-matrix-ansible-role: $tool is required" >&2; exit 2; }
done

FAILS=0
WORK=""
HOST=""
IP=""
JOIN=""
TOKEN=""
API_TOKEN=""
PATTERNS=()
PLAY_RC=0
API_STATUS=""
API_BODY=""

node() { docker exec "$NAME" "$@"; }
node_i() { docker exec -i "$NAME" "$@"; }

# --- assertion helpers (copied from install-matrix-row.sh, which is not sourceable) -------

# check <CLAIM-ID> <description> <command...>: the command's own output is left in the log.
check() {
  local id=$1 desc=$2
  shift 2
  if "$@"; then
    echo "ok   $id $desc"
  else
    echo "FAIL $id $desc"
    FAILS=$((FAILS + 1))
  fi
}

# precondition <description> <command...>: a failure ends the script now.
precondition() {
  local desc=$1
  shift
  if ! "$@"; then
    echo "FAIL precondition $desc"
    exit 1
  fi
}

# --- the container -----------------------------------------------------------------------

# wait_boot: systemd reaches `running` or `degraded`, within about five minutes.
wait_boot() {
  local state="" deadline=$((SECONDS + 240))
  while ((SECONDS < deadline)); do
    state="$(docker exec "$NAME" timeout 60 systemctl is-system-running --wait 2>&1 || true)"
    case "$state" in
      running) return 0 ;;
      degraded)
        echo "systemd is degraded; failed units:"
        node systemctl --failed --no-pager || true
        return 0
        ;;
    esac
    sleep 3
  done
  echo "install-matrix-ansible-role: systemd never reached running or degraded (last answer: $state)" >&2
  return 1
}

# diagnostics: everything a failure needs, and none of the files that hold a secret.
diagnostics() {
  echo "::group::diagnostics"
  node systemctl --failed --no-pager || true
  node journalctl -b --no-pager -n 200 || true
  if [ -n "$WORK" ]; then
    local log
    for log in run-a.log run-l.log run-b.log run-c.log; do
      if [ -f "$WORK/$log" ]; then
        echo "--- $log"
        cat "$WORK/$log"
      fi
    done
  fi
  echo "::endgroup::"
}

on_exit() {
  local rc=$?
  trap - EXIT
  set +e
  if [ "$rc" -ne 0 ]; then diagnostics; fi
  node rm -f /trace/exec.trace >/dev/null 2>&1
  docker rm -f "$NAME" >/dev/null 2>&1
  if [ -n "$WORK" ]; then rm -rf "$WORK"; fi
  exit "$rc"
}

# --- the Relay's Control API, reached from inside the container ---------------------------
# The Control API listens on 127.0.0.1 only, so every call runs inside the container. The
# bearer header reaches curl on standard input, never argv.

relay_host() { node sed -n 's/^hostname = "\(.*\)"$/\1/p' /etc/relay/relay.toml | head -n 1; }

# api_code prints the HTTP status of an unauthenticated ping, 000 when nothing answers.
api_code() {
  node curl -sS -o /dev/null --connect-timeout 1 --max-time 5 -w '%{http_code}' \
    --cacert "$CA_CERT" --resolve "$HOST:9443:127.0.0.1" "https://$HOST:9443/api/v1/ping" 2>/dev/null || true
}

api_answers_within_60s() {
  local i code
  for ((i = 0; i < 60; i++)); do
    code=$(api_code)
    if [ -n "$code" ] && [ "$code" != 000 ]; then return 0; fi
    sleep 1
  done
  return 1
}

# relay_api <method> <path> [json body]: sets API_STATUS and API_BODY. Called directly, never in
# a command substitution. The response stays in memory.
relay_api() {
  local method=$1 path=$2 body=${3:-} out
  local args=(-sS --max-time 60 --cacert "$CA_CERT" --resolve "$HOST:9443:127.0.0.1"
    -X "$method" -H @- -w $'\n%{http_code}')
  if [ -n "$body" ]; then args+=(-H 'Content-Type: application/json' -d "$body"); fi
  out=$(printf 'Authorization: Bearer %s\n' "$API_TOKEN" | node_i curl "${args[@]}" "https://$HOST:9443$path" 2>/dev/null) || true
  API_STATUS=${out##*$'\n'}
  case "$out" in
    *$'\n'*) API_BODY=${out%$'\n'*} ;;
    *) API_BODY="" ;;
  esac
  if [ -z "$API_STATUS" ]; then API_STATUS=000; fi
  return 0
}

# --- scans -------------------------------------------------------------------------------

# count_patterns: how many lines on standard input hold any of PATTERNS.
count_patterns() { grep -acF -f <(printf '%s\n' "${PATTERNS[@]}") || true; }

# node_scan_files: patterns on standard input; prints the name of every file on the Node that
# holds one. Never -I, so a secret in a binary file still matches. /proc, /sys and /dev are
# not files in this sense, and /trace is the runner's own trace of this test.
node_scan_files() {
  node_i bash -c '
mapfile -t p
shopt -s dotglob nullglob
roots=()
for e in /*; do
  case "$e" in /proc | /sys | /dev | /trace) ;; *) roots+=("$e") ;; esac
done
roots+=(/dev/shm)
grep -rlF -D skip --no-messages -f <(printf "%s\n" "${p[@]}") -- "${roots[@]}" || true
'
}

# node_journal_matches: patterns on standard input; exits 0 when the journal holds one.
node_journal_matches() {
  node_i bash -c '
mapfile -t p
journalctl -b -o export --no-pager | grep -aqF -f <(printf "%s\n" "${p[@]}")
'
}

# trace_lines <exec|filewrite|pipewrite|filecopy>: the trace's lines of one kind. A line is
# "PID  syscall(...)", and strace -y annotates an fd that is a file as <path>, so a file write
# is a write whose fd annotation starts with a slash. A pipe, a socket and an anonymous inode
# do not. An <unfinished ...> line still carries its buffer. filecopy is a call that moves bytes
# between descriptors without a buffer in the line (sendfile, splice, copy_file_range), so the
# bytes cannot be read and the descriptors are judged: a failure is a destination that is a file
# and a source that is a pipe, a socket or an anonymous inode, which is how a secret from
# another process would reach a file. A file-to-file copy is not one: cat in a package's
# maintainer script makes them. Argument order differs: sendfile(out_fd, in_fd, ...) names the
# destination first; splice and copy_file_range (fd_in, off_in, fd_out, off_out, ...) the source
# first and the destination third.
trace_lines() {
  local trace="$WORK/trace/exec.trace"
  case "$1" in
    exec) grep -aE '^[0-9]+ +(execve|execveat)\(' "$trace" || true ;;
    filewrite)
      grep -aE '^[0-9]+ +(write|writev|pwrite64|pwritev|pwritev2)\([0-9]+</' "$trace" \
        | grep -avE '\([0-9]+</dev/(null|ptmx|tty[0-9]*|pts/[0-9]+)>' || true
      ;;
    pipewrite) grep -aE '^[0-9]+ +(write|writev)\([0-9]+<pipe:' "$trace" || true ;;
    filecopy)
      local file='[0-9]+</[^>]*>' stream='[0-9]+<(pipe|socket|anon_inode):[^>]*>'
      local device='[0-9]+</dev/(null|ptmx|tty[0-9]*|pts/[0-9]+)>' offset='[^,]*'
      grep -aE -e "^[0-9]+ +sendfile\\($file, $stream" \
        -e "^[0-9]+ +(splice|copy_file_range)\\($stream, $offset, $file" "$trace" \
        | grep -avE -e "^[0-9]+ +sendfile\\($device, " \
          -e "^[0-9]+ +(splice|copy_file_range)\\([^,]*, $offset, $device," || true
      ;;
  esac
}

# --- runs --------------------------------------------------------------------------------

# play <log> <pkg subdirectory> [extra ansible-playbook args]: the exit status is PLAY_RC. The
# vault file and password file are inside WORK; the join string reaches Ansible only through
# the vault.
play() {
  local log=$1 sub=$2
  shift 2
  PLAY_RC=0
  ansible-playbook -i "$WORK/inventory.ini" --vault-password-file "$WORK/vault-pass" \
    -e @"$WORK/vault.yml" -e "relay_daemon_package_dir=$PKGDIR/$sub" "$@" \
    "$ROLE_DIR/test/playbook.yml" >"$WORK/$log" 2>&1 || PLAY_RC=$?
}

recap() { grep -E '^node +: ok=' "$WORK/$1" || true; }

# recap_has <log> <fragment...>: the recap line holds every fragment.
recap_has() {
  local line frag
  line=$(recap "$1")
  shift
  for frag in "$@"; do
    [[ $line == *"$frag"* ]] || { echo "recap '$line' lacks '$frag'"; return 1; }
  done
}

log_has() { grep -qF -- "$2" "$WORK/$1"; }

# run_succeeded <log> <fragment...>: the last play exited 0 and its recap holds every fragment.
run_succeeded() {
  local log=$1
  shift
  [ "$PLAY_RC" -eq 0 ] || { echo "ansible-playbook exited $PLAY_RC"; return 1; }
  recap_has "$log" "$@"
}

# run_a_hit_the_guard: run A ended unreachable, not failed, on the role's remote_tmp guard, so
# the refusal cannot be some other error.
run_a_hit_the_guard() {
  recap_has run-a.log ' unreachable=1 ' ' failed=0 ' \
    && log_has run-a.log 'Failed to create temporary directory' \
    && log_has run-a.log '/dev/null/relay-daemon-role-stages-nothing'
}

# run_l_refused_sudo_input_logging: run L failed, not unreachable, with the role's own refusal.
run_l_refused_sudo_input_logging() {
  [ "$PLAY_RC" -ne 0 ] || { echo "ansible-playbook exited 0"; return 1; }
  recap_has run-l.log ' unreachable=0 ' ' failed=1 ' \
    && log_has run-l.log 'sudo records the standard input of privileged commands'
}

# run_l_stopped_before_the_join_task: the join task's name never appears in run L's output, and
# the trace holds no execution of join so far.
run_l_stopped_before_the_join_task() {
  ! log_has run-l.log 'relay-daemon join reads the join string' \
    && [ "$(trace_lines exec | grep -acF 'execve("/usr/bin/relay-daemon", ["/usr/bin/relay-daemon", "join"]' || true)" = 0 ]
}

# printenv_exec_count: how many times the role's check has run `printenv SUDO_USER` on the Node
# so far (the trace is line-buffered).
printenv_exec_count() { trace_lines exec | grep -acF '"printenv", "SUDO_USER"' || true; }

# the_trace_saw_run_l: the trace holds more of the role's checks than before run L, so the empty
# join list in run L is not a trace that stopped recording. Polls for up to 10s.
the_trace_saw_run_l() {
  local i
  for ((i = 0; i < 10; i++)); do
    if [ "$(printenv_exec_count)" -gt "$PRINTENV_BEFORE_L" ]; then return 0; fi
    sleep 1
  done
  return 1
}

sudo_drop_in_is_valid() { node visudo -cf /etc/sudoers.d/zz-log-input; }

# --- assertions --------------------------------------------------------------------------

daemon_identity_files() {
  grep -o 'IDENTITY_FILES: \[&str; [0-9]*\] = \[[^]]*\]' "$REPO/daemon/src/config.rs" \
    | grep -o '"[^"]*"' | tr -d '"' | paste -sd,
}

role_identity_files() {
  sed -n 's/^relay_daemon_identity_files: \[\(.*\)\]$/\1/p' "$ROLE_DIR/relay_daemon/vars/main.yml" | tr -d ' '
}

identity_lists_are_equal() {
  local daemon role
  daemon=$(daemon_identity_files)
  role=$(role_identity_files)
  [ -n "$daemon" ] && [ "$daemon" = "$role" ] || { echo "daemon '$daemon', role '$role'"; return 1; }
}

# deb_in <dir> <name>: the amd64 .deb files for that package name.
deb_in() {
  local f
  for f in "$1/$2_"*"_amd64.deb"; do
    if [ -e "$f" ]; then printf '%s\n' "$f"; fi
  done
}

exactly_one_deb() { [ "$(deb_in "$1" "$2" | wc -l)" -eq 1 ]; }

join_string_has_its_prefix() { [[ $JOIN == glp_join_* ]]; }

package_is_installed() { [ "$(node dpkg-query -W -f '${db:Status-Status}' relay-daemon 2>/dev/null || true)" = installed ]; }

node_has_no_identity() {
  local f
  for f in key.pem cert.pem ca_bundle.pem node_id; do
    if node test -e "$DAEMON_STATE/$f"; then echo "unexpected $f"; return 1; fi
  done
}

node_has_identity() {
  local f
  for f in key.pem cert.pem ca_bundle.pem node_id; do
    node test -f "$DAEMON_STATE/$f" || { echo "missing $f"; return 1; }
  done
}

daemon_versions_differ() {
  local old new
  old=$(dpkg-deb -f "$OLD_DAEMON_DEB" Version)
  new=$(dpkg-deb -f "$NEW_DAEMON_DEB" Version)
  [ -n "$old" ] && [ -n "$new" ] && [ "$old" != "$new" ]
}

# installed_version_is_the_old_one: no run replaced the daemon run A installed, though runs B and
# C were given a different package. A role that installed over it would have left the new one.
installed_version_is_the_old_one() {
  local want got
  want=$(dpkg-deb -f "$OLD_DAEMON_DEB" Version)
  got=$(node dpkg-query -W -f '${Version}' relay-daemon)
  [ -n "$want" ] && [ "$got" = "$want" ] || { echo "installed '$got', first run supplied '$want'"; return 1; }
}

unit_becomes_active_and_enabled() {
  local i
  for ((i = 0; i < 30; i++)); do
    if node systemctl is-active --quiet relay-daemon \
      && [ "$(node systemctl is-enabled relay-daemon 2>/dev/null || true)" = enabled ]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

policy_dir_is_empty() {
  node test -d /etc/relay-daemon/policy.d && [ -z "$(node find /etc/relay-daemon/policy.d -mindepth 1)" ]
}

trace_file_exists_within_10s() {
  local i
  for ((i = 0; i < 10; i++)); do
    if [ -e "$WORK/trace/exec.trace" ]; then return 0; fi
    sleep 1
  done
  return 1
}

tracer_has_stopped() {
  local i
  for ((i = 0; i < 10; i++)); do
    if ! node pgrep -x strace >/dev/null; then return 0; fi
    sleep 1
  done
  return 1
}

# node_snapshot: hashes and a version are not secret.
node_snapshot() {
  node bash -c '
find /etc/relay-daemon /var/lib/relay-daemon -type f -print0 | sort -z | xargs -0 sha256sum
dpkg-query -W -f "\${Version}\n" relay-daemon
systemctl show -p MainPID --value relay-daemon
'
}

join_exec_count_is_one() {
  local all join
  all=$(trace_lines exec | grep -acF 'execve("/usr/bin/relay-daemon", ' || true)
  join=$(trace_lines exec | grep -acF 'execve("/usr/bin/relay-daemon", ["/usr/bin/relay-daemon", "join"], ' || true)
  [ "$all" = 1 ] && [ "$join" = 1 ] || { echo "relay-daemon execs: $all, of which join: $join"; return 1; }
}

join_string_was_piped() {
  local n
  n=$(trace_lines pipewrite | grep -acF -f <(printf '%s\n' "$JOIN") || true)
  [ "$n" -gt 0 ]
}

# the_trace_saw_the_role_stage_a_file: some write went to a file under Ansible's temporary
# directory (the package is copied there), so an empty file-write list cannot be a trace that
# recorded nothing.
the_trace_saw_the_role_stage_a_file() {
  [ "$(trace_lines filewrite | grep -acF '/ansible-tmp-' || true)" -gt 0 ]
}

trace_has_no_copy_to_a_file() {
  local n
  n=$(trace_lines filecopy | wc -l)
  [ "$n" = 0 ] || { echo "$n sendfile, splice or copy_file_range calls move a pipe, socket or anonymous inode into a file"; return 1; }
}

trace_holds_no_secret() {
  local n
  n=$(trace_lines "$1" | count_patterns)
  [ "$n" = 0 ] || { echo "$n $1 lines hold a secret"; return 1; }
}

scan_finds_the_canary() {
  [ "$(printf '%s\n' "$CANARY" | node_scan_files)" = /var/tmp/relay-role-canary ]
}

no_file_holds_a_secret() {
  local found
  found=$(printf '%s\n' "${PATTERNS[@]}" | node_scan_files)
  [ -z "$found" ] || { echo "files that hold a secret:"; echo "$found"; return 1; }
}

journal_holds_invocations() { printf '%s\n' 'Invoked with' | node_journal_matches; }

# journal_holds_no_secret: grep's exit 1, which is "no match". Any other status (2, a failed
# docker exec) is a scan that did not run, not a clean journal.
journal_holds_no_secret() {
  local rc=0
  printf '%s\n' "${PATTERNS[@]}" | node_journal_matches || rc=$?
  [ "$rc" -eq 1 ] || { echo "the journal scan exited $rc, not 1"; return 1; }
}

run_logs_hold_no_secret() {
  local n
  n=$(cat "$WORK/run-a.log" "$WORK/run-l.log" "$WORK/run-b.log" "$WORK/run-c.log" | count_patterns)
  [ "$n" = 0 ] || { echo "$n run log lines hold a secret"; return 1; }
}

# --- step 0: checks that need no container ------------------------------------------------

check DI-45 "the role's identity file list equals the daemon's IDENTITY_FILES" identity_lists_are_equal
precondition "exactly one new relay package" exactly_one_deb "$PKGDIR/new" relay
precondition "exactly one new relay-daemon package" exactly_one_deb "$PKGDIR/new" relay-daemon
precondition "exactly one old relay-daemon package" exactly_one_deb "$PKGDIR/old" relay-daemon
NEW_RELAY_DEB=$(deb_in "$PKGDIR/new" relay)
OLD_DAEMON_DEB=$(deb_in "$PKGDIR/old" relay-daemon)
NEW_DAEMON_DEB=$(deb_in "$PKGDIR/new" relay-daemon)
precondition "the old and the new relay-daemon versions differ" daemon_versions_differ

# --- step 1: the container ----------------------------------------------------------------

WORK=$(mktemp -d "${RUNNER_TEMP:-/tmp}/ansible-role.XXXXXX")
chmod 700 "$WORK"
mkdir "$WORK/trace"
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

docker build --pull -t "$IMAGE" -f "$REPO/docker/install-matrix/debian-13.Dockerfile" "$REPO/docker/install-matrix"
# Only the Relay's package is mounted: the daemon package reaches the Node through the role.
docker run -d --name "$NAME" --hostname relay-matrix.test --cgroupns=host --privileged \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
  -v "$WORK/trace:/trace" -v "$NEW_RELAY_DEB:/pkgs/relay.deb:ro" "$IMAGE"
wait_boot
IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NAME")
precondition "the container has an IP address" [ -n "$IP" ]

# --- step 2: the Node's sshd and sudo, and the Relay --------------------------------------

node apt-get update -q
node apt-get install -y -q --no-install-recommends openssh-server sudo python3 python3-apt strace
# One long-lived sshd, so there is a process to trace.
node systemctl disable --now ssh.socket 2>/dev/null || true
node systemctl enable --now ssh.service
precondition "ssh.service is active" node systemctl is-active --quiet ssh.service
node useradd -m -s /bin/bash -p '*' ansible
printf 'ansible ALL=(ALL) NOPASSWD:ALL\n' | node_i bash -c 'cat >/etc/sudoers.d/ansible && chmod 0440 /etc/sudoers.d/ansible'
ssh-keygen -q -t ed25519 -N '' -f "$WORK/id"
node_i bash -c '
umask 077
install -d -m 0700 -o ansible -g ansible /home/ansible/.ssh
cat >/home/ansible/.ssh/authorized_keys
chown ansible:ansible /home/ansible/.ssh/authorized_keys
chmod 0600 /home/ansible/.ssh/authorized_keys
' <"$WORK/id.pub"

node apt-get install -y -q /pkgs/relay.deb
node systemctl start relay
HOST=$(relay_host)
precondition "relay.toml names a hostname" [ -n "$HOST" ]
precondition "the Control API answers within 60s" api_answers_within_60s

# --- step 3: the join string, only in the vault -------------------------------------------

PW=$(head -c 24 /dev/urandom | base64 | tr -d '/+=\n')
API_TOKEN=$(printf '%s\n' "$PW" | node_i runuser -u relay -- relay init --config /etc/relay/relay.toml --admin matrix --ttl 2h)
PW=""
precondition "relay init printed an API token" [ -n "$API_TOKEN" ]
echo "::add-mask::$API_TOKEN"
relay_api POST /api/v1/enrollment-tokens '{"initial_tags":["tag:env=role"],"ttl_seconds":3600,"max_uses":1}'
precondition "the Enrollment Token mint answered 201 (got $API_STATUS)" [ "$API_STATUS" = 201 ]
JOIN=$(printf '%s' "$API_BODY" | jq -r '.join_string // empty')
TOKEN=$(printf '%s' "$API_BODY" | jq -r '.token // empty')
API_BODY=""
# Masked before any precondition can print them, so no failure diagnostic shows either.
if [ -n "$JOIN" ]; then echo "::add-mask::$JOIN"; fi
if [ -n "$TOKEN" ]; then echo "::add-mask::$TOKEN"; fi
precondition "the mint response carried a join string" [ -n "$JOIN" ]
precondition "the mint response carried a token" [ -n "$TOKEN" ]
precondition "the join string starts with glp_join_" join_string_has_its_prefix
half=$((${#JOIN} / 2))
# The halves catch a write that splits the string across two syscalls.
PATTERNS=("$JOIN" "$TOKEN" "${JOIN:0:half}" "${JOIN:half}")

( umask 077; head -c 32 /dev/urandom | base64 >"$WORK/vault-pass" )
printf '%s' "$JOIN" | ansible-vault encrypt_string --vault-password-file "$WORK/vault-pass" \
  --stdin-name relay_daemon_join_string >"$WORK/vault.yml"
precondition "the vault file is non-empty" [ -s "$WORK/vault.yml" ]
precondition "the vault file holds neither secret in the clear" [ "$(count_patterns <"$WORK/vault.yml")" = 0 ]

# --- step 4: the controller ---------------------------------------------------------------

printf 'node ansible_host=%s ansible_user=ansible ansible_ssh_private_key_file=%s ansible_python_interpreter=/usr/bin/python3 ansible_ssh_common_args=%s\n' \
  "$IP" "$WORK/id" "'-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'" >"$WORK/inventory.ini"
# Pipelining and keep_remote_files are never set here, and no -v is ever passed: the role must
# force pipelining itself.
export ANSIBLE_ROLES_PATH="$ROLE_DIR" ANSIBLE_NOCOLOR=1 ANSIBLE_HOME="$WORK/ansible-home" ANSIBLE_LOCAL_TEMP="$WORK/ansible-local"

# --- step 5: the tracer, before any ssh connection ----------------------------------------

SSHD=$(node systemctl show -p MainPID --value ssh.service)
precondition "sshd has a PID" [ "${SSHD:-0}" -gt 0 ]
# -v prints the environment as well as argv, -y annotates every fd with what it is, and -s is
# larger than any buffer sshd forwards.
docker exec -d "$NAME" strace -f -qq -v -y -s 1048576 \
  -e trace=execve,execveat,write,writev,pwrite64,pwritev,pwritev2,sendfile,splice,copy_file_range -o /trace/exec.trace -p "$SSHD"
precondition "the trace file exists within 10s" trace_file_exists_within_10s
sleep 1

# --- step 6: run A, the guard -------------------------------------------------------------

# Extra-vars beat the task's vars, and both names are overridden because the ssh plugin takes
# the last one it finds.
play run-a.log old -e '{"ansible_pipelining": false, "ansible_ssh_pipelining": false}'
check DI-45 "with pipelining off, the role refuses before join runs" [ "$PLAY_RC" -ne 0 ]
check DI-45 "the refusal is the role's remote_tmp guard" run_a_hit_the_guard
check DI-45 "the run reached the join task: the old package is installed" package_is_installed
check DI-45 "and the Node holds no identity" node_has_no_identity

# --- step 6b: run L, sudo records standard input ------------------------------------------

# The drop-in is root-owned and checked by visudo before sudo reads it.
printf 'Defaults log_input\n' | node_i bash -c 'cat >/etc/sudoers.d/zz-log-input && chmod 0440 /etc/sudoers.d/zz-log-input'
precondition "the log_input sudoers drop-in is valid" sudo_drop_in_is_valid
PRINTENV_BEFORE_L=$(printenv_exec_count)
play run-l.log old
node rm -f /etc/sudoers.d/zz-log-input
check DI-45 "where sudo records standard input, the role refuses with its own message" run_l_refused_sudo_input_logging
check DI-45 "and the Node holds no identity" node_has_no_identity
check DI-45 "and stopped before the join task: no join execution, no join task" run_l_stopped_before_the_join_task
check DI-45 "the trace saw run L's sudo check (control)" the_trace_saw_run_l

# --- step 7: run B, the second run on the same Node ---------------------------------------

play run-b.log new
check DI-45 "the role exits 0 with failed=0 and unreachable=0" run_succeeded run-b.log ' unreachable=0 ' ' failed=0 '
check DI-45 "an installed daemon is not upgraded: the version is still the old one" installed_version_is_the_old_one
check DI-45 "the identity is persisted" node_has_identity
check DI-45 "the unit is active and enabled within 30s" unit_becomes_active_and_enabled
check DI-45 "the role placed no Policy fragment" policy_dir_is_empty

# --- step 8: run C, the enrolled Node given the new package ------------------------------

SNAP=$(node_snapshot)
play run-c.log new
check DI-45 "an enrolled Node: the role exits 0 and changes nothing" run_succeeded run-c.log ' changed=0 ' ' unreachable=0 ' ' failed=0 '
check DI-45 "an enrolled Node is unchanged: files, package version and daemon process" [ "$(node_snapshot)" = "$SNAP" ]
check DI-45 "and still at the old version" installed_version_is_the_old_one

# --- step 9: the trace --------------------------------------------------------------------

node pkill -INT -x strace || true
precondition "the tracer stopped" tracer_has_stopped

check DI-45 "the trace saw join exactly once (positive control)" join_exec_count_is_one
check DI-45 "the trace saw the join string piped to join (positive control)" join_string_was_piped
check DI-45 "no process argument list or environment on the Node held the join string or the token" trace_holds_no_secret exec
check DI-45 "the trace saw the role stage a file (control)" the_trace_saw_the_role_stage_a_file
check DI-45 "no write to a file on the Node carried the join string or the token" trace_holds_no_secret filewrite
check DI-45 "no sendfile, splice or copy_file_range on the Node moved a pipe, socket or anonymous inode into a file" trace_has_no_copy_to_a_file

# --- step 10: every file on the Node ------------------------------------------------------

CANARY=$(head -c 24 /dev/urandom | base64 | tr -d '/+=\n')
printf '%s\n' "$CANARY" | node_i bash -c 'umask 077; cat >/var/tmp/relay-role-canary'
check DI-45 "the file scan finds a planted canary (control)" scan_finds_the_canary
node rm -f /var/tmp/relay-role-canary
check DI-45 "no file on the Node holds the join string or the token" no_file_holds_a_secret

# --- step 11: the journal -----------------------------------------------------------------

check DI-45 "the journal holds the role's logged module invocations (control)" journal_holds_invocations
check DI-45 "no log on the Node holds the join string or the token" journal_holds_no_secret

# --- step 12: the controller's own output (not a claim) -----------------------------------

check run "the controller's run output holds no join string or token" run_logs_hold_no_secret

if [ "$FAILS" -gt 0 ]; then
  echo "$FAILS checks failed"
  exit 1
fi
echo "all checks passed"
