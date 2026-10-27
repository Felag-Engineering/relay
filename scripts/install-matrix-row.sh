#!/usr/bin/env bash
# One install-matrix row's assertions, as named phases (docs/specs/daemon-installation.md DI-33).
#
#   install-matrix-row.sh <phase>      ROW_FAMILY=deb|rpm   [PKG_ROOT=/pkgs]
#
# Runs as root inside the platform's systemd container, driven phase by phase from the runner
# by scripts/install-matrix-host.sh; the `join` phase also runs on the runner VM, where
# scripts/install-matrix-vm-trace.sh reuses it. Nothing here runs outside CI: it installs
# packages, starts services and writes under /etc and /var.
#
# Packages are read from $PKG_ROOT/old/* (built as 0.0.0~matrix1) and $PKG_ROOT/new/* (the
# real version), and the version from $PKG_ROOT/VERSION. Package-manager front ends run with
# the distribution's defaults: no digest, signature or gpgcheck flag, no macro or config edit,
# so each install is made under the platform's own _pkgverify_level.
#
# Every assertion prints "ok <ID> <description>" or "FAIL <ID> <description>", where ID is the
# spec claim the assertion is evidence for, so the CI log maps assertion to claim. A phase
# exits 1 if any assertion failed. A `precondition` failure ends the phase at once: a leftover
# from an earlier phase must never read as a failed claim.
#
# State that must survive a container restart lives in /root/install-matrix (root, 0700),
# never under /run, which is a tmpfs. It holds secrets (the admin password and API Token), so
# nothing prints its files except the summary and the *.log phase logs.
#
# NOT `set -e`: every assertion in a phase must run and be reported.
set -uo pipefail

PKG_ROOT="${PKG_ROOT:-/pkgs}"
STATE=/root/install-matrix
CA_CERT=/var/lib/relay/ca/ca-cert.pem
RELAY_TOML=/etc/relay/relay.toml
DAEMON_ETC=/etc/relay-daemon
POLICY="$DAEMON_ETC/policy.toml"
POLICY_DIR="$DAEMON_ETC/policy.d"
ENV_FILE="$DAEMON_ETC/relay-daemon.env"
CATALOG="$DAEMON_ETC/templates.d/relay-read/catalog.toml"
DAEMON_STATE=/var/lib/relay-daemon
PHASE="${1:-}"
FAILS=0

export DEBIAN_FRONTEND=noninteractive

usage() {
  echo "usage: ROW_FAMILY=deb|rpm [PKG_ROOT=/pkgs] $0 install|after-boot|join|upgrade|remove|purge|cycles|fips|no-systemd" >&2
}

# --- assertion helpers ------------------------------------------------------------------

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

# precondition <description> <command...>: a failure ends the phase now.
precondition() {
  local desc=$1
  shift
  if ! "$@"; then
    echo "FAIL precondition $desc"
    exit 1
  fi
}

# info <line>: kept in the summary the host driver copies into the job summary.
info() {
  echo "info $*"
  printf '%s\n' "$*" >>"$STATE/summary"
}

is_deb() { [ "$ROW_FAMILY" = deb ]; }
exists_path() { [ -e "$1" ] || [ -L "$1" ]; }
sha() { sha256sum -- "$1" | cut -d' ' -f1; }
unit_prop() { systemctl show -p "$2" --value "$1" 2>/dev/null; }
# is_enabled prints systemctl's answer; a disabled unit makes it exit non-zero, which is not
# an error here.
is_enabled() { systemctl is-enabled "$1" 2>/dev/null || true; }

# stat_is <path> <owner:group> <octal mode>
stat_is() { [ "$(stat -c '%U:%G %a' -- "$1" 2>/dev/null)" = "$2 $3" ]; }

# no_group_other_bits <path>
no_group_other_bits() {
  local mode
  mode=$(stat -c %a -- "$1" 2>/dev/null) || return 1
  [ $((8#$mode & 8#077)) -eq 0 ]
}

dir_empty() { [ -d "$1" ] && [ -z "$(ls -A -- "$1")" ]; }
grep_log() { grep -q -- "$1" "$STATE/$2.log"; }

# relay_remove_names_state: the relay package's own %postun lines. relay-daemon's %postun
# prints /var/lib/relay-daemon into the same transaction, which a prefix match would accept.
relay_remove_names_state() {
  grep -q '^relay: removed\.' "$STATE/remove.log" \
    && grep -qxE '[[:space:]]*/var/lib/relay' "$STATE/remove.log"
}

ensure_state() {
  install -d -m 0700 "$STATE" || exit 1
  precondition "$STATE is a root-owned 0700 directory" stat_is "$STATE" root:root 700
}

# --- packages ---------------------------------------------------------------------------

# pkg_file <old|new> <name>: the family's file for that package name, or nothing.
pkg_file() {
  local dir="$PKG_ROOT/$1" name=$2 f
  if is_deb; then
    for f in "$dir/${name}_"*.deb; do
      if [ -e "$f" ]; then printf '%s\n' "$f"; return 0; fi
    done
  else
    for f in "$dir/${name}-"[0-9]*.rpm; do
      if [ -e "$f" ]; then printf '%s\n' "$f"; return 0; fi
    done
  fi
  return 0
}

# need_pkgs: refuses unless the packages and the version this phase installs are present.
need_pkgs() {
  local which n missing=""
  for which in old new; do
    for n in relay-daemon relay; do
      [ -n "$(pkg_file "$which" "$n")" ] || missing="$missing $PKG_ROOT/$which/$n"
    done
  done
  [ -f "$PKG_ROOT/VERSION" ] || missing="$missing $PKG_ROOT/VERSION"
  if [ -n "$missing" ]; then
    echo "FAIL precondition no $ROW_FAMILY packages under PKG_ROOT/old or /new:$missing"
    exit 1
  fi
}

# build_set <old|new> <name...>: SET becomes the files of those packages that exist.
SET=()
build_set() {
  local which=$1 n f
  shift
  SET=()
  for n in "$@"; do
    f=$(pkg_file "$which" "$n")
    if [ -n "$f" ]; then SET+=("$f"); fi
  done
}

# full_set <old|new>: relay-daemon and relay. daemon_set leaves relay out.
full_set() { build_set "$1" relay-daemon relay; }
daemon_set() { build_set "$1" relay-daemon; }

pm_log() { tee -a "$STATE/$PHASE.log"; }

pm_install() {
  if is_deb; then
    apt-get install -y "$@" 2>&1 | pm_log
  else
    dnf install -y "$@" 2>&1 | pm_log
  fi
  return "${PIPESTATUS[0]}"
}

pm_upgrade() {
  if is_deb; then
    apt-get install -y "$@" 2>&1 | pm_log
  else
    dnf upgrade -y "$@" 2>&1 | pm_log
  fi
  return "${PIPESTATUS[0]}"
}

pm_remove() {
  if is_deb; then
    apt-get remove -y "$@" 2>&1 | pm_log
  else
    dnf remove -y "$@" 2>&1 | pm_log
  fi
  return "${PIPESTATUS[0]}"
}

# pm_purge: deb only; rpm has no purge.
pm_purge() {
  apt-get purge -y "$@" 2>&1 | pm_log
  return "${PIPESTATUS[0]}"
}

# pkg_installed <name>: deb counts only "install ok installed"; a removed-but-not-purged
# package (rc) is not installed.
pkg_installed() {
  if is_deb; then
    [ "$(dpkg-query -W -f '${Status}' "$1" 2>/dev/null)" = "install ok installed" ]
  else
    rpm -q "$1" >/dev/null 2>&1
  fi
}

installed_version() {
  if is_deb; then
    dpkg-query -W -f '${Version}' "$1" 2>/dev/null
  else
    rpm -q --qf '%{VERSION}-%{RELEASE}' "$1" 2>/dev/null
  fi
}

# file_version <package file>: the version the file declares, read from the file itself.
file_version() {
  if is_deb; then
    dpkg-deb -f "$1" Version
  else
    rpm -qp --qf '%{VERSION}-%{RELEASE}' "$1" 2>/dev/null
  fi
}

# versions_are_new <name...>: each package is installed at the version its new file carries.
versions_are_new() {
  local n want got rc=0
  for n in "$@"; do
    want=$(file_version "$(pkg_file new "$n")")
    got=$(installed_version "$n")
    if [ -z "$want" ] || [ "$got" != "$want" ]; then
      echo "$n: installed '${got}', new package file says '${want}'"
      rc=1
    fi
  done
  return "$rc"
}

# owned_by <name> <path>: <name> is the package that owns <path>, and no other.
owned_by() {
  local out
  if is_deb; then
    out=$(dpkg-query -S "$2" 2>/dev/null) || return 1
    [ "$out" = "$1: $2" ]
  else
    out=$(rpm -qf --qf '%{NAME}\n' "$2" 2>/dev/null) || return 1
    [ "$out" = "$1" ]
  fi
}

# declares_no_config <name...>: no package declares configuration files.
declares_no_config() {
  local n out rc=0
  for n in "$@"; do
    if is_deb; then
      out=$(dpkg-query -W -f '${Conffiles}' "$n" 2>/dev/null | tr -d '[:space:]')
    else
      out=$(rpm -qc "$n" 2>/dev/null)
    fi
    if [ -n "$out" ]; then
      echo "$n declares configuration: $out"
      rc=1
    fi
  done
  return "$rc"
}

# reset_state removes the four literal package paths and nothing else. On deb it clears what
# purge rightly left (the operator's fragment was in them); on rpm it is the operator's hand
# deletion. The marker directories, /var/lib/relay.purged-* and the relay account stay: the
# first must be removed by the package scripts themselves, which `pristine` then asserts.
reset_state() {
  rm -rf -- /etc/relay-daemon /var/lib/relay-daemon /etc/relay /var/lib/relay
}

# pristine <daemon|daemon+relay>: the package's paths and markers are absent and its packages
# are not installed, so a leftover fails as a precondition and never as a DI-26 failure.
pristine() {
  local scope=$1 bad=() p n
  for p in "$DAEMON_ETC" "$DAEMON_STATE" /var/lib/relay-daemon-package; do
    if exists_path "$p"; then bad+=("$p present"); fi
  done
  if pkg_installed relay-daemon; then bad+=("package relay-daemon installed"); fi
  if [ "$scope" = daemon+relay ]; then
    for p in /etc/relay /var/lib/relay /var/lib/relay-package; do
      if exists_path "$p"; then bad+=("$p present"); fi
    done
    if pkg_installed relay; then bad+=("package relay installed"); fi
  fi
  if [ "${#bad[@]}" -gt 0 ]; then
    for p in "${bad[@]}"; do echo "FAIL precondition $p"; done
    exit 1
  fi
}

# --- the Relay's Control API ------------------------------------------------------------

relay_host() { sed -n 's/^hostname = "\(.*\)"$/\1/p' "$RELAY_TOML" | head -n 1; }

# api_code prints the HTTP status of an unauthenticated ping, 000 when nothing answers.
api_code() {
  local host
  host=$(relay_host)
  curl -sS -o /dev/null --connect-timeout 1 --max-time 5 -w '%{http_code}' \
    --cacert "$CA_CERT" --resolve "$host:9443:127.0.0.1" "https://$host:9443/api/v1/ping" 2>/dev/null
  return 0
}

# wait_api <seconds>: the Control API answers (any HTTP status) within the time.
wait_api() {
  local i code
  for ((i = 0; i < $1; i++)); do
    code=$(api_code)
    if [ "$code" != 000 ] && [ -n "$code" ]; then return 0; fi
    sleep 1
  done
  return 1
}

# relay_api <method> <path> [json body]: sets API_STATUS and API_BODY. The call is made
# directly, never inside a command substitution, so the variables reach the caller; the
# response body is held in memory and is never written to a file or echoed, because the
# enrollment mint's carries a join string. The bearer header reaches curl through a 0600
# file, never argv.
API_STATUS=""
API_BODY=""
relay_api() {
  local method=$1 path=$2 body=${3:-} host out
  local args
  host=$(relay_host)
  args=(-sS --max-time 60 --cacert "$CA_CERT" --resolve "$host:9443:127.0.0.1"
    -X "$method" -H "@$STATE/api-header" -w $'\n%{http_code}')
  if [ -n "$body" ]; then args+=(-H 'Content-Type: application/json' -d "$body"); fi
  out=$(curl "${args[@]}" "https://$host:9443$path" 2>/dev/null)
  API_STATUS=${out##*$'\n'}
  case "$out" in
    *$'\n'*) API_BODY=${out%$'\n'*} ;;
    *) API_BODY="" ;;
  esac
  if [ -z "$API_STATUS" ]; then API_STATUS=000; fi
  return 0
}

# --- phases -----------------------------------------------------------------------------

rpm_signatures_ok() {
  local f out rc=0
  for f in "$@"; do
    if ! out=$(rpm -K "$f" 2>&1); then
      echo "$out"
      rc=1
    elif [[ $out == *"NOT OK"* ]]; then
      echo "$out"
      rc=1
    fi
  done
  return "$rc"
}

never_started() {
  [ "$(unit_prop "$1" ExecMainStartTimestampMonotonic)" = 0 ]
}

# daemon_installed_state: the checks DI-25 makes on a freshly installed, never-started unit.
daemon_installed_state() {
  local preset enabled
  preset=$(unit_prop relay-daemon UnitFilePreset)
  enabled=$(is_enabled relay-daemon)
  [ -f /usr/lib/systemd/system/relay-daemon.service ] || return 1
  [ "$enabled" = "$preset" ] || { echo "is-enabled '$enabled', preset '$preset'"; return 1; }
  if is_deb && [ "$enabled" != enabled ]; then echo "deb: is-enabled '$enabled'"; return 1; fi
  [ "$(unit_prop relay-daemon ActiveState)" = inactive ] || return 1
  [ "$(unit_prop relay-daemon Result)" = success ] || return 1
  [ "$(unit_prop relay-daemon NRestarts)" = 0 ] || return 1
  never_started relay-daemon
}

relay_installed_state() {
  getent passwd relay >/dev/null && getent group relay >/dev/null || return 1
  [ -x /usr/bin/relay ] && [ -f /usr/lib/systemd/system/relay.service ] || return 1
  [ "$(is_enabled relay)" = "$(unit_prop relay UnitFilePreset)" ] || return 1
  never_started relay
}

phase_install() {
  need_pkgs
  precondition "/run/systemd/system exists" [ -d /run/systemd/system ]
  precondition "/proc/1/comm is exactly systemd" [ "$(cat /proc/1/comm)" = systemd ]
  pristine daemon+relay
  info "systemd: $(systemctl --version | head -n 1)"

  if ! is_deb; then
    info "rpm: $(rpm --version); _pkgverify_level=$(rpm --eval '%{_pkgverify_level}')"
    check DI-33 "rpm -K passes on every rpm, old and new" \
      rpm_signatures_ok "$PKG_ROOT"/old/*.rpm "$PKG_ROOT"/new/*.rpm
  fi

  full_set old
  precondition "install the old package set" pm_install "${SET[@]}"

  check DI-25 "relay-daemon is /usr/bin/relay-daemon, root:root 0755" stat_is /usr/bin/relay-daemon root:root 755
  check DI-25 "the unit is installed, enabled per preset, inactive, not failed, never started" daemon_installed_state

  check DI-26 "the default Policy is placed: root 0644, equal to the shipped default" \
    bash -c 'cmp -s "$1" "$2" && [ "$(stat -c "%U:%G %a" "$1")" = "root:root 644" ]' _ "$POLICY" /usr/share/relay-daemon/policy.default.toml
  check DI-26 "the Policy directory exists, is empty, 0755" \
    bash -c '[ -d "$1" ] && [ -z "$(ls -A "$1")" ] && [ "$(stat -c %a "$1")" = 755 ]' _ "$POLICY_DIR"
  check DI-27 "the env file is root:root 0600 and equals the shipped example" \
    bash -c 'cmp -s "$1" "$2" && [ "$(stat -c "%U:%G %a" "$1")" = "root:root 600" ]' _ "$ENV_FILE" /usr/share/relay-daemon/relay-daemon.env.example
  check DI-31 "the state directory is a 0700 directory" \
    bash -c '[ -d "$1" ] && [ "$(stat -c %a "$1")" = 700 ]' _ "$DAEMON_STATE"

  check DI-29 "the catalog is installed and owned by relay-daemon" owned_by relay-daemon "$CATALOG"
  check DI-29 "no package declares configuration files" declares_no_config relay-daemon relay

  check RC-24 "the relay account and the unit are installed, enabled per preset, never started" relay_installed_state
  check RC-24 "the install printed the configuration guide" grep_log 'relay init' install
  check RC-25 "/etc/relay is root 0755" stat_is /etc/relay root:root 755
  check RC-25 "relay.toml is root:relay 0640 with the host's name as tls.hostname" \
    bash -c '[ "$(stat -c "%U:%G %a" "$1")" = "root:relay 640" ] && grep -qx "hostname = \"relay-matrix.test\"" "$1"' _ "$RELAY_TOML"
  check RC-25 "/var/lib/relay is relay:relay 0700" stat_is /var/lib/relay relay:relay 700

  # Operator edits, which the upgrade must keep.
  local f
  for f in "$POLICY" "$ENV_FILE" "$RELAY_TOML"; do
    echo '# install-matrix edit' >>"$f"
  done
  sha "$POLICY" >"$STATE/policy-after-install"
  sha "$RELAY_TOML" >"$STATE/relay-toml-after-install"
  sha "$ENV_FILE" >"$STATE/env-after-install"
  cp -- "$CATALOG" "$STATE/catalog.orig"

  # Where the preset left relay-daemon disabled (rpm), enable it, so that the boot check
  # exercises an enabled unit on every row.
  if [ "$(is_enabled relay-daemon)" != enabled ]; then
    systemctl enable relay-daemon
    info "the operator enabled relay-daemon: the platform preset left it '$(unit_prop relay-daemon UnitFilePreset)'"
  fi
}

# boot_cycle_is_clean: the enabled unit ran at boot and ended without failing or retrying.
boot_cycle_is_clean() {
  [ "$(is_enabled relay-daemon)" = enabled ] || return 1
  # Type=exec: boot can finish once the daemon is exec'd, before its clean exit.
  local i
  for ((i = 0; i < 10; i++)); do
    case "$(unit_prop relay-daemon ActiveState)" in active | activating | deactivating) sleep 1 ;; *) break ;; esac
  done
  local started
  started=$(unit_prop relay-daemon ExecMainStartTimestampMonotonic)
  [ -n "$started" ] && [ "$started" -gt 0 ] || { echo "ExecMainStartTimestampMonotonic='$started'"; return 1; }
  [ "$(unit_prop relay-daemon ExecMainStatus)" = 0 ] || return 1
  [ "$(unit_prop relay-daemon ActiveState)" = inactive ] || return 1
  [ "$(unit_prop relay-daemon Result)" = success ] || return 1
  [ "$(unit_prop relay-daemon NRestarts)" = 0 ] || return 1
  ! systemctl is-failed --quiet relay-daemon
}

ca_is_private() {
  local key
  [ -d /var/lib/relay/ca ] || return 1
  key=$(find /var/lib/relay/ca -maxdepth 1 -type f -name '*key*' | head -n 1)
  [ -n "$key" ] || { echo "no key file under /var/lib/relay/ca"; return 1; }
  stat_is /var/lib/relay/ca relay:relay 700 || return 1
  [ "$(stat -c %U -- "$key")" = relay ] && no_group_other_bits "$key"
}

# relay_refuses_a_writable_config: with relay.toml group-writable the Relay never listens, the
# journal names the refusal, and the unit ends non-success. relay.service is Type=exec with
# Restart=on-failure, so a refused start is briefly `active` and then cycles; the check never
# asserts "never active".
relay_refuses_a_writable_config() {
  local t i code journal refused=no rc=0
  systemctl stop relay
  t=$(date +%s)
  chmod 0660 "$RELAY_TOML"
  systemctl start relay || true
  for ((i = 0; i < 15; i++)); do
    sleep 1
    curl -sS -o /dev/null --connect-timeout 1 --max-time 3 --cacert "$CA_CERT" \
      --resolve "$(relay_host):9443:127.0.0.1" "https://$(relay_host):9443/api/v1/ping" 2>/dev/null
    code=$?
    if [ "$code" -ne 7 ]; then echo "poll $i: curl exit $code, not 7 (a listener answered)"; rc=1; fi
    if [ "$(unit_prop relay Result)" != success ] || [ "$(unit_prop relay ExecMainStatus)" != 0 ]; then
      refused=yes
    fi
  done
  # The journal is read into a variable first: `grep -q` closing the pipe early would make
  # journalctl fail under pipefail.
  journal=$(journalctl -u relay --no-pager --since "@$t" 2>&1)
  [[ $journal == *"refusing $RELAY_TOML"* ]] || { echo "the journal has no 'refusing $RELAY_TOML'"; rc=1; }
  [ "$refused" = yes ] || { echo "the unit never ended non-success"; rc=1; }
  systemctl stop relay
  chmod 0640 "$RELAY_TOML"
  systemctl reset-failed relay
  systemctl start relay
  return "$rc"
}

phase_after_boot() {
  check DI-25 "after a systemd restart the enabled unit ran, stayed inactive and did not fail or retry" boot_cycle_is_clean

  if ! systemctl is-active --quiet relay; then
    systemctl start relay
    info "boot left relay.service stopped (preset '$(unit_prop relay UnitFilePreset)'); the matrix started it"
  fi
  check RC-15 "the packaged Relay starts on its packaged layout and the Control API answers" wait_api 60
  check RC-17 "the CA directory and its private key are the relay account's alone (extra evidence)" ca_is_private
  check RC-15 "a group-writable relay.toml refuses the Relay's start" relay_refuses_a_writable_config
  check RC-15 "the Relay starts again once relay.toml is restored" wait_api 60
}

# join_inputs: every input of the join phase; a missing one fails as a precondition before
# anything runs.
join_inputs() {
  local ok=yes
  grep -q '^hostname = "' "$RELAY_TOML" 2>/dev/null || { echo "FAIL precondition a hostname line in $RELAY_TOML"; ok=no; }
  [ -f "$CA_CERT" ] || { echo "FAIL precondition $CA_CERT"; ok=no; }
  [ -x /usr/bin/relay ] || { echo "FAIL precondition /usr/bin/relay"; ok=no; }
  [ -x /usr/bin/relay-daemon ] || { echo "FAIL precondition /usr/bin/relay-daemon"; ok=no; }
  [ -f /usr/lib/systemd/system/relay-daemon.service ] || { echo "FAIL precondition the relay-daemon unit"; ok=no; }
  [ -f "$ENV_FILE" ] || { echo "FAIL precondition $ENV_FILE"; ok=no; }
  if [ "$ok" = yes ]; then
    local code
    code=$(api_code)
    if [ "$code" = 000 ] || [ -z "$code" ]; then
      echo "FAIL precondition a running Relay answering on 127.0.0.1:9443"
      ok=no
    fi
  fi
  [ "$ok" = yes ] || exit 1
}

unit_becomes_active_and_enabled() {
  local i
  for ((i = 0; i < 30; i++)); do
    if systemctl is-active --quiet relay-daemon && [ "$(is_enabled relay-daemon)" = enabled ]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

identity_is_persisted() {
  local f
  for f in key.pem cert.pem ca_bundle.pem node_id; do
    [ -f "$DAEMON_STATE/$f" ] || { echo "missing $DAEMON_STATE/$f"; return 1; }
  done
}

no_join_string_on_disk() {
  ! grep -rqI 'glp_join_' "$DAEMON_ETC" "$DAEMON_STATE" "$STATE" 2>/dev/null
}

# facts_dispatch_succeeds: a system.facts dispatch to the enrolled Node returns 200 and a
# successful Task. The Node needs a moment to come online, so a refusal is retried; a 202 is a
# failure, never a retry.
facts_dispatch_succeeds() {
  local i
  for ((i = 0; i < 30; i++)); do
    relay_api POST /api/v1/operations '{"selector":"relay:env=matrix","operation":"system.facts"}'
    case "$API_STATUS" in
      200)
        if printf '%s' "$API_BODY" | jq -e '(.results | length) > 0 and all(.results[]; .outcome == "success")' >/dev/null; then
          return 0
        fi
        ;;
      202)
        echo "the approval gate parked system.facts"
        return 1
        ;;
    esac
    sleep 1
  done
  echo "last status $API_STATUS"
  return 1
}

phase_join() {
  join_inputs

  local env_before join join_rc
  env_before=$(sha "$ENV_FILE")

  # The admin's password and API Token live in 0600 files; the root shell makes every
  # redirection, so the relay account never needs to open the state directory.
  ( umask 077
    head -c 24 /dev/urandom | base64 | tr -d '/+=\n' >"$STATE/admin-password"
    echo >>"$STATE/admin-password" )
  ( umask 077
    runuser -u relay -- relay init --config "$RELAY_TOML" --admin matrix --ttl 2h \
      <"$STATE/admin-password" >"$STATE/api-token" )
  precondition "relay init printed an API Token" [ -s "$STATE/api-token" ]
  ( umask 077
    printf 'Authorization: Bearer %s\n' "$(cat "$STATE/api-token")" >"$STATE/api-header" )

  # The mint must name its use limit (EN-31). The Node enrolls once; a restart reuses its
  # identity, not the token.
  relay_api POST /api/v1/enrollment-tokens '{"scope":["relay:env=matrix"],"ttl_seconds":3600,"max_uses":1}'
  precondition "the Enrollment Token mint answered 201 (got $API_STATUS)" [ "$API_STATUS" = 201 ]
  join=$(printf '%s' "$API_BODY" | jq -r '.join_string // empty')
  API_BODY=""
  precondition "the mint response carried a join string" [ -n "$join" ]

  # printf is a builtin, so the join string is never in any argv.
  printf '%s\n' "$join" | relay-daemon join 2>&1 | tee -a "$STATE/join.log"
  join_rc=${PIPESTATUS[1]}
  join=""
  check DI-42 "relay-daemon join exits 0" [ "$join_rc" -eq 0 ]
  check DI-42 "the unit is active and enabled within 30s of join" unit_becomes_active_and_enabled
  check DI-42 "the identity files are persisted in the state directory" identity_is_persisted
  check DI-42 "join left the env file unchanged" [ "$(sha "$ENV_FILE")" = "$env_before" ]
  check DI-42 "no join string is on disk" no_join_string_on_disk
  check DI-42 "the packaged unit connected: a system.facts dispatch to the Node succeeds" facts_dispatch_succeeds
}

phase_upgrade() {
  need_pkgs
  local relay_pid daemon_pid daemon_en relay_en
  daemon_pid=$(unit_prop relay-daemon MainPID)
  relay_pid=$(unit_prop relay MainPID)
  daemon_en=$(is_enabled relay-daemon)
  relay_en=$(is_enabled relay)

  # A local edit to a package-owned file: the upgrade must replace it.
  echo '# local' >>"$CATALOG"
  if ! is_deb; then
    info "rpm -V before upgrade: $(rpm -V "$(rpm -qf "$CATALOG")" 2>&1 | tr '\n' ';')"
  fi
  full_set new
  precondition "upgrade to the new package set" pm_upgrade "${SET[@]}"
  if ! is_deb; then
    info "rpm -V after upgrade: $(rpm -V "$(rpm -qf "$CATALOG")" 2>&1 | tr '\n' ';')"
  fi

  check DI-33 "each package is installed at the new version" versions_are_new relay-daemon relay
  check DI-26 "the edited Policy survives the upgrade" [ "$(sha "$POLICY")" = "$(cat "$STATE/policy-after-install")" ]
  check DI-27 "the edited env file survives the upgrade, still root:root 0600" \
    bash -c '[ "$(sha256sum < "$1" | cut -d" " -f1)" = "$2" ] && [ "$(stat -c "%U:%G %a" "$1")" = "root:root 600" ]' \
    _ "$ENV_FILE" "$(cat "$STATE/env-after-install")"
  check RC-25 "the edited relay.toml survives the upgrade, still root:relay 0640" \
    bash -c '[ "$(sha256sum < "$1" | cut -d" " -f1)" = "$2" ] && [ "$(stat -c "%U:%G %a" "$1")" = "root:relay 640" ]' \
    _ "$RELAY_TOML" "$(cat "$STATE/relay-toml-after-install")"
  check DI-25 "relay-daemon's enablement is unchanged by the upgrade" [ "$(is_enabled relay-daemon)" = "$daemon_en" ]
  check RC-24 "relay's enablement is unchanged by the upgrade" [ "$(is_enabled relay)" = "$relay_en" ]
  check DI-25 "the upgrade neither started nor restarted relay-daemon" [ "$(unit_prop relay-daemon MainPID)" = "$daemon_pid" ]
  check RC-24 "the upgrade neither started nor restarted the Relay" [ "$(unit_prop relay MainPID)" = "$relay_pid" ]
  # Old and new come from one commit, so on rpm the file's digest is unchanged between
  # versions. A surviving edit stays a FAIL: it is an rpm-semantics finding to escalate.
  check DI-29 "the Templates are replaced on upgrade, not preserved as configuration" cmp -s "$CATALOG" "$STATE/catalog.orig"
}

remove_keeps_state() {
  local rc=0
  [ -f "$POLICY" ] || { echo "$POLICY is gone"; rc=1; }
  [ -d "$POLICY_DIR" ] || { echo "$POLICY_DIR is gone"; rc=1; }
  [ -f "$ENV_FILE" ] || { echo "$ENV_FILE is gone"; rc=1; }
  [ -f "$DAEMON_STATE/key.pem" ] || { echo "$DAEMON_STATE/key.pem is gone"; rc=1; }
  return "$rc"
}

remove_took_the_payload() {
  local rc=0 p
  for p in /usr/bin/relay-daemon /usr/lib/systemd/system/relay-daemon.service "$CATALOG" \
    /etc/systemd/system/multi-user.target.wants/relay-daemon.service; do
    if exists_path "$p"; then echo "$p remains"; rc=1; fi
  done
  if pgrep -x relay-daemon >/dev/null; then echo "a relay-daemon process remains"; rc=1; fi
  return "$rc"
}

phase_remove() {
  # An operator's fragment, for the purge check: the package did not create it.
  printf '[[deny]]\nname = "file.read"\nargs = [["/etc/hostname"]]\n' >"$POLICY_DIR/50-operator.toml"
  chmod 0644 "$POLICY_DIR/50-operator.toml"

  precondition "remove the packages" pm_remove relay-daemon relay

  check DI-31 "remove takes the binary, unit, Templates, enablement link and process" remove_took_the_payload
  check DI-31 "remove keeps the Policy, the Policy directory, the env file and the state" remove_keeps_state
  check DI-26 "the edited Policy survives remove" [ "$(sha "$POLICY")" = "$(cat "$STATE/policy-after-install")" ]
  if ! is_deb; then
    check DI-31 "the remove output names the paths to delete by hand" \
      bash -c 'grep -q "$1" "$3" && grep -q "$2" "$3"' _ "$DAEMON_STATE" "$POLICY" "$STATE/remove.log"
  fi

  check RC-26 "remove keeps relay.toml, the CA and the store" \
    bash -c '[ -f "$1" ] && [ -d /var/lib/relay/ca ] && [ -f /var/lib/relay/relay.db ]' _ "$RELAY_TOML"
  check RC-26 "remove keeps the relay account" getent passwd relay
  if ! is_deb; then
    check RC-26 "the relay package's remove output names /var/lib/relay" relay_remove_names_state
  fi
}

purged_state_is_aside() {
  local dirs=(/var/lib/relay.purged-*) rc=0
  [ -e /var/lib/relay ] && { echo "/var/lib/relay remains"; rc=1; }
  if [ "${#dirs[@]}" -ne 1 ] || [ ! -d "${dirs[0]}" ]; then
    echo "want exactly one /var/lib/relay.purged-*, got: ${dirs[*]}"
    return 1
  fi
  stat_is "${dirs[0]}" root:root 700 || { echo "${dirs[0]} is not root:root 0700"; rc=1; }
  [ -d "${dirs[0]}/ca" ] && [ -f "${dirs[0]}/relay.db" ] || { echo "${dirs[0]} lacks the CA or the store"; rc=1; }
  return "$rc"
}

purge_took_what_it_created() {
  local rc=0 p
  for p in "$POLICY" "$ENV_FILE" "$DAEMON_STATE" /var/lib/relay-daemon-package; do
    if exists_path "$p"; then echo "$p remains"; rc=1; fi
  done
  [ -d "$POLICY_DIR" ] && [ -f "$POLICY_DIR/50-operator.toml" ] || { echo "the operator's fragment is gone"; rc=1; }
  return "$rc"
}

phase_purge() {
  if is_deb; then
    precondition "purge the packages" pm_purge relay-daemon relay
    check DI-31 "purge removes the Policy, env file, state and marker the package created" purge_took_what_it_created
    check DI-31 "purge names the Policy directory it left in place" grep_log 'policy.d' purge
    check RC-26 "purge moves the CA and the store aside together, root 0700, keeping the relay account" purged_state_is_aside
    check RC-26 "purge removes relay.toml and /etc/relay, which the package created" \
      bash -c '[ ! -e "$1" ] && [ ! -e /etc/relay ]' _ "$RELAY_TOML"
    check RC-26 "purge keeps the relay account" getent passwd relay
    check RC-26 "purge names where the state was moved" grep_log 'relay.purged-' purge
  else
    check DI-31 "remove deleted nothing the operator deletes by hand" remove_keeps_state
    check RC-26 "remove deleted nothing: relay.toml and the state remain" \
      bash -c '[ -f "$1" ] && [ -d /var/lib/relay/ca ]' _ "$RELAY_TOML"
  fi
  reset_state
}

# cycle_cleanup: the cleanup after a daemon-only cycle.
cycle_cleanup() {
  if is_deb; then pm_purge relay-daemon; else pm_remove relay-daemon; fi
}

phase_cycles() {
  need_pkgs
  local en_before

  # (a) A deleted Policy stays absent across an upgrade.
  pristine daemon
  daemon_set old
  precondition "install the old daemon set" pm_install "${SET[@]}"
  check DI-26 "cycle (a): the Policy is placed on a first install" [ -f "$POLICY" ]
  en_before=$(is_enabled relay-daemon)
  rm -f -- "$POLICY"
  daemon_set new
  precondition "upgrade the daemon set" pm_upgrade "${SET[@]}"
  check DI-26 "cycle (a): a deleted Policy stays absent across upgrade" [ ! -e "$POLICY" ]
  check DI-25 "cycle (a): enablement is unchanged by the upgrade" [ "$(is_enabled relay-daemon)" = "$en_before" ]
  cycle_cleanup
  reset_state

  # (b) A pre-existing Policy directory means no Policy is placed.
  pristine daemon
  install -d -m 0755 "$POLICY_DIR"
  printf '[[deny]]\nname = "file.read"\nargs = [["/etc/hostname"]]\n' >"$POLICY_DIR/50-existing.toml"
  chmod 0644 "$POLICY_DIR/50-existing.toml"
  local frag_sha
  frag_sha=$(sha "$POLICY_DIR/50-existing.toml")
  daemon_set new
  precondition "install the new daemon set" pm_install "${SET[@]}"
  check DI-26 "cycle (b): a pre-existing Policy directory means no Policy is placed" [ ! -e "$POLICY" ]
  check DI-26 "cycle (b): the existing fragment is byte-unchanged" [ "$(sha "$POLICY_DIR/50-existing.toml")" = "$frag_sha" ]
  cycle_cleanup
  if is_deb; then
    check DI-31 "cycle (b): purge keeps the fragment and directory the package did not create" \
      bash -c '[ -f "$1/50-existing.toml" ]' _ "$POLICY_DIR"
  fi
  reset_state
}

phase_fips() {
  need_pkgs
  pristine daemon+relay
  update-crypto-policies --set FIPS
  check DI-33 "the crypto-policy is FIPS" bash -c '[ "$(update-crypto-policies --show)" = FIPS ]'
  info "crypto-policy FIPS; /proc/sys/crypto/fips_enabled=$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo absent) (the host kernel's, which a container cannot change)"
  check DI-33 "rpm -K passes on every new rpm under the FIPS policy" rpm_signatures_ok "$PKG_ROOT"/new/*.rpm

  full_set new
  precondition "install the new package set under FIPS" pm_install "${SET[@]}"
  check DI-33 "each package is installed at the new version under FIPS" versions_are_new relay-daemon relay
  pm_remove relay-daemon relay
  reset_state
}

phase_no_systemd() {
  need_pkgs
  check DI-25 "this row has no systemd: no /run/systemd/system, PID 1 is not systemd, systemctl exists" \
    bash -c '[ ! -d /run/systemd/system ] && [ "$(cat /proc/1/comm)" != systemd ] && command -v systemctl >/dev/null'
  full_set new
  check DI-25 "the install exits 0 without systemd" pm_install "${SET[@]}"
  check DI-25 "no enablement link exists for either unit" \
    bash -c '[ ! -e /etc/systemd/system/multi-user.target.wants/relay-daemon.service ] && [ ! -L /etc/systemd/system/multi-user.target.wants/relay-daemon.service ] && [ ! -e /etc/systemd/system/multi-user.target.wants/relay.service ] && [ ! -L /etc/systemd/system/multi-user.target.wants/relay.service ]'
  check DI-25 "systemctl is-enabled (offline) says exactly disabled" \
    bash -c '[ "$(systemctl is-enabled relay-daemon 2>/dev/null)" = disabled ]'
  check DI-26 "the Policy is still placed" [ -f "$POLICY" ]
  check DI-27 "the env file is still placed, root:root 0600" stat_is "$ENV_FILE" root:root 600
}

# --- main -------------------------------------------------------------------------------

case "$PHASE" in
  install | after-boot | join | upgrade | remove | purge | cycles | fips | no-systemd) ;;
  *) usage; exit 2 ;;
esac
if [ "$(id -u)" -ne 0 ]; then
  echo "install-matrix-row: must run as root" >&2
  exit 1
fi
case "${ROW_FAMILY:-}" in
  deb | rpm) ;;
  *) echo "install-matrix-row: ROW_FAMILY must be deb or rpm" >&2; exit 2 ;;
esac

ensure_state
echo "== install-matrix-row: phase $PHASE ($ROW_FAMILY) =="
"phase_${PHASE//-/_}"

if [ "$FAILS" -ne 0 ]; then
  echo "== phase $PHASE: $FAILS assertion(s) FAILED =="
  exit 1
fi
echo "== phase $PHASE: all assertions passed =="
