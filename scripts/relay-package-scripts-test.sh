#!/usr/bin/env bash
# Proves the Relay package's maintainer scripts behave as the package promises (RC-24, RC-25,
# RC-26): first install, upgrade, remove, purge and rpm erase, under both the dpkg and the rpm
# argument conventions. Hermetic: no root, no packages, no network.
#
# Each script runs under dash (the shell Debian and Ubuntu run maintainer scripts with) from a
# copy whose fixed path prefixes are rewritten into a fake root under `mktemp -d`. The
# committed scripts keep their literal paths. PATH is the fake root's bin directory and
# nothing else: fakes for the tools that would act on the host (systemctl, systemd-sysusers,
# useradd, getent, chown, hostname, mountpoint) and symlinks to the real tools the scripts
# need, so a tool outside that list fails the test, and a real privileged tool can never run.
# The fake chown changes no ownership; it logs each call with the inode of every operand, so
# ownership is asserted against the file that really ended up in place.
#
# After the rewrite each copy is checked for any absolute path left outside the fake root, so
# an unrelocated path fails the test and never reaches the host.
#
# RELAY_PACKAGE_SCRIPTS_DIR names another directory of the four scripts, for mutation checks.
#
# NOT `set -e`: every case must run and be reported, not stop at the first failure.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)" || exit 1
PKG="$REPO_ROOT/relay/packaging"
SCRIPTS="${RELAY_PACKAGE_SCRIPTS_DIR:-$PKG/scripts}"
[ -z "${RELAY_PACKAGE_SCRIPTS_DIR:-}" ] || echo "testing scripts from $SCRIPTS"
SH="$(command -v dash || command -v sh)" || { echo "FAIL: no sh" >&2; exit 1; }
SH="$(readlink -f "$SH")"
WORKDIR="$(mktemp -d)" || { echo "FAIL: mktemp -d failed" >&2; exit 1; }
trap 'case "${WORKDIR:-}" in /*) rm -rf "$WORKDIR" ;; esac' EXIT
case "$WORKDIR" in
  /*) ;;
  *) echo "FAIL: mktemp returned a non-absolute path: '$WORKDIR'" >&2; exit 1 ;;
esac

uid="$(id -u)"
# The tools the scripts may use. Anything else is absent from PATH.
REAL_TOOLS="sh sed grep cat mkdir chmod mv ln rm rmdir mktemp date stat timeout sleep find"
REAL_STAT="$(command -v stat)"

fail=0
n=0
cur_fail=""

# --- the fake root ---------------------------------------------------------------------------

R=""        # the fake root
UM=022      # the umask the scripts run under
SDIR=s      # which relocated copy of the scripts runs (s, or s-notroot)
ENVV=()     # environment for the fakes
RC=0
ETC="" STATE="" MARK="" CONFIG=""

die() { echo "FAIL: $*" >&2; exit 1; }

# fake NAME: writes $R/bin/NAME from stdin, with R and the real stat baked in.
fake() {
  { echo '#!/bin/sh'; echo "R='$R'"; echo "STAT='$REAL_STAT'"; cat; } > "$R/bin/$1"
  chmod 0755 "$R/bin/$1"
}

# relocate SRC DST ROOT_UID: the script with every fixed prefix moved into the fake root, the
# root uid replaced by the one the test owns files as, and the hostname timeout shortened.
relocate() {
  sed -e "s|/etc/relay|$R/etc/relay|g" \
      -e "s|/var/lib/relay|$R/var/lib/relay|g" \
      -e "s|/usr/share/relay|$R/usr/share/relay|g" \
      -e "s|/usr/lib/sysusers.d|$R/usr/lib/sysusers.d|g" \
      -e "s|/run/systemd/system|$R/run/systemd/system|g" \
      -e "s|^ROOT_UID=0\$|ROOT_UID=$3|" \
      -e "s|^HOSTNAME_TIMEOUT=10\$|HOSTNAME_TIMEOUT=1|" "$1" > "$2"
}

# leak_check FILE: no absolute path is left outside the fake root. Comment lines are dropped,
# the fake root becomes a letter token (so a relocated /etc is preceded by a letter and does
# not match), the two paths the scripts may name in the open are deleted, and any remaining
# top-level system directory, whatever follows it, fails.
leak_check() {
  local left
  left="$(grep -Ev '^[[:space:]]*#' "$1" | sed -e "s|$R|FAKEROOT|g" -e 's|/dev/null||g' -e 's|/usr/sbin/nologin||g' \
    | grep -E "(^|[^A-Za-z0-9_.\$}-])/(etc|var|usr|run|bin|sbin|lib|lib64|opt|srv|tmp|home|root|proc|sys|boot|mnt|media|dev)([^A-Za-z0-9_.-]|\$)")" || true
  if [ -n "$left" ]; then
    echo "FAIL: $(basename "$1") still names an absolute path outside the fake root after relocation:" >&2
    echo "$left" >&2
    exit 1
  fi
}

new_root() { # systemd present|absent|file
  R="$(mktemp -d "$WORKDIR/root.XXXXXX")" || die "mktemp -d"
  case "$R" in
    *'|'* | *'&'* | *'\'* | *"'"* | */etc/relay* | */var/lib/relay* | */usr/share/relay* | */usr/lib/sysusers.d* | */run/systemd/system*)
      die "fake root '$R' has a character or path the rewrite cannot handle" ;;
  esac
  ETC="$R/etc/relay" STATE="$R/var/lib/relay" MARK="$R/var/lib/relay-package" CONFIG="$R/etc/relay/relay.toml"
  UM=022 SDIR=s ENVV=(FAKE_FQDN=relay.example.com)
  mkdir -p "$R/s" "$R/s-notroot" "$R/bin" "$R/etc" "$R/var/lib" "$R/usr/share/relay" "$R/usr/lib/sysusers.d"
  cp "$PKG/relay.toml.in" "$PKG/relay.toml.example" "$PKG/configuration-guide.txt" "$R/usr/share/relay/"
  chmod 0644 "$R"/usr/share/relay/*
  cp "$PKG/relay.sysusers.conf" "$R/usr/lib/sysusers.d/relay.conf"
  case "${1:-absent}" in
    present) mkdir -p "$R/run/systemd/system" ;;
    file) mkdir -p "$R/run/systemd"; : > "$R/run/systemd/system" ;;
  esac
  : > "$R/systemctl.log"; : > "$R/systemctl.all"; : > "$R/chown.log"; : > "$R/forbidden.log"
  : > "$R/account.log"; : > "$R/hostname.log"; : > "$R/mountpoint.log"; : > "$R/stdout"; : > "$R/stderr"

  fake systemctl <<'FAKE'
echo "$*" >> "$R/systemctl.log"
echo "$*" >> "$R/systemctl.all"
[ -z "${FAKE_SYSTEMCTL_FAIL:-}" ] || exit 1
exit 0
FAKE
  fake systemd-sysusers <<'FAKE'
echo "systemd-sysusers $*" >> "$R/account.log"
: > "$R/account-user"
[ -n "${FAKE_ACCOUNT_NOGROUP:-}" ] || : > "$R/account-group"
exit 0
FAKE
  fake useradd <<'FAKE'
echo "useradd $*" >> "$R/account.log"
: > "$R/account-user"
[ -n "${FAKE_ACCOUNT_NOGROUP:-}" ] || : > "$R/account-group"
exit 0
FAKE
  fake getent <<'FAKE'
case "$1 ${2:-}" in
  "passwd relay") [ -e "$R/account-user" ]; exit $? ;;
  "group relay") [ -e "$R/account-group" ]; exit $? ;;
esac
exit 2
FAKE
  # One line per call: the arguments, " :: ", then the inode of every operand after the owner
  # spec (flags skipped; "-" for a missing operand), taken before the call decides to fail.
  fake chown <<'FAKE'
owner=""
ids=""
for a in "$@"; do
  case "$a" in -*) continue ;; esac
  if [ -z "$owner" ]; then owner="$a"; continue; fi
  i=$("$STAT" -c %i -- "$a" 2>/dev/null) || i="-"
  ids="$ids $i"
done
echo "$* ::$ids" >> "$R/chown.log"
if [ -n "${FAKE_CHOWN_FAIL_MATCH:-}" ]; then
  case "$*" in "$FAKE_CHOWN_FAIL_MATCH"*) exit 1 ;; esac
fi
# A file that appears at the target while the install is between its chown and its link.
if [ -n "${FAKE_PLANT:-}" ] && [ "$owner" = root:relay ]; then
  printf 'planted\n' > "$R/etc/relay/relay.toml"
fi
exit 0
FAKE
  fake hostname <<'FAKE'
echo "hostname $*" >> "$R/hostname.log"
[ -z "${FAKE_HOSTNAME_SLEEP:-}" ] || sleep "$FAKE_HOSTNAME_SLEEP"
[ -n "${FAKE_FQDN+x}" ] || exit 1
printf '%s\n' "$FAKE_FQDN"
FAKE
  fake mountpoint <<'FAKE'
echo "$*" >> "$R/mountpoint.log"
[ "${FAKE_MOUNTPOINT:-}" = 1 ]
exit $?
FAKE
  local t
  for t in relay userdel groupdel deluser delgroup; do
    fake "$t" <<FAKE
echo "$t \$*" >> "\$R/forbidden.log"
exit 0
FAKE
  done
  for t in $REAL_TOOLS; do
    ln -s "$(command -v "$t")" "$R/bin/$t" || die "no real $t on this host"
  done

  local f s
  for f in preinst postinst prerm postrm; do
    [ -f "$SCRIPTS/$f.sh" ] || die "no script $SCRIPTS/$f.sh"
    relocate "$SCRIPTS/$f.sh" "$R/s/$f.sh" "$uid"
    relocate "$SCRIPTS/$f.sh" "$R/s-notroot/$f.sh" "$((uid + 1))"
    for s in s s-notroot; do leak_check "$R/$s/$f.sh"; done
  done
}

# sc <script> [args...]: run one maintainer script in the fake root; sets RC.
sc() {
  local name="$1"; shift
  ( cd "$R" && umask "$UM" && exec env -i PATH="$R/bin" ${ENVV[@]+"${ENVV[@]}"} \
      "$SH" "$R/$SDIR/$name.sh" "$@" ) >>"$R/stdout" 2>>"$R/stderr"
  RC=$?
}

# must <script> [args...]: sc, and a non-zero exit fails the case.
must() {
  sc "$@"
  [ "$RC" -eq 0 ] || { [ -n "$cur_fail" ] || cur_fail="$* exited $RC: $(tail -n 3 "$R/stderr" | tr '\n' ' ')"; }
}

# --- assertions ------------------------------------------------------------------------------

expect() { # description, test command...
  local d="$1"; shift
  "$@" || { [ -n "$cur_fail" ] || cur_fail="$d"; }
}
not() { ! "$@"; }
mode_is() { [ "$(stat -c %a "$1" 2>/dev/null)" = "${2#0}" ]; }
absent() { [ ! -e "$1" ] && [ ! -L "$1" ]; }
present() { [ -e "$1" ] || [ -L "$1" ]; }
has_text() { [ "$(cat "$1" 2>/dev/null)" = "$2" ]; }
has_line() { grep -Fxq -- "$1" "$2"; }
has_str() { grep -Fq -- "$1" "$2"; }
ino() { stat -c %i -- "$1" 2>/dev/null; }
empty_dir() { [ -d "$1" ] && [ -z "$(ls -A "$1")" ]; }
log_is() { [ "$(cat "$R/systemctl.log")" = "$1" ]; }
clear_logs() { : > "$R/systemctl.log"; : > "$R/chown.log"; : > "$R/hostname.log"; : > "$R/account.log"; : > "$R/stdout"; : > "$R/stderr"; }
count_in() { grep -Fxc -- "$1" "$2"; }
marker_has() { grep -Fxq -- "$1" "$MARK/marker" 2>/dev/null; }

# chown_ids OWNER: for every chown call whose owner spec is OWNER, the call's operand inodes,
# one line per call.
chown_ids() {
  awk -v o="$1" '{
    split($0, part, " :: "); n = split(part[1], a, " "); own = ""
    for (k = 1; k <= n; k++) { if (a[k] ~ /^-/) continue; own = a[k]; break }
    if (own == o) print part[2]
  }' "$R/chown.log"
}
# owner_calls OWNER INODE: the number of chown calls with owner spec OWNER that name INODE.
owner_calls() {
  awk -v o="$1" -v i="$2" '{
    split($0, part, " :: "); n = split(part[1], a, " "); own = ""
    for (k = 1; k <= n; k++) { if (a[k] ~ /^-/) continue; own = a[k]; break }
    m = split(part[2], ids, " "); hit = 0
    for (k = 1; k <= m; k++) if (ids[k] == i) hit = 1
    if (own == o && hit) c++
  } END { print c + 0 }' "$R/chown.log"
}
# inode_calls INODE: the number of chown calls of any owner that name INODE.
inode_calls() {
  awk -v i="$1" '{
    split($0, part, " :: "); m = split(part[2], ids, " ")
    for (k = 1; k <= m; k++) if (ids[k] == i) { c++; break }
  } END { print c + 0 }' "$R/chown.log"
}
# every chown call has owner spec OWNER.
all_owners_are() {
  awk -v o="$1" '{
    split($0, part, " :: "); n = split(part[1], a, " "); own = ""
    for (k = 1; k <= n; k++) { if (a[k] ~ /^-/) continue; own = a[k]; break }
    if (own != o) bad = 1
  } END { exit bad }' "$R/chown.log"
}

# snapshot: the type, mode, owner and content hash of everything the scripts may touch, except
# the marker directory.
snapshot() {
  ( cd "$R" && { find etc var other usr run -printf '%y %m %U %p -> %l\n' 2>/dev/null
                 find etc var other -type f -exec sha256sum {} + 2>/dev/null; } | grep -v relay-package | LC_ALL=C sort )
}
unchanged() { [ "$(snapshot)" = "$(cat "$1")" ]; }

# After every case: the Relay was never started or enabled, the account was never removed and
# the relay binary never ran, and no temporary file was left in /etc/relay.
after_case() {
  expect "systemctl started, restarted or enabled the Relay" \
    not grep -Eq '(^| )(start|restart|try-restart|reload-or-restart|enable|--now)( |$)' "$R/systemctl.all"
  expect "relay, userdel, groupdel, deluser or delgroup was called: $(cat "$R/forbidden.log" 2>/dev/null)" \
    test ! -s "$R/forbidden.log"
  local leftover="" f
  for f in "$ETC"/.relay-pkg.*; do [ -e "$f" ] && leftover="$leftover $f"; done
  expect "a temporary file was left in /etc/relay: $leftover" test -z "$leftover"
}

# --- sequences, one per argument convention ---------------------------------------------------

first_install() { # deb|rpm
  if [ "$1" = deb ]; then must preinst install; must postinst configure
  else must preinst 1; must postinst 1; fi
}
upgrade() {
  if [ "$1" = deb ]; then
    must prerm upgrade 1.0; must preinst upgrade 1.0; must postinst configure 1.0; must postrm upgrade 1.0
  else must preinst 2; must postinst 2; must prerm 1; must postrm 1; fi
}
remove() { # remove (deb) or erase (rpm)
  if [ "$1" = deb ]; then must prerm remove; must postrm remove
  else must prerm 0; must postrm 0; fi
}
# purge_sequence: what `apt purge` runs.
purge_sequence() { must prerm remove; must postrm remove; must postrm purge; }

# The chown assertions that prove who owns what by inode: the generated file is the one root:relay
# call, and nothing ever gave it, or any path named relay.toml, to another owner; the state
# directory is the one relay:relay call.
assert_ownership() {
  local cfg_i state_i
  cfg_i="$(ino "$CONFIG")"; state_i="$(ino "$STATE")"
  expect "relay.toml has no inode" test -n "$cfg_i"
  expect "exactly one chown root:relay, on the inode that is now relay.toml" \
    test "$(chown_ids root:relay)" = "$cfg_i"
  expect "relay.toml's inode was chowned to another owner" \
    test "$(owner_calls relay:relay "$cfg_i")$(owner_calls relay "$cfg_i")$(owner_calls root:root "$cfg_i")" = 000
  expect "a chown named relay.toml itself" not grep -Fq "relay.toml" "$R/chown.log"
  expect "exactly one chown relay:relay, on the state directory's inode" \
    test "$(chown_ids relay:relay)" = "$state_i"
  expect "the state directory was chowned more than once" test "$(inode_calls "$state_i")" = 1
}

# --- cases -----------------------------------------------------------------------------------

case_first_install_places_config_state_and_account() { # conv
  local um guide
  for um in 022 000 077; do
    new_root present; UM=$um
    first_install "$1"
    expect "umask $um: /etc/relay is not 0755" mode_is "$ETC" 0755
    expect "umask $um: relay.toml is not 0640" mode_is "$CONFIG" 0640
    expect "umask $um: /var/lib/relay is not 0700" mode_is "$STATE" 0700
    expect "umask $um: marker directory is not 0700" mode_is "$MARK" 0700
    expect "umask $um: marker is not 0600" mode_is "$MARK/marker" 0600
    expect "umask $um: ownership" assert_ownership
    expect "umask $um: /etc/relay was chowned to root exactly once" \
      test "$(chown_ids root:root)" = "$(ino "$ETC")"
    expect "umask $um: the account was not created from the packaged sysusers entry" \
      has_line "systemd-sysusers $R/usr/lib/sysusers.d/relay.conf" "$R/account.log"
    expect "umask $um: systemctl log is not daemon-reload, preset" log_is $'daemon-reload\npreset relay.service'
    expect "umask $um: the generated file is not the template with its one hostname line" \
      test "$(diff "$R/usr/share/relay/relay.toml.in" "$CONFIG" | grep '^[<>]')" = \
$'< hostname = "@FQDN@"\n> hostname = "relay.example.com"'
    expect "umask $um: the marker lacks created tokens" \
      test "$(marker_has 'created etc'; echo $?)$(marker_has 'created config'; echo $?)$(marker_has 'created state'; echo $?)" = 000
    after_case
  done
  # The guide is printed, whole, with what the install chose.
  guide="$R/usr/share/relay/configuration-guide.txt"
  expect "a guide line is not printed" bash -c 'while IFS= read -r l; do [ -z "$l" ] || grep -Fxq -- "$l" "$1" || exit 1; done < "$2"' _ "$R/stdout" "$guide"
  expect "the guide does not name relay init" has_str 'relay init' "$R/stdout"
  expect "the guide does not warn against imaging the host" has_str 'Never capture an image or snapshot of this host after the Relay has first started' "$R/stdout"
  expect "the status line does not name the hostname" has_line 'Certificate hostname (tls.hostname): relay.example.com' "$R/stdout"
  expect "the guide's last line does not name the kept copy" \
    bash -c 'tail -n 1 "$1" | grep -Fq /usr/share/relay/configuration-guide.txt' _ "$guide"
  expect "the guide carries a credential" not grep -Eiq 'glp_|password:|token:|secret =' "$guide"
}

case_first_install_without_fqdn() { # conv
  local v name
  for v in unset absent unqualified injection hyphen doubledot longlabel; do
    new_root present
    case "$v" in
      unset) ENVV=() ;;
      absent) rm "$R/bin/hostname" ;;
      unqualified) ENVV=(FAKE_FQDN=relayhost) ;;
      injection) ENVV=("FAKE_FQDN=relay.example.com\"
hostname = \"evil.example.com") ;;
      hyphen) ENVV=(FAKE_FQDN=-bad.example.com) ;;
      doubledot) ENVV=(FAKE_FQDN=a..example.com) ;;
      longlabel) ENVV=("FAKE_FQDN=$(printf 'a%.0s' $(seq 64)).example.com") ;;
    esac
    name="$v"
    first_install "$1"
    expect "$name: the hostname line is not commented out" has_line '# hostname = "relay.example.internal"' "$CONFIG"
    expect "$name: an uncommented hostname key was written" not grep -q '^hostname' "$CONFIG"
    expect "$name: only the hostname line differs from the template" \
      test "$(diff "$R/usr/share/relay/relay.toml.in" "$CONFIG" | grep '^[<>]')" = \
$'< hostname = "@FQDN@"\n> # hostname = "relay.example.internal"'
    expect "$name: the status line does not name tls.hostname" has_str 'so tls.hostname is commented out' "$R/stdout"
    expect "$name: ownership" assert_ownership
    after_case
  done
}

case_first_install_hostname_stall_is_bounded() { # conv
  local t0 t1
  new_root present
  ENVV=(FAKE_FQDN=relay.example.com FAKE_HOSTNAME_SLEEP=5)
  t0="$(date +%s)"
  first_install "$1"
  t1="$(date +%s)"
  expect "a stalled hostname held the install for $((t1 - t0)) s" test "$((t1 - t0))" -lt 4
  expect "a stalled hostname still produced a name" has_line '# hostname = "relay.example.internal"' "$CONFIG"
  after_case
}

case_first_install_without_systemd_runs_no_systemctl() { # conv
  new_root absent
  first_install "$1"
  expect "systemctl ran without /run/systemd/system" test ! -s "$R/systemctl.all"
  expect "relay.toml was not placed" present "$CONFIG"
  expect "the state directory was not created" present "$STATE"
  after_case
}

case_first_install_with_run_systemd_system_a_file_runs_no_systemctl() { # conv
  new_root file
  first_install "$1"
  expect "systemctl ran with /run/systemd/system a regular file" test ! -s "$R/systemctl.all"
  expect "relay.toml was not placed" present "$CONFIG"
  after_case
}

case_preset_failure_does_not_fail_install() { # conv
  new_root present
  ENVV+=(FAKE_SYSTEMCTL_FAIL=1)
  first_install "$1"
  expect "relay.toml was not placed" present "$CONFIG"
  expect "the state directory was not created" present "$STATE"
  after_case
}

case_sysusers_absent_falls_back_to_useradd() { # conv
  new_root present
  rm "$R/bin/systemd-sysusers"
  first_install "$1"
  expect "useradd was not called with the account's flags" \
    grep -Fq -- 'useradd --system --user-group --no-create-home --home-dir / --shell /usr/sbin/nologin' "$R/account.log"
  expect "relay.toml was not placed" present "$CONFIG"
  after_case
}

case_no_account_tool_fails_install_and_places_nothing() { # conv
  new_root present
  rm "$R/bin/systemd-sysusers" "$R/bin/useradd"
  sc preinst "$([ "$1" = deb ] && echo install || echo 1)"
  sc postinst "$([ "$1" = deb ] && echo configure || echo 1)"
  expect "postinst succeeded with no way to create the account" test "$RC" -ne 0
  expect "/etc/relay was created" absent "$ETC"
  expect "/var/lib/relay was created" absent "$STATE"
  expect "a chown ran" test ! -s "$R/chown.log"
  after_case
}

case_account_without_group_fails_install_and_places_nothing() { # conv
  local v
  for v in user-only-no-tools sysusers-makes-no-group; do
    new_root present
    if [ "$v" = user-only-no-tools ]; then
      : > "$R/account-user"
      rm "$R/bin/systemd-sysusers" "$R/bin/useradd"
    else
      ENVV+=(FAKE_ACCOUNT_NOGROUP=1)
    fi
    sc preinst "$([ "$1" = deb ] && echo install || echo 1)"
    sc postinst "$([ "$1" = deb ] && echo configure || echo 1)"
    expect "$v: postinst succeeded without the relay group" test "$RC" -ne 0
    expect "$v: stderr does not name the relay group" has_str 'relay group' "$R/stderr"
    expect "$v: /etc/relay was created" absent "$ETC"
    expect "$v: /var/lib/relay was created" absent "$STATE"
    expect "$v: a chown ran" test ! -s "$R/chown.log"
    after_case
  done
}

case_failed_first_configure_rerun_converges() { # deb only
  local s_i
  # The account tool is missing, then present.
  new_root present
  rm "$R/bin/systemd-sysusers" "$R/bin/useradd"
  must preinst install
  sc postinst configure ""
  expect "the first configure succeeded with no account tool" test "$RC" -ne 0
  fake systemd-sysusers <<'FAKE'
echo "systemd-sysusers $*" >> "$R/account.log"
: > "$R/account-user"
: > "$R/account-group"
exit 0
FAKE
  clear_logs
  must postinst configure ""
  expect "the re-run did not generate relay.toml" present "$CONFIG"
  expect "ownership holds for the re-run" assert_ownership
  expect "the guide was not printed once" test "$(count_in 'The Relay is installed and has not been started.' "$R/stdout")" = 1
  expect "the status line was not printed once" test "$(count_in 'Certificate hostname (tls.hostname): relay.example.com' "$R/stdout")" = 1
  after_case

  # A chown fails after relay.toml is placed, then the install is run again.
  new_root present
  ENVV+=("FAKE_CHOWN_FAIL_MATCH=-h relay:relay")
  must preinst install
  sc postinst configure ""
  expect "the first configure survived a failed chown of the state directory" test "$RC" -ne 0
  expect "relay.toml was not placed before the failure" present "$CONFIG"
  expect "the state directory was not created before the failure" present "$STATE"
  ENVV=(FAKE_FQDN=relay.example.com)
  clear_logs
  must postinst configure ""
  expect "the re-run did not report the config as generated earlier" \
    has_line "Kept $CONFIG, generated earlier in this install." "$R/stdout"
  s_i="$(ino "$STATE")"
  expect "the re-run did not chown the state directory to relay:relay by inode" \
    test "$(chown_ids relay:relay)" = "$s_i"
  expect "the re-run chowned or rewrote relay.toml" test "$(chown_ids root:relay)" = ""
  expect "the state directory is not 0700" mode_is "$STATE" 0700
  expect "created state is not recorded exactly once" test "$(count_in 'created state' "$MARK/marker")" = 1
  expect "created config is not recorded exactly once" test "$(count_in 'created config' "$MARK/marker")" = 1
  expect "created etc is not recorded exactly once" test "$(count_in 'created etc' "$MARK/marker")" = 1
  after_case
}

case_existing_relay_toml_is_never_rewritten() { # conv
  new_root present
  mkdir -m 0755 "$ETC"; printf 'operator config\n' > "$CONFIG"
  first_install "$1"
  expect "relay.toml was rewritten by the first install" has_text "$CONFIG" "operator config"
  expect "the install did not say it kept the file" has_line "Kept the existing $CONFIG; nothing was generated." "$R/stdout"
  expect "the marker records a config the package did not create" not marker_has 'created config'
  expect "the marker does not record the existing config" marker_has 'existed config'
  expect "a chown named the operator's file" not grep -Fq "relay.toml" "$R/chown.log"
  upgrade "$1"
  expect "relay.toml was rewritten by the upgrade" has_text "$CONFIG" "operator config"
  remove "$1"
  expect "relay.toml changed by remove or erase" has_text "$CONFIG" "operator config"
  if [ "$1" = deb ]; then must postrm purge; fi
  expect "relay.toml changed by purge" has_text "$CONFIG" "operator config"
  after_case
}

case_dangling_relay_toml_symlink_not_written_through() { # conv
  new_root present
  mkdir -m 0755 "$ETC"; ln -s "$R/nowhere" "$CONFIG"
  first_install "$1"
  expect "the dangling symlink was written through" absent "$R/nowhere"
  expect "the dangling symlink did not survive" test -L "$CONFIG"
  remove "$1"
  if [ "$1" = deb ]; then must postrm purge; fi
  expect "the dangling symlink did not survive removal" test -L "$CONFIG"
  after_case
}

case_symlinked_etc_relay_not_written_through() { # conv
  new_root present
  mkdir -m 0755 "$R/other"; ln -s "$R/other" "$ETC"
  first_install "$1"
  expect "something was placed under the symlink target" empty_dir "$R/other"
  expect "a chown named a path under /etc/relay" not grep -Fq "$R/etc/relay" "$R/chown.log"
  expect "a chown to root:relay ran" test -z "$(chown_ids root:relay)"
  expect "stderr does not say /etc/relay is a symlink" has_str "$ETC is a symlink" "$R/stderr"
  expect "the status line does not say nothing was generated" has_str 'was not generated' "$R/stdout"
  expect "the install did not create the state directory" present "$STATE"
  after_case
}

case_etc_relay_a_file_is_not_written_through() { # conv
  new_root present
  printf 'not a directory\n' > "$ETC"
  first_install "$1"
  expect "relay.toml was generated" absent "$CONFIG"
  expect "the file at /etc/relay was replaced" has_text "$ETC" "not a directory"
  expect "stderr does not say /etc/relay is not a directory" has_str "$ETC is not a directory" "$R/stderr"
  expect "the status line does not say nothing was generated" has_str 'was not generated' "$R/stdout"
  after_case
}

case_failed_config_chown_places_nothing() { # conv
  new_root present
  ENVV+=("FAKE_CHOWN_FAIL_MATCH=-h root:relay")
  sc preinst "$([ "$1" = deb ] && echo install || echo 1)"
  sc postinst "$([ "$1" = deb ] && echo configure || echo 1)"
  expect "an install whose chown of relay.toml failed succeeded" test "$RC" -ne 0
  expect "a relay.toml with the wrong owner was placed" absent "$CONFIG"
  expect "the marker records a config that was not generated" not marker_has 'created config'
  after_case
}

case_writable_etc_relay_not_written_through() { # conv
  local m
  for m in 0775 0757 1777; do
    new_root present
    mkdir "$ETC"; chmod "$m" "$ETC"
    first_install "$1"
    expect "$m: relay.toml was generated" absent "$CONFIG"
    expect "$m: something was left in /etc/relay" empty_dir "$ETC"
    expect "$m: a chown named a path under /etc/relay" not grep -Fq "$R/etc/relay" "$R/chown.log"
    expect "$m: a chown to root:relay ran" test -z "$(chown_ids root:relay)"
    expect "$m: stderr does not name /etc/relay as writable by group or other" \
      grep -Fq "$ETC is writable by group or other" "$R/stderr"
    expect "$m: the status line does not say nothing was generated" has_str 'was not generated' "$R/stdout"
    expect "$m: the directory's mode changed" mode_is "$ETC" "$m"
    after_case
  done
}

case_etc_relay_not_owned_by_root_not_written_through() { # conv
  new_root present
  mkdir -m 0755 "$ETC"
  SDIR=s; must preinst "$([ "$1" = deb ] && echo install || echo 1)"
  SDIR='s-notroot'; must postinst "$([ "$1" = deb ] && echo configure || echo 1)"
  expect "relay.toml was generated into a directory root does not own" absent "$CONFIG"
  expect "something was left in /etc/relay" empty_dir "$ETC"
  expect "a chown named a path under /etc/relay" not grep -Fq "$R/etc/relay" "$R/chown.log"
  expect "stderr does not say /etc/relay is not owned by root" has_str "$ETC is not owned by root" "$R/stderr"
  after_case
}

case_planted_relay_toml_is_never_clobbered() { # conv
  new_root present
  mkdir -m 0755 "$ETC"
  ENVV+=(FAKE_PLANT=1)
  sc preinst "$([ "$1" = deb ] && echo install || echo 1)"
  sc postinst "$([ "$1" = deb ] && echo configure || echo 1)"
  expect "an install that lost the race for relay.toml succeeded" test "$RC" -ne 0
  expect "a file that appeared at the target was replaced" has_text "$CONFIG" planted
  expect "the marker records a config the package did not create" not marker_has 'created config'
  after_case
}

case_preinst_refuses_bad_marker_dir() { # conv
  local v arg
  arg="$([ "$1" = deb ] && echo install || echo 1)"
  for v in symlink file notroot; do
    new_root present
    mkdir -m 0755 "$R/other"
    case "$v" in
      symlink) ln -s "$R/other" "$MARK" ;;
      file) : > "$MARK" ;;
      notroot) mkdir -m 0755 "$MARK"; SDIR='s-notroot' ;;
    esac
    sc preinst "$arg"
    expect "$v: preinst accepted it" test "$RC" -eq 1
    expect "$v: stderr does not name it" has_str "relay-package" "$R/stderr"
    expect "$v: a marker was written" absent "$R/other/marker"
    expect "$v: /var/lib/relay was created" absent "$STATE"
    # dpkg runs postrm abort-install after a failed preinst; it never reaches through a refused
    # directory.
    if [ "$v" = symlink ]; then
      printf 'precious\n' > "$R/other/marker"
      must postrm abort-install
      expect "$v: abort-install deleted through the symlink" has_text "$R/other/marker" precious
      rm -f "$R/other/marker"
    fi
    case "$v" in
      symlink) expect "$v: the symlink target was touched" empty_dir "$R/other"; expect "$v: the symlink target's mode changed" mode_is "$R/other" 0755; expect "$v: the symlink is gone" test -L "$MARK" ;;
      file) expect "$v: the file was replaced" test -f "$MARK" -a ! -s "$MARK" ;;
      notroot) expect "$v: the directory was changed" mode_is "$MARK" 0755; expect "$v: a marker was written" absent "$MARK/marker" ;;
    esac
    after_case
  done
}

case_existing_state_dir_left_as_is() { # conv
  local s_i
  new_root present
  mkdir -m 0755 "$STATE"; printf 'x\n' > "$STATE/keep"
  s_i="$(ino "$STATE")"
  first_install "$1"
  expect "the operator's state directory was chowned" test "$(inode_calls "$s_i")" = 0
  expect "the operator's state directory's mode changed" mode_is "$STATE" 0755
  expect "the marker does not record the existing state directory" marker_has 'existed state'
  expect "the marker records a state directory the package did not create" not marker_has 'created state'
  after_case
}

case_guide_missing_does_not_fail_install() { # conv
  new_root present
  rm "$R/usr/share/relay/configuration-guide.txt"
  first_install "$1"
  expect "relay.toml was not placed" present "$CONFIG"
  expect "stderr does not name the missing guide" has_str "$R/usr/share/relay/configuration-guide.txt" "$R/stderr"
  expect "the status line was not printed" has_str 'Certificate hostname (tls.hostname)' "$R/stdout"
  after_case
}

case_upgrade_changes_nothing() { # conv
  new_root present
  first_install "$1"
  echo '# an operator edit' >> "$CONFIG"
  snapshot > "$R/snap"
  cp "$MARK/marker" "$R/marker.before"
  clear_logs
  upgrade "$1"
  expect "an upgrade changed the tree" unchanged "$R/snap"
  expect "an upgrade changed the marker" cmp -s "$R/marker.before" "$MARK/marker"
  if [ "$1" = deb ]; then
    expect "systemctl log is not exactly daemon-reload" log_is 'daemon-reload'
  else
    expect "systemctl log is not exactly two daemon-reloads" log_is $'daemon-reload\ndaemon-reload'
  fi
  expect "an upgrade called hostname, sysusers or useradd" test ! -s "$R/hostname.log" -a ! -s "$R/account.log"
  expect "an upgrade called chown" test ! -s "$R/chown.log"
  expect "an upgrade printed" test ! -s "$R/stdout"
  after_case
}

case_deb_configure_with_old_version_never_presets_or_generates() { # deb
  new_root present
  must postinst configure 1.0
  expect "a configure with an old version generated relay.toml" absent "$CONFIG"
  expect "a configure with an old version created /etc/relay" absent "$ETC"
  expect "a configure with an old version created the state directory" absent "$STATE"
  expect "a configure with an old version ran preset" log_is 'daemon-reload'
  after_case
}

case_remove_stops_disables_keeps_everything() { # conv
  new_root present
  first_install "$1"
  snapshot > "$R/snap"
  clear_logs
  remove "$1"
  expect "remove changed the tree" unchanged "$R/snap"
  expect "systemctl log is not stop, disable, daemon-reload" \
    log_is $'stop relay.service\n--no-reload disable relay.service\ndaemon-reload'
  if [ "$1" = deb ]; then expect "remove deleted the marker" present "$MARK/marker"; fi
  after_case

  new_root absent
  first_install "$1"
  clear_logs
  remove "$1"
  expect "without systemd, systemctl log is not exactly disable" log_is '--no-reload disable relay.service'
  after_case
}

case_missing_or_unknown_arguments_are_safe() { # conv
  local s a
  new_root present
  mkdir -m 0755 "$ETC" "$STATE"
  snapshot > "$R/snap"
  for s in preinst postinst prerm postrm; do
    sc "$s"; expect "$s with no argument exited $RC" test "$RC" -eq 0
    for a in "" abort-upgrade failed-upgrade; do
      sc "$s" "$a"; expect "$s '$a' exited $RC" test "$RC" -eq 0
    done
  done
  expect "an unknown argument changed the tree" unchanged "$R/snap"
  expect "an unknown argument called systemctl" test ! -s "$R/systemctl.all"
  expect "an unknown argument called chown" test ! -s "$R/chown.log"
  expect "an unknown argument wrote a marker" absent "$MARK"
  after_case
}

# --- purge (deb), erase (rpm) ----------------------------------------------------------------

# populate_state: the CA and the store, as the Relay's first start would leave them.
populate_state() {
  mkdir -p "$STATE/ca"; printf 'ca key\n' > "$STATE/ca/ca.key"; printf 'store\n' > "$STATE/relay.db"
}
purged_siblings() { ls -d "$R"/var/lib/relay.purged-* 2>/dev/null; }

case_purge_moves_state_aside_and_removes_created_config() { # deb
  local s_i dst top rec
  new_root present
  first_install deb
  populate_state
  s_i="$(ino "$STATE")"
  clear_logs
  purge_sequence
  dst="$(purged_siblings)"
  expect "purge did not leave exactly one purged sibling" test "$(purged_siblings | wc -l)" = 1
  expect "the sibling does not hold the CA and the store together" \
    test -f "$dst/ca/ca.key" -a -f "$dst/relay.db"
  expect "the sibling is not 0700" mode_is "$dst" 0700
  expect "the sibling is not the state directory's inode" test "$(ino "$dst")" = "$s_i"
  expect "purge did not print where the state went" has_str "$dst" "$R/stdout"
  expect "/var/lib/relay remains" absent "$STATE"
  expect "relay.toml remains" absent "$CONFIG"
  expect "/etc/relay remains" absent "$ETC"
  expect "the marker directory remains" absent "$MARK"
  expect "the account flags are gone" test -e "$R/account-user" -a -e "$R/account-group"
  top="$(grep -Fxn -- "-h root:root $STATE :: $s_i" "$R/chown.log" | head -n 1 | cut -d: -f1)"
  # find lists a directory's entries in the filesystem's order, so the walk's call names ca/
  # somewhere after $STATE, not necessarily first.
  rec="$(grep -n -- "^-h root:root $STATE " "$R/chown.log" | grep -F -- " $STATE/ca " | head -n 1 | cut -d: -f1)"
  expect "the re-owns did not run, by the pre-move path and inode, top directory first" \
    test -n "$top" -a -n "$rec" -a "$top" -lt "$rec"
  expect "the walk did not re-own the files inside" \
    test "$(owner_calls root:root "$(ino "$dst/ca/ca.key")")$(owner_calls root:root "$(ino "$dst/relay.db")")" = 11
  expect "a chown after the purge began had another owner" all_owners_are root:root
  after_case
}

case_purge_keeps_operator_files_in_etc_relay() { # deb
  new_root present
  first_install deb
  printf 'rules\n' > "$ETC/gate-rules.json"
  purge_sequence
  expect "relay.toml remains" absent "$CONFIG"
  expect "the operator's file was deleted" has_text "$ETC/gate-rules.json" rules
  expect "purge did not name the kept directory" has_str "$ETC holds files the package did not create" "$R/stdout"
  after_case
}

case_purge_moves_preexisting_state_dir_too() { # deb
  new_root present
  mkdir -m 0755 "$STATE"; printf 'old ca\n' > "$STATE/ca.key"
  first_install deb
  purge_sequence
  expect "a state directory the package did not create was left in place" absent "$STATE"
  expect "its files did not move together" test -f "$(purged_siblings)/ca.key"
  after_case
}

case_purge_mount_point_reowns_in_place() { # deb
  local s_i
  new_root present
  ENVV+=(FAKE_MOUNTPOINT=1)
  first_install deb
  populate_state
  s_i="$(ino "$STATE")"
  clear_logs
  purge_sequence
  expect "/var/lib/relay did not stay in place" test -f "$STATE/ca/ca.key" -a -f "$STATE/relay.db"
  expect "the mount point is not 0700" mode_is "$STATE" 0700
  expect "the top directory was not re-owned to root by inode" \
    test "$(owner_calls root:root "$s_i")" = 2
  expect "a chown after the purge began had another owner" all_owners_are root:root
  expect "a purged sibling was made" test -z "$(purged_siblings)"
  expect "purge did not say it is a mount point and was not moved" \
    bash -c 'grep -Fq "is a mount point" "$1" && grep -Fq "and not moved" "$1"' _ "$R/stdout"
  expect "relay.toml remains" absent "$CONFIG"
  expect "the marker directory remains" absent "$MARK"
  expect "mountpoint was not asked about /var/lib/relay" has_str "$STATE" "$R/mountpoint.log"
  after_case

  new_root present
  rm "$R/bin/mountpoint"
  first_install deb
  populate_state
  purge_sequence
  expect "without mountpoint, a directory on the same device was not moved" absent "$STATE"
  expect "without mountpoint, the sibling does not hold the state" test -f "$(purged_siblings)/ca/ca.key"
  after_case
}

case_purge_symlinked_state_dir_moves_nothing() { # deb
  new_root present
  mkdir -m 0755 "$R/other"; printf 'x\n' > "$R/other/f"
  ln -s "$R/other" "$STATE"
  first_install deb
  clear_logs
  purge_sequence
  expect "purge touched what the symlink points to" test "$(cat "$R/other/f")" = x -a "$(stat -c %a "$R/other")" = 755
  expect "the symlink did not survive" test -L "$STATE"
  expect "purge chowned through a symlink" test ! -s "$R/chown.log"
  expect "purge made a sibling" test -z "$(purged_siblings)"
  expect "purge did not say it is a symlink" has_str "$STATE is a symlink" "$R/stdout"
  after_case
}

case_purge_through_symlinked_etc_deletes_nothing() { # deb
  new_root present
  mkdir -m 0755 "$R/other"; printf 'operator\n' > "$R/other/relay.toml"
  ln -s "$R/other" "$ETC"
  first_install deb
  # A marker that claims the package created both, so only the directory check protects them.
  printf 'created config\ncreated etc\n' > "$MARK/marker"
  purge_sequence
  expect "purge deleted through a symlinked /etc/relay" has_text "$R/other/relay.toml" operator
  expect "the symlink did not survive" test -L "$ETC"
  expect "purge did not name it" has_str "$ETC is not a plain directory" "$R/stdout"
  after_case
}

case_purge_keeps_what_existed_before_the_install() { # deb
  new_root present
  first_install deb
  # A marker that says both: what existed before the first install is never the package's.
  printf 'existed config\nexisted etc\n' >> "$MARK/marker"
  purge_sequence
  expect "purge deleted a file the marker says existed" present "$CONFIG"
  after_case
}

case_purge_failed_top_reown_exits_nonzero_and_keeps_config() { # deb
  new_root present
  first_install deb
  populate_state
  ENVV+=("FAKE_CHOWN_FAIL_MATCH=-h root:root $STATE")
  clear_logs
  must prerm remove; must postrm remove
  sc postrm purge
  expect "a failed re-own of the state directory was reported as success" test "$RC" -ne 0
  expect "the walk ran after a failed top re-own" test "$(wc -l < "$R/chown.log")" = 1
  expect "the state directory was moved" test -f "$STATE/ca/ca.key"
  expect "a sibling was made" test -z "$(purged_siblings)"
  expect "relay.toml was removed before the state was safe" present "$CONFIG"
  expect "the marker was removed before the state was safe" present "$MARK/marker"
  expect "purge did not say it stopped" has_str 'purge stopped' "$R/stderr"
  after_case
}

case_purge_failed_recursive_reown_exits_nonzero_before_move() { # deb
  new_root present
  first_install deb
  populate_state
  ENVV+=("FAKE_CHOWN_FAIL_MATCH=-h root:root $STATE $STATE/")
  must prerm remove; must postrm remove
  sc postrm purge
  expect "a failed recursive re-own was reported as success" test "$RC" -ne 0
  expect "the top directory was not re-owned before the walk failed" \
    grep -Fq -- "-h root:root $STATE :: " "$R/chown.log"
  expect "the state directory was moved after a failed re-own" test -f "$STATE/ca/ca.key"
  expect "a sibling was made" test -z "$(purged_siblings)"
  expect "relay.toml was removed before the state was safe" present "$CONFIG"
  expect "the marker was removed before the state was safe" present "$MARK/marker"
  ENVV=(FAKE_FQDN=relay.example.com)
  must postrm purge
  expect "the purge could not be run again" absent "$STATE"
  expect "the re-run did not move the state" test -f "$(purged_siblings)/ca/ca.key"
  expect "the re-run did not remove relay.toml" absent "$CONFIG"
  after_case
}

case_purge_does_not_reown_hard_linked_files() { # deb
  local o_i k_i
  new_root present
  first_install deb
  populate_state
  # A file whose other name lies outside the state directory: the relay account can make one.
  mkdir -m 0755 "$R/other"; printf 'outside\n' > "$R/other/outside"; chmod 0666 "$R/other/outside"
  ln "$R/other/outside" "$STATE/ca/linked"
  o_i="$(ino "$R/other/outside")"
  k_i="$(ino "$STATE/ca/ca.key")"
  clear_logs
  purge_sequence
  expect "purge re-owned an inode that has a name outside the state directory" \
    test "$(inode_calls "$o_i")" = 0
  expect "purge re-owned the single-link files by inode" test "$(owner_calls root:root "$k_i")" = 1
  expect "the file outside the state directory changed" test "$(cat "$R/other/outside")" = outside
  expect "the state was not moved" test -f "$(purged_siblings)/ca/linked" -a -f "$(purged_siblings)/ca/ca.key"
  expect "purge did not name the entry it left as found" has_str "$STATE/ca/linked" "$R/stderr"
  expect "relay.toml remains" absent "$CONFIG"
  after_case
}

case_second_purge_is_a_no_op() { # deb
  new_root present
  first_install deb
  populate_state
  purge_sequence
  snapshot > "$R/snap"
  must postrm purge
  expect "a second purge changed the tree" unchanged "$R/snap"
  expect "a second purge made another sibling" test "$(purged_siblings | wc -l)" = 1
  after_case
}

case_reinstall_from_config_files_keeps_created_tokens() { # deb
  new_root present
  first_install deb
  remove deb
  clear_logs
  must preinst install 1.0
  must postinst configure 1.0
  expect "a reinstall from the config-files state ran preset" log_is 'daemon-reload'
  expect "a reinstall generated nothing new" test ! -s "$R/chown.log"
  must postrm purge
  expect "a purge after a reinstall left the package's relay.toml" absent "$CONFIG"
  after_case
}

case_remove_then_reinstall_stays_disabled() { # deb
  new_root present
  first_install deb
  clear_logs
  remove deb
  must preinst install 1.0
  must postinst configure 1.0
  expect "a reinstall after remove enabled the Relay" not grep -Fq preset "$R/systemctl.log"
  expect "the disable did not run exactly once" test "$(grep -c disable "$R/systemctl.log")" = 1
  after_case
}

case_abort_install_forgets_marker() { # deb
  new_root present
  must preinst install
  must postrm abort-install 1.0
  expect "abort-install of an upgrade removed the marker" present "$MARK/marker"
  must postrm abort-install
  expect "abort-install left the marker" absent "$MARK/marker"
  expect "abort-install left the marker directory" absent "$MARK"
  after_case
}

case_rpm_erase_deletes_nothing_and_prints_paths() { # rpm
  new_root present
  first_install rpm
  populate_state
  snapshot > "$R/snap"
  clear_logs
  must prerm 0
  must postrm 0
  expect "rpm erase changed the tree" unchanged "$R/snap"
  expect "rpm erase left the marker" absent "$MARK/marker"
  expect "rpm erase did not list exactly the remaining paths" \
    test "$(grep '^  /' "$R/stdout")" = "  $CONFIG"$'\n'"  $ETC"$'\n'"  $STATE"
  expect "rpm erase did not say the state holds the CA key" has_str 'CA' "$R/stdout"
  after_case
}

# --- run -------------------------------------------------------------------------------------

# The constants the harness rewrites exist exactly once, where declared.
for f in preinst postinst; do
  [ "$(grep -c '^ROOT_UID=0$' "$SCRIPTS/$f.sh")" = 1 ] || die "$f.sh must declare ROOT_UID=0 exactly once"
done
[ "$(grep -c '^HOSTNAME_TIMEOUT=10$' "$SCRIPTS/postinst.sh")" = 1 ] || die "postinst.sh must declare HOSTNAME_TIMEOUT=10 exactly once"

run_case() { # name fn args...
  local name="$1"; shift
  cur_fail=""
  n=$((n + 1))
  "$@"
  if [ -z "$cur_fail" ]; then echo "ok   $name"; else echo "FAIL $name: $cur_fail"; fail=$((fail + 1)); fi
}

both_conventions="
first_install_places_config_state_and_account
first_install_without_fqdn
first_install_hostname_stall_is_bounded
first_install_without_systemd_runs_no_systemctl
first_install_with_run_systemd_system_a_file_runs_no_systemctl
preset_failure_does_not_fail_install
sysusers_absent_falls_back_to_useradd
no_account_tool_fails_install_and_places_nothing
account_without_group_fails_install_and_places_nothing
existing_relay_toml_is_never_rewritten
dangling_relay_toml_symlink_not_written_through
symlinked_etc_relay_not_written_through
writable_etc_relay_not_written_through
etc_relay_not_owned_by_root_not_written_through
planted_relay_toml_is_never_clobbered
failed_config_chown_places_nothing
etc_relay_a_file_is_not_written_through
preinst_refuses_bad_marker_dir
existing_state_dir_left_as_is
guide_missing_does_not_fail_install
upgrade_changes_nothing
remove_stops_disables_keeps_everything
missing_or_unknown_arguments_are_safe
"
deb_only="
failed_first_configure_rerun_converges
deb_configure_with_old_version_never_presets_or_generates
purge_moves_state_aside_and_removes_created_config
purge_keeps_operator_files_in_etc_relay
purge_moves_preexisting_state_dir_too
purge_mount_point_reowns_in_place
purge_symlinked_state_dir_moves_nothing
purge_keeps_what_existed_before_the_install
purge_through_symlinked_etc_deletes_nothing
purge_failed_top_reown_exits_nonzero_and_keeps_config
purge_failed_recursive_reown_exits_nonzero_before_move
purge_does_not_reown_hard_linked_files
second_purge_is_a_no_op
reinstall_from_config_files_keeps_created_tokens
remove_then_reinstall_stays_disabled
abort_install_forgets_marker
"
for c in $both_conventions; do
  for conv in deb rpm; do run_case "$c ($conv)" "case_$c" "$conv"; done
done
for c in $deb_only; do run_case "$c (deb)" "case_$c"; done
run_case "rpm_erase_deletes_nothing_and_prints_paths (rpm)" case_rpm_erase_deletes_nothing_and_prints_paths

echo "relay-package-scripts-test: $((n - fail)) of $n cases passed, $fail failed"
[ "$fail" -eq 0 ]
