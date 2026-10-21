#!/bin/sh
# relay postinst (.deb) and %post (.rpm).
#
# First install (`.deb` configure with no previously configured version; `.rpm` $1 == 1):
#   - creates the relay account and group (RC-24), failing before anything else is created if
#     either is missing afterwards;
#   - creates /etc/relay (root, 0755) and /var/lib/relay (relay:relay, 0700), each only if
#     absent;
#   - generates /etc/relay/relay.toml, root:relay 0640, only if none exists, and only through
#     a /etc/relay that only root can write (RC-25);
#   - prints the configuration guide and what it chose for tls.hostname;
#   - where systemd is running, enables the unit through the distribution's presets (RC-24).
# Upgrade or reinstall: `systemctl daemon-reload` only, where systemd is running.
#
# Nothing here ever starts or restarts the Relay or runs `relay init`, and nothing rewrites a
# file that exists: the configuration is a link to a fully written temporary file, which
# fails if the target appeared meanwhile.
#
# `set -e` is not relied on inside any function: the shell ignores it there whenever the call
# sits in an `if`, `while`, `!`, `&&` or `||`, so every command checks its own status.
set -eu
LC_ALL=C
export LC_ALL

ROOT_UID=0
HOSTNAME_TIMEOUT=10
MARKER=/var/lib/relay-package/marker
SHARE=/usr/share/relay
SYSUSERS=/usr/lib/sysusers.d/relay.conf
ETC=/etc/relay
CONFIG="$ETC/relay.toml"
STATE=/var/lib/relay
UNIT=relay.service

first_install=no
case "${1:-}" in
  configure) [ -z "${2:-}" ] && first_install=yes ;;
  1) first_install=yes ;;
  [0-9]*) ;;
  *) exit 0 ;;
esac

systemd_running() { [ -d /run/systemd/system ]; }

if [ "$first_install" != yes ]; then
  if systemd_running; then
    systemctl daemon-reload || true
  fi
  exit 0
fi

exists() { [ -e "$1" ] || [ -L "$1" ]; }
marked() { [ -f "$MARKER" ] && grep -qx "$1" "$MARKER"; }
# record NAME: note that the package created NAME, once, if preinst wrote a marker.
record() {
  [ -f "$MARKER" ] || return 0
  marked "created $1" || echo "created $1" >> "$MARKER"
  return 0
}

# unsafe_reason DIR: succeeds, printing why, when root must not write through DIR; fails when
# DIR is a real directory owned by root with no group or other write bit (%A positions 6 and
# 9; with a POSIX ACL the group bits are the ACL mask, so any named-user or named-group write
# grant shows as group-writable). Once that holds, only root can create, remove or rename an
# entry in DIR, so nobody can swap a temporary file for a symlink between its creation and
# its chown, chmod and link.
unsafe_reason() {
  if [ -L "$1" ]; then echo "a symlink"; return 0; fi
  if [ ! -d "$1" ]; then echo "not a directory"; return 0; fi
  owner=$(stat -c %u -- "$1") || { echo "unreadable"; return 0; }
  perm=$(stat -c %A -- "$1") || { echo "unreadable"; return 0; }
  if [ "$owner" != "$ROOT_UID" ]; then echo "not owned by root"; return 0; fi
  case "$perm" in
    ?????w* | ????????w*) echo "writable by group or other"; return 0 ;;
  esac
  return 1
}

# ensure_account: the relay user and its group exist afterwards, or this fails with a message.
# The account is never removed by this package.
ensure_account() {
  if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers "$SYSUSERS" || true
  fi
  if ! getent passwd relay >/dev/null 2>&1 && command -v useradd >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --home-dir / --shell /usr/sbin/nologin \
      --comment "Relay fleet-administration control plane" relay || true
  fi
  if getent passwd relay >/dev/null 2>&1 && getent group relay >/dev/null 2>&1; then
    return 0
  fi
  echo "relay: the relay account or the relay group does not exist, and neither systemd-sysusers" >&2
  echo "relay: nor useradd could create them; create a system user and group both named relay," >&2
  echo "relay: then install the package again" >&2
  return 1
}

# host_fqdn: prints this host's fully qualified name, or fails. The name must be a DNS name
# the Relay's own validation accepts, with a dot; anything else, a stalled resolver and an
# absent `hostname` included, is "none found".
host_fqdn() {
  name=$(timeout "$HOSTNAME_TIMEOUT" hostname -f 2>/dev/null) || return 1
  [ -n "$name" ] || return 1
  [ "${#name}" -le 253 ] || return 1
  case "$name" in
    *.*) ;;
    *) return 1 ;;
  esac
  case "$name" in
    *[!A-Za-z0-9.-]*) return 1 ;;
    .* | *. | -* | *-) return 1 ;;
    *..* | *.-* | *-.*) return 1 ;;
  esac
  rest=$name
  while [ -n "$rest" ]; do
    label=${rest%%.*}
    [ "${#label}" -le 63 ] || return 1
    case $rest in
      *.*) rest=${rest#*.} ;;
      *) rest= ;;
    esac
  done
  printf '%s\n' "$name"
}

# place_config: sets CONFIG_STATUS to generated, kept, kept-own or unsafe, and CONFIG_FQDN to
# the name written when one was. Returns 1 only for a failed write.
CONFIG_STATUS=""
CONFIG_FQDN=""
place_config() {
  if exists "$CONFIG"; then
    if marked "created config"; then CONFIG_STATUS=kept-own; else CONFIG_STATUS=kept; fi
    return 0
  fi
  if reason=$(unsafe_reason "$ETC"); then
    echo "relay: $ETC is $reason; $CONFIG was not generated. Make $ETC a root-owned" >&2
    echo "relay: directory, mode 0755, then write $CONFIG (root:relay 0640) from" >&2
    echo "relay: $SHARE/relay.toml.example." >&2
    CONFIG_STATUS=unsafe
    return 0
  fi
  if [ ! -f "$SHARE/relay.toml.in" ]; then
    echo "relay: $SHARE/relay.toml.in is missing; $CONFIG not generated" >&2
    return 1
  fi
  fqdn=$(host_fqdn) || fqdn=""
  if [ -n "$fqdn" ]; then
    line="hostname = \"$fqdn\""
  else
    line='# hostname = "relay.example.internal"'
  fi
  tmp=$(mktemp "$ETC/.relay-pkg.XXXXXX") || return 1
  # The name holds only letters, digits, dots and hyphens, so it is safe in the replacement.
  sed "s|^hostname = \"@FQDN@\"\$|$line|" "$SHARE/relay.toml.in" > "$tmp" \
    || { rm -f "$tmp"; return 1; }
  if grep -q '@FQDN@' "$tmp"; then
    rm -f "$tmp"
    echo "relay: $SHARE/relay.toml.in has no hostname line to fill; $CONFIG not generated" >&2
    return 1
  fi
  if ! { chown -h root:relay "$tmp" && chmod 0640 "$tmp"; }; then
    rm -f "$tmp"
    return 1
  fi
  if ! ln "$tmp" "$CONFIG"; then
    rm -f "$tmp"
    echo "relay: $CONFIG could not be linked into place (it may have appeared during the install); left as it is" >&2
    return 1
  fi
  record config
  rm -f "$tmp"
  CONFIG_STATUS=generated
  CONFIG_FQDN=$fqdn
  return 0
}

# place_state: /var/lib/relay exists afterwards, relay:relay 0700 when this package made it.
# A directory the package did not make is left exactly as it is: the unit's StateDirectory=
# sets the top directory at start, and nothing here re-owns an operator's tree.
place_state() {
  if ! exists "$STATE"; then
    mkdir -m 0700 "$STATE" || return 1
    record state
    chown -h relay:relay "$STATE" || return 1
    return 0
  fi
  if marked "created state" && [ -d "$STATE" ] && [ ! -L "$STATE" ]; then
    chown -h relay:relay "$STATE" || return 1
    chmod 0700 "$STATE" || return 1
  fi
  return 0
}

if ! ensure_account; then exit 1; fi

umask 077

# `created etc` is recorded exactly when preinst did not see /etc/relay, whoever made it
# between then and now. Purge removes the directory only if it is empty.
if ! exists "$ETC"; then
  mkdir -m 0755 "$ETC"
  chown -h root:root "$ETC"
fi
if [ -f "$MARKER" ] && ! marked "existed etc"; then
  record etc
fi

if ! place_config; then
  echo "relay: could not generate $CONFIG; fix the cause and install the package again" >&2
  exit 1
fi

if ! place_state; then
  echo "relay: could not create $STATE; fix the cause and install the package again" >&2
  exit 1
fi

# The guide is documentation: a missing copy never fails an install whose work is done.
cat "$SHARE/configuration-guide.txt" \
  || echo "relay: the configuration guide is missing: $SHARE/configuration-guide.txt" >&2
echo
case "$CONFIG_STATUS" in
  generated)
    if [ -n "$CONFIG_FQDN" ]; then
      echo "Certificate hostname (tls.hostname): $CONFIG_FQDN"
    else
      echo "No fully qualified name was found for this host, so tls.hostname is commented out in"
      echo "$CONFIG; the Relay refuses to start, naming tls.hostname, until you set it."
    fi
    ;;
  kept) echo "Kept the existing $CONFIG; nothing was generated." ;;
  kept-own) echo "Kept $CONFIG, generated earlier in this install." ;;
  unsafe) echo "$CONFIG was not generated: see the message above." ;;
esac

if systemd_running; then
  systemctl daemon-reload || true
  systemctl preset "$UNIT" || true
fi
exit 0
