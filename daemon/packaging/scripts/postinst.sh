#!/bin/sh
# relay-daemon postinst (.deb) and %post (.rpm).
#
# First install (`.deb` configure with no previously configured version; `.rpm` $1 == 1):
#   - creates /etc/relay-daemon, the empty Policy directory and /var/lib/relay-daemon (0700),
#     each only if absent;
#   - places the shipped default as the live Policy only if no Policy file exists and the
#     Policy directory did not exist before the install began (DI-26);
#   - places the environment file, root 0600, only if none exists (DI-27);
#   - writes nothing under /etc/relay-daemon, nor through the marker, unless the directory is
#     one only root can write: it then says so on stderr, and the install still succeeds;
#   - where systemd is running, enables the unit through the distribution's presets (DI-25).
# Upgrade or reinstall: `systemctl daemon-reload` only, where systemd is running.
#
# Nothing here ever starts or restarts the daemon, and nothing rewrites a file that exists:
# every placement is a link to a fully written temporary file, which fails if the target
# appeared meanwhile.
set -eu

MARKER_DIR=/var/lib/relay-daemon-package
MARKER="$MARKER_DIR/marker"
SHARE=/usr/share/relay-daemon
ETC=/etc/relay-daemon
POLICY="$ETC/policy.toml"
POLICY_DIR="$ETC/policy.d"
ENV_FILE="$ETC/relay-daemon.env"
STATE=/var/lib/relay-daemon
UNIT=relay-daemon.service

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

# root_only_dir DIR: DIR is a real directory owned by uid 0 with no group or other write bit.
# Under a POSIX ACL the group bits are the ACL mask, so a named write grant reads as
# group-writable and is refused. Only in such a directory is root the only account that can
# create, unlink or rename an entry between two of this script's steps, so a file it creates
# there cannot be swapped for a symlink before it is chowned, chmodded or appended to.
root_only_dir() {
  [ -d "$1" ] && [ ! -L "$1" ] || return 1
  [ "$(stat -c %u "$1")" = 0 ] || return 1
  mode="$(stat -c %A "$1")" || return 1
  case "$mode" in
    d????[!w]??[!w]*) return 0 ;;
  esac
  return 1
}

# The marker is read and appended to only inside a directory only root can write.
have_marker=no
if [ -f "$MARKER" ] && [ ! -L "$MARKER" ]; then
  if root_only_dir "$MARKER_DIR"; then
    have_marker=yes
  else
    echo "relay-daemon: $MARKER_DIR is not a directory only root can write; its marker is ignored" >&2
  fi
fi
marked() { [ "$have_marker" = yes ] && grep -qx "$1" "$MARKER"; }
record() { if [ "$have_marker" = yes ]; then echo "created $1" >> "$MARKER"; fi; return 0; }

# place DST MODE SRC [empty-join]: DST becomes a root-owned copy of SRC, unless DST exists.
# Called only once $ETC is a directory only root can write.
# With empty-join, the copy's RELAY_JOIN value is emptied. Called as an `if` condition, where
# `set -e` does not apply, so every step is checked by hand: a half-written or wrongly owned
# file is never linked into place.
place() {
  dst="$1"; mode="$2"; src="$3"
  if [ ! -f "$src" ]; then
    echo "relay-daemon: $src is missing; $dst not placed" >&2
    return 1
  fi
  tmp="$(mktemp "$ETC/.relay-daemon-pkg.XXXXXX")" || return 1
  if [ "${4:-}" = empty-join ]; then
    sed 's/^RELAY_JOIN=.*/RELAY_JOIN=/' "$src" > "$tmp" || { rm -f "$tmp"; return 1; }
  else
    cat "$src" > "$tmp" || { rm -f "$tmp"; return 1; }
  fi
  if ! { chown -h root:root "$tmp" && chmod "$mode" "$tmp"; }; then
    rm -f "$tmp"
    return 1
  fi
  if ln "$tmp" "$dst" 2>/dev/null; then
    rm -f "$tmp"
    return 0
  fi
  rm -f "$tmp"
  echo "relay-daemon: $dst appeared during the install; left as it is" >&2
  return 1
}

umask 077

# `created etc` is recorded exactly when preinst did not see /etc/relay-daemon, whoever made it
# between then and now. It may be this script, or the catalog package unpacked earlier in the
# same transaction. Purge removes the directory only if it is empty.
if ! exists "$ETC"; then
  mkdir -m 0755 "$ETC"
fi
if [ "$have_marker" = yes ] && ! marked "existed etc"; then
  record etc
fi

# An $ETC another account can write is left exactly as it is. The install still succeeds: with
# no Policy file the daemon is deny-all (DI-20), and with no environment file it is unconfigured.
if root_only_dir "$ETC"; then
  # The Policy directory's prior existence is read from the marker preinst wrote before
  # anything was unpacked. With no marker the answer is unknown, and no Policy is placed: a
  # Node with no Policy file is deny-all, never wider (DI-20).
  if [ "$have_marker" = yes ] && ! marked "existed policy-dir" && ! exists "$POLICY"; then
    if place "$POLICY" 0644 "$SHARE/policy.default.toml"; then
      record policy
    fi
  fi

  if ! exists "$POLICY_DIR"; then
    mkdir -m 0755 "$POLICY_DIR"
    record policy-dir
  fi

  # The placed file is the shipped example with RELAY_JOIN emptied: an empty join string on a
  # Node with no identity is the daemon's clean unconfigured exit, so an enabled unit stays
  # inactive at boot instead of failing on the example's placeholder (DI-25).
  if ! exists "$ENV_FILE"; then
    if place "$ENV_FILE" 0600 "$SHARE/relay-daemon.env.example" empty-join; then
      record env
    fi
  fi
else
  echo "relay-daemon: $ETC is a symlink, not a directory, not owned by root, or writable by" >&2
  echo "group or others; nothing was placed in it, so the daemon has no Policy (deny-all) and" >&2
  echo "no environment file until it is made root-owned 0755 and they are placed by hand" >&2
fi

if ! exists "$STATE"; then
  mkdir -m 0700 "$STATE"
  record state
fi

if systemd_running; then
  systemctl daemon-reload || true
  systemctl preset "$UNIT" || true
fi
exit 0
