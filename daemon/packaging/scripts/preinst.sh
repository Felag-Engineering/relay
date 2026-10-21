#!/bin/sh
# relay-daemon preinst (.deb) and %pre (.rpm).
#
# On a first install only, records which of the package's fixed paths already exist, so that
# postinst places nothing over an operator's files (DI-26, DI-27) and purge deletes only what
# the package itself created (DI-31). A first install is `.deb` preinst `install` with no old
# version, or `.rpm` with $1 == 1. Every other invocation changes nothing.
#
# The marker holds fixed tokens only, and purge maps each token to a literal path: no path is
# ever read from it, or from any file an operator edits. An existing marker directory that
# another account could write is refused: a marker written there could be a planted symlink.
set -eu

MARKER_DIR=/var/lib/relay-daemon-package
MARKER="$MARKER_DIR/marker"

first_install=no
case "${1:-}" in
  install) [ -z "${2:-}" ] && first_install=yes ;;
  1) first_install=yes ;;
esac
[ "$first_install" = yes ] || exit 0

exists() { [ -e "$1" ] || [ -L "$1" ]; }

# root_only_dir DIR: DIR is a real directory owned by uid 0 with no group or other write bit.
# Under a POSIX ACL the group bits are the ACL mask, so a named write grant reads as
# group-writable and is refused. Only in such a directory is root the only account that can
# create, unlink or rename an entry between two of this script's steps.
root_only_dir() {
  [ -d "$1" ] && [ ! -L "$1" ] || return 1
  [ "$(stat -c %u "$1")" = 0 ] || return 1
  perms="$(stat -c %A "$1")" || return 1
  case "$perms" in
    d????[!w]??[!w]*) return 0 ;;
  esac
  return 1
}

umask 077
if exists "$MARKER_DIR" && ! root_only_dir "$MARKER_DIR"; then
  echo "relay-daemon: $MARKER_DIR is not a directory only root can write; refusing to install" >&2
  exit 1
fi
mkdir -p "$MARKER_DIR"
chmod 0700 "$MARKER_DIR"

tmp="$MARKER.new"
rm -f "$tmp"
{
  echo "# relay-daemon package marker: which fixed paths existed before the first install,"
  echo "# and which the package created. Purge reads only this file, and only these tokens."
  exists /etc/relay-daemon && echo "existed etc"
  exists /etc/relay-daemon/policy.d && echo "existed policy-dir"
  exists /etc/relay-daemon/policy.toml && echo "existed policy"
  exists /etc/relay-daemon/relay-daemon.env && echo "existed env"
  exists /var/lib/relay-daemon && echo "existed state"
  :
} > "$tmp"
chmod 0600 "$tmp"
mv -f "$tmp" "$MARKER"
exit 0
