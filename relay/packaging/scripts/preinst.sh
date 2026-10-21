#!/bin/sh
# relay preinst (.deb) and %pre (.rpm).
#
# On a first install only, records which of the package's fixed paths already exist, so that
# postinst generates nothing over an operator's files and purge deletes only what the package
# itself created (RC-25, RC-26). A first install is `.deb` preinst `install` with no old
# version, or `.rpm` with $1 == 1. Every other invocation changes nothing.
#
# The marker holds fixed tokens only, and purge maps each token to a literal path: no path is
# ever read from it, or from any file an operator edits. The marker lives in a root-only
# directory, so no other account can alter it between the install and a purge (ADR-0033).
set -eu

ROOT_UID=0
MARKER_DIR=/var/lib/relay-package
MARKER="$MARKER_DIR/marker"
ETC=/etc/relay
STATE=/var/lib/relay

first_install=no
case "${1:-}" in
  install) [ -z "${2:-}" ] && first_install=yes ;;
  1) first_install=yes ;;
esac
[ "$first_install" = yes ] || exit 0

exists() { [ -e "$1" ] || [ -L "$1" ]; }

# A directory is safe for root to write through when it is a real directory, owned by root,
# with no group or other write bit (%A positions 6 and 9; with a POSIX ACL the group bits are
# the ACL mask, so any named-user or named-group write grant shows as group-writable). Once
# it holds, only root can create, remove or rename an entry in it.
safe_dir() {
  [ -d "$1" ] && [ ! -L "$1" ] || return 1
  owner=$(stat -c %u -- "$1") || return 1
  perm=$(stat -c %A -- "$1") || return 1
  [ "$owner" = "$ROOT_UID" ] || return 1
  case "$perm" in
    ?????w* | ????????w*) return 1 ;;
  esac
  return 0
}

umask 077
# Refused before it is touched: a symlink, a non-directory, or a directory another account
# owns, whose owner could re-open it after any chmod.
if exists "$MARKER_DIR"; then
  if [ -L "$MARKER_DIR" ] || [ ! -d "$MARKER_DIR" ] \
    || [ "$(stat -c %u -- "$MARKER_DIR" 2>/dev/null)" != "$ROOT_UID" ]; then
    echo "relay: $MARKER_DIR is not a directory owned by root; refusing to install" >&2
    exit 1
  fi
fi
mkdir -p "$MARKER_DIR"
chmod 0700 "$MARKER_DIR"
# The checks above make this hold already; it stays as the statement of what the marker needs.
if ! safe_dir "$MARKER_DIR"; then
  echo "relay: $MARKER_DIR is not a root-only directory; refusing to install" >&2
  exit 1
fi

tmp="$MARKER.new"
rm -f "$tmp"
{
  echo "# relay package marker: which fixed paths existed before the first install,"
  echo "# and which the package created. Purge reads only this file, and only these tokens."
  exists "$ETC" && echo "existed etc"
  exists "$ETC/relay.toml" && echo "existed config"
  exists "$STATE" && echo "existed state"
  :
} > "$tmp"
chmod 0600 "$tmp"
mv -f "$tmp" "$MARKER"
exit 0
