#!/bin/sh
# relay-daemon preinst (.deb) and %pre (.rpm).
#
# On a first install only, records which of the package's fixed paths already exist, so that
# postinst places nothing over an operator's files (DI-26, DI-27) and purge deletes only what
# the package itself created (DI-31). A first install is `.deb` preinst `install` with no old
# version, or `.rpm` with $1 == 1. Every other invocation changes nothing.
#
# The marker holds fixed tokens only, and purge maps each token to a literal path: no path is
# ever read from it, or from any file an operator edits.
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

umask 077
if exists "$MARKER_DIR" && { [ -L "$MARKER_DIR" ] || [ ! -d "$MARKER_DIR" ]; }; then
  echo "relay-daemon: $MARKER_DIR is not a directory; refusing to install" >&2
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
