#!/bin/sh
# relay prerm (.deb) and %preun (.rpm).
#
# On removal only (`.deb` prerm `remove`; `.rpm` $1 == 0), stops and disables the unit while
# the binary is still in place (RC-24, RC-26). An upgrade changes nothing here: the package
# never restarts the Relay, and the operator restarts it onto the new binary.
set -eu

UNIT=relay.service

case "${1:-}" in
  remove | 0) ;;
  *) exit 0 ;;
esac

if [ -d /run/systemd/system ]; then
  systemctl stop "$UNIT" || true
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl --no-reload disable "$UNIT" || true
fi
exit 0
