#!/bin/sh
# relay-daemon .rpm %preun. Erase (argument 0) stops and disables the unit before rpm deletes
# the binary. An upgrade does nothing: the daemon is never restarted by a package.
set -eu

case "${1:-}" in
  0)
    if [ -d /run/systemd/system ]; then
      systemctl stop relay-daemon.service || true
    fi
    systemctl disable relay-daemon.service || true
    ;;
  *) ;;
esac
