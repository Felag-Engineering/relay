#!/bin/sh
# relay-daemon .deb prerm. Remove stops and disables the unit before dpkg deletes the binary.
# An upgrade does nothing: the daemon is never restarted by a package.
set -eu

case "${1:-}" in
  remove)
    if [ -d /run/systemd/system ]; then
      systemctl stop relay-daemon.service || true
    fi
    systemctl disable relay-daemon.service || true
    ;;
  *) ;;
esac
