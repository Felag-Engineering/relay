#!/bin/sh
# relay-daemon .rpm %postun. Erase deletes nothing: it prints the paths the package created so
# the operator can delete them by hand. A path the package did not create is never listed.
set -eu

case "${1:-}" in
  0)
    if [ -d /run/systemd/system ]; then
      systemctl daemon-reload || true
    fi
    # BEGIN shared: created-flags
    made_etc=no
    if grep -qsx 'made_etc=yes' /var/lib/relay-daemon-package/created; then made_etc=yes; fi
    made_policy_dir=no
    if grep -qsx 'made_policy_dir=yes' /var/lib/relay-daemon-package/created; then made_policy_dir=yes; fi
    placed_policy=no
    if grep -qsx 'placed_policy=yes' /var/lib/relay-daemon-package/created; then placed_policy=yes; fi
    placed_env=no
    if grep -qsx 'placed_env=yes' /var/lib/relay-daemon-package/created; then placed_env=yes; fi
    made_state=no
    if grep -qsx 'made_state=yes' /var/lib/relay-daemon-package/created; then made_state=yes; fi
    # END shared
    list=
    if [ "$made_etc" = yes ] && { [ -e /etc/relay-daemon ] || [ -L /etc/relay-daemon ]; }; then
      list="${list}  /etc/relay-daemon\n"
    fi
    if [ "$made_policy_dir" = yes ] && { [ -e /etc/relay-daemon/policy.d ] || [ -L /etc/relay-daemon/policy.d ]; }; then
      list="${list}  /etc/relay-daemon/policy.d\n"
    fi
    if [ "$placed_policy" = yes ] && { [ -e /etc/relay-daemon/policy.toml ] || [ -L /etc/relay-daemon/policy.toml ]; }; then
      list="${list}  /etc/relay-daemon/policy.toml\n"
    fi
    if [ "$placed_env" = yes ] && { [ -e /etc/relay-daemon/relay-daemon.env ] || [ -L /etc/relay-daemon/relay-daemon.env ]; }; then
      list="${list}  /etc/relay-daemon/relay-daemon.env\n"
    fi
    if [ "$made_state" = yes ] && { [ -e /var/lib/relay-daemon ] || [ -L /var/lib/relay-daemon ]; }; then
      list="${list}  /var/lib/relay-daemon\n"
    fi
    if [ -d /var/lib/relay-daemon-package ]; then
      list="${list}  /var/lib/relay-daemon-package\n"
    fi
    if [ -n "$list" ]; then
      echo "relay-daemon removed; these were created by the package and are kept - delete by hand to remove this Node's configuration, identity and join string:"
      printf '%b' "$list"
    fi
    ;;
  [1-9]*)
    if [ -d /run/systemd/system ]; then
      systemctl daemon-reload || true
    fi
    ;;
  *) ;;
esac
