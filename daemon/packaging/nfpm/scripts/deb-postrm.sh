#!/bin/sh
# relay-daemon .deb postrm. Remove deletes nothing. Purge deletes only what postinst recorded
# in `created`, each by a literal path: a path the package did not create is never touched.
set -eu

case "${1:-}" in
  remove)
    if [ -d /run/systemd/system ]; then
      systemctl daemon-reload || true
    fi
    ;;
  purge)
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
    if [ -d /etc/relay-daemon ] && [ ! -L /etc/relay-daemon ]; then
      if [ "$placed_policy" = yes ]; then
        rm -f -- /etc/relay-daemon/policy.toml
      fi
      if [ "$placed_env" = yes ]; then
        rm -f -- /etc/relay-daemon/relay-daemon.env
      fi
      if [ "$made_policy_dir" = yes ] && [ -d /etc/relay-daemon/policy.d ] && [ ! -L /etc/relay-daemon/policy.d ]; then
        rmdir /etc/relay-daemon/policy.d || echo "relay-daemon package: kept /etc/relay-daemon/policy.d, not empty" >&2
      fi
    fi
    if [ "$made_state" = yes ] && [ -d /var/lib/relay-daemon ] && [ ! -L /var/lib/relay-daemon ]; then
      rm -rf --one-file-system -- /var/lib/relay-daemon
    elif [ -e /var/lib/relay-daemon ] || [ -L /var/lib/relay-daemon ]; then
      echo "relay-daemon package: kept /var/lib/relay-daemon" >&2
    fi
    if [ "$made_etc" = yes ] && [ -d /etc/relay-daemon ] && [ ! -L /etc/relay-daemon ]; then
      rmdir /etc/relay-daemon || echo "relay-daemon package: kept /etc/relay-daemon, not empty" >&2
    fi
    rm -f -- /var/lib/relay-daemon-package/created
    rm -f -- /var/lib/relay-daemon-package/preexisting
    rm -f -- /var/lib/relay-daemon-package/preexisting.new
    rm -f -- /var/lib/relay-daemon-package/first-install
    if [ -d /var/lib/relay-daemon-package ] && [ ! -L /var/lib/relay-daemon-package ]; then
      rmdir /var/lib/relay-daemon-package || echo "relay-daemon package: kept /var/lib/relay-daemon-package" >&2
    fi
    ;;
  abort-install)
    rm -f -- /var/lib/relay-daemon-package/first-install
    ;;
  *) ;;
esac
