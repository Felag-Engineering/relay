#!/bin/sh
# relay-daemon .deb preinst. On a first install (`install` with no old version) records which
# fixed paths exist before the install begins. Nothing is created here.
set -eu

# BEGIN shared: observe
observe() {
  umask "$(printf '%04o' $(( 0$(umask) | 077 )))"
  if [ -L /var/lib/relay-daemon-package ]; then
    echo "relay-daemon package: /var/lib/relay-daemon-package is a symlink; refusing to write through it" >&2
    exit 1
  fi
  if [ -e /var/lib/relay-daemon-package ] && [ ! -d /var/lib/relay-daemon-package ]; then
    echo "relay-daemon package: /var/lib/relay-daemon-package exists and is not a directory" >&2
    exit 1
  fi
  [ -d /var/lib/relay-daemon-package ] || mkdir /var/lib/relay-daemon-package
  etc_dir=no
  if [ -e /etc/relay-daemon ] || [ -L /etc/relay-daemon ]; then etc_dir=yes; fi
  policy_dir=no
  if [ -e /etc/relay-daemon/policy.d ] || [ -L /etc/relay-daemon/policy.d ]; then policy_dir=yes; fi
  policy_file=no
  if [ -e /etc/relay-daemon/policy.toml ] || [ -L /etc/relay-daemon/policy.toml ]; then policy_file=yes; fi
  env_file=no
  if [ -e /etc/relay-daemon/relay-daemon.env ] || [ -L /etc/relay-daemon/relay-daemon.env ]; then env_file=yes; fi
  state_dir=no
  if [ -e /var/lib/relay-daemon ] || [ -L /var/lib/relay-daemon ]; then state_dir=yes; fi
  {
    echo "etc_dir=$etc_dir"
    echo "policy_dir=$policy_dir"
    echo "policy_file=$policy_file"
    echo "env_file=$env_file"
    echo "state_dir=$state_dir"
  } > /var/lib/relay-daemon-package/preexisting.new
  mv -f -- /var/lib/relay-daemon-package/preexisting.new /var/lib/relay-daemon-package/preexisting
  # A true first install: a `created` left behind belongs to a removed lifecycle, and
  # dropping it can only make purge claim less.
  rm -f -- /var/lib/relay-daemon-package/created
  touch /var/lib/relay-daemon-package/first-install
}
# END shared

case "${1:-}" in
  install)
    if [ -z "${2:-}" ]; then
      observe
    fi
    ;;
  *) ;;
esac
