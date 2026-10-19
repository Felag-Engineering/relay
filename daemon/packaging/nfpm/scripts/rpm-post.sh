#!/bin/sh
# relay-daemon .rpm %post. A first install creates the fixed directories and places the live
# Policy and environment file, each only if absent, then runs `systemctl preset`. An upgrade
# does nothing here; %postun reloads systemd. Nothing here starts or restarts the daemon.
set -eu

# BEGIN shared: first-install
first_install() {
  pre_etc=yes
  if grep -qsx 'etc_dir=no' /var/lib/relay-daemon-package/preexisting; then pre_etc=no; fi
  pre_policy_dir=yes
  if grep -qsx 'policy_dir=no' /var/lib/relay-daemon-package/preexisting; then pre_policy_dir=no; fi
  pre_policy_file=yes
  if grep -qsx 'policy_file=no' /var/lib/relay-daemon-package/preexisting; then pre_policy_file=no; fi
  pre_env_file=yes
  if grep -qsx 'env_file=no' /var/lib/relay-daemon-package/preexisting; then pre_env_file=no; fi
  pre_state_dir=yes
  if grep -qsx 'state_dir=no' /var/lib/relay-daemon-package/preexisting; then pre_state_dir=no; fi

  # Every create below appends its flag to `created` at once, so a later failure still leaves
  # purge an accurate record. The file is made 0600 here and only appended to afterwards.
  ( umask 077; : >> /var/lib/relay-daemon-package/created )

  if [ "$pre_etc" = no ] && [ ! -e /etc/relay-daemon ] && [ ! -L /etc/relay-daemon ]; then
    ( umask "$(printf '%04o' $(( 0$(umask) | 022 )))"; mkdir /etc/relay-daemon )
    printf 'made_etc=yes\n' >> /var/lib/relay-daemon-package/created
  fi

  if [ -d /etc/relay-daemon ] && [ ! -L /etc/relay-daemon ]; then
    if [ "$pre_policy_dir" = no ] && [ ! -e /etc/relay-daemon/policy.d ] && [ ! -L /etc/relay-daemon/policy.d ]; then
      ( umask "$(printf '%04o' $(( 0$(umask) | 022 )))"; mkdir /etc/relay-daemon/policy.d )
      printf 'made_policy_dir=yes\n' >> /var/lib/relay-daemon-package/created
    fi
    if [ "$pre_policy_dir" = no ] && [ "$pre_policy_file" = no ] \
      && [ ! -e /etc/relay-daemon/policy.toml ] && [ ! -L /etc/relay-daemon/policy.toml ]; then
      ( umask "$(printf '%04o' $(( 0$(umask) | 022 )))"; cp -- /usr/share/relay-daemon/policy.default.toml /etc/relay-daemon/policy.toml )
      printf 'placed_policy=yes\n' >> /var/lib/relay-daemon-package/created
    fi
    if [ "$pre_env_file" = no ] && [ ! -e /etc/relay-daemon/relay-daemon.env ] && [ ! -L /etc/relay-daemon/relay-daemon.env ]; then
      ( umask "$(printf '%04o' $(( 0$(umask) | 077 )))"; cp -- /usr/share/relay-daemon/relay-daemon.env.example /etc/relay-daemon/relay-daemon.env )
      printf 'placed_env=yes\n' >> /var/lib/relay-daemon-package/created
    fi
  else
    echo "relay-daemon package: /etc/relay-daemon is not a plain directory; placed no Policy, Policy directory or environment file through it" >&2
  fi

  if [ "$pre_state_dir" = no ] && [ ! -e /var/lib/relay-daemon ] && [ ! -L /var/lib/relay-daemon ]; then
    ( umask "$(printf '%04o' $(( 0$(umask) | 077 )))"; mkdir /var/lib/relay-daemon )
    printf 'made_state=yes\n' >> /var/lib/relay-daemon-package/created
  fi

  if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || echo "relay-daemon package: systemctl daemon-reload failed" >&2
    systemctl preset relay-daemon.service || echo "relay-daemon package: systemctl preset failed" >&2
  fi
  rm -f -- /var/lib/relay-daemon-package/first-install
}
# END shared

case "${1:-}" in
  1)
    if [ -f /var/lib/relay-daemon-package/first-install ]; then
      first_install
    fi
    ;;
  *) ;;
esac
