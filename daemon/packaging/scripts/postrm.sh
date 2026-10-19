#!/bin/sh
# relay-daemon postrm (.deb) and %postun (.rpm).
#
# Remove keeps the Policy, the Policy directory, the environment file and the state directory
# (DI-31). `.deb` purge deletes what the package created and nothing else: it reads only the
# marker preinst and postinst wrote, acts only on the literal paths its fixed tokens name, and
# never reads a path from any file an operator edits. A directory that holds anything the
# package did not put there (a Policy fragment, an operator's Template) is left, and named.
# `.rpm` has no purge: removal deletes no state and prints the paths to delete by hand.
set -eu

MARKER_DIR=/var/lib/relay-daemon-package
MARKER="$MARKER_DIR/marker"
ETC=/etc/relay-daemon

systemd_running() { [ -d /run/systemd/system ]; }
reload() { if systemd_running; then systemctl daemon-reload || true; fi; }
exists() { [ -e "$1" ] || [ -L "$1" ]; }

# created NAME: the package made this path, and it did not exist before the first install.
created() {
  [ -f "$MARKER" ] && grep -qx "created $1" "$MARKER" && ! grep -qx "existed $1" "$MARKER"
}

forget_marker() {
  rm -f "$MARKER"
  rmdir "$MARKER_DIR" 2>/dev/null || true
}

leftovers() {
  for p in "$ETC/policy.toml" "$ETC/policy.d" "$ETC/relay-daemon.env" /var/lib/relay-daemon; do
    if exists "$p"; then echo "  $p"; fi
  done
}

purge() {
  if [ ! -f "$MARKER" ]; then
    echo "relay-daemon: no package marker; purge deletes nothing. Remaining paths:"
    leftovers
    return 0
  fi
  if created policy; then rm -f "$ETC/policy.toml"; fi
  if created env; then rm -f "$ETC/relay-daemon.env"; fi
  if created policy-dir && [ -d "$ETC/policy.d" ] && [ ! -L "$ETC/policy.d" ]; then
    rmdir "$ETC/policy.d" 2>/dev/null \
      || echo "relay-daemon: $ETC/policy.d holds files the package did not create; left in place"
  fi
  if created etc && [ -d "$ETC" ] && [ ! -L "$ETC" ]; then
    rmdir "$ETC" 2>/dev/null \
      || echo "relay-daemon: $ETC holds files the package did not create; left in place"
  fi
  # The state directory is the daemon's own: its identity and dedup markers go with it.
  if created state && [ -d /var/lib/relay-daemon ] && [ ! -L /var/lib/relay-daemon ]; then
    rm -rf /var/lib/relay-daemon
  fi
  forget_marker
}

case "${1:-}" in
  remove) reload ;;
  purge) purge ;;
  abort-install)
    # The first install never completed: nothing was placed, so the marker is meaningless.
    if [ -z "${2:-}" ]; then forget_marker; fi
    ;;
  0)
    reload
    forget_marker
    echo "relay-daemon: removed. Configuration and state were kept; delete by hand when this"
    echo "Node leaves for good (the state directory holds the Node's identity):"
    leftovers
    ;;
  [0-9]*) reload ;;
esac
exit 0
