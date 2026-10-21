#!/bin/sh
# relay-daemon postrm (.deb) and %postun (.rpm).
#
# Remove keeps the Policy, the Policy directory, the environment file and the state directory
# (DI-31). `.deb` purge deletes what the package created and nothing else: it reads only the
# marker preinst and postinst wrote, acts only on the literal paths its fixed tokens name, and
# never reads a path from any file an operator edits, nor a marker in a directory another
# account could write. A directory that holds anything the package did not put there (a Policy
# fragment, an operator's Template) is left, and named.
# `.rpm` has no purge: removal deletes no state and prints the paths to delete by hand.
set -eu

MARKER_DIR=/var/lib/relay-daemon-package
MARKER="$MARKER_DIR/marker"
ETC=/etc/relay-daemon
STATE=/var/lib/relay-daemon

systemd_running() { [ -d /run/systemd/system ]; }
reload() { if systemd_running; then systemctl daemon-reload || true; fi; }
exists() { [ -e "$1" ] || [ -L "$1" ]; }
plain_dir() { [ -d "$1" ] && [ ! -L "$1" ]; }

# root_only_dir DIR: DIR is a real directory owned by uid 0 with no group or other write bit.
# Under a POSIX ACL the group bits are the ACL mask, so a named write grant reads as
# group-writable and is refused. Only in such a directory is root the only account that can
# create, unlink or rename an entry between two of this script's steps.
root_only_dir() {
  [ -d "$1" ] && [ ! -L "$1" ] || return 1
  [ "$(stat -c %u "$1")" = 0 ] || return 1
  perms="$(stat -c %A "$1")" || return 1
  case "$perms" in
    d????[!w]??[!w]*) return 0 ;;
  esac
  return 1
}

# marker_ok: the marker exists and nobody but root could have written or replaced it.
marker_ok() { [ -f "$MARKER" ] && [ ! -L "$MARKER" ] && root_only_dir "$MARKER_DIR"; }

# created NAME: the package made this path, and it did not exist before the first install.
created() {
  marker_ok && grep -qx "created $1" "$MARKER" && ! grep -qx "existed $1" "$MARKER"
}

forget_marker() {
  if root_only_dir "$MARKER_DIR"; then
    rm -f "$MARKER"
    rmdir "$MARKER_DIR" 2>/dev/null || true
  fi
}

# leftovers: every fixed path that remains. The catalog's Template root is named too: on .rpm
# the catalog package does not own it, so removing that package leaves it behind, and it may
# hold an operator's own Templates, so nothing here deletes it.
leftovers() {
  if exists "$ETC" && ! plain_dir "$ETC"; then
    echo "  $ETC (not a plain directory; nothing under it was touched)"
  else
    for p in "$ETC/policy.toml" "$ETC/policy.d" "$ETC/relay-daemon.env" "$ETC/templates.d"; do
      if exists "$p"; then echo "  $p"; fi
    done
  fi
  if exists "$STATE"; then echo "  $STATE"; fi
}

purge() {
  if ! marker_ok; then
    echo "relay-daemon: no package marker only root could have written; purge deletes nothing. Remaining paths:"
    leftovers
    return 0
  fi
  # Nothing under $ETC is touched unless it is a real directory: through a symlink, a path the
  # package created would resolve to somewhere it did not create.
  if plain_dir "$ETC"; then
    if created policy; then rm -f "$ETC/policy.toml"; fi
    if created env; then rm -f "$ETC/relay-daemon.env"; fi
    if created policy-dir && plain_dir "$ETC/policy.d"; then
      rmdir "$ETC/policy.d" 2>/dev/null \
        || echo "relay-daemon: $ETC/policy.d holds files the package did not create; left in place"
    fi
    if created etc; then
      rmdir "$ETC" 2>/dev/null \
        || echo "relay-daemon: $ETC holds files the package did not create; left in place"
    fi
  elif exists "$ETC"; then
    echo "relay-daemon: $ETC is not a plain directory; nothing under it was deleted. Remaining:"
    leftovers
  fi
  # The state directory is the daemon's own: its identity and dedup markers go with it.
  if created state && plain_dir "$STATE"; then
    rm -rf "$STATE"
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
