#!/bin/sh
# relay postrm (.deb) and %postun (.rpm).
#
# Remove keeps the configuration and the state directory (RC-26). `.deb` purge moves the state
# directory, the CA and the store together, aside to a timestamped sibling owned by root, mode
# 0700, and prints where; it never deletes them. It then removes the configuration the package
# generated, and only the literal paths its marker names: it reads only the marker preinst and
# postinst wrote, and never reads a path from any file an operator edits. A directory that
# holds anything the package did not put there is left, and named. Purge never removes the
# relay account or its group. `.rpm` has no purge: removal deletes nothing and prints the
# paths to delete by hand.
#
# `set -e` is not relied on inside any function: the shell ignores it there whenever the call
# sits in an `if`, `while`, `!`, `&&` or `||`, so every step of the re-own and the move checks
# its own status, and a failure leaves a purge that can be run again.
set -eu

MARKER_DIR=/var/lib/relay-package
MARKER="$MARKER_DIR/marker"
ETC=/etc/relay
CONFIG="$ETC/relay.toml"
STATE=/var/lib/relay

systemd_running() { [ -d /run/systemd/system ]; }
reload() { if systemd_running; then systemctl daemon-reload || true; fi; }
exists() { [ -e "$1" ] || [ -L "$1" ]; }
plain_dir() { [ -d "$1" ] && [ ! -L "$1" ]; }

# created NAME: the package made this path, and it did not exist before the first install.
created() {
  [ -f "$MARKER" ] && grep -qx "created $1" "$MARKER" && ! grep -qx "existed $1" "$MARKER"
}

# forget_marker: acts only through a plain marker directory, so a symlink that preinst refused
# is never followed.
forget_marker() {
  plain_dir "$MARKER_DIR" || return 0
  rm -f "$MARKER"
  rmdir "$MARKER_DIR" 2>/dev/null || true
}

# leftovers: every fixed path that remains.
leftovers() {
  for p in "$CONFIG" "$ETC" "$STATE"; do
    if exists "$p"; then echo "  $p"; fi
  done
}

# is_mount_point DIR: a mount point cannot be renamed. `mountpoint` also sees bind mounts;
# without it, a device number that differs from the parent's is the answer.
is_mount_point() {
  if command -v mountpoint >/dev/null 2>&1; then
    mountpoint -q "$1" && return 0
    return 1
  fi
  dev=$(stat -c %d -- "$1") || return 1
  parent_dev=$(stat -c %d -- "${1%/*}") || return 1
  [ "$dev" != "$parent_dev" ]
}

# move_state_aside: the CA and the store leave the relay account's reach, together. The
# directory is re-owned to root, mode 0700, before anything else, and only then renamed to a
# sibling, so a failed step never leaves them readable by the relay account and never splits
# them. Returns 1 on any failed step. A directory the package did not create is treated the
# same way: moving is not deleting.
#
# The recursive re-own skips any non-directory with another hard link: the relay account can
# link a file it controls into the tree from outside it, and re-owning that inode would hand it
# a root-owned file elsewhere. It also stays on one filesystem. Such entries are named and left
# as found; the top-level lock above already shuts the relay account out of the tree.
move_state_aside() {
  if [ -L "$STATE" ]; then
    echo "relay: $STATE is a symlink; nothing it points to was moved; the CA and the store are wherever it points"
    return 0
  fi
  exists "$STATE" || return 0
  if [ ! -d "$STATE" ]; then
    echo "relay: $STATE is not a directory; left as it is"
    return 0
  fi
  chown -h root:root "$STATE" || return 1
  chmod 0700 "$STATE" || return 1
  find "$STATE" -xdev \( -type d -o -links 1 \) -exec chown -h root:root {} + || return 1
  shared=$(find "$STATE" -xdev ! -type d -links +1 -print) || return 1
  if [ -n "$shared" ]; then
    echo "relay: left owned as found, because each has another hard link outside $STATE:" >&2
    echo "$shared" | sed -e 's|^|relay:   |' >&2
  fi
  if is_mount_point "$STATE"; then
    echo "relay: $STATE is a mount point, so the CA private key and the store were re-owned in place -"
    echo "relay: owned by root, mode 0700 - and not moved. It still holds a live CA key: delete it,"
    echo "relay: or destroy the host, when this Relay is gone for good."
    return 0
  fi
  dst="$STATE.purged-$(date -u +%Y%m%dT%H%M%SZ)" || return 1
  if exists "$dst"; then
    echo "relay: $dst already exists; run the purge again" >&2
    return 1
  fi
  mv -T -- "$STATE" "$dst" || return 1
  echo "relay: moved $STATE - the CA private key and the store, together - to $dst,"
  echo "relay: owned by root, mode 0700. It still holds a live CA key: delete it, or destroy the"
  echo "relay: host, when this Relay is gone for good."
  return 0
}

purge() {
  if ! move_state_aside; then
    echo "relay: purge stopped before configuration was removed; fix the cause and run the purge again" >&2
    exit 1
  fi
  if [ ! -f "$MARKER" ]; then
    echo "relay: no package marker; purge deletes no configuration. Remaining paths:"
    leftovers
  elif plain_dir "$ETC"; then
    if created config; then rm -f "$CONFIG"; fi
    if created etc; then
      rmdir "$ETC" 2>/dev/null \
        || echo "relay: $ETC holds files the package did not create; left in place"
    elif exists "$ETC"; then
      echo "relay: $ETC was not created by the package; left in place"
    fi
  elif exists "$ETC"; then
    echo "relay: $ETC is not a plain directory; nothing under it was deleted. Remaining:"
    leftovers
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
    echo "relay: removed. The configuration, the state directory and the relay account were kept;"
    echo "relay: delete by hand when this Relay is gone for good. The state directory holds the CA"
    echo "relay: private key and the store: delete them together, or destroy the host."
    leftovers
    ;;
  [0-9]*) reload ;;
esac
exit 0
