#!/bin/sh
# Dev-fleet configuration one-shot (docs/dev-fleet.md). DEV-ONLY. Runs once per
# `compose up`, as the `relay-config` compose service, before the Relay starts.
#
# It stages the Relay's relay.toml and approval-gate fixtures onto the
# relay-etc named volume, which the Relay mounts read-only at /etc/relay. That
# volume lives on the Docker engine's own Linux filesystem, which the Relay's
# start-time filesystem allowlist accepts (ADR-0043). A bind mount from the
# checkout does not pass: it carries the developer's uid and mode 0644, and on
# Docker Desktop it arrives over virtiofs, 9p or FUSE.
#
# Inputs, mounted read-only from the fleet's folder (deploy/test or deploy/demo):
# /src/relay.toml and /src/approval-gates.json. Output: /stage, the volume root. It also hands
# init's two output volumes, /handoff/credential and /handoff/bootstrap, to the
# Relay's uid.
#   relay.toml                root:10001 0640, the layout the Relay accepts
#   approval-gates.json       root:root  0644, what the gate loader demands
#
# FLEET_HOSTNAME (default `relay`) replaces the committed tls.hostname line in the
# staged relay.toml, so a fleet can carry a real DNS name in its certificate. It is
# refused unless it is a plain DNS name, and the committed line must be there to
# replace, so an edited relay.toml fails here rather than staging a name nobody set.
#
# The container runs as root with only CAP_CHOWN (to group the file to 10001, a
# group root is not in, and to hand init's volumes to the Relay's uid) and
# CAP_DAC_OVERRIDE (to read a checkout the developer's umask made 0600), with no
# network; every path but /stage and /handoff is read-only. Any failure exits
# non-zero, and the Relay depends on this service's success, so the fleet stays
# down.
set -eu

relay_gid=10001
hostname="${FLEET_HOSTNAME:-relay}"

# Lowercase letters, digits, dots and hyphens; labels of 1 to 63 characters that
# neither start nor end with a hyphen; 253 characters at most. Nothing else can
# reach the TOML file or the sed expression below.
valid_hostname() {
  [ "${#1}" -le 253 ] || return 1
  case "$1" in
    "" | *[!a-z0-9.-]* | .* | *. | *..*) return 1 ;;
  esac
  for label in $(printf '%s\n' "$1" | tr '.' ' '); do
    [ "${#label}" -le 63 ] || return 1
    case "$label" in -* | *-) return 1 ;; esac
  done
}
if ! valid_hostname "$hostname"; then
  echo "dev-fleet-config: FLEET_HOSTNAME is not a lowercase DNS name: $hostname" >&2
  exit 1
fi

for f in relay.toml approval-gates.json; do
  if ! [ -r "/src/$f" ]; then
    echo "dev-fleet-config: cannot read /src/$f; check the checkout's file mode" >&2
    exit 1
  fi
done

chown 0:0 /stage
chmod 0755 /stage

stage() {
  # $1 source name, $2 group, $3 mode. Written to a dot name and renamed, so
  # the Relay never sees a half-written file.
  install -o 0 -g "$2" -m "$3" "/src/$1" "/stage/.$1.tmp"
  mv -f "/stage/.$1.tmp" "/stage/$1"
}

stage relay.toml "$relay_gid" 0640
if [ "$hostname" != relay ]; then
  if [ "$(grep -c '^hostname = "relay"$' /stage/relay.toml)" != 1 ]; then
    echo "dev-fleet-config: relay.toml has no single 'hostname = \"relay\"' line for FLEET_HOSTNAME to replace" >&2
    exit 1
  fi
  ( umask 077
    sed "s/^hostname = \"relay\"\$/hostname = \"$hostname\"/" /stage/relay.toml > /stage/.relay.toml.tmp )
  chown 0:"$relay_gid" /stage/.relay.toml.tmp
  chmod 0640 /stage/.relay.toml.tmp
  mv -f /stage/.relay.toml.tmp /stage/relay.toml
  echo "dev-fleet-config: tls.hostname = \"$hostname\""
fi
stage approval-gates.json 0 0644

# Nothing else stays: a file left by a previous fixture must not linger.
for entry in /stage/* /stage/.[!.]*; do
  [ -e "$entry" ] || continue
  case "${entry#/stage/}" in
    relay.toml | approval-gates.json) ;;
    *) rm -rf "$entry" ;;
  esac
done

ls -ln /stage

# init runs as the Relay's uid (relay init refuses root) and writes the admin and
# approver credentials and the daemons' join string onto these two volumes. A
# fresh named volume, or one left by an earlier root-run init, is root-owned, so
# hand both to that uid here. The daemons run as root and read the join string.
# Root takes each directory back before changing its mode: without CAP_FOWNER
# it may chmod only what it owns, and a re-run finds them owned by that uid.
relay_uid=10001
handoff() {
  # $1 directory, $2 mode.
  chown 0:0 "$1"
  chmod "$2" "$1"
  chown -R "$relay_uid:$relay_gid" "$1"
}
handoff /handoff/credential 0700
handoff /handoff/bootstrap 0755
