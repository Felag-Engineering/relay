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
# The container runs as root with only CAP_CHOWN (to group the file to 10001, a
# group root is not in, and to hand init's volumes to the Relay's uid) and
# CAP_DAC_OVERRIDE (to read a checkout the developer's umask made 0600), with no
# network; every path but /stage and /handoff is read-only. Any failure exits
# non-zero, and the Relay depends on this service's success, so the fleet stays
# down.
set -eu

relay_gid=10001

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
