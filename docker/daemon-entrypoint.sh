#!/bin/sh
# relay-daemon container entrypoint (dev fleet, docs/dev-fleet.md).
#
# The daemon reads its Enrollment Token from the RELAY_ENROLLMENT_TOKEN env var,
# but in the dev fleet the token does not exist until runtime: the one-shot
# `bootstrap` service mints it through the Relay's Control API and drops it on a
# shared volume (see docker/bootstrap.sh). This wrapper lifts that file into the
# env var, then execs the daemon so it becomes PID 1 (clean signal handling).
#
# Every other setting (RELAY_ADDR, RELAY_DOMAIN, RELAY_CA_BUNDLE_PATH,
# RELAY_STATE_DIR, RELAY_POLICY_PATH, HOSTNAME, RELAY_NODE_LABELS) comes from the
# compose environment. Enrollment is idempotent: once a Node has persisted its
# identity in RELAY_STATE_DIR it reuses it and never re-enrolls, so the token is
# only consulted on a Node's very first start.
set -eu

export RELAY_ENROLLMENT_TOKEN="$(cat "${RELAY_ENROLLMENT_TOKEN_FILE:-/bootstrap/enrollment-token}")"

exec /usr/local/bin/relay-daemon
