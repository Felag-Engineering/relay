#!/bin/sh
# relay-daemon container entrypoint (dev fleet, docs/dev-fleet.md).
#
# The daemon reads its join string from the RELAY_JOIN env var, but in the dev
# fleet it does not exist until runtime: the one-shot `init` service mints the
# Enrollment Token through the Relay's Control API and drops the join string from
# the mint response on a shared volume (see docker/dev-fleet-init.sh). This
# wrapper lifts that file into the env var, then execs the daemon so it becomes
# PID 1 (clean signal handling).
#
# It also starts the dev-fleet demo service (#389) on the Nodes whose labels
# say they run it — see the block below — BEFORE the join string export, for a
# reason that matters (read that block's comment).
#
# Every other setting (RELAY_ADDR, RELAY_SERVER_NAME, RELAY_STATE_DIR,
# RELAY_POLICY_PATH, HOSTNAME, RELAY_NODE_LABELS) comes from the compose
# environment; no CA material does — the daemon pins the Relay's CA from the join
# string. Enrollment is idempotent: once a Node has persisted its identity in
# RELAY_STATE_DIR it reuses it and never reads the join string again.
set -eu

# Start the dev-fleet demo service on the Nodes whose node: labels say they run
# it. RELAY_NODE_LABELS is a comma-separated key=value list. Spaces are stripped
# here so a label written with padding still matches; this is close to, but not
# identical to, the daemon's own parse (which trims each entry rather than
# deleting every space) — equivalent for every label this fleet uses.
#
# This runs BEFORE the RELAY_JOIN export, and that ordering is the
# whole point: httpd is long-lived, and if it started after the export it
# would hold the Enrollment Token in /proc/<httpd-pid>/environ for the life of
# the container, where the fixture's file.read "*" allow could read it. The
# executor's env_clear() exists precisely to close that leak for Task-spawned
# processes; this entrypoint must not reopen it for a process that outlives
# every Task. (PID 1 itself already holds the token, so this is not a
# regression either way — the fix is simply free.)
#
# A demo-fixture failure must never stop a Node enrolling, so this is
# non-fatal: the fleet's core enrollment and dispatch paths must not depend on
# a demo fixture, and a failure here stays legible through
# `dev-fleet-service status` (exit 3, state=down).
#
# The same Nodes also get the DEV-ONLY systemctl shim on the daemon's PATH
# (docker/fixtures/systemctl-shim), so `service.restart` restarts that demo
# service instead of failing to spawn systemctl. Only here, never on a Node
# without the demo service: there it would have nothing to restart, and the
# db Nodes' `spawn systemctl` failure is a documented demo beat. Non-fatal for
# the same reason as the service start.
labels=$(printf '%s' "${RELAY_NODE_LABELS:-}" | tr -d ' ')
case ",$labels," in
    *,role=web,*)
        if /usr/local/bin/dev-fleet-service start; then
            echo "dev-fleet-service: started on :8080" >&2
        else
            echo "dev-fleet-service: WARNING: failed to start; the Node still enrolls and every other dev-fleet path still works. See /var/lib/dev-fleet-service/httpd.log" >&2
        fi
        if ln -sf /usr/local/lib/dev-fleet-service/systemctl /usr/local/bin/systemctl; then
            echo "dev-fleet-service: systemctl shim installed (service.restart -> dev-fleet-service)" >&2
        else
            echo "dev-fleet-service: WARNING: could not install the systemctl shim; service.restart will fail to spawn systemctl on this Node" >&2
        fi
        ;;
esac

RELAY_JOIN="$(cat "${RELAY_JOIN_FILE:-/bootstrap/join-string}")"
export RELAY_JOIN

exec /usr/local/bin/relay-daemon
