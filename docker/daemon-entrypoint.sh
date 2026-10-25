#!/bin/sh
# relay-daemon container entrypoint (dev fleet, docs/dev-fleet.md).
#
# The daemon reads no join string: `relay-daemon join` enrolls, in its own process,
# from the join string on standard input. In the dev fleet the string does not
# exist until runtime: the one-shot `init` service mints the Enrollment Token
# through the Relay's Control API and drops the join string from the mint response
# on a shared volume (see docker/dev-fleet-init.sh). This wrapper pipes that file
# to `relay-daemon join`, so the string enters no process environment and is
# written nowhere, then execs the daemon so it becomes PID 1 (clean signal
# handling).
#
# The container has no environment file and no running systemd, so the compose
# environment governs `join`, which enrolls into RELAY_STATE_DIR and starts no
# unit. On a restart over an enrolled volume `join` finds the identity, changes
# nothing and exits 0.
#
# It also starts the dev-fleet demo service (#389) on the Nodes whose labels
# say they run it, see the block below.
#
# Every other setting (RELAY_ADDRESS, RELAY_SERVER_NAME, RELAY_STATE_DIR,
# RELAY_POLICY_PATH, HOSTNAME, RELAY_NODE_LABELS) comes from the compose
# environment; no CA material does: `join` pins the Relay's CA from the join
# string.
set -eu

# Start the dev-fleet demo service on the Nodes whose node: labels say they run
# it. RELAY_NODE_LABELS is a comma-separated key=value list. Spaces are stripped
# here so a label written with padding still matches; this is close to, but not
# identical to, the daemon's own parse (which trims each entry rather than
# deleting every space) — equivalent for every label this fleet uses.
#
# The join string enters no process environment, so this block's ordering does
# not matter for the token: httpd, a long-lived process, never holds it.
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

# An input redirect, not cat: the string is never an argument and never a variable.
/usr/local/bin/relay-daemon join < "${RELAY_JOIN_FILE:-/bootstrap/join-string}"

exec /usr/local/bin/relay-daemon
