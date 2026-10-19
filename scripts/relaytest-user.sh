#!/usr/bin/env bash
# Creates the accounts the separate-uid real-binary harness runs the Relay under: the system
# user `relaytest` (with its own group) and the group `relaytest-io`, which the user named in $1
# joins. The harness starts the Relay as relaytest with relaytest-io as its one supplementary
# group; the test reaches the Relay's socket and log only through relaytest-io, and never the
# configuration, CA or store (relay/internal/relaytest/separateuid.go).
#
# Run as root, once per host: CI's integration job runs it; a developer who wants `make verify`
# to exercise the harness locally runs `sudo scripts/relaytest-user.sh "$USER"`. Idempotent.
# A shell that was open before it ran does not have the new group: start a new login, or run
# the suites under `sg relaytest-io -c '...'`.
#
# Recovery: a run killed mid-test (a timeout panic) can leave the Relay and its layout behind;
# `sudo pkill -u relaytest; sudo rm -rf /run/relaytest.*` clears both.
set -euo pipefail

member="${1:?usage: relaytest-user.sh <user to add to relaytest-io>}"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "relaytest-user.sh: must run as root (sudo scripts/relaytest-user.sh ${member})" >&2
    exit 1
fi
id "${member}" >/dev/null
if [[ "${member}" == relaytest ]]; then
    echo "relaytest-user.sh: relaytest must never be in relaytest-io; name the user who runs the tests" >&2
    exit 1
fi

getent group relaytest-io >/dev/null || groupadd --system relaytest-io
if ! getent passwd relaytest >/dev/null; then
    useradd --system --user-group --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin relaytest
fi
# relaytest is never in relaytest-io's member list: the harness grants the Relay that group
# explicitly at start, and nothing else needs it.
usermod -aG relaytest-io "${member}"

echo "relaytest-user.sh: relaytest and relaytest-io exist; ${member} is in relaytest-io"
