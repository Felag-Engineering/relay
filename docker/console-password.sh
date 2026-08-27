#!/bin/sh
# Dev-fleet Console password (docs/dev-fleet.md). Runs once, as the one-shot
# `console-password` compose service, after the `admin` Account exists.
#
# It runs `relay console-password`, which is the same local, root-owned lever a
# real operator uses. There is deliberately no API for this and deliberately no
# flag that takes a password: a password on a command line is a password in
# every process listing and in the shell history of whoever typed it (the same
# reason invariant 11 makes every Relay secret a PATH rather than a value).
#
# So the password reaches the binary through a file this script writes and then
# removes. On a dev fleet the value arrives from the environment, which is
# itself a process-listing exposure — acceptable here and nowhere else, and
# called out rather than hidden.
set -eu

STORE="/var/lib/relay/store/relay.db"
ADMIN_NAME="${CONSOLE_ADMIN_NAME:-admin}"
PASSWORD="${CONSOLE_ADMIN_PASSWORD:-}"

test -n "${PASSWORD}" || { echo "console-password: CONSOLE_ADMIN_PASSWORD is unset" >&2; exit 1; }

PW_FILE="$(mktemp)"
chmod 0600 "${PW_FILE}"
trap 'rm -f "${PW_FILE}"' EXIT INT TERM

printf '%s' "${PASSWORD}" > "${PW_FILE}"

echo "console-password: setting the Console password for ${ADMIN_NAME}..."

# The Relay refuses a password below its 12-byte floor. That floor is not
# bureaucracy: the Console's sign-in throttle has NO hard lockout (spec 12), so
# an attacker gets slow, unlimited attempts and length is the only thing that
# makes that safe — in front of what ADR-0026 made a fleet-execution surface.
relay console-password -store-path "${STORE}" -account "${ADMIN_NAME}" -password-file "${PW_FILE}"

echo "console-password: done — sign in at https://127.0.0.1:9443/console/ as ${ADMIN_NAME}."
