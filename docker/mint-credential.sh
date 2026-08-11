#!/bin/sh
# Dev-fleet credential mint (docs/dev-fleet.md). Runs once, as the one-shot
# `credential` compose service, after the Relay is healthy.
#
# Since #298 (ADR-0023) the control plane accepts only per-Account API Tokens —
# there is no seeded shared credential and no committed hash fixture. The first
# credential is minted locally, against the Relay's own store, by the same
# `relay bootstrap-token` subcommand a real operator runs.
#
# SECURITY notes:
#   - This writes a live admin credential to a volume. That is acceptable ONLY
#     because this is a laptop dev fleet on a private compose network with the
#     control plane published on loopback. Never do this in a real deployment:
#     there, the credential goes from the operator's terminal into their secret
#     store.
#   - It writes to `control-credential`, NOT to the `bootstrap-shared` volume the
#     daemons mount. A control-plane admin credential readable by every Node is
#     exactly what a compromised Node would use to drive the whole fleet.
#   - It mounts relay-data READ-WRITE, because minting is a store write. It is
#     the only service besides the Relay itself that does.
#   - The credential is regenerated on every `compose up` that runs this
#     service. Old tokens are not revoked (bootstrap-token is additive by
#     design); on a dev fleet they simply accumulate and die with the volume.
set -eu

STORE="/var/lib/relay/store/relay.db"
OUT="/credential/control-credential"

echo "credential: minting the founding admin's control-plane credential..."

# Stdout carries only the credential; diagnostics go to stderr, so this
# redirect captures exactly the secret and nothing else.
relay bootstrap-token -store-path "${STORE}" -name "dev-fleet" -ttl 24h > "${OUT}"

chmod 0600 "${OUT}"

# Fail loudly rather than leaving an empty credential for the next service to
# present as a mystery 401.
test -s "${OUT}"

echo "credential: done — control-plane credential is on the control-credential volume."
