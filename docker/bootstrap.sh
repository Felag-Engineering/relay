#!/bin/sh
# Dev-fleet bootstrap (docs/dev-fleet.md). Runs once, as the one-shot `bootstrap`
# compose service, after the Relay is healthy. It solves the enrollment
# chicken-and-egg without adding any Relay startup "seed" seam: it mints an
# Enrollment Token through the real Control API (POST /api/v1/enrollment-tokens),
# and copies out the Relay's PUBLIC CA certificate for the daemons to pin.
#
# SECURITY notes:
#   - It mints only a `relay:`-scoped Enrollment Token (the Relay rejects any
#     non-relay: scope). The token can only enroll Nodes; it can never call the
#     API or run Operations.
#   - It hands daemons ONLY ca-cert.pem (the public CA cert). The CA private key
#     (ca-key.pem) lives on the relay-data volume, which this short-lived helper
#     mounts read-only but the long-lived daemon containers never mount at all —
#     so no daemon ever sees the CA private key.
#   - The dev control credential is passed in via RELAY_CONTROL_CREDENTIAL. It is
#     a DEV-ONLY fixture that grants full control-plane access; never reuse it.
set -eu

CRED="${RELAY_CONTROL_CREDENTIAL:?RELAY_CONTROL_CREDENTIAL must be set}"
CA_CERT="/relay-data/ca/ca-cert.pem"

# 1. Wait for the control API to answer. A 200 here proves the Relay is up AND
#    has created its CA (the cacert we pin below exists). We dial the in-fleet
#    DNS name `relay` so the server cert SAN (RELAY_HOSTNAME=relay) matches — no
#    -k / insecure flag needed inside the fleet.
echo "bootstrap: waiting for the Relay control API..."
until curl -fsS --cacert "${CA_CERT}" \
        -H "Authorization: Bearer ${CRED}" \
        https://relay:9443/api/v1/ping >/dev/null 2>&1; do
    sleep 1
done

# 2. Mint a reusable, relay:-scoped Enrollment Token. max_uses:0 = unlimited, so
#    every daemon (and every restart of a not-yet-enrolled daemon) can use the
#    same token; a 24h TTL is plenty for a laptop session.
echo "bootstrap: minting a relay:-scoped Enrollment Token..."
resp="$(curl -fsS --cacert "${CA_CERT}" \
        -H "Authorization: Bearer ${CRED}" \
        -H 'Content-Type: application/json' \
        -d '{"scope":["relay:env=dev","relay:fleet=dev"],"ttl_seconds":86400,"max_uses":0}' \
        https://relay:9443/api/v1/enrollment-tokens)"

# Extract the "token" field without depending on jq (curl image ships sed).
echo "${resp}" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p' > /bootstrap/enrollment-token

# 3. Hand daemons ONLY the public CA cert (never ca-key.pem).
cp "${CA_CERT}" /bootstrap/ca-cert.pem

# Fail loudly if either artifact is empty — daemons cannot enroll without both.
test -s /bootstrap/enrollment-token
test -s /bootstrap/ca-cert.pem

echo "bootstrap: done — Enrollment Token and CA cert are on the shared volume."
