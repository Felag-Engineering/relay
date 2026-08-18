#!/bin/sh
# Dev-fleet approver Account (docs/dev-fleet.md). Runs once, as the one-shot
# `approver` compose service, after the founding admin credential exists.
#
# WHY A SECOND ACCOUNT EXISTS AT ALL. The dev gate
# (docker/fixtures/approval-gates.json) leaves `requester_allowed` unset, which
# is the strict default: the Account that requested a parked dispatch may not
# approve it. With one Account the fleet could park a dispatch and never
# release it — the approval surface would be untestable by construction. This
# script creates the second, human Account the gate names as its audience.
#
# SECURITY notes:
#   - The approver is a HUMAN Account, distinct from the machine/admin
#     credential an MCP client drives. That separation is the whole point: the
#     decision must arrive on a credential the requesting session does not
#     hold (ADR-0027's out-of-band channel).
#   - Its credential is written to the `control-credential` volume, NOT to
#     `bootstrap-shared`. Daemons mount the latter; an approver credential
#     readable by every Node would let a compromised Node approve its own
#     remediation.
#   - Both files here are live DEV-ONLY credentials on a laptop fleet. Never
#     copy either out of the fleet.
set -eu

CRED_FILE="/credential/control-credential"
OUT="/credential/approver-credential"
CA_CERT="/relay-data/ca/ca-cert.pem"
APPROVER_NAME="dev-approver"

test -s "${CRED_FILE}" || { echo "approver: ${CRED_FILE} missing or empty; did the credential service run?" >&2; exit 1; }
CRED="$(cat "${CRED_FILE}")"

api() {
    _method="$1"; _path="$2"; _body="${3:-}"
    if [ -n "${_body}" ]; then
        curl -fsS --cacert "${CA_CERT}" -X "${_method}" \
            -H "Authorization: Bearer ${CRED}" \
            -H 'Content-Type: application/json' \
            -d "${_body}" "https://relay:9443${_path}"
    else
        curl -fsS --cacert "${CA_CERT}" -X "${_method}" \
            -H "Authorization: Bearer ${CRED}" \
            "https://relay:9443${_path}"
    fi
}

# Idempotent: `compose up` re-runs this service, and the Account survives on the
# relay-data volume. A 409 (name taken) is the normal second-run outcome, so the
# id is looked up rather than demanded from the create call.
echo "approver: ensuring the ${APPROVER_NAME} Account exists..."
api POST /api/v1/accounts \
    "{\"name\":\"${APPROVER_NAME}\",\"kind\":\"human\",\"role\":\"admin\"}" >/dev/null 2>&1 \
    || echo "approver: create returned non-2xx (already exists?) — resolving the id from the list."

# Extract this Account's id without jq (the curl image ships sed). The list is a
# flat JSON array of objects; splitting on "{" puts each Account on its own line
# so the name and id of the SAME record are matched together, never across two.
ACCOUNT_ID="$(api GET /api/v1/accounts \
    | tr '{' '\n' \
    | grep "\"name\":\"${APPROVER_NAME}\"" \
    | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' \
    | head -n 1)"

test -n "${ACCOUNT_ID}" || { echo "approver: could not resolve the ${APPROVER_NAME} Account id" >&2; exit 1; }
echo "approver: ${APPROVER_NAME} is Account ${ACCOUNT_ID}."

# Mint its API Token. The plaintext is returned exactly once, here.
echo "approver: minting the approver's API Token..."
api POST "/api/v1/accounts/${ACCOUNT_ID}/tokens" '{"name":"dev-fleet-approver","ttl_seconds":86400}' \
    | sed -n 's/.*"token":"\([^"]*\)".*/\1/p' > "${OUT}"

chmod 0600 "${OUT}"

# Fail loudly rather than leaving an empty credential for a later 401 to explain.
test -s "${OUT}" || { echo "approver: minted token was empty" >&2; exit 1; }

echo "approver: done — ${APPROVER_NAME}'s credential is on the control-credential volume."
