#!/bin/sh
# Dev-fleet Console admin Account (docs/dev-fleet.md). Runs once, as the
# one-shot `console-admin` compose service, after the founding admin credential
# exists.
#
# WHY THIS IS TWO SERVICES AND NOT ONE. Creating the Account is a control-plane
# act and goes through /api/v1/accounts with a credential, like any other. Setting
# its Console password is NOT: reaching the Console requires a password, so the
# first one cannot be set through the Console, and `relay console-password` roots
# it locally in the store instead — the same chicken-and-egg, and the same answer,
# as `relay bootstrap-token` (ADR-0023) and as ADR-0002's locally-rooted Policy.
# Those are two different authorities, so they are two different containers: this
# one holds a bearer token and no store access, and its sibling holds store
# access and no token.
#
# SECURITY notes:
#   - The Console admin is a HUMAN Account. The Console establishes a per-human
#     identity (ADR-0009) and refuses to set a password on a machine Account.
#   - This is a laptop dev fleet with the control plane published on loopback.
#     A real deployment creates its first human Account the same way and sets
#     the password from the operator's own terminal, never from a compose file.
set -eu

CRED_FILE="/credential/control-credential"
CA_CERT="/relay-data/ca/ca-cert.pem"
ADMIN_NAME="${CONSOLE_ADMIN_NAME:-admin}"

test -s "${CRED_FILE}" || { echo "console-admin: ${CRED_FILE} missing or empty; did the credential service run?" >&2; exit 1; }
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

# Idempotent: `compose up` re-runs this service and the Account survives on the
# relay-data volume, so a 409 on the second run is the normal outcome.
echo "console-admin: ensuring the ${ADMIN_NAME} Account exists..."
api POST /api/v1/accounts \
    "{\"name\":\"${ADMIN_NAME}\",\"kind\":\"human\",\"role\":\"admin\"}" >/dev/null 2>&1 \
    || echo "console-admin: create returned non-2xx (already exists?) — continuing."

# Confirm it is really there rather than trusting the swallowed status above: a
# silent failure here surfaces later as an unexplainable sign-in refusal, and the
# sign-in page cannot tell you why (it never distinguishes its failures, by design).
FOUND="$(api GET /api/v1/accounts \
    | tr '{' '\n' \
    | grep -c "\"name\":\"${ADMIN_NAME}\"" || true)"

test "${FOUND}" -ge 1 || { echo "console-admin: the ${ADMIN_NAME} Account does not exist after create" >&2; exit 1; }

echo "console-admin: ${ADMIN_NAME} exists, role admin, kind human."
