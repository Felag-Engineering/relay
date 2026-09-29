#!/bin/sh
# Dev-fleet OAuth Account (docs/operations/demo-fleet.md, "Signing in as a human
# over OAuth"). Runs once, as the one-shot `oauth-account` compose service that
# only docker-compose.oauth.yml defines, after the founding admin credential
# exists.
#
# WHY THIS EXISTS. The Relay never creates an Account from a token claim
# (ADR-0024): a token whose account claim names no Account is refused, however
# valid the IdP says it is. So the human the demo IdP signs in needs an Account
# created the audited way first — through /api/v1/accounts, like the fleet's
# `dev-approver` and `admin`.
#
# SECURITY notes:
#   - The Account is HUMAN, role operator. An in-band answer counts as a
#     person's own verified decision only on an OAuth session of a human
#     Account (docs/specs/approval.md, AP-79); a machine Account here would
#     quietly turn every answer back into an unverified one.
#   - No credential is minted: an OAuth session presents the IdP's token, never
#     an API Token, so there is nothing to write out and nothing to leak.
set -eu

CRED_FILE="/credential/control-credential"
CA_CERT="/relay-data/ca/ca-cert.pem"
ACCOUNT_NAME="${OAUTH_ACCOUNT_NAME:?OAUTH_ACCOUNT_NAME must name the realm user}"

test -s "${CRED_FILE}" || { echo "oauth-account: ${CRED_FILE} missing or empty; did the credential service run?" >&2; exit 1; }
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
echo "oauth-account: ensuring the ${ACCOUNT_NAME} Account exists..."
api POST /api/v1/accounts \
    "{\"name\":\"${ACCOUNT_NAME}\",\"kind\":\"human\",\"role\":\"operator\"}" >/dev/null 2>&1 \
    || echo "oauth-account: create returned non-2xx (already exists?) — checking it."

# Confirm the record rather than trusting the swallowed status above, and that
# it is still human and enabled: either one wrong surfaces later only as a
# refused sign-in, and the Relay never says which check refused it (by design,
# controlplane/oauth.go). Split on "{" so the fields matched are all from the
# SAME record (the curl image ships no jq).
RECORD="$(api GET /api/v1/accounts | tr '{' '\n' | grep "\"name\":\"${ACCOUNT_NAME}\"" | head -n 1 || true)"

test -n "${RECORD}" || { echo "oauth-account: the ${ACCOUNT_NAME} Account does not exist after create" >&2; exit 1; }
case "${RECORD}" in
    *'"kind":"human"'*) ;;
    *) echo "oauth-account: ${ACCOUNT_NAME} exists but is not a human Account: ${RECORD}" >&2; exit 1 ;;
esac
case "${RECORD}" in
    *'"enabled":true'*) ;;
    *) echo "oauth-account: ${ACCOUNT_NAME} exists but is not enabled: ${RECORD}" >&2; exit 1 ;;
esac
# And still `operator`: an Account of this name promoted to admin since it was
# created would hand the IdP's user admin reach, so refuse rather than go on.
case "${RECORD}" in
    *'"role":"operator"'*) ;;
    *) echo "oauth-account: ${ACCOUNT_NAME} exists but its role is not operator: ${RECORD}" >&2; exit 1 ;;
esac

echo "oauth-account: ${ACCOUNT_NAME} exists, kind human, role operator, enabled; the IdP's ${ACCOUNT_NAME} signs in as it."
