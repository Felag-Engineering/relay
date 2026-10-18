#!/bin/sh
# Dev-fleet bootstrap one-shot (docs/dev-fleet.md). DEV-ONLY. Runs once per
# `compose up`, as the `init` compose service, after the Relay is healthy, and
# does everything the fleet needs before a relay-daemon may start: mints the
# founding admin's credential, creates the dev Accounts (`dev-approver`, the
# Console admin and, under the OAuth overlay, the IdP's user), sets the Console
# password, and mints the Enrollment Token, handing the daemons its join string.
#
# ADR-0030 / ADR-0032 anchor. Steps c (bootstrap-token → founding admin) and i
# (Enrollment Token + join string) are the bootstrap chain ADR-0030's falsifier
# names, formerly docker/mint-credential.sh and docker/bootstrap.sh (folded here
# by #893; `relay init` does not exist). That falsifier is met only when THESE
# steps are deleted and the dev fleet uses `relay init`. Whatever replaces them
# must keep minting the Enrollment Token through the real Control API (ADR-0032).
#
# SECURITY notes:
#   - Everything written here is a live DEV-ONLY credential on a laptop fleet
#     with the control plane published on loopback. Never copy any of it out of
#     the fleet; a real deployment hands its first credential from the
#     operator's terminal to their secret store.
#   - The admin and approver tokens go to the `control-credential` volume, which
#     no daemon mounts: a control-plane credential readable by every Node is what
#     a compromised Node would use to drive the fleet, or to approve its own
#     remediation.
#   - Daemons get only the join string from the mint response (written to
#     `bootstrap-shared`): never CA material, which they pin from the join
#     string's fingerprint, and an Enrollment Token the Relay accepts only if
#     it is `relay:`-scoped — it can enroll Nodes and nothing else.
#   - The Console password reaches `relay console-password` through a 0600 temp
#     file, never argv. The value arrives from the environment, which is itself
#     a process-listing exposure: acceptable on this fleet and nowhere else.
#   - The committed default password is refused once the control plane is
#     published beyond loopback.
#   - The OAuth Account is human/operator and never mints a token: an OAuth
#     session presents the IdP's token, so there is nothing to write out.
#   - This one container holds both the store (read-write) and a bearer token.
#     The old split across two containers (console-admin vs console-password) is
#     deliberately given up on this laptop fleet; the old `credential` already
#     held both, so no daemon-facing exposure is added.
#   - Fail closed: any failure here exits non-zero, and every daemon
#     `depends_on` this service, so the fleet does not start.
set -eu

STORE="/var/lib/relay/store/relay.db"
CA_CERT="/var/lib/relay/ca/ca-cert.pem"
BASE="https://relay:9443"
ADMIN_NAME="${CONSOLE_ADMIN_NAME:-admin}"
PASSWORD="${CONSOLE_ADMIN_PASSWORD:-}"
OAUTH_ACCOUNT_NAME="${OAUTH_ACCOUNT_NAME:-}"

# Both go to stderr: ensure_account's stdout is captured as an id.
log() { echo "init: $*" >&2; }
die() { echo "init: $*" >&2; exit 1; }

# b. The password guard runs first, so a refusal mints nothing.
# The committed default is fine on loopback and nowhere else: it is in this
# repository, so once the control plane is published beyond loopback
# (RELAY_PUBLISH_ADDR) it is a known password in front of a fleet-execution
# surface. Keep this literal in step with docker-compose.demo.yml's default.
test -n "${PASSWORD}" || die "CONSOLE_ADMIN_PASSWORD is unset"
case "${RELAY_PUBLISH_ADDR:-127.0.0.1}" in
    127.* | localhost | ::1 | "[::1]") ;;
    *)
        if [ "${PASSWORD}" = "admin1234567" ]; then
            die "refusing the committed default CONSOLE_ADMIN_PASSWORD: the control plane is published on ${RELAY_PUBLISH_ADDR}, beyond loopback. Set a real CONSOLE_ADMIN_PASSWORD (12+ characters); the fleet does not start until you do."
        fi
        ;;
esac

# c. Since #298 (ADR-0023) the control plane accepts only per-Account API
# Tokens, so the first is minted locally against the Relay's own store, as a
# real operator does. Stdout carries only the credential. It is regenerated on
# every run; old tokens are not revoked and die with the volume.
log "minting the founding admin's control-plane credential..."
relay bootstrap-token -store-path "${STORE}" -name "dev-fleet" -ttl 24h > /credential/control-credential
chmod 0600 /credential/control-credential
test -s /credential/control-credential
# The bearer header reaches curl through a 0600 file, never argv, so the token
# is not visible in a process listing while a call runs.
AUTH_FILE="$(mktemp)"
PW_FILE="$(mktemp)"
trap 'rm -f "${AUTH_FILE}" "${PW_FILE}"' EXIT
trap 'exit 1' INT TERM
chmod 0600 "${AUTH_FILE}" "${PW_FILE}"
printf 'Authorization: Bearer %s\n' "$(cat /credential/control-credential)" > "${AUTH_FILE}"

# d. The one Control API wrapper. We dial the in-fleet name `relay` so the
# server cert SAN (tls.hostname = "relay" in its relay.toml) matches: no insecure flag is needed.
api() {
    _method="$1"; _path="$2"; _body="${3:-}"
    if [ -n "${_body}" ]; then
        curl -fsS --cacert "${CA_CERT}" -X "${_method}" \
            -H "@${AUTH_FILE}" \
            -H 'Content-Type: application/json' \
            -d "${_body}" "${BASE}${_path}"
    else
        curl -fsS --cacert "${CA_CERT}" -X "${_method}" \
            -H "@${AUTH_FILE}" \
            "${BASE}${_path}"
    fi
}

# A 200 proves the Relay is up AND has created the CA we pin.
i=0
until api GET /api/v1/ping >/dev/null 2>&1; do
    i=$((i + 1))
    [ "${i}" -lt 60 ] || die "the Relay control API did not answer within 60s"
    sleep 1
done

# e. The list is a flat JSON array; splitting on "{" puts each Account on its
# own line so every field matched is from the SAME record (no jq in the image).
account_record() {
    api GET /api/v1/accounts | tr '{' '\n' | grep "\"name\":\"$1\"" | head -n 1 || true
}

# Idempotent: `compose up` re-runs this and the Account survives on the volume,
# so a non-2xx (409, name taken) is the normal second-run outcome. The record is
# then required to be what we want: a swallowed failure, or an Account promoted
# since, would surface later only as a refused sign-in. Stdout carries only the
# id; the POST response and every log line stay off it.
ensure_account() {
    _name="$1"; _role="$2"
    api POST /api/v1/accounts \
        "{\"name\":\"${_name}\",\"kind\":\"human\",\"role\":\"${_role}\"}" >/dev/null 2>&1 \
        || log "create ${_name} returned non-2xx (already exists?) — checking it."
    _rec="$(account_record "${_name}")"
    test -n "${_rec}" || die "the ${_name} Account does not exist after create"
    for _want in '"kind":"human"' "\"role\":\"${_role}\"" '"enabled":true'; do
        case "${_rec}" in
            *"${_want}"*) ;;
            *) die "${_name} exists but is not ${_want}: ${_rec}" ;;
        esac
    done
    printf '%s\n' "${_rec}" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p'
}

# f. The dev gate leaves `requester_allowed` unset, so the Account that requests
# a parked dispatch may not approve it; this is the second, human Account the
# gate names as its audience (ADR-0027's out-of-band channel). The demo fleet's
# in-band gate names no audience, so it is one Account among several there.
log "ensuring the dev-approver Account and minting its API Token..."
ID="$(ensure_account dev-approver admin)"
test -n "${ID}" || die "could not resolve the dev-approver Account id"
api POST "/api/v1/accounts/${ID}/tokens" '{"name":"dev-fleet-approver","ttl_seconds":86400}' \
    | sed -n 's/.*"token":"\([^"]*\)".*/\1/p' > /credential/approver-credential
chmod 0600 /credential/approver-credential
test -s /credential/approver-credential || die "the approver's minted token was empty"

# g. The Console admin is a HUMAN Account, distinct from dev-approver and the
# founding admin: the Console is a per-human identity (ADR-0009). Its password
# cannot be set through the Console (reaching it needs one), so
# `relay console-password` roots it locally in the store — the same
# chicken-and-egg and answer as `relay bootstrap-token` (ADR-0023) and
# ADR-0002's locally-rooted Policy. The Relay refuses a password under 12 bytes.
log "ensuring the ${ADMIN_NAME} Account and setting its Console password..."
ensure_account "${ADMIN_NAME}" admin >/dev/null
printf '%s' "${PASSWORD}" > "${PW_FILE}"
relay console-password -store-path "${STORE}" -account "${ADMIN_NAME}" -password-file "${PW_FILE}"

# h. Under the OAuth overlay only: the Relay never creates an Account from a
# token claim (ADR-0024), so the IdP's user needs one created the audited way.
# Role operator, human: an in-band answer counts as a person's own verified
# decision only on an OAuth session of a human Account.
if [ -n "${OAUTH_ACCOUNT_NAME}" ]; then
    log "ensuring the ${OAUTH_ACCOUNT_NAME} OAuth Account..."
    ensure_account "${OAUTH_ACCOUNT_NAME}" operator >/dev/null
fi

# i. A reusable, relay:-scoped Enrollment Token (max_uses 0 = unlimited, so every
# daemon and every restart of a not-yet-enrolled daemon can use it), minted
# through the real Control API. Daemons get ONLY its join string, which carries
# the Relay address and the CA fingerprint they pin; the 0600 file is read by
# docker/daemon-entrypoint.sh. A CA copy left by an older run is removed.
log "minting a relay:-scoped Enrollment Token..."
rm -f /bootstrap/enrollment-token /bootstrap/ca-cert.pem
( umask 077
  api POST /api/v1/enrollment-tokens \
      '{"scope":["relay:env=dev","relay:fleet=dev"],"ttl_seconds":86400,"max_uses":0}' \
      | sed -n 's/.*"join_string":"\([^"]*\)".*/\1/p' > /bootstrap/join-string )
test -s /bootstrap/join-string || die "the mint response carried no join string"

# j.
log "done — sign in at https://127.0.0.1:9443/console/ as ${ADMIN_NAME}."
