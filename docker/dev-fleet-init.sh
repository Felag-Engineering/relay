#!/bin/sh
# Dev-fleet bootstrap one-shot (docs/dev-fleet.md). DEV-ONLY. Runs once per
# `compose up`, as the `init` compose service, after the Relay is healthy, and
# does everything the fleet needs before a relay-daemon may start: creates the
# first admin with `relay init` (the Console admin, with its Console password and
# first API Token), creates the other dev Accounts (`dev-approver` and, under the
# OAuth overlay, the IdP's user), and mints the Enrollment Token, handing the
# daemons its join string.
#
# ADR-0030 / ADR-0032 anchor. Step c is `relay init`: the first admin and its
# credentials come from the binary's one local act, against the Relay's own store,
# through the same configuration check as the Relay. Everything after it is the
# real Control API, the Enrollment Token included (ADR-0032); RC-28 leaves the
# first Enrollment Token to enrollment.md.
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
#     string's fingerprint, and an Enrollment Token that names initial tags — it
#     can enroll Nodes and nothing else.
#   - The Console password reaches `relay init` on its stdin, from the shell's
#     printf builtin, never argv. The value arrives from the environment, which is
#     itself a process-listing exposure: acceptable on this fleet and nowhere else.
#   - `relay init` runs as the Relay's own uid and refuses root, exactly as the
#     Relay does: it reads the same read-only relay.toml through the same check.
#   - The committed default password is refused once the control plane is
#     published beyond loopback.
#   - The OAuth Account is human/operator and never mints a token: an OAuth
#     session presents the IdP's token, so there is nothing to write out.
#   - This one container holds both the store (read-write) and a bearer token,
#     deliberately, on this laptop fleet; no daemon-facing exposure is added.
#   - Fail closed: any failure here exits non-zero, and every daemon
#     `depends_on` this service, so the fleet does not start.
set -eu

CONFIG="/etc/relay/relay.toml"
CA_CERT="/var/lib/relay/ca/ca-cert.pem"
# The certificate carries tls.hostname, FLEET_HOSTNAME as dev-fleet-config.sh
# staged it; curl dials the compose name `relay` but verifies that name.
HOST="${FLEET_HOSTNAME:-relay}"
BASE="https://${HOST}:9443"
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
# surface. Keep this literal in step with the default in deploy/{test,demo}/docker-compose.yml.
test -n "${PASSWORD}" || die "CONSOLE_ADMIN_PASSWORD is unset"
case "${RELAY_PUBLISH_ADDR:-127.0.0.1}" in
    127.* | localhost | ::1 | "[::1]") ;;
    *)
        if [ "${PASSWORD}" = "admin1234567" ]; then
            die "refusing the committed default CONSOLE_ADMIN_PASSWORD: the control plane is published on ${RELAY_PUBLISH_ADDR}, beyond loopback. Set a real CONSOLE_ADMIN_PASSWORD (12+ characters); the fleet does not start until you do."
        fi
        ;;
esac

# c. The first admin, as a real operator creates it (RC-28): `relay init` makes
# the human admin ${ADMIN_NAME}, sets its Console password from stdin and prints
# its first API Token, and nothing else, to stdout. On a re-run the admin exists
# on the volume, so init creates nothing and prints nothing, and
# `relay init --recover` re-mints that admin's API Token instead. Each token
# expires after 24h; old ones are not revoked and die with the volume. The Console password is set once, on the
# first run: changing CONSOLE_ADMIN_PASSWORD afterwards needs a fresh volume.
( umask 077
  log "creating the first admin ${ADMIN_NAME} with relay init..."
  printf '%s\n' "${PASSWORD}" | relay init --config "${CONFIG}" --ttl 24h --admin "${ADMIN_NAME}" > /credential/control-credential
  if ! test -s /credential/control-credential; then
      log "${ADMIN_NAME} exists already; re-minting its API Token with relay init --recover..."
      relay init --config "${CONFIG}" --ttl 24h --recover "${ADMIN_NAME}" > /credential/control-credential
  fi )
chmod 0600 /credential/control-credential
test -s /credential/control-credential || die "relay init printed no credential"
# The bearer header reaches curl through a 0600 file, never argv, so the token
# is not visible in a process listing while a call runs.
AUTH_FILE="$(mktemp)"
trap 'rm -f "${AUTH_FILE}"' EXIT
trap 'exit 1' INT TERM
chmod 0600 "${AUTH_FILE}"
printf 'Authorization: Bearer %s\n' "$(cat /credential/control-credential)" > "${AUTH_FILE}"

# d. The one Control API wrapper. --connect-to sends the request to the in-fleet
# name `relay` while TLS verifies the certificate's own name: no insecure flag is needed.
api() {
    _method="$1"; _path="$2"; _body="${3:-}"
    if [ -n "${_body}" ]; then
        curl -fsS --cacert "${CA_CERT}" --connect-to "${HOST}:9443:relay:9443" -X "${_method}" \
            -H "@${AUTH_FILE}" \
            -H 'Content-Type: application/json' \
            -d "${_body}" "${BASE}${_path}"
    else
        curl -fsS --cacert "${CA_CERT}" --connect-to "${HOST}:9443:relay:9443" -X "${_method}" \
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

# g. The Console admin is the first admin step c created: a HUMAN Account,
# distinct from dev-approver, because the Console is a per-human identity
# (ADR-0009). Checked here like every other Account this script relies on.
ensure_account "${ADMIN_NAME}" admin >/dev/null

# h. Under the OAuth overlay only: the Relay never creates an Account from a
# token claim (ADR-0024), so the IdP's user needs one created the audited way.
# Role operator, human: an in-band answer counts as a person's own verified
# decision only on an OAuth session of a human Account.
if [ -n "${OAUTH_ACCOUNT_NAME}" ]; then
    log "ensuring the ${OAUTH_ACCOUNT_NAME} OAuth Account..."
    ensure_account "${OAUTH_ACCOUNT_NAME}" operator >/dev/null
fi

# i. A reusable Enrollment Token naming initial tags (asks explicitly for unlimited use, so every
# daemon and every restart of a not-yet-enrolled daemon can use it), minted
# through the real Control API. Daemons get ONLY its join string, which carries
# the Relay address and the CA fingerprint they pin; the 0600 file is read by
# docker/daemon-entrypoint.sh. A CA copy left by an older run is removed.
log "minting an Enrollment Token with initial tags..."
rm -f /bootstrap/enrollment-token /bootstrap/ca-cert.pem
( umask 077
  api POST /api/v1/enrollment-tokens \
      '{"initial_tags":["tag:env=dev","tag:fleet=dev"],"ttl_seconds":86400,"unlimited":true}' \
      | sed -n 's/.*"join_string":"\([^"]*\)".*/\1/p' > /bootstrap/join-string )
test -s /bootstrap/join-string || die "the mint response carried no join string"

# j.
if [ "${HOST}" = relay ]; then
    CONSOLE_HOST="127.0.0.1"
else
    CONSOLE_HOST="${HOST}"
fi
log "done — sign in at https://${CONSOLE_HOST}:${RELAY_PUBLISH_PORT:-9443}/console/ as ${ADMIN_NAME}."
