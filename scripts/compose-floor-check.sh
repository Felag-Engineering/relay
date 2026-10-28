#!/usr/bin/env bash
# Proves RC-27 on the committed compose stacks and the Relay image's Dockerfile: the Relay
# container takes relay.toml and every secret file as read-only mounts, runs unprivileged with
# one durable state volume, and nothing about the security floor is in its environment
# (ADR-0043, invariant 11). It also proves the RC-36 port rule, that a published node-plane
# port equals the listen port, since no committed stack sets advertised_address.
#
# It also proves the deployment-stack half of RC-7 on deploy/production: every Relay-image
# service there names ghcr.io/felag-engineering/relay[:<tag>]@sha256:<64 lowercase hex>, and no
# service there carries a build: at all (the stack runs only published images), so a build: on
# any service is refused, a one-shot built from relay.Dockerfile included. The test and demo stacks build from source and are exempt
# (DEV-ONLY). The check holds the shape of the pin and never resolves or chooses a digest.
#
# Needs bash, jq, awk and the `docker compose` CLI plugin, but NOT a Docker engine: each stack is
# rendered with `docker compose config`, which reads files and never connects to a daemon.
# Each stack is rendered with no inherited environment and no .env, so no caller variable can
# change a default.
#
# Stacks: deploy/production, deploy/test, deploy/demo, and deploy/demo with its OAuth overlay.
# Failures print variable and service NAMES, never values.
# Fails closed: a missing or empty floor-name list, a compose error and a stack with no Relay
# service are failures, not passes.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
RETIRED="$REPO_ROOT/relay/internal/relayconfig/retired.go"
DOCKERFILE="$REPO_ROOT/docker/relay.Dockerfile"

failures=0
fail() { echo "::error::compose-floor-check: $*"; failures=$((failures + 1)); }

# The floor names are the RELAY_* names the Relay once read from its environment, taken from the
# source that refuses them, so the list cannot drift from it.
[ -f "$RETIRED" ] || { echo "::error::compose-floor-check: $RETIRED is missing, so the floor names are unknown" >&2; exit 1; }
floor_names="$(grep -oE '"RELAY_[A-Z0-9_]+":' "$RETIRED" | tr -d '":')"
floor_json="$(jq -R . <<<"$floor_names" | jq -sc 'map(select(length > 0))')" || exit 1
if ! jq -e 'length > 0 and index("RELAY_HOSTNAME") != null and index("RELAY_CA_DIR") != null' <<<"$floor_json" >/dev/null; then
  echo "::error::compose-floor-check: the floor names parsed from retired.go are empty or lack RELAY_HOSTNAME / RELAY_CA_DIR" >&2
  exit 1
fi

# Per-service assertions. Emits one "<service>: <reason>" line per violation, and nothing for a
# stack that passes. Classification: a Relay-image service builds docker/relay.Dockerfile or
# names the published image; the Relay is one of those whose entrypoint is the Relay binary (the
# one-shots override it); a daemon builds docker/daemon.Dockerfile.
DEFS_JQ='
def isimage: ((.build.dockerfile // "") | endswith("docker/relay.Dockerfile"))
  or ((.image // "") | test("^ghcr\\.io/felag-engineering/relay([:@]|$)"));
def isdaemon: (.build.dockerfile // "") | endswith("docker/daemon.Dockerfile");
def isrelay: isimage and ((.entrypoint == null) or ((.entrypoint | length) == 0)
  or (.entrypoint[0] == "/usr/local/bin/relay") or (.entrypoint[0] == "relay"));
'
# Shared by the assertions and the vacuity count, so they classify the same services.
ASSERT_JQ="$DEFS_JQ"'
def mounts: .volumes // [];
def cfgmount: mounts | map(select(.target == "/etc/relay/relay.toml" or .target == "/etc/relay"));

(.services | to_entries[]) as $e | $e.key as $n | $e.value as $s |
(
  ($s | select(isrelay) | (
    (if ((.environment // {}) | length) > 0
      then "\($n): F1: the Relay has environment variables set (\(.environment | keys | join(", "))); its configuration is relay.toml alone" else empty end),
    (if ((.env_file // []) | length) > 0 then "\($n): F1: the Relay has an env_file" else empty end),
    (if (cfgmount | length) == 0 then "\($n): F2: relay.toml is not mounted at /etc/relay/relay.toml or /etc/relay"
     elif (cfgmount | any(.read_only != true)) then "\($n): F2: the relay.toml mount is not read_only" else empty end),
    (mounts | map(select(.target != "/var/lib/relay" and .read_only != true)) | .[] |
      "\($n): F3: the mount at \(.target) is not read_only"),
    (mounts | map(select(.type == "tmpfs")) | .[] | "\($n): F3: the tmpfs volume at \(.target) is not allowed"),
    (([mounts[] | select(.target == "/var/lib/relay")]) as $st |
      if ($st | length) != 1 then "\($n): F4: expected exactly one mount at /var/lib/relay, found \($st | length)"
      elif $st[0].type != "volume" then "\($n): F4: the state mount at /var/lib/relay must be a named volume, not \($st[0].type)"
      elif $st[0].read_only == true then "\($n): F4: the state volume must be writable" else empty end),
    (if .read_only != true then "\($n): F5: the root filesystem is not read_only" else empty end),
    (if ((.tmpfs // []) | map(split(":")[0]) | any(. != "/tmp")) then "\($n): F5: tmpfs may only be /tmp" else empty end),
    (if ((.cap_drop // []) | index("ALL")) == null then "\($n): F5: cap_drop does not contain ALL" else empty end),
    (if ((.cap_add // []) | length) > 0 then "\($n): F5: cap_add must be empty" else empty end),
    (if .privileged == true then "\($n): F5: privileged" else empty end),
    (if ((.security_opt // []) | any(. == "no-new-privileges:true" or . == "no-new-privileges")) | not
      then "\($n): F5: security_opt lacks no-new-privileges" else empty end),
    ((.security_opt // [])[] | select(test("unconfined|disable")) | "\($n): F5: security_opt \(.) lifts a confinement"),
    (["pid", "ipc", "network_mode"][] as $k | select(.[$k] == "host") | "\($n): F5: \($k): host shares a host namespace"),
    (if ((.devices // []) | length) > 0 then "\($n): F5: devices are not allowed" else empty end),
    (if ((.volumes_from // []) | length) > 0 then "\($n): F5: volumes_from is not allowed" else empty end),
    (if .user != "10001:10001" then "\($n): F5: user must be exactly 10001:10001" else empty end),
    (if ((.secrets // []) | length) > 0 or ((.configs // []) | length) > 0
      then "\($n): F6: secrets and configs are not modelled; mount the file read-only instead" else empty end),
    (if ((.healthcheck.test // []) | join(" ") | contains("/etc/relay/relay.toml")) | not
      then "\($n): F7: the healthcheck does not read its hostname from /etc/relay/relay.toml" else empty end)
  )),
  ($s | select(isdaemon | not) | (.environment // {}) | keys[] | select(. as $k | $floor | index($k) != null) |
    "\($n): F8: environment sets the floor name \(.)"),
  (($s.ports // [])[] | select(.target == 7654 and ((.published | tostring) != "7654")) |
    "\($n): F9: node-plane port 7654 is published on \(.published); set node_plane.advertised_address in this stack'"'"'s relay.toml (RC-36) and update this check")
)'

# RC-7, production only: one line per service that builds, and per Relay-image service whose image
# is not the published repository pinned by digest. Names and rule IDs, never the image string.
PIN_JQ="$DEFS_JQ"'
.services | to_entries[] | .key as $n | .value as $s |
(
  (if $s.build != null
    then "\($n): P1: the deployment stack builds nothing; it runs only published images, and this service has a build: (RC-7)" else empty end),
  ($s | select(isimage) |
    if ((.image // "") | test("^ghcr\\.io/felag-engineering/relay(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[0-9a-f]{64}$")) | not
    then "\($n): P2: the deployment stack'"'"'s Relay image is not ghcr.io/felag-engineering/relay pinned by digest (@sha256:<64 hex>) (RC-7)" else empty end)
)'

COUNT_JQ="$DEFS_JQ"'[.services[] | select(isrelay)] | length'

render() { # render <compose -f/--profile args>...
  env -i PATH="$PATH" HOME="$HOME" docker compose --env-file /dev/null "$@" config --format json
}

check_stack() { # check_stack <name> <compose args>...
  local name="$1" json lines pin_lines count line; shift
  local errfile; errfile="$(mktemp)" || { fail "$name: mktemp failed"; return; }
  if ! json="$(cd "$REPO_ROOT" && render "$@" 2>"$errfile")" || ! jq -e . >/dev/null 2>&1 <<<"$json"; then
    fail "$name: docker compose config failed or did not print JSON"
    sed 's/^/    /' "$errfile"
    rm -f "$errfile"
    return
  fi
  rm -f "$errfile"
  count="$(jq "$COUNT_JQ" <<<"$json")"
  if ! [ "$count" -ge 1 ] 2>/dev/null; then
    fail "$name: no Relay service found, so nothing was checked"
    return
  fi
  lines="$(jq -r --argjson floor "$floor_json" "$ASSERT_JQ" <<<"$json")" || { fail "$name: assertion query failed"; return; }
  if [ "$name" = production ]; then
    pin_lines="$(jq -r "$PIN_JQ" <<<"$json")" || { fail "$name: pin query failed"; return; }
    lines="$(printf '%s\n%s\n' "$lines" "$pin_lines" | grep -v '^$')"
  fi
  if [ -n "$lines" ]; then
    while IFS= read -r line; do fail "$name: $line"; done <<<"$lines"
    return
  fi
  echo "ok: $name: $count Relay service(s)"
}

check_stack production -f deploy/production/docker-compose.yml
check_stack test -f deploy/test/docker-compose.yml
check_stack demo -f deploy/demo/docker-compose.yml
check_stack oauth -f deploy/demo/docker-compose.yml -f deploy/demo/oauth.yml

# Dockerfile: no stage names a RELAY_* variable in ENV or ARG, every stage a Relay can run from
# ends as 10001:10001, and runtime is the last stage so a bare build gets it.
if [ ! -f "$DOCKERFILE" ]; then
  fail "Dockerfile: docker/relay.Dockerfile is missing"
else
  dockerfile_failed=0
  dockerfile_report="$(awk '
    { sub(/\r$/, "") }
    /^[ \t]*#/ { next }
    { line = $0; while (line ~ /\\[ \t]*$/ && (getline nxt) > 0) { sub(/\\[ \t]*$/, "", line); line = line " " nxt } $0 = line }
    toupper($1) == "FROM" {
      name = ""; parent = ""
      for (i = 2; i <= NF; i++) {
        if ($i ~ /^--/) continue
        if (toupper($i) == "AS") { name = tolower($(i + 1)); break }
        parent = $i
      }
      cur = name; order[++n] = name; par[name] = parent; user[name] = ""
      next
    }
    toupper($1) == "USER" { user[cur] = $2; next }
    toupper($1) == "ENV" || toupper($1) == "ARG" {
      for (i = 2; i <= NF; i++) { split($i, kv, "="); if (kv[1] ~ /^RELAY_/) print "D1: stage " cur " sets " kv[1] "; no stage may name a RELAY_* variable in ENV or ARG" }
    }
    function effective(s,   p) { if (user[s] != "") return user[s]; p = par[s]; return (p in par) ? effective(p) : "(root)" }
    END {
      split("runtime release dev-fleet", want, " ")
      for (i = 1; i <= 3; i++) {
        s = want[i]
        if (!(s in par)) { print "D2: " s " is not a stage"; continue }
        if (effective(s) != "10001:10001") print "D2: stage " s " ends as " effective(s) ", not 10001:10001"
      }
      if (order[n] != "runtime") print "D3: the last stage is " order[n] ", not runtime"
      print "parsed " n " stages"
    }' "$DOCKERFILE")" || { fail "Dockerfile: the stage parser failed"; dockerfile_failed=1; }
  # The END sentinel proves the parser ran to the end and saw a FROM.
  if [ "$dockerfile_failed" -eq 0 ] && ! grep -qE '^parsed [1-9][0-9]* stages$' <<<"$dockerfile_report"; then
    fail "Dockerfile: the stage parser reported no stages"; dockerfile_failed=1
  fi
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    case "$line" in parsed\ *) continue ;; esac
    dockerfile_failed=1
    fail "Dockerfile: $line"
  done <<<"$dockerfile_report"
  [ "$dockerfile_failed" -eq 0 ] && echo "ok: Dockerfile"
fi

if [ "$failures" -gt 0 ]; then
  echo "compose-floor-check: $failures violation(s)" >&2
  exit 1
fi
