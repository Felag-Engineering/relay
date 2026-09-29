#!/usr/bin/env bash
# demo-fleet.sh — the demo compose project's fault injector and reset (#622).
# DEV-ONLY. Nothing in build/test/lint calls this; CI never touches Docker.
#
# WHY A FIXED PROJECT. docker-compose.yml carries no top-level `name:`, so a
# plain `docker compose --profile demo up` names its project after the
# checkout directory — different on every clone/worktree, and identical to
# the default (non-demo) fleet's own project if you happen to run both from
# the same directory. Reset is the most dangerous command in this file: it
# wipes volumes on purpose. Every subcommand here therefore runs against
# EXACTLY ONE project name, `relay-demo`, passed with `-p` (which outranks
# COMPOSE_PROJECT_NAME and .env), and refuses up front if anything about the
# environment says otherwise, before any Docker call except two read-only
# checks (the local-engine context endpoint, and — once that passes — a check
# that no OTHER checkout already owns the relay-demo project). See "The
# fault, and resetting between takes" in docs/operations/demo-fleet.md.
#
# Six subcommands: build (the only one that builds images, and the only one
# that pulls the image-only services' images), reset (wipe +
# recreate + verify), fault (kill the #389 dev-fleet-service on a subset of
# web Nodes, then verify the kill with the service's own probe), down (stop,
# no -v), up (the opposite of down — bring it back with no -v, no build; the
# mint one-shots still re-run on a fresh `up`, so .dev-fleet/ can go stale),
# creds (copy the current credentials out to .dev-fleet/ — mints nothing
# itself). `reset` and `up` also take `--oauth`, which layers
# docker-compose.oauth.yml on (#351: a DEV-ONLY identity provider, and the
# Relay's OAuth sign-in turned on). Without it, what reset/up bring up is
# exactly docker-compose.yml; but `down` and every reset's wipe name the
# overlay too, so they need it to parse (and Compose >= 2.18.0 for `!reset`).
# `dc()` is the ONLY place in this file that runs `docker compose` —
# enforced by scripts/demo-fleet-test.sh's static check S1, so a later edit
# cannot add a second, unguarded call site.
set -euo pipefail

die() {
    local code="$1"
    shift
    echo "demo-fleet: $*" >&2
    exit "$code"
}

# --- Constants -------------------------------------------------------------
# None of these are read from the environment. A demo-reset that could be
# redirected by an exported variable is exactly the foot-gun the issue warns
# about ("the presenter had two terminals open").
readonly DEMO_PROJECT="relay-demo"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
readonly REPO_ROOT
readonly COMPOSE_YML="${REPO_ROOT}/docker-compose.yml"
# The opt-in OAuth overlay (#351): a real identity provider, and the Relay's
# OAuth resource-server half turned on. Layered on only by `reset --oauth` /
# `up --oauth` — a command-line flag, never an environment variable, for the
# same reason as the constants above — and by `down`, so the provider goes
# down with the rest of the fleet whichever way it came up.
readonly COMPOSE_OAUTH_YML="${REPO_ROOT}/docker-compose.oauth.yml"
# The IdP's host port, published only when the overlay is on.
readonly OAUTH_IDP_PORT=8180
# The service only the overlay defines; its presence is how a running fleet
# says which way it was brought up.
readonly OAUTH_MARKER_SERVICE="relay-netns"

# The demo fleet's approval gate: in-band, no audience, requester allowed, so
# an MCP client can be asked the approval question or answer with
# approve_request (docs/operations/demo-fleet.md, "The human approver"). A path
# INSIDE the relay image — docker/relay.Dockerfile bakes it beside the default
# fleet's gate — handed to docker-compose.yml's DEV_FLEET_APPROVAL_GATE_CONFIG,
# which selects between the two. By convention only this script sets it, so
# the default three-Node fleet keeps its out-of-band gate — a convention, not
# an enforced property (see the comment in docker-compose.yml).
readonly DEMO_APPROVAL_GATE_CONFIG="/etc/relay/approval-gates.demo.json"

# One env=prod web Node and one env=staging web Node; neither is on the #452
# "drop first" list (daemon-9, then daemon-5) if the roster is ever trimmed.
readonly DEFAULT_FAULT_TARGETS=(daemon-4 daemon-6)

# The only tunable env var. Validated as a positive integer, else refused —
# this never touches Docker either way, so it is checked before the guard.
DEMO_WAIT_SECONDS="${DEMO_WAIT_SECONDS:-240}"
case "$DEMO_WAIT_SECONDS" in
    '' | *[!0-9]*)
        die 2 "DEMO_WAIT_SECONDS must be a positive integer, got '${DEMO_WAIT_SECONDS}'"
        ;;
    0[0-9]*)
        # A leading zero ("08") is ambiguous the moment it reaches arithmetic
        # ($((...))) below: bash parses a $((...)) operand with a leading 0 as
        # octal, and "08"/"09" are not valid octal, which would abort
        # wait_healthy with a raw bash syntax error instead of a clean refusal
        # (#622 security review S3).
        die 2 "refusing: DEMO_WAIT_SECONDS must not have a leading zero, got '${DEMO_WAIT_SECONDS}'"
        ;;
esac
if [ "$DEMO_WAIT_SECONDS" -le 0 ]; then
    die 2 "DEMO_WAIT_SECONDS must be a positive integer, got '${DEMO_WAIT_SECONDS}'"
fi
readonly DEMO_WAIT_SECONDS

# --- The guard ---------------------------------------------------------
# Runs FIRST, before the subcommand dispatch and before any `docker`
# invocation, except two read-only checks made by this function itself: the
# context-endpoint check (c) and the cross-worktree `docker ps` check (d).
# Every check here refuses (exit 2) rather than proceeds on doubt.
demo_guard() {
    # a. Project name. Unset-only expansion (${VAR-default}, not ${VAR:-default})
    # so COMPOSE_PROJECT_NAME="" (set but empty) is refused, not defaulted —
    # an ambiguous input is a refusal, not a guess.
    local requested="${COMPOSE_PROJECT_NAME-$DEMO_PROJECT}"
    if [ "$requested" != "$DEMO_PROJECT" ]; then
        die 2 "refusing: compose project '${requested}' is not '${DEMO_PROJECT}' — this command wipes volumes and kills processes, and '${DEMO_PROJECT}' is the only project it will ever touch. Unset COMPOSE_PROJECT_NAME (or set it to ${DEMO_PROJECT}) and try again."
    fi

    # b. DOCKER_HOST must be unset or point at a local unix socket. The threat
    # named in the issue is "the presenter had two terminals open" — a remote
    # DOCKER_HOST left over from another session is exactly that.
    if [ -n "${DOCKER_HOST:-}" ]; then
        case "$DOCKER_HOST" in
            unix://*) ;;
            *)
                die 2 "refusing: DOCKER_HOST points at a non-local engine ('${DOCKER_HOST}')"
                ;;
        esac
    fi

    # c. The current docker context must also resolve to a local unix socket.
    # This is the FIRST docker call allowed before the guard passes (the
    # cross-worktree check in (d) below is the second, and only reached if
    # this one succeeds); both only read. `|| endpoint=""` keeps this call
    # from tripping `set -e` before the refusal message below can run.
    local endpoint
    endpoint="$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null)" || endpoint=""
    case "$endpoint" in
        unix://*) ;;
        *)
            die 2 "refusing: the current docker context is not a local engine"
            ;;
    esac

    # d. relay-demo is one project name per Docker engine, but this repo is
    # checked out into many git worktrees on the same machine. Refuse if a
    # relay-demo container already exists that was brought up from a
    # DIFFERENT checkout — a destructive call from here would otherwise tear
    # down, or inject a fault into, a fleet this checkout does not own.
    # Read-only: `docker ps`, never `docker compose`.
    local foreign
    foreign="$(docker ps -a --filter "label=com.docker.compose.project=${DEMO_PROJECT}" \
        --format '{{.Label "com.docker.compose.project.working_dir"}}' 2>/dev/null)" ||
        die 2 "refusing: could not confirm no other checkout owns the ${DEMO_PROJECT} compose project (docker ps failed)"
    local dir
    while IFS= read -r dir; do
        [ -z "$dir" ] && continue
        if [ "$dir" != "$REPO_ROOT" ]; then
            die 2 "refusing: compose project '${DEMO_PROJECT}' is already running from another checkout at '${dir}' (this checkout is '${REPO_ROOT}') — relay-demo is one project per Docker engine; stop it there first, or run this from that checkout."
        fi
    done <<<"$foreign"

    # Guard passed. Clear anything in the caller's shell that could still
    # redirect `dc()`, then pin COMPOSE_PROJECT_NAME so the child call to
    # dev-fleet-mcp.sh (dev_fleet_mcp below) resolves to the same project.
    # The gate selector is pinned the same way, overriding any value the
    # caller exported: every compose call this script makes, the child's
    # included, must resolve the relay service identically, or one of them
    # would see a changed config and recreate the Relay on the wrong gate.
    unset COMPOSE_FILE COMPOSE_PROFILES
    export COMPOSE_PROJECT_NAME="$DEMO_PROJECT"
    export DEV_FLEET_APPROVAL_GATE_CONFIG="$DEMO_APPROVAL_GATE_CONFIG"
}

# OAUTH is 1 when this run layers the OAuth overlay on, else 0. It is set only
# by use_compose_files below, from a subcommand's own `--oauth` flag or from
# what is already running — never from the environment.
OAUTH=0
DC_FILES=(-f "$COMPOSE_YML")

# use_compose_files <0|1>: which compose files dc() — and dev_fleet_mcp's
# child — name from here on.
use_compose_files() {
    case "$1" in
        0) OAUTH=0 DC_FILES=(-f "$COMPOSE_YML") ;;
        1) OAUTH=1 DC_FILES=(-f "$COMPOSE_YML" -f "$COMPOSE_OAUTH_YML") ;;
        *) die 1 "internal: use_compose_files takes 0 or 1, got '$1'" ;;
    esac
}

# dc: the ONLY place in this file that runs `docker compose`. Always pins the
# project, the compose file(s), and profile, so nothing in the caller's
# environment can change which project a call reaches once the guard has
# passed. DC_FILES is this file's own constant paths, chosen above.
dc() {
    docker compose -p "$DEMO_PROJECT" "${DC_FILES[@]}" --profile demo "$@"
}

# running_mode: prints `oauth` if the relay-demo project has any container of
# the overlay's marker service, `plain` if it has a relay container and none
# of the marker's, and `none` if it has neither. Read-only (`docker ps`).
running_mode() {
    local services
    services="$(docker ps -a --filter "label=com.docker.compose.project=${DEMO_PROJECT}" \
        --format '{{.Label "com.docker.compose.service"}}' 2>/dev/null)" ||
        die 1 "could not list the ${DEMO_PROJECT} containers (docker ps failed)"
    if printf '%s\n' "$services" | grep -qxF "$OAUTH_MARKER_SERVICE"; then
        echo oauth
    elif printf '%s\n' "$services" | grep -qxF relay; then
        echo plain
    else
        echo none
    fi
}

# adopt_running_mode: for the subcommands that act on a fleet already up
# (fault, creds) — name the same compose files it was brought up with, so
# Compose sees no orphans. Assigned before it is tested, so a failed
# `docker ps` stops the script rather than reading as "plain".
adopt_running_mode() {
    local have
    have="$(running_mode)"
    if [ "$have" = oauth ]; then
        use_compose_files 1
    fi
}

# parse_oauth_flag <subcommand> [args...]: accepts nothing, or exactly
# `--oauth`; anything else is a usage error. Sets the compose files to match.
parse_oauth_flag() {
    local sub="$1"
    shift
    case "$#:${1-}" in
        0:) use_compose_files 0 ;;
        1:--oauth) use_compose_files 1 ;;
        *) die 2 "refusing: '${sub}' takes no argument but --oauth, got: $*" ;;
    esac
}

# dev_fleet_mcp: runs scripts/dev-fleet-mcp.sh against the demo project from
# REPO_ROOT, regardless of the caller's cwd. dev-fleet-mcp.sh calls bare
# `docker compose` (cp / run --no-deps), so it needs these three exported in
# its own subshell to resolve to relay-demo rather than whatever the
# caller's shell would otherwise leave COMPOSE_FILE/COMPOSE_PROFILES as.
dev_fleet_mcp() {
    (
        cd "$REPO_ROOT" || exit 1
        # dev-fleet-mcp.sh also reads STATE_DIR (default .dev-fleet) and BASE
        # (default https://localhost:9443) from the environment; unset them so
        # a value left over in the caller's shell cannot redirect where
        # credentials are written or which Relay is called (#622 security
        # review S4).
        unset STATE_DIR BASE
        export COMPOSE_PROJECT_NAME="$DEMO_PROJECT"
        # Colon-separated: Compose's own COMPOSE_FILE list separator on Linux.
        if [ "$OAUTH" -eq 1 ]; then
            export COMPOSE_FILE="${COMPOSE_YML}:${COMPOSE_OAUTH_YML}"
        else
            export COMPOSE_FILE="$COMPOSE_YML"
        fi
        export COMPOSE_PROFILES=demo
        bash scripts/dev-fleet-mcp.sh "$@"
    )
}

# dev-fleet-mcp.sh init COPIES credentials out of the volume they already
# live on (`docker compose cp` / `run --no-deps`); it mints nothing itself
# (#622 review C2-B1). Named for what it does, not for what a reader might
# assume `init` implies.
copy_creds() {
    dev_fleet_mcp init
}

# --- Service rosters, derived from the compose file, never hardcoded -------
# Populates WEB_SERVICES and DAEMON_SERVICES (space-separated), so a #452-style
# roster trim (dropping daemon-9, then daemon-5) keeps this script working with
# no edit here.
WEB_SERVICES=""
DAEMON_SERVICES=""
compose_services() {
    local json parsed
    json="$(dc config --format json)" || die 1 "docker compose config failed"
    parsed="$(printf '%s' "$json" | python3 -c '
import json, sys

data = json.load(sys.stdin)
services = data.get("services", {})
daemons = []
web = []
for name, svc in services.items():
    if name.startswith("daemon-"):
        daemons.append(name)
    env = svc.get("environment") or {}
    # Same rule docker/daemon-entrypoint.sh uses: strip every space, then
    # look for the exact term "role=web" in the comma-separated list.
    labels = str(env.get("RELAY_NODE_LABELS", "")).replace(" ", "")
    terms = [t for t in labels.split(",") if t]
    if "role=web" in terms:
        web.append(name)
print(" ".join(sorted(daemons)))
print(" ".join(sorted(web)))
')" || die 1 "failed to parse docker compose config"
    DAEMON_SERVICES="$(printf '%s\n' "$parsed" | sed -n '1p')"
    WEB_SERVICES="$(printf '%s\n' "$parsed" | sed -n '2p')"
}

# --- wait_healthy ------------------------------------------------------
# Polls `dc ps -a --format json` every 2s up to DEMO_WAIT_SECONDS. Handles
# BOTH shapes Compose v2 has shipped for --format json: one JSON object per
# line, or a single JSON array.
read -r -d '' WAIT_HEALTHY_PY <<'PY' || true
import json, os, sys


def load_items(raw):
    raw = raw.strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        items = []
        for line in raw.splitlines():
            line = line.strip()
            if line:
                items.append(json.loads(line))
        return items
    return parsed if isinstance(parsed, list) else [parsed]


items = load_items(sys.stdin.read())
by_service = {i.get("Service"): i for i in items}

daemons = os.environ.get("DAEMON_SERVICES", "").split()
oneshots = ["credential", "approver", "console-admin", "console-password", "bootstrap"]
healthy = ["relay"] + daemons
running = []
if os.environ.get("OAUTH") == "1":
    # docker-compose.oauth.yml's services: the IdP has a healthcheck, the
    # namespace holder has nothing to check but that it runs.
    healthy.append("idp")
    running.append("relay-netns")
    oneshots.append("oauth-account")

missing = []
for svc in healthy:
    item = by_service.get(svc)
    if not item or item.get("State") != "running" or item.get("Health") != "healthy":
        missing.append(svc)
for svc in running:
    item = by_service.get(svc)
    if not item or item.get("State") != "running":
        missing.append(svc)

failed = []
not_done = []
for svc in oneshots:
    item = by_service.get(svc)
    if not item:
        not_done.append(svc)
        continue
    if item.get("State") != "exited":
        not_done.append(svc)
        continue
    if str(item.get("ExitCode")) != "0":
        failed.append(svc)

if failed:
    print(",".join(failed))
    sys.exit(2)
if missing or not_done:
    print(",".join(missing + not_done))
    sys.exit(1)
sys.exit(0)
PY
readonly WAIT_HEALTHY_PY

wait_healthy() {
    local deadline=$((SECONDS + DEMO_WAIT_SECONDS))
    local json out rc
    while :; do
        json="$(dc ps -a --format json 2>/dev/null)" || json=""
        rc=0
        out="$(DAEMON_SERVICES="$DAEMON_SERVICES" OAUTH="$OAUTH" python3 -c "$WAIT_HEALTHY_PY" <<<"$json")" || rc=$?
        if [ "$rc" -eq 0 ]; then
            return 0
        fi
        if [ "$rc" -eq 2 ]; then
            die 1 "demo fleet: one-shot(s) [$out] exited non-zero; inspect with: docker compose -p ${DEMO_PROJECT} logs SERVICE"
        fi
        if [ "$SECONDS" -ge "$deadline" ]; then
            dc ps -a || true
            die 1 "demo fleet did not become healthy within ${DEMO_WAIT_SECONDS}s (still waiting on: $out); inspect with: docker compose -p ${DEMO_PROJECT} logs SERVICE"
        fi
        sleep 2
    done
}

# --- Reset-only checks -------------------------------------------------

# Every image `dc config --images` names must already exist. Reset NEVER
# builds — if one is missing, fail before touching a volume, naming the fix.
# The image list is captured explicitly (not looped over a bare command
# substitution), so an empty or failing list cannot silently pass under `set -e`.
image_precheck() {
    local images
    images="$(dc config --images)" || die 1 "docker compose config --images failed"
    if [ -z "$images" ]; then
        die 1 "docker compose config --images returned no images; run make demo-build once (reset never builds)"
    fi
    local img
    while IFS= read -r img; do
        [ -z "$img" ] && continue
        docker image inspect "$img" >/dev/null 2>&1 ||
            die 1 "image ${img} is missing; run make demo-build once (reset never builds)"
    done <<<"$images"
}

# The demo fleet and the default fleet share host ports 7654/9443 and cannot
# run at once. Refuse BEFORE `dc down -v` if either port is already published
# by some OTHER compose project — read-only (`docker ps`, never `docker compose`).
check_ports_not_foreign() {
    local port owner proj
    local ports=(7654 9443)
    if [ "$OAUTH" -eq 1 ]; then
        ports+=("$OAUTH_IDP_PORT")
    fi
    for port in "${ports[@]}"; do
        # `--filter publish=<port>` only — real Docker rejects a filter value
        # that contains ':' ("filter for 'publish' should not contain ':'"),
        # so this must NOT include the bind address. Any container publishing
        # the host port, on any address, is a conflict either way.
        owner="$(docker ps --filter "publish=${port}" \
            --format '{{.Label "com.docker.compose.project"}}' 2>/dev/null)" ||
            die 1 "could not check whether host port ${port} is already in use (docker ps failed)"
        while IFS= read -r proj; do
            [ -z "$proj" ] && continue
            if [ "$proj" != "$DEMO_PROJECT" ]; then
                die 1 "host port ${port} is already published by compose project '${proj}', not '${DEMO_PROJECT}' — the demo fleet and that project cannot run at once; stop '${proj}' first."
            fi
        done <<<"$owner"
    done
}

# `-p relay-demo` pins the PROJECT name, but what `down -v` actually deletes
# is whatever volume name docker-compose.yml's top-level `volumes:` resolves
# to — normally `<project>_<key>`, but a `name:` or `external:` override on a
# volume there would break that, and `-p` gives no protection against that
# case. Assert every volume compose resolves to still starts with
# `relay-demo_` BEFORE `dc down -v` runs (#622 security review S1).
check_volume_names_scoped() {
    local json
    json="$(dc config --format json)" || die 1 "docker compose config failed"
    printf '%s' "$json" | python3 -c '
import json, sys

data = json.load(sys.stdin)
volumes = data.get("volumes") or {}
prefix = "relay-demo_"
bad = [
    f"{key} -> {name}"
    for key, vol in volumes.items()
    for name in [(vol or {}).get("name") or f"{prefix}{key}"]
    if not name.startswith(prefix)
]
if bad:
    print("volume(s) not scoped to relay-demo_: " + ", ".join(bad), file=sys.stderr)
    sys.exit(1)
' || die 1 "refusing: a compose volume does not resolve to a relay-demo_-prefixed name — down -v would remove a volume this checkout does not own"
}

check_approvals_clear() {
    local out
    out="$(dev_fleet_mcp api GET /api/v1/approvals)" || die 1 "GET /api/v1/approvals failed after reset"
    printf '%s' "$out" | python3 -c '
import json, sys

data = json.load(sys.stdin)
approvals = data.get("approvals")
if approvals is None or len(approvals) != 0:
    print(f"approvals queue is not empty after reset: {approvals}", file=sys.stderr)
    sys.exit(1)
' || die 1 "approvals queue is not empty after reset"
}

# Reads the REAL registry over MCP list_nodes (there is no GET /api/v1/nodes
# list route on the Control API — only /api/v1/nodes/{node_id}), and checks
# every Node the compose file says should exist is present and connected.
check_nodes_healthy() {
    local out want
    out="$(dev_fleet_mcp call list_nodes)" || die 1 "list_nodes over MCP failed after reset"
    want="$(printf '%s\n' "$DAEMON_SERVICES" | wc -w | tr -d ' ')"
    printf '%s' "$out" | DAEMON_COUNT="$want" python3 -c '
import json, os, sys

data = json.load(sys.stdin)
nodes = data.get("result", {}).get("structuredContent", {}).get("nodes")
want = int(os.environ["DAEMON_COUNT"])
if nodes is None:
    print(f"list_nodes response carried no result.structuredContent.nodes: {data}", file=sys.stderr)
    sys.exit(1)
if len(nodes) != want:
    print(f"node count {len(nodes)} != expected {want}", file=sys.stderr)
    sys.exit(1)
bad = [n.get("node_id") for n in nodes if not n.get("connected")]
if bad:
    print(f"not connected after reset: {bad}", file=sys.stderr)
    sys.exit(1)
' || die 1 "not every Node is healthy and connected after reset (list_nodes)"
}

# --- Subcommands -------------------------------------------------------

# `compose build` only builds the services that have a `build:` section. The
# image-only services (today the curl one-shots: approver, console-admin,
# bootstrap) are never built, and reset/up deliberately run with
# `--pull never`, so without the pull below a fresh Docker engine could build
# successfully and still fail reset's image precheck. `--ignore-buildable`
# pulls exactly the services that have no build, whatever they are, so a
# future image-only service is covered without an edit here. `--policy
# missing` fetches only what is not already present: every such image is
# pinned by tag, so a present one is the right one, and a rebuild on a machine
# with no network still succeeds.
#
# The pull names the OAuth overlay too (#351), so one `build` leaves either
# fleet startable: its image-only services are the identity provider and the
# namespace holder, both pinned by digest. It is named here for the same
# reason `down` and every reset's wipe name it — which fleet will be brought up
# next is not known at build time — and it only adds images. The build itself
# stays plain: the overlay adds no service with a `build:` section.
cmd_build() {
    dc build || die 1 "docker compose build failed"
    use_compose_files 1
    dc pull --ignore-buildable --policy missing ||
        die 1 "docker compose pull of the image-only services failed"
}

cmd_reset() {
    parse_oauth_flag reset "$@"
    local want="$OAUTH"

    # Image precheck first, before ANY volume is touched. compose_services
    # (which needs no running fleet, only the compose FILE) is deliberately
    # deferred past this point: a stub/offline failure at the precheck must
    # stop reset before `down -v` runs, with nothing else attempted first.
    # Checked for the fleet being brought up — with --oauth, that includes
    # the IdP's image, which `build` pulls.
    image_precheck
    check_ports_not_foreign

    # Wipe with the overlay layered on whichever way this reset brings the
    # fleet back, so a previous --oauth run's IdP container and its volume go
    # too — `--remove-orphans` alone would leave the volume behind.
    use_compose_files 1
    check_volume_names_scoped
    dc down -v --remove-orphans --timeout 5 || die 1 "docker compose down -v failed"

    use_compose_files "$want"
    dc up -d --no-build --pull never || die 1 "docker compose up failed"

    compose_services
    wait_healthy

    local svc rc
    for svc in $WEB_SERVICES; do
        rc=0
        dc exec -T "$svc" /usr/local/bin/dev-fleet-service status >/dev/null 2>&1 || rc=$?
        if [ "$rc" -eq 3 ]; then
            dc exec -T "$svc" /usr/local/bin/dev-fleet-service start >/dev/null 2>&1 || true
            rc=0
            dc exec -T "$svc" /usr/local/bin/dev-fleet-service status >/dev/null 2>&1 || rc=$?
        fi
        if [ "$rc" -ne 0 ]; then
            die 1 "${svc}: dev-fleet-service is not serving after reset (status exit ${rc})"
        fi
    done

    copy_creds || die 1 "failed to copy the fresh credentials out with scripts/dev-fleet-mcp.sh init"
    check_approvals_clear
    check_nodes_healthy

    local n_daemons n_web
    n_daemons="$(printf '%s\n' "$DAEMON_SERVICES" | wc -w | tr -d ' ')"
    n_web="$(printf '%s\n' "$WEB_SERVICES" | wc -w | tr -d ' ')"
    echo "demo-fleet: reset complete — ${n_daemons} Nodes healthy, ${n_web} web Nodes serving, .dev-fleet/ refreshed with the fresh credentials this reset just minted."
    echo "demo-fleet: the CA was regenerated, so a registered MCP client still holds the OLD bearer token AND the OLD CA (NODE_EXTRA_CA_CERTS is read only at process start). Restart it — .dev-fleet/ is already current, so there is no need to run 'make demo-creds' again first:"
    echo "demo-fleet:   claude mcp remove relay"
    if [ "$OAUTH" -eq 1 ]; then
        oauth_hint
    else
        echo "demo-fleet:   claude mcp add --transport http relay https://relay:9443/mcp --header \"Authorization: Bearer \$(cat .dev-fleet/control-credential)\""
    fi
}

# The registration that signs Claude Code in through the IdP instead of a
# bearer token (docs/operations/demo-fleet.md, "Signing in as a human over
# OAuth"). The client id and callback port are the realm fixture's
# (docker/fixtures/keycloak/relay-demo-realm.json); the IdP login is DEV-ONLY.
oauth_hint() {
    echo "demo-fleet:   claude mcp add --transport http --client-id relay-demo-claude-code --callback-port 33418 relay https://relay:9443/mcp"
    echo "demo-fleet: then start Claude Code with NODE_EXTRA_CA_CERTS=\"\$PWD/.dev-fleet/ca-cert.pem\", run /mcp, pick relay, Authenticate, and sign in as demo-operator / dev-only-demo-operator (DEV-ONLY)."
}

cmd_fault() {
    adopt_running_mode
    compose_services

    local targets=("$@")
    # `make demo-fault` passes an override through the DEMO_FAULT_NODES
    # environment variable rather than as positional args (its value is an
    # exported Make variable, not text spliced into the recipe — see the
    # Makefile comment). `read -ra` splits it on whitespace with NO pathname
    # expansion, so a value carrying a glob character cannot silently expand
    # to filenames in the caller's cwd. Every resulting token is still
    # validated below against the derived web roster, and REFUSED before any
    # exec, exactly like a positional argument — an env value is never
    # treated as shell text to re-parse (#622 security review S2).
    if [ "${#targets[@]}" -eq 0 ] && [ -n "${DEMO_FAULT_NODES:-}" ]; then
        read -ra targets <<<"$DEMO_FAULT_NODES"
    fi
    if [ "${#targets[@]}" -eq 0 ]; then
        targets=("${DEFAULT_FAULT_TARGETS[@]}")
    fi

    local t
    for t in "${targets[@]}"; do
        case " ${WEB_SERVICES} " in
            *" ${t} "*) ;;
            *)
                die 2 "refusing: ${t} runs no demo service (not role=web), so faulting it would report a condition that is not there"
                ;;
        esac
    done

    local running
    running="$(dc ps --status running --services 2>/dev/null | tr '\n' ' ')" ||
        die 1 "could not list running services"
    for t in "${targets[@]}"; do
        case " ${running} " in
            *" ${t} "*) ;;
            *)
                die 1 "demo fleet not up; run make demo-reset"
                ;;
        esac
    done

    local tries rc
    for t in "${targets[@]}"; do
        # Kill by pidof, not the pidfile — a stale pidfile cannot redirect
        # the kill. A zombie already in the list is harmless.
        dc exec -T "$t" sh -c 'pids="$(pidof httpd 2>/dev/null || true)"; [ -z "$pids" ] || kill $pids; exit 0' \
            || die 1 "${t}: failed to run the kill command"

        tries=0
        rc=0
        while :; do
            rc=0
            dc exec -T "$t" /usr/local/bin/dev-fleet-service status >/dev/null 2>&1 || rc=$?
            [ "$rc" -eq 3 ] && break
            tries=$((tries + 1))
            [ "$tries" -ge 5 ] && break
            sleep 1
        done
        if [ "$rc" -ne 3 ]; then
            die 1 "${t}: httpd still answering after kill"
        fi
        echo "${t}: dev-fleet demo service DOWN (dev-fleet-service status: exit 3)"
    done
}

cmd_down() {
    # Always with the overlay layered on: it only adds services, so this stops
    # a plain fleet's containers exactly as before, and an --oauth one without
    # leaving its IdP running (and the network it holds) behind. The cost: a
    # plain `down` now fails if docker-compose.oauth.yml does not parse.
    use_compose_files 1
    dc down || die 1 "docker compose down failed"
}

# The opposite of cmd_down: bring the fleet back up WITHOUT wiping any volume
# — unlike cmd_reset, no `-v`, no image precheck. It is NOT "no credential
# mint": the credential/approver/console-admin/console-password one-shots
# have `restart: no`, but a STOPPED one-shot container is started again by
# `dc up` (including after a prior `cmd_down`), which re-runs its entrypoint
# and so re-mints fresh values into the (persisted) volume — see
# docker/mint-credential.sh. What `up` does NOT do is copy those new values
# out to .dev-fleet/; run `cmd_creds` (`make demo-creds`) after this for that.
#
# `up --oauth` brings it up with the OAuth overlay. Switching between the two
# while containers of the other exist is refused: the two put the Relay's
# ports on different containers, and Compose would recreate the Relay while
# the old holder of those ports still runs. `down` (or `reset`) first.
cmd_up() {
    parse_oauth_flag up "$@"
    local have
    have="$(running_mode)"
    if [ "$OAUTH" -eq 1 ] && [ "$have" = plain ]; then
        die 2 "refusing: ${DEMO_PROJECT} was brought up without --oauth; run 'make demo-down' first, then 'make demo-up-oauth'."
    fi
    if [ "$OAUTH" -eq 0 ] && [ "$have" = oauth ]; then
        die 2 "refusing: ${DEMO_PROJECT} was brought up with --oauth; run 'make demo-down' first, or 'make demo-up-oauth' to keep it."
    fi
    check_ports_not_foreign
    dc up -d --no-build --pull never || die 1 "docker compose up failed"
    compose_services
    wait_healthy
    echo "demo-fleet: relay-demo is up and healthy (no volume touched). If this recreated the mint one-shots, .dev-fleet/ is now stale — run 'make demo-creds' to refresh it."
    if [ "$OAUTH" -eq 1 ]; then
        echo "demo-fleet: OAuth is on. A Claude Code already signed in stays signed in (the IdP's sessions survive down/up); to register one:"
        oauth_hint
    fi
}

# Copies the CURRENT control-plane credentials and CA out to .dev-fleet/
# (scripts/dev-fleet-mcp.sh init: a `docker compose cp` / `run --no-deps`
# read). This mints NOTHING — it only reads out whatever the mint one-shots
# most recently wrote to their volume, which is why it is safe to run after
# either `demo-reset` or `demo-up`, and is a no-op with respect to Jobs,
# approvals, the registry, or any Node's identity.
cmd_creds() {
    adopt_running_mode
    copy_creds || die 1 "failed to copy credentials with scripts/dev-fleet-mcp.sh init"
}

usage() {
    cat >&2 <<USAGE
Usage: scripts/demo-fleet.sh <command>

  build              Build the relay-demo images and pull the image-only services'
                      images, the OAuth overlay's included (the only subcommand that
                      builds or pulls)
  reset [--oauth]    Wipe and recreate the relay-demo fleet, verify it, mint fresh credentials;
                      --oauth adds the DEV-ONLY identity provider and turns on OAuth sign-in
  fault [service...] Kill the dev-fleet demo service on the given web Nodes
                      (default: ${DEFAULT_FAULT_TARGETS[*]})
  down               Stop the relay-demo fleet (no -v)
  up [--oauth]       Bring the relay-demo fleet back up (no -v, no build); the mint
                      one-shots still re-run, so follow with 'creds' to refresh .dev-fleet/;
                      --oauth must match how it was last brought up
  creds              Copy the CURRENT credentials to .dev-fleet/ — mints nothing itself
                      (scripts/dev-fleet-mcp.sh init); run after 'reset' or 'up'

Refuses to run against anything but the '${DEMO_PROJECT}' compose project on a
local Docker engine. See docs/operations/demo-fleet.md, "The fault, and resetting between takes".
USAGE
    exit 2
}

# --- Dispatch ------------------------------------------------------------
# demo_guard runs before anything else, including a missing-argument usage
# exit — no subcommand, real or mistyped, ever reaches a docker call first.
demo_guard

[ $# -ge 1 ] || usage

case "$1" in
    build) cmd_build ;;
    reset)
        shift
        cmd_reset "$@"
        ;;
    fault)
        shift
        cmd_fault "$@"
        ;;
    down) cmd_down ;;
    up)
        shift
        cmd_up "$@"
        ;;
    creds) cmd_creds ;;
    *) usage ;;
esac
