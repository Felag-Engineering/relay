#!/usr/bin/env bash
# Proves scripts/demo-fleet.sh's guard refuses BEFORE any docker call unless the
# target is the relay-demo compose project on a local Docker engine (#622), and
# that a passing guard does not itself imply the destructive calls run.
#
# Hermetic: docker is a STUB written under a throwaway WORKDIR, so nothing here
# touches a real Docker engine. Modelled on scripts/security-surface-test.sh's
# harness (mktemp WORKDIR, guarded EXIT trap, PASS/FAIL, exit 1 on any failure).
#
# NOT `set -e`: every case must run and be reported, not stop at the first
# failure.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
WORKDIR="$(mktemp -d)" || { echo "FAIL: mktemp -d failed" >&2; exit 1; }
trap 'case "${WORKDIR:-}" in /*) rm -rf "$WORKDIR" ;; esac' EXIT
case "$WORKDIR" in
    /*) ;;
    *)
        echo "FAIL: mktemp returned a non-absolute path: '$WORKDIR'" >&2
        exit 1
        ;;
esac

SCRIPT="$REPO_ROOT/scripts/demo-fleet.sh"
STUB_BIN="$WORKDIR/bin"
DOCKER_LOG="$WORKDIR/docker.log"
mkdir -p "$STUB_BIN"

# --- The stub. ONE docker replacement for every case below (#622 review
# non-blocking: the four near-identical stub bodies this file used to carry
# are now this single one), entirely driven by env vars set per `run`
# invocation rather than rewritten mid-file. Logs every invocation, then
# answers exactly the docker calls demo-fleet.sh's guard, image precheck,
# port check, and volume-scope check can make:
#   `docker context inspect --format ...`      -> $STUB_ENDPOINT (default a
#     local unix socket), exit 0.
#   `docker ps ... working_dir ...`            -> $STUB_FOREIGN_WORKDIR if
#     set, else nothing; exit $STUB_PS_EXIT (default 0).
#   `docker ps --filter publish=7654|9443 ...` -> $STUB_PORT_OWNER if set,
#     else nothing; exit $STUB_PS_EXIT. This is the exact bare-port form the
#     script passes — any OTHER `publish=` value (in particular one carrying
#     a bind address) is rejected the way real Docker rejects
#     `publish=127.0.0.1:PORT` (#622 review finding B2).
#   `docker ps --filter publish=8180 ...`      -> $STUB_PORT_8180_OWNER if
#     set, else nothing; exit $STUB_PS_EXIT. The OAuth overlay's IdP port
#     (#351), checked only by `reset --oauth` / `up --oauth`.
#   `docker ps ... com.docker.compose.service ...` -> $STUB_SERVICES if set
#     (newline-separated service names of the project's existing
#     containers), else nothing; exit $STUB_PS_EXIT. How `up` tells which
#     way the running fleet was brought up (#351).
#   `docker compose ... config --images`       -> exit
#     $STUB_COMPOSE_IMAGES_RC (default 1, i.e. fails); on 0, prints
#     $STUB_COMPOSE_IMAGES_OUT (default empty).
#   `docker compose ... config --format json`  -> exit
#     $STUB_COMPOSE_CONFIG_JSON_RC (default 1); on 0, prints
#     $STUB_COMPOSE_CONFIG_JSON_OUT (default empty — an empty stdin is not
#     valid JSON, so a case that reaches this without setting the OUT is
#     expected to fail parsing, same as failing the call outright).
#   `docker image inspect ...`                 -> exit
#     $STUB_IMAGE_INSPECT_RC (default 1).
#   `docker compose ... <subcommand>` for any other subcommand (`build`,
#     `pull`, `down`, `up`, `exec`, ...) -> exit 0 if that subcommand is
#     listed in $STUB_COMPOSE_OK (space-separated, default empty), else 1.
#   anything else -> exit 1.
# Every `docker compose` call also logs a second line,
# `compose-env DEV_FLEET_APPROVAL_GATE_CONFIG=<value or <unset>>`, so a case
# can assert which approval gate the compose file would have been handed.
# Nothing here reaches a real Docker engine.
cat >"$STUB_BIN/docker" <<'STUB'
#!/usr/bin/env bash
set -u
printf '%s\n' "$*" >>"$DOCKER_LOG"

if [ "${1-}" = "context" ] && [ "${2-}" = "inspect" ]; then
    echo "${STUB_ENDPOINT:-unix:///var/run/docker.sock}"
    exit 0
fi

if [ "${1-}" = "ps" ]; then
    for a in "$@"; do
        case "$a" in
            *working_dir*)
                [ -n "${STUB_FOREIGN_WORKDIR:-}" ] && echo "$STUB_FOREIGN_WORKDIR"
                exit "${STUB_PS_EXIT:-0}"
                ;;
            publish=7654 | publish=9443)
                [ -n "${STUB_PORT_OWNER:-}" ] && echo "$STUB_PORT_OWNER"
                exit "${STUB_PS_EXIT:-0}"
                ;;
            publish=8180)
                [ -n "${STUB_PORT_8180_OWNER:-}" ] && echo "$STUB_PORT_8180_OWNER"
                exit "${STUB_PS_EXIT:-0}"
                ;;
            *com.docker.compose.service*)
                [ -n "${STUB_SERVICES:-}" ] && printf '%s\n' "$STUB_SERVICES"
                exit "${STUB_PS_EXIT:-0}"
                ;;
            publish=*)
                # Real Docker rejects a publish filter that carries a bind
                # address ("filter for 'publish' should not contain ':'").
                # Matching only the bare port above, and failing everything
                # else here, catches a regression to `publish=127.0.0.1:PORT`
                # the way real Docker would (#622 review finding B2).
                echo "Error response from daemon: filter for 'publish' should not contain ':': ${a#publish=}" >&2
                exit 1
                ;;
        esac
    done
    exit "${STUB_PS_EXIT:-0}"
fi

if [ "${1-}" = "compose" ]; then
    printf 'compose-env DEV_FLEET_APPROVAL_GATE_CONFIG=%s\n' \
        "${DEV_FLEET_APPROVAL_GATE_CONFIG-<unset>}" >>"$DOCKER_LOG"
    has_images=0
    has_format_json=0
    sub=""
    for a in "$@"; do
        case "$a" in
            --images) has_images=1 ;;
            json) has_format_json=1 ;;
            build | pull | down | up | exec | ps | config)
                [ -z "$sub" ] && sub="$a"
                ;;
        esac
    done
    if [ "$has_images" -eq 1 ]; then
        rc="${STUB_COMPOSE_IMAGES_RC:-1}"
        if [ "$rc" -eq 0 ] && [ -n "${STUB_COMPOSE_IMAGES_OUT:-}" ]; then
            printf '%s\n' "$STUB_COMPOSE_IMAGES_OUT"
        fi
        exit "$rc"
    fi
    if [ "$has_format_json" -eq 1 ]; then
        rc="${STUB_COMPOSE_CONFIG_JSON_RC:-1}"
        if [ "$rc" -eq 0 ]; then
            printf '%s' "${STUB_COMPOSE_CONFIG_JSON_OUT:-}"
        fi
        exit "$rc"
    fi
    case " ${STUB_COMPOSE_OK:-} " in
        *" ${sub} "*) [ -n "$sub" ] && exit 0 ;;
    esac
    exit 1
fi

if [ "${1-}" = "image" ] && [ "${2-}" = "inspect" ]; then
    exit "${STUB_IMAGE_INSPECT_RC:-1}"
fi

exit 1
STUB
chmod +x "$STUB_BIN/docker"

fail=0
OUT=""
RC=0

# run <env...> -- <args...>: runs demo-fleet.sh with a fresh, empty docker.log,
# the stub PATH prepended, and every variable the guard, the stub, or
# demo-fleet.sh itself reads from the environment unset first, so the
# developer's own shell (or a leftover value from an earlier case) cannot
# leak into a case; the caller then re-adds exactly what that case needs.
run() {
    local envs=()
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do
        envs+=("$1")
        shift
    done
    shift # drop the "--" separator
    : >"$DOCKER_LOG"
    OUT="$(env \
        -u COMPOSE_PROJECT_NAME -u DOCKER_HOST -u DEMO_WAIT_SECONDS -u DOCKER_CONTEXT \
        -u STUB_ENDPOINT -u STUB_FOREIGN_WORKDIR -u STUB_PORT_OWNER -u STUB_PS_EXIT \
        -u STUB_PORT_8180_OWNER -u STUB_SERVICES \
        -u STUB_COMPOSE_IMAGES_RC -u STUB_COMPOSE_IMAGES_OUT \
        -u STUB_COMPOSE_CONFIG_JSON_RC -u STUB_COMPOSE_CONFIG_JSON_OUT \
        -u STUB_IMAGE_INSPECT_RC -u STUB_COMPOSE_OK \
        -u DEV_FLEET_APPROVAL_GATE_CONFIG \
        "${envs[@]}" \
        PATH="$STUB_BIN:$PATH" DOCKER_LOG="$DOCKER_LOG" \
        bash "$SCRIPT" "$@" 2>&1)"
    RC=$?
}

# check <name> <want_rc> <stderr_mode>
#   stderr_mode: refuses          -> OUT contains "refusing" (case-sensitive)
#                empty_log        -> docker.log is EMPTY (no docker call at all)
#                contains:<text>  -> OUT contains <text>
#                log_contains:<t> -> docker.log contains a line containing <t>
#                log_not_contains:<t> -> docker.log contains NO line with <t>
check() {
    local name=$1 want_rc=$2
    shift 2
    local ok=1 mode

    if [ "$RC" -ne "$want_rc" ]; then
        echo "FAIL: $name: rc=$RC want=$want_rc (out=[$OUT])" >&2
        ok=0
    fi

    for mode in "$@"; do
        case "$mode" in
            refuses)
                case "$OUT" in
                    *refusing*) ;;
                    *)
                        echo "FAIL: $name: stdout/stderr does not contain 'refusing': [$OUT]" >&2
                        ok=0
                        ;;
                esac
                ;;
            empty_log)
                if [ -s "$DOCKER_LOG" ]; then
                    echo "FAIL: $name: docker.log not empty: [$(cat "$DOCKER_LOG")]" >&2
                    ok=0
                fi
                ;;
            contains:*)
                local want=${mode#contains:}
                case "$OUT" in
                    *"$want"*) ;;
                    *)
                        echo "FAIL: $name: out=[$OUT] does not contain [$want]" >&2
                        ok=0
                        ;;
                esac
                ;;
            log_contains:*)
                local want=${mode#log_contains:}
                if ! grep -qF -- "$want" "$DOCKER_LOG" 2>/dev/null; then
                    echo "FAIL: $name: docker.log does not contain [$want]: $(cat "$DOCKER_LOG" 2>/dev/null)" >&2
                    ok=0
                fi
                ;;
            log_not_contains:*)
                local want=${mode#log_not_contains:}
                if grep -qF -- "$want" "$DOCKER_LOG" 2>/dev/null; then
                    echo "FAIL: $name: docker.log unexpectedly contains [$want]: $(cat "$DOCKER_LOG" 2>/dev/null)" >&2
                    ok=0
                fi
                ;;
            *)
                echo "FAIL: $name: unknown check mode '$mode'" >&2
                ok=0
                ;;
        esac
    done

    [ "$ok" -eq 1 ] || fail=$((fail + 1))
}

# --- Refusal cases: exit 2, "refusing" in the output, and an EMPTY
# docker.log — no docker call at all, not merely no destructive one. ---

run COMPOSE_PROJECT_NAME=gleipnir-relay -- reset
check "R1-reset-directory-named-project" 2 refuses empty_log

run COMPOSE_PROJECT_NAME=relay-demo2 -- reset
check "R2-reset-similar-project-name" 2 refuses empty_log

run COMPOSE_PROJECT_NAME="relay-demo " -- reset
check "R3-reset-trailing-space" 2 refuses empty_log

run COMPOSE_PROJECT_NAME=RELAY-DEMO -- reset
check "R4-reset-wrong-case" 2 refuses empty_log

run COMPOSE_PROJECT_NAME= -- reset
check "R5-reset-set-but-empty-not-defaulted" 2 refuses empty_log

run COMPOSE_PROJECT_NAME=gleipnir-relay -- fault
check "R6-fault-wrong-project" 2 refuses empty_log

run COMPOSE_PROJECT_NAME=gleipnir-relay -- build
check "R7-build-wrong-project" 2 refuses empty_log

run COMPOSE_PROJECT_NAME=gleipnir-relay -- down
check "R8-down-wrong-project" 2 refuses empty_log

run COMPOSE_PROJECT_NAME=gleipnir-relay -- up
check "R9-up-wrong-project" 2 refuses empty_log

run DOCKER_HOST=tcp://prod.example.invalid:2376 -- reset
check "R10-reset-remote-docker-host" 2 refuses empty_log

# R11: project unset (defaults to relay-demo), but the current docker CONTEXT
# resolves to a remote engine. The guard's context-inspect call is the ONE
# docker call allowed before it passes, so the log is non-empty here and
# contains ONLY that call.
run STUB_ENDPOINT=tcp://prod.example.invalid:2376 -- reset
check "R11-reset-remote-docker-context" 2 refuses "log_contains:context inspect"
if [ -s "$DOCKER_LOG" ] && grep -qvF 'context inspect' "$DOCKER_LOG"; then
    echo "FAIL: R11-reset-remote-docker-context: docker.log has a line besides context inspect: $(cat "$DOCKER_LOG")" >&2
    fail=$((fail + 1))
fi

# --- Positive controls: the guard ADMITS the demo project, and a failed
# image precheck stops the script before any destructive call. ---

# P1: project unset, local stub endpoint, no foreign relay-demo worktree, no
# foreign port owner. The guard passes; `dc config --images` (unhandled here,
# so it fails per the stub's default) then fails, so reset dies at the image
# precheck — before `down` or `up`.
run -- reset
check "P1-guard-admits-unset-project" 1 \
    "log_contains:compose -p relay-demo -f $REPO_ROOT/docker-compose.yml --profile demo config" \
    "log_not_contains: down" "log_not_contains: up"

# P2: same, with COMPOSE_PROJECT_NAME explicitly set to relay-demo.
run COMPOSE_PROJECT_NAME=relay-demo -- reset
check "P2-guard-admits-explicit-project" 1 \
    "log_contains:compose -p relay-demo -f $REPO_ROOT/docker-compose.yml --profile demo config" \
    "log_not_contains: down" "log_not_contains: up"

# P3 (review finding 2): `config --images` SUCCEEDS but prints nothing. The
# empty-list guard must still refuse before `down`/`up` — a `for` loop over an
# empty command substitution would otherwise silently pass.
run STUB_COMPOSE_IMAGES_RC=0 -- reset
check "P3-empty-image-list-still-refuses" 1 \
    "contains:no images" "log_not_contains: down" "log_not_contains: up"

# P4 (review finding 8): proves the PORT check specifically — the image
# precheck is made to PASS (a plausible image name, and `image inspect`
# succeeding), so reset reaches `check_ports_not_foreign`, where a foreign
# project already owns host port 7654. Must die before `down`. The two
# `log_contains`/`log_not_contains` assertions on `publish=` also re-prove
# B2: the script queries the bare port, never a bind-address-qualified value.
run STUB_COMPOSE_IMAGES_RC=0 STUB_COMPOSE_IMAGES_OUT=relay-demo-relay \
    STUB_IMAGE_INSPECT_RC=0 STUB_PORT_OWNER=gleipnir-relay \
    -- reset
check "P4-foreign-port-owner-refuses-before-down" 1 \
    "contains:gleipnir-relay" "log_not_contains: down" "log_not_contains: up" \
    "log_contains:publish=7654" "log_not_contains:publish=127.0.0.1"

# P5 (review finding 7): a relay-demo container already exists, owned by a
# DIFFERENT checkout (a different working_dir). Must refuse (exit 2, like the
# other guard refusals) before any destructive call — including before the
# image precheck.
run STUB_FOREIGN_WORKDIR=/some/other/checkout -- reset
# empty_log is deliberately NOT asserted here: the cross-worktree `docker ps`
# call itself is read-only and expected to appear in the log.
check "P5-foreign-worktree-refuses" 2 refuses \
    "log_contains:working_dir" "log_not_contains: down" "log_not_contains: up"

# --- Security review (Stage 6.5) findings ---

# SEC1 (security review S1): the image precheck and the port check both PASS (a plausible image
# name, `image inspect` succeeding, no foreign port owner), so reset reaches
# `check_volume_names_scoped` — where `dc config --format json` reports a
# volume that does NOT resolve to a relay-demo_-prefixed name (as a top-level
# `name:`/`external:` override on docker-compose.yml's volumes: could cause).
# Must refuse before `down -v` ever runs.
run STUB_COMPOSE_IMAGES_RC=0 STUB_COMPOSE_IMAGES_OUT=relay-demo-relay \
    STUB_IMAGE_INSPECT_RC=0 \
    STUB_COMPOSE_CONFIG_JSON_RC=0 \
    STUB_COMPOSE_CONFIG_JSON_OUT='{"volumes":{"relay-data":{"name":"gleipnir-relay_relay-data"}}}' \
    -- reset
check "SEC1-reset-foreign-volume-name-refuses-before-down" 1 \
    "contains:relay-demo_" "log_not_contains: down" "log_not_contains: up"

# SEC2 (security review S2): DEMO_FAULT_NODES (how `make demo-fault DEMO_FAULT_NODES=...` reaches
# the script — an environment variable, never text spliced into a Make
# recipe) carrying a shell metacharacter is refused by the web-roster
# validation before any `exec` into a container. `compose_services` is made
# to succeed (a two-service roster) so the run reaches that validation
# instead of failing earlier for an unrelated reason.
run DEMO_FAULT_NODES='daemon-4; rm -rf /should-not-run' \
    STUB_COMPOSE_CONFIG_JSON_RC=0 \
    STUB_COMPOSE_CONFIG_JSON_OUT='{"services":{"daemon-4":{"environment":{"RELAY_NODE_LABELS":"role=web"}},"daemon-6":{"environment":{"RELAY_NODE_LABELS":"role=web"}}}}' \
    -- fault
check "SEC2-fault-metacharacter-in-node-list-refused-before-exec" 2 refuses "log_not_contains: exec"

# SEC3 (security review S3): DEMO_WAIT_SECONDS with a leading zero is ambiguous once it reaches
# arithmetic ($((...))) in wait_healthy — refused up front, before any
# Docker call, exactly like the non-numeric case already covered.
run DEMO_WAIT_SECONDS=08 -- reset
check "SEC3-reset-wait-seconds-leading-zero-refused" 2 refuses empty_log

# --- Build pulls the image-only services; reset and up never pull ---

COMPOSE_PREFIX="compose -p relay-demo -f $REPO_ROOT/docker-compose.yml --profile demo"
COMPOSE_OAUTH_PREFIX="compose -p relay-demo -f $REPO_ROOT/docker-compose.yml -f $REPO_ROOT/docker-compose.oauth.yml --profile demo"

# B1: `build` builds, THEN pulls every service that has no build section
# (`--ignore-buildable`), fetching only what is missing. Without the pull a
# fresh engine builds cleanly and reset's image precheck then fails on the
# curl one-shots' image. The build names docker-compose.yml alone; the pull
# names the OAuth overlay too (#351), so one build also fetches the identity
# provider's image and an OAuth fleet is startable on a fresh engine.
run STUB_COMPOSE_OK="build pull" -- build
check "B1-build-then-pulls-image-only-services" 0 \
    "log_contains:$COMPOSE_PREFIX build" \
    "log_contains:$COMPOSE_OAUTH_PREFIX pull --ignore-buildable --policy missing" \
    "log_not_contains:$COMPOSE_OAUTH_PREFIX build"
build_line="$(grep -nF -- "$COMPOSE_PREFIX build" "$DOCKER_LOG" | head -1 | cut -d: -f1)"
pull_line="$(grep -nF -- "$COMPOSE_OAUTH_PREFIX pull" "$DOCKER_LOG" | head -1 | cut -d: -f1)"
if [ -z "$build_line" ] || [ -z "$pull_line" ] || [ "$build_line" -ge "$pull_line" ]; then
    echo "FAIL: B1-build-then-pulls-image-only-services: build (line ${build_line:-none}) must come before pull (line ${pull_line:-none})" >&2
    fail=$((fail + 1))
fi

# B2: a failed build stops there; nothing is pulled.
run STUB_COMPOSE_OK="pull" -- build
check "B2-failed-build-does-not-pull" 1 \
    "contains:docker compose build failed" "log_not_contains:--profile demo pull"

# B3: a failed pull fails the build step, loudly, rather than leaving reset to
# discover the missing image later.
run STUB_COMPOSE_OK="build" -- build
check "B3-failed-pull-fails-build" 1 \
    "contains:pull of the image-only services failed"

# B4: reset never pulls. The precheck, port check and volume check pass and
# `down` succeeds, so reset reaches `up`, which must carry `--pull never`; the
# stubbed `up` then fails, stopping the run there.
run STUB_COMPOSE_IMAGES_RC=0 STUB_COMPOSE_IMAGES_OUT=relay-demo-relay \
    STUB_IMAGE_INSPECT_RC=0 \
    STUB_COMPOSE_CONFIG_JSON_RC=0 STUB_COMPOSE_CONFIG_JSON_OUT='{"volumes":{}}' \
    STUB_COMPOSE_OK="down" \
    -- reset
check "B4-reset-never-pulls" 1 \
    "log_contains:$COMPOSE_PREFIX up -d --no-build --pull never" \
    "log_not_contains:--profile demo pull" "log_not_contains:--profile demo build"

# B5: up never pulls either.
run -- up
check "B5-up-never-pulls" 1 \
    "log_contains:$COMPOSE_PREFIX up -d --no-build --pull never" \
    "log_not_contains:--profile demo pull" "log_not_contains:--profile demo build"

# B6: `up --oauth` and `reset --oauth` never pull either.
run -- up --oauth
check "B6-oauth-up-never-pulls" 1 \
    "log_contains:$COMPOSE_OAUTH_PREFIX up -d --no-build --pull never" \
    "log_not_contains:--profile demo pull" "log_not_contains:--profile demo build"

# --- The demo fleet's approval gate ---

# G1: every compose call the script makes hands docker-compose.yml the demo
# fleet's in-band gate — even when the caller's shell exported the default
# fleet's gate — so the demo Relay can never start on the wrong one. B4 above
# reaches down and up; this re-runs it with the conflicting value exported.
run DEV_FLEET_APPROVAL_GATE_CONFIG=/etc/relay/approval-gates.json \
    STUB_COMPOSE_IMAGES_RC=0 STUB_COMPOSE_IMAGES_OUT=relay-demo-relay \
    STUB_IMAGE_INSPECT_RC=0 \
    STUB_COMPOSE_CONFIG_JSON_RC=0 STUB_COMPOSE_CONFIG_JSON_OUT='{"volumes":{}}' \
    STUB_COMPOSE_OK="down" \
    -- reset
check "G1-reset-pins-the-demo-gate" 1 \
    "log_contains:compose-env DEV_FLEET_APPROVAL_GATE_CONFIG=/etc/relay/approval-gates.demo.json" \
    "log_not_contains:DEV_FLEET_APPROVAL_GATE_CONFIG=/etc/relay/approval-gates.json" \
    "log_not_contains:DEV_FLEET_APPROVAL_GATE_CONFIG=<unset>"

# G2: the path the script pins is one the relay image actually bakes, from a
# fixture that exists, and docker-compose.yml actually reads the variable
# (defaulting to the default fleet's gate). A mismatch anywhere in that chain
# would crash-loop the demo Relay (the gate loader is fail-closed) or quietly
# run it on the default gate.
demo_gate_path="$(sed -n 's/^readonly DEMO_APPROVAL_GATE_CONFIG="\(.*\)"$/\1/p' "$SCRIPT")"
if [ "$demo_gate_path" != "/etc/relay/approval-gates.demo.json" ]; then
    echo "FAIL: G2: DEMO_APPROVAL_GATE_CONFIG is not declared readonly as /etc/relay/approval-gates.demo.json (got '${demo_gate_path}')" >&2
    fail=$((fail + 1))
fi
if [ ! -s "$REPO_ROOT/docker/fixtures/approval-gates.demo.json" ]; then
    echo "FAIL: G2: docker/fixtures/approval-gates.demo.json is missing or empty" >&2
    fail=$((fail + 1))
fi
if ! grep -qxF "COPY --chmod=0644 docker/fixtures/approval-gates.demo.json ${demo_gate_path}" \
    "$REPO_ROOT/docker/relay.Dockerfile"; then
    echo "FAIL: G2: docker/relay.Dockerfile does not bake docker/fixtures/approval-gates.demo.json at '${demo_gate_path}' with --chmod=0644" >&2
    fail=$((fail + 1))
fi
if ! grep -qF 'RELAY_APPROVAL_GATE_CONFIG: "${DEV_FLEET_APPROVAL_GATE_CONFIG:-/etc/relay/approval-gates.json}"' \
    "$REPO_ROOT/docker-compose.yml"; then
    echo "FAIL: G2: docker-compose.yml does not select the gate with DEV_FLEET_APPROVAL_GATE_CONFIG, defaulting to the default fleet's gate" >&2
    fail=$((fail + 1))
fi
# --- The OAuth overlay (#351): opt-in by a flag, never by the environment ---

# O1: reset and up take nothing but --oauth. Anything else is refused before
# any compose call (the guard's two read-only calls have already run).
run -- reset --0auth
check "O1-reset-unknown-flag-refused" 2 refuses "log_not_contains:compose -p"
run -- up --oauth extra
check "O1-up-extra-argument-refused" 2 refuses "log_not_contains:compose -p"

# O2: `reset --oauth` layers the overlay onto the image precheck — so a
# missing IdP image stops reset before `down -v`, like any other image.
run -- reset --oauth
check "O2-reset-oauth-prechecks-with-the-overlay" 1 \
    "log_contains:compose -p relay-demo -f $REPO_ROOT/docker-compose.yml -f $REPO_ROOT/docker-compose.oauth.yml --profile demo config --images" \
    "log_not_contains: down" "log_not_contains: up"

# O3: plain `reset` never names the overlay before its wipe — the default
# fleet is exactly docker-compose.yml.
run -- reset
check "O3-plain-reset-precheck-names-no-overlay" 1 "log_not_contains:docker-compose.oauth.yml"

# O4: `reset --oauth` also checks the IdP's host port, and refuses before
# `down` when another project already publishes it.
run STUB_COMPOSE_IMAGES_RC=0 STUB_COMPOSE_IMAGES_OUT=relay-demo-relay \
    STUB_IMAGE_INSPECT_RC=0 STUB_PORT_8180_OWNER=some-other-project \
    -- reset --oauth
check "O4-reset-oauth-foreign-idp-port-refuses-before-down" 1 \
    "contains:host port 8180" "log_contains:publish=8180" \
    "log_not_contains: down" "log_not_contains: up"

# O5: plain `reset` does not check the IdP port at all.
run STUB_COMPOSE_IMAGES_RC=0 STUB_COMPOSE_IMAGES_OUT=relay-demo-relay \
    STUB_IMAGE_INSPECT_RC=0 STUB_PORT_8180_OWNER=some-other-project \
    -- reset
check "O5-plain-reset-ignores-idp-port" 1 "log_not_contains:publish=8180"

# O7: plain `reset` WIPES with the overlay named — so a previous --oauth run's
# IdP and its volume go too — but BRINGS UP with docker-compose.yml alone.
# `down` is made to succeed so reset reaches `up`; `up` fails, stopping it.
run STUB_COMPOSE_IMAGES_RC=0 STUB_COMPOSE_IMAGES_OUT=relay-demo-relay \
    STUB_IMAGE_INSPECT_RC=0 \
    STUB_COMPOSE_CONFIG_JSON_RC=0 STUB_COMPOSE_CONFIG_JSON_OUT='{"volumes":{"relay-data":{}}}' \
    STUB_COMPOSE_OK="down" \
    -- reset
check "O7-plain-reset-wipes-with-overlay-brings-up-without" 1 "contains:docker compose up failed"
o7_down="$(grep -F ' down -v ' "$DOCKER_LOG")"
o7_up="$(grep -F ' up -d ' "$DOCKER_LOG")"
case "$o7_down" in
    *"-f $REPO_ROOT/docker-compose.oauth.yml"*) ;;
    *)
        echo "FAIL: O7: plain reset's down -v does not name the overlay: [$o7_down]" >&2
        fail=$((fail + 1))
        ;;
esac
case "$o7_up" in
    '')
        echo "FAIL: O7: plain reset never reached up: $(cat "$DOCKER_LOG")" >&2
        fail=$((fail + 1))
        ;;
    *docker-compose.oauth.yml*)
        echo "FAIL: O7: plain reset's up names the overlay: [$o7_up]" >&2
        fail=$((fail + 1))
        ;;
esac

# O8 (static): the human the IdP signs in and the Account the one-shot creates
# are one name — the realm fixture's user, the overlay's OAUTH_ACCOUNT_NAME, and
# the sign-in hint the script prints — and it is `demo-user`. A rename that
# misses one leaves a sign-in the Relay refuses with no reason given.
oauth_account="$(sed -n 's/^ *OAUTH_ACCOUNT_NAME: "\(.*\)"$/\1/p' "$REPO_ROOT/docker-compose.oauth.yml")"
if [ "$oauth_account" != "demo-user" ]; then
    echo "FAIL: O8: docker-compose.oauth.yml's OAUTH_ACCOUNT_NAME is '${oauth_account}', not demo-user" >&2
    fail=$((fail + 1))
fi
if ! python3 -c '
import json, sys
users = [u["username"] for u in json.load(open(sys.argv[1]))["users"]]
sys.exit(0 if sys.argv[2] in users else 1)' \
    "$REPO_ROOT/docker/fixtures/keycloak/relay-demo-realm.json" "$oauth_account"; then
    echo "FAIL: O8: the realm fixture has no user named '${oauth_account}'" >&2
    fail=$((fail + 1))
fi
if ! grep -qF "sign in as ${oauth_account} / dev-only-${oauth_account} (DEV-ONLY)" "$SCRIPT"; then
    echo "FAIL: O8: scripts/demo-fleet.sh's sign-in hint does not name ${oauth_account}" >&2
    fail=$((fail + 1))
fi

# O6: `up` refuses to switch modes over a fleet whose containers still exist
# — either way — before any compose call.
run STUB_SERVICES=$'relay-netns\nidp\nrelay' -- up
check "O6-plain-up-over-oauth-fleet-refused" 2 refuses "log_not_contains:compose -p"
run STUB_SERVICES=$'relay\ndaemon-1' -- up --oauth
check "O6-oauth-up-over-plain-fleet-refused" 2 refuses "log_not_contains:compose -p"

# --- Static structure checks ---

# S1: exactly one line in the whole file is a real `docker compose`
# INVOCATION (the word `docker` starting the line, ignoring leading
# whitespace) — the dc() wrapper — and it pins the project with -p. This
# catches a later edit that adds a second, unguarded call site. It does NOT
# catch a `docker compose` invocation embedded after other shell syntax on
# the same line (e.g. inside a `$(...)` following other text); dc() being the
# only construct that opens a line with `docker compose` is the property this
# enforces, not "the substring appears once".
invocation_lines="$(grep -nE '^[[:space:]]*docker[[:space:]]+compose\b' "$SCRIPT")"
invocation_count="$(printf '%s\n' "$invocation_lines" | grep -c . || true)"
if [ "$invocation_count" -ne 1 ]; then
    echo "FAIL: S1: expected exactly 1 'docker compose' invocation line, found $invocation_count:" >&2
    printf '%s\n' "$invocation_lines" >&2
    fail=$((fail + 1))
else
    case "$invocation_lines" in
        *'-p "$DEMO_PROJECT"'*) ;;
        *)
            echo "FAIL: S1: the sole 'docker compose' invocation line does not pin -p \"\$DEMO_PROJECT\": $invocation_lines" >&2
            fail=$((fail + 1))
            ;;
    esac
fi

# S2: DEMO_PROJECT=relay-demo is declared readonly, with no default-expansion
# (neither ":-" nor "-").
if ! grep -qE '^readonly DEMO_PROJECT="relay-demo"$' "$SCRIPT"; then
    echo "FAIL: S2: DEMO_PROJECT is not declared 'readonly DEMO_PROJECT=\"relay-demo\"' verbatim" >&2
    fail=$((fail + 1))
fi
if grep -qE 'DEMO_PROJECT:?-' "$SCRIPT"; then
    echo "FAIL: S2: DEMO_PROJECT has a default-expansion form (':-' or '-') somewhere in the file" >&2
    fail=$((fail + 1))
fi

# S3: the first call to demo_guard comes before the subcommand `case`
# dispatch — a line-number compare, not a string search, so it fails if the
# guard call is ever moved after the dispatch.
guard_line="$(grep -n '^demo_guard$' "$SCRIPT" | head -1 | cut -d: -f1)"
case_line="$(grep -n '^case "\$1" in$' "$SCRIPT" | head -1 | cut -d: -f1)"
if [ -z "$guard_line" ] || [ -z "$case_line" ]; then
    echo "FAIL: S3: could not find both 'demo_guard' (bare call) and 'case \"\$1\" in' in the file" >&2
    fail=$((fail + 1))
elif [ "$guard_line" -ge "$case_line" ]; then
    echo "FAIL: S3: demo_guard (line $guard_line) does not come before the case dispatch (line $case_line)" >&2
    fail=$((fail + 1))
fi

# S4 (security review S5): S1 above only catches a SECOND `docker compose`
# site. Broaden it to every `docker` invocation in the file: every
# non-comment line invoking `docker` with a subcommand must use one of the
# four permitted forms — `context`, `ps`, `image`, or `compose` (dc(), which
# S1 already checks is the only such line). This would catch, for example,
# an unguarded `docker exec`/`docker rm` added anywhere else in the file. A
# comment line (the first non-blank character after the leading whitespace
# is `#`) is excluded — this file's own header prose mentions `docker`
# subcommands by name without invoking any of them.
docker_invocation_lines="$(grep -nE 'docker[[:space:]]+[a-z]+' "$SCRIPT" | grep -vE '^[0-9]+:[[:space:]]*#')"
unpermitted_docker_lines="$(printf '%s\n' "$docker_invocation_lines" | grep -vE 'docker (context|ps|image|compose)\b')"
if [ -n "$unpermitted_docker_lines" ]; then
    echo "FAIL: S4: line(s) invoke 'docker' with a subcommand other than context/ps/image/compose:" >&2
    printf '%s\n' "$unpermitted_docker_lines" >&2
    fail=$((fail + 1))
fi

if [ "$fail" -ne 0 ]; then
    echo "FAIL: $fail case(s) failed" >&2
    exit 1
fi

echo "PASS: scripts/demo-fleet.sh refuses unless the target is the relay-demo project on a local engine — with no more than two read-only Docker calls (the context endpoint, the cross-worktree ps) before that refusal — admits it when it is, stops before down/up on a failed image precheck / foreign port / foreign worktree / foreign volume name, refuses a DEMO_FAULT_NODES value carrying a shell metacharacter before any exec, and routes every docker compose call through one guarded wrapper (#622); build pulls the image-only services while reset and up never pull, and every compose call is handed the demo fleet's baked-in in-band gate; and it layers the OAuth overlay on only for --oauth, refusing a mode switch over a running fleet (#351)."
