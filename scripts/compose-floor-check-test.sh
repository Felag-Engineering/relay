#!/usr/bin/env bash
# Proves scripts/compose-floor-check.sh accepts the good shape and refuses each violation of
# RC-27 and the RC-36 port rule. Hermetic: bash, jq, awk and coreutils, with a stub `docker` on
# PATH that serves canned `docker compose config` JSON. No Docker, no network, no writes outside
# its own `mktemp -d`.
#
# Every refusal case asserts the REASON as well as the exit status, so a fixture that breaks for
# an unrelated reason cannot pass as a proof.
#
# NOT `set -e`: every case must run and be reported, not stop at the first failure.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
WORK="$(mktemp -d)" || { echo "FAIL: mktemp -d failed" >&2; exit 1; }
trap 'case "${WORK:-}" in /*) rm -rf "$WORK" ;; esac' EXIT
case "$WORK" in
  /*) ;;
  *) echo "FAIL: mktemp returned a non-absolute path: '$WORK'" >&2; exit 1 ;;
esac

TREE="$WORK/tree"
BIN="$WORK/bin"
JSON="$WORK/json"
mkdir -p "$TREE/scripts" "$TREE/docker" "$TREE/relay/internal/relayconfig" "$BIN" "$JSON"
cp "$REPO_ROOT/scripts/compose-floor-check.sh" "$TREE/scripts/"
SCRIPT="$TREE/scripts/compose-floor-check.sh"

# The stub picks the stack from the -f arguments. A file named fail-<stack> makes it exit 1.
cat >"$BIN/docker" <<STUB
#!/usr/bin/env bash
[ "\$1" = compose ] || exit 2
shift
[ "\$1" = version ] && exit 0
case " \$* " in
  *docker-compose.oauth.yml*) stack=oauth ;;
  *docker-compose.demo.yml*) stack=demo ;;
  *) stack=deploy ;;
esac
[ -e "$JSON/fail-\$stack" ] && exit 1
cat "$JSON/\$stack.json"
STUB
chmod +x "$BIN/docker"

fail=0
n=0

reset() {
  cp "$REPO_ROOT/docker/relay.Dockerfile" "$TREE/docker/relay.Dockerfile"
  cp "$REPO_ROOT/relay/internal/relayconfig/retired.go" "$TREE/relay/internal/relayconfig/retired.go"
  rm -f "$JSON"/fail-*
  local relay oneshot daemon netns
  relay='{build:{context:".",dockerfile:"docker/relay.Dockerfile"}, entrypoint:null, environment:null,
    user:"10001:10001", read_only:true, tmpfs:["/tmp"], cap_drop:["ALL"],
    security_opt:["no-new-privileges:true"],
    volumes:[{type:"volume",source:"relay-etc",target:"/etc/relay",read_only:true},
             {type:"volume",source:"relay-data",target:"/var/lib/relay"}],
    healthcheck:{test:["CMD","sh","-c","awk /x/ /etc/relay/relay.toml"]},
    ports:[{target:7654,published:"7654"},{target:9443,published:"9443"}]}'
  oneshot='{build:{context:".",dockerfile:"docker/relay.Dockerfile"}, entrypoint:["sh","/dev-fleet-init.sh"], user:"0:0",
    environment:{CONSOLE_ADMIN_PASSWORD:"x", RELAY_PUBLISH_ADDR:"127.0.0.1"}}'
  daemon='{build:{context:".",dockerfile:"docker/daemon.Dockerfile"}, environment:{RELAY_ADDR:"https://relay:7654"}}'
  netns='{image:"curlimages/curl", ports:[{target:7654,published:"7654"}]}'
  jq -n "{services:{relay:$relay}}" >"$JSON/deploy.json"
  jq -n "{services:{relay:$relay, init:$oneshot, \"daemon-1\":$daemon}}" >"$JSON/demo.json"
  jq -n "{services:{relay:$relay, init:$oneshot, \"daemon-1\":$daemon, \"relay-netns\":$netns}}" >"$JSON/oauth.json"
}

# mut <stack> <jq filter>: edit one canned stack.
mut() { jq -c "$2" "$JSON/$1.json" >"$JSON/$1.tmp" && mv "$JSON/$1.tmp" "$JSON/$1.json"; }
# mut_relay <jq filter on .services.relay>, applied to the demo stack.
mut_relay() { mut demo ".services.relay |= ($1)"; }

# run <name> <want-rc> <want-substring> [forbidden-substring]
run() {
  local name="$1" want_rc="$2" want="$3" forbidden="${4:-}" out rc
  n=$((n + 1))
  out="$(env PATH="$BIN:$PATH" bash "$SCRIPT" 2>&1)"; rc=$?
  if [ "$rc" -ne "$want_rc" ]; then
    echo "FAIL: $name: exit $rc, want $want_rc"; echo "$out" | sed 's/^/    /'; fail=$((fail + 1)); return
  fi
  if ! grep -qF -- "$want" <<<"$out"; then
    echo "FAIL: $name: output lacks '$want'"; echo "$out" | sed 's/^/    /'; fail=$((fail + 1)); return
  fi
  if [ -n "$forbidden" ] && grep -qF -- "$forbidden" <<<"$out"; then
    echo "FAIL: $name: output contains '$forbidden'"; fail=$((fail + 1)); return
  fi
  echo "PASS: $name"
}

refuse() { run "$1" 1 "$2" "${3:-}"; } # refuse <name> <reason> [forbidden]

reset
run "1 positive control: three stacks and the real Dockerfile" 0 "ok: Dockerfile"
out="$(env PATH="$BIN:$PATH" bash "$SCRIPT" 2>&1)"
for s in deploy demo oauth; do
  grep -qF "ok: $s:" <<<"$out" || { echo "FAIL: 1: no ok line for $s"; fail=$((fail + 1)); }
done

reset; mut_relay '.environment = {RELAY_HOSTNAME:"secret-host-value"}'
refuse "2 Relay environment sets RELAY_HOSTNAME" "RELAY_HOSTNAME" "secret-host-value"

reset; mut_relay '.environment = {FOO:"bar"}'
refuse "3 Relay environment sets a non-floor variable" "F1"

reset; mut demo '.services.init.environment.RELAY_CA_DIR = "/x"'
refuse "4 one-shot environment sets RELAY_CA_DIR" "F8: environment sets the floor name RELAY_CA_DIR"

reset; mut demo '.services["daemon-1"].environment.RELAY_ADDR = "https://elsewhere:7654"'
run "5 a daemon's RELAY_ADDR is exempt" 0 "ok: demo:"

reset; mut_relay '.volumes[0].read_only = false'
refuse "6 config mount not read_only" "F2"

reset; mut_relay '.volumes += [{type:"bind",source:"/s",target:"/etc/relay/approval-webhook.secret"}]'
refuse "7 extra secret mount not read_only" "F3: the mount at /etc/relay/approval-webhook.secret"

reset; mut_relay '.volumes |= map(select(.target != "/etc/relay"))'
refuse "8 no config mount" "F2: relay.toml is not mounted"

reset; mut_relay '.volumes |= map(if .target == "/var/lib/relay" then .type = "bind" else . end)'
refuse "9a state mount is a bind" "F4"
reset; mut_relay '.volumes += [{type:"volume",source:"b",target:"/var/lib/relay"}]'
refuse "9b state mount duplicated" "F4"
reset; mut_relay '.volumes |= map(select(.target != "/var/lib/relay"))'
refuse "9c state mount removed" "F4"
reset; mut_relay '.volumes |= map(if .target == "/var/lib/relay" then .read_only = true else . end)'
refuse "9d state volume read_only" "F4"

reset; mut_relay '.read_only = false'
refuse "10a root filesystem writable" "F5: the root filesystem"
reset; mut_relay '.cap_drop = ["NET_RAW"]'
refuse "10b cap_drop lacks ALL" "F5: cap_drop"
reset; mut_relay '.cap_add = ["NET_ADMIN"]'
refuse "10c cap_add set" "F5: cap_add"
reset; mut_relay '.privileged = true'
refuse "10d privileged" "F5: privileged"
reset; mut_relay '.security_opt = []'
refuse "10e no-new-privileges missing" "F5: security_opt"
reset; mut_relay '.user = "0:0"'
refuse "10f user 0:0" "F5: user"
reset; mut_relay 'del(.user)'
refuse "10g user absent" "F5: user"
reset; mut_relay '.tmpfs = ["/var"]'
refuse "10h tmpfs /var" "F5: tmpfs"

reset; mut_relay '.secrets = [{source:"s",target:"s"}]'
refuse "11 a secrets entry" "F6"

reset; mut_relay '.healthcheck.test = ["CMD","sh","-c","openssl s_client -servername relay"]'
refuse "12 healthcheck with a literal hostname" "F7"

reset; mut_relay '.ports = [{target:7654,published:"17654"}]'
refuse "13 node plane published on another port" "advertised_address"

reset; mut demo '.services.relay |= (del(.build) | .image = "ghcr.io/felag-engineering/relay@sha256:0000000000000000000000000000000000000000000000000000000000000000" | .environment = {RELAY_HOSTNAME:"x"})'
refuse "14 Relay named by published image is classified" "F1"

reset; mut demo '.services |= del(.relay)'
refuse "15 stack with no Relay service" "no Relay service"

reset; : >"$JSON/fail-demo"
refuse "16 docker compose config fails" "docker compose config failed"

reset; rm "$TREE/relay/internal/relayconfig/retired.go"
refuse "17a retired.go missing" "floor names"
reset; printf 'package relayconfig\nvar retiredEnv = map[string]string{}\n' >"$TREE/relay/internal/relayconfig/retired.go"
refuse "17b retired.go emptied" "empty or lack"

reset; sed -i 's|^FROM alpine:\(.*\) AS os$|&\nENV RELAY_HOSTNAME=x|' "$TREE/docker/relay.Dockerfile"
refuse "18a ENV names RELAY_HOSTNAME" "D1"
reset; printf 'USER 0\n' >>"$TREE/docker/relay.Dockerfile"
refuse "18b runtime ends as root" "D2: stage runtime"
reset; sed -i '/^FROM base AS dev-fleet$/,/^FROM scratch AS release-binary$/{s|^USER 10001:10001$|USER root|}' "$TREE/docker/relay.Dockerfile"
refuse "18c dev-fleet ends as root" "D2: stage dev-fleet"
reset; printf 'FROM scratch AS extra\n' >>"$TREE/docker/relay.Dockerfile"
refuse "18d a stage after runtime" "D3"

reset; mut_relay '.volumes += [{type:"tmpfs",target:"/x",read_only:true}]'
refuse "19a tmpfs volume entry" "F3: the tmpfs volume at /x"
reset; mut_relay '.pid = "host"'
refuse "19b pid host" "F5: pid: host"
reset; mut_relay '.ipc = "host"'
refuse "19c ipc host" "F5: ipc: host"
reset; mut_relay '.network_mode = "host"'
refuse "19d network_mode host" "F5: network_mode: host"
reset; mut_relay '.devices = ["/dev/mem:/dev/mem"]'
refuse "19e devices" "F5: devices"
reset; mut_relay '.volumes_from = ["init"]'
refuse "19f volumes_from" "F5: volumes_from"
reset; mut_relay '.security_opt += ["seccomp=unconfined"]'
refuse "19g seccomp unconfined" "lifts a confinement"

# A parser that fails on the Dockerfile only must fail the check, not leave an empty report that
# reads as success.
reset
REAL_AWK="$(command -v awk)"
cat >"$BIN/awk" <<STUB
#!/usr/bin/env bash
case "\${!#}" in *relay.Dockerfile) exit 2 ;; esac
exec "$REAL_AWK" "\$@"
STUB
chmod +x "$BIN/awk"
refuse "20 the Dockerfile stage parser fails" "the stage parser failed" "ok: Dockerfile"
rm -f "$BIN/awk"

echo
if [ "$fail" -ne 0 ]; then
  echo "compose-floor-check-test: $fail of $n case(s) FAILED" >&2
  exit 1
fi
echo "compose-floor-check-test: all $n cases passed (the good shape is accepted; each violation is refused with its reason)"
