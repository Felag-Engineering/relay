# The demo fleet

The nine-Node `demo` compose profile of the [local dev fleet](../dev-fleet.md), as a runbook:
roster, beats, fault injection and resetting between takes, and resource usage. Read
[dev-fleet.md](../dev-fleet.md) first — its **DEV-ONLY** banner, prerequisites, bring-up and MCP
connection all apply here, with more force: three times the Nodes sit behind the same committed
dev credential.

## The demo profile

A fleet-scale `demo` compose profile (#452): the same fleet as [dev-fleet.md](../dev-fleet.md), plus six more
daemons — `daemon-4..9` — for a total of nine Nodes with varied `node:` labels and a
third, strictly narrower Policy fixture. It exists for a stage demo, where three Nodes
do not read as a fleet and identical Policies produce no interesting refusal. It is
purely additive: every service the profile adds carries `profiles: ["demo"]`, so a
plain `docker compose up` still means exactly what it means there, and nothing in
`daemon-1..3` is touched (`demo_profile_is_additive`, `daemon/tests/dev_fleet_fixtures.rs`,
enforces this).

### Start from a clean registry

Do this first, and on its own, before anything else in this section:

```console
$ make demo-build   # first time, and again after any code change
$ make demo-reset
```

The demo fleet is its own fixed compose project, `relay-demo` — separate
images and separate volumes from the default fleet, driven entirely
through the guarded `scripts/demo-fleet.sh` (see
[The fault, and resetting between takes](#the-fault-and-resetting-between-takes)
below). It cannot run alongside the default fleet: both publish the same host
ports, `127.0.0.1:7654` / `9443`.

`make demo-reset` is `docker compose --profile demo down -v` followed by
`up -d --no-build` under the `relay-demo` project name, plus the health and
credential verification described below. It never builds — run `make
demo-build` once first (and again after any code change); a missing image is
refused up front, before anything is torn down.

Why `down -v` and not a plain `down`: `relay-data` is a **named** volume, so the
Relay's registry — and every Node in it — survives a plain `compose down`. A Node
from an earlier experiment is still in the registry, still matches Selectors, and
would make `node:role=bastion` resolve to **two** Nodes instead of one — which parks
the beat that is supposed to run straight through. `down -v` is the only thing that
clears it. The cost is real and worth stating plainly: `-v` destroys the CA and every
Node identity, so the next `up` re-enrolls the whole fleet from scratch.

`COMPOSE_PROFILES=demo make dev-fleet-up` looks like the Makefile-shaped
equivalent, but it is not: `dev-fleet-up` runs a bare `docker compose`, which
names its project after the checkout directory rather than `relay-demo` — a
project `make demo-reset` refuses on sight (see
[The fault, and resetting between takes](#the-fault-and-resetting-between-takes)).
Use `make demo-build` / `make demo-reset` instead.

Stop the demo fleet with `make demo-down` (no `-v` — Node identities and the
store survive, same as `dev-fleet-down` for the default fleet), and bring it
back with `make demo-up` (also no `-v`, no build — the matching plain
restart). `demo-up` is **not** "no credential mint": the mint one-shots have
`restart: no`, but a stopped one-shot container is started again by `up` just
like any other service, which re-runs its entrypoint and mints fresh values
into the (persisted) volume — it just does not copy them out to
`.dev-fleet/`; run `make demo-creds` after `demo-up` for that (see
[The fault, and resetting between takes](#the-fault-and-resetting-between-takes)
for what `demo-creds` does and does not do). There is no `down` you need to
remember to run before `make demo-reset`: it wipes first.

### The nine-Node roster

| service | hostname | `node:` labels | Policy fixture | demo service |
| --- | --- | --- | --- | --- |
| `daemon-1` | `dev-node-1` | `role=web` | `policy.web.toml` | yes (base, untouched) |
| `daemon-2` | `dev-node-2` | `role=web` | `policy.web.toml` | yes (base, untouched) |
| `daemon-3` | `dev-node-3` | `role=db` | `policy.db.toml` | no (base, untouched) |
| `daemon-4` | `dev-node-4` | `role=web, env=prod` | `policy.web.toml` | yes |
| `daemon-5` | `dev-node-5` | `role=web, env=prod` | `policy.web.toml` | yes |
| `daemon-6` | `dev-node-6` | `role=web, env=staging` | `policy.web.toml` | yes |
| `daemon-7` | `dev-node-7` | `role=db, env=prod` | `policy.db.toml` | no |
| `daemon-8` | `dev-node-8` | `role=bastion, env=prod` | `policy.bastion.toml` | no |
| `daemon-9` | `dev-node-9` | `role=web, env=staging` | `policy.web.toml` | yes |

Totals: 6 `role=web`, 2 `role=db`, 1 `role=bastion`; 4 `env=prod`, 2 `env=staging`, 3 with
no `env` label at all (the three base Nodes, deliberately unlabelled because their
blocks stay untouched). `list_nodes()` shows three distinct `policy_fingerprint`
values, one per Policy fixture — the SHA-256 of that file's raw bytes
(`daemon/src/policy.rs`'s `policy_fingerprint`), computable locally with
`sha256sum docker/fixtures/policy.{web,db,bastion}.toml` and not reproduced here
because it changes on any edit to the file, including a comment.

### What varies, and what cannot

`node:` labels vary as the table above shows. Of the Facts a Node reports
(`daemon/src/operations/system_facts.rs`), only `hostname` and `ip_addresses` can
actually differ in a single-host Docker fleet — `os`, `arch`, and `kernel` all come
from one shared kernel and one image, so every Node reports the same values for
those regardless of label. Faking them (e.g. per-Node `/etc/os-release` variants) was
rejected for the same reason the fake `systemctl` was rejected in the base fleet: a
dev fleet that lies about what it is is worse than one that is legibly limited.

`node:env=prod` / `node:env=staging` above are **Node-authored** labels (set by
`RELAY_NODE_LABELS` in the compose environment, and forgeable by a compromised Node),
while `relay:env=dev` is **Relay-authored** at enrollment. They are different
namespaces on purpose (invariant 7), and `list_nodes()` always returns them as
separate maps — never merged — so you can always tell which one you are looking at.
(`tag:` selectors are not mentioned here: they are refused at parse today, a known
gap tracked separately.)

### Selector cardinalities

| Selector | Nodes |
| --- | --- |
| `relay:env=dev` | 9 |
| `node:role=web` | 6 |
| `node:role=db` | 2 |
| `node:role=bastion` | 1 |
| `node:env=prod` | 4 |
| `node:env=staging` | 2 |
| `node:role=web, node:env=staging` | 2 |
| `node:role=db, node:env=prod` | 1 |

The three base Nodes carry no `node:env` label at all, on purpose — they predate this
profile and their blocks are untouched.

### Verification honesty

**The outcomes below are predicted, not observed.** Every `denied_by_policy` verdict is
underwritten by a hermetic test against the daemon's own evaluator
(`daemon/tests/dev_fleet_fixtures.rs`); every `success` and every `failure` depends on
`busybox httpd` and `dev-fleet-service` actually running in nine containers, which no
test in this repository can prove and which nobody has yet stood up at n=9. **Run the
beats once before presenting them, and correct this section with what you actually
saw.** Each beat below is marked *(tested)* for the half a hermetic test covers, and
*(predicted)* for the half that requires the real fleet.

### The four beats

**a. Fleet read, all success.**

```
run_operation(selector="relay:env=dev", operation="file.read", args={"path":"/etc/os-release"})
```

→ 9 × `success` — the allow verdict is tested on all three fixtures
(`all_three_policy_files_lint_clean_with_the_template_pack`,
`bastion_allows_exactly_the_documented_read_and_nothing_else`); the nine-Node result is
*(predicted)*. No approval: `read`-class.

**b. Mixed read set, no approval at all.**

```
run_operation(selector="relay:env=dev", operation="file.read", args={"path":"/var/lib/dev-fleet-service/state"})
```

→ 6 × `success` (the web Nodes) *(predicted)*, 2 × `failure` (the db Nodes never had the
file) *(predicted)*, 1 × `denied_by_policy` (the bastion, exact-path allow only)
*(tested, `bastion_allows_exactly_the_documented_read_and_nothing_else`)*.

**c. The mutate mixed set — the issue's acceptance criterion.**

**On stage, immediately before this beat, run `list_nodes(selector="node:role=bastion")`
and `list_nodes(selector="relay:env=dev")`.** This is the only instrument that reads the
**real registry** rather than the compose file. If the first returns anything but one
Node, or the second anything but nine, stop and run `make demo-reset`
— a stale Node changes the fan-out and the beat will not land.

Then:

```
raw_exec(selector="relay:env=dev", argv=["/usr/local/bin/dev-fleet-service","restart"])
```

→ parks under `dev-raw-exec-always-needs-a-human` with a `request_id` and a
`plan_hash` — the gate rule matches every Raw Exec regardless of fan-out, as written
in the fixture, though nobody has run this specific fan-out to watch it happen.
Approve as `dev-approver`:

```console
$ scripts/dev-fleet-mcp.sh api-approver POST /api/v1/approvals/<request_id>/decision \
    '{"approve":true,"plan_hash":"<plan_hash>","reason":"repair the dev-fleet demo service"}'
```

then re-issue the same call unchanged → **6 × `success, exit_code: 0`** *(predicted)*
and **3 × `denied_by_policy`** *(tested — `daemon-3` and `daemon-7` by the existing
`raw_exec_verdicts_match_the_web_db_split`; `daemon-8` by
`bastion_fixture_denies_every_raw_exec`, both in
`daemon/tests/dev_fleet_fixtures.rs`)*. Preflight the same argv with `plan=true` first
for 6 allow / 3 deny and no parking.

**d. The straight-through (unparked) mutate at n=9.** Two Selectors, both fan-out 1:

```
run_operation(selector="node:role=db, node:env=prod", operation="service.restart", args={"unit":"nginx"})
```

→ dispatched with no human, terminates `failure` with
`stderr="spawn systemctl: No such file or directory"` and no `exit_code` (the
documented busybox limit from [The fixture limit, stated plainly](../dev-fleet.md#the-fixture-limit-stated-plainly),
not a defect) *(predicted)*; and

```
run_operation(selector="node:role=bastion", operation="service.restart", args={"unit":"nginx"})
```

→ dispatched with no human — the gate's fan-out-1 behavior, untested here,
same as the first command above *(predicted)* — and refused by the Node:
1 × `denied_by_policy` *(tested, `bastion_allows_exactly_the_documented_read_and_nothing_else`)*.

### The threshold, stated on the page

`min_fan_out: 2` is **unchanged**. At nine Nodes almost every interesting fan-out
crosses it and parks — that is the correct lesson to draw, not a bug: raising the
threshold to keep a straight-through beat at n=9 would mean a four-Node mutate running
with no human, which is strictly weaker and teaches the audience the opposite of the
point. The straight-through path stays reachable through the two fan-out-1 Selectors
in beat (d) above. Every Raw Exec parks at any fan-out under a separate rule
(`dev-raw-exec-always-needs-a-human`), and that rule is not retuned either.

### The fault, and resetting between takes

`make demo-fault` kills the real `busybox httpd` (#389) on a subset of `role=web`
Nodes, out of band — through `docker compose exec`, never through the Relay
(there is no "break" verb anywhere in the control path; see
[Why `start|restart|status` and not `stop`](../dev-fleet.md#why-startrestartstatus-and-not-stop)).
The default targets are `daemon-4` (`dev-node-4`, `env=prod`) and `daemon-6`
(`dev-node-6`, `env=staging`) — one of each environment, and neither is on the
["drop first" list](#resource-usage) if the roster is ever trimmed. Override with
`DEMO_FAULT_NODES`, e.g. `make demo-fault DEMO_FAULT_NODES="daemon-2 daemon-9"`
— the Makefile passes it through as a real environment variable rather than
splicing it into the recipe text, and the script splits it on whitespace and
validates every token against the derived web roster (below) before any
`exec` into a container, so a value carrying a shell metacharacter is
refused, not executed.
Every target must be a `role=web` Node — anything else is refused before any
`exec` into a container, since faulting a Node that runs no demo service
would report a condition that was never there. (This refusal runs after the
project guard, and after one read-only `docker compose config` call that
derives the web/daemon rosters from the compose file — it is not before the
script touches Docker at all.) The kill is idempotent: running it again on an
already-down Node reaches the same DOWN report immediately, so it is safe to
run more than once with no reset in between.

**What is true after the fault.** `httpd` is really killed (found by `pidof`,
not the pidfile, so a stale pidfile cannot redirect the kill), and
`dev-fleet-service status` on that Node genuinely reports `state=down` (exit
`3`) — `make demo-fault` verifies this itself, by polling that same probe,
before it prints anything. Nothing is written anywhere to stage the condition.

**Discovery — read path, no approval.** Fan `file.read` of `/proc/net/tcp`
across the web Nodes:

```
run_operation(selector="node:role=web", operation="file.read", args={"path":"/proc/net/tcp"})
```

Read-class, unparked — the wildcard `file.read` allow in `policy.web.toml`
covers this path like any other (proven hermetically by
`web_policy_allows_reading_the_socket_table`,
`daemon/tests/dev_fleet_fixtures.rs`). Look for a row whose **local address is
`0100007F:1F90` (127.0.0.1:8080) AND whose state is `0A` (`TCP_LISTEN`)** —
present on a serving Node, absent on a faulted one. Do not key off the port
`1F90` alone: a recently-closed connection leaves a `TIME_WAIT` row (state
`06`) at that same local address for up to ~60s, and that row is not evidence
the service is up. `/var/lib/dev-fleet-service/state` is deliberately never
rewritten to say "down" (see [The real service](../dev-fleet.md#the-real-service)), so it is
**not** the discovery signal — it is the *repair* proof, below.

**Repair — mutate path.** There is no `node:` Selector that reaches a single
web Node in this roster. `node:role=web` alone reaches all six. Of the two
`role`+`env` combinations that actually exist, each matches exactly two Nodes
(`daemon-4`/`daemon-5` on `env=prod`, `daemon-6`/`daemon-9` on `env=staging`)
— `daemon-1` and `daemon-2` carry no `env` label at all (see
[The nine-Node roster](#the-nine-node-roster)), so they cannot be reached by
a `role`+`env` combination either, only by the even less selective
`node:role=web`. So the Raw Exec below reaches the faulted Node and its
healthy sibling both. That is harmless: `dev-fleet-service restart` is
idempotent, and restarting an already-serving instance still ends in
`state=running`.

```
raw_exec(selector="node:role=web, node:env=prod", argv=["/usr/local/bin/dev-fleet-service","restart"])
```

matches `daemon-4` (faulted) and `daemon-5` (healthy); swap `env=prod` for
`env=staging` to reach `daemon-6` (faulted) and `daemon-9` (healthy) instead.
Every Raw Exec parks under `dev-raw-exec-always-needs-a-human` regardless of
fan-out; approve it as `dev-approver` exactly as in
[The Raw Exec beat](../dev-fleet.md#the-raw-exec-beat), then re-issue the same call unchanged.
`svc.status` and `svc.restart` become the natural read/mutate pair for this
once #626 makes the Template pack dispatchable.

**Independent verification.** `file.read` of
`/var/lib/dev-fleet-service/state` on the repaired Node shows a new `pid` and
`started_epoch` (see [The real service](../dev-fleet.md#the-real-service)), and re-running
the `/proc/net/tcp` discovery read shows the `0100007F:1F90 ... 0A` row is
back.

**`make demo-reset`** is the reliable way back to the starting state between
takes — fault cleared, Jobs/approvals/audit/registry cleared (the store lives
on `relay-data`, wiped by `down -v`), the CA and every credential fresh, and
every Node healthy — and, unlike a bare `docker compose --profile demo down -v`
/ `up`, it never builds (a missing image is refused up front — run
`make demo-build` once, first) and it verifies rather than assumes:

1. Every image `docker compose config --images` names must already exist,
   checked before anything is torn down.
2. `down -v --remove-orphans` then `up -d --no-build --pull never`.
3. Waits for `relay` and every daemon to report `healthy`, and every one-shot
   (`credential`, `approver`, `console-admin`, `console-password`, `bootstrap`)
   to have exited `0`.
4. Probes `dev-fleet-service status` on every `role=web` Node — the fault, if
   any, is cleared by the fresh `up`, but this step confirms it with the same
   live probe the fault check uses, rather than assuming a fresh container
   means a serving one.
5. **Mints** fresh credentials: step 2's `down -v` / `up` recreates the
   `credential`/`approver`/`console-admin`/`console-password` one-shots from
   nothing, which is what actually mints (`docker/mint-credential.sh` runs
   again on every container that starts fresh). This step then **copies**
   them out to `.dev-fleet/` (`scripts/dev-fleet-mcp.sh init` — a
   `docker compose cp` / `run --no-deps` read, nothing more) and checks, live,
   that `GET /api/v1/approvals` comes back empty and that `list_nodes()` over
   MCP reports every Node connected — there is no `GET /api/v1/nodes` list
   route on the Control API, only `GET /api/v1/nodes/{node_id}`, so `list_nodes`
   is the only surface that sees the whole registry.

**The CA is regenerated on every reset, so a registered MCP client is left
holding a stale bearer token and a stale CA it can no longer verify against**
(`NODE_EXTRA_CA_CERTS` is read only at process start). `.dev-fleet/` is
already current — step 5 above just refreshed it — so the fix is only to
restart the client: `claude mcp remove relay` / `claude mcp add ...` as in
[Connecting Claude Code](../dev-fleet.md#connecting-claude-code). `make demo-reset`'s
closing summary says this every time. **Do not follow
`.dev-fleet/start-claude.txt`'s own `make dev-fleet-creds` line** — `.dev-fleet/`
is shared between the default fleet and the demo fleet, and `dev-fleet-creds`
targets the directory-named default project, not `relay-demo`. `make demo-creds`
is the demo fleet's equivalent, and it is only needed after `demo-up`: unlike
`demo-reset`, `demo-up` does not copy anything out on its own, even though its
`up` (see [Survive `down` / `up`](../dev-fleet.md#survive-down--up)) causes the same
one-shots to re-mint into the volume. `demo-creds` itself mints nothing — it
is a pure copy, safe to run any number of times.

**The refusal.** `scripts/demo-fleet.sh` (every one of `demo-build`,
`demo-reset`, `demo-fault`, `demo-up`, `demo-down`, `demo-creds`) refuses
unless the target is exactly the `relay-demo` compose project on a local
Docker engine, and it does so before any Docker call **except two read-only
checks**: the current docker context's endpoint (always made, to confirm it
is a local engine), and — only once that passes — a `docker ps` that confirms
no *other* checkout already owns the `relay-demo` project (this repo lives in
many git worktrees, and `relay-demo` is one project name per Docker engine).
A `COMPOSE_PROJECT_NAME` set to anything else — including set-but-empty — or
a non-local `DOCKER_HOST` are refused with **no** Docker call at all, because
they are decided from the environment alone. Once past that guard, `demo-reset`
and `demo-up` separately refuse — before either touches a volume or a
container, via one more read-only `docker ps` — if host port `7654` or `9443`
is already published by some other compose project. `demo-reset` refuses once
more, via a read-only `docker compose config --format json`, if any volume it
is about to `down -v` does not resolve to a `relay-demo_`-prefixed name — the
defense against a future `name:`/`external:` override on a volume in
`docker-compose.yml` quietly pointing `-p relay-demo` at a volume this
checkout does not own. `make test-demo-fleet` (`scripts/demo-fleet-test.sh`,
in `make verify` and CI) proves every refusal against a stubbed `docker`,
never a real engine.

A checkout directory literally named `relay-demo` would give the *default*
(non-demo) fleet's bare `docker compose up` that same project name — an
unlikely collision, but one more reason to prefer `make demo-build` /
`make demo-reset` over typing `docker compose` by hand under this profile.

**Verification honesty.** The `/proc/net/tcp` discovery signal is *(predicted)*
from `web_policy_allows_reading_the_socket_table`
(`daemon/tests/dev_fleet_fixtures.rs`) — the daemon's own Policy engine agrees
the read is allowed, but no automated test here starts a real `busybox httpd`
or reads its real socket table. "Reset survives back to back, repeatedly" has
**not been observed live at all** — `scripts/demo-fleet-test.sh`'s hermetic
guard proof only proves the refusal logic against a stubbed `docker`; it says
nothing about whether a real `down -v` / `up` / wait / probe cycle actually
succeeds once, let alone repeatedly. Run the fault → discover → repair →
verify sequence, and `make demo-reset` two or three times back to back,
before presenting, and correct this paragraph with what you actually saw.

### Resource usage

**PENDING MEASUREMENT (#452, AC 4).** No number below has been measured — there is no
Docker daemon available in this repository's build environment, only the `docker`
binary — and none should be invented or assumed. Whoever next has a machine with
Docker Engine + Compose v2 should run the procedure below and fill this table in the
same change that adjusts the roster, if adjustment turns out to be needed.

**Procedure:**

1. `docker compose down -v`, then `docker compose --profile demo up --build -d`; wait
   until `docker compose ps` shows all nine daemons `healthy`; let it settle 60s.
2. **Idle:** three samples 10s apart of
   `docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"`.
   Record total memory, the `relay` container, and one representative web / db /
   bastion daemon.
3. **Fan-out:** sample the same command while running
   `run_operation(selector="relay:env=dev", operation="system.facts")` in a tight loop,
   and once more during the approved `raw_exec` restart across all nine. Record the peak.
4. Record the machine (CPU, RAM, OS, Docker version) and the date beside the table —
   numbers without the machine are noise.
5. **If nine does not sit comfortably, drop `daemon-9` first, then `daemon-5`.**
   `daemon-9` and `daemon-6` are both `role=web, env=staging` — dropping both would
   take `node:role=web, node:env=staging` to zero while this section still publishes
   it, so the second drop must be `daemon-5` (`role=web, env=prod`), not `daemon-6`.
   Dropping `daemon-9` then `daemon-5` keeps every Selector in the cardinality table
   above at 1 or more. Update, in the same change: this roster table and the compose
   service + `daemonN-state` volume being dropped, the Selector cardinalities table and
   every beat that says "9 ×" / "6 ×", and `daemon/tests/dev_fleet_fixtures.rs`'s
   `ROSTER` and `a_single_node_selector_survives_at_nine_nodes`.

| measured on | date | who | idle memory (total) | idle memory (`relay`) | idle memory (1 daemon) | fan-out peak memory | idle CPU | fan-out peak CPU |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ |
