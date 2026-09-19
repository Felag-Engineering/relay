# Local dev fleet (`docker compose`)

A one-command, laptop-scale fleet: one **Relay** container plus three
**relay-daemon** containers by default (nine under the optional `demo` compose
profile — see [The demo profile](#the-demo-profile)) that auto-enroll over
CA-pinned mTLS and are drivable through the control plane (MCP + `/api/v1`).
It exists to demo and dogfood the real control path end to end.

> **DEV-ONLY — no production posture.** This environment ships committed
> credentials and a fixture Policy for convenience, runs everything on one host,
> and makes no availability, isolation, or hardening claims. It is **not** a
> deployment guide. The real deployment story is the future `v0.1.0-beta` install
> docs. Never reuse the credentials or Policy below anywhere real. The published
> ports (`7654`, `9443`) are bound to `127.0.0.1` only: the control plane accepts
> a committed dev credential, so exposing it on the LAN would be remote code
> execution for anyone on your network. For the hardened production posture, see
> `daemon/packaging/relay-daemon.service` and
> [docs/operations/daemon-privilege-posture.md](operations/daemon-privilege-posture.md).
> The `demo` compose profile ([below](#the-demo-profile)) is **more** exposed, not
> less: it puts three times the Nodes behind the very same committed dev
> credential and the same loopback-only control plane, so everything in this
> banner applies to it with more force.

## Prerequisites

- Docker Engine with the Compose v2 plugin (`docker compose`, not the legacy
  `docker-compose`).
- Network access to Docker Hub the first time (the Relay/daemon binaries are
  compiled inside multi-stage images; nothing depends on a host Go or Rust
  toolchain).

Docker is **not** required for `make build`, `make test`, or `make lint`, and CI
never invokes it.

## What is in the box

| Piece | What it is |
| --- | --- |
| `relay` | The Go Relay. Node-plane gRPC on `:7654`, control-plane HTTPS (MCP + `/api/v1`) on `:9443` — distinct listeners, distinct published ports. CA + SQLite store live on the `relay-data` volume. |
| `bootstrap` | A one-shot helper that, once the Relay is healthy, mints a `relay:`-scoped Enrollment Token through `POST /api/v1/enrollment-tokens` and exports the Relay's **public** CA certificate for the daemons to pin. Then it exits. |
| `approver` | A one-shot helper that creates the `dev-approver` **human** Account and mints its credential. It exists because the approval gate forbids self-approval — see [The approval gate](#the-approval-gate) below. Then it exits. |
| `console-admin` | A one-shot helper that creates the `admin` **human** Account the Admin Console signs in. Then it exits. |
| `console-password` | A one-shot helper that sets that Account's Console password with `relay console-password`. Separate from `console-admin` because the two acts carry different authorities — see [The Admin Console](#the-admin-console) below. Then it exits. |
| `daemon-1..3` | Three relay-daemons (Rust, musl static binary). Each has a baked, root-owned Policy fixture and a private state volume, enrolls on first start, and reports health once it has a persisted identity. The two `role=web` Nodes (`daemon-1`, `daemon-2`) also run the dev-fleet demo service; `daemon-3` (`role=db`) loads a different Policy fixture and runs no demo service. |
| `daemon-4..9` (`demo` profile) | Six more relay-daemons, started only with `--profile demo`, that scale the fleet to nine Nodes with varied `node:role`/`node:env` labels and a third Policy fixture (`policy.bastion.toml`, the narrowest of the three). See [The demo profile](#the-demo-profile). |

Security-relevant choices, made explicit:

- **Policy arrives with the image, never over the wire (ADR-0002).** The fixture
  Policy is now **three** files, `docker/fixtures/policy.web.toml`,
  `policy.db.toml`, and `policy.bastion.toml` (the narrowest of the three,
  `demo` profile only), all `COPY`d into the daemon image root-owned `0644`,
  passing the daemon's fail-closed loader (which refuses a group/world-writable
  Policy, or one owned by a non-root user). The Relay can query a Node's Policy
  fingerprint but can never change the Policy. The demo Template pack
  (`docker/fixtures/templates.d/relay-demo/`) arrives the same way and under
  the same rule — ADR-0002 applies to templates verbatim, and its loader is
  fail-closed **whole-set**: a bad mode on one template file empties the
  Node's entire template vocabulary and reports the `unloadable` fingerprint.
- **The CA private key never reaches a daemon.** `ca-key.pem` lives only on the
  `relay-data` volume. The short-lived `bootstrap` helper mounts that volume
  read-only to copy out `ca-cert.pem`; the long-lived daemon containers never
  mount it and only ever receive the **public** cert.
- **The Enrollment Token is `relay:`-scoped.** It can only join Nodes; it can
  never call the API or run Operations. Enrollment stamps `relay:env=dev` and
  `relay:fleet=dev` onto each Node — these `relay:` labels are what your Selectors
  target.
- **The control-plane credential is minted at runtime, not committed.** Since
  ADR-0023 the control plane accepts only per-Account API Tokens, so the
  one-shot `credential` service runs `relay bootstrap-token` against the Relay's
  own store and writes the result to the shared volume
  (`docker/mint-credential.sh`). Read it with:

  ```console
  $ docker compose run --rm --no-deps --entrypoint sh credential \
      -c 'cat /credential/control-credential'
  ```

  It lives on its own volume, which the daemons deliberately do not mount — an
  admin credential readable by every Node is exactly what a compromised Node
  would use to drive the whole fleet. It is a live 24h admin credential for the
  founding admin Account; keeping it on a volume at all is a dev-fleet
  convenience only — in a real deployment the
  credential goes from the operator's terminal straight into a secret store (see
  [docs/operations/control-plane-credential.md](operations/control-plane-credential.md)).
  Never copy this one out of the fleet.

## The Admin Console

The Console (ADR-0009) is served on the **same** control-plane listener as MCP and
`/api/v1` — no new listener and no new auth path (invariant 10). Browser sessions
sit beside API Tokens and OAuth as one of the authenticator's credential lanes,
rather than the Console authenticating its own requests, which would be a second
control path and the first one to be forgotten.

```
https://127.0.0.1:9443/console/
```

Your browser will warn about the certificate: the Relay signs its own server cert
with the CA it created on first start, and nothing on your laptop trusts that CA.
That is the correct behaviour and not a misconfiguration — accept it for the dev
fleet, or add `ca-cert.pem` to your trust store if the warning gets tiresome.

Sign in with:

| | |
| --- | --- |
| username | `admin` |
| password | `admin1234567` |

Override either with `CONSOLE_ADMIN_NAME` / `CONSOLE_ADMIN_PASSWORD` in the
environment before `docker compose up`.

**Why the password is not shorter.** The Relay refuses any Console password below
12 bytes (`accounts.MinPasswordBytes`). The sign-in throttle deliberately has no
hard lockout — a lockout is a denial-of-service lever pointed at your own
operators — so an attacker gets slow, unlimited attempts, and length is the only
thing that makes that safe. What sits behind the credential is the front half of a
fleet-execution surface (ADR-0026).

**Why setting it takes two containers.** Creating the Account is a control-plane
request: it goes through `POST /api/v1/accounts` carrying a bearer token, like any
other administrative act. Setting its first Console password is not, and cannot
be — reaching the Console requires a password, so the first one has nowhere to
come from except local root on the Relay's own store. That is the same
chicken-and-egg as `relay bootstrap-token` (ADR-0023) and the same answer ADR-0002
gives for Policy: root it in the filesystem. Two authorities, two containers, and
neither holds the other's power — `console-admin` has a credential and no store
access, `console-password` has store access and no credential.

**What you can do there today.** Everything and nothing: the v0.6.0 Console is
**read-only by construction**. The read seams it is wired with have no write
method on them at all, so "zero mutating routes" is a fact about the types rather
than a property of the handlers. You can watch the fleet, open a Node, read its
daemon-reported effective Policy, follow the activity trail, read what has been
read, and open a parked approval. You cannot run anything, change a label, or
decide an approval — those arrive in v0.7.0 behind step-up re-authentication.

## Bring the fleet up

```console
$ docker compose up --build -d
```

The Relay starts and creates its CA; `bootstrap` waits for the control API, mints
the token, and exports the CA cert; then the daemons enroll and go healthy —
three by default, or nine under `--profile demo`
([The demo profile](#the-demo-profile)).

```console
$ docker compose ps
```

Wait until `daemon-1`, `daemon-2`, and `daemon-3` are `healthy` (each becomes
healthy only after it has persisted its identity, i.e. after a successful
enrollment) — plus `daemon-4..9` under `--profile demo`.

> **Troubleshooting.** The Relay healthcheck probes its control port with busybox
> `nc -w1`. If your busybox build ships an `nc` without the `-w` (timeout) flag,
> the healthcheck never passes, so `bootstrap` never starts and no daemon enrolls
> — check `docker compose logs relay` for a failing healthcheck.

## Verify N enrolled Nodes

**Quick check (no MCP client needed).** The Relay logs every enrollment:

```console
$ docker compose logs relay
```

You should see three Nodes join (nine under `--profile demo`), each stamped
`relay:env=dev` / `relay:fleet=dev`.

**Richer check — list the fleet registry over MCP.** The `list_nodes` tool
returns each Node's `node_labels`, `relay_labels`, and reported
`policy_fingerprint` — the full registry view the quick log check doesn't show.
Use the MCP client setup from [Drive the fleet over MCP](#drive-the-fleet-over-mcp)
below (which needs the exported CA cert; see the next step), then call:

```
list_nodes()
```

The result is a `nodes` array with three entries (nine under `--profile demo`),
each carrying its `node_id`, `node_labels`, `relay_labels` (including
`relay:env=dev` / `relay:fleet=dev`), and `policy_fingerprint`. `node:` and
`relay:` labels come back as separate maps
— never merged — so you can always tell which namespace a label was set from
(ADR-0006). Pass an optional `selector` to filter, e.g.
`list_nodes(selector="relay:env=dev")`.

Export the CA cert and both control-plane credentials to the gitignored
`./.dev-fleet/`, so you can talk to the control plane (MCP and `/api/v1`) over
verified TLS from the host:

```console
$ make dev-fleet-creds
```

The Relay's server certificate SAN is `relay` (the in-fleet DNS name), not
`localhost` — so dial `https://relay:9443` with `127.0.0.1 relay` in `/etc/hosts`
and verification succeeds against `.dev-fleet/ca-cert.pem`. See
[Connecting Claude Code](#connecting-claude-code) for the one-time setup.

## Drive the fleet over MCP

### Connecting Claude Code

The control plane's server certificate has a single SAN: `relay`, the in-fleet DNS name.
So dial it by that name and TLS verifies against the fleet's own CA with no `-k` and no
disabled verification. Map the name to loopback once:

```console
$ grep -q 'relay$' /etc/hosts || echo '127.0.0.1 relay' | sudo tee -a /etc/hosts
```

Export the credentials, then add the server. `NODE_EXTRA_CA_CERTS` is what makes Claude
Code's Node TLS stack trust the fleet's private CA:

```console
$ make dev-fleet-creds
$ claude mcp add --transport http relay https://relay:9443/mcp \
    --header "Authorization: Bearer $(cat .dev-fleet/control-credential)"
```

An **http** transport is dialled by the `claude` process itself, not by a subprocess, so
the CA has to be trusted by that process — `claude mcp add -e` would not help here. Start
Claude Code with it:

```console
$ NODE_EXTRA_CA_CERTS=$PWD/.dev-fleet/ca-cert.pem claude
```

That connects as the **founding admin** — the requester. It deliberately **cannot** approve
its own parked dispatches; use `dev-approver` for that (see
[The approval gate](#the-approval-gate)).

Claude Code does not implement the MCP Tasks extension, so gated dispatches come back to it
as `pending_approval` **results**, never as task handles. That is the universal path and the
one that matters most; reach the Tasks path with
[`scripts/dev-fleet-mcp.sh`](#driving-the-mcp-tasks-extension-scriptsdev-fleet-mcpsh).

### Any other MCP client

Point it at `https://relay:9443/mcp` with:

- **Bearer credential:** `.dev-fleet/control-credential` (from `make dev-fleet-creds`).
- **TLS trust:** `.dev-fleet/ca-cert.pem`. Dial the host as `relay` so the SAN matches —
  never disable verification just to get a connection.

`run_operation` takes a `selector`, an `operation`, and a named-argument **map**
keyed by the Operation's argument names (the Relay maps those names to the
daemon's positional Policy under the hood).

Happy path — fan `system.facts` (a no-argument, `read`-class Operation) across
every dev Node and get a per-Node result:

```
run_operation(selector="relay:env=dev", operation="system.facts")
```

Read a file — the `file.read` example advertised by `list_operations`. The dev
daemon image bakes in `/etc/os-release` (busybox has none), and the fixture Policy
allows `file.read` on any path but `/etc/shadow`, so this succeeds verbatim per Node:

```
run_operation(selector="relay:env=dev", operation="file.read", args={"path":"/etc/os-release"})
```

Policy-denied path — `service.restart sshd`. The fixture Policy allows
`service.restart` only for `nginx` and `php-fpm`, so the daemon's live Policy
engine refuses it:

```
run_operation(selector="relay:env=dev", operation="service.restart", args={"unit":"sshd"})
```

Each matched Node returns `outcome=denied_by_policy` (the "denied-by-policy"
result). The verdict is the daemon's, not the Relay's — the Relay never evaluates
Policy (ADR-0002/0011).

## The approval gate

The fleet ships an **approval gate** (`docker/fixtures/approval-gates.json`, ADR-0027), so
the parked-dispatch and MCP-task-handle surfaces are exercisable rather than theoretical.
Two rules:

| Rule | Matches | Requires |
| --- | --- | --- |
| `dev-fleet-wide-mutates-need-a-human` | `mutate` class, fan-out **≥ 2** | 1 approval from `dev-approver`, out-of-band |
| `dev-raw-exec-always-needs-a-human` | every Raw Exec | 1 approval from `dev-approver`, out-of-band |

The fan-out threshold is deliberate: it leaves **both** paths reachable in one fleet. A
mutate that resolves to a single Node runs straight through; the same mutate aimed
fleet-wide parks. In the **default** (three-Node) fleet, `node:role=db` is one Node and
runs straight through, while `relay:env=dev` (three) waits for a human.

**This changes under `--profile demo` — read this before presenting.** At nine Nodes,
`node:role=db` is **two** Nodes, and `min_fan_out: 2` is a floor, so that Selector now
parks too. The straight-through beat survives only through Selectors that stay at
fan-out 1: `node:role=bastion` (exactly one Node) and `node:role=db, node:env=prod`
(exactly one Node, because `daemon-3` carries no `env` label at all). See
[The demo profile](#the-demo-profile) for the full cardinality table and the exact
commands.

Security-relevant choices, made explicit:

- **The gate is Relay configuration, not a runtime object.** It is baked into the image
  `--chmod=0644`, root-owned, and read from `RELAY_APPROVAL_GATE_CONFIG`. No Account of
  any role can read or loosen it through the API (invariant 11) — a stolen credential that
  could edit its own approval requirements would make the whole mechanism decorative.
- **Loading it is fail-closed.** A malformed, missing, symlinked, or group/world-writable
  gate file fails Relay startup. It never degrades to "nothing needs approval", so a
  broken fixture crash-loops the container instead of quietly disarming the fleet. (If you
  edit the fixture and the `relay` container stops going healthy, read
  `docker compose logs relay` — the loader says exactly what it objected to.)
- **`requester_allowed` is unset, which is the strict default.** The Account that requested
  a parked dispatch may **not** approve it. That is why `dev-approver` exists: with a
  single Account the fleet could park a dispatch and never release it.
- **`dev-approver`'s credential is on the `control-credential` volume**, which daemons
  never mount. An approver credential readable by every Node would let a compromised Node
  approve its own remediation.

### Approving a parked dispatch

Export both credentials to the gitignored `./.dev-fleet/` first:

```console
$ make dev-fleet-creds
```

A gated call comes back as a `pending_approval` **result** (not an error) carrying a
`request_id`, a `plan_hash`, and a Relay-authored `summary`. Decide it as the approver:

```console
$ scripts/dev-fleet-mcp.sh api-approver POST \
    /api/v1/approvals/<request_id>/decision \
    '{"approve":true,"plan_hash":"<plan_hash>","reason":"looks right"}'
```

Then **re-issue the original call unchanged** — approving releases a Plan, it does not
itself dispatch.

Two properties worth watching, because they are the point of the design:

- The **admin** credential cannot decide its own request. It gets
  `409 requester may not decide their own request`, even though it is an admin.
- The decision arrives on a credential the requesting MCP session does not hold. That is
  what `channel: out-of-band` records — evidence, not an assumption about the client.

## A mutate that really runs — and the two that cannot

### The fixture limit, stated plainly

`service.restart` and `pkg.install` cannot complete on `busybox:stable-musl`: there is no
service manager and no package manager on this image. `service.restart` terminates in
`outcome=failure` with `stderr="spawn systemctl: No such file or directory"` and **no
`exit_code` key** — the documented contract for a Task that never ran a process, not a
defect (see [issue #389](https://github.com/Felag-Engineering/gleipnir-relay/issues/389)).

This was deliberately **not** papered over: a fake `systemctl` that reports success without
a service manager would bake a lie into the fixture, and a dev fleet that fakes success is
worse than one that fails legibly. That reasoning does not weaken because there is an
audience.

`service.restart sshd` remains the deterministic **deny** beat below and never needed
`systemctl` to exist — the daemon refuses before it execs.

### The real service

`busybox httpd` serves a real docroot on `127.0.0.1:8080`
(`/srv/dev-fleet-service/www/index.html`), started by `docker/daemon-entrypoint.sh` on the
Nodes labelled `node:role=web` (`daemon-1`, `daemon-2`, and — under `--profile demo` —
`daemon-4`, `daemon-5`, `daemon-6`, `daemon-9`), and managed by the root-owned
`/usr/local/bin/dev-fleet-service`. It has three subcommands and no more — there is
deliberately no `stop` (see [Why `start|restart|status` and not `stop`](#why-startrestartstatus-and-not-stop)
below):

| Subcommand | Exit code | Meaning |
| --- | --- | --- |
| `status` | `0` | serving — prints `state=running pid=… port=…` |
| `status` | `3` | not serving — prints `state=down port=…` |
| `start` | `0` / `1` | idempotent: already serving, or started successfully / failed to start |
| `restart` | `0` / `1` | stopped and restarted successfully / could not act |
| anything else | `2` | usage |

Every one of those success-or-down exit codes comes from a live HTTP fetch of that file,
never from an assumption (the usage exit `2` is the one exception — it is reached before any
probe). State is recorded at `/var/lib/dev-fleet-service/state` (`pid=`, `port=`,
`started_epoch=`) only after an observed successful probe, and stdout/stderr from `httpd`
are captured at `/var/lib/dev-fleet-service/httpd.log`. There is deliberately no `state=` key
in that file: it is never rewritten after a probe-verified start, so a stored `state=running`
would go on claiming liveness after an out-of-band kill — `pid` and `started_epoch` are
enough to prove a restart happened, and neither one can lie about the present.

### The Raw Exec beat

Use `raw_exec(selector=…, argv=[…])` for this — **never `run_operation`**, since the vehicle
for a working mutate here is Raw Exec, not the Template pack (see below).

Preflight without dispatching:

```
raw_exec(selector="relay:env=dev", argv=["/usr/local/bin/dev-fleet-service","status"], plan=true)
```

returns per-Node verdicts allow/allow/deny in the default fleet — 6 allow / 3 deny
under `--profile demo` — no parking, no execution.

The repair:

```
raw_exec(selector="relay:env=dev", argv=["/usr/local/bin/dev-fleet-service","restart"])
```

returns a `pending_approval` result (every Raw Exec parks under
`dev-raw-exec-always-needs-a-human`) carrying `request_id` and `plan_hash`. Approve it as
`dev-approver`:

```console
$ scripts/dev-fleet-mcp.sh api-approver POST /api/v1/approvals/<request_id>/decision \
    '{"approve":true,"plan_hash":"<plan_hash>","reason":"repair the dev-fleet demo service"}'
```

then **re-issue the same `raw_exec` call unchanged** — approving releases a Plan, it does
not itself dispatch. Expect **two Nodes** `outcome=success, exit_code: 0` and **daemon-3**
`outcome=denied_by_policy` in the default fleet — or **6 × `success, exit_code: 0`**
and **3 × `denied_by_policy`** (`daemon-3`, `daemon-7`, `daemon-8`) under
`--profile demo` (predicted; see [The demo profile](#the-demo-profile) for what is
tested versus predicted). The verdict is the daemon's, never the Relay's (ADR-0002 /
ADR-0011).

The independent read — proof that a mutate really happened, taken through a different
Operation and a different tier — before and after the restart:

```
run_operation(selector="relay:env=dev", operation="file.read", args={"path":"/var/lib/dev-fleet-service/state"})
```

`pid` and `started_epoch` both change on the web Nodes; the db Node fails to read a file it
never had.

### Why `start|restart|status` and not `stop`

The agent must be able to repair the fleet and never to break it; the fault is injected out
of band (#622). The script has no `stop` subcommand and the Policy has no allow for one, so
both layers say the same thing.

### The template pack — loaded and enforced, not yet dispatchable

`svc.restart` (`mutate`) and `svc.status` (`read`) are visible through
`list_operations(node_id="<a web node id>")` and `describe_node(...)`'s
`template_vocabulary` (with a real `template_set_fingerprint`; the literal `unloadable`
there means the pack failed to load). They are in each Node's Policy vocabulary — allowed on
the web fixture, absent from the db fixture.

**They cannot be called yet:** the Relay resolves only the four Native Operations at
dispatch, so `run_operation(operation="svc.restart")` returns `unknown operation`. Making a
Template callable is tracked in
[issue #626](https://github.com/Felag-Engineering/gleipnir-relay/issues/626).

After the rebuild, `list_nodes()` shows **two distinct `policy_fingerprint` values** across
the default fleet, because `daemon-3` now loads a different Policy file — the registry's
drift signal, visible for real. Under `--profile demo` there are **three**, one per Policy
fixture (see [The demo profile](#the-demo-profile)).

## Driving the MCP Tasks extension (`scripts/dev-fleet-mcp.sh`)

Relay serves the MCP Tasks extension (SEP-2663, ADR-0028), but **no shipping MCP client
implements it** — not the Go SDK ([go-sdk#626](https://github.com/modelcontextprotocol/go-sdk/issues/626)),
not the TypeScript or Python ones. The capability that triggers it is advertised in a
per-request `_meta` that no client sends, so pointing an ordinary client at the fleet can
never reach `tasks/get`, `tasks/cancel`, or the `CreateTaskResult` shim.

`scripts/dev-fleet-mcp.sh` speaks that wire by hand. It is a curl wrapper, deliberately not
a client library: its value is showing exactly what goes over the wire, which is the only
way to check Relay's reading of a spec nobody else has implemented yet.

```console
$ scripts/dev-fleet-mcp.sh init                 # export CA + both credentials
$ scripts/dev-fleet-mcp.sh call list_nodes      # ordinary client (no Tasks capability)
$ scripts/dev-fleet-mcp.sh call-tasks run_operation '{"selector":"relay:env=dev","operation":"pkg.install","args":{"name":"nginx"}}'
$ scripts/dev-fleet-mcp.sh task-get <taskId>
$ scripts/dev-fleet-mcp.sh task-cancel <taskId>
$ scripts/dev-fleet-mcp.sh raw tasks/update '{}' # served? it must not be
```

The difference between `call` and `call-tasks` is the whole shim: the same gated dispatch
returns a `pending_approval` result to an ordinary client and a `resultType: "task"` handle
to a Tasks-capable one. Both mint the same `taskId`.

These commands exercise the MCP Tasks extension end to end; `docs/specs/` carries what each capability is expected to do.

## Survive `down` / `up`

```console
$ docker compose down
$ docker compose up -d
```

**Under `--profile demo`, use the symmetric profiled form on both commands —
`docker compose --profile demo down` / `--profile demo up -d`.** Whether a
profile-less `down` stops profiled containers has varied across Compose
versions and is not verified here; the profiled form is the one whose
behaviour does not depend on that answer. Get this wrong mid-demo and `up`
brings back **three** daemons, not nine.

The CA and the SQLite store persist on `relay-data`, and each daemon's identity
persists on its private `daemonN-state` volume, so the Nodes come back with the
**same** `node_id`s and do not re-enroll (enrollment is idempotent — a daemon
with a persisted identity reuses it). `docker compose logs relay` after the
restart shows reconnects, not a fresh enrollment storm.

To wipe everything (CA, identities, store) and start clean:

```console
$ docker compose down -v
```

or, under the `demo` profile:

```console
$ docker compose --profile demo down -v
```

## Where to read the audit trail

Every dispatch, refusal, and Policy preflight is audited. Each such decision emits exactly
one structured log line — carrying the principal, selector, operation/action
kind, outcome counts, and job ID — to the Relay's logs:

```console
$ docker compose logs -f relay
```

The durable, full record — including per-Node output — lives only in the
Relay's SQLite store on the `relay-data` volume; the log lines deliberately
omit operation args, raw-exec argv, and captured Stdout/Stderr, so they are a
summary, not a substitute for the store.

A dedicated audit **read** surface (an API/MCP route to query the trail) does not
exist yet — it is future work. For now the logs and the store are the trail.

## The demo profile

A fleet-scale `demo` compose profile (#452): the same fleet as above, plus six more
daemons — `daemon-4..9` — for a total of nine Nodes with varied `node:` labels and a
third, strictly narrower Policy fixture. It exists for a stage demo, where three Nodes
do not read as a fleet and identical Policies produce no interesting refusal. It is
purely additive: every service the profile adds carries `profiles: ["demo"]`, so a
plain `docker compose up` still means exactly what it means above, and nothing in
`daemon-1..3` is touched (`demo_profile_is_additive`, `daemon/tests/dev_fleet_fixtures.rs`,
enforces this).

### Start from a clean registry

Do this first, and on its own, before anything else in this section:

```console
$ docker compose --profile demo down -v
$ docker compose --profile demo up --build -d
```

Why `down -v` and not a plain `down`: `relay-data` is a **named** volume, so the
Relay's registry — and every Node in it — survives a plain `compose down`. A Node
from an earlier experiment is still in the registry, still matches Selectors, and
would make `node:role=bastion` resolve to **two** Nodes instead of one — which parks
the beat that is supposed to run straight through. `down -v` is the only thing that
clears it. The cost is real and worth stating plainly: `-v` destroys the CA and every
Node identity, so the next `up` re-enrolls the whole fleet from scratch.

`COMPOSE_PROFILES=demo make dev-fleet-up` is the Makefile-shaped equivalent for `up`
(the target is a bare `docker compose up --build -d`, so it inherits
`COMPOSE_PROFILES` from the environment with no Makefile change needed).

Stop the demo fleet with `docker compose --profile demo down` / `--profile demo down -v`.
**`make dev-fleet-down` is a profile-less `docker compose down`** — whether that stops
profiled containers has varied across Compose versions and is not verified here. Use
the symmetric `--profile demo` form on every `down` so the answer never matters; see
[Survive `down` / `up`](#survive-down--up) above and [Cleanup](#cleanup) below, both
of which now give the profiled form too.

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
Node, or the second anything but nine, stop and `docker compose --profile demo down -v`
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
documented busybox limit from [The fixture limit, stated plainly](#the-fixture-limit-stated-plainly),
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

## Scaling the fleet

Each daemon needs its **own** state volume for a stable per-Node identity across
restarts, so daemons are explicit services rather than replicas. To add a Node,
copy a `daemon-N` service block (bump the name, `HOSTNAME`, and its
`daemonN-state` volume, and register the new volume under `volumes:`). That copy
silently inherits `RELAY_POLICY_PATH` and a `role=` label, both of which must
be chosen deliberately — `policy.web.toml` + `role=web` to get the demo
service and the repair allow, `policy.db.toml` + `role=db` to get neither,
or `policy.bastion.toml` + `role=bastion` to get neither and nothing else
either — see [The demo profile](#the-demo-profile) for the worked example of
exactly this copy, done six times.

**A new service must declare `profiles: ["demo"]`** (or whichever profile is
appropriate) **or it changes the default fleet** — a plain `docker compose up`
picks up every service that omits a `profiles:` key.
`demo_profile_is_additive` (`daemon/tests/dev_fleet_fixtures.rs`) fails the
build if a new service forgets it.

## Cleanup

```console
$ docker compose down -v
$ rm -rf ./.dev-fleet
```

**Under `--profile demo`, use the symmetric profiled form so the answer never
matters** — same caveat as [Survive `down` / `up`](#survive-down--up) above:
whether a profile-less `down -v` also stops the six `demo`-profile daemons has
varied across Compose versions and is not verified here.

```console
$ docker compose --profile demo down -v
$ rm -rf ./.dev-fleet
```
