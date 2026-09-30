# Local dev fleet (`docker compose`)

A one-command, laptop-scale fleet: one **Relay** container plus three
**relay-daemon** containers that auto-enroll over
CA-pinned mTLS and are drivable through the control plane (MCP + `/api/v1`).
It exists to demo and dogfood the real control path end to end. The nine-Node `demo`
compose profile built on top of it has its own runbook — see
[The demo profile](#the-demo-profile).

Both fleets are `docker-compose.demo.yml` at the repository root, and every command below
names it with `-f` (the `make dev-fleet-*` targets do it for you). There is deliberately no
`docker-compose.yml` at the root, so a bare `docker compose up` there does nothing. The
single-Relay deployment stack, with no relay-daemons and no fixtures, is
`deploy/compose/docker-compose.yml`, documented in
[Running it with Docker Compose](operations/relay-install.md#7-running-it-with-docker-compose)
— and it must never run on a machine that holds a development checkout like this one.

> **DEV-ONLY — no production posture.** This environment ships committed
> credentials and a fixture Policy for convenience, runs everything on one host,
> and makes no availability, isolation, or hardening claims. It is **not** a
> deployment guide. The real deployment story is
> [docs/operations/relay-install.md](operations/relay-install.md) and
> [docs/operations/relay-daemon-install.md](operations/relay-daemon-install.md).
> Never reuse the credentials or Policy below anywhere real. The published
> ports (`7654`, `9443`) are bound to `127.0.0.1` by default: the control plane
> accepts a committed dev credential, so exposing it on the LAN would be remote
> code execution for anyone on your network. `RELAY_PUBLISH_ADDR=0.0.0.0` opts the
> control plane (`9443`) in to being exposed anyway, and the `console-password`
> service then refuses the committed default password: set a real
> `CONSOLE_ADMIN_PASSWORD` first, or the Console cannot be signed in to. The node
> plane (`7654`) has its own `RELAY_NODE_PUBLISH_ADDR`, needed only by a
> relay-daemon outside this compose project. For
> the hardened production posture, see
> `daemon/packaging/relay-daemon.service` and
> [docs/operations/daemon-privilege-posture.md](operations/daemon-privilege-posture.md).

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
| `daemon-4..9` (`demo` profile) | Six more relay-daemons, started only with `--profile demo`. See [The demo profile](#the-demo-profile). |

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
  $ docker compose -f docker-compose.demo.yml run --rm --no-deps --entrypoint sh credential \
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
environment before `docker compose -f docker-compose.demo.yml up`.

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
$ docker compose -f docker-compose.demo.yml up --build -d
```

The Relay starts and creates its CA; `bootstrap` waits for the control API, mints
the token, and exports the CA cert; then the daemons enroll and go healthy.

```console
$ docker compose -f docker-compose.demo.yml ps
```

Wait until `daemon-1`, `daemon-2`, and `daemon-3` are `healthy` (each becomes
healthy only after it has persisted its identity, i.e. after a successful
enrollment).

> **Troubleshooting.** The Relay healthcheck completes a TLS 1.3 handshake with
> both listeners using `openssl s_client`, verified against the Relay's CA. If it
> never passes, `bootstrap` never starts and no daemon enrolls — check
> `docker inspect --format '{{json .State.Health}}' <relay container>` and
> `docker compose -f docker-compose.demo.yml logs relay`.

## Verify N enrolled Nodes

**Quick check (no MCP client needed).** The Relay logs every enrollment:

```console
$ docker compose -f docker-compose.demo.yml logs relay
```

You should see three Nodes join, each stamped
`relay:env=dev` / `relay:fleet=dev`.

**Richer check — list the fleet registry over MCP.** The `list_nodes` tool
returns each Node's `node_labels`, `relay_labels`, and reported
`policy_fingerprint` — the full registry view the quick log check doesn't show.
Use the MCP client setup from [Connecting Claude Code](#connecting-claude-code)
below (it exports the CA cert and credentials first), then call:

```
list_nodes()
```

The result is a `nodes` array with three entries,
each carrying its `node_id`, `node_labels`, `relay_labels` (including
`relay:env=dev` / `relay:fleet=dev`), and `policy_fingerprint`. `node:` and
`relay:` labels come back as separate maps
— never merged — so you can always tell which namespace a label was set from
(ADR-0006). Pass an optional `selector` to filter, e.g.
`list_nodes(selector="relay:env=dev")`.

## Drive the fleet over MCP

### Connecting Claude Code

The control plane's server certificate has a single SAN: `relay`, the in-fleet DNS name,
not `localhost`. So dial it by that name and TLS verifies against the fleet's own CA
(`.dev-fleet/ca-cert.pem`) with no `-k` and no disabled verification. Map the name to
loopback once:

```console
$ grep -q 'relay$' /etc/hosts || echo '127.0.0.1 relay' | sudo tee -a /etc/hosts
```

`make dev-fleet-creds` exports the CA cert and both control-plane credentials (founding
admin and `dev-approver`) to the gitignored `./.dev-fleet/`, for MCP and `/api/v1` alike.
Run it, then add the server. `NODE_EXTRA_CA_CERTS` is what makes Claude Code's Node TLS
stack trust the fleet's private CA:

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
This section covers the dev fixture only; the operator-facing account of gates — rule
schema, webhook, decision endpoint — is
[docs/operations/approval-gates.md](operations/approval-gates.md). The nine-Node demo fleet
runs a different, in-band gate (`docker/fixtures/approval-gates.demo.json`), selected by
`scripts/demo-fleet.sh`; see
[The human approver](operations/demo-fleet.md#the-human-approver) in its runbook. That nothing
else selects it is a convention, not an enforced property: `docker-compose.demo.yml` reads the selector,
`DEV_FLEET_APPROVAL_GATE_CONFIG`, from the caller's shell or a repo-root `.env`, so if either
sets it, `make dev-fleet-up` starts this fleet on the demo fleet's in-band gate. Check that
neither does.
Two rules:

| Rule | Matches | Requires |
| --- | --- | --- |
| `dev-fleet-wide-mutates-need-a-human` | `mutate` class, fan-out **≥ 2** | 1 approval from `dev-approver`, out-of-band |
| `dev-raw-exec-always-needs-a-human` | every Raw Exec | 1 approval from `dev-approver`, out-of-band |

The fan-out threshold is deliberate: it leaves **both** paths reachable in one fleet. A
mutate that resolves to a single Node runs straight through; the same mutate aimed
fleet-wide parks. In this three-Node fleet, `node:role=db` is one Node and runs straight
through, while `relay:env=dev` (three) waits for a human. The counts differ under the
`demo` profile, where `node:role=db` parks too; read its runbook before presenting (see
[The demo profile](#the-demo-profile)).

Security-relevant choices, made explicit:

- **The gate is Relay configuration, not a runtime object.** It is baked into the image
  `--chmod=0644`, root-owned, and read from `RELAY_APPROVAL_GATE_CONFIG`. No Account of
  any role can read or loosen it through the API (invariant 11) — a stolen credential that
  could edit its own approval requirements would make the whole mechanism decorative.
- **Loading it is fail-closed.** A malformed, missing, symlinked, or group/world-writable
  gate file fails Relay startup. It never degrades to "nothing needs approval", so a
  broken fixture crash-loops the container instead of quietly disarming the fleet. (If you
  edit the fixture and the `relay` container stops going healthy, read
  `docker compose -f docker-compose.demo.yml logs relay` — the loader says exactly what it objected to.)
- **`requester_allowed` is unset, which is the strict default.** The Account that requested
  a parked dispatch may **not** approve it. That is why `dev-approver` exists: with a
  single Account the fleet could park a dispatch and never release it.
- **`dev-approver`'s credential is on the `control-credential` volume**, which daemons
  never mount. An approver credential readable by every Node would let a compromised Node
  approve its own remediation.

### Approving a parked dispatch

With both credentials exported by `make dev-fleet-creds` (see
[Connecting Claude Code](#connecting-claude-code)), a gated call comes back as a `pending_approval` **result** (not an error) carrying a
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

## Mutates that really run — and where they cannot

### The fixture limit, stated plainly

There is no service manager and no package manager on `busybox:stable-musl`. `pkg.install`
cannot complete on any Node, and `service.restart` cannot complete on any Node that does not
run the demo service (the `role=db` and `role=bastion` Nodes): it terminates in
`outcome=failure` with `stderr="spawn systemctl: No such file or directory"` and **no
`exit_code` key** — the documented contract for a Task that never ran a process, not a
defect (see [issue #389](https://github.com/Felag-Engineering/gleipnir-relay/issues/389)).

On the `role=web` Nodes, `service.restart` **does** run, through a DEV-ONLY `systemctl`
shim (`docker/fixtures/systemctl-shim`). The image bakes it off the `PATH`, and
`docker/daemon-entrypoint.sh` links it to `/usr/local/bin/systemctl` only on the Nodes that
run the demo service, so the daemon's fixed `systemctl restart <unit>` argv reaches
`/usr/local/bin/dev-fleet-service restart` there and nowhere else. The unit name is
ignored — there is one service on these Nodes — and Policy still decides which units may be
asked for (`nginx` and `php-fpm` on the web fixture). The shim fakes nothing about the
outcome: the exit code is `dev-fleet-service`'s own, taken from a live HTTP probe of the
restarted `httpd` ([The real service](#the-real-service), below), so a restart that fails
still reports failure. What it stands in for is the service manager, not the result — the
line the fixture has always drawn is that a dev fleet must never report success it did not
observe. The Raw Exec `systemctl` allow in the web and db fixtures names
`/usr/bin/systemctl`, which still does not exist, so that allow stays inert.

`service.restart sshd` remains the deterministic **deny** beat below and never needed
`systemctl` to exist — the daemon refuses before it execs.

### The real service

`busybox httpd` serves a real docroot on `127.0.0.1:8080`
(`/srv/dev-fleet-service/www/index.html`), started by `docker/daemon-entrypoint.sh` on the
Nodes labelled `node:role=web` (`daemon-1`, `daemon-2`), and managed by the root-owned
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

Use `raw_exec(selector=…, argv=[…])` for this — **never `run_operation` with the Template
pack's `svc.*`**, since those are not dispatchable yet (see below). The one other working
mutate is `service.restart` on the web Nodes, through the shim described in
[The fixture limit, stated plainly](#the-fixture-limit-stated-plainly).

Preflight without dispatching:

```
raw_exec(selector="relay:env=dev", argv=["/usr/local/bin/dev-fleet-service","status"], plan=true)
```

returns per-Node verdicts allow/allow/deny — no parking, no execution.

The repair:

```
raw_exec(selector="relay:env=dev", argv=["/usr/local/bin/dev-fleet-service","restart"])
```

returns a `pending_approval` result (every Raw Exec parks under
`dev-raw-exec-always-needs-a-human`) carrying `request_id` and `plan_hash`. Approve it as
`dev-approver` with the decision call in
[Approving a parked dispatch](#approving-a-parked-dispatch) (a `reason` such as
`"repair the dev-fleet demo service"`), then **re-issue the same `raw_exec` call
unchanged**. Expect **two Nodes** `outcome=success, exit_code: 0` and **daemon-3**
`outcome=denied_by_policy`. The verdict is the daemon's, never the Relay's (ADR-0002 /
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
of band (see [The fault, and resetting between takes](operations/demo-fleet.md#the-fault-and-resetting-between-takes)
in the demo runbook). The script has no `stop` subcommand and the
Policy has no allow for one, so both layers say the same thing.

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
the fleet, because `daemon-3` now loads a different Policy file — the registry's
drift signal, visible for real.

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
$ docker compose -f docker-compose.demo.yml down
$ docker compose -f docker-compose.demo.yml up -d
```

The CA and the SQLite store persist on `relay-data`, and each daemon's identity
persists on its private `daemonN-state` volume, so the Nodes come back with the
**same** `node_id`s and do not re-enroll (enrollment is idempotent — a daemon
with a persisted identity reuses it). `docker compose -f docker-compose.demo.yml logs relay` after the
restart shows reconnects, not a fresh enrollment storm.

To wipe everything (CA, identities, store) and start clean:

```console
$ docker compose -f docker-compose.demo.yml down -v
```

## Where to read the audit trail

Every dispatch, refusal, and Policy preflight is audited. Each such decision emits exactly
one structured log line — carrying the principal, selector, operation/action
kind, outcome counts, and job ID — to the Relay's logs:

```console
$ docker compose -f docker-compose.demo.yml logs -f relay
```

The durable, full record — including per-Node output — lives only in the
Relay's SQLite store on the `relay-data` volume; the log lines deliberately
omit operation args, raw-exec argv, and captured Stdout/Stderr, so they are a
summary, not a substitute for the store.

A dedicated audit **read** surface (an API/MCP route to query the trail) does not
exist yet — it is future work. For now the logs and the store are the trail.

## The demo profile

The nine-Node `demo` compose profile — its roster, the four beats, the injected fault and
`make demo-reset`, and resource usage — has a runbook of its own:
[docs/operations/demo-fleet.md](operations/demo-fleet.md). It runs as its own fixed
`relay-demo` compose project, so start, stop, reset and clean it up with that runbook's
`make demo-*` targets and commands — never a bare `docker compose -f docker-compose.demo.yml --profile demo …`, which
names its project after the checkout directory rather than `relay-demo`. It is purely
additive to the fleet above (`demo_profile_is_additive`, `daemon/tests/dev_fleet_fixtures.rs`,
enforces this), and everything in this document's DEV-ONLY banner applies to it with more
force, not less: three times the Nodes sit behind the same committed dev credential. That
runbook's [Presenter runbook](operations/demo-fleet.md#presenter-runbook) section is what a
presenter who has never run this fleet follows from cold to on stage, including
[minting Gleipnir's credentials](operations/demo-fleet.md#credentials-for-gleipnir-copy-paste)
and [the scripted bypass beat](operations/demo-fleet.md#the-bypass-beat-scripted-exactly).

## Scaling the fleet

Each daemon needs its **own** state volume for a stable per-Node identity across
restarts, so daemons are explicit services rather than replicas. To add a Node,
copy a `daemon-N` service block (bump the name, `HOSTNAME`, and its
`daemonN-state` volume, and register the new volume under `volumes:`). That copy
silently inherits `RELAY_POLICY_PATH` and a `role=` label, both of which must
be chosen deliberately — `policy.web.toml` + `role=web` to get the demo
service and the repair allow, `policy.db.toml` + `role=db` to get neither,
or `policy.bastion.toml` + `role=bastion` to get neither and nothing else
either — see [The nine-Node roster](operations/demo-fleet.md#the-nine-node-roster) for the worked example of
exactly this copy, done six times.

**A new service must declare `profiles: ["demo"]`** (or whichever profile is
appropriate) **or it changes the default fleet** — a plain `docker compose -f docker-compose.demo.yml up`
picks up every service that omits a `profiles:` key.
`demo_profile_is_additive` (`daemon/tests/dev_fleet_fixtures.rs`) fails the
build if a new service forgets it.

## Cleanup

```console
$ docker compose -f docker-compose.demo.yml down -v
$ rm -rf ./.dev-fleet
```

This cleans up the three-Node fleet only; the demo fleet's cleanup is in its runbook's
[Start from a clean registry](operations/demo-fleet.md#start-from-a-clean-registry).
