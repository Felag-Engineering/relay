# Local dev fleet (`docker compose`)

A one-command, laptop-scale fleet: one **Relay** container plus three
**relay-daemon** containers that auto-enroll over CA-pinned mTLS and are drivable
through the control plane (MCP + `/api/v1`). It exists to demo and dogfood the
real control path end to end.

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
| `daemon-1..3` | Three relay-daemons (Rust, musl static binary). Each has a baked, root-owned Policy fixture and a private state volume, enrolls on first start, and reports health once it has a persisted identity. |

Security-relevant choices, made explicit:

- **Policy arrives with the image, never over the wire (ADR-0002).** The fixture
  Policy (`docker/fixtures/policy.toml`) is `COPY`d into the daemon image, so it
  lands as `root:root 0644` and passes the daemon's fail-closed loader (which
  refuses a group/world-writable Policy, or one owned by a non-root user). The
  Relay can query a Node's Policy fingerprint but can never change the Policy.
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
the token, and exports the CA cert; then the three daemons enroll and go healthy.

```console
$ docker compose ps
```

Wait until `daemon-1`, `daemon-2`, and `daemon-3` are `healthy` (each becomes
healthy only after it has persisted its identity, i.e. after a successful
enrollment).

> **Troubleshooting.** The Relay healthcheck probes its control port with busybox
> `nc -w1`. If your busybox build ships an `nc` without the `-w` (timeout) flag,
> the healthcheck never passes, so `bootstrap` never starts and no daemon enrolls
> — check `docker compose logs relay` for a failing healthcheck.

## Verify N enrolled Nodes

**Quick check (no MCP client needed).** The Relay logs every enrollment:

```console
$ docker compose logs relay
```

You should see three Nodes join, each stamped `relay:env=dev` /
`relay:fleet=dev`.

**Richer check — list the fleet registry over MCP.** The `list_nodes` tool
returns each Node's `node_labels`, `relay_labels`, and reported
`policy_fingerprint` — the full registry view the quick log check doesn't show.
Use the MCP client setup from [Drive the fleet over MCP](#drive-the-fleet-over-mcp)
below (which needs the exported CA cert; see the next step), then call:

```
list_nodes()
```

The result is a `nodes` array with three entries, each carrying its `node_id`,
`node_labels`, `relay_labels` (including `relay:env=dev` / `relay:fleet=dev`),
and `policy_fingerprint`. `node:` and `relay:` labels come back as separate maps
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
fleet-wide parks. So `node:role=db` (one Node) executes, and `relay:env=dev` (three) waits
for a human.

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

`docs/testing/validate-v0.5.1.md` is the script these commands discharge.

## Survive `down` / `up`

```console
$ docker compose down
$ docker compose up -d
```

The CA and the SQLite store persist on `relay-data`, and each daemon's identity
persists on its private `daemonN-state` volume, so the Nodes come back with the
**same** `node_id`s and do not re-enroll (enrollment is idempotent — a daemon
with a persisted identity reuses it). `docker compose logs relay` after the
restart shows reconnects, not a fresh enrollment storm.

To wipe everything (CA, identities, store) and start clean:

```console
$ docker compose down -v
```

## Where to read the audit trail

Every dispatch, refusal, and plan is audited. Each such decision emits exactly
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

## Scaling the fleet

Each daemon needs its **own** state volume for a stable per-Node identity across
restarts, so daemons are explicit services rather than replicas. To add a Node,
copy a `daemon-N` service block (bump the name, `HOSTNAME`, and its
`daemonN-state` volume, and register the new volume under `volumes:`).

## Cleanup

```console
$ docker compose down -v
$ rm -rf ./.dev-fleet
```
