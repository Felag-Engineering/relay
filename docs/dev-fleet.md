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
- **The control-plane credential is a DEV fixture.** The plaintext
  `dev-fleet-control-credential` grants full control-plane access. Its SHA-256
  hash is committed at `docker/fixtures/control-credential.hash`; the Relay only
  ever stores the hash (see
  [docs/operations/control-plane-credential.md](operations/control-plane-credential.md)).
  Treat it as public. Never reuse it.

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

Export the CA cert the bootstrap step produced so you can talk to the control
plane (MCP and `/api/v1`) over verified TLS from the host:

```console
$ docker compose cp relay:/var/lib/relay/ca/ca-cert.pem ./dev-fleet-ca.pem
```

The Relay's server certificate SAN is `relay` (the in-fleet DNS name), not
`localhost`. When you connect from the host to `localhost:9443`, either override
the TLS server name to `relay` or, for a quick look, skip verification.

## Drive the fleet over MCP

Point an MCP client at `https://localhost:9443/mcp` with:

- **Bearer credential:** `dev-fleet-control-credential`.
- **TLS trust:** the exported `dev-fleet-ca.pem`, with the server name overridden
  to `relay` (or verification disabled for a quick look).

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

Every dispatch and refusal is audited. Durable audit rows live in the Relay's
SQLite store on the `relay-data` volume, and the decisions are also emitted to
the Relay's logs:

```console
$ docker compose logs -f relay
```

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
$ rm -f ./dev-fleet-ca.pem
```
