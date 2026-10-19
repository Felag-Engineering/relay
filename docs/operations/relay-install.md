# Installing and running the Relay

How to stand up the Relay — the central Go server — in a clean environment, from a
published release artifact. Companion documents:
[relay-daemon-install.md](relay-daemon-install.md) for the Node side,
[enrollment.md](enrollment.md) for joining Nodes to the fleet,
[ca-disaster-recovery.md](ca-disaster-recovery.md) for the CA the Relay hosts, and
[release-artifacts.md](release-artifacts.md) for the artifact naming and
verification contract this document consumes.

Sections 1–6 are the recommended path: a verified binary under the hardened systemd unit.
[Section 7](#7-running-it-with-docker-compose) is a second path, for evaluation and a single
home-lab host — `deploy/compose/docker-compose.yml` — and says plainly what it keeps
of that posture and what it does not.

## 1. Obtain and verify the artifact

Releases publish `relay-<version>-x86_64-unknown-linux-gnu` and
`relay-<version>-aarch64-unknown-linux-gnu` (statically linked; the `gnu` triple is kept
for naming stability), plus a signed `SHA256SUMS` file. Follow the **verify-then-install** sequence from
[release-artifacts.md](release-artifacts.md) — the digest check happens **before**
the binary is installed or executed, and a mismatch aborts. The full sequence,
including `cosign verify-blob` on `SHA256SUMS` and the optional
`gh attestation verify`, is in release-artifacts.md; the commands below are its
checksum core:

```sh
# Pinned by the operator — never resolved at install time. Substitute the
# release you are installing: the published tag without its leading `v`
# (see release-artifacts.md).
VERSION="X.Y.Z"
ARTIFACT="relay-${VERSION}-x86_64-unknown-linux-gnu"
BASE="https://github.com/Felag-Engineering/relay/releases/download/v${VERSION}"

curl -fsSLO "${BASE}/${ARTIFACT}"
curl -fsSLO "${BASE}/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS   # verify BEFORE install; failure is fatal
install -m 0755 "${ARTIFACT}" /usr/local/bin/relay
/usr/local/bin/relay --version                  # must self-identify as the pinned version
```

`relay --version` (also `-version` and `-V`, identical to relay-daemon's spellings)
prints the build stamp — see [version-stamping.md](version-stamping.md).

The release binary is built with `CGO_ENABLED=0`, so it uses Go's pure resolver: it reads
`/etc/hosts` and `/etc/resolv.conf` directly and ignores NSS modules configured in
`/etc/nsswitch.conf` (LDAP, mDNS and the like). A hostname the Relay itself resolves — an
OAuth issuer, a webhook host — must be resolvable through DNS or `/etc/hosts`.

## 2. Configuration surface

The Relay is configured by CLI flags with `RELAY_`-prefixed environment-variable
overrides (env wins when set). There is **no config file yet**: ADR-0010/0012 call
for a root-owned config file for the security-sensitive values (blast caps,
minimum daemon version, listener addresses); the current flags+env mechanism is a
documented interim — the security property that matters (set only at startup, never
settable via any API, invariant #11) holds either way. All flags from
`relay/cmd/relay/main.go`; `relay/packaging/relay.env.example` documents the same surface
as an `EnvironmentFile`, with the reasoning behind each setting:

| Flag | Env override | Default | Meaning |
|---|---|---|---|
| `-addr` | `RELAY_ADDR` | `:7654` | Node-plane gRPC listen address (mTLS; daemons dial this). |
| `-ca-dir` | `RELAY_CA_DIR` | `./ca-data` | Directory for the Relay-hosted CA key and certificate (created on first start; see [ca-disaster-recovery.md](ca-disaster-recovery.md)). |
| `-store-path` | `RELAY_STORE_PATH` | `./relay-data/relay.db` | SQLite store: registry, Jobs/Tasks, audit trail, Enrollment Tokens, Freeze state. |
| `-hostname` | `RELAY_HOSTNAME` | `localhost` | Hostname placed in the server certificate SAN. **Must match the name daemons dial** (`RELAY_ADDR`/`RELAY_DOMAIN` on the Node side) or their TLS verification fails. |
| `-enroll-ip-rate` | `RELAY_ENROLL_IP_RATE` | `5` | Per-IP enrollment rate (tokens/min). |
| `-enroll-ip-burst` | `RELAY_ENROLL_IP_BURST` | `3` | Per-IP enrollment burst capacity. |
| `-enroll-global-rate` | `RELAY_ENROLL_GLOBAL_RATE` | `50` | Global enrollment rate (tokens/min). Raise temporarily for a large bulk enrollment. |
| `-enroll-global-burst` | `RELAY_ENROLL_GLOBAL_BURST` | `10` | Global enrollment burst capacity. |
| `-enroll-max-tracked-ips` | `RELAY_ENROLL_MAX_TRACKED_IPS` | `100000` | Cap on the per-IP rate-limit bucket map. |
| `-max-nodes` | `RELAY_MAX_NODES` | `110000` | Registry insert cap (`0` = unlimited). |
| `-read-blast-cap` | `RELAY_READ_BLAST_CAP` | `10000` | Blast-radius cap for `read`-class Operations (max Nodes per Job; ADR-0004/0012). |
| `-mutate-blast-cap` | `RELAY_MUTATE_BLAST_CAP` | `100` | Blast-radius cap for `mutate`-class Operations and Raw Exec. |
| `-dispatch-concurrency` | `RELAY_DISPATCH_CONCURRENCY` | `16` | Max Tasks of one Job dispatched at once. Bounds how fast a Job reaches its Nodes, not how many (that is the blast cap). Must be at least 1; 0 refuses startup. Cancel is best-effort (ADR-0013): a cancel withholds a Task of the Job whose send has not begun, but a Task already being sent can still run, and so can a Task a reconnecting Node's reconciliation sent first (#943). |
| `-min-daemon-version` | `RELAY_MIN_DAEMON_VERSION` | *(empty)* | Minimum relay-daemon semver (ADR-0014). Empty disables the `outdated` gate; a malformed value refuses startup. See [iac-upgrades.md](iac-upgrades.md), and the prerelease caveat in [release-artifacts.md](release-artifacts.md) (#261). |
| `-cert-expiring-fraction` | `RELAY_CERT_EXPIRING_FRACTION` | `0.25` | Fraction of a Node identity certificate's validity remaining below which `state:cert-expiring` fires (ADR-0034). Must be in `(0, 1]` — there is no off value; a value outside it refuses startup. |
| `-control-enabled` | `RELAY_CONTROL_ENABLED` | `false` | Enable the control-plane listener (MCP + `/api/v1` + `/metrics`). |
| `-control-addr` | `RELAY_CONTROL_ADDR` | `:9443` | Control-plane HTTPS listen address (distinct from `-addr`). |
| `-oauth-issuer` | `RELAY_OAUTH_ISSUER` | *(empty)* | OIDC issuer for human MCP sessions (ADR-0024). Empty disables OAuth; set, it makes `-oauth-audience` and `-oauth-public-url` required and discovery run at startup. See [control-plane-credential.md](control-plane-credential.md). |
| `-oauth-audience` | `RELAY_OAUTH_AUDIENCE` | *(empty)* | This Relay's OAuth resource identifier, checked against each token's `aud`. |
| `-oauth-public-url` | `RELAY_OAUTH_PUBLIC_URL` | *(empty)* | Externally-reachable control-plane base URL, used to advertise protected-resource metadata. |
| `-oauth-account-claim` | `RELAY_OAUTH_ACCOUNT_CLAIM` | `email` | Token claim naming the Account a session resolves to. |
| `-oauth-required-scope` | `RELAY_OAUTH_REQUIRED_SCOPE` | *(empty)* | Scope every OAuth token must carry. |
| `-approval-gate-config` | `RELAY_APPROVAL_GATE_CONFIG` | *(empty)* | Path to the root-owned approval-gate rules — which dispatches must wait for a human (ADR-0027; [approval-gates.md](approval-gates.md)). Empty disables approval gating. A configured path that cannot be loaded **refuses startup** rather than coming up with an empty rule set. |
| `-approval-webhook-url` | `RELAY_APPROVAL_WEBHOOK_URL` | *(empty)* | HTTPS endpoint notified (fire-and-forget) when a dispatch parks for approval. Empty disables notification. Decisions never arrive this way — they land on `/api/v1`. |
| `-approval-webhook-secret-file` | `RELAY_APPROVAL_WEBHOOK_SECRET_FILE` | *(empty)* | Path to a root-owned file holding the shared secret that signs approval webhook bodies (HMAC-SHA256). A path, never the secret itself; a world-readable file refuses startup. Empty sends unsigned notifications. |
| `-approval-webhook-timeout` | `RELAY_APPROVAL_WEBHOOK_TIMEOUT` | `5s` | Total time budget for one approval webhook delivery attempt. |
| `-console-enabled` | `RELAY_CONSOLE_ENABLED` | `false` | Serve the Admin Console on the control-plane listener (ADR-0009, ADR-0026); requires `-control-enabled`. Humans sign in with a password held as an argon2id hash in the store — the first admin's is set by `relay init` (below). |
| `-console-session-max-age` | `RELAY_CONSOLE_SESSION_MAX_AGE` | `12h` | Absolute lifetime of a Console session; never extended by activity. |
| `-console-session-idle` | `RELAY_CONSOLE_SESSION_IDLE` | `30m` | Idle timeout of a Console session. |
| `-console-step-up-window` | `RELAY_CONSOLE_STEP_UP_WINDOW` | `5m` | How recently a human must have re-entered their password for a privilege-granting Account act to proceed without being asked again. Maximum `15m`: a larger value is clamped, with a startup warning. Sign-in alone does not satisfy it. A successful step-up rotates the session identifier. Startup-only, like everything here: no Account of any role can extend it through any API. |

**Blast caps and the minimum daemon version.** The two blast-radius caps are startup-only:
`-read-blast-cap` / `RELAY_READ_BLAST_CAP` defaults to 10000, deliberately generous, and
`-mutate-blast-cap` / `RELAY_MUTATE_BLAST_CAP` defaults to 100, deliberately small. Raw Exec
always takes the mutate cap. The minimum-daemon-version gate has the same shape:
`-min-daemon-version` / `RELAY_MIN_DAEMON_VERSION` (semver, empty means off) flags any
connected Node whose reported daemon version is below it as `outdated` in the registry
([ADR-0014](../adr/0014-daemon-lifecycle-iac-upgrades-version-gate.md)). Like the rest of the
Relay's configuration today, these are resolved once from flags and environment at process
start; nothing sets or raises them through an API.

Subcommands (checked before flag parsing):

- `relay --version` / `-version` / `-V` — print the build stamp and exit.
- `relay init [--config <path>] [--ttl <duration>] --admin <name>` — create the first admin, once the Relay has
  started and created its store: a human `admin` Account with the name you give, its Console
  password (prompted for, not echoed) and its first API Token, printed to stdout once. This is
  how you obtain the first control-plane credential; there is none in Relay configuration
  ([control-plane-credential.md](control-plane-credential.md), ADR-0023, ADR-0030). Run it as
  the Relay's own account (`sudo -u relay relay init …`): it reads the configuration through
  the same start-time check as the Relay, so it refuses root. On a Relay that already has a
  human Account it creates nothing, prints no credential, and says what is there. The Console
  password it sets is the only one any surface sets, and nothing resets it: a forgotten Console
  password cannot be recovered.
- `relay init [--config <path>] [--ttl <duration>] --recover <name>` — mint a new API Token for
  an enabled human `admin` who has lost theirs, audited. It never touches the Console password.
  It refuses a disabled, non-admin or machine Account. Safe to run while the Relay is running.
- `--ttl` sets the lifetime of the token either form mints, e.g. `24h`; the default is no expiry.

## 3. First start

On first start the Relay creates its CA in `-ca-dir` (directory `0700`;
`ca-key.pem` `0600`, `ca-cert.pem` `0644`) and issues itself a server certificate
for `-hostname`. Both listeners chain to this CA:

- **Node plane** (`-addr`): gRPC over mTLS. Daemons authenticate the Relay against
  the pinned CA bundle; the Relay requires a client certificate for every RPC
  except the certless `Enrollment.Enroll` (ADR-0005/0006).
- **Control plane** (`-control-addr`, when enabled): HTTPS serving the MCP surface
  at `/mcp`, the Control API at `/api/v1`, and Prometheus metrics at `/metrics`.
  The Control API and MCP authenticate every call by a per-Account API Token (or, for
  humans, an OAuth session when `-oauth-issuer` is set) — there is no shared
  credential in Relay configuration (ADR-0023;
  [control-plane-credential.md](control-plane-credential.md)). Its server certificate also chains to
  the Relay CA, so API/MCP clients need `ca-cert.pem` as their trust anchor (e.g.
  `curl --cacert`).

A minimal production start, with durable paths:

```sh
relay \
  -addr :7654 \
  -hostname relay.example.internal \
  -ca-dir /var/lib/relay/ca \
  -store-path /var/lib/relay/relay.db \
  -control-enabled \
  -control-addr :9443
```

Verify it is up (`$RELAY_TOKEN` is an API Token minted per
[control-plane-credential.md](control-plane-credential.md); there is no credential until
you mint one):

```console
$ curl --cacert /var/lib/relay/ca/ca-cert.pem \
    -H "Authorization: Bearer $RELAY_TOKEN" \
    https://relay.example.internal:9443/metrics | head
```

## 4. The packaged systemd unit

The repository ships a hardened unit for the Relay in `relay/packaging/`:
`relay.service`, an example `EnvironmentFile` (`relay.env.example`) covering the
whole configuration surface above, and a README with the install and enable steps
(landed in #362). Use that, not a hand-written unit; the Node-side counterpart is
`daemon/packaging/relay-daemon.service`. The Relay does not need root: it needs
write access to its CA directory and store, and the ability to bind its two ports,
and the packaged unit takes everything else away (empty capability bounding set,
`NoNewPrivileges`, read-only filesystem apart from its state directory).

The unit reads `/etc/relay/relay.env` (`0640 root:relay`), which holds no secret
*values* — every credential is a file path — but does hold the security floor
(invariant 11): whoever can edit it can lower that floor at the next restart.

The packaged unit's directives are reproduced below with its comments stripped. The
comments carry the reasoning for each setting, so install the packaged file, not a copy
of this block.

```ini
[Unit]
Description=Relay (fleet-administration control plane)
Documentation=file:///usr/share/doc/relay/relay-install.md
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=relay
Group=relay
ExecStart=/usr/local/bin/relay
EnvironmentFile=-/etc/relay/relay.env
Restart=on-failure
RestartSec=5s
StateDirectory=relay
StateDirectoryMode=0700
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictSUIDSGID=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
SystemCallArchitectures=native
RestrictAddressFamilies=AF_INET AF_INET6
TasksMax=512

[Install]
WantedBy=multi-user.target
```

Install per `relay/packaging/README.md`, then:

```console
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now relay
$ systemctl status relay
```

The control plane comes up with no Account and no usable credential until you create the
first admin. Run `sudo -u relay relay init --admin <your-name>` on this host: it prompts for
that admin's Console password and prints its first API Token. Switch your callers to
credentials of their own — see [control-plane-credential.md](control-plane-credential.md).

## 5. Operational levers on the Relay host

- **Freeze (ADR-0013).** The Relay-wide emergency stop has a local, host-side
  lever: `kill -USR1 <relay-pid>` engages the Freeze (cheap, no reason required);
  `kill -USR2 <relay-pid>` releases it, recording an audited reason (from
  `RELAY_FREEZE_RELEASE_REASON` if set, else a default). Both are also available
  over the Control API (`POST /api/v1/freeze/engage`, `POST /api/v1/freeze/release`
  — release requires a non-empty `reason`). Freeze state persists across Relay
  restarts.
- **Registry as upgrade dashboard.** With `-min-daemon-version` set, below-minimum
  Nodes still connect and heartbeat but are flagged `outdated` and refused
  dispatch per-Task (ADR-0014) — see [iac-upgrades.md](iac-upgrades.md).
- **Backups.** Two things on this host are worth backing up: the CA key
  ([ca-disaster-recovery.md](ca-disaster-recovery.md)) and the store
  (`-store-path`), which holds the registry, audit trail, and token/revocation
  state.

## 6. What the Relay can never do

Worth restating for anyone operating it (these are the architecture invariants,
not configuration choices): the Relay never modifies a Node's Policy over the wire
(ADR-0002), never pushes binaries to Nodes (ADR-0014), and its own configuration
is never reachable through the Control API (ADR-0010) — the API cannot raise blast
caps, lower the minimum daemon version, or touch the listeners.

## 7. Running it with Docker Compose

[`deploy/compose/docker-compose.yml`](../../deploy/compose/docker-compose.yml) runs the
Relay and nothing else: one service and one data volume. There are no relay-daemons, helper
containers, fixtures or credentials. It is written to be deployed from a git checkout, by hand
or by a tool that deploys compose stacks from git (Komodo, for example).

Read these statements before anything else in this section:

- **It is a second path beside the systemd unit in [section 4](#4-the-packaged-systemd-unit),
  not a replacement for it.** ADR-0033 (decision 5) makes the container the evaluation
  artifact and the hardened unit the recommended production deployment; this stack does not
  change that. The table below is the difference.
- **It is one host with no high-availability claim.** One container, one volume. If the host
  or the volume is lost, the Relay is down: Nodes keep running, but nothing can be dispatched
  to them, and a lost CA means re-enrolling the fleet
  ([ca-disaster-recovery.md](ca-disaster-recovery.md)).
- **No human has yet reviewed it as hardened.** It mirrors the unit's posture where Docker can
  express it, as listed below; that is a description, not a review.
- **Never run it on a host that also holds a development checkout of this repository** — a
  clone or any of its git worktrees. Every checkout carries this same file with the same
  project name, `relay`, so a routine `docker compose -f deploy/compose/docker-compose.yml up
  --build` in *any* of them resolves to the running deployment and replaces it with that
  checkout's work in progress. The data volume is external (step 1), so no `down -v` can
  delete the CA and store, but nothing stops the replacement. The deployment host holds one
  checkout, at the pinned commit you deploy, and nothing else.

It is not the dev fleet. The three-Node dev fleet and the nine-Node demo fleet are
`docker-compose.demo.yml` at the repository root ([dev-fleet.md](../dev-fleet.md)); nothing in
this stack refers to their fixtures, their gates or their committed dev credentials. There is
deliberately no `docker-compose.yml` at the repository root.

### What it keeps of the packaging posture, and what it does not

| Property of `relay/packaging/` | In this stack |
| --- | --- |
| Runs as an unprivileged Unix user | **Kept.** The image's `runtime` stage (`docker/relay.Dockerfile`, its last and default stage) runs as UID/GID `10001` (`relay`), never root. |
| Empty capability set, `NoNewPrivileges` | **Kept.** `cap_drop: [ALL]` and `no-new-privileges`. |
| Read-only filesystem apart from its state | **Kept.** `read_only: true`; the state volume and a private `/tmp` tmpfs are the only writable paths. |
| State directory `0700`, owned by the Relay's own Unix user | **Kept.** `/var/lib/relay` is created `0700` and owned by `relay` in the image, and an empty volume takes both on first mount. The CA key inside it is `0600`. |
| `TasksMax=512` | **Kept.** `pids_limit: 512`. No memory limit is set, here or in the unit. |
| Secrets are file paths, never values | **Kept.** The environment file holds none; a secret (the approval webhook's signing key) is a host file bind-mounted read-only. |
| Configuration set by the operator on the host, unreachable from any API (invariant 11) | **Not kept under a git-driven deploy.** No Relay API reaches it, but the deploy path does. Whoever can push to the branch a deploy tool tracks, or use that tool's interface, controls the published ports, the settings the compose file pins, the image that gets built, and `RELAY_ENV_FILE` — so they can point the Relay at a different environment file, one that sets a hostile `RELAY_OAUTH_ISSUER`, on the next deploy. `.env` files are git-ignored so that none can be committed by accident, but that stops an accident, not a push. Deploy a **pinned commit**, with **auto-deploy webhooks off**, and treat write access to that branch and to the deploy tool (Komodo included) as **root on the Relay host**. |
| Root-owned unit file | **Not kept.** The compose file lives in the checkout; see the row above. |
| Root-owned `EnvironmentFile` read only by the service | **Partly.** The file is read by `docker compose` on the host, as whoever runs it, and its values then sit in the container's environment, where anyone in the `docker` group can read them with `docker inspect`. That is why it must hold no secret — and note that `RELAY_APPROVAL_WEBHOOK_URL` may itself be a capability URL (a webhook endpoint whose path is its secret); if yours is, it is exposed the same way. Membership of the `docker` group is root-equivalent anyway. |
| The unit's finer sandboxing (`SystemCallFilter=@system-service`, `ProtectKernel*`, `MemoryDenyWriteExecute`, `RestrictAddressFamilies`, `ProtectProc`) | **Not claimed.** Docker's default seccomp profile and namespaces cover some of the same ground; they are not equivalent and nothing here asserts they are. |
| A digest-verified release binary (section 1) | **Not kept yet.** A signed Relay image is published per release (`ghcr.io/felag-engineering/relay`, #892), but the stack still builds the image from the checkout's own source, so what runs is whatever that checkout contains. The compose file switches to the published image, pinned by digest, once the first signed release exists; that is a one-line change. |
| `Restart=on-failure`, enabled at boot | **`restart: unless-stopped`.** Docker's `on-failure` would not bring the Relay back after a host or Docker restart; `unless-stopped` does, and additionally restarts after a clean exit nobody asked for, which the Relay does not make on its own. Neither restarts an *unhealthy* container: watch the health status. |

**Open point for a human: who owns a secret file.** Invariant 11 says a file holding a secret
"must be root-owned and not world-readable". What the code enforces today is the mode only:
the Relay refuses a webhook secret file that is group- or world-accessible, so it must be
`0600` — and a `0600` file is readable only by its owner, so under this stack it must be owned
by UID `10001`, the Relay's user, and under the systemd unit by the `relay` user. Neither is
root-owned. The two candidate answers are (a) amend the invariant's wording to "owned by the
Relay's service user, mode `0600`", which is what both deployments do today, or (b) keep
root ownership and change how the Relay reads secrets — for example `0640 root:relay` with the
code accepting group-read by the Relay's own group, or a root-run step that hands the Relay
the secret. This is not resolved here; the instructions below follow what the code enforces.

### What it exposes

Two ports, and the stack binds them differently on purpose. Both are set by **Compose
interpolation variables** — in the shell that runs `docker compose`, in a `.env` file beside
the compose file (git-ignored), or in a deploy tool's stack environment — **never in the
Relay's environment file**, which Compose does not read for this.

| Port | Default binding | Variable | What is reachable there |
| --- | --- | --- | --- |
| `7654`, the Node plane | `0.0.0.0` (every IPv4 interface) | `RELAY_NODE_PUBLISH_ADDR` | gRPC over mTLS. relay-daemons on other hosts dial it, which is the point of the stack. Every RPC requires a client certificate issued by the Relay's CA except Enrollment, which requires an Enrollment Token and is rate-limited per source address and globally. |
| `9443`, the control plane | `127.0.0.1` (host loopback) | `RELAY_PUBLISH_ADDR` | MCP at `/mcp`, the Control API at `/api/v1`, `/metrics`, and — when enabled — the Admin Console at `/console/`. It is an execution surface for whoever holds an API Token or a Console password. |

**Set a Console password before you publish `9443` beyond loopback.** Nothing enforces that
order — the loopback default only makes it the path of least resistance, and step 5 below is
where it happens. Once `9443` is reachable, anyone on that network can attempt a Console
sign-in: the throttle deliberately has no hard lockout, and the Relay refuses any password
shorter than 12 bytes, so length is what protects it. Choose a long one.

**Do not expose `7654` to the internet** unless you must: the global enrollment bucket is
shared by every source, so anyone who can reach the port can spend it and deny enrollment to
your own Nodes (Nodes already enrolled are unaffected).

Docker publishes ports with its own firewall rules, which take effect **before** host
firewalls such as `ufw` or `firewalld` see the traffic. The bind address is the exposure
control here; a host firewall rule on `7654` or `9443` does not restrict a Docker-published
port. Use **Docker Engine 28 or newer**: before 28.0, a port published on `127.0.0.1` was
reported to be reachable from other hosts on the same layer-2 segment (as reported in Docker's
28.0 release notes; not verified here).

### First run

You need Docker Engine 28+ with Compose **v2.24 or newer**, one checkout of this repository
on the Relay host at the commit you deploy (the image is built from it; see the warning at
the top of this section), and a DNS name for the host that every relay-daemon can resolve.
Run every command below from the checkout root.

**1. Create the data volume.** It is declared `external`, so Compose never creates it and no
`docker compose down -v` can delete it — the CA key and the store live on it:

```console
$ docker volume create relay-data
```

Create it empty. On first start Docker copies the image's `/var/lib/relay` into it, owner
`relay` (UID `10001`) and mode `0700`. To use another name, create that one and set
`RELAY_DATA_VOLUME` the same way as the bind addresses.

**2. Write the environment file.** Start from the same sample the systemd unit uses —
[`relay/packaging/relay.env.example`](../../relay/packaging/relay.env.example), kept complete
by a drift test — rather than a second copy:

```console
$ sudo install -d -m 0755 /etc/relay
$ sudo install -m 0600 relay/packaging/relay.env.example /etc/relay/relay.env
$ sudoedit /etc/relay/relay.env
```

Set `RELAY_HOSTNAME` to the name relay-daemons will dial. It becomes the server certificate's
SAN, so it must be the real name: while it is unset or still the sample's
`relay.example.internal`, the container reports **unhealthy** and
`docker inspect --format '{{json .State.Health}}' <container>` says why. For the Console,
set `RELAY_CONSOLE_ENABLED=true`; it is off unless you do, as under the unit. Everything else
is optional (blast caps, enrollment rate limits, the minimum daemon version, OAuth, approval
gates).

The file is **required**: if it is missing, `docker compose` refuses to start the stack
rather than starting the Relay on defaults with no approval gate, the default blast caps and
no version gate. The sample's `chown root:relay` line is for the systemd unit; here the file
is read by `docker compose`, so keep it `0600` and owned by whoever runs Compose (root, for
most deploy tools). To keep it elsewhere, set `RELAY_ENV_FILE` to an **absolute** path (a
relative one resolves against `deploy/compose/`).

Five settings are **pinned by the compose file and win over the environment file**, because
each is tied to the container's layout — its published ports and its volume:
`RELAY_ADDR`, `RELAY_CONTROL_ENABLED` (on), `RELAY_CONTROL_ADDR`, `RELAY_CA_DIR` and
`RELAY_STORE_PATH` (`/var/lib/relay/relay.db`).

**3. Bring it up:**

```console
$ docker compose -f deploy/compose/docker-compose.yml up -d --build
$ docker compose -f deploy/compose/docker-compose.yml ps   # wait for relay to be (healthy)
```

The Relay creates its CA on first start and logs its fingerprint
(`docker compose -f deploy/compose/docker-compose.yml logs relay`).

**4. Create the first admin** with `relay init`, which runs as the Relay's own account inside
the container: a human `admin` Account named as you choose, its Console password (prompted
for twice, not echoed), and its first API Token — the first control-plane credential
([control-plane-credential.md](control-plane-credential.md), ADR-0030). The token is printed
once and never stored; put it in a vault at that moment, and hold it in `RELAY_TOKEN` for the
rest of this procedure without echoing it:

```console
$ docker compose -f deploy/compose/docker-compose.yml exec relay relay init --admin <your-name>
$ read -rs RELAY_TOKEN     # paste the token printed above
```

Copy out the Relay's **public** CA certificate, which every client and every relay-daemon
pins (never `ca-key.pem`):

```console
$ docker compose -f deploy/compose/docker-compose.yml cp \
    relay:/var/lib/relay/ca/ca-cert.pem ./relay-ca-cert.pem
```

**5. Reach the Console** (only if you enabled it in step 2) as the admin from step 4, with the
password you gave `relay init`. That password is the only Console password any surface sets, and
nothing resets it: if it is forgotten, it cannot be recovered. Other people get their own Account
(`POST /api/v1/accounts`) and an API Token; no surface sets a Console password for them, so they
reach the Console only through OAuth, where it is configured
([control-plane-credential.md](control-plane-credential.md)).

Then, if you want the control plane reachable beyond this host, set `RELAY_PUBLISH_ADDR` to
the host's LAN address (or `0.0.0.0`) and run the `up -d` from step 3 again. Sign in at
`https://<RELAY_HOSTNAME>:9443/console/`. The browser warns about the certificate because it
chains to the Relay's private CA; trust `relay-ca-cert.pem` rather than clicking through.

**6. Mint an Enrollment Token** ([enrollment.md](enrollment.md) explains the scope and its
security meaning — the `relay:` labels it stamps are what the security lane targets). From
the Relay host, with `RELAY_TOKEN` from step 4:

```console
$ curl --cacert relay-ca-cert.pem \
    --resolve <RELAY_HOSTNAME>:9443:127.0.0.1 \
    -H "Authorization: Bearer $RELAY_TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"scope":["relay:env=lab"],"ttl_seconds":86400,"max_uses":10}' \
    https://<RELAY_HOSTNAME>:9443/api/v1/enrollment-tokens
```

`--resolve` dials loopback while TLS still verifies the real name; drop it from any other
host once the control plane is published.

**7. Point real relay-daemons at it**, one host at a time, following
[relay-daemon-install.md](relay-daemon-install.md): `RELAY_ADDR` is
`https://<RELAY_HOSTNAME>:7654`, `RELAY_CA_BUNDLE_PATH` is the `relay-ca-cert.pem` from step
4, and the Enrollment Token from step 6 is used once, at first start. Each Node's Policy is
its own and is authored on that Node; this stack ships none and can never write one
(ADR-0002). Finish with `unset RELAY_TOKEN`.

### Operating it

Every command here takes `-f deploy/compose/docker-compose.yml`, shortened below to `…`.

- **Approval gates are off: nothing needs approval** until you add a gate. The stack ships no
  gate file, because a gate is Relay configuration the operator writes on the host and a
  committed one would live in the checkout instead. To add one, write the rules
  ([approval-gates.md](approval-gates.md)) to a host file owned by root and not group- or
  world-writable, uncomment the gate mount in the compose file, and set
  `RELAY_APPROVAL_GATE_CONFIG=/etc/relay/approval-gates.json` in the environment file. A
  configured gate that cannot be loaded refuses startup rather than running ungated.
- **The approval webhook's signing secret** is a file: mode `0600`, owned by UID `10001` (the
  Relay's user inside the image — a file only root can read is unreadable to it; see the open
  point above), mounted read-only through the commented example in the compose file, and
  named by `RELAY_APPROVAL_WEBHOOK_SECRET_FILE`. Anything looser refuses startup.
- **OAuth** is off unless you set `RELAY_OAUTH_ISSUER` and its companions in the environment
  file ([control-plane-credential.md](control-plane-credential.md#human-sessions-oauth-21-through-your-idp)).
  The issuer is fetched from inside the container at startup, over HTTPS, trusting Alpine's
  public CA bundle, and the Relay never creates an Account from a token (ADR-0024), so create
  each person's Account first. The demo fleet shows the other way to carry these settings — a
  second compose file layered on with `-f`, as `docker-compose.oauth.yml` is — and that
  pattern works the same with a real provider, provided the overlay file lives on the host
  outside the checkout like the environment file does. Do not copy the demo overlay's
  contents: its shared network namespace and plain-HTTP loopback issuer exist only because
  its DEV-ONLY Keycloak runs beside the Relay without TLS.
- **Freeze** (ADR-0013): `docker compose … kill -s USR1 relay` engages it and
  `docker compose … kill -s USR2 relay` releases it, the same host-side lever as
  [section 5](#5-operational-levers-on-the-relay-host).
- **Back up the volume** `relay-data`: it holds the CA key and the store. Compose will not
  delete it; `docker volume rm relay-data` will, and every Node must then re-enroll.
- **Upgrades** are a checkout of the next pinned commit and `docker compose … up -d --build`.
  The Relay never pushes binaries to Nodes (ADR-0014).
- **Project name.** The file sets `name: relay`; a deploy tool's own `-p` overrides it. The
  name does **not** prevent a collision — every checkout of this repository resolves to the
  same project, which is why the deployment host must hold no other checkout. The stack also
  publishes the same host ports as the dev and demo fleets, so only one of the three can run
  on a host at a time.
