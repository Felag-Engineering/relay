# Installing and running the Relay

How to stand up the Relay, the central Go server, from a published release artifact.
Companions: [relay-daemon-install.md](relay-daemon-install.md) for the Node side,
[enrollment.md](enrollment.md) for joining Nodes,
[ca-disaster-recovery.md](ca-disaster-recovery.md) for the Relay's CA, and
[release-artifacts.md](release-artifacts.md) for artifact naming and verification.

Sections 1–6 are the recommended path: a verified binary under the hardened systemd unit.
[Section 7](#7-running-it-with-docker-compose) is a supported single-host deployment beside
it, `deploy/production/docker-compose.yml` running the signed published image (ADR-0033, amended
2026-10-15). It states what it keeps of that posture and is not called production until its
hardening review has closed (RC-27).

## 1. Obtain and verify the artifact

Releases publish `relay-<version>-linux-amd64` and
`relay-<version>-linux-arm64` (statically linked, no libc dependency), plus a signed
`SHA256SUMS`. Follow the **verify-then-install** sequence in
[release-artifacts.md](release-artifacts.md): the digest is checked **before** the binary is
installed or run, and a mismatch aborts. That document has the full sequence, including
`cosign verify-blob` on `SHA256SUMS` and the optional `gh attestation verify`; this is its
checksum core:

```sh
# Pinned by the operator, never resolved at install time: the published tag without its
# leading `v` (see release-artifacts.md).
VERSION="X.Y.Z"
ARTIFACT="relay-${VERSION}-linux-amd64"
BASE="https://github.com/Felag-Engineering/relay/releases/download/v${VERSION}"

curl -fsSLO "${BASE}/${ARTIFACT}"
curl -fsSLO "${BASE}/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS   # verify BEFORE install; failure is fatal
install -m 0755 "${ARTIFACT}" /usr/bin/relay    # the path relay.service runs
/usr/bin/relay --version                        # must self-identify as the pinned version
```

`relay --version` (also `-version` and `-V`, as for relay-daemon) prints the build stamp; see
[version-stamping.md](version-stamping.md).

The release binary is built with `CGO_ENABLED=0`, so it uses Go's pure resolver: it reads
`/etc/hosts` and `/etc/resolv.conf` and ignores NSS modules in `/etc/nsswitch.conf` (LDAP,
mDNS). A hostname the Relay resolves, such as an OAuth issuer or a webhook host, must resolve
through DNS or `/etc/hosts`.

## 2. Configuration surface

The Relay reads every setting from one root-owned file, `/etc/relay/relay.toml` (ADR-0043),
and none from flags or the environment. `relay --config <path>` names a different file. A
retired `RELAY_*` setting variable that is still set refuses start and names the key that
replaces it. [`relay/packaging/relay.toml.example`](../../relay/packaging/relay.toml.example)
covers every key, with its default and the reasoning; a drift gate keeps it complete.

Three keys are required and have no default: `ca.dir`, `store.path` and `tls.hostname`. An
unknown key, or a value that cannot work, is refused.

| Key | Default | Meaning |
|---|---|---|
| `node_plane.listen_address` | `:7654` | Node-plane gRPC listen address (mTLS; daemons dial this). |
| `node_plane.advertised_address` | `tls.hostname` on the listen port | The address a join string tells a relay-daemon to dial. Its host must be `tls.hostname` or an entry of `tls.extra_names`; the server certificate names it. Set it when daemons reach the Relay through a port mapping or NAT. |
| `control_plane.enabled` | `false` | Enable the control-plane listener (MCP + `/api/v1` + `/metrics`). |
| `control_plane.listen_address` | `:9443` | Control-plane HTTPS listen address. |
| `ca.dir` | *(required)* | Directory for the Relay-hosted CA key and certificate, created on first start ([ca-disaster-recovery.md](ca-disaster-recovery.md)). |
| `store.path` | *(required)* | SQLite store: registry, Jobs/Tasks, audit trail, Accounts, API Tokens, Enrollment Tokens, Freeze state. |
| `tls.hostname` | *(required)* | The name on the one server certificate both listeners present. **Must match the name daemons dial** (or that name must be an entry of `tls.extra_names`), or their TLS verification fails. The certificate also names loopback and this host's addresses at start, so a daemon may dial one of this host's IPv4 addresses instead. It must be a DNS name or an address a daemon can dial: a wildcard, an unspecified, multicast, broadcast or link-local address, or an IPv4-mapped IPv6 one refuses start. |
| `tls.extra_names` | *(unset)* | Further DNS names and IP addresses the server certificate names, at most 32; a wildcard, a malformed entry or an empty list refuses start, naming the entry's position. An internationalised name is written in its `xn--` form. Use it when daemons or a browser reach the Relay by a name other than `tls.hostname`: through a load balancer, under a second DNS name, or at a NAT address. Read only at start: a reload that changes it is refused and a restart applies it. |
| `enrollment.max_nodes` | `110000` | Registry insert cap (`0` = unlimited). |
| `reach.read_blast_cap` | `10000` | Blast-radius cap for `read`-class Operations (max Nodes per Job; ADR-0004, ADR-0012). |
| `reach.mutate_blast_cap` | `100` | Blast-radius cap for `mutate`-class Operations and Raw Exec. |
| `reach.min_daemon_version` | *(unset)* | Minimum relay-daemon semver (ADR-0014). Unset disables the `outdated` gate. See [iac-upgrades.md](iac-upgrades.md) and the prerelease caveat in [release-artifacts.md](release-artifacts.md). |
| `oauth.issuer` | *(unset)* | OIDC issuer for human MCP sessions (ADR-0024). Unset disables OAuth; every other `oauth.*` key needs it. See [control-plane-credential.md](control-plane-credential.md). |
| `oauth.audience` | *(unset)* | This Relay's OAuth resource identifier, checked against each token's `aud`. |
| `oauth.public_url` | *(unset)* | Externally reachable control-plane base URL, used to advertise protected-resource metadata. |
| `oauth.account_claim` | `email` | Token claim naming the Account a session resolves to. |
| `oauth.required_scope` | *(unset)* | Scope every OAuth token must carry. |
| `[[approval.rules]]` | *(none)* | Gate rules, one section per rule: which dispatches wait for a human (ADR-0027, ADR-0047; [approval-gates.md](approval-gates.md)). None means nothing is gated; the packaged configuration and `relay.toml.example` each carry two, gating every `mutate` and every Raw Exec. Delete one to stop gating what it matches. A rule that cannot be loaded **refuses startup**, and so does a configuration still naming `approval.gate_rules_path`. |
| `approval.webhook_url_file` | *(unset)* | Path of a file holding the HTTPS endpoint notified, fire-and-forget, when a dispatch parks for approval. The URL is a secret, so it is only ever given as a file. Decisions never arrive this way; they land on `/api/v1`. |
| `approval.webhook_secret_file` | *(unset)* | Path of a file holding the shared secret that signs webhook bodies (HMAC-SHA256). Unset sends unsigned notifications. |
| `console.enabled` | `false` | Serve the Admin Console on the control-plane listener (ADR-0009, ADR-0026); needs `control_plane.enabled`. The first admin's password is set by `relay init` (below). |
| `console.session_idle` | `30m` | Idle timeout of a Console session. |
| `log.level` | `info` | `debug`, `info`, `warn`, `error`. Logs are always JSON. |

**Built in, not configured.** These values are constants, with no key: Enrollment is limited
to 60 a minute per source address (burst 10), 300 a minute overall (burst 50), and 100000
tracked addresses; `state:cert-expiring` fires at a quarter of a Node certificate's lifetime
(ADR-0034); a Job sends 16 Tasks at once (cancel is best-effort, ADR-0013: it withholds a
Task whose send has not begun, but a Task already being sent can still run, and so can one a
reconnecting Node's reconciliation sent first); a webhook delivery attempt has a 5s budget;
a Console session lasts at most 12h and the step-up window is 5m. A configuration file that
names a key that was removed is refused at start and on reload, naming the key.

A secret is given as `key_file = "/path"`, never inline. At start
the Relay refuses to run if it could write the configuration file or a file it names, or if
any account but itself and root could read the configuration or a secret file. Place secret
files like the configuration, `0640 root:relay`.

**Reload.** `kill -HUP <relay-pid>` re-reads `relay.toml` all-or-nothing. A change to a
setting that needs a restart (listeners, the Console, `ca.dir`, `store.path`,
`tls.hostname`, `tls.extra_names`, `[oauth]`) is refused by name and nothing changes. No API sets or raises any
of these values (invariant 11).

Subcommands, checked before the configuration is read:

- `relay --version` / `-version` / `-V`: print the build stamp and exit.
- `relay init [--config <path>] [--ttl <duration>] --admin <name>`: once the Relay has started
  and created its store, create the first admin: a human `admin` Account with that name, its
  Console password (prompted for, not echoed) and its first API Token, printed to stdout once.
  This is the only way to obtain the first control-plane credential; there is none in Relay
  configuration ([control-plane-credential.md](control-plane-credential.md), ADR-0023,
  ADR-0030). Run it as the Relay's own account (`sudo -u relay relay init …`): it reads the
  configuration through the same start-time check, so it refuses root. On a Relay that already
  has a human Account it creates nothing, prints no credential, and says what is there. The
  password it sets is the first admin's. Every other human gets a temporary password from an
  admin in the Console and changes it at first sign-in; no surface resets a password a human has
  set, so a forgotten one is replaced by disabling the Account and creating a new one.
- `relay init [--config <path>] [--ttl <duration>] --recover <name>`: mint a new API Token for
  an enabled human `admin` who has lost theirs, audited. It never touches the Console password,
  refuses a disabled, non-admin or machine Account, and is safe while the Relay runs.
- `--ttl` sets the lifetime of the token either form mints, e.g. `24h`; the default is seven
  days (`168h`), and `--ttl 0` means no expiry.

## 3. First start

On first start the Relay creates its CA in `ca.dir` (directory `0700`; `ca-key.pem` `0600`,
`ca-cert.pem` `0644`) and issues itself one server certificate, presented on both listeners, for
`tls.hostname`, each `tls.extra_names` entry, loopback and the host's addresses (up to 64, IPv4
first). The packaged unit
permits `AF_NETLINK` for that listing; if the addresses cannot be listed the Relay logs a
warning and the certificate names all of those except the host's addresses. Both listeners chain to this
CA:

- **Node plane** (`node_plane.listen_address`): gRPC over mTLS. Daemons authenticate the Relay
  against the pinned CA; the Relay requires a client certificate for every RPC except the
  certless `Enrollment.Enroll` (ADR-0005, ADR-0006).
- **Control plane** (`control_plane.listen_address`, when enabled): HTTPS serving MCP at `/mcp`,
  the Control API at `/api/v1`, and Prometheus metrics at `/metrics`. Every call except
  `GET /healthz`, which answers only serving or not serving, is
  authenticated by a per-Account API Token, or for humans an OAuth session when `oauth.issuer`
  is set. There is no shared credential in Relay configuration (ADR-0023). API and MCP clients
  need `ca-cert.pem` as their trust anchor (e.g. `curl --cacert`).

A minimal production `relay.toml`:

```toml
[node_plane]
listen_address = ":7654"

[control_plane]
enabled = true
listen_address = ":9443"

[ca]
dir = "/var/lib/relay/ca"

[store]
path = "/var/lib/relay/relay.db"

[tls]
hostname = "relay.example.internal"
```

That minimal file carries no gate rules, so it gates nothing; copy the two `[[approval.rules]]`
sections from `relay.toml.example` to gate every `mutate` and every Raw Exec.

Verify it is up, with `$RELAY_TOKEN` an API Token from `relay init` (section 4):

```console
$ curl --cacert /var/lib/relay/ca/ca-cert.pem \
    -H "Authorization: Bearer $RELAY_TOKEN" \
    https://relay.example.internal:9443/metrics | head
```

## 4. The packaged systemd unit

Use the hardened unit in `relay/packaging/`, `relay.service`, not a hand-written one; its
README has the install and enable steps, and its comments carry the reasoning for each
directive. The Node-side counterpart is `daemon/packaging/relay-daemon.service`.

The Relay does not need root. It needs write access to its CA directory and store and the
ability to bind its two ports; the unit takes everything else away: a dedicated `relay` user,
an empty capability bounding set, `NoNewPrivileges`, a read-only filesystem apart from
`StateDirectory=relay` (`/var/lib/relay`, `0700`), `SystemCallFilter=@system-service`, and
`TasksMax=512`.

`/etc/relay/relay.toml` is `0640 root:relay`. It holds the security floor (invariant 11):
whoever can edit it can lower that floor at the next restart or reload.

Install per `relay/packaging/README.md`, then:

```console
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now relay
$ systemctl status relay
```

The control plane has no Account and no usable credential until you create the first admin:

```console
$ sudo -u relay relay init --admin <your-name>
```

It prompts for that admin's Console password and prints its first API Token. Give your callers
credentials of their own; see [control-plane-credential.md](control-plane-credential.md).

## 5. Operational levers on the Relay host

- **Freeze (ADR-0013).** `kill -USR1 <relay-pid>` engages the Relay-wide emergency stop, with
  no reason required. `kill -USR2 <relay-pid>` releases it with an audited reason, taken from
  `RELAY_FREEZE_RELEASE_REASON` in the Relay's environment if set, else a default. Both are
  also on the Control API (`POST /api/v1/freeze/engage`, `POST /api/v1/freeze/release`;
  release requires a non-empty `reason`). Freeze state persists across restarts.
- **Registry as upgrade dashboard.** With `reach.min_daemon_version` set, below-minimum Nodes
  still connect and heartbeat but are flagged `outdated` and refused dispatch per Task
  (ADR-0014); see [iac-upgrades.md](iac-upgrades.md).
- **Backups.** Back up the CA key ([ca-disaster-recovery.md](ca-disaster-recovery.md)) and the
  store (`store.path`), which holds the registry, audit trail, and token and revocation state.

## 6. What the Relay can never do

These are architecture invariants, not configuration choices: the Relay never modifies a
Node's Policy over the wire (ADR-0002), never pushes binaries to Nodes (ADR-0014), and its own
configuration is never reachable through the Control API (ADR-0010). The API cannot raise
blast caps, lower the minimum daemon version, or touch the listeners.

## 7. Running it with Docker Compose

[`deploy/production/docker-compose.yml`](../../deploy/production/docker-compose.yml) runs the Relay
and nothing else: one service, one data volume, no relay-daemons, fixtures or credentials. It
is deployed from a git checkout, by hand or by a tool that deploys compose stacks from git
(Komodo, for example). It runs the signed, published Relay image that the compose file pins by
version and digest; the checkout supplies the compose file and the example configuration, not
the image.

Read these first:

- **It is a supported deployment path beside the systemd unit in
  [section 4](#4-the-packaged-systemd-unit), not a replacement** (ADR-0033, amended
  2026-10-15). It is not called production until a human hardening review of this deployment
  has closed (RC-27). It mirrors the unit's posture where Docker can express it, as the table
  below lists; that is a description, not a review.
- **The image is a release a human last verified, not the checkout.** It behaves as its
  version's tag says and can predate this checkout's documentation and specs, so a behaviour
  described here may not be in the image. Moving from an image built from source can be a
  downgrade. An image built from a checkout reports `relay 0.0.0-unknown` and carries no
  version label (only the published `release` stage sets `org.opencontainers.image.version`),
  so for that move compare the checkout against the tag: `git log --oneline v<version>..HEAD`
  lists what the pinned image lacks. Between published images, check what is running with
  `docker compose … exec relay relay --version` (the label carries the same version) against
  the pin before you change it. The compose file builds nothing, so `up -d --build` pulls the
  pinned image if it is not already present and does not build from the checkout; the
  `cosign verify` of step 3 is therefore not optional.
- **It is one host with no high-availability claim.** If the host or the volume is lost, the
  Relay is down: Nodes keep running but nothing can be dispatched to them, and a lost CA means
  re-enrolling the fleet ([ca-disaster-recovery.md](ca-disaster-recovery.md)).
- **Never run it on a host that also holds a development checkout of this repository**, a
  clone or any of its git worktrees. Every checkout carries this file with the same project
  name, `relay`, so a routine `docker compose -f deploy/production/docker-compose.yml up`
  in *any* of them recreates the running deployment from that checkout's copy of the file: its
  image pin, ports and mounts. The
  external data volume (step 1) survives `down -v`, but nothing stops the replacement. The
  deployment host holds one checkout, at the pinned commit you deploy.

It is not a dev fleet. The three-Node test fleet and the nine-Node demo fleet are
`deploy/test/` and `deploy/demo/` ([dev-fleet.md](../dev-fleet.md),
[deploy/README.md](../../deploy/README.md)); nothing in this stack refers to their fixtures,
gates or committed dev credentials. There is deliberately no `docker-compose.yml` at the
repository root.

### What it keeps of the packaging posture, and what it does not

| Property of `relay/packaging/` | In this stack |
| --- | --- |
| Runs as an unprivileged Unix user | **Kept.** The published image (`docker/relay.Dockerfile`, its `release` stage) runs as `10001:10001` (`relay`), never root, and the release workflow refuses to publish one that does not ([release-artifacts.md](release-artifacts.md)); the compose file states it too. |
| Empty capability set, `NoNewPrivileges` | **Kept.** `cap_drop: [ALL]` and `no-new-privileges`. |
| Read-only filesystem apart from its state | **Kept.** `read_only: true`; the state volume and a private `/tmp` tmpfs are the only writable paths. |
| State directory `0700`, owned by the Relay's own Unix user | **Kept.** `/var/lib/relay` is created `0700` and owned by `relay` in the image, and an empty volume takes both on first mount. The CA key inside it is `0600`. |
| `TasksMax=512` | **Kept.** `pids_limit: 512`. No memory limit is set, here or in the unit. |
| Secrets are file paths, never values | **Kept.** `relay.toml` and every secret file it names are host files bind-mounted read-only; nothing about the floor is in the container's environment, so `docker inspect` shows mount paths, not settings or secrets. |
| Configuration set by the operator on the host, unreachable from any API (invariant 11) | **Not kept under a git-driven deploy.** No Relay API reaches it, but the deploy path does. Whoever can push to the branch a deploy tool tracks, or use that tool's interface, controls the published ports, the mounts and user, the image pin, and so the image that runs, and `RELAY_CONFIG_FILE`, so they can point the Relay at a configuration that sets a hostile `oauth.issuer` on the next deploy. `.env` files are git-ignored, which stops an accident, not a push. Deploy a **pinned commit**, with **auto-deploy webhooks off**, and treat write access to that branch and to the deploy tool (Komodo included) as **root on the Relay host**. |
| Root-owned unit file | **Not kept.** The compose file lives in the checkout; see the row above. |
| A configuration file the Relay could not write and no other account could read | **Kept.** Checked at start as the container sees it (ADR-0043); the host file is `root:10001` `0640` on ext4, XFS, btrfs or tmpfs. |
| The unit's finer sandboxing (`SystemCallFilter=@system-service`, `ProtectKernel*`, `MemoryDenyWriteExecute`, `RestrictAddressFamilies`, `ProtectProc`) | **Not claimed.** Docker's default seccomp profile and namespaces cover some of the same ground; they are not equivalent. |
| A digest-verified release binary (section 1) | **Kept.** The stack runs `ghcr.io/felag-engineering/relay` pinned by version and digest, signed keylessly by the release workflow at that digest; its `/usr/local/bin/relay` is the release binary `SHA256SUMS` lists (the release workflow refuses to publish otherwise; [release-artifacts.md](release-artifacts.md)). Docker checks the digest on pull but never the signature: `cosign verify` in step 3 is what proves provenance. |
| `Restart=on-failure`, enabled at boot | **`restart: unless-stopped`.** Docker's `on-failure` would not bring the Relay back after a host or Docker restart; `unless-stopped` does, and also restarts after a clean exit. Neither restarts an *unhealthy* container: watch the health status. |

### What it exposes

Two ports, bound differently on purpose. Both are set by **Compose interpolation variables**
(in the shell that runs `docker compose`, a git-ignored `.env` beside the compose file, or a
deploy tool's stack environment), **never in `relay.toml`**.

| Port | Default binding | Variable | What is reachable there |
| --- | --- | --- | --- |
| `7654`, the Node plane | `0.0.0.0` (every IPv4 interface) | `RELAY_NODE_PUBLISH_ADDR` | gRPC over mTLS, which relay-daemons on other hosts dial. Every RPC requires a client certificate issued by the Relay's CA except Enrollment, which requires an Enrollment Token and is rate-limited per source address and globally. |
| `9443`, the control plane | `127.0.0.1` (host loopback) | `RELAY_PUBLISH_ADDR` | MCP at `/mcp`, the Control API at `/api/v1`, `/metrics`, `/healthz` (unauthenticated, one bit), and when enabled the Admin Console at `/console/`. An execution surface for whoever holds an API Token or a Console password. |

**Set a Console password before you publish `9443` beyond loopback** (step 5). Nothing
enforces that order. Once `9443` is reachable, anyone on that network can attempt a sign-in:
the throttle has no hard lockout and the minimum is 12 bytes, so length is what protects the
password. Choose a long one.

The host port on the left of `7654:7654` is what relay-daemons dial and what a join string
carries. Publish it on any other host port and you must set
`node_plane.advertised_address = "<tls.hostname>:<host port>"` (or a host listed in
`tls.extra_names`) in `relay.toml` (RC-36).

**Do not expose `7654` to the internet** unless you must: the global enrollment bucket is
shared by every source, so anyone who can reach the port can spend it and deny enrollment to
your own Nodes (enrolled Nodes are unaffected).

Docker's own firewall rules take effect **before** host firewalls such as `ufw` or `firewalld`,
so the bind address is the exposure control; a host firewall rule does not restrict a
Docker-published port. Use **Docker Engine 28 or newer**: Docker's 28.0 release notes report
that before 28.0 a port published on `127.0.0.1` could be reached from other hosts on the same
layer-2 segment (not verified here).

### First run

You need Docker Engine 28+ with Compose **v2.24 or newer**, one checkout of this repository on
the Relay host at the commit you deploy (it supplies the compose file and the example
configuration; the image is pulled), a host that can reach `ghcr.io` (the package is public, so
an anonymous pull works), and a DNS name for the host that every relay-daemon can resolve. On
the machine that verifies the image you also need **cosign v3 or later**
(<https://docs.sigstore.dev/>): the image's signature is a cosign v3 bundle stored as an OCI
referrer, and cosign v2 reports "no signatures found" for it. Run every command from the
checkout root.

**1. Create the data volume.** It is declared `external`, so Compose never creates it and no
`docker compose down -v` can delete the CA key and store on it:

```console
$ docker volume create relay-data
```

Create it empty: on first start Docker copies the image's `/var/lib/relay` into it, owner
`relay` (UID `10001`), mode `0700`. To use another name, create that one and set
`RELAY_DATA_VOLUME` the same way as the bind addresses.

**2. Write the configuration file**, starting from
[`relay/packaging/relay.toml.example`](../../relay/packaging/relay.toml.example):

```console
$ sudo install -d -m 0755 /etc/relay
$ sudo install -o root -g 10001 -m 0640 relay/packaging/relay.toml.example /etc/relay/relay.toml
$ sudoedit /etc/relay/relay.toml
```

Group `10001` is the Relay's group inside the image. Confirm `getent group 10001` prints
nothing on the host and that no account has that GID: the Relay's check runs inside the
container and cannot see host accounts, and any host member of GID `10001` can read the
configuration and the secrets. Set, for this container's layout:

- `tls.hostname`, the name relay-daemons will dial. It becomes the server certificate's SAN.
  Inside a container the detected addresses are the container's own, so daemons dialling through
  a port mapping must dial `tls.hostname` or an entry of `tls.extra_names`.
  While it is unset or still the sample's `relay.example.internal`, the container reports
  **unhealthy** and `docker inspect --format '{{json .State.Health}}' <container>` says why.
- `node_plane.listen_address = ":7654"`, `control_plane.enabled = true` and
  `control_plane.listen_address = ":9443"`, which tie to the published ports.
- `ca.dir = "/var/lib/relay/ca"` and `store.path = "/var/lib/relay/relay.db"`, which tie to the
  volume.

For the Console, set `console.enabled = true`. Everything else is optional (blast caps,
enrollment limits, the minimum daemon version, OAuth, approval gates).

At start the Relay refuses the file if it could write it or any other account could read it,
as the container sees it, and logs `hostfile: refusing <path>: <reason>` in
`docker compose … logs relay`. So the host file must be on ext4, XFS, btrfs or tmpfs (not NFS,
CIFS, FUSE, ZFS or a Docker Desktop share), and the stack cannot pass under rootless Docker or
user-namespace remapping, where root's file appears owned by nobody. The Docker data root
holding `relay-data` must be on one of those filesystems too.

The file is **required**: if it is missing, `docker compose` refuses to start the stack rather
than run the Relay on defaults. To keep it elsewhere, set `RELAY_CONFIG_FILE` to an
**absolute** path (a relative one resolves against `deploy/production/`).

**3. Verify the image, then bring it up.** A failed verification is fatal: stop there, and do
not pull or start the image.

```console
$ grep -E '^[[:space:]]+image:' deploy/production/docker-compose.yml
    image: ghcr.io/felag-engineering/relay:<version>@sha256:<digest>
$ cosign verify ghcr.io/felag-engineering/relay@sha256:<digest> \
    --certificate-identity "https://github.com/Felag-Engineering/relay/.github/workflows/release.yml@refs/tags/v<version>" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
$ docker compose -f deploy/production/docker-compose.yml pull
$ docker compose -f deploy/production/docker-compose.yml up -d
$ docker compose -f deploy/production/docker-compose.yml ps   # wait for relay to be (healthy)
```

Take `<version>` and `<digest>` (the 64 hex characters after `sha256:`) from the `image:` line
the first command prints, and verify by digest, never by tag: a tag check verifies whatever the
tag points at now, not what the compose file pulls. To extract the digest without retyping it:
`sed -n 's/^[[:space:]]*image:.*@sha256:\([0-9a-f]\{64\}\)$/\1/p' deploy/production/docker-compose.yml`.
A passing verification proves the image is a genuine release, not that it is the one you
intend: confirm `<version>` is the release you mean to deploy and is not older than the one
already running before you run `up`. A running image built from a checkout reports
`relay 0.0.0-unknown`; for that move run `git log --oneline v<version>..HEAD` to see what the
pinned image lacks.
What the certificate identity means is in
[release-artifacts.md](release-artifacts.md#verify-then-install).

The Relay creates its CA on first start and logs its fingerprint
(`docker compose -f deploy/production/docker-compose.yml logs relay`).

**4. Create the first admin** with `relay init`, which runs as the Relay's own account inside
the container: a human `admin` Account named as you choose, its Console password (prompted
for twice, not echoed), and its first API Token
([control-plane-credential.md](control-plane-credential.md), ADR-0030). The token is printed
once and never stored: put it in a vault now, and hold it in `RELAY_TOKEN` for the rest of
this procedure without echoing it:

```console
$ docker compose -f deploy/production/docker-compose.yml exec relay relay init --admin <your-name>
$ read -rs RELAY_TOKEN     # paste the token printed above
```

Copy out the Relay's **public** CA certificate, which every client pins (never `ca-key.pem`):

```console
$ docker compose -f deploy/production/docker-compose.yml cp \
    relay:/var/lib/relay/ca/ca-cert.pem ./relay-ca-cert.pem
```

**5. Reach the Console** (if enabled in step 2) as the admin from step 4. Other people get their
own Account from an admin in the Console: creating a human Account issues it a temporary
password, shown once and valid for 72 hours, which the person changes at first sign-in. Any
signed-in human changes their own password under "Your account"; no surface resets one a human
has set, so a forgotten password is replaced by disabling the Account and creating a new one.
`POST /api/v1/accounts` creates a human with no password, so that Account has none until an
admin issues one from its Account page in the Console
([control-plane-credential.md](control-plane-credential.md)).

To make the control plane reachable beyond this host, set `RELAY_PUBLISH_ADDR` to the host's
LAN address (or `0.0.0.0`) and run step 3's `up -d` again. Sign in at
`https://<tls.hostname>:9443/console/`. The browser warns because the certificate chains to the
Relay's private CA; trust `relay-ca-cert.pem` rather than clicking through.

**6. Mint an Enrollment Token** ([enrollment.md](enrollment.md) explains the initial tags; they
are written on every Node the token enrolls, as ordinary tags). From the Relay host:

```console
$ curl --cacert relay-ca-cert.pem \
    --resolve <tls.hostname>:9443:127.0.0.1 \
    -H "Authorization: Bearer $RELAY_TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"initial_tags":["tag:env=lab"],"ttl_seconds":86400,"max_uses":10}' \
    https://<tls.hostname>:9443/api/v1/enrollment-tokens
```

`--resolve` dials loopback while TLS still verifies the real name; drop it from other hosts
once the control plane is published.

**7. Point real relay-daemons at it**, one host at a time, per
[relay-daemon-install.md](relay-daemon-install.md): pipe the `join_string` from
step 6's response to `sudo relay-daemon join`. It carries the Relay's address, its CA
fingerprint and the token, and is used once, by `join`, which writes it nowhere; no CA file is
copied to the Node. A daemon with no identity logs `no identity: nothing to connect with` and
exits 0, so enroll with `relay-daemon join` if the unit is inactive. Each
Node's Policy is authored on that Node; this stack ships none and can never write one
(ADR-0002). Finish with `unset RELAY_TOKEN`.

### Operating it

Every command here takes `-f deploy/production/docker-compose.yml`, shortened to `…`.

- **Every mutate and every Raw Exec waits for a person.** `relay.toml.example`, which this
  stack starts from, carries two gate rules, one gating every `mutate` and one every Raw Exec.
  Delete a rule's `[[approval.rules]]` section in `relay.toml` to stop gating what it matches
  ([approval-gates.md](approval-gates.md)). There is no separate gate file. A rule that cannot
  be loaded refuses startup.
- **The approval webhook's signing secret** is a file owned by root, group `10001`, mode
  `0640`, mounted read-only through the commented example in the compose file and named by
  `approval.webhook_secret_file` (the webhook URL, which carries its own token, likewise by
  `approval.webhook_url_file`). A file the Relay could write, or another account could read,
  refuses startup.
- **OAuth** is off unless you set the `[oauth]` table
  ([control-plane-credential.md](control-plane-credential.md#human-sessions-oauth-21-through-your-idp)).
  The issuer is fetched from inside the container at startup over HTTPS, trusting Alpine's
  public CA bundle. The Relay never creates an Account from a token (ADR-0024), so create each
  person's Account first. Do not copy the demo overlay: its shared network namespace and
  plain-HTTP loopback issuer exist only for its DEV-ONLY Keycloak.
- **Freeze** (ADR-0013): `docker compose … kill -s USR1 relay` engages it and
  `docker compose … kill -s USR2 relay` releases it, as in
  [section 5](#5-operational-levers-on-the-relay-host).
- **Reload** (RC-21): edit `relay.toml` on the host, then `docker compose … kill -s HUP relay`.
  A setting that needs a restart is refused by name and nothing changes. Edit the file **in
  place**, or run `docker compose … restart relay` afterwards: `relay.toml` is a single-file
  bind mount, so an editor that saves by writing a new file and renaming it leaves the
  container reading the old one, and the reload logs `configuration reloaded changed=[]`.
- **Back up the volume** `relay-data`: it holds the CA key and the store. Compose will not
  delete it; `docker volume rm relay-data` will, and every Node must then re-enroll.
- **Upgrades** are a checkout of the next pinned commit, whose compose file names the next
  release's image by version and digest; confirm that version is the one you intend and not
  older than the one running (`docker compose … exec relay relay --version`; a checkout-built
  image reports `0.0.0-unknown`, so compare the checkout against the tag with
  `git log --oneline v<version>..HEAD`), verify that digest
  as in step 3, then `docker compose … pull` and `docker compose … up -d`. The Relay never pushes binaries to
  Nodes (ADR-0014).
- **Project name.** The file sets `name: relay`; a deploy tool's own `-p` overrides it. The
  name does **not** prevent a collision: every checkout resolves to the same project, which is
  why the deployment host holds no other checkout. The stack publishes the same host ports as
  the dev and demo fleets, so only one of the three can run on a host at a time.
