# Installing and running the Relay

How to stand up the Relay — the central Go server — in a clean environment, from a
published release artifact. Companion documents:
[relay-daemon-install.md](relay-daemon-install.md) for the Node side,
[enrollment.md](enrollment.md) for joining Nodes to the fleet,
[ca-disaster-recovery.md](ca-disaster-recovery.md) for the CA the Relay hosts, and
[release-artifacts.md](release-artifacts.md) for the artifact naming and
verification contract this document consumes.

## 1. Obtain and verify the artifact

Releases publish `relay-<version>-x86_64-unknown-linux-gnu` (glibc-linked) plus a
`SHA256SUMS` file. Follow the **verify-then-install** sequence from
[release-artifacts.md](release-artifacts.md) — the digest check happens **before**
the binary is installed or executed, and a mismatch aborts:

```sh
# Pinned by the operator — never resolved at install time.
VERSION="0.1.0-beta"
ARTIFACT="relay-${VERSION}-x86_64-unknown-linux-gnu"
BASE="https://github.com/Felag-Engineering/gleipnir-relay/releases/download/v${VERSION}"

curl -fsSLO "${BASE}/${ARTIFACT}"
curl -fsSLO "${BASE}/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS   # verify BEFORE install; failure is fatal
install -m 0755 "${ARTIFACT}" /usr/local/sbin/relay
/usr/local/sbin/relay --version                  # must self-identify as the pinned version
```

`relay --version` (also `-version` and `-V`, identical to relay-daemon's spellings)
prints the build stamp — see [version-stamping.md](version-stamping.md).

## 2. Configuration surface

The Relay is configured by CLI flags with `RELAY_`-prefixed environment-variable
overrides (env wins when set). There is **no config file yet**: ADR-0010/0012 call
for a root-owned config file for the security-sensitive values (blast caps,
minimum daemon version, listener addresses); the current flags+env mechanism is a
documented interim — the security property that matters (set only at startup, never
settable via any API, invariant #11) holds either way. All flags from
`relay/cmd/relay/main.go`:

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
| `-min-daemon-version` | `RELAY_MIN_DAEMON_VERSION` | *(empty)* | Minimum relay-daemon semver (ADR-0014). Empty disables the `outdated` gate; a malformed value refuses startup. See [iac-upgrades.md](iac-upgrades.md), and the prerelease caveat in [release-artifacts.md](release-artifacts.md) (#261). |
| `-control-enabled` | `RELAY_CONTROL_ENABLED` | `false` | Enable the control-plane listener (MCP + `/api/v1` + `/metrics`). |
| `-control-addr` | `RELAY_CONTROL_ADDR` | `:9443` | Control-plane HTTPS listen address (distinct from `-addr`). |

Subcommands (checked before flag parsing):

- `relay --version` / `-version` / `-V` — print the build stamp and exit.
- `relay bootstrap-token -store-path <path>` — mint the founding admin Account's first
  API Token and print it to stdout. This is how you obtain a control-plane credential;
  there is none in Relay configuration
  ([control-plane-credential.md](control-plane-credential.md), ADR-0023).

## 3. First start

On first start the Relay creates its CA in `-ca-dir` (directory `0700`;
`ca-key.pem` `0600`, `ca-cert.pem` `0644`) and issues itself a server certificate
for `-hostname`. Both listeners chain to this CA:

- **Node plane** (`-addr`): gRPC over mTLS. Daemons authenticate the Relay against
  the pinned CA bundle; the Relay requires a client certificate for every RPC
  except the certless `Enrollment.Enroll` (ADR-0005/0006).
- **Control plane** (`-control-addr`, when enabled): HTTPS serving the MCP surface
  at `/mcp`, the Control API at `/api/v1`, and Prometheus metrics at `/metrics`,
  all behind the seeded bearer credential. Its server certificate also chains to
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

Verify it is up:

```console
$ curl --cacert /var/lib/relay/ca/ca-cert.pem \
    -H "Authorization: Bearer $CONTROL_PLANE_CREDENTIAL" \
    https://relay.example.internal:9443/metrics | head
```

## 4. Example systemd unit

The repository ships a hardened unit for the relay-daemon
(`daemon/packaging/relay-daemon.service`) but **no packaged unit for the Relay
binary yet** — the following is a documented example to adapt. The Relay does not
need root: it needs write access to its CA directory and store, and the ability to
bind its two ports.

```ini
[Unit]
Description=Relay (fleet-administration control plane server)
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
# Dedicated unprivileged user; StateDirectory gives it /var/lib/relay.
User=relay
Group=relay
DynamicUser=no
StateDirectory=relay
StateDirectoryMode=0700
Environment=RELAY_ADDR=:7654
Environment=RELAY_HOSTNAME=relay.example.internal
Environment=RELAY_CA_DIR=/var/lib/relay/ca
Environment=RELAY_STORE_PATH=/var/lib/relay/relay.db
Environment=RELAY_CONTROL_ENABLED=true
Environment=RELAY_CONTROL_ADDR=:9443
ExecStart=/usr/local/sbin/relay
Restart=on-failure
RestartSec=5s

# Hardening (the Relay spawns no child processes and needs no capabilities).
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
```

```console
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now relay
$ systemctl status relay
```

The control plane comes up with no usable credential until you mint one. Run
`relay bootstrap-token` on this host and switch your callers to the printed token —
see [control-plane-credential.md](control-plane-credential.md).

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
