# Installing and running the relay-daemon

How to install the relay-daemon — the non-AI Rust daemon on each managed Node —
from a published release artifact, in a clean environment. Companion documents:
[relay-install.md](relay-install.md) for the Relay side,
[enrollment.md](enrollment.md) for joining the fleet,
[policy-as-code.md](policy-as-code.md) for authoring and distributing the Policy
file, [daemon-privilege-posture.md](daemon-privilege-posture.md) for the hardened
systemd unit's rationale, and [release-artifacts.md](release-artifacts.md) for the
artifact contract.

The short version already lives in
[`daemon/packaging/README.md`](../../daemon/packaging/README.md); this document is
the standalone walkthrough for someone standing up a Node from scratch.

## 1. Obtain and verify the artifact

Releases publish `relay-daemon-<version>-x86_64-unknown-linux-musl` — statically
linked (musl, ADR-0007), no libc or distro expectations — plus `SHA256SUMS`.
Follow the **verify-then-install** sequence
([release-artifacts.md](release-artifacts.md)); the digest check happens
**before** the binary is installed or executed, and a mismatch aborts:

```sh
VERSION="X.Y.Z"         # the release pinned by the operator, in config management
ARTIFACT="relay-daemon-${VERSION}-x86_64-unknown-linux-musl"
BASE="https://github.com/Felag-Engineering/gleipnir-relay/releases/download/v${VERSION}"

curl -fsSLO "${BASE}/${ARTIFACT}"
curl -fsSLO "${BASE}/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS   # verify BEFORE install; failure is fatal
install -m 0755 "${ARTIFACT}" /usr/local/bin/relay-daemon
/usr/local/bin/relay-daemon --version            # must self-identify as the pinned version
```

In production this sequence is owned by config management, not typed by hand —
see [enrollment.md](enrollment.md) for the Ansible-flavored role and
[iac-upgrades.md](iac-upgrades.md) for upgrades.

## 2. Configuration surface

The daemon is configured entirely by environment variables (read once at startup,
`daemon/src/config.rs`), conventionally via the systemd unit's `EnvironmentFile`
(`/etc/relay-daemon/relay-daemon.env`, template at
[`daemon/packaging/relay-daemon.env.example`](../../daemon/packaging/relay-daemon.env.example)):

| Variable | Default | Meaning |
|---|---|---|
| `RELAY_ADDR` | `http://127.0.0.1:7654` | The Relay's Node-plane gRPC address. `http://` is normalized to `https://`; the connection is always mTLS (invariant #6). Also settable as the `--relay <addr>` CLI argument. |
| `RELAY_DOMAIN` | *(unset)* | Optional TLS SNI / server-name override when the Relay cert's SAN differs from the dialed host. |
| `RELAY_STATE_DIR` | `/var/lib/relay-daemon` | Where the enrolled identity (`key.pem`, `cert.pem`, `ca_bundle.pem`, `node_id`) and the at-most-once dedup marker store (`seen-tasks/`) persist. |
| `RELAY_POLICY_PATH` | `/etc/relay-daemon/policy.toml` | Path to this Node's Policy file (ADR-0002). See [policy-as-code.md](policy-as-code.md). |
| `RELAY_TEMPLATE_DIR` | `/etc/relay-daemon/templates.d` | Root of this Node's Template Operation files, beside `policy.toml` and under the same root-owned trust root (ADR-0021). Absent = no templates installed. The shipped read catalog installs to `templates.d/relay-read/`. See [template-packs.md](template-packs.md). |
| `RELAY_NODE_LABELS` | *(unset)* | Comma-separated bare `key=value` pairs reported as node-space Labels (the daemon adds the `node:` prefix; it can never emit `relay:` labels — ADR-0006). Example: `env=prod,role=web`. Each key and value must match `[A-Za-z0-9._-]+` (the empty value is accepted); anything else is well-formedness-gated at ingress (#504), never sanitised. A malformed pair is REFUSED at enrollment — the Node does not join — and DROPPED at reconnect — the Node stays connected without that one label. |
| `RELAY_ENROLLMENT_TOKEN` | *(unset)* | The Enrollment Token, used only when no persisted identity exists. Secret: never commit, never log. See [enrollment.md](enrollment.md). |
| `RELAY_CA_BUNDLE_PATH` | *(unset)* | Path to the pinned bootstrap CA bundle (the Relay's `ca-cert.pem`) used to authenticate the Relay during first enrollment. Required together with the token for enrollment. |
| `RELAY_ENROLL_ENDPOINT` | *(falls back to `RELAY_ADDR`)* | Optional distinct endpoint for the enrollment RPC. Must be `https://` — anything else is refused (fail closed). |
| `RELAY_HEARTBEAT_INTERVAL_SECS` | `30` | Heartbeat base interval; each send is jittered ±20% so a bulk-restarted fleet spreads out. |
| `RELAY_SHUTDOWN_GRACE_SECS` | `30` | Graceful-shutdown grace period: on SIGTERM/SIGINT the daemon stops accepting Tasks, drains in-flight ones up to this budget, then exits. |
| `RUST_LOG` | `info` | Log filter (`tracing_subscriber` EnvFilter syntax). |

Fail-closed behaviors to know about (all deliberate):

- **No identity, no token → refuse to run.** Without a persisted identity or a
  configured Enrollment Token the daemon exits rather than fall back to a
  plaintext dial (ADR-0005).
- **Policy missing or unreadable → deny-all.** The daemon starts, connects, and
  denies every Task rather than refusing to start or running open
  (ADR-0002). A group- or world-writable Policy file is likewise refused.
- **Non-`https` enrollment endpoint → fatal.** TLS (and the CA pinning that rides
  on it) is only active under `https://`.

## 3. Subcommands

All fully offline — no network, no identity, no Relay:

- `relay-daemon --version` / `-version` / `-V` — print the build stamp and exit
  (same three spellings as the Relay; [version-stamping.md](version-stamping.md)).
- `relay-daemon policy check <file> [--strict] [--would-allow <spec>]` — lint a
  Policy file and optionally answer a hypothetical through the same evaluator the
  live wire path uses (ADR-0011). Exit codes `0` valid / `1` invalid / `2`
  would-deny. See [policy-as-code.md](policy-as-code.md).
- `relay-daemon dump-operation-schema` — print the canonical Operation schema
  JSON (ADR-0015).

## 4. Install on the Node

Per [`daemon/packaging/README.md`](../../daemon/packaging/README.md):

```console
$ sudo install -m 0755 relay-daemon-${VERSION}-x86_64-unknown-linux-musl /usr/local/bin/relay-daemon
$ sudo install -m 0644 relay-daemon.service /etc/systemd/system/relay-daemon.service
$ sudo mkdir -p /etc/relay-daemon
$ sudo install -m 0644 -o root -g root policy.toml /etc/relay-daemon/policy.toml
$ sudo install -m 0644 -o root -g root ca-cert.pem /etc/relay-daemon/ca-bundle.pem
$ sudo install -m 0600 -o root -g root relay-daemon.env /etc/relay-daemon/relay-daemon.env
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now relay-daemon
$ systemctl status relay-daemon
```

Where the pieces come from:

- **The unit** is the shipped hardened one,
  [`daemon/packaging/relay-daemon.service`](../../daemon/packaging/relay-daemon.service)
  (`User=root` by necessity, everything else stripped —
  [daemon-privilege-posture.md](daemon-privilege-posture.md) explains every
  directive, and the `pkg-install.conf` drop-in for Nodes that run `pkg.install`
  or filesystem-mutating Raw Exec).
- **`policy.toml`** comes from your IaC repo
  ([policy-as-code.md](policy-as-code.md)); the annotated example is
  [`daemon/policy.example.toml`](../../daemon/policy.example.toml), and the
  shipped default — `read` pre-allowed with a confidentiality deny-list,
  `mutate` + Raw Exec opt-in (ADR-0022) — is
  [`daemon/policy.default.toml`](../../daemon/policy.default.toml). Root-owned,
  not group/world-writable.
- **`ca-bundle.pem`** is the Relay CA's `ca-cert.pem`, distributed by config
  management ([enrollment.md](enrollment.md)). It contains no secrets.
- **`relay-daemon.env`** is the filled-in copy of the example env file, `0600
  root:root` because it carries the Enrollment Token (a known interim state —
  see the packaging README).

## 5. Verify

On the Node:

```console
$ journalctl -u relay-daemon -f
# expect: "relay-daemon starting", "policy loaded" (with the fingerprint),
# enrollment (first run only), then "received Ping from Relay"
```

From the Relay's control plane, the new Node appears in `list_nodes` (MCP) with
its Facts, Labels, and Policy fingerprint — see [enrollment.md](enrollment.md)
for the full verification loop.

## 6. Lifecycle

- **Upgrades:** the daemon never self-upgrades and the Relay never pushes
  binaries (ADR-0014). Upgrading is a config-management artifact swap + restart —
  [iac-upgrades.md](iac-upgrades.md).
- **Policy changes:** config-management file push + daemon restart, never over
  the wire — [policy-as-code.md](policy-as-code.md).
- **Certificate renewal:** automatic. Identity certs live ~14 days and the
  daemon renews over its existing mTLS connection at a jittered 50–75% of cert
  lifetime, with retries; no operator action (ADR-0006).
- **Decommissioning:** revoke the Node on the Relay
  (`POST /api/v1/nodes/{node_id}/revoke`, with a JSON body `{"reason": "..."}` —
  required as of #487) and remove the daemon + state dir via config management.
