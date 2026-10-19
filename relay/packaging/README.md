# Relay packaging

A hardened `systemd` unit for running the Relay in production, plus
[`relay.toml.example`](relay.toml.example), the example configuration file
covering its full startup-configuration surface.

The counterpart on the Node side is
[`daemon/packaging`](../../daemon/packaging/README.md), and the two have
deliberately different privilege postures — see below.

## The Relay needs no privilege

The `relay-daemon` runs as root and cannot stop: `service.restart` commands PID
1, `pkg.install` writes the system package database. The Relay does none of
that. It is a network server holding a CA key and a SQLite file; **every
privileged act in the system happens on a Node**, on the far side of an mTLS
tunnel, gated by that Node's own local Policy ([ADR-0002](../../docs/adr/0002-node-side-policy-is-locally-rooted-and-remotely-immutable.md)).

So [`relay.service`](relay.service) takes everything away: a dedicated
unprivileged account, an **empty** capability bounding set, `NoNewPrivileges`,
and a read-only filesystem apart from its own state directory.

Read that as the deployment expression of the architecture, not as generic
hardening advice. If a change ever makes the Relay need a capability back, that
is worth stopping on — it would mean something privileged had moved to the wrong
side of the tunnel.

## Install

```console
$ sudo install -m 0755 /path/to/relay /usr/bin/relay

# A service account that owns the CA and the store. No shell, no home.
$ sudo useradd --system --no-create-home --shell /usr/sbin/nologin relay

$ sudo install -m 0644 relay.service /etc/systemd/system/relay.service
$ sudo mkdir -p /etc/relay
$ sudo install -m 0640 -o root -g relay relay.toml.example /etc/relay/relay.toml
$ sudo "$EDITOR" /etc/relay/relay.toml   # set tls.hostname, ca.dir and store.path at minimum
```

`/etc/relay/relay.toml` is `0640 root:relay`: the Relay reads it and nothing else
should. It holds the **security floor**, and whoever can edit it can lower that
floor at the next restart. The Relay takes nothing from its environment or its
command line (ADR-0043): a `RELAY_*` setting variable that is still set refuses
start and names the key in the file that replaces it.

## Enable

```console
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now relay
$ systemctl status relay
```

## First credential

The control plane authenticates per-Account API Tokens held in the Relay's own
store ([ADR-0023](../../docs/adr/0023-retire-the-shared-control-plane-credential.md)) — there is
deliberately no shared secret in the config. Mint the first one after the Relay
has started once, pointing `-store-path` at the same store the Relay runs with (`store.path` in
`/etc/relay/relay.toml`). The flag is required: the subcommand does not read the
configuration file.

```console
$ sudo -u relay relay bootstrap-token -store-path /var/lib/relay/relay.db
```

The plaintext is printed **once** and never persisted. Put it in a vault at that
moment.

## What is configured here, and what is not

Relay configuration is the operator's, read from `/etc/relay/relay.toml` at
startup, and **never reachable from any API** (AGENTS.md invariant 11). A stolen
API Token cannot raise a blast cap, repoint the CA, move a listener, or change
the OAuth issuer, because no code path exists from a request to any of those
values.

That property is what matters, and it is why several settings live here rather
than anywhere more convenient:

| Setting | Why it is startup-only |
|---|---|
| `reach.read_blast_cap` / `reach.mutate_blast_cap` | The cap on how much damage one dispatch can do — including from a compromised AI-agent. An API that could raise its own limit is not a limit. |
| `ca.dir` | The key that mints Node identities. |
| `approval.gate_rules_path` | A stolen credential that could edit its own approval requirements would make approvals decorative. |
| `[oauth]` | An API that could repoint its own issuer could authenticate anyone. |

Runtime *objects* — Accounts, API Tokens, Enrollment Tokens, Nodes, Jobs,
approvals — are managed through `/api/v1` as normal. The line is between
configuration and objects, not between "important" and "unimportant".

## Secrets are values in the file, or files it names

A credential the Relay needs is given either inline (`approval.webhook_secret`,
`approval.webhook_url`) or by the path of a file holding it
(`approval.webhook_secret_file`, `approval.webhook_url_file`). Never in the
environment: a secret passed as an environment variable is a secret in every
process listing and every crash dump, and a `RELAY_*` setting in the environment
refuses start. At start the Relay refuses to run if it could write the
configuration file or any file it names, or if any account but itself and root
could read the configuration file or a secret file — so a secret file is placed
like the configuration, `0640 root:relay` — and no secret is ever printed in a
log or an error. The CA directory, its private key and the store's directory are
the Relay's own: owned by the service account, and refused if any other account
can read them.

API Tokens are not configuration at all: they live in the store as hashes, and
the first is minted with `relay bootstrap-token` (above).

## The state directory

`StateDirectory=relay` gives `/var/lib/relay`, mode `0700`, owned by the service
account. It holds:

- **the CA key and certificate** (`ca/`) — the most sensitive material in the
  deployment. Whoever reads it can impersonate the Relay to every Node in the
  fleet.
- **the SQLite store** — Jobs, Tasks, the audit trail, Accounts, API Tokens,
  approvals.

Read [docs/operations/ca-disaster-recovery.md](../../docs/operations/ca-disaster-recovery.md)
before going to production. Recovery from CA compromise is re-enrolling the
fleet against a fresh CA, so the backup and permission posture there is not
optional.

## Upgrades

The Relay is upgraded by replacing the binary and restarting — the same
config-management push as any other service. It never self-upgrades, and it
never pushes binaries to Nodes
([ADR-0014](../../docs/adr/0014-daemon-lifecycle-iac-upgrades-version-gate.md));
the Relay's only lever over daemon versions is `reach.min_daemon_version`, which
refuses to dispatch to Nodes below it.

## Keeping the sample honest

`relay.toml.example` is covered by a drift gate in `relay/internal/relayconfig`
(`example_test.go`): every key the loader reads must appear in the sample, and
every value shown commented is the built-in default, or the build fails. The
daemon's sample has the same gate in its own toolchain
(`daemon/tests/packaging_drift.rs`).

Both exist because this drift had already happened once — the daemon's sample
was missing four settings added after it was written, and nothing noticed for
several milestones. A sample that omits a setting does not read as incomplete;
it reads as though the setting does not exist.
