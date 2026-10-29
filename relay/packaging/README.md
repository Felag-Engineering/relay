# Relay packaging

A hardened `systemd` unit for running the Relay in production, plus
[`relay.toml.example`](relay.toml.example), the example configuration file covering every
startup setting. The Node-side counterpart is
[`daemon/packaging`](../../daemon/packaging/README.md), with a deliberately different privilege
posture.

## The Relay needs no privilege

The `relay-daemon` must run as root: `service.restart` commands PID 1, `pkg.install` writes
the system package database. The Relay is a network server holding a CA key and a SQLite file;
**every privileged act happens on a Node**, across an mTLS tunnel, gated by that Node's local
Policy ([ADR-0002](../../docs/adr/0002-node-side-policy-is-locally-rooted-and-remotely-immutable.md)).

So [`relay.service`](relay.service) takes everything away: a dedicated unprivileged account, an
**empty** capability bounding set, `NoNewPrivileges`, and a read-only filesystem apart from its
own state directory. This is the architecture, not generic hardening advice: if a change makes
the Relay need a capability back, stop, because something privileged has moved to the wrong
side of the tunnel.

## Packages

`nfpm/relay.yaml` is the manifest for the Relay's `.deb` and `.rpm`, built by
`scripts/build-packages.sh` with the nfpm pinned under `tools/nfpm`; `scripts/` holds the
package's maintainer scripts and `expected/` the baseline the release checks every package
against. The release builds the packages twice and refuses unless the builds are byte-identical
and `/usr/bin/relay` is the release binary. It reads each package with `dpkg-deb` and `rpm`
and checks its whole content against `expected/` and `scripts/`.

**The release attaches the packages**, with an SBOM each, under the signed `SHA256SUMS`, and
only after the install matrix has passed on exactly those bytes on every supported platform.
Verify, then install, as in
[release-artifacts.md](../../docs/operations/release-artifacts.md). The standalone `relay.service`
and `relay.toml.example` are release attachments too, byte-equal to the copies in the packages;
to install by hand, see below.

The package installs `/usr/bin/relay`, the unit as `/usr/lib/systemd/system/relay.service`, a
`sysusers.d` entry for the `relay` account, a configuration guide that carries no secret as
`/usr/share/doc/relay/configuration-guide.txt` (and as `/usr/share/relay/configuration-guide.txt`,
the copy the install prints, because minimised images leave `/usr/share/doc` out), and the
example configuration and `relay.toml.in` under `/usr/share/relay/`. Nothing under `/etc` or
`/var` is in the package: `relay.toml` is generated, never a package-owned file.

On a first install only, the package:

- creates the `relay` account and group (through `systemd-sysusers`, or `useradd` where it is
  absent) and fails before creating anything else if either is missing afterwards;
- creates `/etc/relay` (root, `0755`) and `/var/lib/relay` (`relay:relay`, `0700`), each if
  absent;
- generates `/etc/relay/relay.toml`, `root:relay 0640`, only if none exists. It sets the host's
  fully qualified name as `tls.hostname`, the CA directory and the store path inside
  `/var/lib/relay`, the control plane and the Admin Console enabled, and the control-plane
  listener on `127.0.0.1:9443`. With no fully qualified name the hostname line is written
  commented out, and the Relay refuses to start, naming `tls.hostname`, until it is set;
- prints the configuration guide and the hostname it chose;
- where systemd is running, runs `systemctl preset`.

It never starts the Relay and never runs `relay init`, so the CA is never created inside an
image the package is installed into. The guide says never to capture an image of the host after
the Relay has first started. An upgrade runs `systemctl daemon-reload` only: it never rewrites
the configuration, never changes enablement and never restarts the Relay.

The package writes `relay.toml` only through a `/etc/relay` that is a real directory owned by
root and not writable by group or other. Through any other it generates nothing, says why, and
the install still succeeds; the Relay then refuses to start for want of a configuration file.

Removing the package stops and disables the unit and removes the binary and the unit. It keeps
the configuration, the state directory and the account. `apt purge` moves the state directory,
the CA and the store together, aside to `/var/lib/relay.purged-<time>`, re-owned by root, mode
`0700`, and prints where; it never deletes it and never deletes the account. The top directory
is re-owned first, which shuts the `relay` account out; the files inside are then re-owned too,
except any with another hard link outside the directory, which are named and left as found. If
`/var/lib/relay` is a mount point it cannot be renamed, so the purge re-owns it in place the
same way and says so. The purge then removes the `relay.toml` the package generated and
`/etc/relay` if the package created it and it is empty, using a marker under
`/var/lib/relay-package/` that records what existed before the first install; anything else is
left and named. `.rpm` has no purge: removal prints the paths to delete by hand.

A reinstall after a purge starts with an empty `/var/lib/relay`, so the Relay's first start
creates a new CA and every enrolled relay-daemon must be enrolled again; the purged CA and store
are in the sibling the purge printed.

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

`/etc/relay/relay.toml` is `0640 root:relay`: the Relay reads it and nothing else should. It
holds the **security floor**; whoever can edit it can lower that floor. The Relay takes nothing
from its environment or command line (ADR-0043): a retired `RELAY_*` setting in the environment
refuses start and names the key that replaces it.

## Enable

```console
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now relay
$ systemctl status relay
```

## First credential

The control plane authenticates per-Account API Tokens held in the Relay's store
([ADR-0023](../../docs/adr/0023-retire-the-shared-control-plane-credential.md)); there is no
shared secret in the config. After the Relay has started once and created its store, create the
first admin as the Relay's own account. `relay init` loads `/etc/relay/relay.toml` through the
same start-time check as the Relay, so it refuses root:

```console
$ sudo -u relay relay init --admin <your-name>
```

It prompts for that admin's Console password (not echoed) and prints its first API Token
**once**; it is never persisted, so put it in a vault then. A re-run creates nothing;
`relay init --recover <name>` re-mints for an enabled human admin who has lost every token.

## What is configured here, and what is not

Relay configuration is read from `/etc/relay/relay.toml` and is **never reachable from any
API** (AGENTS.md invariant 11). A stolen API Token cannot raise a blast cap, repoint the CA,
move a listener, or change the OAuth issuer: no code path leads from a request to those values.
That is why these settings live here rather than anywhere more convenient:

| Setting | Why it is startup-only |
|---|---|
| `reach.read_blast_cap` / `reach.mutate_blast_cap` | The cap on how much damage one dispatch can do — including from a compromised AI-agent. An API that could raise its own limit is not a limit. |
| `ca.dir` | The key that mints Node identities. |
| `approval.rules` | A stolen credential that could edit its own approval requirements would make approvals decorative. |
| `[oauth]` | An API that could repoint its own issuer could authenticate anyone. |

Runtime *objects* (Accounts, API Tokens, Enrollment Tokens, Nodes, Jobs, approvals) are
managed through `/api/v1`. The line is between configuration and objects, not between
important and unimportant.

## Secrets are files the configuration names

A credential the Relay needs is given as the path of a file holding it
(`approval.webhook_secret_file`, `approval.webhook_url_file`), never inline and never in the
environment, where it would show in every process listing and crash dump.

At start the Relay refuses to run if it could write the configuration file or any file it
names, or if any account but itself and root could read the configuration or a secret file.
Place a secret file like the configuration, `0640 root:relay`. No secret is ever printed in a
log or an error. The CA directory, its private key and the store's directory belong to the
service account, and are refused if any other account can read them.

API Tokens are not configuration: they live in the store as hashes, and `relay init` mints the
first.

## The state directory

`StateDirectory=relay` gives `/var/lib/relay`, mode `0700`, owned by the service
account. It holds:

- **the CA key and certificate** (`ca/`): the most sensitive material in the deployment.
  Whoever reads it can impersonate the Relay to every Node.
- **the SQLite store**: Jobs, Tasks, the audit trail, Accounts, API Tokens, approvals.

Read [docs/operations/ca-disaster-recovery.md](../../docs/operations/ca-disaster-recovery.md)
before going to production. Recovery from CA compromise means re-enrolling the fleet against a
fresh CA, so its backup and permission posture is not optional.

## Upgrades

Upgrade the Relay by replacing the binary and restarting, through the same config management
as any other service. It never self-upgrades and never pushes binaries to Nodes
([ADR-0014](../../docs/adr/0014-daemon-lifecycle-iac-upgrades-version-gate.md)). Its only lever
over daemon versions is `reach.min_daemon_version`, which refuses dispatch to Nodes below it.

## Keeping the sample honest

`relay.toml.example` has a drift gate in `relay/internal/relayconfig` (`example_test.go`):
every key the loader reads must appear in the sample, and every commented value must be the
built-in default, or the build fails. The daemon's sample has the same gate
(`daemon/tests/packaging_drift.rs`). A sample that omits a setting does not read as
incomplete; it reads as though the setting does not exist.
