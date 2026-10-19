# relay-daemon packaging

A hardened `systemd` unit for running `relay-daemon` in production, plus an example
`EnvironmentFile`. See
[docs/operations/daemon-privilege-posture.md](../../docs/operations/daemon-privilege-posture.md)
for the full per-Operation privilege map, the rationale behind every hardening
directive, and the documented exception for Nodes that run `pkg.install` or
filesystem-mutating Raw Exec.

## Packages

`nfpm/` holds the manifests for two packages, each built as `.deb` and `.rpm` by
`scripts/build-packages.sh` with the nfpm pinned under `tools/nfpm`; `scripts/` holds the
daemon package's maintainer scripts. The release builds both packages twice and refuses unless
the two builds are byte-identical, and checks that each package's `/usr/bin/relay-daemon` is the
release binary byte for byte. **They are not yet attached to a release**: no package carrying
the unit ships until its syscall filter is verified on a real systemd host and the install
matrix proves the packages on every supported platform. Until then, install by hand as below.

- **`relay-daemon`** installs `/usr/bin/relay-daemon`, the unit as
  `/usr/lib/systemd/system/relay-daemon.service`, and reference copies of the default Policy
  and this directory's environment example under `/usr/share/relay-daemon/`. On a first
  install only it creates `/etc/relay-daemon`, the empty Policy directory
  `/etc/relay-daemon/policy.d` and `/var/lib/relay-daemon` (`0700`), each if absent; places the
  default as `/etc/relay-daemon/policy.toml` only if no Policy file exists and the Policy
  directory did not exist before the install; places `/etc/relay-daemon/relay-daemon.env`
  (root `0600`, with an empty `RELAY_JOIN`) only if none exists; and, where systemd is running,
  runs `systemctl preset`. It never starts or restarts the daemon, and never rewrites the
  Policy or the environment file. An upgrade runs `systemctl daemon-reload` only.
- **`relay-read`** is the shipped read catalog, optional, depending on `relay-daemon`. Its
  Templates are package-owned plain files under `/etc/relay-daemon/templates.d/relay-read/`:
  replaced on upgrade and removed with the package.

Removing `relay-daemon` stops and disables the unit, then removes the binary and the unit, and
keeps the Policy, the Policy directory, the environment file and the state directory, which
holds the Node's identity. `apt purge` then deletes those of them the package created, read
from a marker under `/var/lib/relay-daemon-package/` that records which existed before the
first install; a directory holding anything the package did not put there is left and named.
`.rpm` has no purge: removal prints the paths to delete by hand.

## Install

```console
$ sudo install -m 0755 /path/to/relay-daemon /usr/local/bin/relay-daemon
$ sudo install -m 0644 relay-daemon.service /etc/systemd/system/relay-daemon.service
$ sudo mkdir -p /etc/relay-daemon
$ sudo install -m 0644 -o root -g root /path/to/policy.toml /etc/relay-daemon/policy.toml
$ sudo install -m 0600 -o root -g root relay-daemon.env.example /etc/relay-daemon/relay-daemon.env
$ sudo "$EDITOR" /etc/relay-daemon/relay-daemon.env   # fill in RELAY_* values, see below
```

If you have not authored a Policy yet, install the shipped default
([`../policy.default.toml`](../policy.default.toml), ADR-0022): `read` pre-allowed with a
confidentiality deny-list; `mutate` + Raw Exec stay opt-in.

`relay-read-catalog.ledger` binds each released name in the shipped read catalog to its body
digest and risk class. It is append-only, and a changed Template ships under a new name.

Policy (`/etc/relay-daemon/policy.toml`) must be root-owned and not group/world-writable
— the daemon's fail-closed loader refuses it otherwise. Policy is delivered by the
customer's config management, **never over the wire**: the Relay may query a Node's
Policy fingerprint but can never modify a Node's Policy (ADR-0002). Rotating Policy is a
config-management push followed by a daemon reload/restart, not an API call.

## Enable

```console
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now relay-daemon
$ systemctl status relay-daemon
```

## Upgrades

The daemon never self-upgrades and the Relay never pushes a binary (ADR-0014). Upgrading
`/usr/local/bin/relay-daemon` flows through the same config-management pipeline as the
Policy file: land the new artifact, then `systemctl restart relay-daemon`. The Relay's
only lever over daemon version is refusing to *dispatch* Tasks to an out-of-date Node —
it never reaches into a Node to change its binary.

## The join string lives in the env file

`relay-daemon.env` carries `RELAY_JOIN`, and with it the Enrollment Token, in plaintext
on disk (0600 root:root). That is decided, not interim (ADR-0031, amended 2026-10-16):
the daemon reads the join string only when no identity exists, pins the Relay's CA from
it before sending the token, and ignores it on every later start. Removing the line
once the Node has enrolled is the compensating control.
