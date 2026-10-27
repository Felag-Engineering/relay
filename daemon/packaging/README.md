# relay-daemon packaging

A hardened `systemd` unit for running `relay-daemon` in production, plus an example
`EnvironmentFile`.
[docs/operations/daemon-privilege-posture.md](../../docs/operations/daemon-privilege-posture.md)
has the per-Operation privilege map, the reason for every hardening directive, and the
exception for Nodes that run `pkg.install` or filesystem-mutating Raw Exec.

## Packages

`nfpm/` holds the manifest for the one package, built as `.deb` and `.rpm` by
`scripts/build-packages.sh` with the nfpm pinned under `tools/nfpm`; `scripts/` holds the
daemon package's maintainer scripts. The release builds both twice and refuses unless
the builds are byte-identical and each package's `/usr/bin/relay-daemon` is the release binary.
It reads every package with `dpkg-deb` and `rpm` and checks its whole content against
`expected/` and `scripts/`.

**The packages are not yet attached to a release.** They wait until the install matrix proves
them on every supported platform and the unit's syscall filter is verified on a real systemd
host. The standalone unit and environment example are release attachments; until the packages
are, install by hand as below.

- **`relay-daemon`** installs `/usr/bin/relay-daemon`, the unit as
  `/usr/lib/systemd/system/relay-daemon.service`, and reference copies of the default Policy
  and this directory's environment example under `/usr/share/relay-daemon/`. On a first
  install only it creates `/etc/relay-daemon`, the empty Policy directory
  `/etc/relay-daemon/policy.d` and `/var/lib/relay-daemon` (`0700`), each if absent; places the
  default as `/etc/relay-daemon/policy.toml` only if no Policy file exists and the Policy
  directory did not exist before the install; places `/etc/relay-daemon/relay-daemon.env`
  (root `0600`) only if none exists; and, where systemd is running,
  runs `systemctl preset`. It never starts or restarts the daemon, and never rewrites the
  Policy or the environment file. An upgrade runs `systemctl daemon-reload` only. It also
  carries the shipped read catalog: package-owned plain files under
  `/etc/relay-daemon/templates.d/relay-read/`, replaced on upgrade and removed with the
  package. On a Node holding a pre-release `relay-read` package, `relay-daemon` replaces
  and removes it on upgrade (Replaces and Conflicts on .deb; Obsoletes and Conflicts on
  .rpm).

Removing `relay-daemon` stops and disables the unit and removes the binary, the unit and the shipped catalog. It
keeps the Policy, the Policy directory, the environment file and the state directory (the
Node's identity). `apt purge` then deletes those the package created, using a marker under
`/var/lib/relay-daemon-package/` that records what existed before the first install; a
directory holding anything the package did not put there is left and named. `.rpm` has no
purge: removal prints the paths to delete by hand.

## Install

```console
$ sudo install -m 0755 /path/to/relay-daemon /usr/bin/relay-daemon
$ sudo install -m 0644 relay-daemon.service /etc/systemd/system/relay-daemon.service
$ sudo mkdir -p /etc/relay-daemon
$ sudo install -m 0644 -o root -g root /path/to/policy.toml /etc/relay-daemon/policy.toml
$ sudo install -D -m 0644 templates.d/relay-read/catalog.toml /etc/relay-daemon/templates.d/relay-read/catalog.toml
$ sudo install -m 0600 -o root -g root relay-daemon.env.example /etc/relay-daemon/relay-daemon.env
$ sudo "$EDITOR" /etc/relay-daemon/relay-daemon.env   # fill in RELAY_* values, see below
```

The environment file holds no secret and no join string. The install ends by enrolling the
Node, under Enroll below.

Without a Policy of your own, install the shipped default
([`../policy.default.toml`](../policy.default.toml), ADR-0022): `read` pre-allowed with a
confidentiality deny-list; `mutate` and Raw Exec opt-in.

`relay-read-catalog.ledger` binds each released name in the shipped read catalog to its body
digest and risk class. It is append-only, and a changed Template ships under a new name.

Policy (`/etc/relay-daemon/policy.toml`) must be root-owned and not group- or world-writable;
the daemon's fail-closed loader refuses it otherwise. Beside it sits the Policy directory,
`/etc/relay-daemon/policy.d`: every file in it is a Policy fragment, composed with the Policy
file into one Policy with one fingerprint. The install creates the directory empty (`0755`)
and never writes into it again; config management populates it. Fragments are root-owned and
not group- or world-writable too. A fragment that is a symlink, is not a regular file or is
insecure, or an insecure directory, makes the daemon refuse to start; a fragment that cannot
be read or parsed leaves the whole Policy deny-all; so does a key the daemon does not read
(a mistyped `[[denny]]`), in a fragment or in the Policy file. A `policy.toml` beside fragments
is optional: with none, the daemon composes the fragments alone, and with neither it runs
deny-all. Policy is delivered by
the customer's config management, **never over the wire**: the Relay may query a Node's Policy
fingerprint but can never modify it (ADR-0002). Changing Policy is a config-management push
followed by a daemon restart, not an API call.

## Enable

```console
$ sudo systemctl daemon-reload
$ sudo relay-daemon join          # paste the join string; it enrolls and starts the unit
$ systemctl status relay-daemon
```

`relay-daemon join` reads the join string from a prompt with echo off, or from standard input,
pins the Relay's CA from it, enrolls, persists the identity, and enables and starts the unit.

## Upgrades

The daemon never self-upgrades and the Relay never pushes a binary (ADR-0014). Upgrade
`/usr/bin/relay-daemon` through the same config management as the Policy file: land the
new artifact, then `systemctl restart relay-daemon`. The Relay's only lever is refusing to
*dispatch* Tasks to an out-of-date Node.

## No join string is ever on disk

`relay-daemon join` enrolls in the process that read the join string (ADR-0031, ADR-0033), so
the join string, and with it the Enrollment Token, is written nowhere and never sits in the
daemon's environment. `relay-daemon.env` holds no secret. The daemon reads no join string, and
refuses to start while `RELAY_JOIN` is set, so a stale line is noticed rather than ignored.
