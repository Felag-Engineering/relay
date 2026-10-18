# relay-daemon packaging

A hardened `systemd` unit for running `relay-daemon` in production, plus an example
`EnvironmentFile`. See
[docs/operations/daemon-privilege-posture.md](../../docs/operations/daemon-privilege-posture.md)
for the full per-Operation privilege map, the rationale behind every hardening
directive, and the documented exception for Nodes that run `pkg.install` or
filesystem-mutating Raw Exec.

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
