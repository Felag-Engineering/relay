# One Relay configuration file

**Status:** Accepted (owner decision 2026-10-15). Amends ADR-0010 and ADR-0033.

Invariant 11 asks two things of the Relay's local configuration: a compromised Relay must not be
able to change its own security floor, and a secret must never leak through the process
environment, a process listing or a container's metadata. The configuration as built answers
those with three mechanisms, each needing its own rule:

- the floor arrives as `RELAY_*` environment variables, placed by systemd from a root-owned
  `EnvironmentFile` — so systemd reads the file and the Relay never sees it, and cannot check
  who owns it;
- each secret is a separate file named by a path, with its own mode rule — and the one check
  that exists today (the webhook secret must be `0600`) refuses the root-owned, group-readable
  layout the packaged Relay needs;
- in a container the floor is injected environment, readable by anyone who can inspect the
  container, including an approval webhook URL that may itself be a credential.

Drafting the packaging amendment to ADR-0033 grew a rule for each of these: who owns a secret,
who owns the secrets directory, when a floor file can be checked at all, which container values
are exposed. The rules were each correct and together obscured the property they serve.

## Decisions

**1. One configuration file, which the Relay reads itself.** Every security-floor setting lives
in one TOML file — `/etc/relay/relay.toml` on a packaged host, a read-only mount in a container.
That path is the default, and one command-line flag, `--config`, may name another; the path is
the only configuration the Relay accepts from outside the file. No floor setting is read from the
environment or the command line. TOML because it is what the daemon's Policy already uses, and
because it holds structure (listeners, the identity provider, the approval path) that a flat
`KEY=value` file flattens into naming conventions.

**2. Secrets may sit in that file.** A secret is a value in the configuration file, or a path to
a file holding it — the second for material another tool manages and rotates, such as a TLS
certificate a certificate manager renews or a token a secrets agent writes. Either way a secret
never passes through the environment or the command line, which is the property the old
"secrets are file paths" rule protected; a value in a protected file meets it as well as a path
does.

**3. One check, the same everywhere.** At start, and on every reload, **the Relay refuses to run
if it could write its configuration file, or if anyone but it could read it.** The not-writable
half applies to every file the configuration names — a TLS chain or trust bundle decides whom
the Relay trusts as surely as a setting does — and the not-readable half to every file that holds
a secret. Material the Relay generates in its own state directory is exempt (decision 4). This is
the property itself, tested directly, rather than a proxy for it such as "owned by root, mode
`0640`".

"Could write" is not a mode test, because a mode test passes files the Relay can make writable.
The Relay **could write** a file when any of these holds:

- the file is owned by the Relay's uid, on a filesystem mounted writable — an owner can always
  restore its own write bit;
- its mode or an access-control list grants write to the Relay's uid or any of its groups;
- any directory on its resolved path is owned by, or writable by, the Relay — a writable
  directory lets the Relay replace the file between checks;
- the Relay runs as uid 0, or holds any capability.

"Anyone but it could read" means any account other than the Relay and root. The packaged layout,
`root:relay 0640` with the Relay's group holding only the Relay, passes; an account an operator
adds to that group is one they have chosen to give the Relay's secrets to. A file another tool
manages passes the same way: owned by root, readable by the Relay's group.

The check and the read use the same open descriptor: the Relay opens each file without following
a symlink, checks the descriptor, and reads from it, so nothing can change between the check and
the read. A path that is a symlink is refused; an operator whose tool writes symlinked layouts
points the configuration at the real file.

**4. One state directory, which is the Relay's.** Everything the Relay generates — its CA private
key, its store — lives in its state directory, owned by the Relay's uid and readable by nobody
else. The Relay refuses to start if that directory, or the key in it, is readable by anyone
else.

**Secret values never appear.** No inline secret value, and no approval webhook URL — which may
itself be a credential — appears on any surface, in any log or audit record, or in any refusal
message. A reload's audit record names a changed secret setting, never its value; a parse or
validation error names the key and the line, never the value.

**5. Reload re-reads the one file.** `SIGHUP` re-reads the configuration from the path given at
start and applies the same check before anything else. A container reloads by restarting.

**6. A clean break from `RELAY_*` floor variables.** Nothing has been released, so no operator
depends on them. A `RELAY_*` variable for a floor setting found in the environment refuses start
and names the setting's place in the file, rather than being silently ignored or silently
honoured.

## Considered Options

- **Keep environment variables and fix each rule.** Rejected: it keeps three mechanisms, keeps
  systemd between the Relay and the file it would need to check, and keeps a container's floor —
  and any credential-shaped value in it — readable through `docker inspect`.
- **A `KEY=value` file the Relay reads itself.** Closer to today's syntax, but a flat namespace
  for nested settings, and a second configuration format beside the daemon's TOML.
- **Paths only for secrets.** Kept as an option, not a requirement: forcing every secret into its
  own file multiplies the files to check and gives operators more to get wrong, while the
  property is the same.
- **Keep one release of backward compatibility for `RELAY_*` variables.** Unnecessary before a
  first release, and it would mean two supported ways to set the floor for a release.

## Consequences

Invariant 11's secret sentence is reworded to state its purpose: secrets never pass through the
environment or the command line; the Relay can read them and cannot rewrite them, except key
material it generates itself. ADR-0010's floor-as-environment-variables mechanism and ADR-0033's
packaged `EnvironmentFile` and secrets directory are replaced; both record it.

The Relay package installs `relay.toml` instead of `relay.env`, written once at first install
under the rules ADR-0033 already sets. The container stack mounts the file read-only instead of
injecting environment, which removes most of R35: a container's floor is no longer visible
through its metadata.

Known-gap row 11 (#864) becomes the work to build this: the loader, the one check, the state
directory check, and removing the environment path. The Relay's help and error text that says
"root-owned" goes with it.
*(Amended 2026-10-21: built, and the row is deleted from `AGENTS.md`; see the 2026-10-21
amendment below.)*

The daemon is unchanged. Its configuration is config management's, and invariant 11 is the
Relay's.

## Amendment (2026-10-21): known-gap row 11 is closed

A note on one reference, not a change to any decision here. *Consequences* names known-gap row
11 in `AGENTS.md` as the work to build this decision. The loader, the file check and the
removal of the environment path have landed, and the row is deleted; what is proven is recorded
claim by claim in `docs/specs/relay-configuration.md`. Signposted in place, dated.
