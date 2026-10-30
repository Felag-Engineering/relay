# Installing and running the relay-daemon

How to install the relay-daemon, the non-AI Rust daemon on each managed Node, from
its OS package. The short version is
[`daemon/packaging/README.md`](../../daemon/packaging/README.md). See also
[relay-install.md](relay-install.md) (the Relay side), [enrollment.md](enrollment.md)
(joining the fleet), [policy-as-code.md](policy-as-code.md) (the Policy file),
[daemon-privilege-posture.md](daemon-privilege-posture.md) (the hardened unit's rationale),
and [release-artifacts.md](release-artifacts.md) (the artifact contract).

## 1. Obtain and verify the package

Releases publish the daemon as a `.deb` (`relay-daemon_<pkgversion>-1_amd64.deb`) and an
`.rpm` (`relay-daemon-<pkgversion>-1.x86_64.rpm`), and the same for arm64, plus a `SHA256SUMS`
signed by `SHA256SUMS.sigstore.json`. Check the signature with `cosign verify-blob` first, when
you take the pin and record `PINNED_SHA256`, as
[release-artifacts.md](release-artifacts.md#verify-then-install) shows. Then verify the
package before you install it; a mismatch aborts:

```bash
VERSION="X.Y.Z"         # the release pinned by the operator, in config management
# The package's SHA-256, recorded from the cosign-verified SHA256SUMS when the pin was taken.
PINNED_SHA256="<64-hex digest recorded when you reviewed the release>"
PKGVERSION="${VERSION//-/.}"
DEB="relay-daemon_${PKGVERSION}-1_amd64.deb"      # or relay-daemon-${PKGVERSION}-1.x86_64.rpm
BASE="https://github.com/Felag-Engineering/relay/releases/download/v${VERSION}"

curl -fsSLO "${BASE}/${DEB}"
curl -fsSLO "${BASE}/SHA256SUMS"
echo "${PINNED_SHA256}  ${DEB}" | sha256sum --check -   # the pinned digest, BEFORE install; failure is fatal
sha256sum --check --ignore-missing SHA256SUMS           # the downloaded checksum file must agree
```

A package carries no signature of its own before v1.0.0: the signed `SHA256SUMS` covers it
(DI-24, ADR-0033). For which platforms a release proves the package on, see
[the install matrix](release-artifacts.md#the-install-matrix-gates-the-packages).

In production config management runs this sequence: see [enrollment.md](enrollment.md) for
the release's Ansible role and [iac-upgrades.md](iac-upgrades.md) for upgrades.

## 2. Configuration surface

The daemon is configured entirely by environment variables, read once at startup
(`daemon/src/config.rs`), conventionally through the unit's `EnvironmentFile`
(`/etc/relay-daemon/relay-daemon.env`). The package placed that file (root `0600`) on its first
install, copied from the example, which stays at `/usr/share/relay-daemon/relay-daemon.env.example`
([source](../../daemon/packaging/relay-daemon.env.example)). The package never rewrites it:

| Variable | Default | Meaning |
|---|---|---|
| `RELAY_ADDRESS` | *(the address persisted at enrollment from the join string `relay-daemon join` read)* | Optional override of the Relay's Node-plane gRPC address. `http://` is normalized to `https://`; the connection is always mTLS (invariant #6). Overrides the persisted address on every start when set. Also settable as the `--relay <addr>` CLI argument. |
| `RELAY_SERVER_NAME` | *(unset)* | Optional: the name the daemon expects on the Relay's certificate, sent as TLS SNI and verified against its SAN, when it differs from the dialed host, such as a load-balanced endpoint. An IP-literal address, IPv6 included, needs none: the daemon verifies it against the certificate's IP SAN. |
| `RELAY_STATE_DIR` | `/var/lib/relay-daemon` | Where the enrolled identity (`key.pem`, `cert.pem`, `ca_bundle.pem`, `node_id`, `relay_addr`) and the at-most-once dedup marker store (`seen-tasks/`) persist. |
| `RELAY_POLICY_PATH` | `/etc/relay-daemon/policy.toml` | Path to this Node's Policy file (ADR-0002). Its Policy directory is `policy.d` beside it (default `/etc/relay-daemon/policy.d`), with no setting of its own. See [policy-as-code.md](policy-as-code.md). |
| `RELAY_TEMPLATE_DIR` | `/etc/relay-daemon/templates.d` | Root of this Node's Template Operation files, beside `policy.toml` and under the same root-owned trust root (ADR-0021). Absent = no templates installed. The shipped read catalog installs to `templates.d/relay-read/`. See [template-packs.md](template-packs.md). |
| `RELAY_NODE_LABELS` | *(unset)* | Comma-separated bare `key=value` pairs reported as node-space Labels (the daemon adds the `node:` prefix; it can never emit `relay:` labels — ADR-0006). Example: `env=prod,role=web`. Each key and value must match `[A-Za-z0-9._-]+` (the empty value is accepted); anything else is refused at ingress, never sanitised. A malformed pair is REFUSED at enrollment — the Node does not join — and DROPPED at reconnect — the Node stays connected without that one label. The daemon also declares `node:hostname`, `node:os` and `node:arch` by default (its hostname, and the OS and architecture as Rust names them: `linux`; `x86_64`, `aarch64`). A key set here replaces the default of the same name, e.g. `hostname=web-01`. Overriding `os` takes the Node out of `node:os=linux`, the label that targets the whole fleet; to target a distribution, declare another key such as `distro=ubuntu`. `node:hostname` is self-reported and not unique; target a single Node by its Node ID. `node:os=linux` is for routine targeting and is never a security-lane target, which uses `relay:` labels (invariant 7). A default that is not a well-formed label (an unusual hostname) is left out with one log line naming its key, and the Node still joins. |
| `RELAY_ENROLL_ADDRESS` | *(falls back to `RELAY_ADDRESS`, then the join string's address)* | Optional distinct endpoint for the enrollment RPC `relay-daemon join` makes. Must be `https://` — anything else is refused (fail closed). The CA pin applies to whichever endpoint is dialled. |
| `RELAY_SHUTDOWN_GRACE_SECS` | `30` | Graceful-shutdown grace period: on SIGTERM/SIGINT the daemon stops accepting Tasks, drains in-flight ones up to this budget, then exits. |
| `RUST_LOG` | `info` | Log filter (`tracing_subscriber` EnvFilter syntax). Keep Policy decision events on: see [section 6](#6-local-record-of-policy-decisions). |

The heartbeat is built in, not a setting: the daemon sends one every 60 seconds, jittered ±20%, and the Relay marks a Node offline and closes its stream after three missed heartbeats (about three minutes). A daemon older than this one that still sets `RELAY_HEARTBEAT_INTERVAL_SECS` above about 150 would be marked offline between its own heartbeats, so remove that setting when upgrading. Upgrade the Relay before the daemons: a daemon of this version against an older Relay is disconnected repeatedly by the Relay's ping enforcement.

Fail-closed behaviors to know about (all deliberate):

- **No identity → exit cleanly.** With no identity file the daemon logs one line and exits 0,
  so an unconfigured Node stays inactive without failing or retrying. It dials nothing and
  never falls back to a plaintext dial (ADR-0005). The daemon never enrolls:
  `relay-daemon join` does.
- **`RELAY_JOIN` set → refuse to run.** `RELAY_JOIN` is not a setting. The daemon exits
  non-zero naming it, however it is set (empty included), so a stale line in an existing
  environment file is noticed. Remove the line, then enroll with `relay-daemon join`.
- **Broken configuration → refuse to run.** A partial identity (some but not all of
  `key.pem`, `cert.pem`, `ca_bundle.pem`, `node_id`) exits non-zero.
- **Untrusted state directory or address file → refuse to run.** A state directory that is a
  symlink, group- or world-writable, or not owned by root, and a `relay_addr` that is a
  symlink, not a regular file, group- or world-writable, or not owned by root, stop both
  `relay-daemon join` and the unit before anything in the directory is read. The error names
  the path. The package and the unit (`StateDirectoryMode=0700`) create the directory
  root-owned `0700`.
- **No Relay address → refuse to run.** An enrolled daemon with neither `RELAY_ADDRESS` nor a
  persisted address exits non-zero, naming `RELAY_ADDRESS`; there is no localhost default. A
  Node with no persisted address works only while `RELAY_ADDRESS` is set; nothing backfills it.
- **Policy unreadable, or missing with no fragment → deny-all.** The daemon starts, connects,
  and denies every Task rather than refusing to start or running open (ADR-0002). A group- or
  world-writable Policy file is likewise refused. A `policy.toml` beside fragments is
  optional: with no Policy file and at least one fragment in `policy.d`, the daemon composes
  the fragments alone, and warns `no policy file; composing the Policy directory's fragments
  alone`. That drops every deny the file held, the shipped confidentiality deny-list included,
  so keep load-bearing denies in a fragment as well. A Node whose `/etc/relay-daemon/policy.d`
  already existed when the package was installed gets no default Policy file, so its fragments
  are its whole Policy. Deleting the Policy file locks a Node down to deny-all only when
  `policy.d` holds no fragment.
- **A Policy fragment or Policy directory refused → refuse to run.** A fragment in `policy.d`
  that is a symlink, is not a regular file, or is group/world-writable or owned by neither
  root nor the daemon's user, and a `policy.d` that is insecure the same way, exit the daemon
  non-zero. The journal line `policy fragment or Policy directory refused` names the reason.
- **A broken fragment → deny-all.** A fragment that cannot be read or parsed invalidates the
  whole Policy: the daemon runs deny-all, with no partial load. A key the daemon does not read
  (a mistyped `[[denny]]`) is a parse error, in a fragment or in the Policy file, and
  `relay-daemon policy check` reports it.
- **Non-`https` enrollment endpoint → fatal.** TLS, and the CA pinning that rides on it, is
  only active under `https://`.

## 3. Subcommands

These are offline: no network, no identity, no Relay.

- `relay-daemon --version` / `-version` / `-V` — print the build stamp and exit (the same
  three spellings as the Relay; [version-stamping.md](version-stamping.md)).
- `relay-daemon policy check <file> [--policy-dir <dir>] [--strict] [--templates <dir>] [--would-allow <spec>]` —
  lint a Policy file, and with `--policy-dir` the fragments in `<dir>` together with it. With
  `--templates`, it also lints the Template files under `<dir>` and resolves Operation names
  against them. It can optionally
  answer a hypothetical through the evaluator the live wire path uses (ADR-0011).
  It prints the Policy fingerprint those files give. Exit codes `0` valid / `1` invalid / `2`
  would-deny. See [policy-as-code.md](policy-as-code.md).
- `relay-daemon dump-operation-schema` — print the canonical Operation schema JSON (ADR-0015).

One subcommand changes the Node. It is the only thing that enrolls it:

- `sudo relay-daemon join` — enroll this Node in one step (DI-42). It reads the join string
  from a prompt with echo off, or from standard input (piped from the operator's secret
  store, never saved to a file on the Node), and refuses one given as an argument. It stops
  before reading the string if the Node already holds an identity (it then changes nothing and exits 0, so config management may rerun it).
  It refuses before reading the string if the environment file is one it cannot parse, if a
  setting it reads from the shell disagrees with the file, or if `RELAY_JOIN` is set. Then it pins the
  Relay's CA from the string's fingerprint, enrolls over TLS trusting only that CA, persists
  the identity and the Relay address in the state directory, and enables and starts the unit
  (`/usr/bin/systemctl enable --now relay-daemon.service`).

  The join string is written nowhere and never sits in an environment: `join` reads
  `/etc/relay-daemon/relay-daemon.env` and never writes it. When that file exists its
  `RELAY_STATE_DIR`, `RELAY_ADDRESS`, `RELAY_ENROLL_ADDRESS`, `RELAY_SERVER_NAME` and
  `RELAY_NODE_LABELS` govern, as they do for the unit, and a different value in the shell
  `join` runs in (`sudo -E`) is refused rather than enrolled somewhere the unit does not look.
  Without that file the shell's environment governs. It starts the unit only where systemd is
  running and only for the state directory the unit reads; elsewhere it says so and exits 0.

  The join string's integrity rides on the channel you moved it over. The CA fingerprint
  inside it is the only thing a Node that has never reached the Relay trusts, so whoever can
  change the string on the way can put in their own address and fingerprint, and the Node
  enrolls with their Relay instead (ADR-0031). Move it only over a channel that protects it
  from alteration as well as from reading: your vault, an SSH session to the Node, the Ansible
  role's standard input. Never over chat, email or a ticket.

  A failed run (a CA that does not match the fingerprint, an unreachable Relay, a rejected
  token, an interrupt) leaves the state directory as it found it, and says what, if anything,
  it could not remove. After an interrupt, a timeout, or a failure once the Relay had answered
  (a bundle that is not the pinned CA, a certificate that does not match the key, a write that
  failed) the Relay may have recorded the enrollment: if the rerun reports the token used up,
  mint another and revoke the stray Node.

  While one `join` runs, a second against the same state directory is refused and changes
  nothing; a second that starts after the first has enrolled finds the identity and exits 0.

  Exit codes: `0` enrolled (or already enrolled), `1` refused or failed, `2` given arguments,
  `130` interrupted. If a terminal is left without echo, `stty echo` restores it.

## 4. Install on the Node

```console
$ sudo apt-get install ./relay-daemon_<pkgversion>-1_amd64.deb   # or: sudo dnf install ./relay-daemon-<pkgversion>-1.x86_64.rpm
$ sudoedit /etc/relay-daemon/relay-daemon.env   # set RELAY_NODE_LABELS
$ sudo relay-daemon join      # paste the join string; it enrolls and starts the unit
$ systemctl status relay-daemon
```

What the package did:

- Placed the binary at `/usr/bin/relay-daemon` and the hardened unit at
  `/usr/lib/systemd/system/relay-daemon.service`.
- Placed the shipped read catalog under `/etc/relay-daemon/templates.d/relay-read/`. The
  package owns it and replaces it on upgrade; never write into it.
- Placed the shipped default Policy as `/etc/relay-daemon/policy.toml`, only on a first install
  where no Policy file and no `policy.d` already existed.
- Created an empty `/etc/relay-daemon/policy.d`, for fragments you place.
- Placed `/etc/relay-daemon/relay-daemon.env` (root `0600`, from the example) if none existed.
- Created the state directory `/var/lib/relay-daemon` (`0700`).
- Ran `systemctl preset` where systemd runs. It never starts the daemon. Whether the unit is
  enabled at boot follows the distribution's presets, and `join` enables and starts it anyway.

If `/etc/relay-daemon` is a symlink, isn't root's, or is group- or other-writable, the package
places nothing in it and does not enable the unit.

Where the pieces come from:

- **The unit** is the shipped hardened one, installed at
  `/usr/lib/systemd/system/relay-daemon.service` from
  [`daemon/packaging/relay-daemon.service`](../../daemon/packaging/relay-daemon.service):
  `User=root` by necessity, everything else stripped.
  [daemon-privilege-posture.md](daemon-privilege-posture.md) explains every directive, and the
  `pkg-install.conf` drop-in for Nodes that run `pkg.install` or filesystem-mutating Raw Exec.
- **The Policy** is yours after the first install. To replace it or add fragments, see
  [policy-as-code.md](policy-as-code.md); it stays root-owned and not group/world-writable.
  Check the composed Policy with
  `relay-daemon policy check /etc/relay-daemon/policy.toml --policy-dir /etc/relay-daemon/policy.d --templates /etc/relay-daemon/templates.d --strict`.
  `--strict` passes on the shipped default only when `--templates` is given, because without
  it the read catalog's Operation names are unknown (DI-28). The annotated example is
  [`daemon/policy.example.toml`](../../daemon/policy.example.toml); the shipped default
  (`read` pre-allowed with a confidentiality deny-list, `mutate` and Raw Exec opt-in,
  ADR-0022) is [`daemon/policy.default.toml`](../../daemon/policy.default.toml).
- **`relay-daemon.env`** holds no secret and no join string, and is `0600 root:root` as
  defence in depth. No CA file is installed: `relay-daemon join` pins the Relay's CA from the
  join string and writes it into the state directory at enrollment.

**Hand-built install.** It is documented in
[`daemon/packaging/README.md`](../../daemon/packaging/README.md), and its pieces are verified
per DI-32. It is not supported: the package is the only supported install, and no supported
procedure moves a hand-built Node onto the package.

## 5. Verify

On the Node:

```console
$ journalctl -u relay-daemon -f
# expect: "relay-daemon starting", "policy loaded" (with the fingerprint),
# then "received Ping from Relay" (enrollment happened in relay-daemon join)
```

On the Relay's control plane the new Node appears in `list_nodes` (MCP) with its Facts,
Labels, and Policy fingerprint; [enrollment.md](enrollment.md) has the full verification
loop.

## 6. Local record of Policy decisions

The daemon keeps its own record of its Policy decisions, so a Node holds evidence of what it
was asked to run even if the Relay is compromised. Each Policy gate decision (a Task's one pass
through the Policy engine, or the canonical-path refusal just before it) is one structured log
line, shipped by journald and your log pipeline. The path re-check after an Allow, by
`file.read` and for each Template `path` slot, is a second evaluation that is not logged at the
deny target: a refusal there shows only as the Task's result, after the Allow line. The daemon
writes no file of its own; retention is journald's (`SystemMaxUse=` / `MaxRetentionSec=` in
`journald.conf`).

- **Allow:** target `relay_daemon::allow`, one event per Policy Allow, emitted after the
  decision and before anything is invoked or spawned. It records the Allow, not a successful
  run: a Template slot refused afterwards, or a `file.read` or Template `path` slot that fails
  its path re-check, still logged an Allow.
- **Deny:** target `relay_daemon::deny`, the same field names.

Shared fields: `task_id`, `operation` (the Operation name, or `raw_exec`),
`tier` (`native`, `template` or `raw_exec`), `risk_class`, `argv_digest`, `argc`
and `policy_fingerprint`. An Allow, and a Deny by a rule, also carry `rule`. A
Deny adds `reason`, plus `args` for a typed Operation Policy Deny or `program`
(`argv[0]`) for Raw Exec. The canonical-path Deny carries neither `args` nor
`rule`, only `reason`.

`task_id`, `operation`, `reason`, `args` and `program` come from the caller and
are written quoted, with control characters such as a newline escaped, so a
caller-supplied value cannot start a second journal line. Each is capped at 256
characters (an `args` list at 16 elements); a value that was cut ends with `…`
after its closing quote. The full text stays in the Task's result. The same
escaping applies to every Relay-supplied value the daemon logs, such as the
`node_id` in renewal and enrollment messages and Relay error text. It does not
cover the daemon's own load errors for its root-owned Policy and Template
files, which are logged as written and can span several lines.

An Allow never carries argv. A Raw Exec Allow carries only the digest and
`argc`. There is no Job id on the wire to a Node: correlate by `task_id` against
the Relay's audit trail.

`argv_digest` is the SHA-256 of the elements joined by a NUL byte. For a typed
Operation the first element is the Operation name, followed by its positional
arguments in Policy order; for Raw Exec the elements are the argv. `argc` counts
the elements. For a Template `path` slot the argument is the path as the caller
sent it; the command receives the resolved target the daemon re-checked, which can
be a different spelling of the same file. To reproduce one:

```console
$ printf "%s\0%s" /bin/echo hello | sha256sum
```

The digest is unsalted and meant for correlation, not secrecy: anyone who can
read the journal can confirm a guess at a low-entropy argument.

Log lines are plain text with no ANSI colour, so `journalctl` filters them
directly. To list every decision:

```console
$ journalctl -u relay-daemon -g 'relay_daemon::(allow|deny):'
```

If your `journalctl` was built without PCRE2, filter with grep instead:

```console
$ journalctl -u relay-daemon | grep -E 'relay_daemon::(allow|deny):'
```

A `RUST_LOG` filter above `info` drops Allows. To quiet the daemon and keep the record, use
`RUST_LOG=warn,relay_daemon::allow=info`. Module-path directives do not govern decision
events, which sit at `relay_daemon::allow` and `relay_daemon::deny`. A module directive names
the crate that holds the module:

- `relay_daemon`: the bin (dispatch, scheduler, dedup, shutdown, startup);
- `relay_exec`: the executor;
- `relay_ops`: Operations, Templates, Raw Exec;
- `relay_transport`: Tunnel, enrollment, renewal, identity;
- `relay_policy`: Policy loading and lint.

A bare `relay_daemon=<level>` reaches only the bin's modules and the two
decision targets. Example: `RUST_LOG=info,relay_ops::raw_exec=debug`.

## 7. Lifecycle

- **Upgrades:** the daemon never self-upgrades and the Relay never pushes binaries
  (ADR-0014). Install the newer verified package through config management, then
  `systemctl restart relay-daemon`: the package runs `daemon-reload` only and never restarts.
  An upgrade replaces the binary, the unit and the shipped catalog, and never rewrites the
  Policy, the env file or the state directory ([iac-upgrades.md](iac-upgrades.md)). **From
  v0.1.0, remove the `RELAY_JOIN` line from `/etc/relay-daemon/relay-daemon.env` first.** That
  release placed the line (empty from the package, the join string from `relay-daemon join`),
  and this daemon refuses to start while it is set. Any join string it held was an Enrollment
  Token: let it expire.
- **Policy changes:** a config-management file push and daemon restart, never over the wire
  ([policy-as-code.md](policy-as-code.md)).
- **Certificate renewal:** automatic. Identity certs live ~14 days and the daemon renews over
  its existing mTLS connection at a jittered 50–75% of cert lifetime, with retries (ADR-0006).
- **Decommissioning:** revoke the Node on the Relay (`POST /api/v1/nodes/{node_id}/revoke`,
  with a required JSON body `{"reason": "..."}`), then remove the package. Removing keeps the
  Policy, `policy.d`, the env file and the state directory. `apt purge` deletes the ones the
  package created, the Node's identity included (DI-31), and leaves any that existed before the
  package was first installed. `.rpm` removal prints the paths to delete by hand.
