# Daemon privilege posture

The relay-daemon is, by design, the most privileged binary in the system: it is remote
code execution as a service, gated by Policy (ADR-0002) rather than by dropping
privilege. This document records what the daemon genuinely needs root for today, what
the hardened unit (`daemon/packaging/relay-daemon.service`) restricts, and what remains
for a follow-up audit.

## Scope

This is **v0.0.7 groundwork** — a "restricted user" posture that bounds everything the
daemon does *not* need, shipped as an example hardened `systemd` unit plus this map from
Operation to privilege. It is explicitly **not** the v0.0.8 capability/syscall audit: the
unit deliberately omits `SystemCallFilter` and `MemoryDenyWriteExecute` (see
[What the unit restricts](#what-the-unit-restricts) below), and the capability set here
is "the minimal set that keeps today's five Operations working," not a syscall-level
proof of minimality.

## Why the daemon is privileged

Relay's entire value proposition is running administrative commands on a fleet — the
daemon *is* the execution surface. Two of its five Operations are inherently
system-level:

- `service.restart` invokes `systemctl restart <unit>`, which talks to PID 1 to manage
  services across the whole Node — not something a low-privilege process can do.
- `pkg.install` invokes the system package manager (`apt-get`/`dnf`/`yum`), which writes
  package metadata and files under `/usr`, `/etc`, and `/var` system-wide.

Raw Exec (Policy-gated, ADR-0001/0002) can run anything an operator's Policy allows,
including further privileged actions. Given this, `User=root` is not a mistake to be
"fixed" by dropping to a service account — a non-root daemon cannot restart arbitrary
services or install packages at all. The honest posture is: **keep root, and use the
unit to remove every privilege the daemon does not exercise.**

## Per-Operation privilege map

| Operation | Mechanism (source) | Privilege actually needed |
| --- | --- | --- |
| `system.facts` (read) | `/proc/sys/kernel/{hostname,osrelease}` reads + `libc::getifaddrs` over an `AF_NETLINK` socket; no subprocess (`daemon/src/operations/system_facts.rs`) | None beyond default process privilege; needs the `AF_NETLINK` address family available. Fully compatible with the strict hardened baseline. |
| `file.read` (read) | `std::fs::File::open` on an arbitrary target path; no subprocess (`daemon/src/operations/file_read.rs`) | Read access to whatever path Policy's argument constraints allow. `CAP_DAC_READ_SEARCH` grants universal read (no write, no privilege bypass) so `file.read` isn't limited to files the process's own UID happens to own. |
| `service.restart` (mutate) | `["systemctl", "restart", <unit>]` argv, unit name validated against a strict charset (`daemon/src/operations/service_restart.rs`) | Root to authorize systemctl → PID 1. The daemon itself performs no filesystem writes for this Operation, so it works unmodified under `ProtectSystem=strict`. |
| `pkg.install` (mutate) | `["apt-get"\|"dnf"\|"yum", "install", "-y", <pkgspec>]` argv, name/version validated against a strict charset before argv is built (`daemon/src/operations/pkg_install.rs`) | Broad root: the package manager writes `/usr`, `/etc`, `/var` and typically needs `CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_SETUID`, `CAP_SETGID`, `CAP_SETFCAP` to install file ownership/permissions/capabilities correctly. **Conflicts** with the strict baseline's `ProtectSystem=strict` and minimal `CapabilityBoundingSet` — see [Documented exceptions](#documented-exceptions). |
| Raw Exec (mutate) | Arbitrary argv, gated by Policy allow/deny regexes (ADR-0001/0002); no daemon-side restriction beyond what Policy admits | Unbounded — whatever the operator's Policy allows. A read-only Raw Exec command works under the strict baseline; a filesystem-mutating one needs the same relaxations as `pkg.install`. |

## What the unit restricts

Directive-by-directive, from `daemon/packaging/relay-daemon.service`:

- **`NoNewPrivileges=yes`** — blocks `setuid`/file-capability escalation via `execve`.
  The daemon never needs to gain privilege beyond what it starts with.
- **`ProtectSystem=strict`** — mounts `/usr`, `/etc`, `/boot`, and the rest of the OS
  file hierarchy read-only, with `StateDirectory` carved out as the one writable path.
  This directly reinforces ADR-0002: Policy lives under `/etc/relay-daemon/`, and this
  directive means even a compromised daemon process cannot rewrite its own Policy file
  from inside the unit — Policy really is remotely (and now locally-process-) immutable.
- **`ProtectHome=read-only`** (not `=yes`) — keeps `/home` and `/root` readable so
  `file.read` can still reach files there, while blocking writes. `=yes` is stricter but
  would silently break `file.read` for any Policy-permitted path under a home directory;
  fleets that never `file.read` home directories can tighten this to `=yes`.
- **`PrivateTmp=yes`** — the daemon gets its own `/tmp`, isolated from other processes on
  the Node; nothing the daemon does needs to share `/tmp` with anything else.
- **`RestrictSUIDSGID=yes`** — the daemon never needs to create setuid/setgid files.
- **`CapabilityBoundingSet=CAP_DAC_READ_SEARCH`** — the one capability kept, for
  `file.read`'s universal-read need (see the table above). No write or privilege-bypass
  capability is retained by the baseline.
- **`AmbientCapabilities=`** (empty) — no capability is ambiently inherited by child
  processes (`systemctl`, `apt-get`/`dnf`/`yum`, Raw Exec's spawned command); those
  processes get their privilege from running as root under `User=root`, not from an
  inherited capability set.
- **`StateDirectory=relay-daemon`, `StateDirectoryMode=0700`** — the one writable path,
  holding the daemon's persisted identity (`key.pem`/`cert.pem`/`ca_bundle.pem`/
  `node_id`, `daemon/src/identity.rs`) and the at-most-once dedup **marker-file** store:
  `<state_dir>/seen-tasks/`, a directory (mode 0700) holding one empty marker file (mode
  0600) per seen `task_id` — **not** a SQL database; there is no `rusqlite` dependency in
  the daemon (`daemon/src/dedup.rs:27-31`, ADR-0004).
- **`PrivateDevices`, `ProtectKernelTunables`, `ProtectKernelModules`,
  `ProtectKernelLogs`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`,
  `RestrictRealtime`, `RestrictNamespaces`, `LockPersonality`** — the daemon never
  touches hardware devices, kernel tunables/modules/logs, cgroups, the system clock,
  the hostname, realtime scheduling, namespaces, or its own execution-domain
  personality. None of the five Operations above need any of these; they are removed
  outright.
- **`ProtectProc=invisible`** — hides other processes' `/proc/<pid>` entries from the
  daemon. `/proc/sys/...` (used by `system.facts`) is a separate tree from per-process
  `/proc/<pid>/...` and stays visible at this setting.
- **`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`** — `AF_INET`/
  `AF_INET6` are required for the daemon's outbound mTLS connection to the Relay;
  `AF_UNIX` is **load-bearing for `service.restart`**: that Operation spawns
  `systemctl restart <unit>`, and `systemctl` reaches PID 1 over D-Bus on an `AF_UNIX`
  socket (`/run/dbus/system_bus_socket` or `/run/systemd/private`). The spawned
  `systemctl` child inherits this unit's seccomp `RestrictAddressFamilies` across
  `execve`, so dropping `AF_UNIX` would silently break `service.restart`.
  `AF_NETLINK` is **load-bearing for `system.facts`**: `libc::getifaddrs` opens an
  `AF_NETLINK` socket internally to enumerate interfaces. Omitting it would silently
  break a `read`-class Operation. Every other address family (e.g. `AF_PACKET`) is
  denied.
- **`SystemCallFilter` and `MemoryDenyWriteExecute` are intentionally omitted.** Both
  require enumerating the exact syscall surface the daemon and its spawned executors
  (`systemctl`, `apt-get`/`dnf`/`yum`, and whatever Raw Exec's Policy allows) legitimately
  use. Guessing an allowlist now risks silently breaking `pkg.install` or a
  Policy-permitted Raw Exec command in the field. This is the **v0.0.8 syscall/capability
  audit's** job, not this change's.

## Documented exceptions

On Nodes that actually run `pkg.install` or a filesystem-mutating Raw Exec command, the
strict baseline above **will** fail (`ProtectSystem=strict` blocks the package manager's
writes to `/usr`/`/etc`/`/var`, and the minimal `CapabilityBoundingSet` lacks the
capabilities those writes need). This is intentional — the strict baseline stays the
default for read/`service.restart`-only fleets — and the fix is an opt-in drop-in on the
Nodes that need it, not a weaker shipped default.

Create `/etc/systemd/system/relay-daemon.service.d/pkg-install.conf`:

```ini
[Service]
# Relax the read-only OS hierarchy so the package manager can write its
# targets. "full" still protects /boot; use ReadWritePaths= instead if only
# specific trees need write access on an otherwise-strict baseline.
ProtectSystem=full

# Capabilities the package manager needs to set file ownership, permission
# bits, and capabilities on installed files, and to create/adjust the
# users/groups some packages provision.
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETUID CAP_SETGID CAP_SETFCAP
```

Then `systemctl daemon-reload && systemctl restart relay-daemon` on that Node. Keep this
override scoped to Nodes whose Policy actually permits `pkg.install` or write-heavy Raw
Exec; every other Node keeps the strict baseline.

For Nodes whose `pkg.install` traffic is unusually heavy (a large maintainer-script
fan-out, or many concurrent installs), the same drop-in is the place to raise
`TasksMax=` above the shipped `4096` (see
[Resource limits on spawned children](#resource-limits-on-spawned-children-v008-exec-audit)
below) and, optionally, add a `MemoryMax=` scoped to this unit's cgroup — the shipped
unit intentionally ships without one (see that section for why).

## Resource limits on spawned children (v0.0.8 exec audit)

**The gap being closed:** before this change, a spawned child (Raw Exec, or the
`systemctl`/`apt-get`/`dnf`/`yum` child of `service.restart`/`pkg.install`) ran under only
a wall-clock timeout and a 1 MiB per-stream output cap (`MAX_OUTPUT_BYTES`,
`daemon/src/config.rs`). There was no `setrlimit`, no `pre_exec`, and no cgroup
`TasksMax`/`MemoryMax` anywhere in the tree. A Policy-permitted Raw Exec fork bomb,
memory hog, fd exhauster, or runaway writer ran unbounded — the timeout eventually killed
the process group, but not before resource exhaustion.

**The choice: BOTH `setrlimit` and a cgroup `TasksMax` backstop, with a clear division of
labor.**

- `setrlimit` via a tokio `pre_exec` hook (`daemon/src/executor.rs::execute`,
  `apply_rlimits`) is the **primary, in-tree, per-Task, unit-tested layer**. It runs in
  the forked child after `fork()` and before `exec()`, for every child at the single spawn
  chokepoint that Raw Exec, `service.restart`, and `pkg.install` all funnel through — no
  per-Operation duplication.
- The systemd unit's pids-cgroup `TasksMax=4096` (`daemon/packaging/relay-daemon.service`)
  is a **defense-in-depth fork-bomb backstop**, stated here **conditionally** because the
  naive claim "a root child always bypasses `RLIMIT_NPROC`" is **false** under the shipped
  hardened unit:
  - The kernel's fork-time `RLIMIT_NPROC` check gates the bypass on
    `task_ns_capable(CAP_SYS_RESOURCE)`: a process holding `CAP_SYS_RESOURCE` can exceed
    `RLIMIT_NPROC`; a process **without** it cannot, regardless of its UID.
  - The shipped unit sets `CapabilityBoundingSet=CAP_DAC_READ_SEARCH`, which strips
    `CAP_SYS_RESOURCE` from the daemon. Per `capabilities(7)`, a child's capabilities at
    `execve` are bounded by the parent's capability bounding set even for a UID-0 child, so
    **no process spawned by the hardened daemon can hold `CAP_SYS_RESOURCE`** — including
    under the `pkg-install.conf` drop-in above, which also never adds it back. Its
    fork-time check therefore returns false, and `RLIMIT_NPROC` (set per-Task by the
    executor) **does** contain even a root Raw Exec fork bomb under the shipped unit.
  - The "root bypasses `RLIMIT_NPROC`" premise is true **only** for deployments run
    **without** this capability-bounded unit: the dev-fleet's Docker containers
    (`docs/dev-fleet.md`), or a bare `ExecStart` with no hardening block. There a UID-0
    child retains `CAP_SYS_RESOURCE` and can out-fork `RLIMIT_NPROC` — that is exactly the
    gap `TasksMax` closes. The pids controller is not `CAP_SYS_RESOURCE`-bypassable and
    counts only this service's cgroup, so it backstops those non-hardened deployments while
    being redundant (never harmful) under the hardened one.

**The specific rlimits, defaults, and why** (`ResourceLimits::DEFAULT`,
`daemon/src/config.rs`) — a single generous global profile, not a per-Operation-class
split:

| Limit | Default | Why |
| --- | --- | --- |
| `RLIMIT_NPROC` | 2048 | Processes/threads per real UID — the fork-bomb bound (see above for its conditional root-bypass caveat and how `TasksMax` covers the non-hardened case). |
| `RLIMIT_DATA` | 2 GiB | Bounds `brk` + anonymous `mmap` — the malloc/alloc-bomb surface on Linux ≥ 4.7 — **not** `RLIMIT_AS`. `RLIMIT_AS` would also count file-backed `mmap` (package files, shared libs, mmap'd DBs), risking breaking `pkg.install`; `RLIMIT_DATA` contains an allocation bomb without that risk. On kernels older than 4.7, `RLIMIT_DATA` caps only `brk` (weaker alloc containment) — the fleet targets modern Linux. |
| `RLIMIT_NOFILE` | 4096 | Open file descriptors — the fd-exhaustion bound. |
| `RLIMIT_CPU` | 600 s | A pure backstop **above** the 300 s wall-clock `MAX_TIMEOUT` (`dispatch.rs`), and it bounds **CPU-bound** (spin/compute) runaways specifically. A sleeping / wall-clock-bound / hung-I/O child accrues little CPU time and is instead bounded by the existing wall-clock timeout kill, not by `RLIMIT_CPU` — do not mistake this for a wall-clock bound. |
| `RLIMIT_FSIZE` | 4 GiB | Largest single file a child may write — the runaway-write bound. |

`pkg.install`'s headroom comes from this single generous global default rather than a
class-specific profile: the bomb-vs-legitimate gap is orders of magnitude (a bomb wants
unbounded; `apt`/`dnf` want a few hundred MB of heap, a few dozen processes, a few
thousand fds), so one generous default contains bombs while comfortably accommodating the
heaviest legitimate Operation. A class split would add `ExecRequest`/operation-fn
plumbing and test churn for no security or functional gain.

**The `TasksMax=4096` sizing budget.** The daemon runs under a bare `#[tokio::main]`
(`main.rs`), so tokio's builder defaults apply — `max_blocking_threads=512`, worker
threads ≈ #CPUs, plus the main thread — all in the **same cgroup** as any spawned child
process tree, all counting toward `TasksMax`:

| Component | Budget |
| --- | --- |
| tokio blocking-pool ceiling (`max_blocking_threads` default) | 512 |
| tokio worker threads (≈ #CPUs; budgeted for a large host) | 256 |
| main thread + tracing/signal/misc runtime threads | 8 |
| largest legitimate child process tree (`pkg.install`'s `dpkg`/`apt` maintainer-script fan-out) | 256 |
| **subtotal (legitimate ceiling)** | **≈ 1032** |
| headroom/slack (≈ 4× the legitimate ceiling; still far below a fork bomb) | → **`TasksMax=4096`** |

`4096` is deliberately **not** left at `512` — tokio's own `max_blocking_threads`
default — so the two ceilings don't coincidentally collide; it sits materially above both
the ~1032 legitimate ceiling and the 512 blocking-pool default, and orders of magnitude
below an unbounded fork bomb, so it never clips legitimate work while still bounding a
bomb. Operators raise it (and may add a scoped `MemoryMax=`) in the `pkg-install.conf`
drop-in for unusually heavy installs.

**Deny-closed behavior.** Each configured limit sets `rlim_cur == rlim_max` to a finite
constant, so a spawned child is always bounded even when the inherited hard limit is
unlimited. If any `setrlimit` call in `pre_exec` fails (e.g. a value that would require
raising a hard limit the process cannot raise), the closure returns `Err`, `cmd.spawn()`
returns `Err`, and `execute()` maps it to `OUTCOME_FAILURE` via the same path already used
for spawn errors — the daemon **never** spawns a child with weaker-than-configured limits.
The shipped defaults sit below systemd's own default hard limits (`DefaultLimitNOFILE`
hard ~524288, unlimited `DATA`/`CPU`/`FSIZE`, a high `NPROC`), so in production
`setrlimit` lowers and succeeds out of the box. A host that has **already** tightened a
hard limit below a shipped default (e.g. `LimitNOFILE` hard < 4096) would make `setrlimit`
require a raise, fail with `EPERM`, and the affected exec Operations return
`OUTCOME_FAILURE` on that host — this is the intended deny-closed behavior (refuse rather
than run unbounded); operators in that situation tune the constant.

**Threat-model framing.** This closes ACCIDENTAL/naive resource exhaustion (a
Policy-permitted command that forks, allocates, opens fds, or writes without bound by
mistake) and adds defense-in-depth. It is **not** a sandbox against a Policy-permitted
**malicious** command that deliberately raises its own limits — that is only possible if
the command holds `CAP_SYS_RESOURCE`, which requires a non-hardened deployment (see
above). Policy is the gate against running that command at all; the cgroup
`TasksMax`/`MemoryMax` narrow even that residual case.

**Operator tuning.** `ResourceLimits::DEFAULT` is a compile-time constant today (the
`MAX_OUTPUT_BYTES` precedent); env-tunability is future work. The operator's runtime lever
is the systemd unit: raise `TasksMax=` and/or add a scoped `MemoryMax=` in the
`pkg-install.conf` drop-in for Nodes whose installs need more headroom.

## Verification

Static validation (runnable in CI/dev environments, no real Node needed):

```console
$ systemd-analyze verify daemon/packaging/relay-daemon.service
```

Off this host (no installed `relay-daemon` binary), this reports:

```
relay-daemon.service: Command /usr/local/bin/relay-daemon is not executable: No such file or directory
```

That specific complaint is expected and non-fatal in this environment — it confirms the
unit *parses and validates* except for the binary not being installed at this path.
Any other error (a malformed directive, an invalid value) is a real problem to fix.

```console
$ systemd-analyze security --offline=true daemon/packaging/relay-daemon.service
```

confirms the requested directives register as active — `NoNewPrivileges=`,
`RestrictRealtime=`, `ProtectSystem=` (strict), `ProtectProc=`, `PrivateTmp=`,
`PrivateDevices=`, `ProtectClock=`, `ProtectKernelLogs=`, `ProtectControlGroups=`,
`ProtectKernelModules=`, `ProtectKernelTunables=`, `ProtectHostname=`,
`LockPersonality=`, and every `RestrictNamespaces=` sub-check all report `✓`, and the
retained `CAP_DAC_READ_SEARCH` and the intentionally-allowed `AF_NETLINK`/`AF_UNIX`/
`AF_INET`/`AF_INET6` address families show up as the (expected, documented) residual
exposure — the tool has no way to know those are load-bearing for `file.read` and
`system.facts` rather than an oversight. `User=root` is, as always, flagged; that is the
whole point of this document.

**What this does not cover**: a live real-host `enroll → connect → execute
(system.facts) → report` cycle running the daemon *under this unit* on real `systemd`.
The dev fleet (`docs/dev-fleet.md`) runs daemons in Docker containers, not under
`systemd`, so that path cannot be exercised there. Running the daemon under
`relay-daemon.service` on an actual systemd host (with policy.toml and an Enrollment
Token in place) and confirming it enrolls, connects, and successfully executes
`system.facts` is a manual verification step for a real deployment target, not something
this repository's automated checks can currently run.

## Forward pointer

Resource limits on spawned children (rlimits + the `TasksMax` cgroup backstop) are now
addressed by this document's
[Resource limits on spawned children](#resource-limits-on-spawned-children-v008-exec-audit)
section. What remains outstanding for the v0.0.8 audit is the exact syscall surface (a
real `SystemCallFilter` allowlist, derived from tracing the daemon and its executor
children rather than guessed) and the precise minimal capability set (rather than "the
capabilities `pkg.install`'s package managers typically need"). This document and unit are
the restricted-user baseline that audit builds on, not a substitute for it.
