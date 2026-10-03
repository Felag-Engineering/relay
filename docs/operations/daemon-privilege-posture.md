# Daemon privilege posture

The relay-daemon is, by design, the most privileged binary in the system: it is remote
code execution as a service, gated by Policy (ADR-0002) rather than by dropping
privilege. This document records what the daemon genuinely needs root for today, what
the hardened unit (`daemon/packaging/relay-daemon.service`) restricts, and what remains
for a follow-up audit.

## Scope

This is **v0.0.7 groundwork** — a "restricted user" posture that bounds everything the
daemon does *not* need, shipped as an example hardened `systemd` unit plus this map from
Operation to privilege — **plus, as of the v0.0.8 audit below, the static-derivation
portion of the capability/syscall audit**: a derived candidate `SystemCallFilter`
allowlist and minimal capability set (see
[Syscall and capability surface (v0.0.8 audit)](#syscall-and-capability-surface-v008-audit)),
each backed by daemon-source-plus-`systemd-analyze` evidence rather than a guess. The
shipped unit (`daemon/packaging/relay-daemon.service`) now **carries** the derived
`SystemCallFilter`/`SystemCallArchitectures`/`MemoryDenyWriteExecute` directives, applied
by #224 (see [What the unit restricts](#what-the-unit-restricts) below). What this
document does **not** yet cover is the LIVE apply-and-verify on a real systemd host —
tracing the applied unit under load and confirming no legitimate syscall is denied — which
#224 (closed by PR #241) split out as its own outstanding manual step, tracked by **#246**.

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
| `pkg.install` (mutate) | `["apt-get"\|"dnf"\|"yum", "install", "-y", <pkgspec>]` argv, name/version validated against a strict charset before argv is built (`daemon/src/operations/pkg_install.rs`) | Broad root: the package manager writes `/usr`, `/etc`, `/var` and needs (derived and confirmed by the audit below) `CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_SETUID`, `CAP_SETGID`, `CAP_SETFCAP` to install file ownership/permissions/capabilities correctly — see [Candidate minimal capability set](#candidate-minimal-capability-set). **Conflicts** with the strict baseline's `ProtectSystem=strict` and minimal `CapabilityBoundingSet` — see [Documented exceptions](#documented-exceptions). |
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
- **`SystemCallFilter=@system-service`, `SystemCallArchitectures=native`, and
  `MemoryDenyWriteExecute=yes` are now applied to the shipped unit (#224).** They are the
  derived (not guessed) allowlist from
  [Syscall and capability surface (v0.0.8 audit)](#syscall-and-capability-surface-v008-audit)
  below, which enumerates the syscall surface the daemon and its spawned executors
  (`systemctl`, `apt-get`/`dnf`/`yum`, and whatever Raw Exec's Policy allows) legitimately
  use and derives the allowlist from it. The strict base above keeps
  `MemoryDenyWriteExecute=yes`; the `pkg-install.conf` drop-in (see
  [Documented exceptions](#documented-exceptions)) overrides it to `=no` for its
  maintainer-script interpreters. **Live trace still pending:** applying these lines is
  done, but validating them against `pkg.install` and a Policy-permitted Raw Exec command
  on a real systemd host is the outstanding manual step tracked by **#246** — see
  [What the derivation did and did NOT cover](#what-the-derivation-did-and-did-not-cover-residual-risk)
  for the residual risk this leaves open.

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

# Conservative default: the base's inherited MemoryDenyWriteExecute=yes could
# silently break a maintainer-script interpreter that needs W^X memory on the
# very Nodes that opt into running pkg.install. This is a documented choice
# PENDING the live trace (#246), not a verified fact — the live trace can
# promote this back to inheriting the base's =yes if it proves safe.
MemoryDenyWriteExecute=no
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

## Syscall and capability surface (v0.0.8 audit)

### Method and provenance

The numbers in this section are a **static derivation** — daemon source (the single spawn
chokepoint and each Operation's executor code) plus its crate surface (`tokio`, `tonic`,
`rustls`/`ring`, `libc`) mapped onto the real `systemd-analyze syscall-filter` group
vocabulary, cross-checked against the shipped unit with
`systemd-analyze security --offline=true`. They are **not** a live `strace`/seccomp trace of
a running daemon on this box: `strace`, `perf`, and `auditctl` are absent here, this
environment is non-root with no passwordless `sudo`, and the dev fleet
(`docs/dev-fleet.md`) runs daemons under Docker rather than `systemd` — none of which can
exercise a real privileged trace. Every number below is reproducible with two unprivileged
commands:

```console
$ systemd-analyze syscall-filter @system-service
$ systemd-analyze security --offline=true daemon/packaging/relay-daemon.service
```

`scripts/daemon-privilege-audit.sh` runs both (plus `systemd-analyze verify`) and prints the
same evidence; it also carries the full live-tracing procedure as a commented, never-executed
reference block. Numbers were measured against **systemd 257 (257.13-1~deb13u1)**; a re-run
on a different systemd version may report different counts (see
[What the derivation did and did NOT cover](#what-the-derivation-did-and-did-not-cover-residual-risk)
below) — that is expected, not a regression.

### Derived syscall surface

| Surface | Representative syscalls | Covering `@group` | In `@system-service`? |
| --- | --- | --- | --- |
| Daemon runtime (`tokio`, full multi-thread) | `epoll_create1`/`epoll_ctl`/`epoll_wait`, `eventfd2`, `futex`, `clone`/`clone3`, `membarrier`, `rseq`, `timerfd_*` | `@io-event`, `@default`, `@process`, `@timer` | yes |
| Transport (`tonic`+`rustls`/`ring`, over `AF_INET`/`AF_INET6`) | `socket`, `connect`, `sendmsg`, `recvmsg`, `getrandom` | `@network-io`, `@default` | yes |
| Spawn chokepoint (`executor.rs::execute`) | `clone`/`clone3`+`execve` (fork+exec), `setpgid` (`process_group(0)`), `prlimit64`×5 (`apply_rlimits`, via `rustix::process::setrlimit`), `kill(-pgid)`, `wait4`/`waitid` (reap) | `@process`, `@default`, `@system-service` (direct: `setpgid`) | yes |
| `system_facts.rs` (`system.facts`) | `/proc/sys` reads (`open`/`openat`/`read`/`close`), `libc::getifaddrs` → `AF_NETLINK` `socket`/`bind`/`sendto`/`recvmsg` | `@file-system`, `@basic-io`, `@network-io` | yes |
| `file_read.rs` (`file.read`) | `open`/`openat`, `read`, `close` | `@file-system`, `@basic-io` | yes |
| `service_restart.rs` child (`systemctl`) | `AF_UNIX` `socket`/`connect`/`sendmsg`/`recvmsg` to PID 1 over D-Bus | `@network-io` | yes |
| `pkg_install.rs` child (`apt-get`/`dnf`/`yum`) | `openat`/`write`/`chmod`/`chown`/`rename`/`mkdir`/`unlink`-family (metadata + writes under `/usr`,`/etc`,`/var`) | `@file-system`, `@chown` | yes (bounded surface only — see residual risk below) |

**Checkable result:** every syscall the daemon itself and its non-Raw-Exec children (the
`systemctl` child of `service.restart`, the package-manager binary's own syscalls for
`pkg.install`) issue maps into `@system-service` — flattening `@system-service`'s 16
subgroups (`@aio @basic-io @chown @default @file-system @io-event @ipc @keyring @memlock
@network-io @process @resources @setuid @signal @sync @timer`) plus its own direct members
into one deduplicated set gives **390 concrete syscalls on systemd 257** (systemd-version
dependent; `scripts/daemon-privilege-audit.sh` recomputes this on any box it runs on). The
specific load-bearing syscalls — `setrlimit`/`prlimit64`, `clone`/`clone3`/`execve`/
`execveat`, `kill`/`tgkill`, `wait4`/`waitid`/`pidfd_open`/`pidfd_send_signal`,
`socket`/`connect`/`sendmsg`/`recvmsg`, `epoll_create`/`epoll_ctl`/`epoll_wait`/`eventfd2`/
`futex`/`membarrier`/`rseq`, `getrandom`, `getifaddrs`'s netlink path (`socket`/`bind`/
`sendto`/`recvmsg` over `AF_NETLINK`), `open`/`openat`/`read`/`write`/`mkdir`/`rename`/
`fsync`/`getdents64` — were each individually confirmed as a member of `@system-service`
against `systemd-analyze syscall-filter` output, not merely assumed from the group names.

### Candidate `SystemCallFilter` allowlist

- **Base (BOTH profiles share it): `SystemCallFilter=@system-service`.** This is systemd's
  own documented recommended base allowlist for a general system service. It already
  contains `@default` (⇒ covers `prlimit64`, the syscall `apply_rlimits` actually issues),
  `@setuid`, `@chown` (⇒ the package manager's
  ownership syscalls), `@signal`, `@process`, `@network-io` (⇒ the `AF_UNIX` `systemctl`
  child and the `AF_INET`/`AF_INET6` mTLS transport), `@file-system` (⇒ the package manager's
  writes), `@io-event`, `@basic-io`, `@sync`.

- **DECISION — the two profiles (strict vs. the `pkg.install`/mutating-Raw-Exec drop-in)
  share the SAME `SystemCallFilter`; they differ in `ProtectSystem` +
  `CapabilityBoundingSet` (see [Documented exceptions](#documented-exceptions)) and — as of
  #224 — a scoped, pending-live-verification `MemoryDenyWriteExecute=no` override on the
  drop-in only; the `SystemCallFilter` itself is identical across both profiles.**
  Justification (checkable): `pkg.install`'s writes to `/usr`, `/etc`, `/var` are blocked by
  `ProtectSystem=strict` — a mount/namespace restriction — **not** by the syscall filter; the
  underlying `openat(O_WRONLY)`/`chmod`/`chown`/`mkdir`/`rename`/`unlink` calls are all
  members of `@system-service`. So the drop-in needs to relax `ProtectSystem` (to `full`) and
  add capabilities (it already does both — see
  [Documented exceptions](#documented-exceptions)), but needs **no wider
  `SystemCallFilter`**. The drop-in inherits `@system-service` from the base unit; it does not
  repeat or widen it. The `MemoryDenyWriteExecute=no` override is a documented choice
  pending the live trace, not a verified fact (see [Documented exceptions](#documented-exceptions)).

- **Adjacent cheap hardening the offline analysis surfaces, applied by #224 alongside:**
  `SystemCallArchitectures=native` (closes the "service may execute system calls with all
  ABIs" 0.2-point row) and `MemoryDenyWriteExecute=yes` — applied to the strict base. Like
  the `SystemCallFilter` itself, both are **static candidates, unvalidated until a live
  trace** — flag in particular that `MemoryDenyWriteExecute` for the drop-in still needs
  live validation under a representative `pkg.install` (a maintainer-script interpreter
  that needs W^X memory would break under it); #224 already sets the drop-in's
  `MemoryDenyWriteExecute=no` explicitly rather than inheriting the strict base's `yes` (see
  [Documented exceptions](#documented-exceptions)), as the documented choice pending that
  live confirmation.

- **Real evidence (reproduce with `systemd-analyze security --offline=true
  daemon/packaging/relay-daemon.service` against the shipped unit):**
  - Before this change (pre-#224): `Overall exposure level for relay-daemon.service: 3.7
    OK` — every `SystemCallFilter=~@*` row was `✗` (no filter).
  - After #224 (base `@system-service` + `SystemCallArchitectures=native` +
    `MemoryDenyWriteExecute=yes`, now applied to the shipped unit): `Overall exposure level
    for relay-daemon.service: 2.1 OK`, reproducible on this box (systemd 257 — confirmed).
    Rows that flip ✗→✓: `@clock`, `@cpu-emulation`, `@debug`, `@module`, `@mount`,
    `@obsolete`, `@raw-io`, `@reboot`, `@swap`, plus the `SystemCallArchitectures=` and
    `MemoryDenyWriteExecute=` rows.
  - Rows that **stay ✗ and why** (documented, intentional residual — analogous to the
    existing `AF_NETLINK`/`AF_UNIX` residual in [Verification](#verification)):
    `SystemCallFilter=~@resources` ("`@resources` is included, e.g. `ioprio_set` is
    allowed") — `@resources` contains `setrlimit`, but `apply_rlimits` calls
    `rustix::process::setrlimit`, which issues `prlimit64` directly; `prlimit64` is a member
    of `@default`, not `@resources`. The rlimit deny-closed guarantee — denying `prlimit64`
    would make that call return `EPERM`, `cmd.spawn()` return `Err`, and every exec Operation
    return `OUTCOME_FAILURE` (see
    [Deny-closed behavior](#resource-limits-on-spawned-children-v008-exec-audit) above) — is
    therefore load-bearing on `@default`, which this checklist never offers to narrow, not on
    `@resources`; `@resources` stays allowed here as part of the unnarrowed base.
    `SystemCallFilter=~@privileged` ("`@privileged` is included,
    e.g. `chown` is allowed") — `@system-service` pulls in `@chown` and the `setuid`-class
    syscalls that overlap `@privileged`; in the strict profile those syscalls are allowed by
    the filter but `EPERM` at the kernel's capability check without the caps that back them,
    so there is no real privilege; in the drop-in they are intentionally cap-backed.
  - Placement matters: pasting the three candidate lines **after** `[Install]` instead of
    inside `[Service]` does not error loudly — systemd only logs a low-visibility `Unknown
    key ... in section [Install], ignoring` warning per line — and the exposure score stays
    at the unmodified `3.7`, silently no-opping the change. Verified against a scratch copy
    while producing the numbers above.

  ```ini
  [Service]
  # ... existing directives (User=root, ProtectSystem=strict, CapabilityBoundingSet=
  # CAP_DAC_READ_SEARCH, AmbientCapabilities=, RestrictAddressFamilies=..., etc.) ...

  # APPLIED to the shipped unit by #224. These three lines MUST go within this
  # [Service] section (e.g. immediately after the existing
  # RestrictAddressFamilies= line, before [Install]) — placing them after
  # [Install] silently no-ops (see "Placement matters" above).
  SystemCallFilter=@system-service
  SystemCallArchitectures=native
  MemoryDenyWriteExecute=yes
  ```

  The `pkg-install.conf` drop-in (see [Documented exceptions](#documented-exceptions))
  needs **no `SystemCallFilter` addition** — it inherits `@system-service` from the base
  unit above it, and adds its own `MemoryDenyWriteExecute=no` override. These three lines
  are now applied to `daemon/packaging/relay-daemon.service` by **#224**.

### Candidate minimal capability set

Split by profile, confirmed against source:

- **Strict (read + `service.restart`): `CAP_DAC_READ_SEARCH` only.** `file_read.rs` needs
  universal read of non-root-owned files (the load-bearing case); `service_restart.rs`'s
  `systemctl` child is authorized by `UID 0` talking to PID 1 over `AF_UNIX` D-Bus, not by a
  capability; `system_facts.rs`'s `/proc/sys` reads and `getifaddrs` call need no capability
  either. **Audit result: this set is already minimal — no reduction possible.**
- **Drop-in (`pkg.install` / fs-mutating Raw Exec): adds `CAP_CHOWN`, `CAP_DAC_OVERRIDE`,
  `CAP_FOWNER`, `CAP_SETUID`, `CAP_SETGID`, `CAP_SETFCAP`** — identical to the existing
  drop-in's `CapabilityBoundingSet=` line (see
  [Documented exceptions](#documented-exceptions)); cite `pkg_install.rs`. **Audit result:
  CONFIRMS the existing set** — each capability maps to a documented package-manager need
  (file ownership, permission bits, file capabilities, and the user/group provisioning some
  packages perform), and no capability can be dropped without a live trace proving a given
  package family never exercises it. The audit **validates rather than shrinks** the
  capability sets — stated honestly, not as a reduction.

### What the derivation did and did NOT cover (residual risk)

The derivation above covers the daemon itself and its fixed-argv children — `systemctl`,
and `apt-get`/`dnf`/`yum`'s own syscalls — all of which land inside `@system-service`. It
does **not** bound two things:

1. **Raw Exec.** Its Policy-gated argv is arbitrary by design (ADR-0001/0002), so its
   syscall surface is unbounded by definition — a read-only command fits the strict profile,
   an fs-mutating one needs the drop-in, and nothing in this audit can enumerate every
   command an operator's Policy might permit.
2. **Package-manager MAINTAINER SCRIPTS.** `dpkg`/`rpm` run arbitrary shell/Perl/Python
   post-install hooks as part of `apt-get`/`dnf`/`yum install`; that surface is near-arbitrary
   and not reducible to the package manager's own syscalls.

A maintainer script or Raw Exec command that invokes a syscall **outside** `@system-service`
(e.g. `@mount`, `quotactl`, a `@privileged`-only call, `bpf`) would be `SIGSYS`/`EPERM`'d
under the candidate allowlist — unlike the `ProtectSystem` case, this is a **hard syscall
block**, not a soft one. Only a **LIVE** `strace`/seccomp trace on a real systemd host (the
#224 follow-up, **#246**) closes this gap. If a live trace shows a real, legitimate need outside
`@system-service`, the fix is a targeted, trace-validated **additive**
`SystemCallFilter=@mount` (or whichever specific group) line in the `pkg-install.conf`
drop-in — never a speculative widening of the shipped base.

**Provenance caveat, restated:** every number in this section comes from static analysis —
daemon source plus `systemd-analyze` — not a live `strace` trace on this box. See
[Method and provenance](#method-and-provenance) above.

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

**What this does not cover**: the shipped unit now carries the derived `SystemCallFilter`,
`SystemCallArchitectures`, and `MemoryDenyWriteExecute` directives (offline exposure `2.1`,
applied by #224), but a live real-host `enroll → connect → execute (system.facts) →
report` cycle running the daemon *under this unit* on real `systemd`, and — per the
[Syscall and capability surface](#syscall-and-capability-surface-v008-audit) section
above — a live `strace`/seccomp trace of all five Operations plus a permitted Raw Exec
against the applied allowlist and capability sets, are **STILL pending** and **MUST** be
run by a human on a real systemd host. The dev fleet (`docs/dev-fleet.md`) runs daemons in
Docker containers, not under `systemd`, so neither path can be exercised there. Running the
daemon under `relay-daemon.service` on an actual systemd host (with policy.toml and an
Enrollment Token in place), confirming it enrolls, connects, and successfully executes
`system.facts`, and running the tracing procedure below against every Operation — promoting
the applied profile to a live-validated one — is the outstanding manual step tracked by **#246**;
it is not something this repository's automated checks can currently run.

### #224 apply status

- **Applied:** `SystemCallFilter=@system-service`, `SystemCallArchitectures=native`, and
  `MemoryDenyWriteExecute=yes` are now in `daemon/packaging/relay-daemon.service`'s
  `[Service]` section (see [What the unit restricts](#what-the-unit-restricts)).
- **Offline exposure confirmed:** `3.7 -> 2.1` on this box, systemd 257 (see
  [Real evidence](#candidate-systemcallfilter-allowlist) above).
- **Drop-in `MemoryDenyWriteExecute` decided:** the `pkg-install.conf` drop-in adds
  `MemoryDenyWriteExecute=no` as the conservative default (see
  [Documented exceptions](#documented-exceptions)) — a documented choice pending the live
  trace, not a verified fact.
- **[ ] Live-systemd verification run — REQUIRED, NOT YET DONE (#246).** #224 itself closed
  with PR #241 and split this item out to #246. Human must, on a real
  systemd host: install the unit, enroll a Node, run all five Operations (`system.facts`,
  `file.read`, `service.restart`, `pkg.install`) + a permitted Raw Exec under the filter,
  confirm none break (esp. `pkg.install` maintainer scripts + Raw Exec, the two surfaces
  the static audit could not bound), and record the run here.

### Live tracing procedure (real systemd host)

The reproducible procedure a human runs on a real systemd host to close out #246 and
validate the applied profile. The same content lives, verbatim, as a commented
(never-executed) block in `scripts/daemon-privilege-audit.sh`, so the procedure travels
with the repo rather than only this doc.

**Environment:** a real systemd host, `relay-daemon` installed at
`/usr/local/bin/relay-daemon` under `relay-daemon.service`, `policy.toml` and an Enrollment
Token in place, `strace`/`auditctl` (or equivalent) available.

1. **Syscall union including children** — seccomp is inherited across `execve`, so the trace
   must follow forked children through their own `execve` (`service.restart`'s `systemctl`
   child is the load-bearing example):

   ```console
   $ strace -f -qq -e trace=all -o /tmp/relay-trace.log \
       -p "$(systemctl show -p MainPID --value relay-daemon)"
   ```

   While attached, drive one of each Operation — `system.facts`, `file.read`,
   `service.restart`, `pkg.install`, and a representative Policy-permitted Raw Exec — from
   the Relay. Then extract the syscall set and diff it against the candidate:

   ```console
   $ grep -oE '^[0-9]+ +[a-z_]+\(' /tmp/relay-trace.log \
       | sed -E 's/^[0-9]+ +([a-z_]+)\(/\1/' | sort -u
   ```

   Map each syscall to its `@group` (`systemd-analyze syscall-filter <group>`) and confirm
   it lands inside `@system-service`; anything outside it is a trace-validated candidate
   addition, never a speculative one.

2. **Seccomp audit-mode alternative** (no `strace` needed): set
   `SystemCallFilter=@system-service` plus `SystemCallLog=@system-service` in the unit (or
   run under the kernel's `SECCOMP_RET_LOG` action) and read
   `journalctl -u relay-daemon | grep SECCOMP` for any denied syscall while exercising every
   Operation.

3. **Capability confirmation:** run under the candidate `CapabilityBoundingSet` and confirm
   `file.read` of a non-root-owned, otherwise-unreadable file still succeeds (exercises
   `CAP_DAC_READ_SEARCH`), and that `pkg.install` succeeds only under the `pkg-install.conf`
   drop-in (see [Documented exceptions](#documented-exceptions)), never under the strict
   baseline.

`scripts/daemon-privilege-audit.sh` runs the unprivileged portion of this audit — the two
`systemd-analyze` commands from
[Method and provenance](#method-and-provenance) — and prints the same evidence this section
cites; it carries steps 1-3 above as a commented, never-executed reference block, since none
of them are runnable in this repository's dev/CI environment.

## Forward pointer

Resource limits on spawned children (rlimits + the `TasksMax` cgroup backstop) are now
addressed by this document's
[Resource limits on spawned children](#resource-limits-on-spawned-children-v008-exec-audit)
section. The exact syscall surface and the precise minimal capability set are **no longer
outstanding as guesses**: both are now delivered above as static-derived candidates — a
base `SystemCallFilter=@system-service` shared by both profiles, and confirmed strict
(`CAP_DAC_READ_SEARCH` only) / drop-in (adds `CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER`,
`CAP_SETUID`, `CAP_SETGID`, `CAP_SETFCAP`) capability sets — see
[Syscall and capability surface (v0.0.8 audit)](#syscall-and-capability-surface-v008-audit).
The "capabilities `pkg.install`'s package managers typically need" framing is retired: the
drop-in's capability set is now audit-confirmed, not guessed.

**Apply-to-unit and measure-offline-exposure: DONE.** `daemon/packaging/relay-daemon.service`
now carries `SystemCallFilter=@system-service`, `SystemCallArchitectures=native`, and
`MemoryDenyWriteExecute=yes`, and the offline exposure measured `2.1` (down from `3.7`) on
systemd 257 (see [#224 apply status](#224-apply-status)). **The drop-in `MemoryDenyWriteExecute`
stance: DECIDED** — `=no`, pending live confirmation (see
[Documented exceptions](#documented-exceptions)).

What **remains** — split out of #224 into **#246**: run the
[live tracing procedure](#live-tracing-procedure-real-systemd-host) on a real systemd host to
confirm no legitimate syscall is denied — especially package-manager maintainer scripts and a
representative Policy-permitted Raw Exec command, the two surfaces this audit explicitly could
not bound (see
[What the derivation did and did NOT cover](#what-the-derivation-did-and-did-not-cover-residual-risk)) —
and either confirm or revise the drop-in's `MemoryDenyWriteExecute=no` stance from that trace.
This is the sole **remaining human step**; it cannot be performed in this environment (no real
systemd host, no root/strace, Docker-only dev fleet). This document and unit are the
restricted-user baseline plus the applied, statically-derived profile that audit builds on,
not a substitute for the live verification it still requires.
