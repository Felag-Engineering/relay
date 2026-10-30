# Daemon privilege posture

The relay-daemon is the most privileged binary in the system: it is remote code execution as
a service, gated by Policy (ADR-0002) rather than by dropping privilege. This document records
what the daemon needs root for, what the hardened unit (`daemon/packaging/relay-daemon.service`)
restricts, and what is still unverified.

## Scope

The shipped unit is a restricted-root posture: it removes every privilege the daemon does not
exercise. Its `SystemCallFilter`, `SystemCallArchitectures` and `MemoryDenyWriteExecute`
directives, and the capability sets below, are a **static derivation** from daemon source and
`systemd-analyze` (see
[Syscall and capability surface](#syscall-and-capability-surface)),
not a guess. They have **not** been verified live on a real systemd host under load; that
manual step is tracked by **#246** (see [Live tracing procedure](#live-tracing-procedure-real-systemd-host)).

## Why the daemon is privileged

The daemon *is* the execution surface. Two Native Operations are inherently system-level:

- `service.restart` runs `systemctl restart <unit>`, which talks to PID 1 to manage services
  across the Node.
- `pkg.install` runs the system package manager (`apt-get`/`dnf`/`yum`), which writes under
  `/usr`, `/etc` and `/var`.

Raw Exec (Policy-gated, ADR-0001, ADR-0002) can run anything an operator's Policy allows. A
non-root daemon could not restart arbitrary services or install packages at all, so
`User=root` is not a mistake to fix. The posture is: **keep root, and use the unit to remove
every privilege the daemon does not exercise.**

## Per-Operation privilege map

| Operation | Mechanism (source) | Privilege actually needed |
| --- | --- | --- |
| `system.facts` (read) | `/proc/sys/kernel/{hostname,osrelease}` reads + `libc::getifaddrs` over an `AF_NETLINK` socket; no subprocess (relay-ops `operations::system_facts`) | None beyond default process privilege; needs the `AF_NETLINK` address family. Compatible with the strict baseline. |
| `file.read` (read) | `std::fs::File::open` on the target path; no subprocess (relay-ops `operations::file_read`) | Read access to whatever path Policy's argument constraints allow. `CAP_DAC_READ_SEARCH` grants universal read (no write, no privilege bypass), so `file.read` is not limited to files the process's UID owns. |
| `service.restart` (mutate) | `["systemctl", "restart", <unit>]` argv, unit name validated against a strict charset (relay-ops `operations::service_restart`) | Root, to authorize systemctl → PID 1. The daemon writes nothing for this Operation, so it works under `ProtectSystem=strict`. |
| `pkg.install` (mutate) | `["apt-get"\|"dnf"\|"yum", "install", "-y", <pkgspec>]` argv, name/version validated against a strict charset before argv is built (relay-ops `operations::pkg_install`) | Broad root: the package manager writes `/usr`, `/etc`, `/var` and needs `CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_SETUID`, `CAP_SETGID`, `CAP_SETFCAP` (see [Candidate minimal capability set](#candidate-minimal-capability-set)). **Conflicts** with the strict baseline's `ProtectSystem=strict` and minimal `CapabilityBoundingSet`; see [Documented exceptions](#documented-exceptions). |
| Raw Exec (mutate) | Arbitrary argv, gated by Policy allow/deny regexes (ADR-0001, ADR-0002) | Unbounded: whatever the operator's Policy allows. A read-only command works under the strict baseline; a filesystem-mutating one needs the same relaxations as `pkg.install`. |

## What the unit restricts

From `daemon/packaging/relay-daemon.service`:

- **`NoNewPrivileges=yes`**: blocks `setuid`/file-capability escalation via `execve`.
- **`ProtectSystem=strict`**: mounts the OS hierarchy read-only, with `StateDirectory` the one
  writable path. This reinforces ADR-0002: Policy lives under `/etc/relay-daemon/`, so even a
  compromised daemon process cannot rewrite its own Policy file or add, change or remove a
  fragment in the Policy directory (`/etc/relay-daemon/policy.d`). The `pkg.install` drop-in's
  `ProtectSystem=full` also mounts `/etc` read-only, so the Policy directory stays read-only
  under it.
- **`ProtectHome=read-only`** (not `=yes`): keeps `/home` and `/root` readable for `file.read`
  while blocking writes. `=yes` would silently break `file.read` for any Policy-permitted path
  under a home directory; fleets that never read there can tighten it.
- **`PrivateTmp=yes`**: the daemon gets its own `/tmp`.
- **`RestrictSUIDSGID=yes`**: the daemon never creates setuid/setgid files.
- **`CapabilityBoundingSet=CAP_DAC_READ_SEARCH`**: the one capability kept, for `file.read`.
  No write or privilege-bypass capability is retained.
- **`AmbientCapabilities=`** (empty): no capability is ambiently inherited by child processes
  (`systemctl`, the package manager, Raw Exec's command); they get privilege from running as
  root, not from an inherited set.
- **`StateDirectory=relay-daemon`, `StateDirectoryMode=0700`**: the one writable path. It holds
  the persisted identity (`key.pem`, `cert.pem`, `ca_bundle.pem`, `node_id`) and the
  at-most-once dedup store: `<state_dir>/seen-tasks/`, a directory (mode 0700) of one empty
  marker file (mode 0600) per seen `task_id`. It is not a database (ADR-0004).
- **`PrivateDevices`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`,
  `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `RestrictRealtime`,
  `RestrictNamespaces`, `LockPersonality`**: no Operation touches devices, kernel
  tunables/modules/logs, cgroups, the clock, the hostname, realtime scheduling, namespaces or
  its execution-domain personality, so all are removed.
- **No `ProtectProc=`**: systemd implements it as a `hidepid=` mount of `/proc`, and that mount
  exempts its `gid=` group, 0 by default. The daemon runs as `root:root`, so the directive would
  hide nothing, and running it under another group to make it bite would blind `proc.list` and
  `net.listening`, whose job is the whole process table.
- **`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`**: `AF_INET`/`AF_INET6` carry
  the outbound mTLS connection to the Relay. `AF_UNIX` is **load-bearing for
  `service.restart`**: `systemctl` reaches PID 1 over D-Bus on an `AF_UNIX` socket, and the
  child inherits this restriction across `execve`. `AF_NETLINK` is **load-bearing for
  `system.facts`**: `libc::getifaddrs` opens a netlink socket. Dropping either silently breaks
  that Operation. Every other family (e.g. `AF_PACKET`) is denied.
- **`SystemCallFilter=@system-service`, `SystemCallArchitectures=native`,
  `MemoryDenyWriteExecute=yes`**: the derived allowlist from
  [Syscall and capability surface](#syscall-and-capability-surface).
  The `pkg-install.conf` drop-in ([Documented exceptions](#documented-exceptions)) overrides
  `MemoryDenyWriteExecute` to `=no` for maintainer-script interpreters. Not yet validated
  live against `pkg.install` and a Policy-permitted Raw Exec command (#246); see
  [the residual risk](#what-the-derivation-did-and-did-not-cover-residual-risk).
- **`TasksMax=4096`**: the fork-bomb backstop; see
  [Resource limits on spawned children](#resource-limits-on-spawned-children-v008-exec-audit).

## Documented exceptions

On Nodes that run `pkg.install` or a filesystem-mutating Raw Exec command, the strict baseline
**will** fail: `ProtectSystem=strict` blocks the package manager's writes and the minimal
`CapabilityBoundingSet` lacks the capabilities they need. This is intentional. The strict
baseline stays the default; Nodes that need more opt in with a drop-in.

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

Then `systemctl daemon-reload && systemctl restart relay-daemon` on that Node. Scope the
override to Nodes whose Policy permits `pkg.install` or write-heavy Raw Exec.

For unusually heavy `pkg.install` traffic (a large maintainer-script fan-out, or many
concurrent installs), the same drop-in is where to raise `TasksMax=` above `4096` and,
optionally, add a `MemoryMax=` scoped to this unit's cgroup. The shipped unit has no
`MemoryMax=`.

## Resource limits on spawned children (v0.0.8 exec audit)

Every spawned child (Raw Exec, or the `systemctl`/package-manager child of `service.restart`
and `pkg.install`) runs under a wall-clock timeout, a 1 MiB per-stream output cap
(`MAX_OUTPUT_BYTES`, `daemon/src/config.rs`), per-Task rlimits, and the unit's cgroup
`TasksMax`. Two layers:

- **`setrlimit` via a tokio `pre_exec` hook** (relay-exec `executor::execute`,
  `apply_rlimits`) is the primary, per-Task, unit-tested layer. It runs in the forked child
  before `exec()`, at the single spawn chokepoint that Raw Exec, `service.restart` and
  `pkg.install` share.
- **The unit's pids-cgroup `TasksMax=4096`** is a defense-in-depth fork-bomb backstop. Under
  the hardened unit it is redundant, because a root child cannot bypass `RLIMIT_NPROC` there:
  - The kernel lets a process exceed `RLIMIT_NPROC` only if it holds `CAP_SYS_RESOURCE`,
    whatever its UID.
  - `CapabilityBoundingSet=CAP_DAC_READ_SEARCH` strips `CAP_SYS_RESOURCE`, and per
    `capabilities(7)` a child's capabilities are bounded by the parent's bounding set even at
    UID 0. The `pkg-install.conf` drop-in never adds it back. So `RLIMIT_NPROC` **does**
    contain even a root Raw Exec fork bomb under the shipped unit.
  - Without this unit (the dev fleet's Docker containers, or a bare `ExecStart`), a UID-0
    child keeps `CAP_SYS_RESOURCE` and can out-fork `RLIMIT_NPROC`. `TasksMax` closes that:
    the pids controller cannot be bypassed by `CAP_SYS_RESOURCE` and counts only this
    service's cgroup.

**The rlimits** (`ResourceLimits::DEFAULT`, relay-exec `limits`), one generous global profile:

| Limit | Default | Why |
| --- | --- | --- |
| `RLIMIT_NPROC` | 2048 | Processes/threads per real UID: the fork-bomb bound (see above). |
| `RLIMIT_DATA` | 2 GiB | Bounds `brk` + anonymous `mmap`, the allocation-bomb surface on Linux ≥ 4.7. Not `RLIMIT_AS`, which also counts file-backed `mmap` and could break `pkg.install`. On kernels before 4.7 it caps only `brk`; the fleet targets modern Linux. |
| `RLIMIT_NOFILE` | 4096 | Open file descriptors. |
| `RLIMIT_CPU` | 600 s | A backstop above the 300 s wall-clock `MAX_TIMEOUT` (`dispatch.rs`) for **CPU-bound** runaways. A sleeping or hung child accrues little CPU time and is bounded by the wall-clock kill instead. |
| `RLIMIT_FSIZE` | 4 GiB | Largest single file a child may write. |

One profile is enough: a bomb wants unbounded resources, while `apt`/`dnf` want a few hundred
MB of heap, a few dozen processes and a few thousand fds.

**The `TasksMax=4096` budget.** The daemon runs under a bare `#[tokio::main]` (`main.rs`), so
tokio's defaults apply, and its threads share the cgroup with every spawned child:

| Component | Budget |
| --- | --- |
| tokio blocking-pool ceiling (`max_blocking_threads` default) | 512 |
| tokio worker threads (≈ #CPUs; budgeted for a large host) | 256 |
| main thread + tracing/signal/misc runtime threads | 8 |
| largest legitimate child process tree (`pkg.install`'s `dpkg`/`apt` maintainer-script fan-out) | 256 |
| **subtotal (legitimate ceiling)** | **≈ 1032** |
| headroom/slack (≈ 4× the legitimate ceiling; still far below a fork bomb) | → **`TasksMax=4096`** |

`4096` sits well above both the ~1032 legitimate ceiling and tokio's 512 blocking-pool
default, and far below an unbounded fork bomb.

**Deny-closed behavior.** Each limit sets `rlim_cur == rlim_max` to a finite constant, so a
child is bounded even when the inherited hard limit is unlimited. If any `setrlimit` in
`pre_exec` fails, `cmd.spawn()` returns `Err` and `execute()` maps it to `OUTCOME_FAILURE`:
the daemon **never** spawns a child with weaker limits. The defaults sit below systemd's
default hard limits, so `setrlimit` succeeds out of the box. On a host that has already
tightened a hard limit below a default (e.g. `LimitNOFILE` hard < 4096), `setrlimit` fails
with `EPERM` and exec Operations return `OUTCOME_FAILURE` there; tune the constant.

**Threat model.** This contains accidental resource exhaustion by a Policy-permitted command
and adds defense in depth. It is **not** a sandbox against a malicious command that raises its
own limits, which needs `CAP_SYS_RESOURCE` and so a non-hardened deployment. Policy is the
gate against running that command at all.

**Operator tuning.** `ResourceLimits::DEFAULT` is a compile-time constant. The runtime lever is
the unit: raise `TasksMax=` and/or add a scoped `MemoryMax=` in the `pkg-install.conf` drop-in.

## Syscall and capability surface

### Method and provenance

These numbers are a **static derivation**: daemon source (the spawn chokepoint and each
Operation's executor) plus its crates (`tokio`, `tonic`, `rustls`/`ring`, `libc`), mapped onto
`systemd-analyze syscall-filter` groups and cross-checked with
`systemd-analyze security --offline=true`. They are **not** a live `strace`/seccomp trace; the
dev fleet runs daemons under Docker, not systemd. Reproduce them with two unprivileged
commands:

```console
$ systemd-analyze syscall-filter @system-service
$ systemd-analyze security --offline=true daemon/packaging/relay-daemon.service
```

`scripts/daemon-privilege-audit.sh` runs both, plus `systemd-analyze verify`, and carries the
live-tracing procedure as a commented, never-executed block. Numbers were measured on
**systemd 257 (257.13-1~deb13u1)**; another systemd version may report different counts, which
is expected.

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

**Result:** every syscall the daemon and its non-Raw-Exec children issue maps into
`@system-service`. Flattening its 16 subgroups (`@aio @basic-io @chown @default @file-system
@io-event @ipc @keyring @memlock @network-io @process @resources @setuid @signal @sync @timer`)
and direct members gives **390 syscalls on systemd 257** (version-dependent; the audit script
recomputes it). The load-bearing syscalls (`setrlimit`/`prlimit64`, `clone`/`clone3`/`execve`/
`execveat`, `kill`/`tgkill`, `wait4`/`waitid`/`pidfd_open`/`pidfd_send_signal`,
`socket`/`connect`/`sendmsg`/`recvmsg`, `epoll_*`/`eventfd2`/`futex`/`membarrier`/`rseq`,
`getrandom`, the netlink path of `getifaddrs`, `open`/`openat`/`read`/`write`/`mkdir`/`rename`/
`fsync`/`getdents64`) were each confirmed as members against `systemd-analyze syscall-filter`
output.

### Candidate `SystemCallFilter` allowlist

- **Base, shared by both profiles: `SystemCallFilter=@system-service`**, systemd's recommended
  base for a general service. It includes `@default` (which covers `prlimit64`, the syscall
  `apply_rlimits` issues), `@setuid`, `@chown`, `@signal`, `@process`, `@network-io` (the
  `AF_UNIX` `systemctl` child and the mTLS transport), `@file-system`, `@io-event`,
  `@basic-io` and `@sync`.
- **The strict profile and the `pkg-install.conf` drop-in share the same `SystemCallFilter`.**
  They differ in `ProtectSystem`, `CapabilityBoundingSet` and the drop-in's
  `MemoryDenyWriteExecute=no` ([Documented exceptions](#documented-exceptions)).
  `pkg.install`'s writes are blocked by `ProtectSystem=strict`, a mount restriction, not by
  the filter: the underlying `openat(O_WRONLY)`/`chmod`/`chown`/`mkdir`/`rename`/`unlink` are
  all in `@system-service`. So the drop-in inherits the base filter and needs no wider one.
- **`SystemCallArchitectures=native` and `MemoryDenyWriteExecute=yes`** are applied to the
  strict base alongside it. Like the filter, they are static candidates until a live trace;
  in particular `MemoryDenyWriteExecute` is overridden to `=no` in the drop-in pending that
  trace.
- **Evidence** (`systemd-analyze security --offline=true daemon/packaging/relay-daemon.service`):
  - Without the three directives: `Overall exposure level for relay-daemon.service: 3.7 OK`,
    with every `SystemCallFilter=~@*` row `✗`.
  - With them, as shipped: `Overall exposure level for relay-daemon.service: 2.1 OK` on systemd
    257. Rows that flip ✗→✓: `@clock`, `@cpu-emulation`, `@debug`, `@module`, `@mount`,
    `@obsolete`, `@raw-io`, `@reboot`, `@swap`, plus the `SystemCallArchitectures=` and
    `MemoryDenyWriteExecute=` rows.
  - Rows that **stay ✗, intentionally**:
    - `SystemCallFilter=~@resources`: `@resources` contains `setrlimit`, but `apply_rlimits`
      issues `prlimit64`, a member of `@default`. Denying `prlimit64` would make every exec
      Operation return `OUTCOME_FAILURE` (see
      [Deny-closed behavior](#resource-limits-on-spawned-children-v008-exec-audit)), so the
      rlimit guarantee rests on `@default`, which is never narrowed. `@resources` stays
      allowed as part of the base.
    - `SystemCallFilter=~@privileged`: `@system-service` pulls in `@chown` and `setuid`-class
      syscalls. In the strict profile they pass the filter but fail the kernel's capability
      check with `EPERM`; in the drop-in they are intentionally cap-backed.
  - **Placement matters.** The three lines must be inside `[Service]`. Placed after
    `[Install]`, systemd only logs `Unknown key ... in section [Install], ignoring` and the
    score stays `3.7`: the change silently does nothing.

  ```ini
  [Service]
  # ... existing directives (User=root, ProtectSystem=strict, CapabilityBoundingSet=
  # CAP_DAC_READ_SEARCH, AmbientCapabilities=, RestrictAddressFamilies=..., etc.) ...

  # These three lines MUST go within this [Service] section (e.g. immediately after
  # the existing RestrictAddressFamilies= line, before [Install]) — placing them
  # after [Install] silently no-ops (see "Placement matters" above).
  SystemCallFilter=@system-service
  SystemCallArchitectures=native
  MemoryDenyWriteExecute=yes
  ```

### Candidate minimal capability set

Split by profile, confirmed against source:

- **Strict (read + `service.restart`): `CAP_DAC_READ_SEARCH` only.** `file_read.rs` needs
  universal read; `service_restart.rs`'s `systemctl` child is authorized by UID 0 talking to
  PID 1 over D-Bus, not by a capability; `system_facts.rs` needs none. This set is already
  minimal.
- **Drop-in (`pkg.install` / filesystem-mutating Raw Exec): adds `CAP_CHOWN`,
  `CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_SETUID`, `CAP_SETGID`, `CAP_SETFCAP`** (cite
  `pkg_install.rs`). The audit confirms rather than shrinks this set: each maps to a
  package-manager need (file ownership, permission bits, file capabilities, user/group
  provisioning), and none can be dropped without a live trace proving a package family never
  uses it.

### What the derivation did and did NOT cover (residual risk)

The derivation covers the daemon and its fixed-argv children (`systemctl`, and the package
manager's own syscalls). It does **not** bound:

1. **Raw Exec.** Its Policy-gated argv is arbitrary by design (ADR-0001, ADR-0002), so its
   syscall surface cannot be enumerated.
2. **Package-manager maintainer scripts.** `dpkg`/`rpm` run arbitrary shell/Perl/Python hooks
   during install.

A maintainer script or Raw Exec command that needs a syscall **outside** `@system-service`
(e.g. `@mount`, `quotactl`, a `@privileged`-only call, `bpf`) is `SIGSYS`/`EPERM`'d: a **hard
block**, unlike the `ProtectSystem` case. Only a live trace on a real systemd host (#246)
closes this. If it shows a legitimate need, the fix is a targeted, trace-validated
**additive** line (e.g. `SystemCallFilter=@mount`) in the `pkg-install.conf` drop-in, never a
speculative widening of the base.

## Verification

Static validation, no real Node needed:

```console
$ systemd-analyze verify daemon/packaging/relay-daemon.service
```

On a host without the binary installed this reports:

```
relay-daemon.service: Command /usr/bin/relay-daemon is not executable: No such file or directory
```

That complaint is expected: the unit parses and validates apart from the missing binary. Any
other error (a malformed directive, an invalid value) is real.

```console
$ systemd-analyze security --offline=true daemon/packaging/relay-daemon.service
```

This confirms the directives are active: `NoNewPrivileges=`, `RestrictRealtime=`,
`ProtectSystem=` (strict), `PrivateTmp=`, `PrivateDevices=`, `ProtectClock=`,
`ProtectKernelLogs=`, `ProtectControlGroups=`, `ProtectKernelModules=`,
`ProtectKernelTunables=`, `ProtectHostname=`, `LockPersonality=` and every
`RestrictNamespaces=` sub-check report `✓`. The retained `CAP_DAC_READ_SEARCH` and the
`AF_NETLINK`/`AF_UNIX`/`AF_INET`/`AF_INET6` families show as expected residual exposure; the
tool cannot know they are load-bearing. `User=root` is always flagged.

**Still pending (#246), and only a human on a real systemd host can do it:** run the daemon
under `relay-daemon.service` with `policy.toml` in place and the Node enrolled with
`relay-daemon join`, confirm it connects and executes `system.facts`, then run the tracing procedure below against
`system.facts`, `file.read`, `service.restart`, `pkg.install` and a permitted Raw Exec. Confirm
none break (especially `pkg.install` maintainer scripts and Raw Exec), confirm or revise the
drop-in's `MemoryDenyWriteExecute=no`, and record the run here.

### Live tracing procedure (real systemd host)

The same procedure is a commented, never-executed block in `scripts/daemon-privilege-audit.sh`.

**Environment:** a real systemd host, `relay-daemon` installed at `/usr/bin/relay-daemon` under
`relay-daemon.service`, `policy.toml` in place and the Node enrolled with `relay-daemon join`, `strace`/`auditctl` (or
equivalent) available.

1. **Syscall union including children.** Seccomp is inherited across `execve`, so the trace
   must follow forked children (`service.restart`'s `systemctl` is the load-bearing case):

   ```console
   $ strace -f -qq -e trace=all -o /tmp/relay-trace.log \
       -p "$(systemctl show -p MainPID --value relay-daemon)"
   ```

   While attached, drive one of each Operation (`system.facts`, `file.read`,
   `service.restart`, `pkg.install`, and a representative Policy-permitted Raw Exec) from the
   Relay. On a packaged Relay the mutate and Raw Exec dispatches park at the gate first: approve
   each (answer the MCP client's approval question, or POST to the pending result's
   `decision_path` on the Control API), then re-drive it. Then extract the syscall set:

   ```console
   $ grep -oE '^[0-9]+ +[a-z_]+\(' /tmp/relay-trace.log \
       | sed -E 's/^[0-9]+ +([a-z_]+)\(/\1/' | sort -u
   ```

   Map each syscall to its `@group` (`systemd-analyze syscall-filter <group>`) and confirm it
   is in `@system-service`; anything outside is a trace-validated candidate addition.

2. **Seccomp audit-mode alternative** (no `strace`): set `SystemCallFilter=@system-service`
   plus `SystemCallLog=@system-service` in the unit (or use the kernel's `SECCOMP_RET_LOG`
   action) and read `journalctl -u relay-daemon | grep SECCOMP` for denied syscalls while
   exercising every Operation.

3. **Capability confirmation:** under the candidate `CapabilityBoundingSet`, confirm `file.read`
   of a non-root-owned, otherwise-unreadable file succeeds (exercises `CAP_DAC_READ_SEARCH`),
   and that `pkg.install` succeeds only under the `pkg-install.conf` drop-in, never under the
   strict baseline.
