# Node code never overrides the operator's umask — a declared mode is a ceiling

> If the Node specifies umask, that is a boundary we shouldn't be getting around. What is
> created and enforced on the Node is enforced on the Node.
> — owner decision, 2026-09-07 (issue #532)

A process's umask strips permission bits from what that process creates. It can only
*remove* permissions, never add them, and it is set by the operator — in the unit file, in
the shell, in whatever config management owns the host. `open(2)`'s mode argument and
`mkdir(2)`'s are **requests**, masked on the way through. `chmod(2)` is not: it sets the
bits it is given, whatever the umask said.

So a `set_permissions` call after creation is not "making sure the mode is right". It is the
Node's own code reaching past a setting the operator chose, on a host they own, in a daemon
that runs as root. That is the boundary this ADR draws.

The rule this repo actually had was narrower and had been written down: *force only where
forcing can only tighten.* It is a defensible rule — it never widens anything — and it is
why `dedup.rs` carried a comment arguing for its two forced modes, and why `dispatch.rs`
copied the shape into a test fixture. It is nonetheless the wrong rule, for a reason the
narrow version cannot see: with a declared mode of `0700` and an operator umask of `0o100`,
"forcing can only tighten" re-adds the **owner-execute bit the operator deliberately
stripped**. The forced call is looser than what the operator asked for. In practice the two
rules differ only in the pathological cases; in principle they differ everywhere, and the
principle is the part that survives being copied into the next file.

The evidence that this needs writing down rather than remembering is that it recurred under
review. Two issues in the #481 run — **#507** (`daemon/src/identity.rs`) and **#509**
(`relay/internal/ca/ca.go`) — were filed **recommending the forced chmod**, in both cases as
a hardening improvement, and both were caught during implementation rather than by the rule
they were violating: #507 became a fix *removing* the forcing, and #509 confirmed `ca.go`
had never had it. A rule that is only in reviewers' heads gets re-derived backwards by the
next reasonable person, because "make the permissions definitely right" is a genuinely
appealing instinct. It is also the second such near-miss on the same trust boundary the
Policy file sits behind (ADR-0002, ADR-0021), which is why this is an ADR and not a comment.

## Decisions

- **A declared mode is a ceiling — the most the code asks for.** Node code requests modes
  through `OpenOptions::mode()`, `DirBuilder::mode()`, Go's `os.OpenFile`/`os.MkdirAll`
  perm argument, and nothing else. The umask may tighten what it gets. **Nothing in node
  code may widen it back.**

- **No `set_permissions` / `os.Chmod` on a production path. Flat prohibition, no
  can-only-tighten exemption.** The exemption is what let the pattern spread, and a flat
  rule is the only kind that survives being copied. This is a *narrowing* rule: it removes
  a capability from node code, never grants one.

- **The rule is about the operator, not about the bits.** It applies wherever a real
  operator's umask is in play — the daemon and the Relay, at runtime, on a host somebody
  owns. It says nothing about what modes are appropriate; declare them as tightly as the
  material deserves.

- **Test fixtures are exempt, and this is not an exception to the principle.** A test
  constructing a fixture has no Node, no operator and no boundary to cross — the fixture
  *is* the input, and a test proving a loader rejects a world-readable file must be able to
  produce one. `chmod` is the only way to build that state, since the umask can only take
  bits away. Today's fixtures — `relay/internal/approvalnotify/approvalnotify_test.go`,
  `daemon/src/templates.rs`, `daemon/src/policy.rs`, `daemon/src/policy_check.rs`, plus the
  permission-denied guidance in `daemon/src/operations/file_read.rs` — stay exactly as they
  are. The line to hold is that fixture code is not a template for production code; where a
  fixture does *not* need an exact mode, it should request rather than force, so the shape
  being copied is the right one.

- **Tests assert ceilings, never exact modes**, using one of the two helpers that already
  exist — **`assertModeWithin`** (`relay/internal/ca/ca_test.go`) and
  **`mode_assert::assert_within`** (`daemon/src/identity.rs`, now also used by
  `dedup.rs`). Named here so a third shape is not invented. Each asserts two things: no bit
  set beyond the declared ceiling (which catches every widening regression — a re-added
  chmod, a dropped `.mode()`, a loosened constant — under *any* umask), and the
  security-relevant bits clear outright. An exact-equality assertion is the wrong test: it
  fails when a umask **tightens** a file, which is not a regression but the boundary
  working, and its obvious "fix" is to loosen the writer.

- **The ceiling in a test is a literal, never the production constant.** #509 established
  this empirically: a ceiling taken from `certPerm` rises in lockstep with any edit to
  `certPerm`, so the assertion can never fail on a widened constant — it asserts only that
  the code agrees with itself. The literal is what makes the test a second opinion.

- **A mode the umask tightens into unusability is a loud failure by design.** It is not a
  bug to engineer around, and specifically not a justification for reintroducing a forced
  mode. The daemon's contract when it cannot write its own state is to refuse work, not to
  proceed without it; see below.

## The one place this could have cost an invariant

`dedup.rs`'s forced modes were never a security measure. Their comment argued *functional*
correctness: a umask of `0o100` strips user-execute from the `0o700` `seen-tasks/` directory,
and a directory without user-execute cannot have files created in it. That directory holds
the markers enforcing **at-most-once Task execution (ADR-0004, invariant #4)** — the one
invariant a permissions change here could plausibly break. So the failure path was checked,
not assumed (#532's requirement, demonstrated in this change):

1. `main.rs` opens the store with `?` — a store that cannot be opened stops the daemon
   before it connects. Nothing executes.
2. If `open` succeeds and only the marker write fails, `run_once` **fails closed**: *"if the
   durable record failed, do not execute. Without a persisted marker, at-most-once cannot be
   guaranteed on a retry."* The Task is refused with a `FAILURE` naming the record error;
   `exec` is never called.
3. Where the daemon's privileges bypass DAC entirely, the tightened directory stays usable
   and Tasks run normally, each with its marker durably recorded.

There is no fourth branch, and in particular none where a Task executes without a marker
behind it. Every reachable outcome preserves at-most-once: **refused, or recorded then
run.** `daemon/src/dedup.rs`'s
`umask_tightened_dedup_directory_never_executes_unrecorded` asserts both live branches and
`record_error_fails_closed` guards the fail-closed path independently of privilege.

Worth recording because it surprises: the shipped unit runs the daemon as `User=root` but
bounds it to `CapabilityBoundingSet=CAP_DAC_READ_SEARCH`, so it holds no `CAP_DAC_OVERRIDE`
and Unix write permissions genuinely apply to it. Root-ness is not a reason to assume the
directory stays writable — and an unconfined root, which does bypass DAC, simply lands in
branch 3. The refusal, when it happens, is loud, immediate, and attributable to the
operator's own setting, which is exactly what the boundary implies should happen.

## Considered Options

- **Keep "force only where forcing can only tighten".** Rejected. It permits re-adding owner
  bits a umask stripped, so it does not actually implement the boundary; and as a
  per-site judgement it is re-litigated at every new site, which is how it spread. Its
  practical advantage — a mode that is exactly what the code declared, always — is precisely
  the thing the operator is entitled to override.

- **Force, but only for group/world bits.** A tighter variant that never touches owner bits.
  Rejected: still a chmod over the operator's umask, still a per-site judgement, and it
  buys nothing the umask does not already guarantee (a umask cannot *add* group or world
  bits).

- **Refuse to start under a umask that would tighten a declared mode.** Rejected as
  hostile and unnecessary: the daemon would refuse configurations that are perfectly
  workable (`umask 077` tightens nothing this code declares), and where a umask really is
  incompatible the existing fail-closed paths already say so at the point of failure, with
  the actual error.

- **Set the umask ourselves at startup.** Rejected outright: it is the same override with a
  wider blast radius — `umask(2)` is process-global and would silently govern every file the
  daemon and its Task subprocesses create.

## Consequences

- Three production sites drop their forced modes and keep their requests:
  `daemon/src/dedup.rs` (the `0700` `seen-tasks/` directory and the `0600` marker file) and
  the `0600` temp-file fixture helper in `daemon/src/dispatch.rs`, which now *requests*
  its mode instead of forcing it so the shape it models is the correct one.
  `relay/internal/ca/ca.go` and `daemon/src/identity.rs` already complied; the stale
  rationale in `identity.rs` that cited `dedup.rs`'s forcing as a permitted case is
  rewritten to cite this ADR.

- Under an ordinary umask nothing changes: the requested modes still land, and the ceiling
  tests prove it (dropping either `.mode()` call makes them fail).

- A Node whose umask tightens the daemon's state directory out of usability now fails
  loudly instead of quietly having its permissions rewritten. That is the accepted cost, and
  the invariant-4 analysis above is why it is affordable.

- This is a rule about node code, not a runtime control: nothing enforces it mechanically
  today. A grep-based CI check that fails when a production path calls
  `set_permissions`/`os.Chmod` would make the boundary enforced rather than remembered, and
  is cheap now that the rule is flat rather than a per-site judgement. #532 raises it as a
  separate follow-up, deliberately not bundled here.

- Cited by: ADR-0002 and ADR-0021 (the local, root-owned filesystem trust root these modes
  protect) and ADR-0004 (at-most-once, the invariant the `dedup.rs` sites touch).
