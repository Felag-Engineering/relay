# `file.read` path arguments are matched in canonical form, and the executor re-checks the resolved target

**Status:** Accepted.

A `[[deny]]` rule for `file.read` (e.g. the shipped `/etc/shadow` deny) is matched by exact
byte string. Finding **#236** showed that deny is evaded by any non-canonical spelling of the
same file — `/etc/../etc/shadow`, `//etc/shadow`, `/etc//shadow`, `/etc/./shadow`,
`/etc/shadow/`, `/proc/self/root/etc/shadow`, a symlink, or (on a case-folding mount)
`/etc/Shadow`. This ADR decides how the deny is made to hold. It closes #236, filed by the
v0.0.8 red-team, whose regression test is
`noncanonical_path_denied_by_canonical_form_precondition` in
`daemon/crates/relay-policy/src/lib.rs`.

## Decision

Two layers, each doing exactly what it can do without giving Policy filesystem knowledge:

1. **Policy stays a pure function and rejects non-canonical *form*.** For a path-typed
   argument (at the time, only `file.read`'s `path`), `Policy::evaluate` returns **Deny** unless
   the path is in strict canonical form: **absolute**, with **no** `.`, `..` or empty (`//`)
   segment and **no** trailing slash. The test is pure and lexical (no I/O, deterministic,
   fail-closed), so only the one canonical spelling reaches allow/deny matching. This closes the
   *lexical* evasions.

2. **The executor re-checks the *resolved* target it actually opened.** `file.read` opens the
   path, reads the resolved path back off the descriptor (`/proc/self/fd/<n>`), re-evaluates
   Policy against it, and **refuses to read if it is denied**, reading only from the *same*
   descriptor it checked. The descriptor pins the inode, so there is no check-to-read TOCTOU
   window even if a symlink is swapped afterwards. This closes the *resolution* evasions:
   `/proc/self/root/etc/shadow`, `/proc/<pid>/root/etc/shadow`, and a symlink whose target is
   denied. If the resolved path cannot be read back, the executor fails closed (denied).

Layer 1 keeps Policy pure and deterministic (ADR-0011/0012). Layer 2 puts the one unavoidable
filesystem fact, *what path did I actually open*, where the open happens, and reuses the same
Policy engine rather than reimplementing matching.

## What this does not close (recorded residual)

**Case/Unicode folding on a case-insensitive or normalizing mount.** `/etc/Shadow` is canonical
*form*, and on a case-sensitive Linux filesystem (ext4/xfs default) names a different, usually
non-existent file (`ENOENT` → `OUTCOME_FAILURE`). Only on a case-folding or Unicode-normalizing
mount does it resolve to `/etc/shadow`, and there the descriptor may read back as the requested
spelling, so the re-check misses it. Neither canonical form nor `canonicalize` folds case or
Unicode. Closing this needs the daemon to know the mount's fold behaviour; it is recorded as a
**narrow, mount-specific residual** in the threat model. The regression test asserts Deny for
the deterministic evasions and documents the case/Unicode row as this residual.

## Alternatives considered

- **Canonicalize inside `Policy::evaluate`** (`std::fs::canonicalize` before matching).
  Rejected: it puts filesystem I/O into Policy evaluation (breaking its purity and its use in
  hypotheticals: `PolicyQuery`, the Policy preflight, ADR-0011), requires the target to exist,
  and, because the executor opens the path *after* the check, reintroduces a TOCTOU gap a
  symlink swap can drive through. Layer 2 avoids all three.
- **A typed prefix-path matcher in `/proto`** (structured path rules, deny a whole subtree).
  Deferred, not rejected: more expressive and the right long-term shape, but a wire contract
  change (invariant #8) that still needs canonical-form normalization underneath, and larger
  than a pre-launch fix warrants. It can supersede the exact-string matcher post-beta without
  invalidating this decision.

## Consequences

- The shipped `policy.example.toml` `/etc/shadow` deny holds against every deterministic
  spelling, and its comment states that path denies are matched in canonical form and
  re-checked on the resolved target.
- `file.read`'s `path` gains a Policy precondition: a non-canonical path is a **policy Deny**
  (`OUTCOME_DENIED_BY_POLICY`), distinct from a missing-file `OUTCOME_FAILURE`. Deliberately
  stricter, the more restrictive option on the privileged side.
- The `file.read` executor opens once, resolves the real target off the descriptor, re-checks
  Policy, and reads only from that descriptor; a `file_read` test covers the symlink and
  `/proc` re-check.
- Any future path-typed Operation inherits the same two-layer obligation.
- The residual-risk register (#225) records R2 (#236) as **fixed**, with the
  case/Unicode-on-folding-mount case carried as the narrow residual above.
