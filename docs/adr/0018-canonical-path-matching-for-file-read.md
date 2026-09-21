# `file.read` path arguments are matched in canonical form, and the executor re-checks the resolved target

A `[[deny]]` rule for `file.read` (e.g. the shipped `/etc/shadow` deny) is matched by exact
byte string. Finding **#236** showed that deny is evaded by any non-canonical spelling of the
same file — `/etc/../etc/shadow`, `//etc/shadow`, `/etc//shadow`, `/etc/./shadow`,
`/etc/shadow/`, `/proc/self/root/etc/shadow`, a symlink, or (on a case-folding mount)
`/etc/Shadow`. This ADR decides how the deny is made to hold. It closes the security debt the
v0.0.8 red-team filed as #236 and resolves the `#[ignore]`d regression test at
`daemon/src/policy.rs:2270`.

## Decision

Two layers, each doing exactly what it can do without giving Policy filesystem knowledge:

1. **Policy stays a pure function and rejects non-canonical *form*.** For a path-typed
   argument (today only `file.read`'s `path`), `Policy::evaluate` returns **Deny** unless the
   path is already in strict canonical form: **absolute**, with **no** `.` segment, **no**
   `..` segment, **no** empty segment (`//`), and **no** trailing slash. This is a pure
   lexical test — no I/O, deterministic, fail-closed — so the only spelling that can reach the
   allow/deny string matching is the single canonical one. This closes the *lexical* evasions
   (`/etc/../etc/shadow`, `//etc/shadow`, `/etc//shadow`, `/etc/./shadow`, `/etc/shadow/`).

2. **The executor re-checks the *resolved* target it actually opened.** `file.read` opens the
   path, reads the real resolved path back off the open descriptor (`/proc/self/fd/<n>`),
   re-evaluates Policy against that real path, and **refuses to read if the resolved path is
   denied** — reading only from the *same* descriptor it checked. Because the descriptor pins
   the opened inode, the check and the read see the same file: there is no check-to-read TOCTOU
   window even if a symlink is swapped afterwards. This closes the *resolution* evasions that
   are not visible as a string: `/proc/self/root/etc/shadow` and `/proc/<pid>/root/etc/shadow`
   (the descriptor resolves to `/etc/shadow`), and a symlink whose target is denied. If the
   resolved path cannot be read back off the descriptor, the executor fails closed (denied).

Layer 1 keeps Policy pure and deterministic (consistent with ADR-0011/0012 — Policy is the
daemon's live engine, evaluated without side effects). Layer 2 puts the one unavoidable
filesystem fact — *what path did I actually open* — at the boundary where the open happens,
and re-uses the same Policy engine rather than reimplementing matching.

## What this does not close (recorded residual)

**Case/Unicode folding on a case-insensitive or normalizing mount.** `/etc/Shadow` is canonical
*form* and, on a case-sensitive Linux filesystem (ext4/xfs default), simply names a different,
usually non-existent file — harmless (`ENOENT` → `OUTCOME_FAILURE`). Only on a case-folding or
Unicode-normalizing mount does it resolve to `/etc/shadow`, and there the descriptor's real
path may read back as the requested spelling, so the re-check does not catch it. Canonical-form
matching and `canonicalize` both fold `.`/`..`/`//`/symlinks but **never** case or Unicode.
Closing this would require the daemon to know the mount's fold behaviour, which exact-string
Policy cannot; it is out of scope here and recorded as a **narrow, mount-specific residual** in
the threat model. The regression test asserts Deny for the deterministic evasions and documents
the case/Unicode row as this residual rather than asserting it fs-independently.

## Alternatives considered

- **Canonicalize inside `Policy::evaluate`** (`std::fs::canonicalize` before matching). Rejected:
  it puts filesystem I/O into Policy evaluation (breaking its purity and its use in
  hypotheticals — `PolicyQuery`, the Policy preflight, ADR-0011), requires the target to already exist,
  and — because the executor opens the path *later* than the check — reintroduces a TOCTOU gap
  a symlink swap can drive through. Resolving on the descriptor the executor already holds
  (layer 2) avoids all three.
- **A typed prefix-path matcher in `/proto`** (structured path rules, deny a whole subtree).
  Deferred, not rejected: it is more expressive and the right long-term shape, but it is a wire
  contract change (invariant #8: regenerate both sides) and still needs canonical-form
  normalization underneath. It is larger than a pre-launch fix warrants; it can supersede the
  exact-string matcher post-beta without invalidating this decision.

## Consequences

- The shipped `policy.example.toml` `/etc/shadow` deny now holds against every deterministic
  spelling. The misleading "exact-string" comment there is corrected to state that path denies
  are matched in canonical form and re-checked on the resolved target.
- `file.read`'s `path` gains a Policy precondition (canonical form); a non-canonical path is a
  **policy Deny** (`OUTCOME_DENIED_BY_POLICY`), distinct from a missing-file `OUTCOME_FAILURE`.
  This is a deliberately stricter contract — the more restrictive option on the privileged side.
- The `file.read` executor no longer does a bare `File::open`: it opens once, resolves the real
  target off the descriptor, re-checks Policy, and reads only from that same descriptor.
- The `#[ignore]`d test at `policy.rs:2270` is enabled for the deterministic evasions;
  executor-level symlink/`/proc` re-check is covered by a new `file_read` test.
- Any future path-typed Operation inherits the same two-layer obligation; this ADR is its
  reference.
- The v0.0.8 residual-risk register (#225) records R2 (#236) as **fixed**, with the
  case/Unicode-on-folding-mount case carried as the narrow residual above.
