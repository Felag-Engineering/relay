<!-- Opened by the dev-loop? Fill every section. Opened by a human? Fill every section except
     Reviews. A human merges this; they may be reading it
     weeks later with no memory of the context. -->

Closes #

## What changed

Behaviour, from the user's perspective. Not a file-by-file list.

## Verification

- [ ] `make verify` green

**Gates skipped:** none / `lint-zizmor` (`zizmor` absent) / …

> A skipped gate is not a passed gate. If `make verify` recorded a skip (`shellcheck`,
> `zizmor` or `cargo-deny` absent), say so here — CI runs those gates regardless, and the
> reviewer needs to know the local run did not.

## Reviews

> Filled by the dev-loop only. A human contributor skips this section — delete it or
> leave it blank.

- Claude: plan / code / security — <verdicts, cycles used>
- Codex: once, final diff — `<verdict>`, or absent (`reason=<token>`, model `<slug>`): the gate
  ran with one reviewer
- If Codex's stderr printed `codex-review: scope-partial files=<n>`, part of this branch was
  already committed when Codex ran and it saw only the uncommitted remainder — name which
  committed files it did not see: <files, or n/a>

> Codex runs once per issue, on the final diff — not every review cycle, because its allowance
> is plan quota, not API spend. "Absent" is never a pass. The reason token NARROWS the cause, it
> does not fully distinguish it: `reason=no-result` covers both an exhausted quota and a
> rejected model slug, and only the script's own stderr replay — terminal diagnostics, never
> quoted here — says which (#694).

## Capability spec

- [ ] The governing spec in `docs/specs/` is still true of the code after this change
- [ ] Or: no capability spec covers this area yet

**Spec:** none applies / `docs/specs/<name>.md`

> Capability specs are **human-authored** and the loop never edits one. A change that makes a
> spec statement untrue stops and escalates — say which statement, below — so a human can
> update the spec first.

## Security surface

- [ ] Touches none of: `/proto`, Policy, execution, transport, mTLS, auth, blast caps, label authority
- [ ] Or: names the invariant below and has a human reviewing it deliberately

**Invariants touched:** none / #N — …

## Escalations

Anything the pipeline stopped on, guessed at under a stated assumption, or left undone.
"None" is a valid answer; silence is not.

---

**Must be merged by a human** — nothing here merges autonomously.
