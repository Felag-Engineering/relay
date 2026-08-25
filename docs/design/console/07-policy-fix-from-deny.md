# 07 — Policy fix, from a deny

**Artboard 5.** The reactive half of the Policy pair: one deny in, one rule out.
**Milestone v0.7.0.**

**Governing:** ADR-0002, ADR-0011, ADR-0018, ADR-0022, invariants #2, #3.
**Backend:** the Plan's deny detail; `policyview` for the Node's effective Policy. **No write
path.**

## What this screen is for

`ui-advisory.md` sets the bar: *the operator must be able to go from "denied" to "I understand
exactly why, and what file to change in my IaC" without leaving the Console.* Until this screen,
that sentence had no implementation.

Reached from a deny — in a Plan, a Job result, or an approval card.

## Layout

**Left — what was denied.** The Operation with its arguments and risk badge; the deny block with
the rule verbatim, its file and line, and the Node's Policy fingerprint; and the context that
makes it actionable: how many Nodes deny for this same reason, and what the rest of the fleet
carries. The affected Nodes list, with a link to open them as a fleet filter.

**Right — the fix.** The suggested change as a **diff** against the current rule. Then, in its own
card, the boundary statement. Then the rollout ladder.

## Two kinds of deny, rendered differently

- **Deny-by-default** — no allow rule matches. The absence of an allow *is* the deny. Show the
  nearest rule and why the argument fell outside it.
- **An explicit `[[deny]]`** — deny beats allow. Show the deny rule itself.

The distinction matters because the fixes differ: widen an `allowed_args` versus remove or narrow
a deny. An implementer must not collapse them into one message.

## The diff

Rendered with add and remove gutters, using **neutral tints, not red and green**. Colour is scarce
here and a Policy diff is not a failure.

```
  [[operation]]
  name = "service.restart"
- allowed_args = [["php-fpm"]]
+ allowed_args = [["nginx", "php-fpm"]]
```

Alongside it, an honest impact line: what this widens, on which Nodes, and — importantly — that it
widens nothing else. Argument-level granularity means the allow list is the whole grant.

## The boundary, stated on screen

> The Relay will not apply this, and has no way to.

Followed by why: Policy is rooted on each machine and immutable from here, and that property is
what makes a compromised Relay survivable. This screen ends at the clipboard on purpose.

## The rollout ladder

Four steps, and step 3 is the one that closes the loop:

1. Commit to the file the package installs as a conffile, so the edit survives daemon upgrades.
2. Roll out through config management. The daemon reloads locally; nothing is pushed from here.
3. **Watch the Policy-fingerprint facet on the fleet view.** When the old fingerprint reaches zero
   Nodes, the rollout landed everywhere — by string comparison, not by trust.
4. Re-run the Plan. The denies become allows, or they say what is still wrong.

## Handoff to the author screen

"Open in Policy Author" carries this Node's effective Policy and the pending edit into spec 06, so
a one-line fix can grow into a considered rewrite without retyping.

## Must not appear

- Any apply, push or distribute control.
- Red/green diff colouring.
- A suggested rule wider than what the denied action needs. If the operator wants broader, that is
  the author screen's job.

## Acceptance

- [ ] Deny-by-default and explicit-deny render differently and suggest different fixes.
- [ ] The suggested rule is minimal: it permits the denied action and nothing more.
- [ ] The rendered rule and line number match the Node's live effective Policy.
- [ ] The screen states the no-write boundary in the UI, not only in documentation.
- [ ] "Open in Policy Author" preserves the edit.
