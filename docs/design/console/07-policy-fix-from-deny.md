# 07 — Policy fix, from a deny

**Artboard 5.** The reactive half of the Policy pair: one deny in, one rule out.
**Milestone v0.7.0.**

**Governing:** ADR-0002, ADR-0011, ADR-0018, ADR-0022, invariants #2, #3.
**Backend:** the Preflight's deny detail; `policyview` for the Node's effective Policy. **No write
path.**

## What this screen is for

`ui-advisory.md` sets the bar: *the operator must be able to go from "denied" to "I understand
exactly why, and what file to change in my IaC" without leaving the Console.* Until this screen,
that sentence had no implementation.

Reached from a deny — in a Preflight, a Job result, or an approval card.

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

1. Commit to the Policy file, or to a fragment in the Policy directory, in the IaC repo.
2. Roll out through config management, which restarts the daemon; nothing is pushed from here.
3. **Watch the Policy-fingerprint facet on the fleet view.** When the old fingerprint reaches zero
   Nodes, the rollout landed everywhere — by string comparison, not by trust.
4. Re-run the Preflight. The denies become allows, or they say what is still wrong.

## Handoff to the Policy Catalog

List the catalog fragments whose declared Operations (PC-3) include the denied Operation's name,
and link to the Policy Catalog (spec 06) with them shown — a published fragment beats a
hand-written rule. Matching is by Operation name only: the screen never says a fragment *would*
permit this Task (invariant 12), and points to `policy check --would-allow` for that verdict. The
catalog never takes this screen's rule with it: it emits no allow rules (PC-11).

## Must not appear

- Any apply, push or distribute control.
- Red/green diff colouring.
- A suggested rule wider than what the denied action needs. Broader permission comes from a
  catalog fragment or the operator's own IaC repo.

## Acceptance

- [ ] Deny-by-default and explicit-deny render differently and suggest different fixes.
- [ ] The suggested rule is minimal: it permits the denied action and nothing more.
- [ ] The rendered rule and line number match the Node's live effective Policy.
- [ ] The screen states the no-write boundary in the UI, not only in documentation.
- [ ] Catalog fragments declaring the denied Operation are listed by name match only, with no
      allow/deny verdict, and link to the Policy Catalog.
