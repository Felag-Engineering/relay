# 05 — Composer and Preflight

**Artboard 4.** The execution surface, and the trust-building wedge. **Milestone v0.7.0.**

**Governing:** ADR-0001, ADR-0011, ADR-0012, ADR-0026, ADR-0027, invariants #1, #3, #5, #10, #13.
**Backend:** `capability/{execution,plan,cancel}`, `opvocab` golden schema, the approval gate,
step-up re-auth.

## What this screen is for

ADR-0026 reversed ADR-0009's no-execution stance for exactly this: *a skeptical operator does not
come to trust a fleet-wide RCE system by reading its documentation. They trust it by probing the
boundary themselves — composing an Operation, seeing the Preflight, watching a Policy rule deny it,
and reading the rule that fired.* **The wall is the same wall.** An Operation dispatched here traverses
Selector → Policy → blast cap → audit identically to one from MCP.

## The rhythm

**Compose → see the truth → confirm identity → run.** The mutating path is deliberately slower
than the reading path, and the visual sequence must convey that.

There is **no Run button**. `Preflight` is the only primary action. `Apply` does not exist until a
Preflight has rendered beneath it.

## Layout

Two columns. Left is the form, right is empty until preflighted.

**Left — the form.** An Operation picker driven by `list_operations` schemas, each entry showing
its risk badge. Beneath it, schema-driven argument fields showing their constraints inline as
quiet helper text *before* submission — enum choices, patterns, charsets. ADR-0001's legibility
bar applies to humans too. Then a Selector input with a live match line: "matches 2,214 Nodes ·
mutate-cap 2,500 ✓".

A **Raw Exec** tab exists and is visible only to `admin`. Raw Exec is always mutate-class and
always takes the mutate cap.

**Right — the Preflight.** Empty until preflighted, and the empty state says why: *this side stays
empty until you press Preflight; there is no path from the form to a running command that does not
pass through here first.*

Once rendered: fan-out summary with cap arithmetic, risk badge, plan hash in mono, a segmented
verdict bar, then grouped verdicts — allow (collapsed, it is the mode), deny (expanded, showing
the rule verbatim once when all denies share a reason), unknown/offline (collapsed). The Preflight
is **pinned** and never reflows while it is being read.

Beneath the Preflight, and only then, **Apply**.

## The blast cap

Rendered as arithmetic inside the fan-out line, never as a setting. Over-cap is **informative, not
an error**: no red, no shake, no disabled control without explanation. The number is a fact about
this Relay's configuration, which no screen can edit and no Account of any role can raise
(invariant #11).

## Apply

Clicking Apply opens the **step-up** modal. This is the strongest per-action human-intent binding
in the system and the reason a browser may dispatch at all. `read`-class dispatch does **not**
require step-up — it is bounded by the read cap and audited metadata-only, and gating it would
make the preflight-first habit expensive enough to route around.

If the deployment's approval gate matches this action, applying **parks** the Job for sign-off
rather than dispatching. Say so before the click, not after.

## Editing after a Preflight

Any edit re-preflights: new plan hash, and **existing approvals fall away**. Approvers do not
amend — an approver who wants changes sends it back. An approval commits to a plan hash over the
Operation, its arguments and the *resolved fan-out*; letting the thing change under a signature
would make the signature meaningless, and letting an approver edit then approve collapses
`requester_allowed: false`.

## Entry points

Two, per the design session: the **Run** nav item (discoverability — ADR-0026's wedge argument
requires that the first operator to open the Console can find it) and **contextually** from a
filtered fleet view or a Node ("Run against these 4,012", "Run here"), pre-filling the Selector.

## Must not appear

- A Run button, at any point, in any state.
- An Apply button before a Preflight has rendered.
- Any Relay-side computation of a Policy verdict. A Preflight is daemon-evaluated (ADR-0011); this
  screen renders a verdict it did not compute (invariant #12).
- Any editable blast cap, gate rule, or `console_execution` value.

## States

- **`console_execution = off`** — the routes are not mounted and this screen **does not exist**.
  Not greyed out, not "unavailable": absent. `absent` beats `forbidden` and that property is the
  whole point of the flag.
- **`viewer`** — no Run nav item, no contextual entry.
- **`operator`** — composer yes, Raw Exec tab no.
- **Frozen** — Preflights still resolve, Apply is refused with the Freeze reason. Say what is still
  true.
- **Over cap** — the Preflight still renders; Apply is unavailable with the cap named.

## Acceptance

- [ ] A Console route that attempts to dispatch outside the capability layer **does not compile**
      (the `no_dispatch` structural guard, extended to the Console package).
- [ ] Applying a `mutate` demands step-up; applying a `read` does not.
- [ ] With `console_execution = off`, no execution route is mounted and the composer is not
      rendered.
- [ ] `operator` can run an Operation and cannot reach Raw Exec; the refusal is decided by the
      capability layer's `RoleGate`, not by this screen.
- [ ] A denied Node in the Preflight shows the rule that fired, verbatim, styled
      informative-neutral.
- [ ] Editing any field after a Preflight renders invalidates the plan hash visibly.
- [ ] `console_execution` is file-only Relay configuration: it lands with the packaging config
      sample and its drift gate, and no API can read or set it.
