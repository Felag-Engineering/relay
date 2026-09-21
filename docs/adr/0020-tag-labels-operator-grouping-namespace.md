# `tag:` labels — an operator-set grouping namespace outside the security lane

Operators need to group Nodes ad hoc from the Relay side ("these 40 boxes are the
Postgres-15 canary") without a config-management round-trip. Neither existing namespace
(ADR-0006) can serve: `node:` is node-rooted and Relay-immutable by invariant, and
`relay:` is reserved for the security-sensitive lane. This ADR adds a third namespace,
and — closing a gap found in Console planning (`docs/design/console-backend-coverage.md`)
— schedules post-enrollment `relay:` label management, without which quarantine was
impossible after enrollment.

## Decisions

- **A third label namespace, `tag:…`** — Relay-stored and Node-immutable (a Node can
  neither set nor remove one; it shares `relay:`'s forge-resistance), created and removed
  through the shared capability layer (Control API + Admin Console) by `operator`-or-above
  with standard session auth — no step-up — and audited like every capability action.
  Valid in Selectors for routine targeting exactly like `node:` labels.
- **`tag:` is never a security-lane target.** Quarantine, remediation, and
  secret-distribution Selectors must target `relay:` labels only, exactly as before —
  ADR-0006's operating rules are unchanged. The lane keeps its small vocabulary and heavy
  write ceremony; `tag:` absorbs the everyday traffic that would otherwise erode both.
- **Post-enrollment `relay:` label management exists now.** Set/remove `relay:` labels on
  a live Node via the capability layer, gated `admin` + step-up re-authentication. Until
  now `relay:` labels could only be stamped at enrollment from Enrollment Token scope,
  which made the flagship use case — quarantining a Node you have come to distrust —
  impossible short of full revocation. The incident ladder becomes: quarantine
  (`relay:`) < revoke < Freeze.
- **Namespaces cannot collide; the prefix is mandatory.** Unprefixed label keys remain
  invalid, so every label's authority is legible from its name.

## Considered Options

- **Open `relay:` to everyday tagging.** Rejected: either every `tag`-grade write costs
  `admin` + step-up (ceremony fatigue trains admins to rubber-stamp the same step-up that
  guards quarantine and secret targeting) or the namespace's authz is relaxed (weakens the
  lane itself). An auditor should read the `relay:` lane and see only security state.
- **System Model Services as the grouping mechanism.** Rejected: the System Model is
  advisory by invariant #9 and never feeds Selectors; anything meant for targeting must be
  a real Label.
- **Unprefixed operator labels.** Rejected: authority would no longer be legible from the
  key, and collision with `node:`-reported keys becomes ambiguous.

## Consequences

- Amends ADR-0006's two-namespace model to three (its `node:`/`relay:` authority rules
  are unchanged; a pointer is added there) and AGENTS.md invariant #7 in the same
  change → human-merge lane.
- A hijacked `operator` session can rewrite `tag:` labels and thereby redirect *routine*
  Jobs — bounded, as ever, by Grants, Node Policy, and blast caps — but can never attract
  a secret distribution or lift a quarantine: those live in `relay:`, behind `admin` +
  step-up.
- Backend (capability + `/api/v1` endpoints for both namespaces, one mechanism with two
  authz tiers) and Console surfaces (bulk tag-from-filter in the fleet view; `relay:`
  set/remove on Node detail) are scheduled in v0.7.0
  (`docs/design/console-backend-coverage.md`).
- `tag:` labels persist in the registry alongside `relay:` labels and appear in
  `list_nodes`/`describe_node`, Selectors, and Console views like any Label.
- GLOSSARY.md's **Label** entry is updated in the same change.

## Amendment (2026-09-08): invariant 7 restated as write authority, not as status

This ADR's decision is unchanged. What changed is how AGENTS.md invariant 7 summarises it.

The invariant read that `tag:` labels "are operator-set through the control plane … for
ad-hoc grouping and routine targeting" — present tense, for a namespace this ADR decided on
but which has no write path and no storage on the Node record until label management lands
(#430). A `tag:` Selector therefore resolves to the empty set rather than an error, and the
surfaces do not agree about that: the Admin Console refuses a `tag:` filter with an
explanatory error, while the MCP `list_nodes` schema advertises `tag:` to an AI-agent with no
caveat, so the agent receives a false negative rather than a refusal. Issue #347 recorded the
documentation half of this.

The invariant now states the property this ADR actually establishes — that each namespace has
exactly one writer and is immutable from every other side — rather than asserting that any
given namespace is populated. Write authority is a rule that holds before and after #430; a
claim about what is settable today is not. The `relay:` clause lost its "(enrollment-stamped,
or `admin` + step-up)" parenthetical for the same reason: how the Relay comes to write a
`relay:` label is mechanism, and its second half is likewise unbuilt.

The surface disagreement above is a defect in its own right, not a documentation problem, and
is not resolved here.

## Amendment (2026-09-16): `tag:` may engage a quarantine, and no Account writes `relay:` directly

Owner decision, 2026-09-16 (#582). Two decisions above are superseded; the rest stand.

- **"`tag:` is never a security-lane target"** is narrowed: engaging a quarantine may target
  `tag:`. Lifting may not, and remediation and secret distribution still target `relay:` only. The
  reasoning and the accepted residual are in ADR-0006's amendment of the same date.
- **"Post-enrollment `relay:` label management exists now … `admin` + step-up"** is superseded
  before it was built. No Account sets or removes a `relay:` label directly. Each `relay:` key is
  defined together with the action that writes it, and roles, step-up and audit apply to that
  action: a quarantine is engaged by `operator` or above (machine Accounts allowed, counted against
  the `mutate` blast cap) and lifted only by a human `admin` with step-up. A generic `relay:` write
  would make the namespace's meaning whatever its last editor intended; binding each key to an
  action keeps it legible. The incident ladder is unchanged: quarantine < revoke < Freeze.

`tag:` storage and its write path are still unbuilt (#430); until they exist, a `tag:` term is
refused at parse on every surface, quarantine included.

## Amendment (2026-09-20): amended by ADR-0034

ADR-0034 added a fourth namespace, `state:` (Relay-derived, written by nobody), beside `node:`,
`relay:` and `tag:`. Wherever this ADR counts three namespaces, read four; the rules for `tag:`
are unchanged.
