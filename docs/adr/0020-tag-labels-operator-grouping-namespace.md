# `tag:` labels — an operator-set grouping namespace outside the security lane

**Status:** Accepted; amended by ADR-0034.

ADR-0050 (2026-10-23) builds `tag:` for the MVP and narrows its writer to a human Account at
`operator` or above; a join token's labels become initial tags.

Operators need to group Nodes ad hoc from the Relay side ("these 40 boxes are the
Postgres-15 canary") without a config-management round-trip. Neither existing namespace
(ADR-0006) can serve: `node:` is node-rooted and Relay-immutable, and `relay:` is reserved for
the security-sensitive lane. This ADR adds a third namespace, and schedules post-enrollment
`relay:` label management (a gap found in Console planning,
`docs/design/console-backend-coverage.md`), without which quarantine was impossible after
enrollment.

## Decisions

- **A third label namespace, `tag:…`**: Relay-stored and Node-immutable (sharing `relay:`'s
  forge-resistance), created and removed through the capability layer (Control API + Admin
  Console) by `operator`-or-above with standard session auth, no step-up, and audited like
  every capability action. Valid in Selectors for routine targeting like `node:` labels.
- **`tag:` is never a security-lane target.** Quarantine, remediation, and
  secret-distribution Selectors target `relay:` labels only; ADR-0006's operating rules are
  unchanged. The lane keeps its small vocabulary and heavy write ceremony; `tag:` absorbs the
  everyday traffic that would otherwise erode both.
- **Post-enrollment `relay:` label management exists now.** Set/remove `relay:` labels on a
  live Node via the capability layer, gated `admin` + step-up re-authentication. Stamping only
  at enrollment made the flagship use case, quarantining a Node you have come to distrust,
  impossible short of revocation. The incident ladder becomes: quarantine (`relay:`) < revoke
  < Freeze.
- **Namespaces cannot collide; the prefix is mandatory.** Unprefixed label keys remain
  invalid, so every label's authority is legible from its name.

## Considered Options

- **Open `relay:` to everyday tagging.** Rejected: either every `tag`-grade write costs
  `admin` + step-up (training admins to rubber-stamp the step-up that guards quarantine and
  secret targeting) or the namespace's authz is relaxed (weakening the lane). An auditor
  reading the `relay:` lane should see only security state.
- **System Model Services as the grouping mechanism.** Rejected: the System Model is
  advisory by invariant #9 and never feeds Selectors; anything meant for targeting must be
  a real Label.
- **Unprefixed operator labels.** Rejected: authority would no longer be legible from the
  key, and collision with `node:`-reported keys becomes ambiguous.

## Consequences

- Amends ADR-0006's two-namespace model to three (its `node:`/`relay:` authority rules
  are unchanged; a pointer is added there) and AGENTS.md invariant #7 in the same
  change → human-merge lane.
- A hijacked `operator` session can rewrite `tag:` labels and so redirect *routine* Jobs
  (bounded by Grants, Node Policy, and blast caps), but can never attract a secret
  distribution or lift a quarantine: those live in `relay:`, behind `admin` + step-up.
- The backend (capability + `/api/v1` endpoints for both namespaces, one mechanism with two
  authz tiers) and Console surfaces (bulk tag-from-filter in the fleet view; `relay:`
  set/remove on Node detail) are scoped in `docs/design/console-backend-coverage.md`.
- `tag:` labels persist in the registry alongside `relay:` labels and appear in
  `list_nodes`/`describe_node`, Selectors, and Console views like any Label.
- GLOSSARY.md's **Label** entry is updated in the same change.

## Amendment (2026-09-08): invariant 7 restated as write authority, not as status

This ADR's decision is unchanged. What changed is how AGENTS.md invariant 7 summarises it.

The invariant read that `tag:` labels "are operator-set through the control plane … for
ad-hoc grouping and routine targeting", in the present tense, for a namespace with no write
path and no storage on the Node record until label management lands (#430). At the time a
`tag:` Selector resolved to the empty set, and the surfaces disagreed: the Admin Console
refused a `tag:` filter, while the MCP `list_nodes` schema advertised `tag:` with no caveat, so
an AI-agent got a false negative rather than a refusal (#347). That disagreement is a defect in
its own right and is not resolved here.

The invariant now states the property this ADR establishes, that each namespace has exactly one
writer and is immutable from every other side, rather than asserting that any namespace is
populated. The `relay:` clause lost its "(enrollment-stamped, or `admin` + step-up)"
parenthetical for the same reason: how the Relay writes a `relay:` label is mechanism, and the
second half was unbuilt.

## Amendment (2026-09-16): `tag:` may engage a quarantine, and no Account writes `relay:` directly

Owner decision, 2026-09-16 (#582). Two decisions above are superseded; the rest stand.

- **"`tag:` is never a security-lane target"** is narrowed: engaging a quarantine may target
  `tag:`. Lifting may not, and remediation and secret distribution still target `relay:` only. The
  reasoning and the accepted residual are in ADR-0006's amendment of the same date.
- **"Post-enrollment `relay:` label management exists now … `admin` + step-up"** is superseded
  before it was built. No Account sets or removes a `relay:` label directly. Each `relay:` key is
  defined with the action that writes it, and roles, step-up and audit apply to that action: a
  quarantine is engaged by `operator` or above (machine Accounts allowed, counted against the
  `mutate` blast cap) and lifted only by a human `admin` with step-up. Binding each key to an
  action keeps the namespace legible, where a generic write would make it mean whatever its last
  editor intended. The incident ladder is unchanged: quarantine < revoke < Freeze.

`tag:` storage and its write path are still unbuilt (#430); until they exist, a `tag:` term is
refused at parse on every surface, quarantine included.

## Amendment (2026-09-20): amended by ADR-0034

ADR-0034 added a fourth namespace, `state:` (Relay-derived, written by nobody), beside `node:`,
`relay:` and `tag:`. Wherever this ADR counts three namespaces, read four; the rules for `tag:`
are unchanged.
