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
  are unchanged; a pointer is added there) and CLAUDE.md invariant #7 in the same
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
- CONTEXT.md's **Label** entry is updated in the same change.
