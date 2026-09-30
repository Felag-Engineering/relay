# Deferred

Work **agreed in principle and not yet specified.** Each gets an ADR when it is picked up; none
is authorized by appearing here.

This list is the one part of the retired `ROADMAP.md` with no other home. Everything else it held
moved: milestone status to GitHub milestones, behaviour to the capability specifications in
[`docs/specs/`](specs/), decisions to [`docs/adr/`](adr/), and what must always be true to the
architecture invariants in [`AGENTS.md`](../AGENTS.md).

Six of the entries below have no GitHub issue. That is why the file exists rather than the list
being dissolved into the tracker — an item agreed in principle and recorded nowhere is an item
that gets re-decided from scratch in six months.

- **HA / horizontal Relay scaling** — Node→instance routing registry (ADR-0005 caveat).
  *Build* deferred; the **design spike is required before the v1.0.0 freeze** (issue
  #139).
- **Multi-principal RBAC & Grants** — per-Account authorization rules (Operations ×
  Selectors); a Grant only ever narrows what Node Policy allows, never widens it. Design
  rule when built: a Grant used as a *security boundary* must scope by `relay:` labels
  (ADR-0006). Engine candidate: Cedar (#285) — evaluated jointly with the approval-rule
  grammar (v0.5.0) so Relay never hand-rolls two policy engines.
  **Direction settled 2026-09-30 in ADR-0041 (Proposed):** Grants are Operation × Selector,
  deny-by-default; picked up with the identity work below, after the demo. Stays here until
  that milestone exists.
- **Staged rollout & approval** — first-class rollout spec on Jobs: canary stage → gate
  (`all-success` or `manual-approval` — the v0.5.0 approval mechanism reused as a rollout
  gate) → remainder, executed and audited as one Job. The Job schema's Stages and the
  approval-requirement schema both already anticipate it. Write the rollout ADR pre-1.0;
  execution may land post-1.0.
- **Mutate-lane live streaming** — read-lane streaming lands in v0.9.0; the mutate lane
  stays deferred (ADR-0004 caveat).
- **Postgres store** — swap behind the repository interface when HA lands.
- **Graphic System Model view**; **System Model entry locking** (ADR-0008 notes) — follow
  v1.1.0.
- **Per-Account rate limits** — throttle Job creation per Account so a runaway AI-agent
  loop is bounded in time as well as blast radius. Decide pull-forward into v0.3.0 via
  #279.
- **IdP-federated teams/audiences** — `on_behalf_of` and approval audiences resolved from
  OIDC group claims (direction named in v0.3.0; Relay never grows a native org chart).
  **Direction settled 2026-09-30 in ADR-0041 (Proposed):** Gleipnir is the directory and Relay
  pulls a signed copy; teams are groupings of principals; the approver's own identity reaches
  Relay verified. Deliberately not started before the demo; no milestone yet.
- **Expectations (runtime health only)** — advisory, scheduled *read-class* checks;
  findings may *propose* a remediation Job routed through the v0.5.0 approval mechanism;
  nothing auto-executes (ADR-0008 stands). The scheduler must be able to construct
  **read-class dispatches only, enforced by type**. Sits naturally after v0.9.0 +
  v1.1.0.
