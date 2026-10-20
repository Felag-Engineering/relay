# Deferred

Work **agreed in principle and not yet specified.** Each gets an ADR when it is picked up; none
is authorized by appearing here.

This is the one part of the retired `ROADMAP.md` with no other home: milestone status is in
GitHub milestones, behaviour in [`docs/specs/`](specs/), decisions in [`docs/adr/`](adr/), and
what must always be true in the invariants in [`AGENTS.md`](../AGENTS.md). Six entries have no
GitHub issue, and an item agreed in principle but recorded nowhere gets re-decided from scratch.

- **HA / horizontal Relay scaling**: a Node→instance routing registry (ADR-0005 caveat).
  *Build* deferred; the **design spike is required before the v1.0.0 freeze** (#139).
- **Multi-principal RBAC & Grants**: per-Account authorization rules (Operations ×
  Selectors). A Grant only ever narrows what Node Policy allows. A Grant used as a *security
  boundary* must scope by `relay:` labels (ADR-0006). Engine candidate: Cedar (#285), evaluated
  together with the approval-rule grammar so Relay never hand-rolls two policy engines.
  **Direction settled 2026-09-30 in ADR-0041 (Proposed):** Grants are Operation × Selector,
  deny-by-default, picked up with the identity work below after the demo. Stays here until
  that milestone exists.
- **Staged rollout & approval**: a rollout spec on Jobs: canary stage → gate (`all-success`
  or `manual-approval`, reusing the approval mechanism) → remainder, executed and audited as
  one Job. The Job schema's Stages and the approval-requirement schema already anticipate it.
  Write the rollout ADR pre-1.0; execution may land post-1.0.
- **Mutate-lane live streaming**: read-lane streaming is v0.9.0; the mutate lane stays
  deferred (ADR-0004 caveat).
- **Postgres store**: swap in behind the repository interface when HA lands.
- **Graphic System Model view**; **System Model entry locking** (ADR-0008 notes): after
  v1.1.0.
- **Per-Account rate limits**: throttle Job creation per Account, so a runaway AI-agent loop
  is bounded in time as well as blast radius. Scheduling is decided in #279.
- **IdP-federated teams/audiences**: `on_behalf_of` and approval audiences resolved from OIDC
  group claims; Relay never grows a native org chart. **Direction settled 2026-09-30 in
  ADR-0041 (Proposed):** Gleipnir is the directory and Relay pulls a signed copy; teams are
  groupings of principals; the approver's own identity reaches Relay verified. Not started
  before the demo; no milestone yet.
- **Expectations (runtime health only)**: advisory, scheduled *read-class* checks. Findings
  may *propose* a remediation Job routed through the approval mechanism; nothing
  auto-executes (ADR-0008). The scheduler must be able to construct **read-class dispatches
  only, enforced by type**. Fits after v0.9.0 and v1.1.0.
