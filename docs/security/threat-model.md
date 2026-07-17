# Relay threat model

Relay is remote code execution as a service, driven autonomously by an AI-agent across a
fleet of Nodes — this document frames the adversaries and trust boundaries an adversarial
security pass must hold against before it runs on real machines.

## Product bet and kill criterion

Relay's bet is that large fleets will let an AI-agent operate them autonomously only if the
control plane is built for **structural distrust**: every layer assumes the layer above it
may be compromised, jailbroken, or simply wrong, and enforces its own limits regardless. This
is why Operations are typed and native rather than shell strings, why Policy is enforced
locally on the Node and only ever queried (never set) by the Relay, and why a blast-radius
cap sits between any single decision and the whole fleet. Distrust architecture is not a
compliance checkbox layered on afterward — it is the enabling condition for the autonomy the
product is betting on.

That bet has a falsification condition. If it turns out customers operating fleets at scale
are satisfied with weaker guarantees, Relay's reason to exist goes away:

> Relay exists for autonomous AI operation of large fleets under structural distrust. If
> customers at that scale are content with prompt-level guardrails over SSH, Relay has no
> market.

Everything below exists in service of that bet: the trust boundaries are where the
architecture asserts distrust, and the adversary catalogue is who that distrust is defending
against.

## Trust boundaries

The request path for any action is AI-agent → Relay → relay-daemon → Node OS, with a
separate, out-of-band path for Policy (operator → Node) and a certless bootstrap path for a
new Node's identity (relay-daemon → CA). Each boundary below is a point where one side must
not be able to compel the other beyond what the architecture allows it.

| Boundary | Untrusted side | Trusted side | What crosses | Primary control at the boundary |
| --- | --- | --- | --- | --- |
| AI-agent ↔ Relay | AI-agent (authenticates as a machine Account) | Relay | MCP tool calls / Control API requests | Relay-side authorization (deny-by-default) plus Selectors → Policy → blast cap; the Control API can never reach Relay configuration ([ADR-0010](../adr/0010-control-api-and-account-model.md), invariant #11). |
| Relay ↔ relay-daemon | The network, and any peer that fails cert verification | Relay and relay-daemon mutually, once mTLS-verified | Tasks, results, PolicySnapshots, Facts | mTLS everywhere; the daemon refuses an untrusted Relay; Node identity is its client cert ([ADR-0005](../adr/0005-grpc-bidi-over-mtls-transport.md), [ADR-0006](../adr/0006-node-enrollment-identity-and-label-authority.md), invariant #6). mTLS authenticates the transport but does not make an authenticated Relay authoritative over the daemon — the Node still distrusts the Relay's intent by design (see row 4 and the Malicious Relay adversary below). |
| relay-daemon ↔ Node OS | The incoming Task | The local Policy engine | argv exec (never `/bin/sh`); Raw Exec regex-gated | Typed native Operations plus regex-gated Raw Exec, deny-by-default Policy ([ADR-0001](../adr/0001-structured-operations-with-regex-gated-raw-exec.md), [ADR-0002](../adr/0002-node-side-policy-is-locally-rooted-and-remotely-immutable.md), invariants #1, #3). |
| Operator ↔ Policy file | Anything over the wire | The local Policy file/owner | Nothing writable — the Relay may only *query* Policy (fingerprint/snapshot) | Policy is locally-rooted and remotely-immutable; the Relay only reads it, never writes it ([ADR-0002](../adr/0002-node-side-policy-is-locally-rooted-and-remotely-immutable.md), invariant #2). |
| Enrollment (certless) ↔ CA | The enrolling daemon (no client cert yet) | The Relay's private CA (issuance authority) | Enrollment Token + CSR → signed per-Node client certificate | The Enrollment Token is scoped/expiring/revocable and can only enroll — it is a bearer credential presented by an as-yet-unverified party that *gates who may request issuance*, not a trusted root. `node_id` is Relay-generated at enrollment (`randomNodeID`); the CSR subject is discarded and never trusted, so an enrolling daemon cannot choose or influence its own identity. `relay:` labels are stamped from the token scope and are Node-immutable ([ADR-0006](../adr/0006-node-enrollment-identity-and-label-authority.md), invariant #7). |

## Adversary catalogue

### Compromised Node

**Assumed capabilities:** Full control of one Node and its relay-daemon process. Can forge
its own `node:` labels and lie in the Facts it self-reports.

**Goal:** Escalate to other Nodes, or forge trust it does not have (e.g. attract Selectors or
Operations meant for a different Node or trust domain).

**Primary defense:** The daemon enforces Policy locally and deny-by-default regardless of
what the Relay asks for, and a compromised Node can never forge `relay:` labels — the
security-sensitive lane it would need to attract into or evade is Relay-set and Node-immutable
([ADR-0002](../adr/0002-node-side-policy-is-locally-rooted-and-remotely-immutable.md),
[ADR-0006](../adr/0006-node-enrollment-identity-and-label-authority.md), invariants #3, #7).

### Stolen API credential

**Assumed capabilities:** A valid API Token, usable at its Account's role.

**Goal:** Run unauthorized Operations, or widen the blast radius beyond what the Account
should be able to reach.

**Primary defense:** The Control API manages runtime objects only; it can never raise its own
blast cap or reach Relay configuration, and every request still passes Selector → Policy →
blast cap regardless of the credential's role
([ADR-0010](../adr/0010-control-api-and-account-model.md), invariant #11).

### Jailbroken AI-agent

**Assumed capabilities:** Full, adversarial control of the orchestrator driving the Relay.

**Goal:** Coerce the fleet into actions outside its intended bounds.

**Primary defense:** The System Model is advisory with AI-immutable grounding facts and never
bypasses Selectors → Policy → blast cap; the AI-agent is just a machine Account and gets
nothing other AI-agents can't have ([ADR-0008](../adr/0008-system-model-git-backed-semantic-graph.md),
invariant #9).

### Malicious Relay

**Assumed capabilities:** A compromised or hostile central Relay.

**Goal:** Push forbidden actions to Nodes, or mutate a Node's Policy to weaken its defenses.

**Primary defense:** Policy is locally-rooted and remotely-immutable — the Relay may only
*query* it, never write it over the wire — and the daemon still enforces deny-by-default
regardless of what the Relay sends; mTLS is mutual, so the daemon refuses an untrusted Relay
(it verifies the Relay's cert) while the Node's own identity is its client cert — a Node
cannot be tricked into obeying an imposter Relay
([ADR-0002](../adr/0002-node-side-policy-is-locally-rooted-and-remotely-immutable.md),
[ADR-0005](../adr/0005-grpc-bidi-over-mtls-transport.md)/[ADR-0006](../adr/0006-node-enrollment-identity-and-label-authority.md),
invariants #2, #6).

### Network attacker

**Assumed capabilities:** Full network position — can intercept, inject, or replay traffic.

**Goal:** Impersonate the Relay or a Node, or inject Tasks that were never issued.

**Primary defense:** mTLS everywhere; the daemon refuses an untrusted Relay and Node identity
is its client cert; at-most-once Task dedup blunts replay of a captured Task
([ADR-0005](../adr/0005-grpc-bidi-over-mtls-transport.md),
[ADR-0006](../adr/0006-node-enrollment-identity-and-label-authority.md),
[ADR-0004](../adr/0004-async-job-execution-model.md), invariants #6, #4).

## Architecture invariants → boundaries

The table below maps each of the fourteen architecture invariants declared in `CLAUDE.md` to
the ADR(s) that back it, the trust boundary (or boundaries) it defends, the adversary it
primarily counters, and its residual risk.

| Invariant | ADR(s) | Boundary defended | Primary adversary | Residual risk |
| --- | --- | --- | --- | --- |
| #1 — Typed argv Operations, regex-gated Raw Exec | [ADR-0001](../adr/0001-structured-operations-with-regex-gated-raw-exec.md) | relay-daemon ↔ Node OS | Jailbroken AI-agent (also Malicious Relay) | Raw Exec safety is only as tight as the operator-authored regex; a loose regex re-opens arbitrary execution, and typed Operations still invoke real binaries whose own arg-parsing bugs are out of scope. |
| #2 — Policy locally-rooted & remotely-immutable | [ADR-0002](../adr/0002-node-side-policy-is-locally-rooted-and-remotely-immutable.md) | Operator ↔ Policy file (primary); Relay ↔ relay-daemon (query-only) | Malicious Relay | A Node's own root can rewrite its local Policy (the Compromised Node case, in-scope by design); Policy is only as strong as authored. |
| #3 — Deny-by-default, deny-beats-allow, arg-level granularity | [ADR-0002](../adr/0002-node-side-policy-is-locally-rooted-and-remotely-immutable.md) | relay-daemon ↔ Node OS | Malicious Relay (also Jailbroken AI-agent) | An over-broad allow rule authored locally still widens what runs; deny-beats-allow only helps where a deny rule exists. |
| #4 — At-most-once Task execution (dedup across reconnects) | [ADR-0004](../adr/0004-async-job-execution-model.md) | Relay ↔ relay-daemon | Network attacker | At-most-once is not exactly-once — a dropped Task may run zero times and is not auto-retried; dedup depends on the daemon retaining Task IDs. |
| #5 — Blast-radius cap enforced on the Relay before dispatch | [ADR-0004](../adr/0004-async-job-execution-model.md) | AI-agent ↔ Relay | Jailbroken AI-agent (also Stolen API credential) | The cap is a Relay-side control, so a Malicious Relay is above it (which is why per-Node Policy still enforces); the cap value is operator config. |
| #6 — mTLS everywhere; daemon refuses an untrusted Relay; Node identity = client cert | [ADR-0005](../adr/0005-grpc-bidi-over-mtls-transport.md), [ADR-0006](../adr/0006-node-enrollment-identity-and-label-authority.md) | Relay ↔ relay-daemon | Network attacker (also Malicious Relay) | mTLS authenticates the transport, not intent — an authenticated-but-hostile Relay is still distrusted (invariant #2/#3's job); a CA compromise breaks the trust root (see Enrollment ↔ CA). |
| #7 — Two label namespaces (node:/relay:), each immutable from the other side | [ADR-0006](../adr/0006-node-enrollment-identity-and-label-authority.md) | Enrollment (certless) ↔ CA; Relay ↔ relay-daemon | Compromised Node | A Compromised Node freely forges its own node: labels, so routine node:-targeting trusts the Node only as much as the Node; the security-sensitive lane must target relay:. |
| #8 — `/proto` is the single source of truth (wire protocol + Operation vocabulary) | [ADR-0007](../adr/0007-polyglot-rust-daemon-go-relay.md) | None as a runtime control — it defines what crosses Relay ↔ relay-daemon | None at runtime | Enforced at build time by CI (proto-check, proto-breaking), not by any runtime boundary; see Findings. |
| #9 — System Model advisory; AI-immutable grounding facts; never desired-state, no auto-reconcile | [ADR-0008](../adr/0008-system-model-git-backed-semantic-graph.md) | AI-agent ↔ Relay | Jailbroken AI-agent | The AI-agent may still create/update Services/Dependencies/Annotations (audited via git provenance); a wrong-but-authorized model can mislead the AI-agent's own reasoning but never bypasses Selectors → Policy → blast cap. |
| #10 — One capability layer, three thin surfaces; Console has no execution surface | [ADR-0009](../adr/0009-admin-console-web-ui.md), [ADR-0010](../adr/0010-control-api-and-account-model.md) | AI-agent ↔ Relay | Stolen API credential (also Jailbroken AI-agent) | Largely an internal-architecture invariant; its runtime teeth are the single AI-agent ↔ Relay gate and the Console's no-execution property. |
| #11 — Control API manages runtime objects, never Relay configuration; can't raise its own limits | [ADR-0010](../adr/0010-control-api-and-account-model.md) | AI-agent ↔ Relay | Stolen API credential | Relay configuration is a root-owned local file out of the API's reach; a root compromise on the Relay host is above this line (and above the whole control plane). |
| #12 — Policy evaluated only by the daemon's live engine, incl. hypotheticals (PolicyQuery, plan mode) | [ADR-0011](../adr/0011-plan-mode-daemon-evaluated-policy-queries.md) | relay-daemon ↔ Node OS (enforcement); Relay ↔ relay-daemon (plan/PolicyQuery answers) | Malicious Relay | Plan / PolicyQuery answers are point-in-time and advisory — never a reservation; Policy can change before execution. |
| #13 — Every Operation declares a risk class (read/mutate); blast caps by class; Raw Exec takes the mutate-cap; class is `/proto` contract | [ADR-0012](../adr/0012-operation-risk-classes-and-split-blast-cap.md) | AI-agent ↔ Relay | Jailbroken AI-agent (also Stolen API credential) | The class lives in `/proto` (shares invariant #8's build-time contract-integrity property); a misclassified Operation would mis-cap — guarded by `/proto` review, not a runtime boundary. |
| #14 — Daemon never self-upgrades; Relay never pushes binaries; upgrades via config management; dispatch-level min-version gate | [ADR-0014](../adr/0014-daemon-lifecycle-iac-upgrades-version-gate.md) | Relay ↔ relay-daemon | Malicious Relay | Daemon version currency depends on the customer's config-management discipline; the min-version gate can refuse dispatch but cannot force an upgrade, and a compromised config-management pipeline is upstream / out of scope. |

### Findings

**Finding 1 — unmapped invariant:** invariant #8 (`/proto` single source of truth) maps to no
runtime trust boundary. It is a build-time / contract-integrity invariant enforced by CI gates
(`proto-check`, `proto-breaking`), not by any point in the AI-agent → Relay → relay-daemon →
Node OS request path — it underpins what crosses Relay ↔ relay-daemon rather than acting at
it. This is not a defect; it is disclosed here so the milestone's "every invariant maps to a
boundary" line has an honest, recorded exception. Invariant #13's risk-class-contract half
shares this same build-time property.

**Finding 2 — boundary coverage:** all five trust boundaries are defended by at least one
invariant — there is no undefended boundary. AI-agent ↔ Relay: #5, #9, #10, #11, #13; Relay ↔
relay-daemon: #2, #4, #6, #7, #12, #14; relay-daemon ↔ Node OS: #1, #3, #12; Operator ↔ Policy
file: #2; Enrollment (certless) ↔ CA: #7.

**Observation (not a finding):** the Trust boundaries table names AI-agent ↔ Relay by the
AI-agent surface; the Control API and Admin Console are additional crossings of the same
caller ↔ Relay boundary, all gated by the one capability layer (invariant #10), and the
Console adds no execution surface.

**Framing (not a finding):** ADR-0003, ADR-0013, ADR-0015, and ADR-0016 back no numbered
invariant — expected, since they are design decisions rather than load-bearing distrust
invariants.

These findings are recorded for the residual-risk register created by the closer issue
**#225** (consistent with the "Kept current" section below); this document does not create
that register.

## Scope

This document covers the product bet and kill criterion, the trust boundaries, the adversary
catalogue, and the architecture-invariant → boundary map above. The mapping from every
architecture invariant in `CLAUDE.md` to the boundary it defends now exists in the section
above, produced by issue **#213**. The Ansible-MCP foil demo (issue #140) is out of scope
for this milestone; it is a separate positioning exercise, not part of the threat model.

## Kept current

This is a living document: as the system and its security posture change, this document
should be updated alongside it, not left to drift. The residual-risk register — the record of
findings accepted, mitigated, or still open at the end of the v0.0.8 milestone — does not
exist yet; it is created by the closer issue **#225**, which will link back here.
