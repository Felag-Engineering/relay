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
| Enrollment (certless) ↔ CA | The enrolling daemon (no client cert yet) | The Relay's private CA (issuance authority) | Enrollment Token + CSR → signed per-Node client certificate | The Enrollment Token is scoped/expiring/revocable and can only enroll — it is a bearer credential presented by an as-yet-unverified party that *gates who may request issuance*, not a trusted root. `node_id` is Relay-generated at enrollment (`randomNodeID`); the CSR subject is discarded and never trusted, so an enrolling daemon cannot choose or influence its own identity. `relay:` labels are stamped from the token scope and are Node-immutable ([ADR-0006](../adr/0006-node-enrollment-identity-and-label-authority.md), invariant #7). The scope itself is gated to entries rendering as exactly one Selector term — refused at mint and again when an already-stored scope is used to enroll (#555). |

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

**Recorded disposition (v0.0.8):** the forgeability of `node:` labels is **accepted for
launch** by [ADR-0017](../adr/0017-node-origin-label-trust.md), which maps the forge-to-attract
and forge-to-evade attacks to the lanes: both are blocked in the security lane (it targets
`relay:`) and residual only in the routine lane, which is trusted as much as the Node by
design. The pass verified the `relay:` namespace is structurally un-forgeable but the
security lane's *use* of it is convention today; **#243** tracks making that structural when
the security-lane actions are built.

### Stolen API credential

**Assumed capabilities:** A valid API Token, usable at its Account's role.

**Goal:** Run unauthorized Operations, or widen the blast radius beyond what the Account
should be able to reach.

**Primary defense:** The Control API manages runtime objects only; it can never raise its own
blast cap or reach Relay configuration, and every request still passes Selector → Policy →
blast cap regardless of the credential's role
([ADR-0010](../adr/0010-control-api-and-account-model.md), invariant #11).

### Hijacked Console session (from v0.7.0)

**Assumed capabilities:** An authenticated browser session belonging to a human Account —
obtained by session theft, stored XSS in the Console, or a CSRF-forged request from another
origin.

**Goal:** Execute Operations or Raw Exec on the fleet as that human, or elevate by
administering Accounts.

**Primary defense:** No single one — this adversary is defended in depth, deliberately, and
is the reason [ADR-0026](../adr/0026-admin-console-execution-surface.md) supersedes
ADR-0009's stronger "execution is absent from the browser" property. In order: the Console is
internal-only, never internet-facing (ADR-0009); execution is absent entirely when
`console_execution = off`; the capability layer's role gate decides `operator`/`admin`, not
the Console; a `mutate` apply requires **step-up re-authentication**, so a hijacked session
alone is not an applying session; the approval gate can require a second person for
Console-originated mutates (`requester_allowed: false`); and every dispatch still passes
Selector → Policy → blast cap, so the ceiling is what the fleet's own Policy already permits.
CSP and CSRF discipline are load-bearing controls here rather than hygiene — see **R11**.

**From the Plan capability ([ADR-0038](../adr/0038-plan-is-an-approved-route-of-execution.md),
not yet built):** an approved-but-incomplete route is the asset here, because it is standing
authority that outlives the moment it was granted. The only per-advance identity check is that
the caller is the Plan's proposer — which a stolen proposer credential satisfies by definition —
so **an advance re-authenticates nothing**, in deliberate contrast to ADR-0026's Console apply,
which demands step-up re-authentication on every mutate. What bounds it is time and reach rather
than identity: a mandatory window inside ADR-0027's 24-hour ceiling, revocation that closes a
route mid-step, a Freeze that stops the next advance, an approved Node set bound by identity so
the route cannot wander to a host the approver never saw, and every step still meeting that
Node's own Policy. Recorded as the open question in `docs/specs/plan.md` rather than settled.

### Jailbroken AI-agent

**Assumed capabilities:** Full, adversarial control of the orchestrator driving the Relay.

**Goal:** Coerce the fleet into actions outside its intended bounds.

**Primary defense:** The System Model is advisory with AI-immutable grounding facts and never
bypasses Selectors → Policy → blast cap; the AI-agent is just a machine Account and gets
nothing other AI-agents can't have ([ADR-0008](../adr/0008-system-model-git-backed-semantic-graph.md),
invariant #9).

**From the Plan capability ([ADR-0038](../adr/0038-plan-is-an-approved-route-of-execution.md),
not yet built):** a Plan lets one human decision release several dispatches, which is a new lever
here and is deliberately shaped to be a poor one. Relay stores the approved route and the agent
advances a cursor carrying **no description of the work**, so a jailbroken agent cannot reorder,
skip, replay or substitute a step — the obvious attack is structural rather than checked. Relay
authors the step list an approver reads; the agent's diagnosis rides in the **asserted** lane
beside `on_behalf_of`, marked as a claim. The gate is priced at the strictest step, so a route
cannot be made cheap to approve by burying one expensive step among five trivial ones. What
remains is R14.

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
| #1 — Nothing on the wire can compose or escalate a command (three tiers: Native argv, Template author-fixed structure with quoted slots, Raw Exec argv + regex) | [ADR-0001](../adr/0001-structured-operations-with-regex-gated-raw-exec.md) | relay-daemon ↔ Node OS | Jailbroken AI-agent (also Malicious Relay) | Raw Exec safety is only as tight as the operator-authored regex; a loose regex re-opens arbitrary execution, and typed Operations still invoke real binaries whose own arg-parsing bugs are out of scope. **Red-team (v0.0.8) confirmed two concrete deny-evasions on this boundary — register R1 (#227, argv-element merge) and R2 (#236, non-canonical `file.read` path spellings); both are now fixed by canonicalizing before matching ([ADR-0019](../adr/0019-canonical-argv-matching-for-raw-exec-deny.md), [ADR-0018](../adr/0018-canonical-path-matching-for-file-read.md)),** leaving the joined form's argument-boundary lossiness as R10 and the wrapper-interpreter re-dispatch (R4) as operator guidance. |
| #2 — Policy locally-rooted & remotely-immutable | [ADR-0002](../adr/0002-node-side-policy-is-locally-rooted-and-remotely-immutable.md) | Operator ↔ Policy file (primary); Relay ↔ relay-daemon (query-only) | Malicious Relay | A Node's own root can rewrite its local Policy (the Compromised Node case, in-scope by design); Policy is only as strong as authored. |
| #3 — Deny-by-default, deny-beats-allow, arg-level granularity | [ADR-0002](../adr/0002-node-side-policy-is-locally-rooted-and-remotely-immutable.md) | relay-daemon ↔ Node OS | Malicious Relay (also Jailbroken AI-agent) | An over-broad allow rule authored locally still widens what runs; deny-beats-allow only helps where a deny rule exists. **Red-team (v0.0.8) found deny rules evaded with no authoring error:** exact-string `file.read` denies fell to non-canonical path spellings (R2/#236) and Raw Exec per-element denies to argv-element merge (R1/#227). Both are now closed by canonicalizing before matching ([ADR-0018](../adr/0018-canonical-path-matching-for-file-read.md), [ADR-0019](../adr/0019-canonical-argv-matching-for-raw-exec-deny.md)); see the residual-risk register for their narrowed remainders. |
| #4 — At-most-once Task execution (dedup across reconnects) | [ADR-0004](../adr/0004-async-job-execution-model.md) | Relay ↔ relay-daemon | Network attacker | At-most-once is not exactly-once — a dropped Task may run zero times and is not auto-retried; dedup depends on the daemon retaining Task IDs. |
| #5 — Blast-radius cap enforced on the Relay before dispatch | [ADR-0004](../adr/0004-async-job-execution-model.md) | AI-agent ↔ Relay | Jailbroken AI-agent (also Stolen API credential) | The cap is a Relay-side control, so a Malicious Relay is above it (which is why per-Node Policy still enforces); the cap value is operator config. |
| #6 — mTLS everywhere; daemon refuses an untrusted Relay; Node identity = client cert | [ADR-0005](../adr/0005-grpc-bidi-over-mtls-transport.md), [ADR-0006](../adr/0006-node-enrollment-identity-and-label-authority.md) | Relay ↔ relay-daemon | Network attacker (also Malicious Relay) | mTLS authenticates the transport, not intent — an authenticated-but-hostile Relay is still distrusted (invariant #2/#3's job); a CA compromise breaks the trust root (see Enrollment ↔ CA). |
| #7 — Four label namespaces, each with exactly one writer and immutable from every other side | [ADR-0006](../adr/0006-node-enrollment-identity-and-label-authority.md), [ADR-0017](../adr/0017-node-origin-label-trust.md), [ADR-0020](../adr/0020-tag-labels-operator-grouping-namespace.md), [ADR-0034](../adr/0034-state-labels-relay-derived-namespace.md) | Enrollment (certless) ↔ CA; Relay ↔ relay-daemon | Compromised Node | A Compromised Node freely forges its own node: labels, so routine node:-targeting trusts the Node only as much as the Node; the security-sensitive lane must target relay:. Node-origin label trust is accepted for launch (ADR-0017); #243 tracks making the security lane's relay:-targeting structural. |
| #8 — `/proto` is the single source of truth (wire protocol + Operation vocabulary) | [ADR-0007](../adr/0007-polyglot-rust-daemon-go-relay.md) | None as a runtime control — it defines what crosses Relay ↔ relay-daemon | None at runtime | Enforced at build time by CI (proto-check, proto-breaking), not by any runtime boundary; see Findings. |
| #9 — System Model advisory; AI-immutable grounding facts; never desired-state, no auto-reconcile | [ADR-0008](../adr/0008-system-model-git-backed-semantic-graph.md) | AI-agent ↔ Relay | Jailbroken AI-agent | The AI-agent may still create/update Services/Dependencies/Annotations (audited via git provenance); a wrong-but-authorized model can mislead the AI-agent's own reasoning but never bypasses Selectors → Policy → blast cap. |
| #10 — One capability layer; every interface is an adapter over it, narrowing only | [ADR-0009](../adr/0009-admin-console-web-ui.md), [ADR-0010](../adr/0010-control-api-and-account-model.md), [ADR-0026](../adr/0026-admin-console-execution-surface.md) | AI-agent ↔ Relay | Stolen API credential, Hijacked Console session (also Jailbroken AI-agent) | Largely an internal-architecture invariant; its runtime tooth is the single caller ↔ Relay gate — every surface reaches Nodes only through the one capability layer, enforced structurally by the `no_dispatch` guard on each surface package. **Changed by ADR-0026:** the Console's no-execution property was a second runtime tooth and is surrendered when execution lands (v0.7.0, #438 — **not yet built**; the composition root ships it off); step-up on mutate apply is what replaces it. See R11. |
| #11 — Control API manages runtime objects, never Relay configuration; can't raise its own limits | [ADR-0010](../adr/0010-control-api-and-account-model.md) | AI-agent ↔ Relay | Stolen API credential | Relay configuration is a root-owned local file out of the API's reach; a root compromise on the Relay host is above this line (and above the whole control plane). |
| #12 — Policy evaluated only by the daemon's live engine, incl. hypotheticals (PolicyQuery, Policy preflight) | [ADR-0011](../adr/0011-plan-mode-daemon-evaluated-policy-queries.md) | relay-daemon ↔ Node OS (enforcement); Relay ↔ relay-daemon (preflight/PolicyQuery answers) | Malicious Relay | Preflight / PolicyQuery answers are point-in-time and advisory — never a reservation; Policy can change before execution. |
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
caller ↔ Relay boundary, all gated by the one capability layer (invariant #10). *(Written
when the Console added no execution surface. From v0.7.0 it does —
[ADR-0026](../adr/0026-admin-console-execution-surface.md) — so all three crossings now
carry execution and the boundary's defense rests entirely on the capability layer and the
per-surface intent binding, not on one surface being incapable. The "Hijacked Console
session" adversary and R11 carry the delta.)*

**Framing (not a finding):** ADR-0003, ADR-0013, ADR-0015, and ADR-0016 back no numbered
invariant — expected, since they are design decisions rather than load-bearing distrust
invariants.

These findings are folded into the residual-risk register below, created by the closer issue
**#225**.

## Residual-risk register

The v0.0.8 pass produced findings across the Raw Exec red-team (#214, #215, #223), the Policy
loader (#216), wire fuzzing (#217, #218), the privileged-daemon audit (#219, #220, #224), the
secret-handling audit (#222), and the node-origin label-trust decision (#221). Each is
recorded below with its boundary, disposition, rationale/compensating control, and reference.
Dispositions: **fixed** (defect closed, regression-tested), **mitigated** (compensating
control, residual bounded), **accepted** (documented, not eliminated — with a qualifier for
*why*).

| ID | Risk | Boundary | Disposition | Rationale / compensating control | Ref |
| --- | --- | --- | --- | --- | --- |
| **R1** | Anchored per-element Raw Exec **deny** (`^--force$`) evaded by merging the denied token into an adjacent argv element (argv is space-joined for matching). | relay-daemon ↔ Node OS | **Fixed** (narrowed remainder → R10) | Closed by [ADR-0019](../adr/0019-canonical-argv-matching-for-raw-exec-deny.md): the deny pass also runs over the **canonical elements** (`argv.join(" ")` re-split on whitespace), in addition to the joined string and the raw elements, so an element-anchored deny holds against merged, padded and tab/LF/CR/NBSP-separated spellings. Strictly additive — monotonic in the deny direction, no allow is widened; the Deny reason names which form matched. A companion guard refuses Raw Exec whose `argv[0]` is not a single non-empty program token (empty or whitespace-bearing). Standing guidance (gate by a tight anchored *allow-list*, deny lists are a backstop) is unchanged. | #227 → #248; [ADR-0019](../adr/0019-canonical-argv-matching-for-raw-exec-deny.md); `daemon/src/policy.rs` `mod raw_exec_redteam` (Axis 7 rows + `deny_element_merge_closed_by_canonical_elements`, formerly `#[ignore]`d) |
| **R2** | Exact-string `file.read` **deny** (e.g. `/etc/shadow`) evaded by any non-canonical spelling (`/etc/../etc/shadow`, `//etc/shadow`, `/proc/self/root/…`, symlink, case) — no `canonicalize` anywhere in `daemon/src`; the shipped `policy.example.toml` deny does not hold. | relay-daemon ↔ Node OS | **Fixed** (narrow residual: case/Unicode folding mounts) | Closed by [ADR-0018](../adr/0018-canonical-path-matching-for-file-read.md): Policy fail-closes on a non-canonical path *form* (lexical, pure) and the `file.read` executor re-checks the *resolved* target off the open descriptor (closing `/proc`-magic and symlink aliases). The misleading `policy.example.toml` comment was corrected with the fix. Residual: case/Unicode folding on a case-insensitive mount — neither canonical form nor `canonicalize` folds case. | #236 → #247; [ADR-0018](../adr/0018-canonical-path-matching-for-file-read.md); `daemon/src/policy.rs::noncanonical_path_denied_by_canonical_form_precondition`, `operations/file_read.rs` resolved-target tests |
| **R3** | A compromised Node forges its own `node:` labels. | Relay ↔ relay-daemon (routine targeting) | **Accepted — for launch** | The security lane targets the un-forgeable `relay:` namespace; residual is confined to the routine lane (trusted only as much as the Node). Making the security lane's `relay:`-targeting structural is tracked post-beta. A sharper sub-case is now **closed**: a forged `node:` value could render as a CROSS-NAMESPACE (`relay:`-spelled) term in a Console-generated Selector URL (the measured payload was `node:role=web, relay:quarantine=on`) — never a `relay:` write, but a filter link targeting something other than what the operator asked for. `registry.WellFormedLabel`, enforced at the `protoconv.ParseNodeLabel` ingress seam, refuses any `node:` key/value that could render as more than one Selector term. | [ADR-0017](../adr/0017-node-origin-label-trust.md); #243; #504 |
| **R4** | A fully-anchored Raw Exec allow of a wrapper interpreter (`^/usr/bin/env `) still admits re-dispatch (`env bash -c …`). | relay-daemon ↔ Node OS | **Accepted — operator guidance** | Not an engine defect: the operator must anchor the *whole* command for wrapper interpreters. Folded into Raw Exec authoring guidance. | #223 (row R4) |
| **R5** | Raw Exec and package-manager maintainer scripts have unbounded syscall surface under `SystemCallFilter` (a syscall outside `@system-service` is a hard `SIGSYS`). | relay-daemon ↔ Node OS | **Accepted — disclosed** | Static derivation cannot bound an arbitrary-command surface; the `pkg-install` drop-in relaxes the filter for that unit only, strict profile elsewhere. | #219; `docs/operations/daemon-privilege-posture.md` |
| **R6** | Policy loader parent-dir rename-swap not fully closed. | Operator ↔ Policy file | **Mitigated** | Open-once + `fstat`-on-descriptor + `O_NOFOLLOW` + non-regular-file rejection close the symlink/TOCTOU-on-file gap; the residual rename-swap is bounded by a root-owned policy directory. | #216; `daemon/src/policy.rs::load_policy` |
| **R7** | `setrlimit` NPROC bound may interact with process availability on busy nodes. | relay-daemon ↔ Node OS | **Accepted — trade-off** | Deny-closed caps (NPROC/DATA/NOFILE/CPU/FSIZE) + cgroup `TasksMax=4096` bound fork/alloc/fd bombs at the spawn chokepoint; the NPROC value is tunable. | #220; `daemon/src/executor.rs`, `relay-daemon.service:110` |
| **R8** | Verbatim audit-output retention (captured Operation output stored in full) can carry secrets the operator put in output. | AI-agent ↔ Relay (audit) | **Accepted — decision** | A conscious posture: no secret was found leaking through relay/daemon logs (5×3 audit matrix); secrets in *captured output* are the operator's responsibility. | #222; `docs/security/secret-handling-audit.md` |
| **R9** | Invariant #8 (`/proto`) and invariant #13's class-contract half map to no runtime boundary. | (build-time) | **Accepted — disclosed** | Enforced by CI gates (`proto-check`, `proto-breaking`), not a runtime control. Finding 1 above. | §Findings |
| **R10** | The Raw Exec gate matches a **whitespace-joined projection of argv**, which is inherently approximate: a caller can still shift element boundaries in ways that keep the joined string constant (`["systemctl","restart nginx"]`), so the gate cannot see the real argument boundaries below `argv[0]`. | relay-daemon ↔ Node OS | **Accepted — narrowed remainder of R1** | Scope: a **token-form** deny (`^--force$`) now holds against every merge/padding/separator spelling (ADR-0019 canonical elements), and the `argv[0]` guard removes the *which program runs* ambiguity — the part of the projection that touches invariant #1 (defense-in-depth: `argv[0]` goes straight to `Command::new`, so a merged `argv[0]` was already `ENOENT` absent a planted file). What remains is argument-boundary legibility **and** one authoring-dependent case: a deny written as a multi-token whole-command string (`^systemctl restart nginx --force$`) matches only the joined form and stays whitespace-fragile, so a tab-separated argv can miss it while a loose `\s`-based allow still matches — pre-existing, unchanged by ADR-0019, and the same family as the unanchored-allow footgun (R4-class authoring mismatch), not a new evasion class. Mitigation is the shipped guidance: deny **tokens**, anchor whole commands in the **allow**. Fully closing it means rejecting ambiguous argv outright or joining on a separator that cannot appear in an element — both breaking changes to Policy authoring, both declined. v0.8.0's Template Operations are the structural answer. | [ADR-0019](../adr/0019-canonical-argv-matching-for-raw-exec-deny.md) §Residual; #248 |
| **R11** | Browser-borne fleet execution: from v0.7.0 the Admin Console can dispatch Operations and Raw Exec, so session hijack, XSS, or CSRF reaches command execution on every Node the session's role can target. ADR-0009 had **eliminated** this consequence class by making execution absent from the browser; ADR-0026 reverts that to **mitigation**. | AI-agent ↔ Relay (Console crossing) | **Accepted — decision, with a deployment opt-out** | A deliberate trade recorded in [ADR-0026](../adr/0026-admin-console-execution-surface.md), not an oversight. Compensating controls, in depth: internal-only exposure; `console_execution = off` restores ADR-0009's property verbatim (routes unmounted — absent, not forbidden); preflight-by-default; **step-up re-authentication on every mutate apply**, so a stolen session is not an applying session; role gates decided by the capability layer (`operator`+ run, `admin` Raw Exec), never by the Console; the approval gate's `requester_allowed: false` for a second person; Node Policy underneath everything, so the ceiling is what the fleet already permits. **CSP and CSRF discipline are load-bearing security controls on this path, not hygiene** — that is the honest cost of the reversal. Counter-argument for the trade: the Console's step-up apply is the strongest per-action human-intent binding in the system, and the alternative after the CLI cut was pushing humans onto `curl`, which has none. | [ADR-0026](../adr/0026-admin-console-execution-surface.md); #264; `docs/design/approval-and-attribution.md` |
| **R13** | The stored-Label allowlist (`registry.WellFormedLabel`, `[A-Za-z0-9._-]`) is narrower than `capability.ParseSelector`, so the SQLite read-back filter declines to serve some labels that parse and match perfectly well — `relay:tier=pci/1`, `relay:owner=team@sec`, `relay:dc=dc1:rack2`. On upgrade, a Node enrolled under such a scope silently stops carrying that label for every reader, so a **security-lane** Selector resolves to fewer Nodes than before. Nothing is logged at the moment it happens, and there is still no event and no self-heal, but the condition is now reported once at startup and counted on /metrics (#565). | Enrollment (certless) ↔ CA (relay-space targeting) | **Accepted — disclosed, bounded, under-inclusive only** | The gate guards RENDERING, not parsing: a term concatenated back together by a Console href or by an AI-agent is the hazard, so the allowlist must stay narrower than the parser. Bounded in direction — a filter can only REMOVE matches and the Selector grammar has no negation, so this can never make a Selector match a Node it should not. Quarantine specifically cannot be lost: `registry.QuarantineKey`/`QuarantineOn` are `quarantine`/`on`, both inside the allowlist, and `Node.Quarantined()` requires that exact pair. Nothing is deleted or rewritten — "decline to serve, never write" (`store/registry.go`). Pre-existing and undocumented for **node-space** since #504, where it self-heals on the Node's next Hello; #555 extends it to relay-space, which has NO self-heal, which is what makes it worth a register entry. Compensating control is operator-facing: `docs/operations/enrollment.md` tells operators to audit `relay_labels` and re-mint before upgrading. **Detection only, as of #565 — REPAIRS NOTHING.** A one-shot, read-only startup scan (`Store.ScanDeclinedLabels`) logs **up to 50 findings per namespace** — node_id, namespace, handler-quoted key bounded to 128 bytes on a rune boundary, and which part (key/value/both) is malformed — alongside exact `labels_declined_at_scan`/`nodes_affected_at_scan` totals and `truncated=true` when more exist. **It is a sample, not a roster:** on a fleet with one declined pair on each of 500 Nodes, 450 affected Nodes are counted but never named, so past the cap the authoritative enumeration is a direct store query (`docs/operations/enrollment.md`) — an operator who re-mints only the Nodes the log named and treats R13 as discharged would leave the rest silently under-including. `relay_labels_declined_total{namespace=...}` advances on every declined read-back. The dropped VALUE is never logged. The Label is still declined, the under-inclusion residual stands unchanged, and remediation is still operator-facing (`docs/operations/enrollment.md`) — neither signal re-mints a token or re-enrolls a Node. The counter is traffic-driven, so a Relay nobody reads, whose affected Nodes never reconnect, sits flat; the boot scan, not the counter, is where "which Nodes" is answered at all — subject to the cap above, past which the store query is the only complete answer. A further accepted residual: because the counter is per-namespace and live, a reader who can scrape `/metrics` and also call `GET /api/v1/nodes/{id}` can difference the two to learn that a specific Node under-includes — recon on a defensive gap, requiring an existing viewer+ credential, revealing neither key nor value, and unable to lose a quarantine. | #504; #555; #565; `relay/internal/store/registry.go` `wellFormedLabels`; `relay/internal/store/labelscan.go`. Numbered R13, not R12: R12 is claimed by the in-flight token-cascade attribution work (#557), so taking it here would land two rows with one ID. |
| **R12** | The Enrollment-Token cascade is the one revocation path that **proceeds while the audit sink is down**. `POST /api/v1/nodes/{id}/revoke` fails closed (record first, 500, Node not revoked); `DELETE /api/v1/enrollment-tokens/{id}` records per Node, notes any failure, and revokes anyway. So an `admin` who can break the audit store can revoke Nodes leaving only a `slog.Error` and a 500. | AI-agent ↔ Relay (audit) | **Accepted — decision** | Deliberate asymmetry, not an oversight (#557). The two are licensed differently: #487's route may fail closed because *nothing has happened yet* and `RevokeNode` has no error return, whereas mid-cascade the token is already revoked and earlier Nodes already are too. Refusing Node 7 of 20 would leave a Node whose enrolling token is dead still holding a live Tunnel **and** a cert-authenticated `Renew` that reissues its identity — `enroll`'s renew path performs no denylist check of its own, so the interceptor only bites once `RevokeNode` has run. Enforcement never reads the trail: the denylist is rehydrated at startup from the **registry**, so an audit-write failure has zero enforcement consequence. The trade is therefore a recoverable evidence gap against a permanent authentication hole, and the worst case degrades to the pre-#557 status quo plus a 500 naming it. Note a retry cannot backfill the missing rows — the already-revoked skip suppresses them, correctly, to protect the causative-record rule. | #557; #487; `relay/internal/revocation/service.go`, `relay/internal/controlplane/api/tokens.go` |
| **R14** | **Nothing evaluates a Plan as a whole.** Policy decides each step independently on its own Node, and the blast cap is per-dispatch, so a route of individually-legal steps whose *combination* is harmful is refused by nothing in the machine. For a **gated** route the approving human is the only control that sees it whole — and an **ungated** route (no step trips a gate rule) is created approved with no human in the loop at all, so for that case nothing sees it whole. | AI-agent ↔ Relay | **Accepted — inherent to the capability** | Not closable without Relay reasoning about intent, which it deliberately does not do. Bounded instead: the requirement is derived at the **strictest step**, so a route is never cheaper to approve than its worst part; Relay authors the step list, and the agent's rationale is stored in the asserted lane and rendered as a claim, so a compromised agent's lever is argument rather than presentation; the approved Node set is bound **by identity**, so a route can never reach a host the approver did not see and a compromised Node cannot forge its way in (invariant 7); the first cut targets **one Node**, capping reach at a single host — **a control with an expiry date, since the bound is designed to rise**; every step still meets that Node's Policy, so the ceiling stays what the fleet already permits; and an approved route expires on a mandatory window, is revocable mid-route, and stops at the next advance under a Freeze. Anticipatory — the capability is unbuilt. | [ADR-0038](../adr/0038-plan-is-an-approved-route-of-execution.md); `docs/specs/plan.md` |

**Resolved during the pass (no residual):** the Policy loader symlink/TOCTOU-on-file gap (#216, now `O_NOFOLLOW` + fstat-on-fd), unbounded child resources (#220, `setrlimit` at the spawn chokepoint), and the comment-only Rust "never logged" guarantee (#222, now a compile-time `E0119` guard on `EnrollConfig`/`Identity`). Wire fuzzing (#217 Go, #218 Rust) found **no engine bypass and zero crashes**; #218 also strengthened the deny-branch regression net.

## Acceptance (v0.0.8 sign-off)

The milestone's four acceptance criteria, each with its evidence location and honest status.
Sign-off is a **human decision** (this milestone is human-led); two criteria are met only
conditionally and are called out.

1. **Threat-model doc + every invariant mapped to a boundary — MET.** This document: Trust
   boundaries, Adversary catalogue, and the 14-row invariant→boundary map, with Finding 1
   recording invariant #8 as a disclosed build-time exception. The register above completes
   the "Kept current" deliverable.
2. **Raw Exec red-team regression suite, no surviving bypass — MET (unconditionally, as of
   v0.0.9).** The suite exists (`daemon/src/policy.rs` `mod raw_exec_redteam`, rows R1–R18 +
   the Axis 7 canonicalization rows + the `file.read` path-argument table; re-pins in
   `daemon/src/raw_exec.rs`). At v0.0.8 sign-off two `#[ignore]`d tests encoded surviving
   bypasses held open as ADR-gated decisions — #227 and #236. Both were resolved by the
   decision this milestone carried: #236 by [ADR-0018](../adr/0018-canonical-path-matching-for-file-read.md)
   (#247) and #227 by [ADR-0019](../adr/0019-canonical-argv-matching-for-raw-exec-deny.md)
   (#248). Both tests are now enabled and pin their fixes; **no `#[ignore]`d bypass remains**.
3. **Bounded fuzzers in CI, zero known crashes — MET.** Go native fuzz (6 targets incl.
   `FuzzSignCSR` on the certless CSR path) run bounded nightly (`.github/workflows/security-nightly.yml`
   fuzz job; `make fuzz-relay`); Rust `proptest` suites over policy and dispatch
   (`daemon/src/policy.rs`, `daemon/src/dispatch.rs`) under `cargo test`. No crash reproducers
   committed. Coverage-guided `cargo-fuzz` is deferred to #238.
4. **Daemon runs a documented least-privilege profile — applied + documented; live
   verification OUTSTANDING.** The shipped unit carries `SystemCallFilter=@system-service`,
   `SystemCallArchitectures=native`, `MemoryDenyWriteExecute=yes`, `CapabilityBoundingSet=CAP_DAC_READ_SEARCH`,
   and `TasksMax=4096` (`daemon/packaging/relay-daemon.service`); the posture is documented in
   `docs/operations/daemon-privilege-posture.md` (offline `systemd-analyze` exposure 3.7→2.1).
   The profile has **not been exercised on a live systemd host** (the dev fleet is Docker);
   verifying all five Operations plus a permitted Raw Exec under the filter **requires a human
   on real hardware** and is the one outstanding acceptance task (#224).

**Sign-off status: pending human decision.** Two items blocked an unconditional sign-off at
the end of v0.0.8. The first — the disposition of #227 and #236 — is discharged: the human
decision was to **fix both before shipping binaries**, done in v0.0.9 via ADR-0018 (#247) and
ADR-0019 (#248), with the narrowed remainders recorded as R10 and R2's case/Unicode residual.
The live least-privilege verification (#224) remains outstanding; every other criterion is met.

## Scope

This document covers the product bet and kill criterion, the trust boundaries, the adversary
catalogue, and the architecture-invariant → boundary map above. The mapping from every
architecture invariant in `CLAUDE.md` to the boundary it defends now exists in the section
above, produced by issue **#213**. The Ansible-MCP foil demo (issue #140) is out of scope
for this milestone; it is a separate positioning exercise, not part of the threat model.

## Kept current

This is a living document: as the system and its security posture change, this document
should be updated alongside it, not left to drift. The **residual-risk register** and the
**Acceptance (v0.0.8 sign-off)** section above are the record of findings fixed, mitigated,
or accepted at the end of the v0.0.8 milestone (closer issue **#225**), kept current as those
entries are resolved — R1/#227 and R2/#236 have since been fixed (v0.0.9), leaving R10 as R1's
narrowed remainder. Keep it current the same way: when an entry is resolved, or when the live
least-privilege verification (#224) is run, update the entry and the Acceptance status rather
than letting the doc drift from reality.

**R11 and R14 are the anticipatory entries.** Each records a consequence class a decision
introduces, not one that exists in shipped code — the Console execution composer does not exist
yet, and neither does the Plan capability. Both are written down now because the decisions were
taken now ([ADR-0026](../adr/0026-admin-console-execution-surface.md),
[ADR-0038](../adr/0038-plan-is-an-approved-route-of-execution.md)), and a security posture that
is only documented after it ships is documented too late. Revisit each when its capability lands:
the compensating controls they name are commitments to verify, not controls already in place.
