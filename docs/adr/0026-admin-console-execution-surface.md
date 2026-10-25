# The Admin Console gains an execution surface

**Status:** Accepted (2026-08-03); amended by ADR-0044. Decision 7's second-person option is
superseded by ADR-0047.

ADR-0052 (2026-10-23) supersedes the Console's execution surface for the MVP: the Console runs
no command, and the `console_execution` flag is deleted.

Decision on issue #264, taken by the owner 2026-08-03. It **supersedes the no-execution clause
of [ADR-0009](0009-admin-console-web-ui.md)** and amends AGENTS.md invariant #10. The rest of
ADR-0009 — thin adapter, internal-only exposure, Account auth, Policy read-only — stands.

The Console will expose the same execution surface as the MCP surface and the Control API:
`run_operation`, the Policy preflight, Raw Exec, Job and Task status. Not as a new control path
— through the one capability layer, like everything else (ADR-0003, ADR-0010).

## What ADR-0009 decided, and why reversing it is not a climb-down

ADR-0009's reasoning was sound, and this ADR does not claim it was wrong:

> A browser is the most attackable client in the system; keeping execution out of it
> **eliminates (rather than mitigates)** the "session hijack / XSS / CSRF → fleet-wide
> RCE" consequence class.

That is a real property and we are giving it up. Everything below is mitigation, and mitigation
is weaker than elimination. Two things changed the balance.

**The Console is the trust-building wedge, and the wedge has to be hands-on.** A skeptical
operator does not come to trust a fleet-wide RCE system by reading its documentation. They
trust it by probing the boundary themselves — composing an Operation, seeing the Plan, watching
a Policy rule deny it, reading the rule that fired — and only then handing the same keys to an
AI-agent. ADR-0009 sent that operator to `curl` or a CLI. The CLI was cut (v0.4.0, 2026-08-13)
because the Console covers this surface better, which leaves `curl` as the sanctioned human
execution path for a product whose central claim is that the boundary is legible. **The wall is
the same wall**: an Operation dispatched from the Console traverses Selector → Policy → blast cap
→ audit identically to one from MCP. Refusing to show that wall to a human does not make it
stronger.

**Intent binding runs the other way from what 0009 assumed.** Per
`docs/design/approval-and-attribution.md`, an authenticated session proves a human authorized
the *session*, not that a human intended each *call*. MCP-originated calls are agent-grade
regardless of whose identity authorizes them — they are model-generated, and the session is
steerable by prompt injection in content the model read (#274, #283). The axis for gating is
therefore not human-vs-machine principal but **how strongly the originating surface binds a
human's intent to the individual action**.

By that measure the Console's step-up apply is the **strongest** execution surface, not the
weakest: it is the confirmation ladder's self-confirmation rung fused into the request surface,
carrying a credential the agent session does not hold. ADR-0009 removed the surface with the
best intent binding and kept the ones with the worst. That was the backwards part.

It is also why browser security moves onto the critical path: a forged click would counterfeit
the strongest credential in the model. See "Consequences".

## Decisions

1. **The Console may dispatch, through the capability layer only.** No Console-specific
   dispatch, authz, blast-cap, or audit code exists. Invariant #10's structural guarantee is
   unchanged; only its Console clause changes. The `no_dispatch`-style structural guard
   (`relay/internal/controlplane/api/no_dispatch_test.go`, mirroring the MCP surface's)
   **extends to the Console package**: a Console file that holds a `*capability.Service`, calls
   `capability.New`, or reaches capability's internal dispatch fails the test suite. The guard
   is extended, never dropped — a new execution surface is exactly when the temptation to
   shortcut appears.

2. **Preflight-by-default.** Every execution UI resolves and renders the Policy preflight first
   — fan-out, per-Node Policy verdicts, the rule that would fire — and applying is a separate,
   deliberate act. The preflight is daemon-evaluated (ADR-0011); the Console renders a verdict
   it did not compute.

3. **Step-up re-authentication on every `mutate` apply**, in addition to the existing step-up
   on privilege-granting actions (ADR-0009). This is the intent binding above, and why a
   hijacked session is not equivalent to fleet execution. `read`-class dispatch needs no
   step-up: it is bounded by the read blast cap, audited metadata-only (ADR-0025), and gating it
   would make the plan-first habit expensive enough to route around. Reading is still
   exfiltration (ADR-0021) — the exposure is accepted, not overlooked.

4. **Role gates are unchanged and not re-implemented.** `operator`+ for `run_operation`,
   `admin` for Raw Exec — decided by the capability layer's `RoleGate`, as for MCP and the
   Control API. The Console renders the refusal; it never decides one. A surface that gated Raw
   Exec itself would be a second control path, and the first to be forgotten.

5. **`console_execution = on | off`**, a root-owned Relay configuration setting, **default
   `on`**. Invariant #11 governs it: it lives in the Relay's local configuration, never in the
   Control API, and no Account of any role can turn it on. When `off`, the execution routes are
   **not mounted and the composer is not rendered** — an absent capability, not an RBAC
   refusal, preserving ADR-0009's original property verbatim for deployments that want it. The
   objection becomes a deployment tier rather than an argument.

6. **Browser-borne execution is named in the threat model.** `docs/security/threat-model.md`
   records CSRF and XSS as controls on the fleet-RCE path rather than an admin-abuse path, and
   invariant #10's row loses "the Console's no-execution property" as one of its runtime teeth.
   A load-bearing, undocumented control is the failure this repo's threat model exists to
   prevent.

7. **Strict deployments can require a second person.** v0.5.0's approval gate config
   (root-owned, narrows-only) can match Console-originated mutates and set
   `requester_allowed: false`, so the requester cannot self-confirm. Step-up apply is the
   self-confirmation rung; it does not remove the rung above it.
   *(Amended 2026-10-18 by ADR-0044: the second person decides on the Control API. The Console
   has no approval surface, so a Console-originated request that parks is answered there.)*

## Alternatives considered

- **Keep the no-execution stance; humans use the Control API.** The strongest security posture
  available. Rejected on the wedge argument: after the CLI cut it means `curl` with a bearer
  token — no Plan rendering, no step-up, and worse intent binding than the surface being
  protected. We would defend a property by pushing humans onto a weaker path.

- **Execution in a separate binary or origin**, so an XSS in the monitoring UI cannot reach
  execution. Genuinely stronger; rejected for the same-origin ergonomics that make the composer
  useful (a Node view's "run here" affordance is the point) and because two deployables double
  the exposure surface an operator must get right. `console_execution = off` plus a separate
  read-only Console deployment reaches a similar place for those who want it.

- **RBAC restriction instead of a config flag.** Reserve execution to `admin` and skip the
  flag. Rejected: the routes stay mounted, so the consequence class survives any
  role-assignment mistake or account compromise. ADR-0009's insight was that *absent* beats
  *forbidden*, and the flag preserves it.

- **Default `console_execution = off`.** The more conservative default: the safe posture would
  be the one you get by not deciding. Rejected by the owner because a Console that ships inert
  teaches operators the feature does not exist, and the wedge only works if the first operator
  to open the Console can use it. A real trade-off — a deployment profile that flips the
  default for regulated installs is a reasonable future revision.

## Consequences

- **The browser-borne fleet-RCE consequence class returns**, mitigated rather than eliminated.
  Session hijack, XSS and CSRF are now on the path to command execution on every Node the
  session's role can reach. The mitigations are stacked and each is load-bearing:
  internal-only exposure, preflight-by-default, step-up on apply, role gates, Node Policy
  underneath everything, and `console_execution = off` for deployments that decline the trade.

- **CSP and CSRF discipline become security controls with a fleet blast radius.** They were
  already required from v0.6.0's login (ADR-0009); what changes is the severity of getting them
  wrong. Console work carries a high review bar, and lands in front of a human.

- **A hijacked session still cannot exceed Policy.** The daemon enforces locally and the Relay
  cannot modify Policy over the wire (ADR-0002). The ceiling on browser-borne compromise is what
  the fleet's own Policy permits — the ceiling the AI-agent has had since v0.0.6.

- **Audit attribution is unchanged in shape** but gains a new principal class: human-originated
  dispatches carrying the verified lane end-to-end (login → apply → audit record), alongside the
  step-up event.

- **v0.7.0 absorbs the work**; v0.6.0 (monitoring) is unaffected and ships with zero mutating
  routes. `docs/design/console-backend-coverage.md`'s sequencing holds: Accounts → Approval
  Callout → monitoring → admin → execution composer, so the composer is deliberately last,
  behind the step-up and approval machinery it depends on.

## Amendment (2026-09-10): invariant 10 restated — the Console clause made conditional

This ADR's decision is unchanged. What changed is how AGENTS.md invariant 10 summarises it.

The invariant read "The Console **does** execute (v0.7.0)" — present tense, for a surface this
ADR authorised but which is not built. The composition root hardcodes execution off, no config
key turns it on, and `/console/run` renders a placeholder; #438 is the build. An agent reading
the invariant as fact would conclude the surface existed and needed only enabling, and a
reviewer would accept execution wiring no acceptance criterion here has been met for.

The clause could not be deleted: it corrects ADR-0009's no-execution scope, and removing it
would reopen the assumption that the Console is read-only by design. It is now conditional —
"where it executes, it does so preflight-by-default…" — which states this ADR's constraints
without asserting the surface has shipped, and stays true when #438 lands.

The same edit dropped the surface headcount. The invariant opened "One capability layer, three
thin surfaces"; three was a snapshot, not a decision — the capability layer's own documentation
anticipates "any future CLI", and ADR-0030 discusses the CLI that was built and then cut. The
invariant now states the property: ports and adapters, the capability layer as the single
implementation, each interface an adapter over it.

The first draft said the adapters "all expose the same controls", which was wrong in a telling
direction: it reads as a parity mandate, and this ADR is the counter-example. Console execution
is gated behind a root-owned flag precisely so that surface *can* offer less than the layer
allows, and `approve_request` registers only when a decider is configured (ADR-0029). An adapter
**narrows only** — it may offer less, and may never widen, reimplement, or decide. Which surface
exposes what belongs in the capability specifications, not the invariant. GLOSSARY.md's
**Capability layer** entry carries the matching vocabulary.

## Amendment (2026-09-20): terminology for ADR-0038

ADR-0038 gave **Plan** to the approved route of execution and renamed the no-execution preview
**Policy preflight**. This ADR's decision 2 and its references to "plan mode" /
"plan-by-default" were reworded in place to *preflight*; nothing in the decision changed.
Invariant 10's clause reads "preflight-by-default" (amended 2026-09-20). The Console's
user-facing word is **Preflight** (#575, owner decision 2026-09-20).

## Amendment (2026-10-18): amended by ADR-0044 — the Console decides no approval

[ADR-0044](0044-the-console-does-not-decide-approvals.md) removes the Console's approval surface
and keeps the Control API decision endpoint. This ADR's execution surface is unchanged; what
moves is decision 7. A rule demanding a second person for a Console-originated mutate works as
before, and that second person now decides on the Control API rather than in the Console. The
Console's step-up is taken for a mutate apply and the privilege-granting Account acts, no longer
for an approval decision. The Consequences' build-order line naming "Approval Callout" as a
dependency of the composer refers to the approval *backend*, which stays.
