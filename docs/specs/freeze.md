# Freeze

**Status:** aspirational — confirmed with the owner on `2026-09-14` as matching intent; the first
pass is what is built today.

## Purpose

Freeze is the stop button. Engaged, the Relay refuses to dispatch anything new to the fleet —
every risk class, every caller, regardless of authorization, Policy or blast cap.

It exists for one situation: *"I don't trust what is driving this."* Every other control answers
a question about the request — is this caller allowed, is this Operation permitted, is this too
many Nodes. Freeze answers a question about the *driver*, and needs no theory about which
request is the bad one.

So it covers reads as well as mutations: an untrusted driver exfiltrating through `file.read` is
the same problem as one restarting services.

## Surfaces

| Surface | How it is reached |
|---|---|
| **Control API** | `POST /api/v1/freeze/engage`, `POST /api/v1/freeze/release` |
| **Relay host** | `SIGUSR1` engages, `SIGUSR2` releases — the local lever, see below |
| **Admin Console** | Not offered; engaging from the Console is future work (see *Future work*) |

The host-side lever is **unreachable from any surface, by construction**: the Control API holds an
interface carrying only the gated pair, so no route can reach the local path even by accident.
The two are different roots of authority, and the difference is visible at the call site.

## Behaviour

### What a Freeze stops, and what it does not

**Stops:** all new Task dispatch, every risk class. A frozen Relay refuses before Selector
resolution and before authorization — the outermost gate in the pipeline.

That includes a dispatch whose approval was given before the Freeze, and every step of a
harness's sequence: each is new dispatch and meets the same outermost gate. "A human already
approved this" is a statement about authorization, and a Freeze is not an authorization check.

**Does not stop:**

- **Policy preflights.** Observation is what an incident needs, so a preflight answers while
  frozen and reports the frozen state advisorily (ADR-0011, ADR-0013). This is the only
  exemption: a preflight sends no Task.
- **In-flight Tasks.** They keep running unless separately cancelled. Indiscriminately killing
  half-finished package installs creates the second incident.
- **Reads of the control plane.** The registry, the audit trail and the pending approval requests
  stay readable; an incident is when you most need to look.

A Freeze is not a Policy change, not a revocation, and not a cancellation. It is a valve on
dispatch, and it converts no state.

### Asymmetric activation — engage cheap, release deliberate

Deliberately a fire alarm: anyone may pull the handle, the chief clears re-entry.

| | Over the Control API | On the host |
|---|---|---|
| **Engage** | `operator`+ **and a human Account** | `SIGUSR1`, no reason required |
| **Release** | `admin`, with an audited reason | `SIGUSR2`, with a reason |

What is load-bearing in that table:

**Engaging over the API requires a human Account** (ADR-0013, amended 2026-08-24). "Anyone may
pull the handle" is an argument about people. A machine Account — an AI-agent — halting the fleet
is a jailbroken driver switching off its own overseers: a denial of service. Automation that
genuinely needs to stop dispatch uses the host lever, whose authority is root on the box rather
than a stealable credential.

**Release is not human-only.** An incident must have an automated way back.

**The host lever exists because the distrusted thing may be the API credential itself.** Root on
the box must then suffice, so the local path bypasses the role gate. It is a *different*
authority, not a backdoor.

**A release always carries a reason**, on both paths, because "why did the fleet start moving
again" is the question an incident review asks.

### Failing closed

**A failed read of the Freeze state refuses dispatch.** An unreadable stop button is treated as
engaged, even at the cost of availability during a store blip.

The Freeze **survives a Relay restart**; otherwise the crash it was engaged for could release it.

### An accepted information disclosure

Because the Freeze gate runs before authorization, a caller not authorized for the Operation
still learns the Relay is frozen. Accepted: every caller reaching that path is already
authenticated, and reordering the two refusals would cost registry-resolution work for no
security return.

### Auditing

Every engage and release is audited with the Account that did it, or `local-host` for the signal
path. A refused engage or release is audited too, as interesting as a successful one, and leaves
the Freeze state untouched.

## Refusals

| Refusal | Cause |
|---|---|
| Not authorized to engage | Below `operator`, or a machine Account over the API |
| Not authorized to release | Below `admin` over the API |
| Reason required | A release with no reason, on either path |
| Frozen | Any new dispatch while engaged — the refusal the capability exists to produce |
| Internal | The Freeze state could not be read; dispatch refuses, failing closed |

## Governing ADRs and invariants

- **ADR-0013** — cancellation and emergency Freeze: what it halts, the asymmetry, and the
  deliberate exemption of Policy preflights.
- **ADR-0011** — preflights answer while frozen, which is a decision about Freeze as much as
  about the preflight.
- **ADR-0049** — every step of a Gleipnir Plan is new dispatch, so the Freeze stops it; the
  exemption covers preflights and stops at them.
- **Invariant 5** — Freeze is not the blast cap and does not substitute for it; it sits outside
  and above.
- **Invariant 10** — the decision is the capability layer's. A surface engages and renders; the
  local lever is a second root of authority, not a second implementation.
- **Invariant 11** — the host lever's authority is root on the box, which is the same authority
  root as Relay configuration and Node Policy.

## Seams and proof

The Freeze lives behind a small store seam — read, engage, release — with a default of "never
frozen" for composition roots that wire no real store. **That default is a missing stop button**,
so the composition root's fail-open guard requires a real Freeze store alongside a real
dispatcher: an unstoppable real executor is the same class of wiring bug as an unauthorized one.

### What proves each claim

| Behaviour | Proven by | Seam |
|---|---|---|
| A frozen Relay refuses dispatch | `TestRunRefusedWhenFrozen` | capability |
| An unfrozen Relay is unaffected | `TestRunNotFrozenProceedsNormally` | capability |
| **A failed Freeze read refuses, failing closed** | `TestRunFreezeReadErrorFailsClosed` | capability |
| The Freeze gate precedes even an approval park | `TestFrozenRelayNeverEvenParks` | capability |
| A Freeze survives a Relay restart | `TestFreezeSurvivesRestart` | capability |
| Engage and release persist and audit | `TestEngageFreezePersistsAndAudits`, `TestReleaseFreezePersistsAndAudits` | capability |
| Engage consults the control authorizer | `TestEngageFreeze_ConsultsTheControlAuthorizer` | capability |
| Engaging over the Control API requires a human Account, at any role | `TestAuthorizeControl_FreezeEngageIsHumanOnly`, `TestFreezeEngage_RequiresHumanOperator` | capability, API |
| A refused engage or release changes nothing and is still audited | `TestEngageFreeze_RefusedIsNotEngagedAndIsAudited`, `TestReleaseFreeze_RefusedIsNotReleasedAndIsAudited` | capability |
| A release requires a reason — including on the local lever | `TestReleaseFreeze_RequiresAReason`, `TestReleaseFreezeLocal_StillRequiresAReason` | capability |
| The local lever bypasses the role gate deliberately | `TestFreezeLocalLever_BypassesTheRoleGate` | capability |
| Preflights answer while frozen, while real runs refuse | `TestPlanFrozenReportsAdvisoryWhileRunRefuses` | capability |
| Freeze engage/release works end to end over the API | `TestControlAPI_FreezeEngageRelease` | e2e |
| Freeze state carries no database import into the state package | `.golangci.yml` depguard rule `domain-no-sql` | lint |

Claims above with **no row**, and so nothing checking them:

- That in-flight Tasks keep running through a Freeze. Stated by ADR-0013 and true by construction
  — the gate is on new dispatch only — but not asserted.
- That the host lever is unreachable from any surface. True by the interface the API holds, and
  argued at the call site, but there is no structural test like `no_dispatch`.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Freeze check | One store read per dispatch attempt, outermost in the pipeline | *(none)* |
| Engage latency | Takes effect for the next dispatch attempt; nothing in flight is revisited | *(none)* |

There are no benchmarks in this repository. The Freeze read is on the path of **every** dispatch,
including a 10,000-Node read, making it the most frequently executed guardrail; nothing measures
it.

## Out of scope

- **Job and Task cancellation** — `execution.md`. ADR-0013 siblings, not the same mechanism: a
  Freeze stops what has not started; a cancel acts on one Job that has.
- **Revocation** — the other rung of the incident ladder, identity-shaped rather than
  dispatch-shaped: `enrollment.md`. Quarantine is cut from the MVP (roadmap: relay/quarantine).
- **Policy** — a Node refusing work locally is not a Freeze, and a Freeze is not a Policy change.
- **Per-Account rate limits** — a decision still open, and a different control: rate limiting
  shapes normal traffic, Freeze stops abnormal traffic entirely.

## Future work

Future work is in the private roadmap: roadmap: relay/research/spec-future-work/freeze.

## Open questions

- **The local lever is a signal, a thin interface for an audited act.** `SIGUSR2` carries its
  reason through a side channel (`RELAY_FREEZE_RELEASE_REASON`, with a default) rather than in
  the signal itself. It works, and would look obvious in a post-incident review if the reason
  went missing.
