# Freeze

**Status:** aspirational — confirmed with the owner on `2026-09-14` as matching intent; the first
pass is what is built today.

## Purpose

Freeze is the stop button. Engaged, the Relay refuses to dispatch anything new to the fleet —
every risk class, every caller, regardless of authorization, Policy or blast cap.

It exists for one situation: *"I don't trust what is driving this."* Every other control in Relay
answers a question about the request — is this caller allowed, is this Operation permitted, is
this too many Nodes. Freeze answers a question about the *driver*, and it is the only control
that needs no theory about which request is the bad one.

That is why it covers reads as well as mutations. An untrusted driver exfiltrating through
`file.read` is the same problem as one restarting services, and a stop button that only stopped
half the traffic would be the wrong shape.

## Surfaces

| Surface | How it is reached |
|---|---|
| **Control API** | `POST /api/v1/freeze/engage`, `POST /api/v1/freeze/release` |
| **Relay host** | `SIGUSR1` engages, `SIGUSR2` releases — the local lever, see below |
| **Admin Console** | Future work (#457) — not in the first pass |

The host-side lever is **unreachable from any surface, by construction**: the Control API holds an
interface carrying only the gated pair, so no route can reach the local path even by accident.
The two are different roots of authority and that difference is visible at the call site rather
than hidden behind a Principal the role gate happens to wave through.

## Behaviour

### What a Freeze stops, and what it does not

**Stops:** all new Task dispatch, every risk class. A frozen Relay refuses before Selector
resolution and before authorization — the outermost gate in the pipeline.

That includes **every advance of an approved Plan.** An advance is new dispatch, so it meets the
same outermost gate with no special rule, and a Plan approved before the Freeze is not a way past
one (`plan.md`, ADR-0038). The intuition worth naming, because it is the one that would build a
bypass: "a human already approved this" is a statement about authorization, and a Freeze is not an
authorization check.

**Does not stop:**

- **Policy preflights.** Observation is exactly what is wanted during an incident, so a preflight
  answers while frozen and reports the frozen state advisorily (ADR-0011, ADR-0013). This is the
  exemption, and it is the only one: a preflight sends no Task.
- **In-flight steps of an approved Plan.** The step already dispatched keeps running, on the same
  reasoning as any in-flight Task below. **Advancing** that Plan does not — see *Stops*.
- **In-flight Tasks.** They keep running unless separately cancelled. Indiscriminately killing
  half-finished package installs creates the second incident.
- **Reads of the control plane.** The registry, the audit trail and the approval queue stay
  readable; an incident is when you most need to look.

A Freeze is not a Policy change, not a revocation, and not a cancellation. It is a valve on
dispatch, and it converts no state.

### Asymmetric activation — engage cheap, release deliberate

Deliberately a fire alarm: anyone may pull the handle, the chief clears re-entry.

| | Over the Control API | On the host |
|---|---|---|
| **Engage** | `operator`+ **and a human Account** | `SIGUSR1`, no reason required |
| **Release** | `admin`, with an audited reason | `SIGUSR2`, with a reason |

Three things about that table are load-bearing:

**Engaging over the API requires a human Account** (amended 2026-08-24). "Anyone may pull the
handle" was always an argument about people. A machine Account at `operator` — an AI-agent —
halting the fleet is not the fire alarm the cheapness argument had in mind; it is a jailbroken
driver switching off its own overseers, which is a denial of service. Automation that genuinely
needs to stop dispatch uses the host lever, where the authority is root on the box rather than a
stealable credential.

**Release is not human-only.** An incident must have an automated way back.

**The host lever exists because the distrusted thing may be the API credential itself.** When it
is, root-on-the-box must suffice to pull the cord — so the local path bypasses the role gate. It
is not a backdoor around authorization; it is a *different* authority, and the asymmetry is the
point.

**A release always carries a reason.** Both paths require one, including the local lever, because
"why did the fleet start moving again" is the question an incident review asks.

### Failing closed

**A failed read of the Freeze state refuses dispatch.** A guardrail must never fail open, even at
the cost of availability during a store blip. An unreadable stop button is treated as engaged.

The Freeze **survives a Relay restart**. A stop button that forgot itself on process exit would
be released by the crash it might have been engaged for.

### An accepted information disclosure

Because the Freeze gate runs before authorization, a caller not authorized for the Operation
still learns the Relay is frozen before being told they are denied. Accepted: every caller
reaching that path is already mTLS-authenticated, so there is no anonymous caller to leak it to,
and spending registry-resolution work to order the two refusals more tidily would be a cost with
no security return.

### Auditing

Every engage and release is audited with the Account that did it, or `local-host` for the signal
path. A refused engage or release is audited too — an attempt to stop the fleet that was turned
away is exactly as interesting as one that succeeded, and a refused attempt leaves the Freeze
state untouched.

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
- **ADR-0038** — a Plan is an approved route, and every advance of one is new dispatch. The Freeze
  exemption covers preflights and stops at them.
- **Invariant 5** — Freeze is not the blast cap and does not substitute for it; it sits outside
  and above.
- **Invariant 10** — the decision is the capability layer's. A surface engages and renders; the
  local lever is a second root of authority, not a second implementation.
- **Invariant 11** — the host lever's authority is root on the box, which is the same authority
  root as Relay configuration and Node Policy.

## Seams and proof

The Freeze lives behind a small store seam — read, engage, release — with a safe default of
"never frozen" for composition roots that wire no real store. **That default is a missing stop
button, not a fail-open of authorization**, and the composition root's fail-open guard requires a
real Freeze store alongside a real dispatcher for exactly that reason: an un-stoppable real
executor is the same class of wiring bug as an unauthorized one.

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
| A refused engage or release changes nothing and is still audited | `TestEngageFreeze_RefusedIsNotEngagedAndIsAudited`, `TestReleaseFreeze_RefusedIsNotReleasedAndIsAudited` | capability |
| A release requires a reason — including on the local lever | `TestReleaseFreeze_RequiresAReason`, `TestReleaseFreezeLocal_StillRequiresAReason` | capability |
| The local lever bypasses the role gate deliberately | `TestFreezeLocalLever_BypassesTheRoleGate` | capability |
| Preflights answer while frozen, while real runs refuse | `TestPlanFrozenReportsAdvisoryWhileRunRefuses` | capability |
| Freeze engage/release works end to end over the API | `TestControlAPI_FreezeEngageRelease` | e2e |
| Freeze state carries no database import into the state package | `TestNoDatabaseSQLImport` | compile-time |

Claims above with **no row**, and so nothing checking them:

- That engaging over the Control API requires a **human** Account. The role gate is covered and
  the human-Account clause is the 2026-08-24 amendment to ADR-0013; no test names it, and it is
  the clause that stops a jailbroken AI-agent halting the fleet.
- That in-flight Tasks keep running through a Freeze. Stated by ADR-0013 and true by construction
  — the gate is on new dispatch only — but not asserted.
- That the host lever is unreachable from any surface. True by the interface the API holds, and
  argued at the call site, but there is no structural test like `no_dispatch`.
- That a Freeze stops the next **advance** of an approved Plan. Unbuilt rather than untested —
  the capability does not exist yet (`plan.md`), and the claim sits in its testing backlog. It is
  named here because this is where someone will look for it.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Freeze check | One store read per dispatch attempt, outermost in the pipeline | *(none)* |
| Engage latency | Takes effect for the next dispatch attempt; nothing in flight is revisited | *(none)* |

There are no benchmarks in this repository. The Freeze read is on the path of **every** dispatch,
including a 10,000-Node read, so it is the most frequently executed guardrail in the system and
nothing measures it.

## Out of scope

- **Job and Task cancellation** — `execution.md`. Cancel acts on one Job the engine created;
  Freeze is a global valve on new dispatch. They are ADR-0013 siblings and are not the same
  mechanism: a Freeze stops what has not started, a cancel asks about what has.
- **Quarantine and revocation** — the other rungs of the incident ladder, and both label- and
  identity-shaped rather than dispatch-shaped. See `selectors-and-labels.md` and `enrollment.md`.
- **Policy** — a Node refusing work locally is not a Freeze, and a Freeze is not a Policy change.
- **Per-Account rate limits** — a decision still open, and a different control: rate limiting
  shapes normal traffic, Freeze stops abnormal traffic entirely.

## Future work

Deliberately not in the first pass: the built capability should work end to end before anything is
added to it.

- **Engaging from the Console** (#457).
- **Approvals during a Freeze, stated as behaviour.** A pending request can still be decided while
  frozen, nothing dispatches until release, and an approved request still expires on its own clock
  and must be re-requested if the Freeze outlasts it. Settle once Plans and approvals are built.

## Open questions

- **Nothing tests the human-Account requirement on API engage — a test is wanted in the first
  pass** (ADR-0013's 2026-08-24
  amendment). It is the clause that prevents an AI-agent switching off its own overseers, and it
  is the least-covered statement in this capability.
- **The local lever is a signal, which is a thin interface for an audited act.** `SIGUSR2` carries
  a reason today through a side channel rather than in the signal itself. It works, and it is the
  kind of thing that looks obvious in a post-incident review if the reason went missing.

## History

- `2026-09-14` — Confirmed with the owner: the built behaviour is the first pass. Console engage
  and approvals-during-a-Freeze moved to Future work; a test for the human-Account engage rule is
  wanted now.

- `2026-09-12` — ADR-0038: the exemption is **Policy preflights**, not "Plans". Every advance of
  an approved Plan is new dispatch and is stopped. Before the rename this section read as though
  a Freeze did not stop approved routes, which was the opposite of the rule.
- `2026-09-12` — First written. Closes the dangling reference from `execution.md`'s out-of-scope
  section, and narrows from the originally proposed `freeze-and-cancellation.md`: cancellation
  moved into `execution.md`, since it acts on a Job that capability creates.
