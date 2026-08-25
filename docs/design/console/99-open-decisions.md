# 99 — Open decisions

**Read this before writing Console code.** Several things the screen specs describe are **not
decided**. They are drawn in the wireframes because a wireframe is the cheap place to see an idea,
not because anyone has ruled on them.

Per CLAUDE.md, an implementing agent has **no merge authority** and must **stop and flag a human
rather than guess on a hard call**. Every item in the first two sections is a hard call. Building
past one turns a sketch into an accidental architecture, which is precisely the failure this file
exists to prevent.

---

## Blocking — needs an ADR before the code lands

> **D1 was resolved on 2026-08-24** and is kept here with its reasoning; its ADR is still
> unwritten and the code still waits on it.

### D1. The `state:` Label namespace — **RESOLVED 2026-08-24, ADR still to be written**

**What:** a fourth namespace of Relay-derived labels, targetable by Selectors, writable by nobody.

**Why it exists:** operational state is what fleet maintenance actually targets — "run this on the
ones that are behind" — and today it is not expressible. Labels target; Facts explicitly do not;
and daemon version and the fingerprints are *neither*, as `Hello` shows by carrying
`daemon_version` and `Facts` as separate fields.

**Still needs an ADR** because it changes CONTEXT.md's definition of **Selector** ("a label-based
query") and adds a namespace alongside ADR-0006's and ADR-0020's three. Both files are
escalate-to-a-human. The decisions below are settled; the ADR records them.

#### The governing rule: every `state:` label is Node-local and objective

Computable from one Node's registry record, with **no reference to any other Node**.

This is not a style preference. The first draft defined `state:policy-drift` as "fingerprint
behind the fleet's mode", which is fleet-relative and fails badly: roll a Policy to 51% of the
fleet and the mode flips, so the other 49% become "drifted" without anything about them changing.
A Selector targeting it would **silently invert its meaning mid-rollout**. It also smuggles
desired-state past invariant #9 — computing "behind" requires a notion of what the fleet *should*
be on, and CONTEXT.md deliberately defines fingerprints as an observation ("confirm a rollout
landed by string comparison"), not a target.

#### The closed vocabulary

Two shapes, both Node-local.

**Boolean markers**

| Label | True when |
|---|---|
| `state:offline` | not currently connected |
| `state:outdated` | daemon below the Relay's configured dispatch minimum (ADR-0014) |
| `state:template-unloadable` | the Node's template set failed to load; vocabulary empty, fail closed |
| `state:cert-expiring` | identity certificate within the configured warning window of `NotAfter` and not yet renewed (D4) |

**Key=value state facts**

| Label | Value |
|---|---|
| `state:daemon-version=` | the version reported in `Hello` |
| `state:policy-fingerprint=` | the fingerprint reported in `Hello` / `PolicySnapshot` |
| `state:template-fingerprint=` | the template-set fingerprint, or the literal `unloadable` |

**Drift is not a label.** It stays an observation — the facet rail's fingerprint distribution and
a presentational count on the rollup card. Targeting "the ones that are behind" is
`state:policy-fingerprint=4b18…c02`: Node-local, objective, and stable under rollout. The facet
rail is the UI for it — click the old fingerprint, the filter fills in.

#### Resolution model

`state:` terms are **evaluated at Selector-resolution time** as predicates over registry data, not
materialised as rows. Every surviving label is Node-local, so this is cheap and always correct.
Materialising would mean recomputing on every `Hello`, every `PolicySnapshot`, every disconnect
and every min-version config change, and keeping a denormalised copy that can go stale — for no
correctness gain.

Selector resolution therefore gains a second code path alongside label matching. That is the cost,
and it is accepted.

#### Also settled

- The vocabulary is **closed** and lives in the contract. Free-form state labels would become a
  second `tag:` with none of the guarantees, and Selectors written against them would silently
  stop matching when a definition changed.
- `state:` is **never** a valid security-lane target. Invariant #7 stands unchanged: quarantine,
  remediation and secret distribution target `relay:` and only `relay:`. Rationale: `state:` is
  computed partly from what the Node itself reports, so a compromised Node can influence it.
- **No Account of any role can write one**, enforced structurally, not by permission check.
- `state:` labels appear in `list_nodes` output, so the AI-agent and the Control API target them
  identically to the Console. No Console-only concept.

**Rejected:** folding into `relay:` (mixes derived state into the security lane); extending
Selector grammar to comparisons like `daemon.version < 1.4.2` (a bigger change to the domain
language, and unnecessary once fingerprints are targetable); the `tag:` bridge (a snapshot that
goes stale).

### D2. Stopping one agent — **RESOLVED 2026-08-24, ADR still to be written**

**The problem with the first draft:** an MCP session is authenticated by a bearer token, so killing
the connection buys seconds — the client reconnects with the same credential. "End session" as
drawn was theatre: it looked like a brake and was not one.

**What the operator actually needs**, watching the stream and seeing something alarming: stop it
now, without freezing the whole fleet, reversibly. Revoking the Account's API Token gets the first
two and fails the third. Freeze gets the first and third and fails the second.

So the missing rung is **Account-scoped, not session-scoped**. It suspends the actor.

#### The incident ladder, completed

| Rung | Fences | Reversible |
|---|---|---|
| `relay:quarantine` | one Node | yes |
| **suspend Account** | one actor | yes — **the gap this fills** |
| revoke Node | one Node | no |
| Freeze | everything | yes |

Quarantine fences a machine; suspend fences an actor. The symmetry is deliberate and worth
teaching.

#### Two controls, two intents

- **Disconnect** — drops the connection, no state change. For an agent stuck in a loop that just
  needs its context broken. It may reconnect immediately, and the UI must say so. Not a security
  control and must not be presented as one.
- **Suspend** — the durable, reversible, Account-scoped brake.

#### Suspension semantics

- **Every call is refused**, not merely dispatch. The actor is suspended because it is not trusted,
  and reading is exfiltration by construction (ADR-0021); narrowing to dispatch would leave the
  exfiltration path open. Refused calls are still audited, so a suspended agent remains observable
  through what it attempts.
- **In-flight Tasks keep running**, exactly as under Freeze. Cancel is the instrument for those.
  Two controls, one consistent meaning of "stop".
- The Account may still connect; it simply gets nowhere. This is what makes the control durable
  where a connection kill is not.

#### Authorization — mirrors Freeze exactly

**`operator`+ to engage. `admin` + step-up, with an audited reason, to lift.** ADR-0013 already
settled this asymmetry for Freeze — cheap to engage, deliberate to release — and the reasoning
transfers: no friction on the emergency path, and an attacker who suspends your agents has made
noise rather than progress.

#### What the ADR must still record

- Whether suspension lives on the Account model (ADR-0010) as a state, or as a capability-layer
  verb. It is an Account-state change, so the former is the presumption.
- Whether a suspended Account's existing Enrollment Tokens and API Tokens remain valid (they
  should — suspension is not revocation, and conflating them costs the reversibility that is the
  whole point).
- The audit shape: engage, lift, and every refused call while suspended.

## Needs a ruling — smaller, but not an implementer's call

### D3. The word "outdated" — **RESOLVED 2026-08-24**

**Settled by the code, not by preference.** `Outdated` is a live field on the MCP wire —
`relay/internal/controlplane/mcp/tools_execution.go` returns it on every Plan entry, and
`mcp_plan_test.go` pins its meaning: *"outdated:true — a real dispatch would refuse it, but Plan
mode never [does]."* That is ADR-0014's meaning, shipped and under test.

**`outdated` means: the Node's daemon is below the Relay's configured dispatch minimum.**
`ui-advisory.md`'s use of the word for Policy-fingerprint drift is the incorrect one, and D1 has
removed that concept from the UI regardless.

The Console uses **`state:outdated`**, matching the wire. An earlier draft of these specs used
`state:version-gated`, which was more legible in isolation and violated CLAUDE.md's no-synonyms
rule: an operator reading a Plan through MCP and the same Plan in the Console would have seen two
words for one thing. Renaming the wire field instead was rejected — ADR-0014 mandates
additive-only evolution within `relay.v1`, so a rename is a breaking contract change for a
cosmetic gain.

**Follow-up work this creates:**
- CONTEXT.md gains an `outdated` entry pinned to ADR-0014's meaning, with *Avoid: version-gated,
  stale, behind*.
- `ui-advisory.md`'s "`outdated` flags" sentence, which refers to Policy fingerprints, is corrected.

### D4. `state:cert-expiring` — **RESOLVED 2026-08-24: include it**

Node identity certificates carry `LeafValidity = 336 * time.Hour` (`relay/internal/ca/ca.go`), and
renewal is cert-authenticated and jittered. The Relay issued the certificate, so it knows every
Node's `NotAfter`; "expires within the warning window and has not renewed" is computable from one
Node's record against a config threshold — the same shape as `state:outdated`, and it passes D1's
Node-local rule.

**It is an alarm, not a to-do list.** Node certificate renewal is already fully automatic and
involves no human: `rpc Renew` is cert-authenticated over mTLS (deliberately excluded from the
certless allowlist), the daemon runs `renew::run` as a spawned task, the Relay reissues for the
**same `node_id`** derived from the verified peer cert rather than the CSR so provenance survives,
and renewals are jittered to spread the fleet. `state:cert-expiring` therefore fires only when
**that automation has failed** on a specific Node — which is what makes it worth surfacing and
also what makes it rare.

**Why it earns a slot:** it is the only early warning for a failure nothing else catches in time. A
Node that stops renewing is invisible until it drops off, at which point `state:offline` reports it
after a two-week fuse has already burned down.

**Why 336 hours:** `LeafValidity` is a deliberate security property of *Node identity* certs — a
stolen Node key self-expires in two weeks, bounding the damage of a compromised machine
independently of whether anyone noticed and revoked it. Automatic renewal is what makes a short
lifetime free to the operator.

**Open sub-question for the ADR:** the warning-window threshold is Relay configuration (file-only,
invariant #11) and nobody has proposed a value. It should be long enough to act on and short enough
to stay quiet — a fraction of `LeafValidity` rather than an absolute.

### D5. Colour deviations from the brief — **RESOLVED 2026-08-24: both accepted**

1. **Amber is split from indigo.** Amber means *attention now* (Freeze, `state:offline`,
   `state:outdated`, `state:cert-expiring`, over-cap notes). Indigo means *the security lane*
   (`relay:` labels and the acts that set them). `console-wireframe-brief.md` reserved amber for
   the Freeze banner and quarantine, then used amber for the odd Node out in the pixel wall — so
   it already contradicted itself. Splitting keeps quarantine visually bound to `relay:` everywhere
   it appears, rather than sharing a colour with "this machine is unreachable".
2. **One muted red exists**, on `failure` and `timeout` only. The brief says "red for nothing
   routine"; a Task that ran and genuinely failed is not routine. Everything else that stops a Task
   is a boundary doing its job and stays neutral — above all `denied_by_policy`, which is slate.

`console-wireframe-brief.md` rule 1 should be updated to match.

### D6. The `Jobs` nav destination — **RESOLVED 2026-08-24: dropped**

Activity already renders Job rows and filters to them, so a separate Jobs destination was a
duplicate list to keep consistent with the first one. Removed before anyone builds it twice.

**Job detail remains its own page**, reached from any dispatch row in Activity, from a Node's
recent Tasks, and from the agent stream. Dropping the list does not drop the record.

### D7. Policy as its own nav item — **RESOLVED 2026-08-24: keeps its slot**

Policy authoring is recurring work and the deny-to-fix loop is central to the trust story;
enrollment is mostly a one-off by comparison. Folding Policy under "Node setup" would bury the
screen operators return to.

### Resulting navigation — nine destinations, three groups

```
Observe      Fleet · Agents · Activity
Act          Run · Policy · Approvals
Administer   Add Nodes · Accounts · Incident
```

## Prerequisites that already exist as issues

### D8. #397 — enrollment mint has no role gate

`POST /api/v1/enrollment-tokens` authenticates the caller and never checks their role, so a
`viewer` can mint a token that stamps `relay:` labels. **Spec 09 must not ship before this is
fixed** — rendering on top of an ungated mint wraps a privilege escalation in a convenience.

### D13. E2a — the Relay's server certificate never rotates **(blocking, and not a UI bug)**

`relay/cmd/relay/main.go:391` and `:575` each call `IssueServerCertificate` once at process start.
There is **no `GetCertificate` callback anywhere**, and the leaf borrows `LeafValidity` (336h — the
constant meant for Node identity). A Relay running longer than fourteen days serves an expired
certificate and **the whole fleet fail-closes off it.** Unnoticed only because nothing has run for
two continuous weeks.

Recorded in `../self-serve-enrollment.md` as **E2a**, "lands first and alone". It is repeated here
because **the Console's own TLS rides on the same certificate** (ADR-0031 puts both listeners on
one): a Console shipped before E2a lands breaks for every user at the fourteen-day mark. No Console
work should be considered done against a Relay that still has this defect.

**Nothing about the fix is manual.** The Relay is its own CA; `IssueServerCertificate` is an
in-process call against a key already on disk. The fix is to call it again from a `GetCertificate`
callback when the leaf is within a jittered fraction of expiry — the process mints its own
replacement, in memory, with no operator involvement and no restart. Short validity is not a cost
here, because rotation is a function call; ADR-0031 §5 asks only that the server leaf get **its own
constant** rather than borrowing the identity one.

### D14. CA rotation has no story — **raised as [#412](https://github.com/Felag-Engineering/gleipnir-relay/issues/412)**

`caValidity = 10 * 365 * 24 * time.Hour`. Ten years is a long horizon, but it is not "never", and
the more urgent case is unbounded: **if the CA key is ever compromised, there is no rotation path
at all.**

Rotation is genuinely hard here and that is by design. ADR-0031's join string pins the **CA
fingerprint**, and the daemon verifies the presented chain roots in a certificate matching that pin
*before anything else happens*. Every Node's trust anchor is that one CA, and the daemon's security
model is built on distrusting the Relay — so the Relay cannot simply hand out a new anchor.

Not a Console concern and not in scope for these specs. Recorded because it surfaced while
specifying certificate expiry, and because an unsolved trust-root rotation story is cheap to design
now and very expensive to retrofit. Raised as decision issue **#412** (2026-08-24) for a future ADR
covering both planned rotation and CA-key compromise, which may want different answers.

### D9. The SSE seam must cover MCP tool calls — **RESOLVED 2026-08-24: widen it**

`console-backend-coverage.md` scopes the v0.6.0 event seam to "registry and Job state
transitions". The agent stream (spec 03) needs **MCP tool-call events**, which is a third
publisher, not a filter on the first two: a `list_nodes` call transitions no registry state and
creates no Job.

**One in-process pub/sub, three publishers** — registry transitions, Job transitions, MCP tool
calls — built once in v0.6.0. A second event mechanism later is worse than widening this one now,
and the agent stream is read-only, so v0.6.0's zero-mutating-routes acceptance criterion is
untouched.

**A hard constraint on the tool-call publisher.** Its events carry **arguments** — file paths,
Selectors, and for `raw_exec` the full argv. That is the point and it is fine. It must **never**
carry read *results*: ADR-0025's no-retention property is about the data, not about one table, and
an event bus that ships read output has leaked it just as surely as an audit row that stores it.
Assert this structurally, the way `no_dispatch` is asserted.

`console-backend-coverage.md`'s SSE row should be updated to say three publishers.

### D10. The approval record needs a shape key — **RESOLVED 2026-08-24, and it is a v0.5.0 decision**

Spec 08's anti-fatigue diff — "same as what you approved Tuesday, except the fan-out grew
1,180 → 2,214" — is the highest-value element on the highest-stakes screen. It has to find *the
last approved action of the same shape*, so the approval record must be queryable by shape.

**Add one field: a shape key.** A hash over the Operation and the **normalised Selector**,
deliberately **excluding** fan-out and any argument expected to vary. Finding the prior approval
becomes a lookup rather than a scan, and "same shape, different scale" is precisely what the diff
exists to express.

**Why this cannot wait.** v0.5.0 lands well before the Console. Retrofitting means a migration over
records whose shape key cannot be recomputed — normalising a Selector after the fact is guesswork,
and the approval trail is exactly the data you least want to guess about.

**What the v0.5.0 work must settle:** the normalisation rules for a Selector (term order,
whitespace, namespace canonicalisation), and which arguments are part of the shape versus part of
the scale. Getting the second wrong in either direction breaks the feature: too strict and every
approval looks novel, too loose and a materially different action reads as routine.

**Rejected:** scanning the audit trail at render time (a scan on the most latency-sensitive screen,
with a fuzzy definition of "matching"); storing a resolved pointer to the prior approval at write
time (moves comparison logic into the write path, where an error is baked into history).

---

## Proposed, not specified

### D11. A read-egress view — **RESOLVED 2026-08-24: specified as [17](17-read-egress.md)**

ADR-0021 says reading is exfiltration by construction; ADR-0022 builds a 25-path confidentiality
deny-list around it; ADR-0025 makes every read auditable and fails the read closed if the audit
write fails. All that machinery existed and nothing in the Console surfaced any of it.

Specified without a wireframe, by choice. **No new collection is required** — every row derives
from a `KindRead` audit record that already exists.

The screen is a map of **exposure surface**, not a data browser: the audit trail can say a read
happened, by whom, of what and when, but never what it contained. That limit is what stops the
screen becoming a second copy of the fleet's secrets.

### D12. A capability preview — "what could this Account actually do?"

Given a role and the fleet's live Policy, render the reachable envelope before someone is handed
the keys. Turns an abstract role grant into a concrete blast radius. More speculative; raised, not
pursued.

---

## Known gaps with no spec yet

**None.** Every screen named in earlier drafts now has one: the Console shell (11), login (12), Job
detail (13), the approval queue (14), Accounts and API tokens (15), the incident ladder (16) and
read egress (17).

Two dimensions that cut across every screen and are not drawn anywhere: a `viewer` sees a
**structurally smaller** Console rather than a greyed-out one, and `console_execution = off`
removes Run **entirely** rather than disabling it. ADR-0026's insight is that *absent* beats
*forbidden*; an implementation that ships a disabled composer has given the property away.
