# 99 — Open decisions

**Read this before writing Console code.** Several things the screen specs describe are **not
decided**. They are drawn in the wireframes because a wireframe is the cheap place to see an idea,
not because anyone has ruled on them.

Per AGENTS.md, an implementing agent has **no merge authority** and must **stop and flag a human
rather than guess on a hard call**. Every item in the first two sections is a hard call. Building
past one turns a sketch into an accidental architecture, which is precisely the failure this file
exists to prevent.

---

## Blocking — needs an ADR before the code lands

> **D1 and D2 were resolved on 2026-08-24.** D1's ADR-0034 is merged. D2's ADR-0035 was drafted,
> then **deferred — not adopted** in review (#443). Both are kept here with their reasoning. A
> summary of what the review changed after the issues were cut is at the end of this file.

### D1. The `state:` Label namespace — **RESOLVED 2026-08-24 — drafted as [ADR-0034](../../adr/0034-state-labels-relay-derived-namespace.md)**

**What:** a fourth namespace of Relay-derived labels, targetable by Selectors, writable by nobody.

**Why it exists:** operational state is what fleet maintenance actually targets — "run this on the
ones that are behind" — and today it is not expressible. Labels target; Facts explicitly do not;
and daemon version and the fingerprints are *neither*, as `Hello` shows by carrying
`daemon_version` and `Facts` as separate fields.

**ADR-0034 is merged**, with the GLOSSARY.md and AGENTS.md invariant #7 amendments. Its Consequences
carry the review's additions: the registry must first persist liveness and certificate validity
(#440), the `cert-expiring` window is 25% of `LeafValidity` remaining, `tag:` parsing lands in the
same Selector change, and the security-lane assertion lives on the `relay:` write path (#430).

#### The governing rule: every `state:` label is Node-local and objective

Computable from one Node's registry record, with **no reference to any other Node**.

This is not a style preference. The first draft defined `state:policy-drift` as "fingerprint
behind the fleet's mode", which is fleet-relative and fails badly: roll a Policy to 51% of the
fleet and the mode flips, so the other 49% become "drifted" without anything about them changing.
A Selector targeting it would **silently invert its meaning mid-rollout**. It also smuggles
desired-state past invariant #9 — computing "behind" requires a notion of what the fleet *should*
be on, and GLOSSARY.md deliberately defines fingerprints as an observation ("confirm a rollout
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

### D2. Stopping one agent — **DEFERRED 2026-08-24 — [ADR-0035](../../adr/0035-account-suspension.md) drafted, then not adopted**

**Outcome: cut.** Suspension was plumbing for a control nothing yet needs, and review found the
draft could lock every admin out (an `operator` may suspend admins; lifting is an admin call; every
call from a suspended Account is refused). Disconnect had no object: MCP is stateless (ADR-0028),
so there is no connection to drop — and therefore no "agent session" either; spec 03 is now
per-Account activity. Stopping one actor today is **revoking its API Tokens** or **Freeze**; the
incident ladder stays at ADR-0020's three rungs. ADR-0035's banner and #443 carry the constraints
any revival must meet. The reasoning below is kept as the record of the design.

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

#### Recorded in ADR-0035; still open within it

- Whether suspension lives on the Account model (ADR-0010) as a state, or as a capability-layer
  verb. It is an Account-state change, so the former is the presumption.
- Whether a suspended Account's existing Enrollment Tokens and API Tokens remain valid (they
  should — suspension is not revocation, and conflating them costs the reversibility that is the
  whole point).
- The audit shape: engage, lift, and every refused call while suspended.

## Needs a ruling — smaller, but not an implementer's call

### D3. The word "outdated" — **RESOLVED 2026-08-24**

**Settled by the code, not by preference.** `Outdated` is a live field on the MCP wire —
`relay/internal/controlplane/mcp/tools_execution.go` returns it on every Preflight entry, and
`mcp_plan_test.go` pins its meaning: *"outdated:true — a real dispatch would refuse it, but Plan
mode never [does]."* That is ADR-0014's meaning, shipped and under test.

**`outdated` means: the Node's daemon is below the Relay's configured dispatch minimum.**
`ui-advisory.md`'s use of the word for Policy-fingerprint drift is the incorrect one, and D1 has
removed that concept from the UI regardless.

The Console uses **`state:outdated`**, matching the wire. An earlier draft of these specs used
`state:version-gated`, which was more legible in isolation and violated AGENTS.md's no-synonyms
rule: an operator reading a Preflight through MCP and the same Preflight in the Console would have
seen two words for one thing. Renaming the wire field instead was rejected — ADR-0014 mandates
additive-only evolution within `relay.v1`, so a rename is a breaking contract change for a
cosmetic gain.

**Follow-up work this creates:**
- GLOSSARY.md gains an `outdated` entry pinned to ADR-0014's meaning, with *Avoid: version-gated,
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

**Settled in review: 25% of `LeafValidity` remaining** (84h). The daemon renews at a jittered
50–75% of the lifetime (`daemon/src/renew.rs`), so under a quarter left means the whole renewal
window was missed. A threshold inside the jitter window would alarm on a healthy fleet. File-only
configuration (invariant #11), as a fraction so it tracks any change to the lifetime. The registry
must persist `cert_not_after` first (#440).

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

### D15. CSP violation reporting — **DEFERRED (#460)**

Spec 11's CSP section says to "report violations rather than silently dropping them, because a
CSP violation in this product is a security event, not a rendering glitch." #460 (the Console
CSRF fix) implements the rest of that section but ships no `report-to`/`Reporting-Endpoints`
pair, deliberately: naming a reporting group with no endpoint behind it is worse than naming
none, because it looks like a working control while silently dropping every report.

Four reasons, recorded here rather than left an unrecorded omission:

1. **A report sink is an unauthenticated POST.** The Reporting API delivers to whatever endpoint
   the header names with no credential attached, so the sink is attacker-reachable by
   construction. It needs a body cap, a rate limit and a redaction rule before it is safe to
   expose at all — none of which exists yet.
2. **It cannot live behind this file's own control.** The browser's Reporting API sends reports
   without this Console's CSRF token and, by default, without credentials, so routing reports
   through `Secure` would have it 403 every report it was supposed to receive. It needs a route
   outside both `Secure` and the authenticator — a THIRD hole in the control plane's auth
   wrapper, whose extent `Unauthenticated`'s own doc asserts is exactly two routes and no more.
3. **Where reports go is an open product decision, not an implementation detail.** If a CSP
   violation is a security event per spec 11, it belongs in the audit trail — under a `kind` that
   does not exist yet — against ADR-0025's posture that the Relay authors its own audit records
   rather than accepting one from an unauthenticated caller.
4. **It is on neither spec 11's acceptance list nor v0.6.0's.** Nothing currently promises this
   ships in this milestone.

**What would close it:** a ruling on the sink (a new audit `kind`, most likely, given (3)), plus a
bounded, rate-limited, unauthenticated route built to receive it — sized as its own change, not a
rider on a CSRF fix.

### D16. What the Console calls a Policy preflight — **RESOLVED 2026-09-20: "Preflight" (#575)**

**What:** ADR-0038 gave the word **Plan** to an approved route of execution and renamed the
no-execution preview **Policy preflight**. These specs and the Console's copy still said "Plan" in
the old sense — and the Console is the one surface where both meanings will appear on screen at
once: a preflight verdict before a mutate apply, and an approved Plan, with its plan hash, in the
approval queue. A button or card labelled "Plan" would then be genuinely ambiguous to an operator
who never read GLOSSARY.md, and the button label is a UX call, not a terminology correction.

**Ruling (owner, 2026-09-20):** the Console says **Preflight**. The composer's primary action is
`Preflight`; the rendered verdict is the Preflight; the Agents stream's outcome chip for a
preflight call reads `preflight`. **Plan** is reserved for the approved route (ADR-0038) and for
the plan hash an approval commits to (ADR-0027) — the approval object, the Job's Plan block and
every "plan hash" keep the word, and the shared Plan renderer keeps its name because it renders a
Preflight verdict in the composer and a Plan on the other two screens (00). Spec 05 was renamed
from "Composer and Plan" to "Composer and Preflight" in the same sweep. The wire still spells the
option `plan` until the code follows (GLOSSARY.md): that spelling is a contract, the label is copy,
and they are allowed to differ until the contract moves.

## Prerequisites that already exist as issues

### D8. [#397](https://github.com/Felag-Engineering/gleipnir-relay/issues/397) — three route families have no role gate — **RESOLVED: gates landed**

**Broader than earlier drafts of this file recorded.** Three `/api/v1` route families authenticate
the caller and then never check their role:

| Route | Handler |
|---|---|
| `POST /api/v1/enrollment-tokens` | `api/tokens.go` |
| `POST /api/v1/nodes/{node_id}/revoke` | `api/nodes.go` |
| `POST /api/v1/freeze/engage` · `/release` | `api/freeze.go` |

So a `viewer` can mint a token that stamps `relay:` labels, revoke Nodes, and engage or release the
fleet Freeze — while the documentation says all three are admin-only. `requireAdmin` exists
(`api/accounts.go`) and is referenced only from `accounts.go`.

**Added in review:** Freeze engage is **human-principal only** — a machine Account at `operator`
must not be able to freeze the fleet. Recorded on #397 as an acceptance line.

**Nothing here needs deciding.** Minting requires `admin` per ADR-0032 §5; Freeze is `operator`+ to
engage and `admin` with an audited reason to release per ADR-0013; revocation is `admin` + step-up
per ADR-0020's incident ladder. The gates are specified and absent.

**Blocked two specs, not one:**
- **[09 — Add Nodes](09-add-nodes.md)**, whose whole subject is minting.
- **[16 — Incident](16-incident-ladder.md)**, which specifies revoke as `admin` + step-up and
  Freeze as `operator`+ / `admin`. Building a UI whose controls state a role requirement the API
  does not enforce is worse than building nothing: it documents a protection that is not there.

**Resolved (2026-08-24).** The floors are enforced, all five of them, from the one
`authz.RoleGate` the capability layer already held: mint `admin`, token revoke `admin`
(the fourth route, which this entry's table did not name — found by the structural guard),
Node revoke `admin`, Freeze engage a human `operator`+, Freeze release `admin` with a
reason. Freeze's floor lives in `capability.Service`, so the Console inherits it rather
than re-deriving it; mint and revoke are checked at the Control API surface because
`capability`'s import allowlist bars `internal/enroll` and `internal/revocation`, leaving
no capability-layer method to gate. Every refusal is audited as a `refusal` with the
Account, and `TestEveryRouteIsRoleClassified` now fails any route added without a declared
floor.

**One half of D8 is still owed:** ADR-0020 asks for `admin` **+ step-up re-authentication**
on Node revoke, and there is no step-up mechanism on the Control API yet. Spec 16 may state
the role requirement as enforced; it may not yet promise the step-up.

### D13. [#403](https://github.com/Felag-Engineering/gleipnir-relay/issues/403) — the Relay's server certificate never rotates **(blocking, and not a UI bug)**

`relay/cmd/relay/main.go:391` and `:575` each call `IssueServerCertificate` once at process start.
There is **no `GetCertificate` callback anywhere**, and the leaf borrows `LeafValidity` (336h — the
constant meant for Node identity). A Relay running longer than fourteen days serves an expired
certificate and **the whole fleet fail-closes off it.** Unnoticed only because nothing has run for
two continuous weeks.

Tracked as [#403](https://github.com/Felag-Engineering/gleipnir-relay/issues/403), and as **E2a**
in `../self-serve-enrollment.md` ("lands first and alone"), with acceptance criteria already
written there. Its sibling [#404](https://github.com/Felag-Engineering/gleipnir-relay/issues/404)
collapses the two listeners onto one multi-SAN certificate. **Neither needs a specification** — the
fix is settled in ADR-0031 §5. Repeated here because **the Console's own TLS rides on the same certificate** (ADR-0031 puts both listeners on
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

**One in-process pub/sub, four publishers** — registry transitions, Job transitions, MCP tool
calls, and **enrollment attempts** (spec 10's day-one watch: Relay-side outcomes only, token ID
never plaintext) — built once in v0.6.0. Events carry monotonic IDs from a bounded per-publisher
ring buffer so a client can resume from `Last-Event-ID`; a client too far behind receives a `gap`
event and reloads its region rather than pretending continuity. A second event mechanism later is worse than widening this one now,
and the agent stream is read-only, so v0.6.0's zero-mutating-routes acceptance criterion is
untouched.

**A hard constraint on the tool-call publisher.** Its events carry **arguments** — file paths,
Selectors, and for `raw_exec` the full argv. That is the point and it is fine. It must **never**
carry read *results*: ADR-0025's no-retention property is about the data, not about one table, and
an event bus that ships read output has leaked it just as surely as an audit row that stores it.
Assert this structurally, the way `no_dispatch` is asserted.

`console-backend-coverage.md`'s SSE row says four publishers.

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
and the approval trail is exactly the data you least want to guess about. *(v0.5.0 had already
shipped when this was written, so it is a retrofit — #415 — but `v0.1.0-beta` has not started and
no production approval records exist, so the migration is over test data.)* For a Grant (#378) the
key hashes the Scope.

**What the v0.5.0 work must settle:** the normalisation rules for a Selector (term order,
whitespace, namespace canonicalisation), and which arguments are part of the shape versus part of
the scale. Getting the second wrong in either direction breaks the feature: too strict and every
approval looks novel, too loose and a materially different action reads as routine.

**Rejected:** scanning the audit trail at render time (a scan on the most latency-sensitive screen,
with a fuzzy definition of "matching"); storing a resolved pointer to the prior approval at write
time (moves comparison logic into the write path, where an error is baked into history).

**Settled by #415.** Three answers, in code:

*Selector normalisation.* Terms are projected from the **typed** `Predicate`, never from Selector
text: the namespace travels as its own length-prefixed field, so a `tag:` term can never normalise
into anything a `relay:` one could collide with (invariant 7). Terms are sorted by
(namespace, key, value) as strings and **exact** duplicates dropped — `node:a=b, node:a=c` is not
collapsed. Nothing is case-folded, whitespace-trimmed inside a term, or Unicode-normalised, because
`Selector.Matches` is an exact map lookup: folding would let two Selectors that target *different*
Nodes share a key. Whitespace-insensitivity comes from the parser, which already trims around terms.
The only folding anywhere is `ToLower` on a Grant's account and Operation names, matching
`Grant.Covers`' `EqualFold` — the rule is **fold where the matcher folds, and nowhere else**.

*Shape versus scale.* Declared per Operation in `opvocab.Descriptor.ArgClasses` and cross-checked
against the daemon's golden Operation schema, so an argument the daemon grows without a class fails
a test. `pkg.install.version` is **scale** — the textbook "argument expected to vary"; classifying
it as shape would make every step of a rollout look novel. Every other native argument is shape. A
**Template Operation** has declared nothing, so every one of its arguments is shape, and every
**Raw Exec** argv element is shape: "never inferred" means we do not guess which element is scale.
A Grant's key also excludes `MaxFanOut` — a ceiling is fan-out, and "same scope, ceiling grew
10 → 500" is the diff the callout exists to shout rather than hide behind a novel-looking key.

*The retrofit.* A pre-#415 **grant** request is recomputed exactly, because its Scope is fully
stored. A pre-#415 **Plan** record cannot be: `approval_requests` never stored the Selector or the
arguments, and this section already rules out guessing. Each such record gets a unique
`legacy:<request id>` key, so it is its own shape and the read seams refuse it — the callout can
never say "you approved this Tuesday" about a record whose shape nobody knows.

**Still missing, and worth naming.** The diff this enables is not yet *renderable*. The approval
record stores no arguments and no Selector — only the Relay-authored `plan_summary` prose — so
"same as Tuesday, except 1.24.0 → 1.25.0" cannot be produced from stored data without parsing that
prose, which is the exact fidelity problem the summary exists to prevent. #415 makes finding the
prior record a lookup; **#426 must decide where the diff inputs come from.**

**Settled by #426: three sources and no new column.**

- *A Grant's* numbers come from the `approval_grants` scope/window columns, reached from the
  Request by `GrantByRequest` (a read and a join, never a claim path — and deliberately **not**
  `ActiveGrants`, because the prior Grant a diff compares against is usually the expired or
  exhausted one). `HashGrantShape` excludes exactly the fan-out ceiling, the window and `max_uses`,
  so two Grants sharing a shape key can differ **only** in those three, and all three are stored.
  That is the spec's headline sentence rendered from columns.
- *A Plan's* scale arguments and its Selector come from the **park's own `approval_requested` audit
  record**, joined on `approval_id` (`idx_audit_approval`). `auditsink.baseRecord` already persists
  the Selector as written, the arguments and the raw-exec argv there. This is not the render-time
  scan rejected above: the prior record is still found by shape key, and these are two exact-id
  reads of records already identified.
- *The fan-out comes from nowhere, and the callout says so.* A park creates **no Job at all**, so
  there is no Task and no result anywhere for the record being rendered — only for a prior one that
  already ran. "1,180 → 2,214" is therefore unavailable, and the card names the fan-out as
  uncomparable rather than parsing a number back out of the summary. Making it comparable means
  putting the resolved fan-out on the approval record, which is #469 and its own change.

Two consequences worth recording as deviations rather than leaving them to be discovered:

1. **The diff renders FIRST on the card**, above spec 08's card order (requester 1, action 2, diff
   3). The spec also calls it "the most eye-catching text on the card", and those two cannot both
   be satisfied by a callout in third place. `TestApproval_DiffIsTheFirstThingOnTheCard` pins it.
2. **Spec 14's per-row fan-out cannot be rendered**, for the same reason as above, so neither the
   row nor the "then largest fan-out" tiebreak carries one. #462 stays open, narrowed to the
   tiebreak and blocked on #469.

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

---

## Review, 2026-08-24 — what changed after the issues were cut

Recorded so the issues, the specs and the ROADMAP are read as one thing.

- **There are no agent sessions.** MCP is stateless (ADR-0028); spec 03 is per-Account activity in
  a 15-minute window. Disconnect is gone; Suspend is deferred (D2, #443). #432 closed.
- **v0.6.0 "zero mutating routes"** means *no Console route reaches the capability layer's write or
  dispatch path*. A session, a saved view or an audit query is not that. **Cancel is v0.7.0** on
  both Job detail (13) and the agent stream (03).
- **`console_execution`** lands with the composer (v0.7.0, spec 05), through config → packaging
  sample → drift gate. In v0.6.0 there is no execution route for it to gate; the shell's property
  is that the nav is built from mounted routes, exercised by the `viewer` dimension.
- **Backend seams the issues assumed existed:** the registry gains liveness and certificate
  validity (#440); audit/Job query seams live in the capability layer's read lane (#441); saved
  views get a preference store (#442). #414 is `state:` evaluation only and is blocked by #440.
- **Read egress** rows derive from `KindRead`, read-class `KindDispatch` and Task outcomes — no new
  collection, but not `KindRead` alone.
- **A batch is a Grant** over a Scope (ADR-0027, #378 amendment); specs 08 and 14 render Scopes.
- **Day one** shows Relay-side enrollment rejections only; daemon-side fingerprint rejections are
  invisible to the Relay by design (#444 for a handshake-abort hook).
- **Login throttling** is not gated on #279 (that is per-Account *Job* rate); spec 12 carries
  defaults, with progressive delay and no hard lockout.
- **Freeze engage is human-principal only** (#397).
- **#397 and #403** carry the `blocking` label and no milestone: they are landed by hand ahead of
  the loop, since the loop walks milestones.
