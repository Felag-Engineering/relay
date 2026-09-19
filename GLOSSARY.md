# Glossary

The canonical vocabulary of this project. Every term below is the word to use — in code,
comments, commits, issue titles, test names, and prose. Most carry an `_Avoid_` line naming
the synonyms this project has deliberately rejected; those are decisions, not suggestions.

What Relay is, and why it is shaped that way, is in [README.md](README.md). The invariants
that constrain every change are in [AGENTS.md](AGENTS.md).

**Gleipnir** is a different project: the first-party AI-agent system that will drive
Relay. It is a *consumer* of Relay (over MCP and the Control API), never a component of
it. The repo name `gleipnir-relay` is historical; the product here is Relay (see
ADR-0016 for the internal-naming boundary).

## Language

**Relay**:
The central server. Accepts relay-daemon connections, routes Operations to
specific Nodes, returns results, and exposes the tool surface used by the
AI-agent.
_Avoid_: hub, server, master, control plane

**relay-daemon**:
The non-AI daemon installed on each managed Node. Dials home to the Relay, holds
a persistent connection, and executes Operations subject to local Policy.
_Avoid_: agent, thrall, client, minion

**AI-agent**:
The AI orchestrator that administers the fleet by using the Relay as one of its
tools. Explicitly *not* the relay-daemon. **Gleipnir** is the first-party AI-agent
system; from Relay's perspective it is simply an AI-agent authenticating as a machine
Account — Relay grants it nothing other AI-agents can't have.
_Avoid_: agent (unqualified), AI, brain, operator, Gleipnir (for the role — Gleipnir
is one AI-agent system, not the role itself)

**Node**:
A managed Linux server that runs a relay-daemon.
_Avoid_: host, machine, target

**Operation**:
A structured, typed administrative action from a declared vocabulary (e.g. restart a
service, read a file, install a package). The primary execution primitive. Two kinds:
**Native Operations**, built into the daemon (frozen at four — ADR-0021), and
**Template Operations**, loaded per Node (see Template Operation). Every Operation
declares a **risk class** — `read` (cannot change Node state) or `mutate` — used for
blast-radius control, never as a substitute for Policy (ADR-0012). Raw Exec is always
`mutate`.
_Avoid_: command, task

**Template Operation**:
An Operation defined by an operator-authored shell template with named, typed-validated
parameter slots — the extensibility tier between Native Operations and Raw Exec
(ADR-0001 tier 2, realized by ADR-0021). The author fixes the command structure;
substitution can never alter it. Mandatory risk class; governed by Policy exactly like a
Native Operation. Loaded from root-owned local files beside the Policy file (same trust
root, ADR-0002); the daemon reports a **template-set fingerprint** beside the Policy
fingerprint. A directory of templates installed and versioned as a unit is a **template
pack**; the first-party **shipped read catalog** is one, installed with the daemon
package. A Node without a given template reports the distinct `unsupported` outcome.
_Avoid_: script, macro, custom command, snippet

**Raw Exec**:
The escape hatch: arbitrary command execution, permitted only when it matches a
Node's regex-based Policy. Exceptional path for what the Operation vocabulary
cannot express.
_Avoid_: shell, command string

**Policy**:
The per-relay-daemon rules that decide whether a given Operation or Raw Exec is
allowed to run on that Node. Locally-rooted and remotely-immutable: enforced by the
relay-daemon, queryable by the Relay, never changeable over the wire. The last line
of defense.
_Avoid_: ACL, ruleset, permissions

**Policy fragment**:
One file in a Node's Policy directory, beside the Policy file. The daemon composes the Policy
file and every fragment into one Policy with one Policy fingerprint; which file a rule came from
affects only error messages (`docs/specs/policy.md`, `docs/specs/daemon-installation.md`).
Written by config management, never over the wire.
_Avoid_: policy file (for a single fragment), policy module, snippet, include

**Catalog fragment**:
A first-party, opt-in Policy fragment published in the **Policy Catalog**: named, versioned
with the release under its `SHA256SUMS`, never edited downstream, and never widened in place — a
fragment that permits more ships under a new name. Live on a Node only once config management
places it in the Policy directory. Declares its **required daemon release**, the earliest
relay-daemon that can load it — not the Relay's minimum-version gate (ADR-0014). The shipped
default Policy is not a catalog fragment (ADR-0022).
_Avoid_: preset, profile, playbook, role, pack (a **template pack** is a different thing)

**Policy Catalog**:
The set of catalog fragments, and the Console screen that arranges them into cohorts and exports
the files and config-management variables to install them (`docs/specs/policy-catalog.md`).
Ends at the clipboard: the Relay never applies Policy (invariant 2) and stores no arrangement.
Unrelated to the **shipped read catalog**, which is a template pack.
_Avoid_: Policy Author (the screen's former name), policy editor, policy store

**Cohort** (Policy Catalog):
A named group of Nodes that should run the same catalog fragments — in practice, one
config-management group. Exists only on the Policy Catalog screen and in its export; the Relay
stores none and it is never a Selector or a Label. Unrelated to the "emergency cohorts" of
ADR-0006, a security-lane idea nothing yet defines.
_Avoid_: group (unqualified), fleet segment, tier

**Canonical form**:
The single normalized spelling a value is reduced to — or required to already be in —
before Policy matches it, so that one thing has one representation an operator's rules can
be written against. Two instances today, both deny-side and both purely lexical (no I/O):
a **path argument** must already be in canonical form — absolute, no `.`, `..`, or empty
segment, no trailing slash — or Policy denies it (ADR-0018); and a Raw Exec command's
**canonical elements** are `argv.join(" ")` re-split on whitespace, which the deny pass
matches in addition to the joined command and the raw argv elements (ADR-0019).
Canonicalization never widens an allow. What each folds is specific to it: the **path**
rule folds `.`, `..` and `//` (and, at the executor, symlinks and `/proc` aliases), but
never case and never Unicode normalization — `/etc/Shadow` is canonical form (ADR-0018);
the **Raw Exec** split folds element boundaries using the Unicode `White_Space` definition,
so a tab or an NBSP separates canonical elements exactly like an ASCII space (ADR-0019).
_Avoid_: normalized form, sanitizing, cleaning (and don't say "canonical" for the
*joined* Raw Exec command — that is the joined form)

**Job**:
A single dispatch of an Operation or Raw Exec across the Nodes matched by a Selector.
Comprises one Task per matched Node and is the unit of audit and blast-radius control.
_Avoid_: batch, run, execution

**Stage**:
The persistence-model layer between a Job and its Tasks: a Job comprises one or more
ordered stages, each a batch of Tasks. **In v1 a Job always has exactly one stage**
(enforced in code and schema); the concept exists so post-1.0 staged rollout lands
without a data migration. Not yet operator-facing — a scheduling/persistence detail.

A Stage is **not** a **Plan** step and the two are never merged: a Stage orders batches
*within one Operation's fan-out* (canary → remainder), where a Plan step is a whole Job
running a different Operation. They are orthogonal axes and compose (ADR-0038).
_Avoid_: phase, wave; step (that is a Plan's)

**Task**:
The execution of one Operation or Raw Exec on a single Node, as part of a Job (within a
Stage). Carries a unique ID for at-most-once execution and reports an independent outcome.
Not to be confused with an **MCP task handle** (see below), which is a different thing at a
different layer.
_Avoid_: command, unit, step; "task" unqualified in any context where MCP is also in play

**Selector**:
A query over a Node's Labels that targets a set of Nodes (e.g. `role=web, env=prod`). Operations
and Raw Exec fan out to every matching Node and return a per-Node result. A single Node is
just a Selector that matches one. Terms in the `state:` namespace are Relay-derived and evaluated
at resolution time rather than matched against stored Labels (ADR-0034); every other namespace is a
stored-Label match.
_Avoid_: filter, query, target spec

**Label**:
A key/value tag on a Node used by Selectors to target it. Lives in one of four
non-overlapping namespaces, each immutable from the other sides: **node-space** (`node:…`,
rooted on the Node and set out-of-band via config management; the Relay records but never
modifies or removes them; authoritative for routine targeting, trusted only as much as the
Node), **relay-space** (`relay:…`, set by the Relay — stamped at enrollment, or written as the
side effect of a defined Relay action such as a quarantine, never by an Account directly — and
immutable to the Node; reserved for the security-sensitive lane), or **tag-space** (`tag:…`, set
by operators through the control plane with standard auth; immutable to the Node; grouping and
routine targeting, and a valid target for *engaging* a quarantine only — ADR-0020, amended
2026-09-16), or **state-space** (`state:…`, derived by the Relay
from the registry, set by nobody — not the Node, not an operator, not an `admin` — evaluated at
Selector-resolution time, closed vocabulary, for routine targeting only and never a valid
security-lane target — ADR-0034). Remediation and secret-distribution Selectors target
`relay:` labels only; engaging a quarantine may target `relay:` or `tag:`, lifting one `relay:`
only (ADR-0006, amended 2026-09-16). A stored Label must render as exactly one
Selector term, enforced as an allowlist rather than by example: the key is non-empty and
every byte of key and value is in `[A-Za-z0-9._-]`. A violating Label is refused at
ingress, never sanitised — sanitising would let the Relay itself manufacture a value
that matches a Selector nobody wrote. For node-space this is refused at Hello/Enroll
ingress (#504); for relay-space, the security-sensitive namespace, it is refused at
Enrollment Token mint and again when an already-minted token's scope is used to enroll
a Node (#555). The allowlist is deliberately narrower than the Selector parser, which
would accept `relay:tier=pci/1` — the hazard it guards is a term being re-rendered into
two, not a term failing to parse — so a Label stored before the gate can be refused now
and is also declined on read-back (threat model R13) — reported once per Relay startup
and counted on /metrics, per namespace (#565).
_Avoid_: tag (for the general concept — `tag:` names only the operator namespace), attribute,
annotation

**Facts**:
Descriptive properties a daemon self-reports about its Node (OS, kernel, hostname, IP,
installed packages). Inform decisions but are never used for targeting — that is the role of
Labels (see Label).
_Avoid_: metadata, attributes, properties

**Policy fingerprint**:
A hash of a Node's loaded Policy that the daemon reports (in `Hello` and every
`PolicySnapshot`) and the Relay records in the registry — fleet-wide Policy *drift visibility*
without the Policy itself ever traveling. Report-only: the Relay observes it but never sets a
Node's Policy (ADR-0002). Lets an operator confirm a Policy rollout landed everywhere by string
comparison against the registry (ADR-0002, ADR-0006).
_Avoid_: policy hash, checksum, policy version

**Template-set fingerprint**:
The Policy fingerprint's sibling for Template Operations (ADR-0021): a hash of the Node's
loaded template set, reported in `Hello` and every `TemplateSnapshot` and recorded in the
registry — fleet-wide template *drift visibility* without the templates themselves ever
traveling. Report-only: the Relay observes it but never sets a Node's templates. Empty means
no templates are installed; the literal `unloadable` means the Node's local template set
failed to load, so its template vocabulary is empty (fail closed).
_Avoid_: template hash, template version

**`outdated`**:
The registry and preflight flag for a Node whose daemon is **below the Relay's configured minimum
version**: it still connects, heartbeats and appears in the registry, but the Job engine refuses to
send it Tasks, reported per-Task as `OUTCOME_VERSION_REFUSED` (ADR-0014). Surfaced as
`state:outdated` (ADR-0034). It says nothing about Policy or template freshness — fingerprint
divergence is an observation read from the registry, never a flag.
_Avoid_: version-gated, stale, behind, out of date (for Policy or template drift — say
"a different Policy fingerprint")

**`unsupported`**:
The per-Node outcome for an Operation that is not in *that Node's* vocabulary — an unloaded
Template Operation, or an unknown name. Nothing executed and Policy was never consulted, so it
is neither a failure (nothing ran) nor a denial (the Node was never asked to decide). A Policy
preflight reports the same conclusion for the same Node. Vocabulary is per-Node once templates exist;
`list_operations`/`describe_node` report what a given Node actually has (ADR-0021).
_Avoid_: unknown operation, not found, unimplemented

**Enrollment Token**:
The reusable, scoped, expiring, revocable credential a daemon presents to join the fleet.
Distinct from a Node's identity certificate: the token authorizes *enrollment* and stamps
relay-space Labels; the certificate is the resulting *identity*. Can only enroll, never run
Operations.
_Avoid_: API key, secret, join key

**Join string**:
The one pasteable artifact that enrolls a Node: `glp_join_…`, encoding the Relay's enrollment
address, the **CA fingerprint** the daemon pins, and an **Enrollment Token** (ADR-0031, decision
3). It replaces supplying a CA bundle path and a token separately, and carries the `glp_` prefix
so a leak is greppable. **Decided, not yet built**: no code parses or renders one today, and the
daemon still verifies the Relay against a CA bundle file. A join string contains a live
Enrollment Token and is handled as a secret.
_Avoid_: join token, enrollment string, bootstrap string

**CA fingerprint**:
A hash of the Relay's CA certificate — the stable value an operator compares when trusting a
Relay, rendered on the Console's day-one screen and logged at startup. Distinct from the
**server certificate fingerprint**, which changes every time the server certificate rotates and
is never something to pin or compare (ADR-0031, decision 5). The third kind of fingerprint, beside
the Policy and template-set fingerprints; unlike them it describes the Relay, not a Node.
_Avoid_: cert hash, thumbprint, server fingerprint (a different, rotating value)

**Certificate renewal**:
A Node rotating its short-lived identity certificate before expiry over its existing mTLS
identity — no Enrollment Token — via the Relay's cert-authenticated `Renew` RPC. The Relay
issues a fresh certificate for the *same* node_id (derived from the verified peer cert, never
the CSR), preserving provenance; renewals are jittered to spread the fleet over time. Distinct
from *enrollment*: enrollment is token-authenticated and mints the first identity; renewal is
cert-authenticated and refreshes the existing one. (ADR-0006)
_Avoid_: re-enroll, reissue, cert refresh

**Server certificate rotation**:
The Relay *re-issuing* its own TLS server certificate from the in-process CA once the leaf
passes a jittered fraction of its lifetime — on the next handshake, with no restart, no
operator, and no network. Distinct from *Certificate renewal*, which is a Node refreshing its
identity certificate over the wire: rotation never leaves the Relay process, and each listener
rotates independently. The server leaf's lifetime is its own constant, never the Node identity
one — sharing it is what left the certificate expiring with nothing to renew it (ADR-0031 §5).
_Avoid_: server cert renewal, cert refresh

**Freeze**:
The Relay-wide emergency stop: halts all new Task dispatch (every risk class) while
leaving in-flight Tasks running and **Policy preflights** answerable. An approved **Plan**
gets no exemption: every advance is new dispatch, so a Freeze stops the next step and
leaves the current one running (ADR-0038). Cheap to engage — a **human**
`operator`+ Account via the Control API, or root on the Relay host via the host-side
lever — and deliberate to release (`admin`, with an audited reason). Engaging is the one
act in the system gated on an Account being human rather than on its role: a machine
Account is refused at every role, because an AI-agent halting the plane that supervises
it is a denial of service rather than a fire alarm, and automation that needs to stop
dispatch has the host lever. Persisted across Relay restarts (ADR-0013, amended by #397).
_Avoid_: pause, maintenance mode, lockdown, kill switch

**Cancellation**:
Stopping a single in-flight Task by its ID (`TaskCancel`): the daemon kills the Task's
process group and reports `OUTCOME_CANCELLED`. Best-effort and honest — a Task that already
finished reports its real outcome, never a retroactive cancel, and the cancelled Task ID stays
deduped, so at-most-once still holds. Narrower than Freeze, which halts *all* new dispatch
fleet-wide (ADR-0013).
_Avoid_: abort, kill, stop, interrupt

**Plan**:
An **approved route of execution**: an ordered list of steps an AI-agent proposes, a human
approves once, and the agent then walks one step at a time. Relay stores the route and a
monotonic **step cursor**; the agent advances by naming the Plan and the step it believes is
next, and **nothing else** — so the advance call carries no description of the work and there
is nothing in it to tamper with. The agent decides *whether* and *when* to continue; Relay
decides *what* runs (ADR-0038). One step is one **Job**, never a **Stage**. A Plan composes
nothing: each step is an independently Policy-evaluated, independently capped dispatch, and
the daemon never learns a Plan exists.
_Avoid_: script, program, workflow, runbook, playbook, batch, procedure; **plan mode** and
**dry-run** (the preview is **Policy preflight**, below)

**Policy preflight**:
The no-execution preview of a dispatch: the Relay resolves the Selector, checks
authorization and the blast-radius cap, and each matched daemon's live Policy engine
answers whether it *would* allow the action (ADR-0011). Advisory and point-in-time —
never a reservation, never a substitute for enforcement at execution. Called **plan mode**
until ADR-0038 gave that word to the Plan above; the option is still spelled `plan` on the
wire until the code follows.
_Avoid_: plan, plan mode (both now mean the route); dry-run, simulation, check mode — a
preflight never reaches an executor, it asks Policy a question

**Plan hash**:
The content address of a Plan — a hash over the ordered steps, their Operations and
arguments, and the *resolved fan-out*. It is what an Approval commits to (ADR-0027):
dispatch proceeds only if the Plan still hashes the same, and material drift re-parks for
re-approval. The fan-out is bound **by identity, never by count** — any Node not in the
approved set re-parks, while a Node that has left it is shrinkage, dropped and recorded
(ADR-0038). A single gated dispatch is the **one-step** case, which is how it was first
built and still how it behaves.
_Avoid_: job hash, checksum, fingerprint (reserved for the Policy, template-set and CA fingerprints)

**Shape key**:
The content address of *what* an approval is for, as opposed to *how much of it*: a hash
over the Operation, its risk class, its **shape arguments**, and the **normalised
Selector** — never the resolved fan-out, never an argument declared to be scale. Over a
multi-step **Plan** it addresses the route the same way, so "the last approved route that
looked like this" stays a lookup. For
**Raw Exec** every argv element is shape: there is nothing declared for the arbitrary-
command path, and which element is "scale" is never guessed. For an **Approval grant** it
hashes the **Scope** minus the window, the use limit and the fan-out ceiling. It exists so
"the last approved action of the same shape" is a lookup, which is what the approval
object's anti-fatigue diff needs (ADR-0027, D10). It is a grouping key and never a release
lookup: a dispatch proceeds only on a matching **Plan hash** or a claimed **Approval
grant**, never on a shape key. Which arguments are shape and which are scale is
**declared per Operation** in the Relay's Operation-vocabulary mirror, never inferred from
a value.
_Avoid_: plan hash (that is the fan-out-bearing one), fingerprint, similarity hash, group key

**Approval**:
A human decision that a specific parked Job may proceed, recorded against its Plan hash.
The Job waits in **`pending-approval`** until the Gate rule's requirement is satisfied or
its TTL expires. Relay authors what the approver sees, so the requesting AI-agent can
neither truncate nor spin it. The decision arrives by one of two paths: **out-of-band**, on
an authenticated Relay surface (Console or Control API) where the approver is verified; or
**in-band**, through the requesting client's MCP session (`approve_request`, or an MRTR
answer), where the approver is asserted and only as honest as the client (ADR-0027,
ADR-0029). An Approval **narrows** — it permits
one already-Policy-legal Plan to run. It is never authorization and can never widen what a
Node's Policy allows.
_Avoid_: authorization, permission, sign-off, confirmation (unqualified — name the rung)

**Decision**:
One recorded answer to a parked Job — who decided, when, over which **channel**, against
which Plan hash, and whether a human decided. An Approval is *satisfied* by a set of
Decisions from **distinct** Accounts (quorum means distinct deciders); one denying Decision
is terminal, mirroring Policy's deny-beats-allow. Every Decision is its own audit record,
including a denial and including the first of two, so partial quorum is never an absence in
the trail.
_Avoid_: vote, approval (for the individual answer — the Approval is the whole requirement
being met), response

**Bulk decision**:
Several Decisions made together in one act in the Admin Console, under one step-up. Not a
new kind of Decision and not an Approval grant: each request is answered against its own
Plan hash, checked and audited on its own, and a refused one does not carry the others with
it. Approval grant requests cannot be bulk-approved (`docs/specs/approval.md`).
_Avoid_: batch, batch approval (a batch is an Approval grant — ADR-0027), blanket approval

**Channel** (of a Decision):
How strongly a Decision's delivery path is trusted. **`in-band`** means the answer came
back over the same MCP session that requested the action, so it is only as trustworthy as
the harness; **`out-of-band`** means it landed on an authenticated Relay endpoint carrying a
credential the requesting session does not hold. In-band is an *assumption about the
client*; out-of-band is *evidence*. Set by the surface that receives the Decision, never by
the caller, and checked as a floor: a stronger channel satisfies a weaker requirement,
never the reverse (ADR-0027).
_Avoid_: transport (reserved for the gRPC/mTLS node plane), delivery envelope (that is
*how* an approver is reached, not how strongly their answer is trusted)

**Gate rule**:
One rule in the Relay's root-owned approval-gate configuration, matching on risk class,
blast size, Selector namespace, principal, and Operation, and requiring a `count`,
`audience`, `requester_allowed`, `channel`, and `ttl`. File-only and above the AI's reach,
like the blast cap (invariant 11). Narrows only: a Gate rule can demand approval where none
was demanded, never grant what Policy refuses.
_Avoid_: approval policy (collides with **Policy**), approval rule, gate config (for a
single rule)

**Approval grant**:
One human Approval covering a **described, bounded set of future dispatches** — where a
**Plan** covers an *enumerated* one, and that difference is the whole distinction between
them —
decision 12's time-boxed narrowing grant (ADR-0027). Always written in full: an unqualified
**Grant** is the authorization rule above, and the two are unrelated mechanisms.

Where an Approval binds to a **Plan hash**, an Approval grant binds to a **Scope** (the
requesting Account, risk class, an Operation allow-list, a fan-out *ceiling*; no Selector
namespace since 2026-09-16, ADR-0027) plus a **window** and a **use limit**. Those walls are its entire
security argument, so every one of them is mandatory and an unbounded Scope cannot be
stored. It exists because fatigue is a security property: forty elicitations produce forty
rubber stamps, and a rubber-stamped Approval is worse than none.

Requesting one is *not* being granted one — it creates an ordinary Approval whose subject
is a Scope, answered on the same channel with the same quorum, audience, requester
exclusion, and channel floor. What it costs to approve is derived from the Gate rules at
the Scope's widest admissible dispatch, so it is never a cheaper path than the work it
replaces. Every dispatch it releases audits to the same approval ID. **The ask is its own
audit record**, separate from a single dispatch parking for approval (#546): the two are
answered the same way but their blast radii are not comparable, and a trail that files
them together says an ask for standing authority over many future dispatches is the same
act as one enumerated route waiting for one answer. (Both are standing authority once
answered; a Grant's walls are described and a Plan's contents are listed, which is why a
Grant never releases a Plan — ADR-0038.)
_Avoid_: Grant (unqualified), batch approval / blanket approval (a grant is neither
blanket nor unbounded), standing approval, pre-authorization

**Scope** (of an Approval grant):
The wall around an Approval grant. The **dual** of a Gate rule's match: on a match an
omitted field gates *more* dispatches (the safe direction) and `min_fan_out` is a floor; on
a Scope an omitted field would cover *more* (the unsafe direction) and `max_fan_out` is a
**ceiling**. Never build one from the other.
_Avoid_: match, filter, selector (reserved for Node targeting)

**MCP task handle**:
MCP's own async primitive (SEP-2663): a handle returned in place of a result for one
outstanding `tools/call`, which the client polls via `tasks/get`. It is a *delivery
envelope* for an Approval, never an execution unit. Always written in full; "task" alone
means a Relay **Task**.

Relay mints **one handle per parked dispatch**, not per Job — a parked dispatch creates no
Job at all, and the Job arrives later if an approval releases it, or never. A handle is
owner-only and expires; one that is not yours reads exactly like one that never existed.

Two things a handle deliberately is not. It is not a decision channel: no `tasks/*`
method accepts an approval, and `tasks/cancel` ends the *client's* interest while leaving a still-
parked Approval pending and decidable — an in-band Decision arrives only through
`approve_request` or an MRTR answer, never a `tasks/*` method (ADR-0028, ADR-0029). And it is
not required: a client that knows nothing
about Tasks drives the same gated dispatch to completion on the universal path, so nothing
may come to depend on a handle existing.

Relay serves the extension itself, as a shim, because its SDK does not implement it
(ADR-0028). The shim is temporary by design and has a written removal condition.
_Avoid_: task (unqualified), MCP task, job handle, task id (when a Relay **Task** is also in
play)

**MRTR** (Multi Round-Trip Requests):
MCP's stateless pattern (SEP-2322, protocol 2026-07-28) for a server that needs input
mid-call: the server answers `tools/call` with an input-required result and ends the
request; the client obtains the input and retries the call carrying it. Relay's use is
**MRTR elicitation** — a Relay-authored approval question on a gated call, answered in-band
with an asserted approver, through the same decision path as `approve_request` (ADR-0029
decision 6). Replaces server-initiated `elicitation/create`, which 2026-07-28 removed.
_Avoid_: elicitation (unqualified — say which form), held elicitation

**Relay-side authorization**:
The central rules deciding which Account may send which Operations to which Nodes.
Distinct from Policy: authorization governs *who may ask*, Policy governs *what a Node
will ever do*.
_Avoid_: permissions, RBAC (when ambiguous with Policy)

**Grant**:
A Relay-side authorization rule: which Account may request which Operations (or Raw
Exec) against which Selector. Deny-by-default. Grants are runtime objects managed via
the Control API and Admin Console — unlike **Policy**, which is Node-rooted and never
managed centrally. A Grant can only *narrow* what may run, never widen it: execution
requires both a Grant (Relay-side, "may this Account ask") and Policy allowance
(Node-side, "will this Node ever do it"), and the Node's Policy always has the last
word. Unqualified, "Grant" always means this one; the approval mechanism's is an
**Approval grant**, always written in full.
_Avoid_: policy (reserved for the Node-side document), permission, ACL, rule

**Account**:
A named identity — human or machine — with a role, to which every credential binds: a
human's password or OIDC identity, a machine's API Tokens. The AI-agent authenticates as
a machine Account. The three roles are an ordered ladder, each adding to the one below:
**`viewer`** may read but dispatch nothing; **`operator`** may additionally run
structured Operations; **`admin`** may additionally use Raw Exec and administer the
control plane. Raw Exec being admin-only is enforced centrally, in the capability
layer's Authorizer, so every surface inherits it — it decides who may *ask* for the
arbitrary-command path, while Node Policy still governs every command that arrives.
The unit of Relay-side
authorization and of audit attribution across all three surfaces (ADR-0010). An Account
is a *durable identity*; a token is a *revocable credential for one* — disabling the
Account and revoking one of its tokens are different acts with different blast radii.
The **founding admin** is the Account the config-seeded control-plane credential
resolves to: a real, stored, listable Account, not a special case. In code, the
capability layer's `Principal` **is** the acting Account (its ID, name, and role at the
time it authenticated); the identifier lags the glossary, the meaning does not.
_Avoid_: user, principal, service account (say "machine Account")

**API Token**:
A bearer credential bound to an Account, used by machines (and the AI-agent via MCP) to
call the Control API. Named, revocable, optionally expiring, stored only as a hash, and
inheriting its Account's role. It carries the fixed prefix **`glp_`** — a security
feature, not branding: it is what makes a leaked token greppable in a repository, a
paste, or a CI log, and what secret scanners key on. The plaintext is shown exactly
once, at mint; there is no recovery, only re-mint plus revoke. Distinct from an
**Enrollment Token**, which joins Nodes to the fleet and can never call the API, and from
an **OAuth session**, which is how a *human* authenticates.
_Avoid_: API key, PAT, bearer token (unqualified)

**OAuth session**:
A control-plane session a human establishes through the organization's own IdP, using
MCP's standard OAuth 2.1 layer, resolving to their Account (ADR-0024). Relay is a
**protected resource only** — it validates tokens, and is never an authorization server.
A session's authority is its Account's role, exactly like an API Token's. Crucially, an
OAuth session buys **attribution and revocation, not trust**: it proves a human authorized
the *session*, not that a human intended each *call*, so MCP-originated calls stay
agent-grade for approval gating whoever authorized them.
_Avoid_: login, SSO session, user session (say OAuth session), "authenticated human"

**Attribution**:
Who an audited action is recorded as coming from, in **two structurally distinct lanes**
(ADR-0010, `docs/design/approval-and-attribution.md`). The **verified lane** is what the
Relay authenticated itself — the acting Account, its role at that moment, and the API
Token presented. The **asserted lane** is what the caller *claimed*: `on_behalf_of` (a
free-form user or team), a session reference, a change reference, and the W3C
`traceparent`. Asserted values are bounded, stored verbatim, and **never an authorization
input** — a jailbroken AI-agent can assert anything and forge nothing. They are still
worth recording: for an honest orchestrator the asserted lane is the join key back to the
harness's own session logs, where the literal instruction lives. Keeping the lanes apart
is load-bearing — blurring them is how an audit trail becomes fiction.
_Avoid_: "the principal" (for the pair), user id, requester (unqualified — say verified or
asserted)

**Capability layer**:
The single Relay-side layer that decides — authorization, Selector resolution, the
blast-radius cap, dispatch, and audit — and the only path to any of them. Every interface is
an adapter over it (ports and adapters, with this layer as the core): the MCP surface, the
Control API and the Admin Console today, and anything added later. Each adapter exposes this
layer and may **narrow** what it offers; none may widen it, reimplement any part of it, or
decide. So what may be done, who may do it, and how it is recorded are settled here rather than
once per interface (ADR-0009, ADR-0010; invariant 10). It renders nothing
and speaks no wire format; an adapter that decides anything itself is a bug, guarded
structurally in the Console's case by `no_dispatch`. Its outbound collaborators are injected
seams — Authorizer, CapChecker, AuditSink, FreezeStore, Conduit — so the layer depends on
interfaces it defines rather than on the packages that satisfy them. Each capability it
exposes is the unit one **capability specification** in `docs/specs/` describes, which is why
a capability spec is true of every surface at once.
_Avoid_: service layer, business logic, core, the backend, "the service"

**Control API**:
The REST/JSON surface (`/api/v1`, OpenAPI-described) through which humans' tooling and
machines drive the control plane — both administration and execution. One of the three
user-facing surfaces (with the MCP surface and the Admin Console), all thin adapters
over the same capability layer; the Control API is the programmable superset
(ADR-0010). It never reaches the Relay's own configuration, which is a root-owned
local file.
_Avoid_: REST API (unqualified), admin API, "the API" (in docs; fine in speech)

**System Model**:
The Relay-maintained graph that links Nodes and Labels into higher-order Services,
Dependencies, and Annotations, giving the AI-agent a persistent, shared understanding of the
fleet. Stored as git-backed YAML; advisory to execution, never authoritative.
_Avoid_: topology, CMDB, knowledge base, map

**Service**:
A named grouping in the System Model defined by a Selector over Labels — how related Labels
are linked into a meaningful unit (e.g. "payments"). Desugars to a Selector for execution.
_Avoid_: app, group, cluster

**Dependency**:
A directed relationship in the System Model between Services (e.g. "payments depends on
postgres-primary"), letting the AI-agent reason about ripple effects and impact.
_Avoid_: link, edge, relation

**Annotation**:
Free-text notes attached to any System Model entity by the AI-agent or a human, carrying
provenance. Descriptive context only, never used for targeting.
_Avoid_: comment, note, tag

**Admin Console**:
The human-facing web UI for operators to observe the fleet, administer the control plane
(enrollment lifecycle, revocation, registry/audit views), and — from v0.7.0 — execute:
Operations and Raw Exec run from the Console, preflight-by-default and with step-up re-auth
on a mutate apply, behind the root-owned `console_execution` flag (ADR-0026, superseding
ADR-0009's no-execution scope). A thin adapter over the same operator capability layer as
the MCP surface (ADR-0003, ADR-0009); it renders decisions, it never makes them. Distinct
from the **AI-agent**, which drives the Relay over MCP.
_Avoid_: dashboard, portal, admin panel, "the UI"

**Step-up re-authentication**:
Re-proving human presence by re-entering a credential against the session's own Account,
without ending the session. Gates privilege-granting actions (ADR-0009) and every `mutate`
apply on the Admin Console (ADR-0026 decision 3) and `relay:`-label management (invariant
7). Its window — how recently is "recent enough" — is file-only Relay configuration no
Account may widen over the wire (invariant 11). Recorded as its own event, distinct from a
sign-in: a hijacked session grinding at the step-up prompt is a different incident from an
anonymous caller grinding at the sign-in form, because the step-up door is reachable only
from an already-authenticated session. A refused or throttled step-up is likewise its own
event, distinct from a refused or throttled sign-in, for the same reason.
_Avoid_: re-auth, sudo mode, 2FA, MFA, confirmation (unqualified — name the rung)

**Event seam**:
The Relay's one in-process pub/sub (`internal/events`) feeding the Admin Console's live
views: exactly four publishers — registry transitions, Job transitions, MCP tool calls,
and enrollment attempts — with monotonic IDs over per-publisher bounded ring buffers
(1,000 events or 10 minutes, whichever first), `Last-Event-ID` resume, and a `gap` event
the seam emits rather than fabricate continuity. It carries tool-call ARGUMENTS and never
read RESULTS (ADR-0025) — enforced structurally, not by convention: the package imports
nothing but the standard library. Memory-only; nothing here is persisted. Subscribing to it
is itself an audited read (`watch_events`, one `KindRead` record per subscription, naming
the kinds asked for — ADR-0025).
_Avoid_: event stream, notifications, the firehose, pubsub
