# Relay

**Relay** is a fleet-administration control plane — this project. Non-AI daemons on
managed Linux servers dial home to a central server and hold a persistent connection
open; through that connection the central server can run administrative actions on the
servers. An AI orchestrator drives the whole fleet by using the Relay as a tool,
while per-server policy restricts what may actually run — defense in depth.

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
_Avoid_: phase, wave

**Task**:
The execution of one Operation or Raw Exec on a single Node, as part of a Job (within a
Stage). Carries a unique ID for at-most-once execution and reports an independent outcome.
Not to be confused with an **MCP task handle** (see below), which is a different thing at a
different layer.
_Avoid_: command, unit, step; "task" unqualified in any context where MCP is also in play

**Selector**:
A label-based query that targets a set of Nodes (e.g. `role=web, env=prod`). Operations
and Raw Exec fan out to every matching Node and return a per-Node result. A single Node is
just a Selector that matches one.
_Avoid_: filter, query, target spec

**Label**:
A key/value tag on a Node used by Selectors to target it. Lives in one of three
non-overlapping namespaces, each immutable from the other sides: **node-space** (`node:…`,
rooted on the Node and set out-of-band via config management; the Relay records but never
modifies or removes them; authoritative for routine targeting, trusted only as much as the
Node), **relay-space** (`relay:…`, set by the Relay — stamped at enrollment or managed
post-enrollment by an `admin` with step-up — and immutable to the Node; reserved for the
security-sensitive lane), or **tag-space** (`tag:…`, set by operators through the control
plane with standard auth; immutable to the Node; ad-hoc grouping and routine targeting only,
never a valid security-lane target — ADR-0020). Remediation/quarantine and secret-distribution
Selectors target `relay:` labels only.
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

**`unsupported`**:
The per-Node outcome for an Operation that is not in *that Node's* vocabulary — an unloaded
Template Operation, or an unknown name. Nothing executed and Policy was never consulted, so it
is neither a failure (nothing ran) nor a denial (the Node was never asked to decide). Plan mode
reports the same conclusion for the same Node. Vocabulary is per-Node once templates exist;
`list_operations`/`describe_node` report what a given Node actually has (ADR-0021).
_Avoid_: unknown operation, not found, unimplemented

**Enrollment Token**:
The reusable, scoped, expiring, revocable credential a daemon presents to join the fleet.
Distinct from a Node's identity certificate: the token authorizes *enrollment* and stamps
relay-space Labels; the certificate is the resulting *identity*. Can only enroll, never run
Operations.
_Avoid_: API key, secret, join key

**Certificate renewal**:
A Node rotating its short-lived identity certificate before expiry over its existing mTLS
identity — no Enrollment Token — via the Relay's cert-authenticated `Renew` RPC. The Relay
issues a fresh certificate for the *same* node_id (derived from the verified peer cert, never
the CSR), preserving provenance; renewals are jittered to spread the fleet over time. Distinct
from *enrollment*: enrollment is token-authenticated and mints the first identity; renewal is
cert-authenticated and refreshes the existing one. (ADR-0006)
_Avoid_: re-enroll, reissue, cert refresh

**Freeze**:
The Relay-wide emergency stop: halts all new Task dispatch (every risk class) while
leaving in-flight Tasks running and Plans available. Cheap to engage (`operator`+ via
the Control API, or locally on the Relay host), deliberate to release (`admin`, with an
audited reason). Persisted across Relay restarts (ADR-0013).
_Avoid_: pause, maintenance mode, lockdown, kill switch

**Cancellation**:
Stopping a single in-flight Task by its ID (`TaskCancel`): the daemon kills the Task's
process group and reports `OUTCOME_CANCELLED`. Best-effort and honest — a Task that already
finished reports its real outcome, never a retroactive cancel, and the cancelled Task ID stays
deduped, so at-most-once still holds. Narrower than Freeze, which halts *all* new dispatch
fleet-wide (ADR-0013).
_Avoid_: abort, kill, stop, interrupt

**Plan**:
The no-execution preview of a Job: the Relay resolves the Selector, checks
authorization and the blast-radius cap, and each matched daemon's live Policy engine
answers whether it *would* allow the action (ADR-0011). Advisory and point-in-time —
never a reservation, never a substitute for enforcement at execution.
_Avoid_: dry-run, simulation, preview, check mode

**Plan hash**:
The content address of a Plan — a hash over the Operation, its arguments, and the
*resolved fan-out*. It is what an Approval commits to (ADR-0027): dispatch proceeds only
if the Plan still hashes the same, and material drift re-parks the Job for re-approval.
_Avoid_: job hash, checksum, fingerprint (reserved for Policy and template-set fingerprints)

**Approval**:
A verified human decision that a specific parked Job may proceed, recorded against its
Plan hash. The Job waits in **`pending-approval`** until the Gate rule's requirement is
satisfied or its TTL expires. Relay authors what the approver sees, so the requesting
AI-agent can neither truncate nor spin it; the decision arrives on an authenticated
channel, never through the MCP session (ADR-0027). An Approval **narrows** — it permits
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
One human Approval covering a **bounded set of future dispatches** instead of one Plan —
decision 12's time-boxed narrowing grant (ADR-0027). Always written in full: an unqualified
**Grant** is the authorization rule above, and the two are unrelated mechanisms.

Where an Approval binds to a **Plan hash**, an Approval grant binds to a **Scope** (the
requesting Account, risk class, an Operation allow-list, a fan-out *ceiling*, optionally a
Selector namespace) plus a **window** and a **use limit**. Those walls are its entire
security argument, so every one of them is mandatory and an unbounded Scope cannot be
stored. It exists because fatigue is a security property: forty elicitations produce forty
rubber stamps, and a rubber-stamped Approval is worse than none.

Requesting one is *not* being granted one — it creates an ordinary Approval whose subject
is a Scope, answered on the same channel with the same quorum, audience, requester
exclusion, and channel floor. What it costs to approve is derived from the Gate rules at
the Scope's widest admissible dispatch, so it is never a cheaper path than the work it
replaces. Every dispatch it releases audits to the same approval ID.
_Avoid_: Grant (unqualified), batch approval / blanket approval (a grant is neither
blanket nor unbounded), standing approval, pre-authorization

**Scope** (of an Approval grant):
The wall around an Approval grant. The **dual** of a Gate rule's match: on a match an
omitted field gates *more* dispatches (the safe direction) and `min_fan_out` is a floor; on
a Scope an omitted field would cover *more* (the unsafe direction) and `max_fan_out` is a
**ceiling**. Never build one from the other.
_Avoid_: match, filter, selector (reserved for Node targeting)

**MCP task handle**:
MCP's own async primitive: a handle returned in place of a result for one long-running
`tools/call`, which the client polls, and which can carry a server-to-client elicitation
while the work is outstanding. Relay maps **one MCP task handle to one Job** — it is a
*delivery envelope* for an Approval, never an execution unit. Always written in full;
"task" alone means a Relay **Task**.
_Avoid_: task (unqualified), MCP task, job handle
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
Operations and Raw Exec run from the Console, plan-by-default and with step-up re-auth
on a mutate apply, behind the root-owned `console_execution` flag (ADR-0026, superseding
ADR-0009's no-execution scope). A thin adapter over the same operator capability layer as
the MCP surface (ADR-0003, ADR-0009); it renders decisions, it never makes them. Distinct
from the **AI-agent**, which drives the Relay over MCP.
_Avoid_: dashboard, portal, admin panel, "the UI"
