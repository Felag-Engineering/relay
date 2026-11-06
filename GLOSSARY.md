# Glossary

The canonical vocabulary of this project: the word to use in code, comments, commits, issue
titles, test names and prose. Most terms carry an `_Avoid_` line naming rejected synonyms;
those are decisions, not suggestions. What Relay is and why is in [README.md](README.md); the
invariants are in [AGENTS.md](AGENTS.md).

**Gleipnir** is a different project: the first-party AI-agent system that drives Relay, a
*consumer* of Relay (over MCP and the Control API), never a component of it. The repo was
`gleipnir-relay`; it and the Go module are `relay` (ADR-0016 holds the internal-naming boundary).

## Language

**Relay**:
The central server: it accepts relay-daemon connections, routes Operations to Nodes, returns results
and exposes the tool surface the AI-agent uses. **Control plane** names the layer (the Relay with its
three surfaces), never the Relay binary, a Node or the daemon.
_Avoid_: hub, server, master

**relay-daemon**:
The non-AI daemon on each managed Node: it dials home to the Relay, holds a persistent connection
and executes Operations subject to local Policy.
_Avoid_: agent, thrall, client, minion

**AI-agent**:
The AI orchestrator that administers the fleet with the Relay as one of its tools; never the
relay-daemon. **Gleipnir** is the first-party AI-agent system: to Relay it is an AI-agent
authenticating as a machine Account, granted nothing other AI-agents can't have.
_Avoid_: agent (unqualified), AI, brain, operator, Gleipnir (for the role — Gleipnir
is one AI-agent system, not the role itself)

**Node**:
A managed Linux server that runs a relay-daemon.
_Avoid_: host, machine, target

**Operation**:
A typed administrative action from a declared vocabulary: a **Native Operation** (in the daemon,
frozen at four, ADR-0021) or a **Template Operation**. Each declares a **risk class**, `read` (cannot
change Node state) or `mutate`, which sets its blast cap and never replaces Policy (ADR-0012).
_Avoid_: command, task

**Template Operation**:
An Operation defined by an operator-authored shell template with named, type-validated slots whose
values are passed as arguments, never parsed as shell text (invariant 1; ADR-0001 tier 2, ADR-0021);
Policy governs it like a Native one. It loads from the **Template root**. A **template pack** is a
directory installed as a unit; the **shipped read catalog** is the first-party one (ADR-0053).
_Avoid_: script, macro, custom command, snippet

**Raw Exec**:
The escape hatch: arbitrary command execution, permitted only when it matches a Node's regex-based
Policy, for what the Operation vocabulary cannot express (invariant 1). Always `mutate` (ADR-0012).
_Avoid_: shell, command string

**Policy**:
The per-Node rules that decide whether an Operation or Raw Exec may run on that Node: enforced by
the relay-daemon, queryable by the Relay, never changeable over the wire (invariant 2). The last
line of defense.
_Avoid_: ACL, ruleset, permissions

**Policy fragment**:
One file in a Node's Policy directory, beside the Policy file, written by config management and never
over the wire. The daemon composes the Policy file and every fragment into one Policy with one
fingerprint; a rule's source file shows only in error messages (`policy.md`).
_Avoid_: policy file (for a single fragment), policy module, snippet, include

**Catalog fragment**:
Cut from the MVP with the **Policy Catalog**: a first-party, opt-in Policy fragment an operator would
pick by name and hand to config management (`roadmap: relay/policy-catalog-and-live-reload`).
_Avoid_: preset, profile, playbook, role, pack (a **template pack** is a different thing)

**Policy Catalog**:
Cut from the MVP (`roadmap: relay/policy-catalog-and-live-reload`): a library of catalog fragments
and a Console screen to arrange and export them, ending at the clipboard (invariant 2). Unrelated to
the **shipped read catalog**, which is a template pack.
_Avoid_: Policy Author (the screen's former name), policy editor, policy store

**Cohort** (Policy Catalog):
Cut with the **Policy Catalog**: a named set of Nodes that would run the same catalog fragments, held
by no Relay record and never a Selector or a Label. Unrelated to the "emergency cohorts" of ADR-0006.
_Avoid_: group (unqualified), fleet segment, tier

**Canonical form**:
The single spelling a value is reduced to, or must already be in, before Policy matches it: deny-side,
purely lexical, never widening an allow. A **path argument** must already be canonical (absolute, no
`.`, `..` or empty segment, no trailing slash; case and Unicode never folded) or Policy denies it
(ADR-0018). A Raw Exec command's **canonical elements** are its joined argv re-split on Unicode
whitespace, which the deny pass matches beside the joined command and raw argv elements (ADR-0019).
_Avoid_: normalized form, sanitizing, cleaning (and don't say "canonical" for the
*joined* Raw Exec command — that is the joined form)

**Job**:
A single dispatch of an Operation or Raw Exec across the Nodes matched by a Selector.
Comprises one Task per matched Node and is the unit of audit and blast-radius control.
_Avoid_: batch, run, execution

**Stage**:
The persistence layer between a Job and its Tasks: an ordered set of Tasks, exactly one per Job in v1,
so staged rollout needs no data migration. Not operator-facing, and not a step of a Gleipnir **Plan**:
a Stage orders Tasks within one Operation's fan-out.
_Avoid_: phase, wave, step

**Task**:
The execution of one Operation or Raw Exec on one Node, within a Job's Stage. It carries a unique ID
for at-most-once execution (invariant 4) and reports its own outcome. Not an **MCP task handle**.
_Avoid_: command, unit, step; "task" unqualified in any context where MCP is also in play

**Selector**:
An expression over Node Labels that picks a set of Nodes (e.g. `role=web, env=prod`); a single Node
is a Selector that matches one. `state:` terms are derived at resolution time (ADR-0034); every other
namespace matches stored Labels.
_Avoid_: filter, query, target spec

**Label**:
A key/value pair on a Node that Selectors match, in one of four namespaces, each with one writer
(invariant 7; ADR-0020): `node:` (the Node and its config management, trusted only as much as the Node),
`relay:` (the Relay, as the side effect of a defined action; the only remediation target), `tag:` (a **Tag**)
and `state:` (Relay-derived, written by nobody; ADR-0034). A stored Label is one Selector term (every byte in
`[A-Za-z0-9._-]`), refused at ingress, never sanitised; stricter than the Selector grammar (threat model R13).
_Avoid_: tag (for the general concept — `tag:` names only the operator namespace), attribute,
annotation

**Tag**:
A `tag:key=value` **Label** a person puts on a Node to group it (ADR-0050), written and audited only
by a human Account at `operator` or above, never by an AI-agent, a machine Account or the Node. It
never changes what a gate rule matches. An **initial tag** is one an Enrollment Token's mint names.
_Avoid_: operator label, custom label, Node tag

**Facts**:
Descriptive values a daemon self-reports about its Node (OS, kernel, hostname, IP, installed
packages). They inform decisions and are never used for targeting, which is what Labels are for.
_Avoid_: metadata, attributes, properties

**Policy view**:
The display-only copy of a Node's effective Policy that its relay-daemon last reported, with the
Policy fingerprint and a Relay-stamped receipt time. A report, never a live query and never an input
to a verdict (invariant 12); Template command bodies are not part of it (ADR-0021).
_Avoid_: Policy snapshot (that is the wire message the view is built from), cached Policy

**Policy fingerprint**:
A hash of a Node's loaded Policy that the daemon reports (in `Hello` and every `PolicySnapshot`) and
the Relay records: fleet-wide drift visibility without the Policy traveling. Report-only (ADR-0002,
ADR-0006); a human may name one with a **Policy alias**.
_Avoid_: policy hash, checksum, policy version

**Policy alias**:
A display-only name, such as "web-hardened", a human `admin` gives one Policy fingerprint on this
Relay (`query.md`). Always shown beside the full fingerprint; never a Selector term, a decision input
or Policy, never sent to a Node (invariant 2), and it marks no Policy as desired (invariant 9). The
Console's per-render letter for an unaliased fingerprint is not one.
_Avoid_: policy name, policy label (a Label is something else), policy version

**Template root**:
The root-owned directory on a Node from which the relay-daemon loads its Template Operations, never
written by the daemon or the Relay (ADR-0021). The shipped read catalog installs into it with the
daemon package, beside an operator's own Templates.
_Avoid_: templates dir, template directory, the templates.d (as a noun)

**Template-set fingerprint**:
The Policy fingerprint's sibling for Template Operations: a hash of the Node's loaded template set,
reported in `Hello` and every `TemplateSnapshot` (ADR-0021). Report-only. Empty means none installed;
`unloadable` means the set failed to load, so the Node's template vocabulary is empty (fail closed).
_Avoid_: template hash, template version

**`outdated`**:
The registry and preflight flag for a Node whose daemon is below the Relay's minimum version: it
connects and appears in the registry but is sent no Tasks (`OUTCOME_VERSION_REFUSED`, ADR-0014;
`state:outdated`, ADR-0034). It says nothing about Policy or template fingerprint divergence.
_Avoid_: version-gated, stale, behind, out of date (for Policy or template drift — say
"a different Policy fingerprint")

**`unsupported`**:
The per-Node outcome for an Operation not in that Node's vocabulary (an unloaded Template or an
unknown name): nothing ran and Policy was never consulted, so it is neither failure nor denial.
Reported by the daemon, or by the Relay for a Node it leaves out of a Template dispatch (ADR-0042).
_Avoid_: unknown operation, not found, unimplemented

**Enrollment Bundle**:
Retired (ADR-0048): Relay renders no install artifact. A minted join string is shown once, and each
release ships an Ansible role.
_Avoid_: enrollment kit, onboarding package

**Enrollment Token**:
The expiring, revocable credential a daemon presents to join the fleet, use-limited unless minted
for unlimited use. It authorizes *enrollment* and writes any **initial tags** its mint names
(ADR-0050); the Node's identity certificate is the resulting *identity*. It can never run Operations.
_Avoid_: API key, secret, join key

**Join string**:
The one pasteable artifact that enrolls a Node: `glp_join_` plus the base64url of the versioned
`JoinString` message, carrying the Relay address, the **CA fingerprint** the daemon pins before it
sends the token, and an **Enrollment Token** (ADR-0031). Handled as a secret; consumed by
`relay-daemon join` and persisted nowhere (ADR-0033; `daemon-installation.md` DI-43).
_Avoid_: join token, enrollment string, bootstrap string

**CA fingerprint**:
A hash of the Relay's CA certificate: the stable value an operator compares when trusting a Relay,
shown on the Console's day-one screen and logged at startup. Unlike the **server certificate
fingerprint**, which changes on every rotation, it is pinned and compared (ADR-0031).
_Avoid_: cert hash, thumbprint, server fingerprint (a different, rotating value)

**Certificate renewal**:
A Node refreshing its short-lived identity certificate before expiry over its existing mTLS identity,
with no Enrollment Token, via the `Renew` RPC. The Relay issues a fresh certificate for the same
node_id, taken from the verified peer cert, never the CSR (ADR-0006). Enrollment mints the first one.
_Avoid_: reissue, cert refresh; "re-enroll" only for a fresh enrollment under a new token
after revocation, never for renewal

**Server certificate rotation**:
The Relay re-issuing its own TLS server certificate from its in-process CA once the leaf passes a
jittered fraction of its lifetime, with no restart. Unlike *Certificate renewal*, rotation never
leaves the Relay process; one certificate serves both listeners (ADR-0031).
_Avoid_: server cert renewal, cert refresh

**Quarantine**:
Fencing a distrusted Node off from routine work. Engaging one only ever *reduces* what may run and
may target `relay:` or `tag:` Labels; lifting one targets `relay:` only (invariant 7). Cut from the
MVP (`roadmap: relay/quarantine`); the `state:quarantined` marker is Relay-derived and read-only.
_Avoid_: isolate, cordon, drain (Kubernetes senses), blacklist

**Freeze**:
The Relay-wide emergency halt of all new Task dispatch; in-flight Tasks run on and Policy preflights
stay answerable, and it persists across restarts (ADR-0013). Engaged by a *human* `operator`+
Account, never a machine one, or by root on the Relay host; released by `admin` with an audited reason.
_Avoid_: pause, maintenance mode, lockdown, kill switch

**Cancellation**:
Ending one in-flight Task by its ID (`TaskCancel`): the daemon terminates its process group and
reports `OUTCOME_CANCELLED`. Best-effort: a finished Task reports its real outcome and the ID stays
deduped, so at-most-once holds. Narrower than a Freeze (ADR-0013).
_Avoid_: abort, kill, stop, interrupt

**Plan**:
Gleipnir's word for a series of tool calls, with branches, that Gleipnir submits to its **Harness**
to carry out one call at a time. Not a Relay object (ADR-0049): each call reaching Relay is an
ordinary dispatch decided alone; Relay's own check before a call runs is the **Policy preflight**.
_Avoid_: script, program, workflow, runbook, playbook, batch, procedure (each for anything Relay
stores or runs)

**Harness**:
The program an **AI-agent** runs in, such as Gleipnir's runtime, Claude Code or Codex. It holds the
MCP session and credential, sends tool calls and puts approval questions before a person, which Relay
trusts and cannot verify (threat model R14, R21). Approval text calls it the *requesting client*.
_Avoid_: wrapper

**Policy preflight**:
The no-execution preview of a dispatch: the Relay resolves the Selector and checks authorization and
the blast cap, and each matched daemon's live Policy engine answers whether it *would* allow it
(ADR-0011, ADR-0038). Advisory and point-in-time, never a reservation; spelled `plan` on the wire.
_Avoid_: plan, plan mode; dry-run, simulation, check mode — a preflight never reaches an
executor, it asks Policy a question

**Plan hash**:
The content address of one gated dispatch (ADR-0027): what an Approval commits to, so a dispatch
that no longer hashes the same parks again (`approval.md`). Spelled `plan_hash`; the *plan* in it
has no multi-step reading (ADR-0049).
_Avoid_: job hash, checksum, fingerprint (reserved for the Policy, template-set and CA fingerprints)

**Shape key**:
A content address of *what* an approval was for, leaving out the resolved fan-out. **Relay has
none** (ADR-0047): a request is addressed only by its ID and its **Plan hash** (`approval.md`).
_Avoid_: plan hash (that is the fan-out-bearing one), fingerprint, similarity hash, group key

**Approval**:
A human decision that a specific parked **Request** may proceed, recorded against its Plan hash.
Parking creates no Job: the Request waits in `pending-approval` until its Gate rule is satisfied or
its TTL expires (ADR-0027, ADR-0028). Relay authors what the approver sees; the answer arrives
out-of-band on the Control API (approver verified) or in-band as an MRTR answer (approver asserted,
ADR-0029). It only narrows: it never widens what a Node's Policy allows.
_Avoid_: authorization, permission, sign-off, confirmation (unqualified — name the rung)

**Decision**:
One recorded answer to a parked **Request**, never to a Job: who decided, when, over which
**channel**, against which Plan hash, and how the decider was identified. The first accepted
Decision ends the request, releasing or denying it (ADR-0047); each is its own audit record.
_Avoid_: vote, approval (for the individual answer — the Approval is the whole requirement
being met), response

**Bulk decision**:
Several Decisions made together in one act. **Relay has none** (ADR-0044; `approval.md` AP-59). If
it returns it is never a new kind of Decision and never an Approval grant.
_Avoid_: batch, batch approval (a batch is an Approval grant — ADR-0027), blanket approval

**Channel** (of a Decision):
The surface a Decision arrived on: **`in-band`**, an answer on the requesting client's retried MCP
call, or **`out-of-band`**, the Control API decision endpoint. Set by the receiving surface, never
the caller, and recorded on every Decision; no gate rule demands one (ADR-0047).
_Avoid_: transport (reserved for the gRPC/mTLS node plane), delivery envelope (that is
*how* an approver is reached, not how strongly their answer is trusted)

**Confirmation ladder**:
The two rungs a gate gives (ADR-0047): **no gate**, the request runs at once, and **self-confirmation**,
the requester's own side confirms (a human reviewing what Relay rendered, or the person answering an
MCP request's elicited question). A machine Account never confirms its own request on its own authority.
_Avoid_: confirmation (unqualified — name the rung), approval tier. In **new** prose name the
rung rather than numbering it; ADR-0027 decision 5 numbers them and ADR-0028, ADR-0029 and
`docs/operations/approval-gates.md` cite "rung 2", and that numbering stands wherever it is
already written or quoted.

**Token-session answer**:
An elicited approval answer on an **API Token** session, recorded as that Account's decision and
marked as such, distinct from an OAuth session's verified decision (`approval.md`; threat model R45).
_Avoid_: verified answer (that is the OAuth session's)

**Responder assertion**:
The claim a client attaches to an **MRTR elicitation** answer that a human, not the model, produced
it. Relay checks only that it is present and that the sealed state binds the answer to this caller,
request, plan and call; it cannot check the claim, so it records it in the **asserted** lane (see
*Attribution*). An OAuth-session answer needs none and ignores one; an API Token-session answer
needs none and records one if sent (`approval.md` AP-79; threat model R21, R45).
_Avoid_: human flag, responder flag, human-in-the-loop token

**Sealed request state**:
The opaque, tamper-sealed token Relay hands a client with an **MRTR elicitation** question and
requires back on the retry, bound to the calling Account, the approval Request, the Plan hash and
that call. It proves which question is being answered and carries no authority (`approval.md`).
_Avoid_: continuation token, resume handle, elicitation cookie ("nonce" keeps its ordinary
OAuth and CSP sense elsewhere and is not reserved here)

**Security floor**:
The configuration that bounds *who may authenticate and how recently they proved it*: listeners,
CA/TLS, auth bootstrap, the identity provider, session and step-up windows, the approval
notification path. Set outside Relay by whoever administers its host, in a file the Relay only reads
(ADR-0043); nothing Relay runs or accepts can write it (invariant 11). Contrast reach settings (blast
caps, gate rules, the minimum daemon version), which a human may change with step-up.
_Avoid_: hard limits, static config (both also describe operator settings)

**Requester exclusion**:
A gate-rule term, `requester_allowed`, that barred the requester from deciding their own
request. Retired by ADR-0047: a gate rule naming it is refused at load.
_Avoid_: self-approval ban, four-eyes (a count, not an exclusion)

**Gate rule**:
One `[[approval.rules]]` section of the Relay configuration file: it matches on risk class, fan-out,
Selector namespace, Account, Operation or Raw Exec, and carries a TTL (ADR-0047). With none, nothing
is gated; no API Token or MCP tool reaches one. It narrows only, never granting what Policy refuses.
_Avoid_: approval policy (collides with **Policy**), approval rule, gate config (for a
single rule)

**Approval grant**:
One human Approval that covered a bounded set of future dispatches. **Relay has none** (ADR-0047;
`approval.md` AP-84): every gated dispatch parks on its own, and old audit records keep their grant
ID. Always written in full: an unqualified **Grant** is Relay-side authorization, an unrelated thing.
_Avoid_: Grant (unqualified), batch approval / blanket approval (a grant is neither
blanket nor unbounded), standing approval, pre-authorization

**Scope** (of an Approval grant):
The wall around an Approval grant, which Relay does not have (AP-84). Never build one from a Gate
rule's conditions.
_Avoid_: match, filter, selector (reserved for Node targeting)

**MCP task handle**:
MCP's own async primitive (SEP-2663): a handle returned in place of a result for one outstanding
`tools/call`, which the client polls. **Relay returns none** (ADR-0047; `approval.md` AP-85). Always
written in full; "task" alone means a Relay **Task**.
_Avoid_: task (unqualified), MCP task, job handle, task id (when a Relay **Task** is also in
play)

**MRTR** (Multi Round-Trip Requests):
MCP's stateless pattern (SEP-2322) for mid-call input: the server answers `tools/call` with an
input-required result and ends the request; the client retries carrying the input. Relay's use is
**MRTR elicitation**, an approval question Relay authors, answered in-band by an asserted approver
(ADR-0029, ADR-0047).
_Avoid_: elicitation (unqualified — say which form), held elicitation

**Relay-side authorization**:
The central rules deciding which Account may send which Operations to which Nodes.
Distinct from Policy: authorization governs *who may ask*, Policy governs *what a Node
will ever do*.
_Avoid_: permissions, RBAC (when ambiguous with Policy)

**Grant**:
A Relay-side authorization: which Account may request which Operations, or Raw Exec, against which
Selector. Deny-by-default, a runtime object managed through the Control API and Admin Console. It only
narrows: execution needs a Grant and Policy, and Policy has the last word. See **Approval grant**.
_Avoid_: policy (reserved for the Node-side document), permission, ACL, rule

**Account**:
A named identity, human or machine, with a role, to which every credential binds; the unit of Relay-side
authorization and audit attribution (ADR-0010). Roles ladder: **`viewer`** may read but dispatch nothing,
**`operator`** may additionally run structured Operations, **`admin`** may additionally use Raw Exec and
administer the control plane. Relay seeds no Account and reserves no name; the **founding admin** is the
first human `admin`, named at `relay init` (ADR-0030). A token is a revocable credential for an Account.
_Avoid_: user, principal, service account (say "machine Account")

**API Token**:
A bearer credential bound to an Account, human or machine: named, revocable, optionally expiring,
hashed at rest, shown once, with its Account's role and a `glp_` prefix that makes a leak greppable.
Unlike an **Enrollment Token**, it calls the Control API. Distinct from an **OAuth session**, a human's
IdP-backed session.
_Avoid_: API key, PAT, bearer token (unqualified)

**Temporary password**:
The first Console password of a human Account an `admin` creates: Relay-generated, shown to that
admin once, valid for 72 hours and good only for the change-password form, so the admin never learns
the password the person sets (ADR-0045). The founding admin has none; there is no password reset.
_Avoid_: initial password, one-time password, OTP (an authenticator code), reset password

**OAuth session**:
A control-plane session a human establishes through the organization's own IdP over MCP's OAuth 2.1
layer, resolving to their Account; Relay is a protected resource only, never an authorization server
(ADR-0024). It buys attribution and revocation, not trust: MCP calls on it stay agent-grade for
gating, but an approval answer on it is that human's verified decision (`approval.md` AP-79). It proves
who owns the session, not that a human read the question.
_Avoid_: login, SSO session, user session (say OAuth session), "authenticated human"

**Principal**:
The verified identity a request runs as: the Account the capability layer resolved from the presented
credential, with its role and kind. Every capability-layer decision takes one, and no adapter builds
one from anything but the verified lane. Distinct from the asserted `on_behalf_of` (see Attribution).
_Avoid_: user, caller (for the verified identity), "the principal" for the verified-plus-asserted pair

**Attribution**:
Who an audited action is recorded as coming from, in two distinct lanes (ADR-0010). The **verified
lane** is what Relay authenticated: the acting Account, its role then and the presented API Token.
The **asserted lane** is what the caller claimed (`on_behalf_of`, session and change references,
`traceparent`): bounded, stored verbatim, and never an authorization input.
_Avoid_: "the principal" (for the pair), user id, requester (unqualified — say verified or
asserted)

**Capability layer**:
The single Relay-side layer that decides authorization, Selector resolution, the blast-radius cap,
dispatch and audit, and the only path to them. Every interface is an adapter over it that may narrow,
never widen, reimplement or decide (invariant 10; ADR-0009, ADR-0010).
_Avoid_: service layer, business logic, core, the backend, "the service"

**Control API**:
The REST/JSON surface (`/api/v1`, OpenAPI-described) through which tooling and machines drive the
control plane: one of the three surfaces, an adapter over the capability layer and its programmable
superset (ADR-0010). It never writes Relay configuration or reaches the security floor (invariant 11).
_Avoid_: REST API (unqualified), admin API, "the API" (in docs; fine in speech)

**System Model**:
Retired unbuilt (ADR-0051): a shared record of Services, Dependencies and Annotations any AI-agent
could rewrite. Invariant 9 constrains any fleet model Relay keeps (see **Fleet model**).
_Avoid_: topology, CMDB, knowledge base, map

**Fleet model**:
Any record Relay keeps of how the fleet fits together: advisory, never a desired-state spec, and
constrained by invariant 9 (ADR-0051). Relay keeps none in the MVP (`roadmap: relay/fleet-topology`).
_Avoid_: CMDB, inventory model

**Service**, **Dependency**, **Annotation**:
Retired with the System Model (ADR-0051).
_Avoid_: app, group, cluster (use a **Tag** to group Nodes)

**Admin Console**:
The human-facing web UI for observing the fleet and administering the control plane: enrollment,
Accounts, tokens, Tags, Policy aliases, registry and audit. A thin adapter over the capability layer
(ADR-0003, ADR-0009) that runs no command on any Node (ADR-0052) and has no approval surface (ADR-0044).
_Avoid_: dashboard, portal, admin panel, "the UI"

**Step-up re-authentication**:
Re-proving human presence by re-entering a credential against the session's own Account, without
ending the session; it gates privilege-granting actions (ADR-0009, ADR-0045). Its window is security
floor (invariant 11). Each step-up, refused or throttled ones too, is its own event, never a sign-in.
_Avoid_: re-auth, sudo mode, 2FA, MFA, confirmation (unqualified — name the rung)

**Event seam**:
The Relay's one in-process, memory-only pub/sub feeding the Admin Console's live views from four
publishers (registry, Job, MCP tool-call, enrollment), resuming with a `gap` event, never faked
continuity. It carries tool-call arguments, never read results, and subscribing is audited (ADR-0025).
_Avoid_: event stream, notifications, the firehose, pubsub
