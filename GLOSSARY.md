# Glossary

The canonical vocabulary of this project: the word to use in code, comments, commits, issue
titles, test names and prose. Most terms carry an `_Avoid_` line naming rejected synonyms;
those are decisions, not suggestions. What Relay is and why is in [README.md](README.md); the
invariants are in [AGENTS.md](AGENTS.md).

**Gleipnir** is a different project: the first-party AI-agent system that drives Relay, a
*consumer* of Relay (over MCP and the Control API), never a component of it. The repo was
`gleipnir-relay` until 2026-10; it and the Go module are now `relay` (ADR-0016, amended
2026-10-15, holds the internal-naming boundary).

## Language

**Relay**:
The central server. Accepts relay-daemon connections, routes Operations to Nodes, returns
results, and exposes the tool surface the AI-agent uses. **Control plane** names the layer (the
Relay with its three surfaces), never the Relay binary, a Node or the daemon.
_Avoid_: hub, server, master

**relay-daemon**:
The non-AI daemon installed on each managed Node. Dials home to the Relay, holds
a persistent connection, and executes Operations subject to local Policy.
_Avoid_: agent, thrall, client, minion

**AI-agent**:
The AI orchestrator that administers the fleet using the Relay as one of its tools.
Explicitly *not* the relay-daemon. **Gleipnir** is the first-party AI-agent system; to Relay it
is an AI-agent authenticating as a machine Account, granted nothing other AI-agents can't have.
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
An Operation defined by an operator-authored shell template with named, type-validated
parameter slots: the tier between Native Operations and Raw Exec (ADR-0001 tier 2, realized by
ADR-0021). The author fixes the command structure; substitution can never alter it. Mandatory
risk class; governed by Policy exactly like a Native Operation. Loaded from root-owned local
files beside the Policy file (same trust root, ADR-0002); the daemon reports a **template-set
fingerprint** beside the Policy fingerprint. A directory of templates installed and versioned
as a unit is a **template pack**; the first-party **shipped read catalog** is one, shipped inside
the `relay-daemon` package as package-owned files and allowed by the default Policy (ADR-0053). A Node
without a given template reports the distinct `unsupported` outcome.
_Avoid_: script, macro, custom command, snippet

**Raw Exec**:
The escape hatch: arbitrary command execution, permitted only when it matches a
Node's regex-based Policy. Exceptional path for what the Operation vocabulary
cannot express.
_Avoid_: shell, command string

**Policy**:
The per-Node rules that decide whether an Operation or Raw Exec may run on that Node.
Locally-rooted and remotely-immutable: enforced by the relay-daemon, queryable by the Relay,
never changeable over the wire. The last line of defense.
_Avoid_: ACL, ruleset, permissions

**Policy fragment**:
One file in a Node's Policy directory, beside the Policy file. The daemon composes the Policy
file and every fragment into one Policy with one Policy fingerprint; which file a rule came from
affects only error messages (`docs/specs/policy.md`, `docs/specs/daemon-installation.md`).
Written by config management, never over the wire.
_Avoid_: policy file (for a single fragment), policy module, snippet, include

**Catalog fragment**:
Cut from the MVP with the **Policy Catalog** (`roadmap: relay/policy-catalog-and-live-reload`):
a first-party, opt-in Policy fragment an operator would pick by name and hand to config
management. The MVP's fragments are the operator's own files in the Policy directory.
_Avoid_: preset, profile, playbook, role, pack (a **template pack** is a different thing)

**Policy Catalog**:
Cut from the MVP (`roadmap: relay/policy-catalog-and-live-reload`): a library of catalog
fragments and a Console screen to arrange and export them. Would end at the clipboard: the Relay
never writes, sends or signs a Node's Policy (invariant 2). Unrelated to the **shipped read
catalog**, which is a template pack.
_Avoid_: Policy Author (the screen's former name), policy editor, policy store

**Cohort** (Policy Catalog):
Cut with the **Policy Catalog** (`roadmap: relay/policy-catalog-and-live-reload`): a named group
of Nodes that would run the same catalog fragments. It would be held by no Relay record and never
be a Selector or a Label. Unrelated to the "emergency cohorts" of
ADR-0006, a security-lane idea nothing yet defines.
_Avoid_: group (unqualified), fleet segment, tier

**Canonical form**:
The single normalized spelling a value is reduced to, or required to already be in, before
Policy matches it, so one thing has one representation for an operator's rules. Two
instances, both deny-side and purely lexical (no I/O):
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
(enforced in code and schema), so post-1.0 staged rollout lands without a data migration. Not
operator-facing.

A Stage is **not** a step of a Gleipnir **Plan**: a Stage orders batches *within one
Operation's fan-out* (canary → remainder), where each Plan step is its own dispatch.
_Avoid_: phase, wave, step

**Task**:
The execution of one Operation or Raw Exec on a single Node, as part of a Job (within a
Stage). Carries a unique ID for at-most-once execution and reports an independent outcome.
Not to be confused with an **MCP task handle** (see below), which is a different thing at a
different layer.
_Avoid_: command, unit, step; "task" unqualified in any context where MCP is also in play

**Selector**:
A query over Node Labels that targets a set of Nodes (e.g. `role=web, env=prod`). Operations
and Raw Exec fan out to every matching Node and return a per-Node result; a single Node is a
Selector that matches one. `state:` terms are Relay-derived and evaluated at resolution time
(ADR-0034); every other namespace matches stored Labels.
_Avoid_: filter, query, target spec

**Label**:
A key/value tag on a Node used by Selectors to target it. Lives in one of four
non-overlapping namespaces, each immutable from the other sides: **node-space** (`node:…`,
rooted on the Node: the daemon declares `node:hostname`, `node:os` and `node:arch` by default and
config management sets the rest out-of-band, overriding a default by key; the Relay records but never
modifies or removes them; authoritative for routine targeting, trusted only as much as the
Node), **relay-space** (`relay:…`, set by the Relay — stamped at enrollment, or written as the
side effect of a defined Relay action, today only enrollment's `relay:node-id`, never by an
Account directly — and
immutable to the Node; reserved for the security-sensitive lane), or **tag-space** (`tag:…`, a
**Tag**, set by a human Account at `operator` or above through the Console or the Control API,
never by an AI-agent or the Node; grouping and routine targeting, and a valid target for
*engaging* a quarantine only — ADR-0020, ADR-0050), or **state-space** (`state:…`, derived by the Relay
from the registry, set by nobody — not the Node, not an operator, not an `admin` — evaluated at
Selector-resolution time, closed vocabulary, for routine targeting only and never a valid
security-lane target — ADR-0034). Remediation and secret-distribution Selectors target
`relay:` labels only; engaging a quarantine may target `relay:` or `tag:`, lifting one `relay:`
only (ADR-0006, amended 2026-09-16). A stored Label must render as exactly one Selector
term, enforced as an allowlist: the key is non-empty and every byte of key and value is in
`[A-Za-z0-9._-]`. A violating Label is refused at ingress, never sanitised, since sanitising
would let the Relay manufacture a value matching a Selector nobody wrote. Node-space is refused
at Hello/Enroll ingress; tag-space when a Tag is written, at Enrollment Token mint, and again
when a minted token's initial tags enroll a Node. The allowlist is deliberately narrower than the
Selector parser (which
accepts `relay:tier=pci/1`): it guards against a term re-rendering into two. A Label stored
before the gate is declined on read-back (threat model R13), reported once per Relay startup
and counted on /metrics, per namespace.
_Avoid_: tag (for the general concept — `tag:` names only the operator namespace), attribute,
annotation

**Tag**:
A `tag:key=value` **Label** a person puts on a Node to group it, such as `tag:env=prod`
(ADR-0050). Written only by a human Account at `operator` or above, on the Console's Node page,
in bulk over the Nodes a Selector matches, or through the Control API; never by an AI-agent, a
machine Account or the Node, and audited with old and new values. An **initial tag** is one a
join token's mint names, written on each Node the token enrolls and editable afterwards. A tag
never changes what a gate rule matches.
_Avoid_: operator label, custom label, Node tag

**Facts**:
Descriptive properties a daemon self-reports about its Node (OS, kernel, hostname, IP,
installed packages). Inform decisions but are never used for targeting — that is the role of
Labels (see Label).
_Avoid_: metadata, attributes, properties

**Policy view**:
The display-only copy of a Node's effective Policy that the relay-daemon last reported (raw
patterns, allowed Operations, operation and deny rules, the Policy fingerprint and, on MCP,
whether Raw Exec is enabled), shown by `describe_node`, the Console Node detail and the Compare
screen with its Relay-stamped receipt time. A report, never a live query and never an input to
a verdict: the Relay evaluates nothing (invariant 12). Template command bodies are not part of
it (ADR-0021).
_Avoid_: Policy snapshot (that is the wire message the view is built from), cached Policy

**Policy fingerprint**:
A hash of a Node's loaded Policy that the daemon reports (in `Hello` and every
`PolicySnapshot`) and the Relay records: fleet-wide Policy *drift visibility* without the
Policy ever traveling. Report-only; the Relay never sets a Node's Policy (ADR-0002). An operator
confirms a Policy rollout landed everywhere by comparing it across the registry (ADR-0006). A
human may name one with a **Policy alias**.
_Avoid_: policy hash, checksum, policy version

**Policy alias**:
A human-readable name a human `admin` gives one Policy fingerprint on this Relay — "web-hardened"
— so that people can say which Policy they mean (`docs/specs/query.md`). Display only: always shown
beside the full fingerprint, never a Selector term or filter value, never an input to Policy
evaluation or any other decision, and never Policy — the Relay holds it and never sends it to a
Node (invariant 2). It attaches to a fingerprint, never to a Node or group, so it marks no Policy
as desired (invariant 9). The Console's per-render letter for an unaliased fingerprint is not one.
_Avoid_: policy name, policy label (a Label is something else), policy version

**Template root**:
The directory on a Node from which the relay-daemon loads its Template Operations,
`/etc/relay-daemon/templates.d/`, root-owned and never written by the daemon or the Relay
(ADR-0021). The shipped read catalog installs into it with the daemon package; an operator's own Templates
sit beside them.
_Avoid_: templates dir, template directory, the templates.d (as a noun)

**Template-set fingerprint**:
The Policy fingerprint's sibling for Template Operations (ADR-0021): a hash of the Node's
loaded template set, reported in `Hello` and every `TemplateSnapshot` and recorded in the
registry. Report-only; the Relay never sets a Node's templates. Empty means none installed; the
literal `unloadable` means the local template set failed to load, so its template vocabulary is
empty (fail closed).
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
The per-Node outcome for an Operation not in *that Node's* vocabulary: an unloaded Template
Operation, or an unknown name. Nothing executed and Policy was never consulted, so it is
neither a failure nor a denial. It is daemon-reported, or Relay-reported for a Node left out of
a Template dispatch because it does not report that Template or has reported no vocabulary,
and so is never sent a Task (ADR-0042). A Policy preflight reports the same for the same Node.
`list_operations`/`describe_node` report what a given Node actually has (ADR-0021).
_Avoid_: unknown operation, not found, unimplemented

**Enrollment Bundle**:
Retired by ADR-0048: Relay renders no install artifact. A minted join string is shown once, apart
from the command that consumes it, and each release ships an Ansible role.
_Avoid_: enrollment kit, onboarding package

**Enrollment Token**:
The expiring, use-limited, revocable credential a daemon presents to join the fleet. Distinct
from a Node's identity certificate: the token authorizes *enrollment* and writes any **initial
tags** its mint names on each Node it enrolls (ADR-0050), beside the `relay:node-id` every
enrollment stamps; the certificate is the resulting *identity*. Can only enroll, never run Operations.
_Avoid_: API key, secret, join key

**Join string**:
The one pasteable artifact that enrolls a Node: `glp_join_` followed by the unpadded base64url
of the versioned `JoinString` message in `/proto`, which carries the Relay address Nodes dial,
the **CA fingerprint** the daemon pins, and an **Enrollment Token** (ADR-0031, decision 3,
amended 2026-10-16). It replaces supplying a CA bundle path and a token separately, and carries
the `glp_` prefix so a leak is greppable. Minting an Enrollment Token returns one, and a Node
enrolls by it, pinning the CA fingerprint before it sends the token. A join string contains a
live Enrollment Token and is handled as a secret. Where it reaches a Node it is consumed by
`relay-daemon join`, which enrolls in the process that read it, and is persisted nowhere
(ADR-0031 and ADR-0033, amended 2026-10-21); until that lands the daemon reads it from
`RELAY_JOIN` in its root-owned environment file, inert once the Node holds an identity.
_Avoid_: join token, enrollment string, bootstrap string

**CA fingerprint**:
A hash of the Relay's CA certificate: the stable value an operator compares when trusting a
Relay, shown on the Console's day-one screen and logged at startup. Distinct from the **server
certificate fingerprint**, which changes on every rotation and is never pinned or compared
(ADR-0031, decision 5). Unlike the Policy and template-set fingerprints, it describes the
Relay, not a Node.
_Avoid_: cert hash, thumbprint, server fingerprint (a different, rotating value)

**Certificate renewal**:
A Node rotating its short-lived identity certificate before expiry over its existing mTLS
identity, with no Enrollment Token, via the cert-authenticated `Renew` RPC. The Relay issues a
fresh certificate for the *same* node_id (from the verified peer cert, never the CSR),
preserving provenance; renewals are jittered across the fleet. Enrollment is token-authenticated
and mints the first identity; renewal is cert-authenticated and refreshes it (ADR-0006).
_Avoid_: reissue, cert refresh; "re-enroll" only for a fresh enrollment under a new token
after revocation, never for renewal

**Server certificate rotation**:
The Relay *re-issuing* its own TLS server certificate from the in-process CA once the leaf
passes a jittered fraction of its lifetime, on the next handshake, with no restart, operator or
network. Unlike *Certificate renewal* (a Node refreshing its identity over the wire), rotation
never leaves the Relay process. There is one server certificate, presented by both listeners,
so it rotates once for both (ADR-0031 §1). The server leaf's lifetime is its own constant,
never the Node identity one (ADR-0031 §5).
_Avoid_: server cert renewal, cert refresh

**Quarantine**:
Fencing a distrusted Node off from routine work. Engaging one only ever *reduces* what may
run and may target `relay:` or `tag:` labels; lifting one targets `relay:` only (invariant 7).
Cut from the MVP (`roadmap: relay/quarantine`): revoking a Node and the Freeze cover the
urgent case. The `state:quarantined` marker is Relay-derived and read-only.
_Avoid_: isolate, cordon, drain (Kubernetes senses), blacklist

**Freeze**:
The Relay-wide emergency stop: halts all new Task dispatch (every risk class) while
leaving in-flight Tasks running and **Policy preflights** answerable. Every step of a
Gleipnir **Plan** is new dispatch, so a Freeze stops the next one and leaves the current one
running. Cheap to engage (a **human** `operator`+ Account via the
Control API, or root on the Relay host) and deliberate to release (`admin`, with an audited
reason). Engaging is the one act gated on an Account being human rather than on its role: a
machine Account is refused at every role, because an AI-agent halting the plane that
supervises it is a denial of service, not a fire alarm; automation has the host lever.
Persisted across Relay restarts (ADR-0013, as amended).
_Avoid_: pause, maintenance mode, lockdown, kill switch

**Cancellation**:
Stopping a single in-flight Task by its ID (`TaskCancel`): the daemon kills the Task's
process group and reports `OUTCOME_CANCELLED`. Best-effort and honest: a finished Task reports
its real outcome, and the cancelled Task ID stays deduped, so at-most-once holds. Narrower than
Freeze, which halts *all* new dispatch (ADR-0013).
_Avoid_: abort, kill, stop, interrupt

**Plan**:
Gleipnir's word: a series of tool calls, with branches, that Gleipnir determines and submits to
the **Harness**, which carries it out one call at a time. Not a Relay object (ADR-0049): each call
that reaches Relay is an ordinary dispatch, decided alone, and Relay cannot tell that calls belong
to one Plan. Relay's own check before a call runs is the **Policy preflight**.
_Avoid_: script, program, workflow, runbook, playbook, batch, procedure (each for anything Relay
stores or runs)

**Harness**:
The program an **AI-agent** runs in, such as Gleipnir's runtime, Claude Code or Codex: it holds
the MCP session and its credential, sends the AI-agent's tool calls to Relay, puts Relay's approval
questions in front of a person, and, for Gleipnir, carries out its **Plan** one call at a time. Relay
trusts it to route questions to a person and to run the route that person saw, and cannot verify
either (threat-model R21, R14).
Approval text calls it the *requesting client*, which is accepted for this role.
_Avoid_: wrapper

**Policy preflight**:
The no-execution preview of a dispatch: the Relay resolves the Selector, checks
authorization and the blast-radius cap, and each matched daemon's live Policy engine answers
whether it *would* allow the action (ADR-0011). Advisory and point-in-time, never a
reservation or a substitute for enforcement. Formerly **plan mode**, renamed by ADR-0038, a
rename ADR-0049 keeps; the option is still spelled `plan` on the wire.
_Avoid_: plan, plan mode; dry-run, simulation, check mode — a preflight never reaches an
executor, it asks Policy a question

**Plan hash**:
The content address of one gated dispatch, defined by ADR-0027 decision 8: what an Approval
commits to, so a dispatch that no longer hashes the same parks again (`approval.md` AP-20 to
AP-22). Spelled `plan_hash` on the wire; the word *plan* in it is historical and has no
multi-step reading (ADR-0049).
_Avoid_: job hash, checksum, fingerprint (reserved for the Policy, template-set and CA fingerprints)

**Shape key**:
The content address of *what* an approval is for, as opposed to *how much of it*: a hash
over the Operation, its risk class, its **shape arguments**, and the **normalised
Selector**, never the resolved fan-out or an argument declared to be scale. For **Raw Exec** every argv element is
shape: nothing is declared for the arbitrary-command path, and "scale" is never guessed. For an
**Approval grant** it hashes the **Scope** minus the window, the use limit and the fan-out
ceiling. It exists so "the last approved action of the same shape" is a lookup, which the
approval object's anti-fatigue diff needs (ADR-0027, D10). It is a grouping key and never a release
lookup: a dispatch proceeds only on a matching **Plan hash** or a claimed **Approval
grant**, never on a shape key. Which arguments are shape and which are scale is
**declared per Operation** in the Relay's Operation-vocabulary mirror, never inferred from
a value.
_Avoid_: plan hash (that is the fan-out-bearing one), fingerprint, similarity hash, group key

**Approval**:
A human decision that a specific parked **Request** may proceed, recorded against its plan
hash. **Parking creates no Job**: the gate sits before the dispatcher, so the Request waits,
and a Job is minted only if a decision releases one (ADR-0027 decision 1 as amended
2026-09-24; ADR-0028 §Amendment 2026-08-17). The Request waits in **`pending-approval`** until
the Gate rule's requirement is satisfied or its TTL expires. Relay authors what the approver
sees, so the requesting AI-agent can neither truncate nor spin it. The decision arrives
**out-of-band**, on the Control API's authenticated decision endpoint, where the approver is
verified (the Admin Console has no approval surface, ADR-0044); or **in-band**, through the
requesting client's MCP session (`approve_request`, or an MRTR answer), where the approver is
asserted and only as honest as the client (ADR-0027, ADR-0029). An Approval **narrows**: it
permits one already-Policy-legal dispatch to run, and can never widen what a Node's Policy allows.
_Avoid_: authorization, permission, sign-off, confirmation (unqualified — name the rung)

**Decision**:
One recorded answer to a parked **Request** (never to a Job; parking mints none): who
decided, when, over which **channel**, against which Plan hash, and whether a human decided.
An Approval is *satisfied* by Decisions from **distinct** Accounts; one denying Decision is
terminal, mirroring deny-beats-allow. Every Decision is its own audit record, a denial and the
first of two included, so partial quorum is never an absence in the trail.
_Avoid_: vote, approval (for the individual answer — the Approval is the whole requirement
being met), response

**Bulk decision**:
Several Decisions made together in one act. **Relay has none**: it was retired unbuilt on
2026-10-18 with the Console's approval surface (ADR-0044; `docs/specs/approval.md`, AP-59 under
*Retired*). The entry stays so the word keeps its meaning if it returns (never a new kind of
Decision, never an Approval grant) and so *batch* keeps its _Avoid_.
_Avoid_: batch, batch approval (a batch is an Approval grant — ADR-0027), blanket approval

**Channel** (of a Decision):
How strongly a Decision's delivery path is trusted. **`in-band`**: the answer came back over
the MCP session that requested the action, so it is only as trustworthy as the harness.
**`out-of-band`**: it landed on an authenticated Relay endpoint with a credential the
requesting session does not hold. In-band is an *assumption about the client*; out-of-band is
*evidence*. Set by the receiving surface, never the caller, and checked as a floor: a stronger
channel satisfies a weaker requirement, never the reverse (ADR-0027).
_Avoid_: transport (reserved for the gRPC/mTLS node plane), delivery envelope (that is
*how* an approver is reached, not how strongly their answer is trusted)

**Confirmation ladder**:
The three rungs a Gate rule selects between, named so that "confirmation" unqualified never
has to be (ADR-0027 decision 5). **No gate** — below the rule's thresholds; the request runs
immediately. **Self-confirmation** — the requester's own side confirms: a human reviewing what
Relay rendered, or, for an MCP request, an in-band answer carrying an asserted approver. A
machine Account can never reach this rung on its own authority; the one relaxation is
ADR-0029's, and it records an assertion rather than a verified human. **Second-person** — the
audience excludes the requester, so the decider is someone else. A rung says *who must answer*;
the **Channel** says *how strongly the answer is trusted*, and the two are set independently.
_Avoid_: confirmation (unqualified — name the rung), approval tier. In **new** prose name the
rung rather than numbering it; ADR-0027 decision 5 numbers them and ADR-0028, ADR-0029 and
`docs/operations/approval-gates.md` cite "rung 2", and that numbering stands wherever it is
already written or quoted.

**Responder assertion**:
The claim a client attaches to an **MRTR elicitation** answer that a *human*, and not the
model, produced it — the thing that distinguishes an answered question from a machine-composed
one. Relay checks only that it is present and that the answer's sealed state is bound to this
caller, request, plan and call; it cannot check that the claim is true. It is not the only way
an in-band answer is accepted: any answer on a human Account's **OAuth session** needs none, and
is that human's verified decision whatever the client calls itself; on such a session a responder
assertion, if sent, is ignored and not recorded (`docs/specs/approval.md` AP-79). From the MVP
an answer on an **API Token** session needs none either, and counts as that session's Account's
decision (ADR-0047, amended 2026-10-23; threat model R45); the assertion, if sent, is recorded.
Recorded in the **asserted** lane, never the verified one (see *Attribution*): "a client told
us a human answered", never "a human authenticated to Relay". The in-band honesty residual
rests on it (`docs/specs/approval.md`; threat model R21).
_Avoid_: human flag, responder flag, human-in-the-loop token

**Sealed request state**:
The opaque token Relay hands a client with an **MRTR elicitation** question and requires back
on the retried call. Sealed against tampering and **bound to four things** (the calling
Account, the approval Request, the Plan hash and that call), so a state altered, replayed
against another request, presented by another Account, carried on another call, or expired is
refused. It carries no authority: it proves which question is being answered, never that the
answer may be accepted, which stays the gate's decision (`docs/specs/approval.md`).
_Avoid_: continuation token, resume handle, elicitation cookie ("nonce" keeps its ordinary
OAuth and CSP sense elsewhere and is not reserved here)

**Security floor**:
The configuration that bounds *who may authenticate and how recently they proved it*:
listeners, CA/TLS, auth bootstrap, the identity provider, session and step-up windows, the
approval notification path. Set by whoever administers the Relay's
host, outside Relay, in one configuration file the Relay reads itself (ADR-0043); nothing Relay
runs or accepts can write it — no API, no request, and not the Relay process (invariant 11). Contrast
**operator settings**, which merely bound reach and may live in the store.
_Avoid_: hard limits, static config (both also describe operator settings)

**Requester exclusion**:
The Gate-rule term (`requester_allowed: false`) under which the Account that requested a gated
dispatch may not be among its approvers (ADR-0027). Enforced identically on every decision path.
_Avoid_: self-approval ban, four-eyes (a count, not an exclusion)

**Gate rule**:
One rule in the Relay's approval-gate configuration, matching on risk class, blast size,
Selector namespace, Principal and Operation, and requiring a `count`, `audience`,
`requester_allowed`, `channel` and `ttl`. Today an optional root-owned file loaded at startup
(no gate at all when none is configured); designed to become a store-backed operator setting
only a human `admin` edits, with step-up re-authentication, audited (ADR-0027 amendments of
2026-09-15/16; the reach-bounding class of invariant 11). Never reachable from an API Token or
an MCP tool. Narrows only: it can demand approval, never grant what Policy refuses.
_Avoid_: approval policy (collides with **Policy**), approval rule, gate config (for a
single rule)

**Approval grant**:
One human Approval covering a **described, bounded set of future dispatches**. It is decision 12's
time-boxed narrowing grant (ADR-0027). Always written in full: an unqualified **Grant** is the
authorization rule below, an unrelated mechanism.

Where an Approval binds to a **Plan hash**, an Approval grant binds to a **Scope** (the
requesting Account, risk class, an Operation allow-list, a fan-out *ceiling*, and today an
explicit **Raw Exec opt-in**; no Selector namespace since 2026-09-16, ADR-0027) plus a
**window** and a **use limit**. Today the opt-in is accepted and priced at the `admin` role
floor and the window's hard maximum is 24 hours; designed to become a Scope that may not cover
Raw Exec at all, under a 4-hour maximum (ADR-0027 §Amendment 2026-09-24;
`docs/specs/approval.md`). Those walls are its entire
security argument, so every one of them is mandatory and an unbounded Scope cannot be
stored. It exists because fatigue is a security property: forty elicitations produce forty
rubber stamps, and a rubber-stamped Approval is worse than none.

Requesting one is *not* being granted one — it creates an ordinary Approval whose subject
is a Scope. Today it is answered on the same channel with the same quorum, audience, requester
exclusion and channel floor as any other request; designed to become a floor rather than an
equality, so that a grant is issued only by **second-person, out-of-band** approval however
lenient the Gate rules are (ADR-0027 §Amendment 2026-09-24). What it costs to approve is derived from the Gate rules at
the Scope's widest admissible dispatch, so it is never a cheaper path than the work it
replaces. Every dispatch it releases audits to the same approval ID. **The ask is its own
audit record**, separate from a single dispatch parking for approval: the two are answered the
same way but their blast radii are not comparable.
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

Relay mints **at most one handle per parked dispatch**, never per Job (a parked dispatch
creates no Job). *At most*, because a park that emits an answerable **MRTR elicitation**
question emits no task envelope: elicitation wins (ADR-0028 §Amendment 2026-09-24). A handle is
owner-only and expires; one that is not yours reads exactly like one that never existed.

A handle is not a decision channel: no `tasks/*` method accepts an approval, and
`tasks/cancel` ends the *client's* interest while leaving a parked Approval pending and
decidable; an in-band Decision arrives only through `approve_request` or an MRTR answer
(ADR-0028, ADR-0029). Nor is it required: a client that knows nothing about Tasks drives the
same gated dispatch to completion on the universal path.

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
A Relay-side authorization rule: which Account may request which Operations (or Raw Exec)
against which Selector. Deny-by-default. Grants are runtime objects managed via the Control
API and Admin Console, unlike Node-rooted **Policy**. A Grant only *narrows*: execution needs
both a Grant ("may this Account ask") and Policy ("will this Node ever do it"), and Policy has
the last word. Unqualified, "Grant" means this one; the approval mechanism's is an **Approval
grant**, always written in full.
_Avoid_: policy (reserved for the Node-side document), permission, ACL, rule

**Account**:
A named identity — human or machine — with a role, to which every credential binds: a
human's password or OIDC identity, a machine's API Tokens. The AI-agent authenticates as
a machine Account. The three roles are an ordered ladder, each adding to the one below:
**`viewer`** may read but dispatch nothing; **`operator`** may additionally run
structured Operations; **`admin`** may additionally use Raw Exec and administer the
control plane. Raw Exec being admin-only is enforced in the capability layer's Authorizer,
so every surface inherits it; Node Policy still governs every command that arrives. The unit
of Relay-side authorization and audit attribution across all three surfaces (ADR-0010). An
Account is a *durable identity*; a token is a *revocable credential for one*, so disabling the
Account and revoking a token have different blast radii. The **founding admin** is the first
human `admin`: the Account the operator names at `relay init` on a store with no human
Account. The Relay seeds no Account and reserves no name (ADR-0030, amended 2026-10-16); the
founding admin is an ordinary stored Account. In code, the capability layer's `Principal`
**is** the acting Account (ID, name and role when it authenticated).
_Avoid_: user, principal, service account (say "machine Account")

**API Token**:
A bearer credential bound to an Account, used by machines (and the AI-agent via MCP) to
call the Control API. Named, revocable, optionally expiring (a human Account's defaults to seven
days, designed for the MVP), stored only as a hash, and inheriting its Account's role. Its fixed prefix **`glp_`** is a security feature, not branding:
it makes a leaked token greppable and is what secret scanners key on. The plaintext is shown
once, at mint; there is no recovery, only re-mint plus revoke. Distinct from an
**Enrollment Token**, which joins Nodes to the fleet and can never call the API, and from
an **OAuth session**, which is how a *human* authenticates.
_Avoid_: API key, PAT, bearer token (unqualified)

**Temporary password**:
The first Console password of a human Account created in the Admin Console: generated by the
Relay when an `admin` creates the Account, shown to that admin once, and valid for 72 hours
(ADR-0045). A sign-in with it reaches only the change-password form, so the person sets a
password the admin never learns; it stops being accepted once redeemed or re-issued, and an
`admin` may re-issue one only while the Account's human has never set their own. It is
credential issuance, not a change to the security floor (invariant 11, as ADR-0045 reads it).
The founding admin has none: `relay init` sets that password. There is no **password reset**:
no Account sets a password another Account's human chose.
_Avoid_: initial password, one-time password, OTP (an authenticator code), reset password

**OAuth session**:
A control-plane session a human establishes through the organization's own IdP, using
MCP's standard OAuth 2.1 layer, resolving to their Account (ADR-0024). Relay is a
**protected resource only** — it validates tokens, and is never an authorization server.
Its authority is its Account's role, as with an API Token. An OAuth session buys
**attribution and revocation, not trust**: it proves a human authorized the *session*, not each
*call*, so MCP-originated calls stay agent-grade for approval gating. The one exception is the
*answer* to an approval question: any answer on a human Account's OAuth session is that
human's verified decision, whatever the client calls itself (`docs/specs/approval.md` AP-79).
It proves who owns the session, not that a human read the question.
_Avoid_: login, SSO session, user session (say OAuth session), "authenticated human"

**Principal**:
The verified identity a request runs as: the Account the capability layer resolved from the
credential presented, with its role and kind. Every capability-layer decision takes a Principal;
no adapter constructs one from anything but the verified lane. Distinct from the asserted
`on_behalf_of` (see Attribution).
_Avoid_: user, caller (for the verified identity), "the principal" for the verified-plus-asserted pair

**Attribution**:
Who an audited action is recorded as coming from, in **two structurally distinct lanes**
(ADR-0010, `docs/design/approval-and-attribution.md`). The **verified lane** is what the
Relay authenticated itself — the acting Account, its role at that moment, and the API
Token presented. The **asserted lane** is what the caller *claimed*: `on_behalf_of` (a
free-form user or team), a session reference, a change reference, and the W3C
`traceparent`. Asserted values are bounded, stored verbatim, and **never an authorization
input**: a jailbroken AI-agent can assert anything and forge nothing. For an honest
orchestrator the asserted lane joins a record back to the harness's own session logs, where
the literal instruction lives. Blurring the lanes is how an audit trail becomes fiction.
_Avoid_: "the principal" (for the pair), user id, requester (unqualified — say verified or
asserted)

**Capability layer**:
The single Relay-side layer that decides (authorization, Selector resolution, the
blast-radius cap, dispatch and audit) and the only path to any of them. Every interface is an
adapter over it (ports and adapters): the MCP surface, the Control API, the Admin Console, and
anything added later. An adapter may **narrow** what it offers; none may widen it, reimplement
any part of it, or decide (ADR-0009, ADR-0010; invariant 10). It renders nothing and speaks no
wire format; an adapter that decides anything is a bug, guarded structurally for the Console by
`no_dispatch`. Its outbound collaborators are injected seams (Authorizer, CapChecker,
AuditSink, FreezeStore, Conduit), so it depends on interfaces it defines. Each capability it
exposes is what one **capability specification** in `docs/specs/` describes, which is why a
spec is true of every surface at once.
_Avoid_: service layer, business logic, core, the backend, "the service"

**Control API**:
The REST/JSON surface (`/api/v1`, OpenAPI-described) through which tooling and machines drive
the control plane, for administration and execution. One of the three surfaces, all thin
adapters over the capability layer; the Control API is the programmable superset (ADR-0010). It never writes the Relay's configuration and never reaches the security floor
at all (invariant 11); where operator settings are store-backed it reads their non-secret
values (`docs/specs/relay-configuration.md`, designed for v0.7.0).
_Avoid_: REST API (unqualified), admin API, "the API" (in docs; fine in speech)

**System Model**:
Retired by ADR-0051, unbuilt: a shared map of Services, Dependencies and Annotations any
AI-agent could rewrite. What daemons observe and what people declare about the fleet are
Relay's later work (`roadmap: relay/fleet-topology`); an AI-agent's beliefs are agent memory.
Invariant 9 constrains any fleet model Relay keeps.
_Avoid_: topology, CMDB, knowledge base, map

**Fleet model**:
Any record Relay keeps of how the fleet fits together. Invariant 9 constrains it: advisory, never
a desired-state spec, what Relay observed distinguishable from what anyone wrote, and no AI-agent
writes its grounding facts (ADR-0051). Relay keeps none in the MVP; observed topology and
declared meaning are later work (`roadmap: relay/fleet-topology`).
_Avoid_: CMDB, inventory model

**Service**, **Dependency**, **Annotation**:
Retired with the System Model (ADR-0051).
_Avoid_: app, group, cluster (use a **Tag** to group Nodes)

**Admin Console**:
The human-facing web UI for operators to observe the fleet and administer the control plane
(enrollment lifecycle, revocation, Accounts and tokens, tags, Policy aliases, registry and audit
views). It runs no command on any Node (ADR-0052); people run commands through their AI-agent
client or the Control API. A thin adapter over the same
capability layer as the MCP surface (ADR-0003, ADR-0009); it renders decisions, never makes
them. It has no approval surface: an **Approval** is decided in-band or on the Control API
(ADR-0044). Distinct from the **AI-agent**, which drives the Relay over MCP.
_Avoid_: dashboard, portal, admin panel, "the UI"

**Step-up re-authentication**:
Re-proving human presence by re-entering a credential against the session's own Account,
without ending the session. Gates privilege-granting actions (ADR-0009). Changing one's own Console password proves the current one as a step-up on every change,
which the recent-authentication window never satisfies (ADR-0045). Its window is file-only Relay configuration no Account may widen over the wire
(invariant 11). Recorded as its own event, distinct from a sign-in, and so is a refused or
throttled step-up: a hijacked session grinding at the step-up prompt is a different incident
from an anonymous caller grinding at the sign-in form.
_Avoid_: re-auth, sudo mode, 2FA, MFA, confirmation (unqualified — name the rung)

**Event seam**:
The Relay's one in-process pub/sub (`internal/events`) feeding the Admin Console's live
views: exactly four publishers (registry transitions, Job transitions, MCP tool calls,
and enrollment attempts), with monotonic IDs over per-publisher bounded ring buffers (1,000
events or 10 minutes, whichever first), `Last-Event-ID` resume, and a `gap` event rather than
fabricated continuity. It carries tool-call ARGUMENTS and never read RESULTS (ADR-0025),
enforced structurally: the package imports only the standard library. Memory-only. Subscribing
is itself an audited read (`watch_events`, one `KindRead` record per subscription, naming the
kinds asked for, ADR-0025).
_Avoid_: event stream, notifications, the firehose, pubsub
