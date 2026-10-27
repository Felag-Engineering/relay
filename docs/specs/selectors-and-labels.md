# Selectors and Labels

**Status:** aspirational — worked through with the owner on `2026-09-13`, revised to the
owner's MVP decisions of `2026-10-23` (ADR-0050). Describes intended behaviour, not the code
(see the establishing phase in `README.md`).

## Purpose

Labels describe a Node; a Selector says which Nodes a caller means. Every capability that acts
on more than one Node takes a Selector, so this is the control plane's shared addressing
vocabulary.

There are four namespaces with one writer each. A Node describes itself in `node:`, and nothing
remote can change that. The Relay applies `relay:` labels as a consequence of its own actions.
Operators organise the fleet with `tag:`. `state:` tracks a Node's current condition and is
written by nobody.

This is a security boundary. What a Selector resolves to sets the blast radius of everything
downstream, and **who may write a Label decides whether a target can be forged.** A
compromised Node that could write a security-lane label could put itself into, or take itself
out of, a remediation target.

## Surfaces

A Selector is accepted wherever a capability acts on or lists Nodes: `list_nodes`,
`run_operation` and `raw_exec` over MCP; the Control API's execution and node routes; the
Console's fleet filter. One grammar, one parser, one resolver; no surface evaluates a Selector
itself.

Label **writes** are deliberately asymmetric:

- `node:` — the Node's daemon, from its `RELAY_NODE_LABELS` setting and its Facts; no Relay
  surface.
- `relay:` — no surface writes one directly. Each is written by the Relay action that defines
  it; today that is enrollment.
- `tag:` — the Console and the Control API, by a human Account of `operator` or above. The
  Console writes on a Node's page, and in bulk over the Nodes a Selector matches. No MCP tool
  writes a tag. Built on both surfaces; one write names at most 256 Nodes.
- `state:` — no writer anywhere.

## Behaviour

### Four namespaces, one writer each

Every Label is namespaced, and a namespace is immutable from every side but its own author
(invariant 7).

| Namespace | Written by | Never written by | Purpose |
|---|---|---|---|
| `node:` | The Node: config management declares, the daemon reports built-ins | The Relay, any Account | Routine targeting; the Node's self-description |
| `relay:` | The Relay, only as the side effect of a defined action | The Node, any Account directly | The security lane |
| `tag:` | A human Account of `operator` or above, on the Console or the Control API | The Node, a machine Account, MCP | Routine targeting; organising the fleet |
| `state:` | **Nobody** — derived from the registry at resolution time | Anyone | Routine targeting on live condition |

**Only `relay:` is a security-lane target.** Remediation and secret distribution target
`relay:` and only `relay:`; today the one `relay:` key written is `relay:node-id`. Where a
quarantine is engaged, it may target `relay:` or `tag:`, because no Node can write either;
lifting one targets `relay:` only. Quarantine is not in the MVP (`roadmap: relay/quarantine`).
`node:` and `state:` are routine targeting only, because a Node controls them (invariant 7;
ADR-0006, ADR-0020, ADR-0050).

The writers are structurally separated, not separated by permission: a report from a daemon
cannot reach the `relay:` or `tag:` labels on its Node record, and a daemon can never revoke or
un-revoke itself.

### `relay:` — written only by Relay actions

- **No Account ever writes a `relay:` label directly.** Each `relay:` key is defined together
  with the action that sets and clears it; roles, step-up and audit apply to that action.
- The set of `relay:` keys is **closed, and grows only when an action is built.** Every key in
  it is defined or reserved by a Relay action, and no Account chooses one. An Enrollment Token
  names no `relay:` label; its labels are initial tags (below). Defined or reserved by an
  action:

  | Key | Written by | Value |
  |---|---|---|
  | `relay:enrollment-token` | Reserved, with no writer (ADR-0048) | The ID of the Enrollment Token the Node joined through |
  | `relay:node-id` | Enrollment, on every Node (`enrollment.md` EN-38, ADR-0048) | The Relay-assigned Node ID, bound to the Node's certificate |

- `relay:node-id` is how the security lane addresses one specific Node without trusting it
  (`enrollment.md` EN-38).
- `relay:enrollment-token` has no writer; a leaked token's Nodes are contained by revoking it
  (`enrollment.md`). Fencing them off without revoking waits in `roadmap: relay/quarantine`.
- A quarantine, when it is built, defines its own key with the action that engages and lifts
  it.

### `node:` — declared and built-in

- **Declared labels** (`node:env=prod`, `node:role=web`) come from the daemon's
  `RELAY_NODE_LABELS` environment setting, written by the customer's config management. The
  daemon reads it at start; changing it takes a restart of the daemon.
- **Built-in labels** are filled from the Facts the daemon already reports: `node:hostname`,
  `node:ip`, `node:os`, `node:arch`. Their keys are reserved; a declared label cannot set one.
  Designed for the MVP, not built.
- A multi-valued built-in (`node:ip`) matches when any of its values matches.
- Every `node:` label, declared or built-in, is forgeable by its own Node.

A root-owned declared-labels file, reloaded with Policy and reported without a reconnect, waits
in `roadmap: relay/policy-catalog-and-live-reload`, with the `state:labels-invalid` marker it
would bring.

### `tag:` — organising the fleet

Tag writes on the Console and the Control API are built (ADR-0050). Initial tags from an
Enrollment Token are designed for the MVP, not built.

- **Only a human Account of `operator` or above writes a tag,** through the Console or the
  Control API. Standard authentication, no step-up. No MCP tool writes a tag, a machine Account
  writes none, and a Node never writes one.
- On the Console, an operator writes tags on a Node's page, or in bulk over the Nodes a
  Selector matches. A bulk write first lists the matched Nodes, and writes only once the
  operator accepts that list.
- **One tag write names at most 256 Nodes,** on every surface: the capability layer refuses a
  longer list and changes nothing. The Console's confirm step refuses a larger match and asks
  for a narrower filter.
- A tag is `key=value`, the same shape as every other Label.
- **Every change is audited with its old and new values.** A bulk write is audited as one
  action naming every Node it touched.
- **An Enrollment Token's labels are initial tags.** The mint names zero or more `tag:` labels,
  and enrollment writes them on each Node the token enrolls. Afterwards they are ordinary tags,
  edited like any other (`enrollment.md`).
- A tag grants no reach its writer did not already have: every dispatch still passes the blast
  cap, Policy and approval. A tag is never a remediation or secret-distribution target. Where a
  quarantine is engaged by `tag:`, only the resulting `relay:` label matters once it is engaged.

### Limits

- Per Node: at most 64 declared `node:` labels and at most 64 tags.
- A key is at most 63 characters and a value at most 255, both within the safe character set.
- The length limits hold today for `node:` and `tag:`. A `node:` label over a limit is dropped
  at `Hello`, refuses the whole `Enroll` (`enrollment.md`), and is dropped on read if it was
  stored before the limit existed; it is never truncated. A `relay:` label stamped from a token
  scope is not yet held to the length limits. The per-Node counts are not yet enforced for
  `node:`.

### What a compromised Node can and cannot forge

- It **can** forge its own `node:` labels, declared and built-in. Routine `node:` targeting
  trusts the Node exactly as much as the Node.
- It **can** influence `state:` terms derived from its own reports, including hiding
  `policy-invalid` and `raw-exec-enabled`.
- It **cannot** touch `relay:` or `tag:`. That is what makes the security lane safe to target.

Because a Node's reported facts feed `node:` built-ins and `state:`, values are gated at ingress
against a well-formedness allowlist so a hostile value cannot inject a second Selector term. A
value that cannot be rendered as a single Selector term is **refused at ingress, never
sanitised** — sanitising would let the Relay itself manufacture a value matching a Selector
nobody wrote.

### `state:` — derived, never stored

`state:` labels are evaluated at Selector-resolution time from the registry. **No Node record has
a `state:` field**, and nothing writes one. The vocabulary is closed; adding a term is a change to
this spec.

| Kind | Terms |
|---|---|
| Markers (boolean) | `offline`, `outdated`, `cert-expiring`, `raw-exec-enabled` |
| Facts (key=value) | `daemon-version`, `policy-fingerprint` |

- `outdated` means below the ADR-0014 dispatch minimum and nothing else.
- `cert-expiring` fires within the built-in fraction of the certificate's lifetime
  (`relay-configuration.md`), and stays quiet when the provenance needed to compute it is unknown.
- `raw-exec-enabled` means the Node's Policy enables Raw Exec. A `policy-invalid` marker waits with
  a reported `invalid` Policy state (`roadmap: relay/policy-catalog-and-live-reload`).
- `policy-fingerprint` covers the evaluated Policy; the Template set carries its own fingerprint
  (ADR-0021).
- **Terms derived from a Node's own report find Nodes; they guarantee nothing.** A compromised
  Node can hide any of them.
- A marker written with a value, or a fact written bare, is a parse error rather than a silently
  empty match.

Deriving at resolution time is why resolution has a second code path; the alternative, a stored
copy, needed recompute triggers on several separate events.

### The grammar

A Selector is **an AND of exact terms**. There is no OR across keys and no parentheses, so a
Selector's blast radius stays legible at a glance.

- **Every term carries a namespace prefix.** An unprefixed term is a parse error, never a guess:
  a term read in the wrong namespace is a targeting error with a blast radius.
- `node:key=value`, `relay:key=value`, `tag:key=value` — key and value both required, and the
  term matches that exact value.
- `state:marker` or `state:fact=value` — from the closed vocabulary above.
- **Negation is refused at parse, permanently, in every namespace.** It has two faults. A label
  the store declines to serve is invisible to resolution, so under negation it would add a Node
  to a match rather than remove one. And "everything except" includes every Node that carries
  no label at all, so a new or unlabelled Node falls into the target unasked.
- **An empty Selector** matches every Node for reads and listing, and is **refused for
  dispatch**. Targeting the whole fleet must be written deliberately, with a built-in label every
  Node carries, such as `node:os=linux`, so an AI-agent that forgets a Selector gets an error, not
  the fleet. There is no whole-fleet keyword (owner decision 2026-10-23); the blast cap and the
  gate still apply to the result.

Value sets (`node:role=web|api`) and value globs (`node:hostname=web-*`) wait in
`roadmap: relay/selector-value-sets-and-globs`.

### Resolution

Resolution walks the registry and returns the Nodes matching every term. The blast-radius cap is
checked against the resolved **count** (invariant 5).

A Selector's resolved set is the same for every surface and every caller; authorization decides
who may *ask*, never what matches.

### Labels the store declines to serve

The stored-Label allowlist is deliberately **narrower than the parser**: the hazard is a term
concatenated back together by a Console href or an AI-agent, so rendering is gated more tightly
than parsing. A stored Label outside the allowlist is declined at read-back, never deleted or
rewritten: *decline to serve, never write*.

A declined label is invisible to resolution. Every term is positive, so that can only remove a
Node from a match, never add one; it is one of the two reasons negation is refused. For `node:`
the condition self-heals on the Node's next report; for `relay:` there is **no self-heal**,
which is a disclosed residual (threat-model register R13) with operator-facing remediation.

## Refusals

| Refusal | Cause |
|---|---|
| Unprefixed term | A term with no `node:`/`relay:`/`tag:`/`state:` prefix — a parse error, never a guess |
| Negated term | Refused at parse in every namespace, permanently: a declined label would add a Node to the match, and "everything except" includes every unlabelled Node |
| Empty Selector on dispatch | The whole fleet must be targeted explicitly |
| Unknown `state:` term | Outside the closed vocabulary |
| Marker with a value, fact without one | The two `state:` shapes are not interchangeable |
| `tag:` term, until tags land | Refused at parse with a recognisable refusal, identically on every surface |
| Malformed label at ingress | A key or value that cannot render as one Selector term — refused, never sanitised |
| Declared label on a reserved built-in key | `node:hostname`, `node:ip`, `node:os`, `node:arch` are the daemon's |
| Direct write of a `relay:` label | No surface offers one; `relay:` labels are written only by their defining action |
| Enrollment Token naming a `relay:` label | A token's labels are initial tags; every `relay:` key is defined by a Relay action |
| Tag write by a `viewer`, a machine Account or a Node, or over MCP | `tag:` is written only by a human Account of `operator` or above, on the Console or the Control API |
| Tag over the per-Node limit | At most 64 tags per Node |

## Governing ADRs and invariants

- **Invariant 7** (ADR-0006, ADR-0020, ADR-0034, ADR-0050) — the whole of it. Its `tag:` clause,
  as ADR-0050 rewords it, names a human Account of `operator` or above, on the Console and the
  Control API. This spec holds the invariant's per-namespace mechanism.
- **Invariant 5** (ADR-0004) — the cap is checked against the *resolved* count.
- **Invariant 10** — one parser and one resolver in the capability layer; no surface evaluates a
  Selector itself.
- **ADR-0050 — tags are the operator's labels.** Who writes a tag and where, initial tags from
  an Enrollment Token, and `relay:` holding only keys a Relay action defines. It supersedes in
  part ADR-0006's amendment of 2026-10-22 and ADR-0048 decision 4, where a token's scope was
  `relay:` labels.
- **ADR-0048.** Every enrollment writes `relay:node-id`, and `relay:enrollment-token` stays
  reserved and unwritten (decision 5).
- **ADR-0020 — amended 2026-09-16, and by ADR-0050.** Its direct post-enrollment `relay:` label
  management (`admin` + step-up) is superseded: `relay:` labels are written only by defined
  actions. Its `tag:` design stands as ADR-0050 narrows it: human Accounts only, no MCP.
- **ADR-0034 — needs amending** if `raw-exec-enabled` is added to the `state:` vocabulary. The
  Template markers stand (ADR-0021).
- **ADR-0017** — unchanged: `node:` labels are trusted exactly as much as the Node.
- **GLOSSARY.md — needs updating** for Label (the `relay:` writing rule, the `tag:` writer,
  `node:` built-ins) and the `state:` vocabulary.

## Seams and proof

Parsing and resolution live in the capability layer; label authority lives in the registry; the
`state:` vocabulary lives in its own package with no database import. Tests sit at those seams,
not at a surface.

### What proves each claim

| Behaviour | Proven by | Seam |
|---|---|---|
| All four namespaces are recognised, and namespace naming is total and distinct | `TestNamespaceNames_ReportsAllFourNamespaces`, `TestNamespaceName_TotalAndDistinct` | capability |
| The grammar parses, and an unprefixed term is an error | `TestParseSelector` | capability |
| A Relay-set label survives a Node's report, and vice versa | `TestImmutabilityBoundary_RelaySurvivesNodeReport`, `TestImmutabilityBoundary_NodeSurvivesRelaySet` | registry |
| No Node record carries a `state:` field | `TestNode_HasNoStateLabelField` | nodestate |
| The `state:` vocabulary is closed, and its key kinds match | `TestKeyKind_Closure`, `TestMarkerKeysAndFactKeys_MatchKeyKind` | nodestate |
| A hostile daemon version cannot inject a Selector term | `TestFacts_HostileDaemonVersionCannotInjectASelectorTerm` | nodestate |
| No whitespace rune, including Unicode, reaches a Selector term | `TestFacts_NoWhiteSpaceRuneReachesASelectorTerm`, `TestFacts_UnicodeWhitespaceCannotInjectASelectorTerm` | nodestate |
| Hostile value shapes are omitted rather than rendered | `TestFacts_OmitsHostileValueShapes` | nodestate |
| `outdated` comes only from the version gate | `TestMarkers_OutdatedComesOnlyFromNodeOutdated`, `TestOutdated_WithMinimumConfigured`, `TestOutdated_NoMinimumConfigured` | nodestate |
| `cert-expiring` fires inside the window and is quiet outside it or when provenance is unknown | `TestMarkers_CertExpiringFiresUnderTheWindow`, `TestMarkers_CertExpiringQuietAboveTheWindow`, `TestMarkers_CertExpiringQuietWhenProvenanceUnknown` | nodestate |
| A `relay:`-namespace Selector narrows as expected; `state:` too | `TestSelectorNamespaceNarrows`, `TestSelectorNamespaceState` | approval |
| Labels are independent across Nodes, and reads return copies | `TestLabels_AreIndependentOfOtherNodes`, `TestGetReturnsCopy` | registry |
| `state:` derivation imports no database | `.golangci.yml` depguard rule `domain-no-sql` | lint |

Claims above with **no row**, and so nothing checking them:

- **Everything decided on `2026-09-13` and `2026-10-23`** has no test yet: `relay:` labels
  written only by their defining action, declared versus built-in `node:` labels and reserved
  keys, bulk tagging audited as one action, initial tags from an
  Enrollment Token, the per-Node limits, the new `state:` markers, the refusal of a negated
  term, and the empty-Selector refusal on dispatch.
- `tag:` writes by human `operator` Accounts on the Console and the Control API, their
  old-and-new audit and the 256-Node cap are tested in the capability layer, the Control API
  and the Console, but this spec is aspirational and records no proof rows for them.
- That a zero-width space in a reported fact is accepted. It is;
  `TestFacts_ZeroWidthSpaceIsAcceptedKnownGap` documents it as a **known gap**, which is not
  coverage.
- That `relay:` labels can only be written through the Relay's own actions. The immutability
  boundary is tested from both directions, but no test asserts the *absence* of any other write
  path the way `no_dispatch` asserts the absence of a parallel dispatch path.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Resolution | Walks the registry once per dispatch; the resolved count feeds the blast cap | *(none)* |
| `state:` evaluation | At resolution time, not stored — so it costs per resolution rather than per state change | *(none)* |
| Declined labels | Reported once at startup (capped sample per namespace) and counted on `/metrics`; the counter is traffic-driven | *(none)* |

There are no benchmarks in this repository. Resolution cost scales with fleet size and is on the
path of every dispatch, including a read at the 10,000-Node cap; nothing measures it.

## Out of scope

- **The blast-radius cap itself** — `execution.md`. This spec produces the count; that one
  enforces the limit.
- **Enrollment mechanics** — `enrollment.md`: a token's initial tags, what enrollment writes,
  and provenance. This spec defines the namespaces and their writers; that one defines the
  enrollment action.
- **Quarantine** — not in the MVP (`roadmap: relay/quarantine`). This spec holds only the
  namespace rule a quarantine must keep.
- **The incident ladder** (revoke, Freeze) — `freeze.md` and `enrollment.md`.
- **Policy** — a Node's Policy governs what may run on it, not which Nodes are addressed.
- **Setting a Node's declared labels** — the customer's config management writes
  `RELAY_NODE_LABELS` (`daemon-installation.md`).

## Accepted residual risk

- **Node-derived terms can lie.** `node:` labels and the `state:` terms derived from a Node's own
  report — `policy-invalid`, `raw-exec-enabled`, `daemon-version`, `policy-fingerprint` —
  describe what the Node claims.
- **A zero-width space is accepted in a reported fact.** It cannot inject a term, but it can make
  two visually identical values distinct.

## Future work

Wanted, deliberately not in the first pass.

- **A structural guard for `relay:` writes** — an absence test asserting that no path other than a
  defining action writes a `relay:` label, the analogue of `no_dispatch`.
- **Value sets and globs** — `roadmap: relay/selector-value-sets-and-globs`.
- **A declared-labels file reloaded with Policy, and `state:labels-invalid`** —
  `roadmap: relay/policy-catalog-and-live-reload`.
- **Quarantine, and fencing off a token's Nodes without revoking it** —
  `roadmap: relay/quarantine`.

## Open questions

No question is open. A Node's declared labels live in its `RELAY_NODE_LABELS` setting; who may
take the actions that write `relay:` labels is settled in `enrollment.md`; a re-enrolled Node is
a new record whose tags do not follow it (`enrollment.md`).
