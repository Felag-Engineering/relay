# Selectors and Labels

**Status:** current as of `2026-09-12`.

## Purpose

Labels are how a Node is described. A Selector is how a caller says which Nodes it means. Every
capability that acts on more than one Node takes a Selector, so this is the shared addressing
vocabulary of the whole control plane.

It is a security boundary, not a convenience. What a Selector resolves to determines the blast
radius of everything downstream, and **who is allowed to write a Label determines whether a
target can be forged.** A compromised Node that could label itself into the quarantine lane
would escape quarantine by describing itself out of it.

This spec has no surface of its own — no tool, no route, no screen. It documents an input the
other capabilities accept, which is why four of them cite it rather than restating it.

## Surfaces

A Selector is accepted wherever a capability acts on Nodes: `list_nodes`, `run_operation` and
`raw_exec` over MCP; the Control API's execution and node routes; the Console's fleet filter.
One grammar, one parser, one resolver — no surface evaluates a Selector itself.

Label **writes** are a different matter, and deliberately asymmetric — see below.

## Behaviour

### Four namespaces, one writer each

Every Label is namespaced, and a namespace is immutable from every side but its own author
(invariant 7).

| Namespace | Written by | Never written by | Purpose |
|---|---|---|---|
| `node:` | The Node's own config management, reported in `Hello` | The Relay | Routine targeting; the Node's self-description |
| `relay:` | The Relay | The Node | The security-sensitive lane |
| `tag:` | An operator through the control plane | The Node | Ad-hoc grouping |
| `state:` | **Nobody** — derived from the registry at resolution time | Anyone | Routine targeting on live condition |

**Only `relay:` is a valid security-lane target.** Quarantine, remediation and
secret-distribution targeting must target `relay:` and only `relay:`. The other three are
routine targeting and are never a security-lane target.

The writers are structurally separated, not separated by permission: `node:` and `relay:` labels
live in different maps on the Node record, and a report from a daemon cannot reach the
`relay:` map. A daemon can never revoke or un-revoke itself.

### What a compromised Node can and cannot forge

- It **can** forge its own `node:` labels freely. Routine `node:`-targeting therefore trusts the
  Node exactly as much as the Node.
- It **can** influence `state:` by lying in `Hello` — the facts it reports (daemon version,
  Policy fingerprint, template fingerprint) become `state:` terms.
- It **cannot** touch `relay:` or `tag:`. That is what makes the security lane safe to target.

Because a Node's reported facts feed `state:`, values are gated at ingress against a
well-formedness allowlist so a hostile value cannot inject a second Selector term. A value that
cannot be rendered as a single Selector term is **refused at ingress, never sanitised** —
sanitising would let the Relay itself manufacture a value matching a Selector nobody wrote.

### The grammar

Every term carries a namespace prefix. **An unprefixed term is a parse error, never a guess** —
the parser is fail-closed, because a term silently interpreted in the wrong namespace is a
targeting error with a blast radius.

- `node:key=value` and `relay:key=value` — key and value both required.
- `state:marker` or `state:fact=value` — a closed vocabulary, below.
- `tag:` — **refused outright**, see below.
- An empty or omitted Selector matches every Node.

### `tag:` is refused, not empty

`tag:` is a declared namespace in the model with **no storage on the Node record and no write
path** until label management lands (#430). A `tag:` term is therefore **refused at parse** with
a recognisable sentinel error, not parsed into a predicate that silently matches nothing.

That distinction is the whole point. A silently-empty result reads to a caller — especially an
AI-agent — as *"no Nodes carry that tag"* rather than *"this namespace is not implemented"*, and
a false negative about fleet state is worse than an error. The refusal lives in the shared
parser rather than on any surface, so every surface inherits it identically.

### `state:` is derived, never stored

`state:` labels are evaluated at Selector-resolution time from the registry. **No Node record
has a `state:` field**, and nothing writes one. The vocabulary is closed:

| Kind | Terms |
|---|---|
| Markers (boolean) | `offline`, `outdated`, `template-unloadable`, `cert-expiring` |
| Facts (key=value) | `daemon-version`, `policy-fingerprint`, `template-fingerprint` |

A marker written with a value, or a fact written bare, is a parse error rather than a
silently-empty match. `outdated` means below the ADR-0014 dispatch minimum and nothing else.
`cert-expiring` fires within a configurable fraction of the certificate's lifetime, and stays
quiet when the provenance needed to compute it is unknown.

Deriving at resolution time rather than storing a denormalised copy is why a second code path
exists in resolution. The alternative was a stored copy with recompute triggers on four separate
events.

### Resolution

Resolution walks the registry and returns the Nodes matching every predicate. The resolved
**count** is what the blast-radius cap is checked against (invariant 5), so resolution is what
makes the cap meaningful.

A Selector's resolved set is the same for every surface and every caller; authorization decides
who may *ask*, never what matches.

### Labels the store declines to serve

The stored-Label allowlist is deliberately **narrower than the parser**, because the hazard is a
term concatenated back together by a Console href or an AI-agent — so rendering must be gated
more tightly than parsing. A stored Label outside the allowlist is declined at read-back rather
than deleted or rewritten: *decline to serve, never write*.

The consequence is **under-inclusion only**: a filter can only remove matches, and the grammar
has no negation, so this can never make a Selector match a Node it should not. Quarantine
specifically cannot be lost — its key and value are both inside the allowlist. For `node:` the
condition self-heals on the Node's next `Hello`; for `relay:` there is **no self-heal**, which
is why it is a disclosed residual (threat-model register R13) with operator-facing remediation.

## Refusals

| Refusal | Cause |
|---|---|
| Unprefixed term | A term with no `node:`/`relay:`/`state:` prefix — a parse error, never a guess |
| `tag:` unsupported | The namespace exists in the model but has no storage yet (#430) |
| Unknown `state:` term | Outside the closed vocabulary |
| Marker with a value, fact without one | The two `state:` shapes are not interchangeable |
| Malformed label at ingress | A key or value that cannot render as one Selector term — refused, never sanitised |

## Governing ADRs and invariants

- **Invariant 7** (ADR-0006, ADR-0020, ADR-0034) — the whole of it. This spec is where the
  invariant's per-namespace mechanism lives.
- **Invariant 5** (ADR-0004) — the cap is checked against the *resolved* count, which is what
  resolution produces.
- **Invariant 10** — one parser and one resolver in the capability layer; no surface evaluates a
  Selector itself.
- **ADR-0006** — node/relay label authority and the enrollment stamp.
- **ADR-0017** — node-origin label trust: `node:` labels are trusted exactly as much as the Node.
- **ADR-0020** — the `tag:` namespace for operator grouping.
- **ADR-0034** — `state:` as Relay-derived, evaluated at resolution time from a closed vocabulary.

## Seams and proof

Parsing and resolution live in the capability layer; label authority lives in the registry; the
`state:` vocabulary lives in its own package with no database import. Tested at those seams
rather than through a surface.

### What proves each claim

| Behaviour | Proven by | Seam |
|---|---|---|
| All four namespaces are recognised, and namespace naming is total and distinct | `TestNamespaceNames_ReportsAllFourNamespaces`, `TestNamespaceName_TotalAndDistinct` | capability |
| The grammar parses, and an unprefixed term is an error | `TestParseSelector` | capability |
| A `tag:` term is refused with a recognisable sentinel | `TestParseSelectorTagRefusalIsASentinel` | capability |
| The unprefixed-term error does not suggest `tag:` as a fix | `TestParseSelectorUnprefixedErrorDoesNotOfferTag` | capability |
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
| `state:` derivation imports no database | `TestNoDatabaseSQLImport` | compile-time |

Claims above with **no row**, and so nothing checking them:

- That a zero-width space in a reported fact is accepted. It is — `TestFacts_ZeroWidthSpaceIsAcceptedKnownGap` documents it as a **known gap** rather than proving it safe, which is the honest state and not the same as coverage.
- That `relay:` labels can only be written through the Relay's own paths. The immutability
  boundary is tested from both directions, but no test asserts the *absence* of a daemon-reachable
  write path the way `no_dispatch` asserts the absence of a parallel dispatch path.

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
- **Enrollment stamping of `relay:` labels** — `enrollment.md`. A token's scope becomes the
  enrolling Node's `relay:` labels, which is why minting is a claim the control plane vouches for.
- **The incident ladder** (quarantine, revoke, Freeze) — it *targets* `relay:` labels but is not
  addressing; see `freeze.md` and the enrollment spec.
- **Policy** — a Node's Policy governs what may run on it, not which Nodes are addressed. The two
  are unrelated and neither substitutes for the other.
- **Services and Dependencies** — the System Model desugars to Selectors but is advisory and
  unbuilt (invariant 9).

## Open questions

- **`tag:` has no write path** (#430). Until it lands, the namespace is declared, refused at
  parse, and carries no storage. It is the last of the four namespaces that is not real.
- **`relay:` label management is unbuilt** (#430). Labels are stamped at enrollment today;
  operator management through the control plane — `admin` plus step-up — does not exist, and the
  API and MCP registry interfaces deliberately exclude the setter.
- **A zero-width space is accepted in a reported fact.** Documented as a known gap by its own
  test. It cannot inject a term, but it can make two visually identical `state:` facts distinct.
- **Nothing asserts the absence of a daemon-reachable `relay:` write path.** The immutability
  boundary is tested behaviourally; the structural guarantee `no_dispatch` provides for dispatch
  has no analogue here.

## History

- `2026-09-12` — ADR-0038: the list of specs citing invariant 7 now names `policy-preflight`
  (renamed from `plan-mode`) and `plan`.
- `2026-09-12` — First written. Extracted because four capability specs cite this vocabulary
  (execution, policy-preflight, plan, approval, query) and would otherwise restate invariant 7's namespace
  rules four times.
