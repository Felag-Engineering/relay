# Template dispatch resolves its risk class over the reporting Nodes

**Status:** Accepted (owner decision 2026-10-02, issue #626). Amends ADR-0021 and ADR-0012.

ADR-0021 built the Template tier on the daemon and made the Operation vocabulary per-Node. It
never said how the Relay *calls* a Template, and the gap turned out to be the whole tier: the
daemon loads, reports, Policy-checks and runs Templates, and both execution surfaces refuse
every Template name as `unknown operation`, because the only vocabulary they consult is the
four Natives (#626).

The missing piece is not a lookup. `jobs.Action.RiskClass` is load-bearing twice: it chooses
the blast cap (invariants 5 and 13, ADR-0012) and it is what the approval gate matches on
(ADR-0027). For a Native the class is a constant the Relay compiled in. For a Template it is a
value **each Node reports about itself**, so it cannot be known until the Selector is resolved,
and a Node is exactly the party whose compromise the rest of the system is built to survive. A
Node that reports `read` for a mutating Template would, if believed alone, take the read cap and
pass under every rule that keys on `mutate`.

## Decisions

- **The capability layer resolves a Template's class; no adapter ever does.** An adapter that
  receives a name outside the Native vocabulary builds a Template Action with **no** risk class
  and hands it to the capability layer, which fills it in after Selector resolution. The
  capability layer refuses a Template Action that arrives already carrying a class, so an
  adapter cannot decide one even by mistake (invariant 10). A structural test holds this.

- **Most-restrictive wins, over the Nodes that report the Template.** The dispatch is `read`
  only if every remaining Node reports the Template as `read`; any other report — `mutate`,
  unspecified, anything unrecognised — makes the whole dispatch `mutate`. A Node can always
  make a dispatch *stricter*; it cannot make one looser than its peers report.

- **Each Task carries its own Node's class, and output retention follows it.** The dispatch's
  most-restrictive class drives the cap, the approval gate and the plan hash. It does **not**
  drive output retention (ADR-0025): there, "stricter" means *keeping more*, so a single Node
  reporting `mutate` for a Template its peers report `read` would cause every honest Node's
  read output to be retained in the audit trail and the read lane. Each Task is therefore
  recorded under the class its own Node reported, and retention is decided per Task. A Node
  that lies about its class changes the retention of its own output and nobody else's.
  (Found in security review of the first implementation; owner decision 2026-10-02.)

- **A stale report counts as no report.** A cached vocabulary whose fingerprint differs from
  the template-set fingerprint the Node's latest `Hello` carried predates a daemon restart; until
  the new report lands, that Node is excluded as not reported.

- **A Node that does not report the Template is excluded before the class, the cap and the
  approval gate are decided**, and appears in the result as `unsupported`. Nothing is sent to
  it. This covers both a Node whose reported vocabulary lacks the name and a Node the Relay
  holds **no report for at all** — for instance one that has not reconnected since the Relay
  last started, since the vocabulary cache is in memory. The Relay never dispatches a Template
  to a Node whose vocabulary it cannot see. The two cases carry different Relay-authored
  reasons so a caller can tell "this Node does not have it" from "this Node has not told us".

- **A name no matched Node reports is refused** before a Job exists, pointing the caller at
  `list_operations`. That is the Template form of `unknown operation`.

- **The blast cap counts the Nodes that remain, not the Nodes the Selector matched.** Excluded
  Nodes are never dispatched, so the cap measures what actually runs. The same remaining set is
  what the approval gate's fan-out sees and what the plan hash binds, together with the
  resolved class — so a change in which Nodes report the Template, or in what class they
  report, re-parks an approved dispatch rather than releasing it against an approval that
  described something else (ADR-0027's drift rule, unchanged).

- **Argument names are checked against every reporting Node.** The call's arguments must be
  exactly the slot names of the Template on each remaining Node. If those Nodes disagree about
  the Template's slot set, the dispatch is refused as a vocabulary disagreement rather than sent
  to some of them. This keeps #345's property — a misspelled argument is a malformed call, never
  a per-Node `failure` or `denied_by_policy` — for Templates as for Natives. Values are still
  validated only by the daemon; the Relay checks names, never values (invariant 12).

- **Order.** Selector resolution → Template resolution (exclusion, class, slot agreement) →
  authorization, which therefore sees the resolved class → the zero-match and no-reporting-Node
  refusals → blast cap → approval gate → dispatch. Template resolution computes; it refuses
  nothing until after authorization, so a caller who may not ask learns nothing about which
  Nodes carry which Templates. Policy preflight follows the same order and reports where a run
  refuses (ADR-0011, ADR-0038), with one exception: an unknown or malformed Template call is a
  request that cannot be asked at all, so a preflight refuses it as a run would.

- **Policy preflight excludes exactly as a run does.** A matched Node excluded from a Template
  dispatch is never queried; the preflight reports it `unsupported` with the same Relay-authored
  reason the run's Task carries, so preflight and apply agree. This is the one place the Relay
  reads its cached vocabulary during a preflight, and it decides only fan-out and class: every
  `allow` and `deny` is still the daemon's live answer (invariant 12). `policy-preflight.md`'s
  PF-7 and PF-11 are amended on the same date to say so.

- **The vocabulary cache becomes a dispatch input.** It stops being display-only. It stays
  in-memory and is still refreshed only by the Node's own report on (re)connect; nothing on the
  Relay writes a Node's vocabulary (invariant 2 applies to Templates verbatim, per ADR-0021).

- **The class travels with the Task, and the daemon checks it.** The Task carries the class the
  Relay dispatched it under, and a daemon whose own Template declares `mutate` refuses a Task
  dispatched as `read`. This closes the window between a Node's report and the Task's arrival —
  a Policy reload that turns a `read` Template into a `mutate` one. It is a `/proto` change and
  lands as its own change after the Relay-side resolution; until it lands, the window is a
  known gap, tracked on #626.

## Residual risk

- **When every reporting Node says `read`, the Relay believes them.** A compromised Node, or a
  set of them, can report a mutating Template as `read` and take the read cap and every
  `read`-keyed approval rule for a dispatch reaching only those Nodes. Most-restrictive closes
  this whenever any honest peer is also targeted; it does not close it for a dispatch aimed only
  at liars. The daemon's own Policy remains the gate on what actually runs on each Node, so the
  exposure is to the Relay's *fan-out* guardrails, not to Policy.
- **A Node can withhold a Template to be excluded.** Harmless: exclusion only ever reduces what
  runs.
- **A Node can veto a Template dispatch** by reporting a different slot set for the same name:
  the slot-agreement rule refuses the whole call rather than send it to some Nodes. Accepted —
  it only ever prevents a run, and the refusal names the disagreeing Node so the Selector can
  be narrowed around it.
- Stronger answers are deliberately not chosen here — a class an operator pins per Template
  name on the Relay, pinning at first observation and alarming on a downgrade, or a Relay floor
  for unknown names. Each is a runtime object or a write path this decision avoids; each stays
  open in `operations-and-templates.md`'s future work.

## Considered Options

- **Always `mutate` for Templates.** No trust in Node reports at all. Rejected: the shipped
  catalog is `read` by design, and putting every observation behind the mutate cap and
  mutate-keyed approval recreates the friction ADR-0012 split the cap to remove.
- **A Relay-pinned class per Template name.** Strongest, and a new operator-managed runtime
  object with step-up and audit (invariant 11). Disproportionate before Templates have a single
  caller; kept as future work.
- **Dispatch blind to Nodes with no report, counting the dispatch as `mutate`.** Fewer
  surprises after a Relay restart, but sends a Task to a Node whose vocabulary the Relay has
  never seen. Rejected in favour of exclusion.
- **No Relay-side argument-name check.** Simpler, and reopens #345 for every Template typo.
  Rejected.
- **Resolving the class in each adapter.** Forbidden outright by invariant 10.

## Consequences

- ADR-0021 is amended: Templates are dispatchable on every execution surface, by name, through
  the capability layer, under the rules above.
- ADR-0012 is amended: a Template's class is not compiled into `/proto` like a Native's; it is
  declared in the Node's Policy, reported by the Node, and resolved by the rule above.
  Raw Exec is still always `mutate`, and the class still chooses the cap.
- `unsupported` gains a Relay-reported form (a Node excluded at resolution) beside the
  daemon-reported one, recorded as a Task resolved without being sent — the precedent is
  `version_refused` (ADR-0014).
- `list_operations` keeps its per-Node view; a Selector-wide view of the vocabulary stays future
  work in `query.md`.
