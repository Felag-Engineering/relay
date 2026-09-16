# Observability

**Status:** aspirational — worked through with the owner on `2026-09-15`, awaiting their review of
this draft. Describes intended behaviour, not the code (see the establishing phase in
`README.md`).

## Purpose

Observability is what an operator can see of **Relay's own operational health**: is it up, how
much of the fleet is connected, is dispatch succeeding or being refused and why, are approvals
piling up unanswered, is a Freeze engaged, is a certificate lapsing, which build is running. It
is what an SRE wires into the monitoring they already run, so Relay is a well-behaved service in
someone's datacentre rather than a black box.

It is deliberately **not the audit trail**. The audit trail answers *who did what to which Node*
and is a record of decisions. Observability answers *is the system healthy*, and it must stay
safe to ship into a metrics pipeline far more people can read — so it never carries secrets,
command output, Operation arguments or a series per Node.

## Surfaces

| Surface | What it is |
|---|---|
| **Metrics listener** | A third listener, separate from the Node and control-plane listeners, serving Prometheus text and nothing else. Bound to loopback by default; its address is security floor (`relay-configuration.md`) |
| **Health endpoint** | Unauthenticated, on the metrics listener: "serving" or "not serving" and nothing more |
| **Relay logs** | Structured process logs to standard error, collected by the journal under the shipped unit. One routing-only line per audited decision |
| **relay-daemon logs** | Structured logs on each Node, collected by that Node's journal. The daemon exposes no metrics |
| **Control plane, MCP, Console** | Not observability surfaces. They answer questions about the fleet, which is `query.md` |

The metrics listener carries **no execution path and no fleet contents** — counters only. Its
access control is the bind address: whoever can reach the port may scrape, which is why loopback
is the default and why an operator who binds it wider is publishing aggregate numbers to that
network.

Separating it from the control plane is deliberate on two counts. A Prometheus scrape no longer
needs an API Token that could also list the fleet or dispatch, and metrics keep answering when
the control plane is switched off — the counters were running anyway.

## Behaviour

### What is measured

Aggregate only. Every label is drawn from a small closed enum — dispatch outcome, refusal
reason, listener, label namespace — and the one free-form value is the build stamp, fixed for the
process's lifetime.

Today: build info, dispatches by outcome, refusals by reason, Nodes connected, enrolled and
revoked, enrollments, Freeze engagement, server certificate rotations by listener, and Labels
declined by namespace.

Added, because they are what an SRE pages on and an AI-driven fleet fails at first: dispatch
latency as a histogram, Task queue depth, pending approvals, reconnect churn, enrollment refusals
by reason, store size, webhook delivery failures, and the count of connected Nodes below the
minimum daemon version — a boolean bucket, never a series per version string, so release churn
cannot inflate cardinality.

### Cardinality is a security property, not a performance one

**The same set of series at a hundred Nodes as at a hundred thousand.** No metric carries a Node
ID, Account, API Token, Selector, Operation argument or free-text reason.

That rule is what keeps the metrics pipeline outside the fleet's trust boundary: a pipeline many
people can read must not become a way to learn which Nodes exist, who acted, or what was run.
Per-Node numbers are a real need and they are answered by `query.md`, which is authorized and
audited.

### Honest gauges

A gauge whose source cannot be read is **omitted from the scrape**, never emitted as a zero or a
stale value. A missing series is a legible failure; a false one is a wrong answer an alert will
believe.

Nothing reads a metric back. A metric never influences a decision, never gates a dispatch, and
never feeds Policy, Selector resolution or the blast cap.

### Logs

Relay logs are structured, on standard error, collected by the journal. JSON output and the log
level are operator settings in the store (`relay-configuration.md`). The daemon's level follows a
`RELAY_`-prefixed variable, like every other Node setting.

One routing-only line accompanies each audited decision, written by the same call that writes the
audit record so the two cannot disagree about whether a decision happened. It carries routing
metadata only — never arguments, never output.

**Neither Relay nor relay-daemon ever logs a token, private key, secret value, Operation
argument, Raw Exec argv or command output.** Read output is audited but not retained (ADR-0025),
and so cannot reach a log or a metric either.

### The daemon stays dark

relay-daemon has logs and no metrics, and grows no exporter. At a hundred thousand Nodes nobody
reads per-Node journals, and a per-Node scrape target is a hundred thousand scrape targets.

What the Relay already knows from `Hello` and heartbeats it exposes as fleet aggregates —
connected counts, version-floor counts, reconnect churn. Per-Node health is a question with an
answer, and that answer is `query.md`.

## Refusals

| Refusal | Cause |
|---|---|
| Unreachable | A scrape from outside the metrics listener's bind address. The port is the access control |
| Not serving | The health endpoint while the Relay is starting or shutting down. It reveals nothing else |
| Series omitted | A gauge whose source failed to read |
| No route exists | Any attempt to change configuration, dispatch, or read fleet contents through the metrics listener. There is nothing there to refuse |

## Governing ADRs and invariants

**No ADR governs observability as a capability.** Its constraints come from elsewhere:

- **Invariant 10 / ADR-0009, ADR-0010** — the metrics listener is an adapter with no execution
  path; it decides nothing.
- **Invariant 11** — observability reports configuration's consequences and offers no path to
  change them. The security floor itself is not exported: drift between hosts is real, but
  publishing the caps and gate count publishes the fleet's ceiling to anyone who can scrape.
- **ADR-0025** — read output is audited and not retained, so it reaches neither logs nor metrics.
- **ADR-0034** — `state:cert-expiring` is the Node-side certificate alarm; rotation counters are
  its Relay-side counterpart.
- **AGENTS.md security posture** — never log secrets.

## Seams and proof

Metrics live behind a counter and gauge-sampler seam that the rest of the Relay increments and
never reads. Gauges are pulled from sources at scrape time rather than maintained as state, which
is what makes "omit on failure" expressible.

### What proves each claim

| Behaviour | Proven by | Seam |
|---|---|---|
| Every dispatch outcome and refusal kind has a series | `TestIncDispatch_EveryOutcome`, `TestIncRefusal_EveryKind` | metrics |
| An out-of-range outcome falls back rather than creating a series | `TestIncDispatch_OutOfRangeFallsBackToUnspecified`, `TestIncServerCertRotation_OutOfRangeFallsBackToNodePlane` | metrics |
| A gauge whose source fails is omitted, not reported false | `TestHandler_SamplerErrorOmitsGaugeLine`, `TestHandler_NilSamplerOmitsGaugeLine` | metrics |
| Declined-Label series are per namespace, and absent when unwired | `TestHandler_LabelsDeclinedSeries`, `TestHandler_NilLabelsDeclinedOmitsSeries` | metrics |
| Gauges render from their sources, and the build stamp is omitted when unset | `TestHandler_GaugesFromSources`, `TestHandler_BuildInfo`, `TestHandler_BuildInfoOmittedWhenUnset` | metrics |
| The exposition is Prometheus text | `TestHandler_ContentType` | metrics |
| Today's `/metrics` path requires a credential | `TestMetricsSurface_RequiresCredential` | e2e |

Claims above with **no row**, and so nothing checking them:

- **That no metric can carry a Node ID, Account, Token, Selector or argument.** The central
  property of this capability, and it holds today by every call site being written carefully. A
  structural test — like `no_dispatch` for adapters — is what would keep it true.
- That series count is independent of fleet size. Provable by construction today; nothing asserts
  it, and a histogram added later is how it would break.
- That neither binary ever logs a secret, an argument or command output. Asserted for enrollment
  tokens only (`TestNoSecretInLogs`); nothing covers Operation arguments or Raw Exec argv.
- That the per-decision log line and the audit record cannot disagree.
- That the metrics listener exposes no execution path — the `no_dispatch` guard covers the other
  adapters and this listener does not exist yet.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Scrape | Gauges sampled at scrape time; a slow source delays a scrape and never a dispatch | *(none)* |
| Series count | Constant in fleet size | *(none)* |

## Out of scope

- Audit records — what is recorded, who may read them, retention — `audit-and-read-lane.md`.
- Fleet state: Node liveness, `state:` labels, `describe_node`, per-Node history — `query.md`
  and `selectors-and-labels.md`. **Metrics count; they never list.**
- Approval notifications and webhooks — `approval.md`. Their *delivery failures* are counted here.
- Where the listener binds and how logs are configured — `relay-configuration.md`.
- Monitoring the customer's own services on their Nodes. Out of realm: that is their existing
  monitoring, not Relay.

## Future work

- **OpenTelemetry** — OTLP export and traces. Prometheus text is the committed format; OTel is an
  option, not a promise, and it adds a dependency and an export path to a security-critical
  binary.
- **A structural cardinality guard**, so "no metric carries an identifier" is enforced by the
  build rather than by review.
- **Exporting the security floor for drift detection**, if running many Relays ever makes
  per-host drift a real operational problem.

## Open questions

- **Does the health endpoint need to distinguish "starting" from "degraded"?** A load balancer
  wants one bit; an operator debugging a stuck start wants more, and more is exactly what an
  unauthenticated endpoint should not give.
- **What is the retention and scrape interval assumption behind the latency histogram?** Bucket
  boundaries are a contract once dashboards depend on them.

## History

- `2026-09-15` — First worked through with the owner. Metrics move to a third, loopback-bound
  listener with an unauthenticated health endpoint; operational signals added (latency, queue
  depth, pending approvals, reconnect churn, enrollment refusals, store size, webhook failures,
  below-minimum-version count); the daemon stays dark and is aggregated Relay-side; Prometheus
  text committed with OpenTelemetry deferred; the security floor is not exported.
- `2026-09-13` — Stub created to name the capability.
