# Observability

**Status:** aspirational — worked through with the owner on `2026-09-15`, awaiting their review of
this draft. Describes intended behaviour, not the code (see the establishing phase in
`README.md`).

## Purpose

Observability is what an operator can see of **Relay's own operational health**: is it up, how
much of the fleet is connected, is dispatch succeeding or being refused and why, are approvals
piling up unanswered, is a Freeze engaged, is a certificate lapsing, which build is running. An
SRE wires it into the monitoring they already run.

It is deliberately **not the audit trail**, which records decisions: *who did what to which
Node*. Observability answers *is the system healthy*, and must stay safe to ship into a metrics
pipeline far more people can read — so it never carries secrets, command output, Operation
arguments or a series per Node.

## Surfaces

| Surface | What it is |
|---|---|
| **Metrics** | Prometheus text at `/metrics` on the control-plane listener, behind the same API-token authentication as every other control-plane route. There is no third listener. Built |
| **Health endpoint** | Unauthenticated, on the control-plane listener: "serving" or "not serving" and nothing more. MVP work, not yet built |
| **Relay logs** | Structured process logs to standard error, collected by the journal under the shipped unit. One routing-only line per audited decision |
| **relay-daemon logs** | Structured logs on each Node, collected by that Node's journal. The daemon exposes no metrics |
| **Control plane, MCP, Console** | Not observability surfaces. They answer questions about the fleet, which is `query.md` |

The metrics route carries **no execution path and no fleet contents**, only aggregate numbers.
A scraper authenticates with an API Token like any other control-plane caller
(`accounts-and-access.md`), so metrics answer only while the control plane is on. A separate
listener that needs no token is later work (`roadmap: relay/opentelemetry`).

The health endpoint is the one unauthenticated route. It answers one bit, so a load balancer or
an init system can probe it without a credential, and it reveals nothing else.

## Behaviour

### What is measured

Aggregate only. Every label is drawn from a small closed enum — dispatch outcome, refusal
reason, listener, label namespace — and the one free-form value is the build stamp, fixed for the
process's lifetime.

Built, about a dozen metrics: build info, Nodes connected, enrolled and revoked, dispatches by
outcome, refusals by reason, Freeze engagement, server certificate rotations by listener, protocol
violations, Labels declined by namespace, and enrollments.

Added for the MVP, because an SRE pages on them, and not yet built:

- **Certificate expiry**, for the Relay CA and the server certificate.
- **Failed authentications.**
- **Approvals waiting** for an answer.

Nothing in this set is a series per Node, per Account or per argument. A fuller metric set, such
as dispatch latency, reconnect churn and store size, is later work (`roadmap: relay/opentelemetry`).

### Cardinality is a security property, not a performance one

**The same set of series at a hundred Nodes as at a hundred thousand.** No metric carries a Node
ID, Account, API Token, Selector, Operation argument or free-text reason.

That keeps the metrics pipeline outside the fleet's trust boundary: a pipeline many people can
read must not reveal which Nodes exist, who acted, or what was run. Per-Node numbers come from
`query.md`, which is authorized and audited.

### Honest gauges

A gauge whose source cannot be read is **omitted from the scrape**, never emitted as a zero or a
stale value. A missing series is a legible failure; a false one is a wrong answer an alert will
believe.

Nothing reads a metric back. A metric never influences a decision, never gates a dispatch, and
never feeds Policy, Selector resolution or the blast cap.

### Logs

Relay logs are structured JSON on standard error, collected by the journal. The format is fixed;
the log level is set in the configuration file and applied on reload (`relay-configuration.md`).
Store-backed settings are not in the MVP (`roadmap: relay/settings-in-the-console`). The daemon's
level follows `RUST_LOG`.

One routing-only line accompanies each audited decision, written by the same call that writes the
audit record so the two cannot disagree about whether a decision happened. It never carries
arguments or output.

**Neither Relay nor relay-daemon ever logs a token, private key, secret value, Operation
argument, Raw Exec argv or command output.** Read output is audited but not retained (ADR-0025),
and so cannot reach a log or a metric either. One exception is accepted for now: a Policy
denial's text can quote caller-supplied text, and so an argument, into the daemon log
(`policy.md`, Accepted residual risk; threat model R20).

### The daemon stays dark

**Relay reports telemetry about itself and the fleet's relationship to it, and never collects or
forwards host telemetry from Nodes** (owner decision, 2026-10-23). relay-daemon has logs and no
metrics, and grows no exporter: at a hundred thousand Nodes nobody reads per-Node journals, and
per-Node scraping means a hundred thousand scrape targets.

What the Relay knows from `Hello` and heartbeats it exposes as fleet aggregates, such as the
connected, enrolled and revoked counts. Per-Node health is `query.md`.

## Refusals

| Refusal | Cause |
|---|---|
| Unauthenticated | A scrape of `/metrics` without a valid API Token, refused like any control-plane call |
| Not serving | The health endpoint while the Relay is starting or shutting down. It reveals nothing else |
| Series omitted | A gauge whose source failed to read |
| No route exists | Any attempt to change configuration, dispatch, or read fleet contents through the metrics or health route. There is nothing there to refuse |

## Governing ADRs and invariants

**No ADR governs observability as a capability.** Its constraints come from elsewhere:

- **Invariant 10 / ADR-0009, ADR-0010** — the metrics and health routes are adapters with no
  execution path; they decide nothing.
- **Invariant 11** — observability reports configuration's consequences and offers no path to
  change them. The security floor itself is not exported: drift between hosts is real, but
  publishing the caps and gate count publishes the fleet's ceiling to anyone who can scrape.
- **ADR-0025** — read output is audited and not retained, so it reaches neither logs nor metrics.
- **ADR-0034** — `state:cert-expiring` is the Node-side certificate alarm; the certificate expiry
  metric and the rotation counters are its Relay-side counterpart.
- **AGENTS.md security posture** — never log secrets.

## Seams and proof

Metrics live behind a counter and gauge-sampler seam that the rest of the Relay increments and
never reads. Gauges are pulled from sources at scrape time, not maintained as state, which makes
"omit on failure" expressible.

### What proves each claim

| Behaviour | Proven by | Seam |
|---|---|---|
| Every dispatch outcome and refusal kind has a series | `TestIncDispatch_EveryOutcome`, `TestIncRefusal_EveryKind` | metrics |
| An out-of-range outcome falls back rather than creating a series | `TestIncDispatch_OutOfRangeFallsBackToUnspecified`, `TestIncServerCertRotation_OutOfRangeFallsBackToNodePlane` | metrics |
| A gauge whose source fails is omitted, not reported false | `TestHandler_SamplerErrorOmitsGaugeLine`, `TestHandler_NilSamplerOmitsGaugeLine` | metrics |
| Declined-Label series are per namespace, and absent when unwired | `TestHandler_LabelsDeclinedSeries`, `TestHandler_NilLabelsDeclinedOmitsSeries` | metrics |
| Gauges render from their sources, and the build stamp is omitted when unset | `TestHandler_GaugesFromSources`, `TestHandler_BuildInfo`, `TestHandler_BuildInfoOmittedWhenUnset` | metrics |
| The exposition is Prometheus text | `TestHandler_ContentType` | metrics |
| `/metrics` requires a credential | `TestMetricsSurface_RequiresCredential` | e2e |

Claims above with **no row**, and so nothing checking them:

- **That no metric can carry a Node ID, Account, Token, Selector or argument.** The central
  property here, held today only by careful call sites. A structural test like `no_dispatch`
  would keep it true.
- That series count is independent of fleet size. True by construction today; nothing asserts it,
  and a histogram added later is how it would break.
- That neither binary ever logs a secret, an argument or command output (R20 excepted). Asserted
  for enrollment tokens only (`TestNoSecretInLogs`); nothing covers Operation arguments or Raw
  Exec argv.
- That the per-decision log line and the audit record cannot disagree.
- That the metrics and health routes expose no execution path.
- That the health endpoint answers only serving or not serving, without a credential. It is not
  built yet.
- The three MVP metrics: certificate expiry, failed authentications, approvals waiting. Not built
  yet.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Scrape | Gauges sampled at scrape time; a slow source delays a scrape and never a dispatch | *(none)* |
| Series count | Constant in fleet size | *(none)* |

## Out of scope

- Audit records — what is recorded, who may read them, retention — `audit-and-read-lane.md`.
- Fleet state: Node liveness, `state:` labels, `describe_node`, per-Node history — `query.md`
  and `selectors-and-labels.md`. **Metrics count; they never list.**
- Approval notifications and webhooks — `approval.md`. Their delivery failures are not counted in
  the MVP.
- Where the control-plane listener binds and the log level — `relay-configuration.md`.
- **Host telemetry from Nodes.** Relay reports telemetry about itself and the fleet's relationship
  to it, and never collects or forwards host telemetry: no Node's CPU, memory, disk, services or
  journal reach a metric, and the daemon exports no metrics. Monitoring the customer's hosts and
  services is their existing monitoring, not Relay (owner decision, 2026-10-23).
- **A separate metrics listener, traces, OTLP export and a fuller metric set** —
  `roadmap: relay/opentelemetry`.

## Accepted residual risk

- **Policy denial text can carry an argument into the daemon log.** Accepted by the owner on
  `2026-09-17`; the risk, its compensating control and its fix are recorded in `policy.md` and
  threat model R20.

## Future work

Waits in the private roadmap: OpenTelemetry, the separate listener and the fuller metric set
(`roadmap: relay/opentelemetry`); a structural cardinality guard and exporting the security floor
(`roadmap: relay/research/spec-future-work/observability`).

## Open questions

None open. The health endpoint answers one bit, serving or not serving (owner, 2026-10-23). The
latency histogram's bucket question moved to the roadmap with the histogram.
