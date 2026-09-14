# Observability

**Status:** stub — aspirational, not yet worked through with the owner (`2026-09-13`).

## Purpose

Observability is what an operator can see of Relay's own operational health: is the Relay up,
how much of the fleet is connected, is dispatch succeeding or being refused and why, is a Freeze
engaged, is a certificate about to lapse, which build is running. It is what an SRE wires into
the monitoring they already have, so that Relay is a well-behaved service in someone's
datacentre rather than a black box.

It is deliberately **not** the audit trail. The audit trail answers *who did what to which Node*
and is a record of decisions; observability answers *is the system healthy* and must stay safe
to ship to a metrics or log pipeline that far more people can read — which means it never
carries secrets, command output or Operation arguments, and never grows a series per Node.

## Surfaces

- **Metrics** — a Prometheus text exposition at `/metrics` on the control-plane listener, behind
  the same authentication as MCP and the Control API. Absent when the control plane is off,
  though the counters behind it run regardless.
- **Relay logs** — structured process logs to standard error, collected by the journal under the
  shipped unit. Includes one routing-only line per audited decision.
- **relay-daemon logs** — structured logs on each Node, collected by that Node's own journal.
  The daemon exposes no metrics.
- **The Console's live event feed** — a server-sent stream of Relay events. Uncertain whether
  this is observability or Console behaviour.
- **Health and readiness endpoints** — none exist today.

## Behaviour

_To be established by interrogation._

Candidate claims, from the ADRs and the code — each to be confirmed, changed or dropped:

- Every metric is aggregate-only: its labels are drawn from small closed enums (dispatch outcome,
  refusal reason, listener, label namespace), and no metric ever carries a Node ID, Account,
  API Token, Selector, Operation argument or free-text reason.
- Series cardinality is independent of fleet size: the same set of series at five Nodes as at
  a hundred thousand.
- The one free-form label set is the build stamp, fixed for the process's lifetime.
- Metrics cover connected Nodes, enrolled and revoked Nodes, Freeze engagement, dispatches by
  outcome, refusals by reason, successful enrollments, server certificate rotations by listener,
  declined Labels by namespace, and the build.
- A gauge whose source fails to read is omitted from the scrape rather than reported as a false
  value.
- A metric is never an input to a decision: nothing reads it back.
- Neither Relay nor relay-daemon ever logs a token, private key, secret value, Operation
  argument, Raw Exec argv or command output.
- The per-decision log line and the audit record are written by the same call, so they cannot
  disagree about whether a decision happened.
- Reaching `/metrics` requires an authenticated Account; it grants no execution capability.

## Refusals

_To be established by interrogation._

Candidate claims, from the ADRs and the code — each to be confirmed, changed or dropped:

- An unauthenticated scrape is refused like any other control-plane request.
- With the control plane disabled there is no `/metrics` route at all.

## Governing ADRs and invariants

**No ADR governs observability as a capability.** The constraints come from elsewhere:

- **Invariant 10 / ADR-0009, ADR-0010** — `/metrics` is an adapter on the shared control-plane
  listener with no execution path, covered by the same authentication as every other surface.
- **Invariant 11** — observability may report configuration's consequences but never offers a
  path to change them.
- **ADR-0025** — read output is audited but not retained, and so never appears in logs or
  metrics either.
- **AGENTS.md security posture** — never log secrets.
- **ADR-0034** — `state:cert-expiring` is the Node-side certificate alarm; certificate rotation
  metrics are its Relay-side counterpart.

## Seams and proof

_Not yet written._

## Out of scope

- Audit records — what is recorded, who can read them, retention — `audit-and-read-lane.md`.
- Fleet state as seen by an AI-agent or operator (Node liveness, `state:` labels,
  `describe_node`) — `query.md` and `selectors-and-labels.md`. Metrics count; they never list.
- Approval notifications and webhooks — `approval.md`.
- Where metrics and logs are configured (listener, log destination) — `relay-configuration.md`.
- Monitoring the customer's own services on Nodes — out of realm: that is configuration
  management and existing monitoring, not Relay.

## Open questions

1. **Health and readiness.** There is no liveness or readiness endpoint, and `/metrics` needs a
   credential. Do you want an unauthenticated health check a load balancer can hit, and what may
   it reveal?
2. **Who may scrape?** `/metrics` accepts any authenticated Account today. Should scraping take a
   dedicated low role, so a Prometheus credential cannot also read the fleet or dispatch?
3. **Should metrics be on the control-plane listener at all?** They vanish when the control plane
   is off, and they share an exposure posture with MCP. A separate, metrics-only listener is the
   common alternative — do you want one?
4. **What is missing that an SRE would page on?** Nothing measures dispatch latency, Task queue
   depth, pending approvals, reconnect churn, enrollment refusals by reason, store size or
   webhook delivery failures. Which of these belong?
5. **The daemon is dark.** relay-daemon has logs but no metrics, and at a hundred thousand Nodes
   nobody reads per-Node journals. Is daemon health something the Relay should aggregate from
   `Hello` and heartbeats, or strictly the customer's monitoring?
6. **Log format and level are not configurable** on the Relay; the daemon's level follows a
   generic environment variable rather than a `RELAY_` one. Do you want JSON logs and an
   operator-set level, and should both follow the naming rule?
7. **Is the per-decision log line wanted?** It duplicates routing metadata from the audit trail
   into a pipeline with weaker access control. Keep it, drop it, or make it opt-in?
8. **The Console's live event feed** — is it an observability surface with its own contract,
   or purely Console behaviour described in the Console design?
9. **Is "never a series per Node" absolute?** Some operators will want per-Node dispatch
   failure counts. Confirm that belongs in `query.md`, never in metrics.
10. **OpenTelemetry.** The exposition is hand-rolled Prometheus text. Is Prometheus the committed
    format, or should traces and OTLP export be in scope?
11. **Should the effective security floor be exported as metrics** (blast caps, gate count,
    minimum daemon version) so drift between hosts is alertable — or is that reading
    configuration over the wire?

## History

- `2026-09-13` — stub created to name the capability.
