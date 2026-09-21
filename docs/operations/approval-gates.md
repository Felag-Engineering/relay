# Approval gates

Which dispatches must wait for a human before they run ([ADR-0027](../adr/0027-approval-callout-notify-via-mcp-decide-out-of-band.md)).

## Where the configuration lives

A root-owned local file, named by `--approval-gate-config` (or
`RELAY_APPROVAL_GATE_CONFIG`). It sits with the blast caps on the
Relay-configuration side of the line: **no Account of any role can read or write
it through the Control API** (invariant 11). A stolen credential that could edit
its own approval requirements would make the mechanism decorative.

```
relay --approval-gate-config /etc/relay/approval-gates.json
```

**No path configured means no approval gating.** That is the only way to get a
gate-less Relay, and it is safe because a gate can only ever *add* a reason to
stop — never grant one. Every other outcome is a startup failure:

| Situation | Result |
|---|---|
| No path configured | No gates. Pre-v0.5.0 behaviour. |
| Path configured, file missing | **Startup fails** |
| Malformed JSON, unknown field, invalid value | **Startup fails** |
| File is a symlink, a directory, or group/world-writable | **Startup fails** |

The asymmetry is the point. A Relay that silently decided nothing needs approval
because it could not read its own config is exactly the failure this mechanism
exists to prevent, so an unreadable file is never allowed to degrade into an
empty rule set.

Install it `0644 root:root` or stricter.

## Format

JSON — parsed by the Go standard library. TOML or YAML would be friendlier to
hand-author, but both mean adding a parser dependency to a security-critical
control plane in order to parse a security-critical file, and that trade is not
worth making for ergonomics. In practice this file is rendered by config
management.

```json
{
  "rules": [
    {
      "name": "prod-mutates-need-two-people",
      "match": {
        "risk_class": "mutate",
        "min_fan_out": 10,
        "selector_namespace": "relay"
      },
      "require": {
        "count": 2,
        "audience": ["ana", "bo", "mike"],
        "requester_allowed": false,
        "channel": "out-of-band",
        "ttl": "2h"
      }
    },
    {
      "name": "raw-exec-always-asks",
      "match": { "raw_exec": true },
      "require": { "count": 1, "channel": "out-of-band", "ttl": "30m" }
    }
  ]
}
```

### `match` — when the rule applies

Every field is optional; an omitted field matches anything. A `match` with no
fields matches every dispatch, which is a legitimate way to say "everything
needs approval".

| Field | Meaning |
|---|---|
| `risk_class` | `read` or `mutate` |
| `min_fan_out` | Matches dispatches touching **at least** this many Nodes |
| `selector_namespace` | `node`, `relay`, or `tag` — the namespace the Selector used |
| `account` | The requesting Account's name |
| `operation` | An Operation name, e.g. `service.restart` |
| `raw_exec` | `true` restricts the rule to the Raw Exec path |

### `require` — what it demands

| Field | Default | Meaning |
|---|---|---|
| `count` | `1` | Distinct approvals needed. v1 accepts `1` or `2`. |
| `audience` | any | Account names that may decide |
| `requester_allowed` | **`false`** | Whether the requester may satisfy a slot |
| `channel` | **`out-of-band`** | `in-band` or `out-of-band` |
| `ttl` | `4h` | How long the parked dispatch waits |

Both defaults in bold are the strict reading. An omitted `requester_allowed`
requires a second person, and an unstated `channel` gets the stronger one — an
unstated channel must never silently mean "trust the harness".

## How overlapping rules combine

When several rules match one dispatch, their requirements merge to the
**strictest**: the highest `count`, the stronger `channel`, the shorter `ttl`,
and `requester_allowed: false` if any matching rule says so.

This is deliberately *not* first-match-wins. First-match-wins would make rule
order security-relevant and would let a broad permissive rule shadow a narrow
strict one — the mistake that makes firewall rulesets dangerous. Here, **adding
a rule can only ever tighten the outcome**, so you cannot accidentally weaken an
existing rule by writing a broader one, and rule order does not matter.

The Relay refuses at startup to load a rule that can never be satisfied — for
example `count: 2` with a single-member `audience`.

## What happens when a dispatch is gated

1. The dispatch resolves its Selector, passes authz and the blast cap, and then
   **parks**. No Job and no Tasks are created, so nothing is left behind that a
   restart could mistake for interrupted work.
2. The Relay records an `approval_requested` audit entry and returns a park to
   the caller carrying the request ID, the plan hash, and which rules fired. On
   `/api/v1` that is a **`202 Accepted`** with `"status": "pending_approval"` —
   not a `200` (nothing ran) and not an error (nothing was denied).
   Re-driving the same dispatch while it waits — which is how a caller polls —
   returns the same park but audits as `approval_pending_observed`, not a
   second `approval_requested`: the request count stays truthful, and the
   polling itself stays on the record.
3. A human decides. An **out-of-band** decision arrives through the decision endpoint or the
   Admin Console, on a channel other than the requesting MCP session. An **in-band** decision
   (`approve_request`, and MRTR elicitation once built — ADR-0029) travels through the tool
   surface with an *asserted* approver, and satisfies only an `in-band` rule, never an
   `out-of-band` one.
4. Once the requirement is satisfied, the same dispatch proceeds and the
   approval is bound to the Job it released, so audit can answer "who approved
   what actually ran" in one join.

## The decision endpoint

Three routes on `/api/v1`, published in [the OpenAPI spec](../api/openapi.yaml):

| Route | Who |
|---|---|
| `GET /api/v1/approvals` | any authenticated Account — the queue |
| `GET /api/v1/approvals/{id}` | any authenticated Account |
| `POST /api/v1/approvals/{id}/decision` | see the floor below |

```bash
# What is waiting?
curl -s -H "Authorization: Bearer $RELAY_TOKEN" https://relay:9443/api/v1/approvals

# Answer one. plan_hash is required.
curl -s -X POST -H "Authorization: Bearer $RELAY_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"approve":true,"plan_hash":"<from the request>","reason":"change ticket OPS-91"}' \
  https://relay:9443/api/v1/approvals/<request-id>/decision
```

Reading the queue is open to every authenticated Account, including `viewer`. A
rule's `audience` restricts who may **decide**, not who may see that a decision
is owed — hiding pending fleet state from the operators watching it buys nothing,
since every entry is a Relay-authored summary of an action they can already read
in the audit trail.

### Who may decide

**The floor for deciding is the floor the Action needed to be requested.**
Approving an Operation needs `operator`; approving a Raw Exec needs `admin` —
the same ladder, read from the same `authz.RoleGate`. An operator who cannot
*ask* for Raw Exec cannot *release* someone else's, or ADR-0001's admin-only rule
would hold for asking and not for granting.

On top of the role floor, the domain refuses a decision that:

| Situation | Result |
|---|---|
| Request already decided, or past its deadline | `409` |
| Requester decides their own, under `requester_allowed: false` | `409` |
| A **machine** Account decides its own, under **any** configuration | `409` |
| The same Account fills a second quorum slot | `409` |
| `plan_hash` no longer matches | `409` |
| Decider outside the rule's `audience` | `403` |

The machine rule is not `requester_allowed` restated. That knob is *your*
configuration; this one is structural. ADR-0027's confirmation ladder puts
self-confirmation at rung 2 and makes rung 2 **human-only**, because an agent
confirming its own proposal is the same actor answering twice — so a
misconfigured `requester_allowed: true` can never hand an AI-agent its own
approval.

A machine Account *may* decide **someone else's** request if its role clears the
floor. That is a real deployment (an approval bridge holding its own credential),
and it is worth understanding what it costs you: the verified approver in audit
is then the bridge, not whoever the bridge asked. If that is not the attribution
you want, keep machine Accounts out of the `audience`.

### The channel is set by the door, not the caller

The decision body has **no `channel` field**, and sending one is a `400`. Every
decision that arrives on this endpoint is recorded `out-of-band` because of what
the endpoint is. A channel a request body could name is a channel a request body
could upgrade, which would make the whole in-band/out-of-band distinction
decoration.

Strength is a floor, not an equality check: an out-of-band answer satisfies an
`in-band` rule (it is more evidence than was asked for), and an in-band answer
never satisfies an `out-of-band` rule. An unstamped channel satisfies nothing.

### Deciding does not dispatch

A satisfied requirement lets the **same Plan** proceed the next time it is
driven. The caller re-issues the request; the Relay looks up the approval by plan
hash and lets it through. Nothing runs at the moment of approval, which is
exactly why fleet drift between the answer and the run re-parks instead of
silently widening what was approved.

## Notifying an approver

Optional, and never load-bearing. With a webhook configured the Relay POSTs a
Relay-authored notice, once, when a dispatch parks:

```
relay --approval-webhook-url https://notify.internal/relay-approvals \
      --approval-webhook-secret-file /etc/relay/approval-webhook.key
```

| Flag / env | Meaning |
|---|---|
| `--approval-webhook-url` / `RELAY_APPROVAL_WEBHOOK_URL` | Where to POST. HTTPS required off-loopback. Empty disables it. |
| `--approval-webhook-secret-file` / `RELAY_APPROVAL_WEBHOOK_SECRET_FILE` | Root-owned `0600` file holding the HMAC-SHA256 signing secret. Empty sends unsigned. |
| `--approval-webhook-timeout` / `RELAY_APPROVAL_WEBHOOK_TIMEOUT` | Budget for one delivery attempt (default `5s`). |

Signed deliveries carry `Relay-Timestamp` and
`Relay-Signature: sha256=<hex>` over `"<timestamp>.<body>"`, so a receiver can
check authenticity *and* freshness. The signature authenticates **the Relay to
the receiver**; it is not an authorization mechanism, and there is no callback
for it to protect — decisions only ever arrive on `/api/v1`.

Delivery is **one attempt, no retry, no queue**, and it never blocks or fails a
park. A park is durable, audited, and in the queue before the notification is
attempted, so an endpoint that is down costs an approver a poll and nothing else.
Configuration is the fail-closed half: a webhook you asked for and did not get
would leave you believing you will be paged, so an invalid URL or an
unreadable/world-readable secret file **refuses startup**.

**What leaves the Relay.** The body carries the plan summary, which includes the
Operation's *arguments* — they are what the approver is deciding about. It
carries no credential, no token, and no captured output. Treat the endpoint as a
disclosure boundary with the same trust level as the audit trail; the known
residual that a secret passed as an Operation argument reaches the audit trail
verbatim reaches this body by the same route.

### Approvals bind to a plan hash, not to a Job

An approval commits to the Operation, its arguments, **and the resolved
fan-out**. If the fleet drifts between approval and dispatch — a Node joins the
Selector's match set — the hash differs, the approval no longer applies, and the
dispatch re-parks. This closes the park-something-innocuous-then-mutate-the-world
gap, and there is no "close enough" comparison anywhere in the path.

### Everything expires

Parked requests and granted approvals both stop being redeemable at their
deadline. Expiry is enforced by the clock at read time, so it holds even if the
background sweeper is not running; the sweeper's job is to retire lapsed
requests from the queue and record an `approval_expired` audit entry.

## How an agent waits: three envelopes, one decision

An operator meeting this system for the first time should be clear that the
paragraphs below are about **how a caller learns it must wait and how it finds
out the answer arrived**. None of them is about who may decide, and none of them
can be used to decide. That question is settled once, on the decision endpoint,
and every envelope here routes around it rather than through it.

| Envelope | Who gets it | How it waits |
|---|---|---|
| `202 pending_approval` on `/api/v1` | every Control API caller | re-drive the same call |
| `pending_approval` tool result over MCP | every MCP client | re-drive the same call |
| **MCP task handle** (SEP-2663) | MCP clients that advertised the Tasks extension | poll `tasks/get` |

The first two are the **universal path**, and they are what makes the guarantee
independent of client behaviour: a harness with zero approval features still
drives a gated dispatch to completion by calling the same thing again once a
human has answered. Nothing in the system may come to depend on anything richer
([ADR-0027](../adr/0027-approval-callout-notify-via-mcp-decide-out-of-band.md)
decision 2).

### The MCP task handle

For a client that advertises `io.modelcontextprotocol/tasks`, a parked
`tools/call` comes back as a **task result** carrying a handle, and the client
polls `tasks/get` instead of re-driving the call. `tasks/cancel` ends its
interest.

What this buys, precisely:

- **A poll stops being a dispatch attempt.** Re-driving runs the whole
  Selector → authz → blast-cap → gate path every few seconds just to be told
  "still waiting". `tasks/get` reads state. The audit distinction
  `approval_pending_observed` exists because polling-by-re-driving had to be
  told apart from asking; with a handle the problem does not arise.
- **Server-controlled cadence.** The response carries `pollIntervalMs`
  (5 s — the wait being timed is a human one) and `ttlMs`.

And what it explicitly does **not** change:

- **Who may decide.** A handle is a poll token, not a decision one. The only MCP path that
  records a decision is the in-band one (`approve_request`, ADR-0029), through the same guarded
  capability-layer seam as every other decision; a task handle never decides anything.
- **What `tasks/cancel` reaches.** It marks the *handle* cancelled. If the
  dispatch is still parked, the approval request stays pending, stays in the
  queue, and stays decidable; a re-drive of the same Plan re-attaches to it. A
  cancel arrives over the AI's own session, and if it could withdraw a pending
  request an agent could pull one back the moment it sensed a denial coming —
  erasing the evidence a human was about to rule on. If a Job already exists,
  cancelling goes through the ordinary Job-cancel path with its ordinary
  honest-cancel semantics.
- **Who can see a handle.** Resolving one is owner-only. A handle that is not
  yours is indistinguishable from one that never existed, so a guessed ID
  cannot be confirmed.

> **This is a temporary implementation.** The Go MCP SDK does not implement
> SEP-2663, so Relay serves it itself as a bounded shim
> ([ADR-0028](../adr/0028-mcp-tasks-extension-transport-layer-shim.md)). When
> [go-sdk#626](https://github.com/modelcontextprotocol/go-sdk/issues/626) ships
> Tasks, the shim is deleted. Operationally this matters in one way: a
> deployment can tell whether anyone is actually using the extension by looking
> for `mcp task result issued` in the Relay's logs. Silence means no
> Tasks-capable client has driven a gated dispatch here.

## What approval is not

**Approval is not authorization.** A satisfied requirement lets one
already-legal Plan proceed. It never widens what a Node's Policy allows
([ADR-0002](../adr/0002-node-side-policy-is-locally-rooted-and-remotely-immutable.md)),
and an approved Job still traverses Selector → authz → blast cap → Policy
unchanged. Node Policy remains the floor no human can lower over the wire.

**A Freeze outranks it.** The Relay-wide emergency stop
([ADR-0013](../adr/0013-cancellation-and-emergency-freeze.md)) is the outermost
gate, so a frozen Relay refuses before the approval gate is consulted. Nothing
parks during a Freeze — a Freeze is a stop, not a queue that drains the moment
it lifts.
