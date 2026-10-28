# Approval gates

Which dispatches must wait for a human before they run
([ADR-0027](../adr/0027-approval-callout-notify-via-mcp-decide-out-of-band.md)).

> **Changing for the MVP ([ADR-0047](../adr/0047-approval-is-one-in-band-answer.md)).** This
> runbook describes the code as it stands. ADR-0047 cuts approval to one answer per request: a
> rule names only what it matches and how long a parked request lives (no `count`, `audience`,
> `requester_allowed` or `channel`); `approve_request` is retired and approval grants are removed; gate rules
> become a section of `relay.toml` rather than a separate file named by
> `approval.gate_rules_path`; and the inline `webhook_url` and `webhook_secret` keys go, leaving
> only their `_file` forms. Gate rules stay in the configuration file: the Console has no
> approval or settings screen (roadmap: relay/settings-in-the-console). This page is rewritten
> when that code lands.

## Where the configuration lives

A root-owned local file of gate rules, named by `approval.gate_rules_path` in `relay.toml`.
Like the blast caps, it is Relay configuration: **no Account of any role can read or write it
through the Control API** (invariant 11). A stolen credential that could edit its own
approval requirements would make the mechanism decorative.

```toml
[approval]
gate_rules_path = "/etc/relay/approval-gates.json"
```

**No path configured means no approval gating.** That is the only way to get a gate-less
Relay, and it is safe because a gate can only *add* a reason to stop. Every other problem
refuses startup:

| Situation | Result |
|---|---|
| No path configured | No gates. |
| Path configured, file missing | **Startup fails** |
| Malformed JSON, unknown field, invalid value | **Startup fails** |
| File is a symlink, a directory, or group/world-writable | **Startup fails** |

An unreadable file never degrades into an empty rule set: a Relay that silently decided
nothing needs approval is the failure this mechanism exists to prevent.

Install it `0644 root:root` or stricter. A SIGHUP reloads `relay.toml` and the rules file
together, all-or-nothing: a reload that cannot load the rules is refused and the running rules
stay in force.

## Format

JSON, parsed by the Go standard library. TOML or YAML would mean adding a parser dependency to
a security-critical control plane to parse a security-critical file; in practice config
management renders this file.

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

Every field is optional; an omitted field matches anything. A `match` with no fields matches
every dispatch, a legitimate way to say "everything needs approval".

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

The bold defaults are the strict reading: an omitted `requester_allowed` requires a second
person, and an unstated `channel` must never silently mean "trust the harness".

## How overlapping rules combine

When several rules match one dispatch, their requirements merge to the **strictest**: the
highest `count`, the stronger `channel`, the shorter `ttl`, and `requester_allowed: false` if
any matching rule says so.

This is deliberately *not* first-match-wins, which would make rule order security-relevant and
let a broad permissive rule shadow a narrow strict one. Here **adding a rule can only tighten
the outcome**, and rule order does not matter.

The Relay refuses at startup to load a rule that can never be satisfied, for example
`count: 2` with a single-member `audience`.

## What happens when a dispatch is gated

1. The dispatch resolves its Selector, passes authz and the blast cap, and then **parks**. No
   Job and no Tasks are created, so a restart finds nothing to mistake for interrupted work.
2. The Relay records an `approval_requested` audit entry and returns a park carrying the
   request ID, the plan hash, and which rules fired. On `/api/v1` that is a
   **`202 Accepted`** with `"status": "pending_approval"`: not a `200` (nothing ran) and not an
   error (nothing was denied). Re-driving the same dispatch while it waits, which is how a
   caller polls, returns the same park and audits as `approval_pending_observed`, so the
   request count stays truthful and the polling stays on the record.
3. A human decides. An **out-of-band** decision arrives through the decision endpoint, on a
   channel other than the requesting MCP session. An **in-band** decision (`approve_request`,
   or an answer to an elicited approval question, ADR-0029) travels through the tool surface
   with an *asserted* approver, and satisfies only an `in-band` rule, never an `out-of-band`
   one.
4. Once the requirement is satisfied, the same dispatch proceeds and the approval is bound to
   the Job it released, so "who approved what actually ran" is one join.

## The decision endpoint

Three routes on `/api/v1`, published in [the OpenAPI spec](../api/openapi.yaml). The Admin
Console has no approval surface; this endpoint is the out-of-band path.

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

Every authenticated Account can read the queue, `viewer` included. A rule's `audience`
restricts who may **decide**, not who may see that a decision is owed: every entry is a
Relay-authored summary of an action already readable in the audit trail.

### Who may decide

**The floor for deciding is the floor for requesting.** Approving an Operation needs
`operator`; approving a Raw Exec needs `admin`, read from the same `authz.RoleGate`. An
operator who cannot *ask* for Raw Exec cannot *release* someone else's.

On top of the role floor, the domain refuses a decision when:

| Situation | Result |
|---|---|
| Request already decided, or past its deadline | `409` |
| Requester decides their own, under `requester_allowed: false` | `409` |
| A **machine** Account decides its own, under **any** configuration | `409` |
| The same Account fills a second quorum slot | `409` |
| `plan_hash` no longer matches | `409` |
| Decider outside the rule's `audience` | `403` |

The machine rule is structural, not your `requester_allowed` setting. ADR-0027's confirmation
ladder makes self-confirmation (rung 2) **human-only**, because an AI-agent confirming its own
proposal is the same actor answering twice. A misconfigured `requester_allowed: true` can
never hand an AI-agent its own approval.

A machine Account *may* decide **someone else's** request if its role clears the floor (an
approval bridge holding its own credential, say). The verified approver in audit is then the
bridge, not whoever the bridge asked. If you do not want that attribution, keep machine
Accounts out of the `audience`.

### The channel is set by the door, not the caller

The decision body has **no `channel` field**; sending one is a `400`. Every decision on this
endpoint is recorded `out-of-band` because of what the endpoint is. A channel a request body
could name is a channel it could upgrade.

Strength is a floor: an out-of-band answer satisfies an `in-band` rule, an in-band answer never
satisfies an `out-of-band` rule, and an unstamped channel satisfies nothing.

### Deciding does not dispatch

A satisfied requirement lets the **same dispatch** proceed the next time it is driven. The caller
re-issues the request; the Relay finds the approval by plan hash and lets it through. Nothing
runs at the moment of approval, so fleet drift between the answer and the run re-parks rather
than widening what was approved.

## Notifying an approver

Optional, and never load-bearing. With a webhook configured, the Relay POSTs a Relay-authored
notice once, when a dispatch parks:

```toml
[approval]
webhook_url = "https://notify.internal/relay-approvals"
webhook_secret_file = "/etc/relay/approval-webhook.key"
```

| Key | Meaning |
|---|---|
| `webhook_url` / `webhook_url_file` | Where to POST: a secret, given inline or as a file holding it. HTTPS required off-loopback. Unset disables notification. |
| `webhook_secret` / `webhook_secret_file` | The HMAC-SHA256 signing secret, inline or as a root-owned `0600` file. Unset sends unsigned. |
| `webhook_timeout` | Budget for one delivery attempt (default `5s`). |

Give each secret one way, never both. Signed deliveries carry `Relay-Timestamp` and
`Relay-Signature: sha256=<hex>` over `"<timestamp>.<body>"`, so a receiver can check
authenticity *and* freshness. The signature authenticates **the Relay to the receiver**; it
authorizes nothing, and there is no callback for it to protect. Decisions only arrive on
`/api/v1`.

Delivery is **one attempt, no retry, no queue**, and it never blocks or fails a park. A park
is durable, audited and queued before the notification is attempted, so an endpoint that is
down costs an approver a poll. Configuration fails closed: a webhook you asked for and did not
get would leave you believing you will be paged, so an invalid URL or an unreadable or
world-readable secret file **refuses startup**.

**What leaves the Relay.** The body carries the plan summary, including the Operation's
*arguments*, since they are what the approver decides about. It carries no credential, no
token, and no captured output. Treat the endpoint as a disclosure boundary at the audit
trail's trust level: a secret passed as an Operation argument reaches this body just as it
reaches the audit trail.

### Approvals bind to a plan hash, not to a Job

An approval commits to the Operation, its arguments, **and the resolved fan-out**. If the
fleet drifts between approval and dispatch (a Node joins the Selector's match set), the hash
differs, the approval no longer applies, and the dispatch re-parks. There is no "close enough"
comparison anywhere in the path.

### Everything expires

Parked requests and granted approvals stop being redeemable at their deadline. The clock
enforces expiry at read time, so it holds even if the background sweeper is not running; the
sweeper retires lapsed requests from the queue and records an `approval_expired` audit entry.

An approved request releases exactly one execution (AP-77). Re-driving the same
call once it has been released (including while it is still running), on any surface and by
any caller, returns the Job it already released and runs nothing, up to the approval's
deadline. After the deadline the same call parks for a fresh approval.

## How an AI-agent waits: three envelopes, one decision

This section is about **how a caller learns it must wait and finds out the answer arrived**.
None of these envelopes decides anything; that happens only on the decision endpoint (or
in-band, as above).

| Envelope | Who gets it | How it waits |
|---|---|---|
| `202 pending_approval` on `/api/v1` | every Control API caller | re-drive the same call |
| `pending_approval` tool result over MCP | every MCP client | re-drive the same call |
| **MCP task handle** (SEP-2663) | MCP clients that advertised the Tasks extension | poll `tasks/get` |

The first two are the **universal path**: a harness with no approval features still drives a
gated dispatch to completion by calling the same thing again once a human has answered.
Nothing may come to depend on anything richer
([ADR-0027](../adr/0027-approval-callout-notify-via-mcp-decide-out-of-band.md) decision 2).

### The MCP task handle

For a client that advertises `io.modelcontextprotocol/tasks`, a parked `tools/call` returns a
**task result** carrying a handle, and the client polls `tasks/get` instead of re-driving.
`tasks/cancel` ends its interest.

What this buys:

- **A poll is no longer a dispatch attempt.** Re-driving runs the whole Selector → authz →
  blast-cap → gate path just to hear "still waiting"; `tasks/get` reads state.
- **Server-controlled cadence.** The response carries `pollIntervalMs` (5 s, since the wait is
  a human one) and `ttlMs`.

What it does **not** change:

- **Who may decide.** A handle is a poll token. The only MCP path that records a decision is
  the in-band one (`approve_request`, ADR-0029), through the same capability-layer seam as
  every other decision.
- **What `tasks/cancel` reaches.** It marks the *handle* cancelled. A still-parked approval
  request stays pending, queued and decidable, and a re-drive of the same dispatch re-attaches to
  it. A cancel arrives over the AI's own session; if it could withdraw a pending request, an
  AI-agent could pull one back the moment it sensed a denial coming. If a Job already exists,
  cancelling goes through the ordinary Job-cancel path.
- **Who can see a handle.** Resolving one is owner-only. A handle that is not yours is
  indistinguishable from one that never existed.

> **This is a temporary implementation.** The Go MCP SDK does not implement SEP-2663, so Relay
> serves it as a bounded shim
> ([ADR-0028](../adr/0028-mcp-tasks-extension-transport-layer-shim.md)), deleted when
> [go-sdk#626](https://github.com/modelcontextprotocol/go-sdk/issues/626) ships Tasks. To tell
> whether anyone uses the extension, look for `mcp task result issued` in the Relay's logs.
> Silence means no Tasks-capable client has driven a gated dispatch here.

## What approval is not

**Approval is not authorization.** A satisfied requirement lets one already-legal dispatch
proceed. It never widens what a Node's Policy allows
([ADR-0002](../adr/0002-node-side-policy-is-locally-rooted-and-remotely-immutable.md)), and an
approved Job still traverses Selector → authz → blast cap → Policy unchanged.

**A Freeze outranks it.** The Relay-wide emergency stop
([ADR-0013](../adr/0013-cancellation-and-emergency-freeze.md)) is the outermost gate, so a
frozen Relay refuses before the approval gate is consulted. Nothing parks during a Freeze: it
is a stop, not a queue that drains when it lifts.
