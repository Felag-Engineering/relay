# Approval gates

Which dispatches must wait for a human before they run
([ADR-0027](../adr/0027-approval-callout-notify-via-mcp-decide-out-of-band.md),
[ADR-0047](../adr/0047-approval-is-one-in-band-answer.md)).

A gate rule names what it matches and how long a parked request lives, and nothing else. One
Decision ends a request. Gate rules are `[[approval.rules]]` sections of `relay.toml`.

## Where the configuration lives

In `relay.toml`, the Relay's one configuration file, as `[[approval.rules]]` sections. Like the
blast caps, it is Relay configuration: **no Account of any role can read or write it through the
Control API** (invariant 11). A stolen credential that could edit its own approval requirements
would make the mechanism decorative.

```toml
[[approval.rules]]
name = "prod-mutates-need-a-human"
risk_class = "mutate"
min_fan_out = 10
selector_namespace = "relay"
ttl = "2h"

[[approval.rules]]
name = "raw-exec-always-asks"
raw_exec = true
ttl = "30m"
```

The rules are checked, read and reloaded with the rest of the file, under the same file check:
the file must be one the Relay cannot write and no other account can read. **A configuration
with no `[[approval.rules]]` gates nothing.** That is safe because a gate can only *add* a
reason to stop. A rule that cannot be loaded refuses startup:

| Situation | Result |
|---|---|
| No `[[approval.rules]]` section | No gates. |
| A rule names a field a rule does not have | **Startup fails**, naming "an unrecognised key in [approval.rules]" and a line; a field a rule used to have (`count`, `audience`, `requester_allowed`, `channel`) is named as `approval.rules.<field>` |
| A rule's value is invalid | **Startup fails**, naming `approval.rules.<field>` and a line |
| `rules`, a rule field or `approval` is spelled in another case (`Rules`, `Risk_Class`) | **Startup fails**, naming the setting as the schema spells it |
| Two rules share a name (case-insensitively), or a rule has no name | **Startup fails** |
| Rules written as an inline array or a single `[approval.rules]` table | **Startup fails**, naming `approval.rules` |
| `approval.gate_rules_path` is present | **Startup fails**, naming the key |

A refusal names a setting and a line, never a value or a rule's name. An invalid rule never
degrades into an empty rule set: a Relay that silently decided nothing needs approval is the
failure this mechanism exists to prevent.

A SIGHUP reloads `relay.toml`, rules included, all-or-nothing: a reload that cannot load the
rules is refused and the running rules stay in force. A change to the rules is recorded in the
reload's audit entry as `approval.rules`.

### Moving from the rules file

An earlier release read the rules from a JSON file named by `approval.gate_rules_path`. That key
is refused now, so a deployment that still names it **does not start** until the rules move into
`relay.toml`. Each JSON rule becomes one `[[approval.rules]]` section, with `match` and
`require.ttl` flattened to fields of the rule:

```toml
# was: {"name": "raw-exec-always-asks", "match": {"raw_exec": true},
#       "require": {"count": 1, "channel": "out-of-band", "ttl": "30m"}}
[[approval.rules]]
name = "raw-exec-always-asks"
raw_exec = true
ttl = "30m"
```

Drop `count`, `audience`, `requester_allowed` and `channel`; a rule that still names one is
refused. Then remove `approval.gate_rules_path` and the file it named.

**Drain the pending queue before you upgrade.** A request parked before the upgrade under a
rule that needed more than one Decision, named an audience, excluded the requester or required
an out-of-band channel ends on **one** Decision after it, from anyone with the role to decide,
the requester included, until its TTL runs out. Answer or deny what is waiting, or let it
expire, before the new release starts.

## Format

TOML, as the rest of `relay.toml`. Rules are written **only** as `[[approval.rules]]` array
tables, one per rule. An inline array (`rules = [...]`), a value written at `approval.rules`, a
dotted `rules.<field>` outside a rule section and the single-bracket `[approval.rules]` table are
each refused.

### What a rule matches

Every match field is optional; an omitted field matches anything. A rule with no
match field matches every dispatch, a legitimate way to say "everything needs approval".

| Field | Meaning |
|---|---|
| `name` | Required, unique case-insensitively. Names which rule parked a request, in the park and the audit entry. |
| `risk_class` | `read` or `mutate` |
| `min_fan_out` | Matches dispatches touching **at least** this many Nodes |
| `selector_namespace` | `node`, `relay`, `tag` or `state` — the namespace the Selector used |
| `account` | The requesting Account's name |
| `operation` | An Operation name, e.g. `service.restart` |
| `raw_exec` | `true` restricts the rule to the Raw Exec path |
| `ttl` | How long the parked dispatch waits, a positive duration such as `"2h"`. Default `4h`. |

A rule names no audience, no quorum, no requester exclusion and no channel. A rule that names
`count`, `audience`, `requester_allowed` or `channel` is refused when the configuration loads,
naming the field.

## How overlapping rules combine

When several rules match one dispatch, the **shortest `ttl` wins**, and the park names every rule
that matched. A rule that sets no `ttl` counts as the `4h` default.

This is deliberately *not* first-match-wins, which would make rule order security-relevant and
let a broad rule shadow a narrow one. Rule order does not matter.

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
   channel other than the requesting MCP session. An **in-band** decision (an answer to an
   elicited approval question, ADR-0029) travels over the requesting session. Either channel is
   recorded with the Decision and neither is demanded: a rule never requires one.
4. The first Decision ends the request: an approving Decision releases it, and a denying one
   ends it. The same dispatch then proceeds, and the approval is bound to the Job it released,
   so "who approved what actually ran" is one join.

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

Every authenticated Account can read the queue, `viewer` included. The role floor restricts who
may **decide**, not who may see that a decision is owed: every entry is a Relay-authored summary
of an action already readable in the audit trail. An approval's JSON carries the request, its
Decisions (each with the channel it arrived on) and its deadline; it carries no progress, count,
audience, requester or channel requirement, because a rule has none.

### Who may decide

**The floor for deciding is the floor for requesting.** Approving an Operation needs
`operator`; approving a Raw Exec needs `admin`, read from the same `authz.RoleGate`. An
operator who cannot *ask* for Raw Exec cannot *release* someone else's. Any Account whose role
clears the floor may decide, in-band or on the Control API.

On top of the role floor, the domain refuses a decision when:

| Situation | Result |
|---|---|
| Request already decided (by anyone, the first Decision ended it), or past its deadline | `409` |
| A **machine** Account decides its own request, other than by the in-band forms | `409` |
| `plan_hash` no longer matches | `409` |

A **human** may confirm their own request: the confirmation ladder has two rungs, no gate and
self-confirmation. The machine rule is structural, not a setting. Self-confirmation is
**human-only**, because an AI-agent confirming its own proposal is the same actor answering
twice. The exceptions are the two in-band forms ADR-0029 and AP-87 name: a machine relaying an
answer it names a human for, and a machine answering on its own API Token session.

A machine Account *may* decide **someone else's** request if its role clears the floor (an
approval bridge holding its own credential, say). The verified approver in audit is then the
bridge, not whoever the bridge asked.

### The channel is set by the door, not the caller

The decision body has **no `channel` field**; sending one is a `400`. Every decision on this
endpoint is recorded `out-of-band` because of what the endpoint is. A channel a request body
could name is a channel it could upgrade. The channel is a record for the audit trail; no rule
demands one.

### Deciding does not dispatch

An approval lets the **same dispatch** proceed the next time it is driven. The caller
re-issues the request; the Relay finds the approval by plan hash and lets it through. Nothing
runs at the moment of approval, so fleet drift between the answer and the run re-parks rather
than widening what was approved.

## Notifying an approver

Optional, and never load-bearing. With a webhook configured, the Relay POSTs a Relay-authored
notice once, when a dispatch parks:

```toml
[approval]
webhook_url_file = "/etc/relay/approval-webhook.url"
webhook_secret_file = "/etc/relay/approval-webhook.key"
```

| Key | Meaning |
|---|---|
| `webhook_url_file` | A file holding where to POST: a secret, so only ever given as a file. HTTPS required off-loopback. Unset disables notification. |
| `webhook_secret_file` | A root-owned `0600` file holding the HMAC-SHA256 signing secret. Unset sends unsigned. |

Each is a file. The budget for one delivery attempt is built in at `5s`. Signed deliveries carry `Relay-Timestamp` and
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

## How an AI-agent waits: two envelopes, one decision

This section is about **how a caller learns it must wait and finds out the answer arrived**.
Neither envelope decides anything; that happens only on the decision endpoint (or
in-band, as above).

| Envelope | Who gets it | How it waits |
|---|---|---|
| `202 pending_approval` on `/api/v1` | every Control API caller | re-drive the same call |
| `pending_approval` tool result over MCP | every MCP client | re-drive the same call |

Both are the **universal path**: a harness with no approval features still drives a
gated dispatch to completion by calling the same thing again once a human has answered.
Nothing may come to depend on anything richer
([ADR-0027](../adr/0027-approval-callout-notify-via-mcp-decide-out-of-band.md) decision 2).

## What approval is not

**Approval is not authorization.** An approval lets one already-legal dispatch
proceed. It never widens what a Node's Policy allows
([ADR-0002](../adr/0002-node-side-policy-is-locally-rooted-and-remotely-immutable.md)), and an
approved Job still traverses Selector → authz → blast cap → Policy unchanged.

**A Freeze outranks it.** The Relay-wide emergency stop
([ADR-0013](../adr/0013-cancellation-and-emergency-freeze.md)) is the outermost gate, so a
frozen Relay refuses before the approval gate is consulted. Nothing parks during a Freeze: it
is a stop, not a queue that drains when it lifts.
