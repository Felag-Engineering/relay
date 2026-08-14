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
   the caller carrying the request ID, the plan hash, and which rules fired.
3. A human decides through the decision endpoint. The decision arrives on an
   authenticated channel — **never through the MCP session that requested the
   action**.
4. Once the requirement is satisfied, the same dispatch proceeds and the
   approval is bound to the Job it released, so audit can answer "who approved
   what actually ran" in one join.

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
