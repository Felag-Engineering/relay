# AI-agent integrates via an MCP server with a meta-tool surface and selector fan-out

The Relay exposes its capabilities to the AI-agent through a **Model Context Protocol
(MCP)** server. The surface is a small, stable set of **meta-tools** plus vocabulary
introspection, rather than one MCP tool per Operation:

- `list_nodes(selector?)` — fleet inventory and labels
- `describe_node(node)` — Node facts plus its effective Policy
- `list_operations()` — the Operation vocabulary, each with a JSON argument schema
- `run_operation(selector, op, args)` — the structured execution path
- `raw_exec(selector, command)` — the regex-gated escape hatch, deliberately a separate tool

Targeting is by **Selector** (label match, e.g. `role=web, env=prod`); a call fans out to
all matching Nodes and returns a per-Node result array. Single-Node addressing is just a
Selector that matches one.

## Considered Options

- **One MCP tool per Operation** (`service_restart(selector, name)`, …). More legible
  per-Operation arg schemas, but a large and growing tool list that bloats model context,
  and node-targeting must be duplicated on every tool. Rejected for v1.
- **Meta-tools + introspection (chosen).** Small, stable tool list; the Operation
  vocabulary evolves behind `list_operations()` without changing the tool surface.

## Consequences

- `describe_node` exposing effective Policy is what lets the AI-agent plan within ADR
  0002's constraint: it cannot change Policy, so it must read it to route around what is
  forbidden.
- `raw_exec` being a distinct tool makes the dangerous path conspicuous, separately
  authorizable, and separately auditable.
- Selector fan-out makes batch execution semantics (partial failure, concurrency limits,
  per-Node results) a first-class concern.
