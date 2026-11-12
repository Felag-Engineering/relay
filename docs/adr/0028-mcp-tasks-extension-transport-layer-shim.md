# Relay implements the MCP Tasks extension as a transport-layer shim

**Status:** Superseded by ADR-0047 (2026-10-22).

The shim is removed. MCP Tasks for long-running Jobs waits in the roadmap
(`roadmap: relay/mcp-tasks-for-long-running-jobs`).

## What it decided

Relay would implement the MCP Tasks extension (SEP-2663) itself, as a bounded shim around the
MCP Go SDK and never a fork of it, so that a parked dispatch could return a task handle the
client polls. The alternatives it rejected were waiting for the SDK to implement Tasks and
forking the SDK.

## Where to read now

ADR-0047 decision 8: there is no MCP task handle; elicitation answers a parked request, and a
client that cannot be asked gets `pending_approval`. The full text of this ADR is in git:
`git show 3694f23:docs/adr/0028-mcp-tasks-extension-transport-layer-shim.md`.
