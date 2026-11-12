# System Model: a Relay-maintained, git-backed semantic graph of the fleet

**Status:** Superseded by ADR-0051 (2026-10-23).

Withdrawn unbuilt: observed topology and declared meaning are Relay's later work, an AI-agent's
beliefs are agent memory, and invariant 9 constrains any fleet model Relay keeps.

## What it decided

The Relay would keep a shared System Model of the fleet: Services (named Selectors),
Dependencies between them and free-text Annotations, stored as git-backed YAML and exposed over
MCP. Any AI-agent could rewrite that semantic layer; Nodes and `relay:` labels stayed
read-only facts, and the model was advisory and never bypassed Selectors, Policy or the blast
cap.

## Where to read now

ADR-0051 for the decision in force. The full text of this ADR is in git:
`git show 3694f23:docs/adr/0008-system-model-git-backed-semantic-graph.md`.
