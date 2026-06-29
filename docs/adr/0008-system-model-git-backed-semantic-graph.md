# System Model: a Relay-maintained, git-backed semantic graph of the fleet

The Relay maintains a **System Model** — a graph that links Nodes and Labels into
higher-order **Services**, **Dependencies**, and **Annotations** — giving the AI-agent a
persistent, shared understanding of the fleet as a connected system rather than a flat set
of Nodes. It lives inside the Relay application (no separate component) and is exposed over
the existing MCP surface (ADR-0003).

## Decisions

- **Shared, persistent, server-side** in the Relay, grounded in the Relay's authoritative
  registry. Nodes and `relay:` labels are facts the System Model imports; the AI-agent
  **cannot edit them** through the model and enriches only the semantic layer.
- **Semantic layer = Services, Dependencies, Annotations.** A **Service** is a *named
  Selector* (this is how related Labels get "linked together"); a **Dependency** is a
  directed edge between Services; an **Annotation** is free text on any entity. A Service
  desugars to the same Selector → Policy → blast-cap path (ADR-0003/0004) — it adds
  understanding, not a second way to execute.
- **AI-updatable with provenance.** The AI-agent has full create/update/delete on the
  semantic layer whenever it sees fit. Every mutation records author (which AI-agent or a
  human), timestamp, and an optional reason.
- **Advisory, never authoritative for execution.** The model informs Selector choice and
  blast-radius/impact reasoning; it never bypasses Policy or the blast-radius cap.
- **Storage: git-backed YAML.** The model is a human-readable YAML file under version
  control; each change is a commit. Audit trail, diffs, blame-style provenance, direct
  human editing, and one-command revert all come from git natively — matching the priority
  that the model be easily auditable and human-correctable.
- **MCP exposure:** reads via MCP **Resources** (the AI-agent pulls the current map into
  context); writes via MCP **Tools** (`define_service`, `set_dependency`, `annotate`,
  `query_model`).

## Considered / deferred

- **DB-backed storage** rejected for now: git gives audit/diff/revert for free for a
  low-write, high-stakes representation. (Revisit if write frequency grows.)
- **Graphic representation** is anticipated as a future *view* layered over the YAML — YAML
  stays the source of truth even once a visual exists.
- **Locking/pinning** declared entries so the AI cannot change them is a potential future
  feature; for now full AI write access is bounded by provenance, audit, and easy revert.

## Consequences

- The Relay needs a git working tree (or embedded git) for the model file.
- Because grounding facts are registry-owned, the AI-agent cannot invent Nodes or forge
  `relay:` labels through the model — the enrichment layer can't lie about base facts.
