# Polyglot: Rust relay-daemon, Go Relay, shared protobuf contract in a monorepo

The relay-daemon is written in **Rust**; the Relay is written in **Go**. Both live in one
monorepo beside a shared **`/proto`** directory that is the single source of truth for the
wire protocol and the Operation vocabulary. Each side generates its own types from the proto
(tonic/prost for Rust, the standard plugin for Go).

## Why this split (and why it stays clean)

- The daemon is the **privileged, security-critical** component — it executes commands,
  possibly as root, and enforces Policy. Rust's memory safety is most valuable exactly here.
- The daemon also **changes least** (connection handling, Policy engine, Operation
  executors stabilize early), so Rust's slower iteration lands on the slow-changing half,
  while Go's fast iteration serves the constantly-evolving Relay orchestration/Job/MCP logic.
- The daemon must be **as lightweight as possible** to run across the fleet, including
  resource-constrained Nodes: a Rust musl binary is ~single-digit MB RSS with no runtime.
- Polyglot's usual cost — shared logic drifting — is mild here because of ADR-0002's
  asymmetric authority: Policy is *enforced* only in the daemon and merely *displayed* by the
  Relay; Operations are *executed* only in the daemon and merely *routed/validated* by the
  Relay. Almost nothing shared is logic; everything shared is contract, and the contract
  lives in `/proto`.

## Consequences

- The agentic development loop must support two toolchains, two test conventions, and two CI
  lanes; `CLAUDE.md` documents both. This is the accepted tax.
- The monorepo (not two repos) keeps the `/proto` contract atomic across both components.
- Layout: `/proto`, `/relay` (Go), `/daemon` (Rust), with one shared `CONTEXT.md`.
