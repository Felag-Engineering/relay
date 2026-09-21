# Admin Console: a human web UI as a thin adapter over the operator capability layer

**Status:** Superseded in part by ADR-0026.

The Relay gains a human-facing **Admin Console** — a web UI for operators to observe the
fleet and administer the control plane (enrollment lifecycle, revocation, registry and
audit views). It is a **thin adapter** over the same Relay control-plane capability layer
that the MCP surface (ADR-0003) and the general API use — not a second control path.
Every action it takes flows through the capability layer and its audit chain; the Console
renders and requests, it does not re-implement control logic.

> **Superseded in part (2026-08-14).** The no-execution clause below — the scope sentence
> and the "No execution surface" decision — is superseded by
> [ADR-0026](0026-admin-console-execution-surface.md): the Console gains an execution
> surface in v0.7.0, plan-by-default, step-up on mutate apply, behind a root-owned
> `console_execution` flag. **Everything else in this ADR stands**: thin adapter over the
> one capability layer, internal-only exposure, the Account model, and Policy read-only.
> Read ADR-0026 for what replaced it and what was given up.

Scope (v1): **admin + observability only — the Console has no execution surface.**
Monitoring (registry, labels, liveness, facts, Enrollment Tokens, cert lifecycle,
Jobs/Tasks, audit) and lifecycle control (mint/revoke tokens, revoke Nodes). It cannot
dispatch Operations or Raw Exec; execution is reserved for the MCP surface (the
AI-agent's hands) and the general API. It is sequenced as its own milestones after the orchestration work,
once the capability layer and audit trail exist; it is deliberately out of scope for the
v0.1.0-beta vertical slice.

## Decisions

- **Thin adapter over a shared capability layer.** The Console calls the same internal
  control API as MCP and a CLI. Node dispatch, blast-radius enforcement, effective-Policy
  read, and audit live in that layer once. This is the load-bearing decision: it prevents
  authz/audit/blast-cap drift on the most dangerous surface in the system. the MCP milestone's
  work must therefore be built as a **reusable capability layer**, not MCP-specific
  plumbing.
- **Human auth uses the unified Account model (ADR-0010).** Humans log in with a local
  username/password (hashed at rest) as the baseline — no external IdP required — with
  OIDC as an optional additional method. Authorization is role-based via the shared
  `viewer`/`operator`/`admin` roles defined in ADR-0010. This is separate from Node
  identity (mTLS client certs). *(Revised 2026-07-02: originally OIDC-only with no
  stored passwords; local auth was added so small fleets without an IdP can use the
  Console, accepting that the Relay holds password hashes.)*
- **No execution surface.** *(Superseded by [ADR-0026](0026-admin-console-execution-surface.md),
  2026-08-14 — retained here because ADR-0026's reasoning only makes sense against it.)*
  The Console cannot dispatch Operations or Raw Exec — not as
  an RBAC restriction but as an absent capability. A browser is the most attackable
  client in the system; keeping execution out of it eliminates (rather than mitigates)
  the "session hijack / XSS / CSRF → fleet-wide RCE" consequence class. Humans who need
  to execute use the general API (or a CLI over it); the AI-agent uses MCP. Adding
  execution to the Console later is possible but requires amending this ADR and a
  dedicated threat model for browser-initiated execution.
  *(That amendment is ADR-0026, and the dedicated threat model this clause demanded is
  the threat-model delta it carries. `console_execution = off` preserves this property
  verbatim for deployments that want it.)*
- **Internal-only exposure.** The Console is not internet-facing by default; it is served
  on an internal/VPN/bastion-reachable interface. Enrolling Nodes never reach it.
- **Reads are authoritative-registry-grounded; Policy stays read-only.** Monitoring reads
  the Relay's live registry and audit store and shows *effective* Policy (ADR-0002); the
  Console never offers a way to mutate Node Policy over the wire.

## Considered Options

- **Server-rendered Go + HTMX (chosen).** Served by the Relay or a sibling Go binary, with
  live updates via SSE. Minimal JavaScript and third-party supply-chain surface, easy to
  audit, aligned with the single-Go-server design (ADR-0007). Chosen because for an
  internal, RCE-capable console, attack-surface minimality and auditability outweigh
  rich-client ergonomics.
- **SPA (React/Svelte) + JSON/gRPC-web API.** Richer client interactivity, but a large JS
  dependency/attack surface, a separate build/deploy, and a second API contract to secure.
  Rejected for v1; revisit only if dashboard interactivity demands it.
- **UI as a parallel control path.** Faster to prototype, but duplicates the
  Selector→Policy→blast-cap→audit chain and guarantees security drift. Rejected.
- **Reuse the MCP static admin token for humans.** Simple, but yields no per-human
  identity, no RBAC, and no per-human audit — unacceptable for a fleet RCE surface.
  Rejected in favor of SSO/RBAC.
- **Full-control Console (`run_operation` + break-glass `raw_exec`).** The original v1
  scope of this ADR: execution from the Console gated by an `operator`/`admin` RBAC split
  and per-action step-up MFA for Raw Exec. Revised out (2026-07-02): mitigations reduce
  but do not remove the browser-borne fleet-RCE consequence class, and execution is not
  needed in the Console — the general API and MCP cover human and AI execution
  respectively. Convenience lost, consequence class removed.

## Consequences

- The worst browser-borne compromise is now admin abuse (minting an Enrollment Token to
  enroll a rogue Node; revoking Nodes as denial of service) rather than command execution
  on existing Nodes. Still serious — the Console keeps a high review bar and a threat
  model before any lifecycle-control action ships — but the consequence ceiling is
  structurally lower. *(No longer true once ADR-0026 lands with `console_execution = on`:
  the ceiling returns to command execution, mitigated rather than eliminated. It remains
  true for any deployment running `console_execution = off`.)*
- Once the Console manages Accounts and roles, a hijacked admin session can *indirectly*
  reach execution by elevating a machine Account it controls. Mitigation: all
  privilege-granting actions (create Account, change role, mint API Token) require
  **step-up re-authentication** (sudo-mode: re-enter password / OIDC re-prompt), and
  every such change is audited and, as always, bounded by Node Policy.
- Human-action audit must attribute the human principal end-to-end (login → action →
  audit record), extending the Job-engine milestone's audit schema.
- The Job-engine milestone is influenced now: build the operator capability layer MCP-independent so the
  Console and the general API are cheap adapters later.
- A phased build remains natural: monitoring (read-only) first, token/Node lifecycle
  second — each separately reviewable.

## Amendment (2026-09-20): terminology, and the HTMX choice

Terminology only, per ADR-0038: the supersession note above now says *preflight-by-default*;
"Plan" in this ADR's body, where it means the no-execution preview, reads as **Policy preflight**.

*Considered Options* records "Server-rendered Go + HTMX (chosen)". The Console shipped
server-rendered Go templates with SSE for liveness and **no HTMX** — the shell decisions (#475)
record why. The choice of server rendering over an SPA stands; the HTMX half of it was not
taken up and is not planned.
