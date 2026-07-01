# Admin Console: a human web UI as a thin adapter over the operator capability layer

The Relay gains a human-facing **Admin Console** — a web UI for operators to monitor the
fleet and drive the control plane (enrollment, revocation, Operations, Raw Exec). It is a
**thin adapter** over the same Relay control-plane capability layer that the MCP surface
(ADR-0003) and a CLI use — not a second control path. Every action it takes flows through
the one Selector → Policy → blast-cap → audit chain; the Console renders and requests, it
does not re-implement control logic.

Scope (v1): full control — monitoring (registry, labels, liveness, facts, Enrollment
Tokens, cert lifecycle, Jobs/Tasks, audit) **and** control (mint/revoke tokens, revoke
Nodes, `run_operation`, `raw_exec`). It is sequenced as its own milestone after v0.0.4,
once the capability layer and audit trail exist; it is deliberately out of scope for the
v0.1.0-beta vertical slice.

## Decisions

- **Thin adapter over a shared capability layer.** The Console calls the same internal
  control API as MCP and a CLI. Node dispatch, blast-radius enforcement, effective-Policy
  read, and audit live in that layer once. This is the load-bearing decision: it prevents
  authz/audit/blast-cap drift on the most dangerous surface in the system. v0.0.4's MCP
  work must therefore be built as a **reusable capability layer**, not MCP-specific
  plumbing.
- **Human auth is a distinct subsystem: SSO/OIDC + RBAC.** Humans authenticate via an
  external identity provider (OIDC); the Relay stores no passwords. Authorization is
  role-based — at least `viewer` (read-only), `operator` (structured Operations,
  token/Node lifecycle), and `admin` (Raw Exec, user management). This is separate from
  Node identity (mTLS client certs) and from the AI-agent's MCP admin principal.
- **Raw Exec is break-glass.** `raw_exec` from the Console requires the `admin` role AND
  per-action step-up re-authentication (MFA), mirroring ADR-0003's choice to make the
  dangerous path conspicuous and separately authorizable.
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

## Consequences

- The Console's security posture is as critical as the daemon's Policy engine: session
  hijack / XSS / CSRF here is fleet-wide RCE. It gets the same review bar and a dedicated
  threat model before any control action ships.
- Human-action audit must attribute the human principal end-to-end (login → action →
  per-Node Task), extending v0.0.4's audit schema.
- v0.0.4 is influenced now: build the operator capability layer MCP-independent so the
  Console and a CLI are cheap adapters later.
- A phased build is natural even within "full control": monitoring and token/Node
  lifecycle first, `run_operation` next, `raw_exec` (break-glass) last — each separately
  reviewable — without changing this decision.
