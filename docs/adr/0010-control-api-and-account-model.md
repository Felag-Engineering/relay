# Control API: a REST control-plane surface with a unified Account model

The Relay exposes **three user-facing surfaces**, all thin adapters over the single
control-plane capability layer (ADR-0009): the **MCP surface** (ADR-0003 — the AI-agent's
hands), the **Admin Console** (ADR-0009 — the human's eyes and lifecycle keys; execution
added by [ADR-0026](0026-admin-console-execution-surface.md), which superseded this
clause), and the **Control API** — a general REST/JSON API for everything else: IaC
tooling (Ansible), CLIs, and extensions built on Relay. The Control API is the
programmable superset: admin *and* execution. No surface is a parallel control path;
capability parity is a review rule, not a runtime dependency between surfaces.

## Decisions

- **REST/JSON over HTTPS, versioned under `/api/v1`, described by a published OpenAPI
  spec.** The audience is DevOps tooling: Ansible's `uri` module, curl, and extension
  builders with zero codegen barrier. The OpenAPI spec is the control plane's contract
  the way `/proto` is the node plane's — two contracts for two planes, one capability
  layer behind both.
- **Scope: runtime objects and execution — never Relay configuration.** Enrollment
  Tokens, Accounts, revocation, Labels, Jobs, Operations, and Raw Exec are driven via
  the API. The Relay's own configuration (listeners, TLS/CA, OIDC provider, storage,
  blast-radius cap) lives in a root-owned local config file and is *not* reachable over
  the API: configuration is needed before auth can exist (bootstrap paradox), and — 
  rhyming with ADR-0002 — a stolen API credential must not be able to reconfigure the
  Relay or raise its own limits. The blast-radius cap is deliberately file-only.
- **IaC-first standup is a requirement.** A playbook must take a clean host to a live
  fleet end-to-end: write Relay config + start service → mint a scoped, short-TTL
  Enrollment Token via the API → install daemons with it. Relay standup is a
  file-and-service concern owned by IaC tools; the API takes over after boot.
- **Bootstrap chain of trust: Ansible Vault → seeded admin Account.** The config file
  declares the initial `admin` Account with a credential **hash**; the plaintext lives
  only in the operator's secret store (e.g. Ansible Vault). Rotation is re-running the
  playbook; recovery is editing the root-owned file. Every other credential in the
  system is minted from this one via the API and is revocable.
- **Unified Account model across all three surfaces.** An **Account** is a named
  identity (human or machine) with a **role**; all credentials bind to an Account:
  - Humans: local username/password (hashed at rest) as baseline; OIDC optional.
  - Machines: **API Tokens** — child records of an Account (`token_id`, `account_id`,
    name, hash, expiry, revocation, last-used). Secret shown once at mint, stored only
    hashed, recognizable `glp_` prefix for secret scanners. A token inherits its
    Account's role; per-token scopes are deliberately deferred.
  - Roles: `viewer` (read), `operator` (run Operations; Token/Node lifecycle),
    `admin` (Raw Exec; Account management).
- **MCP has no separate auth story.** The AI-agent is simply a machine Account whose
  API Token the MCP endpoint validates. Whether the AI-agent may even *attempt* Raw
  Exec is a role assignment (`admin` vs `operator`) — a central gate that acts before
  any Node's Policy is consulted.
- **Audit attributes the Account** (and which token) on every action, uniformly,
  regardless of entry surface.
- **Staged adoption — one credential first.** Pre-beta there are no Account tables,
  roles, or CRUD: the single seeded admin credential is the bearer token for both the
  MCP endpoint and the first Control API slice (authenticated = admin). The full model
  (Accounts, API Tokens, roles) lands in the Control API milestone; the seeded
  credential simply becomes the first admin Account. Known, accepted gap until then:
  audit cannot distinguish consumers sharing the credential, and Node Policy is the
  only gate on AI-agent Raw Exec.

## Considered Options

- **gRPC control API.** Uniform with the node plane, but hostile to curl/Ansible and
  forces codegen on every consumer. Rejected.
- **Relay configuration via API.** Convenient, but bootstrap-paradoxical and lets a
  stolen credential rewrite the Relay's security posture. Rejected.
- **Unix-socket local admin channel as the root of trust.** Zero secrets in the IaC
  repo; rejected for v1 in favor of the vault-managed seeded credential — one less
  moving part, and vault-encrypted secrets are the customers' native pattern.
- **Per-surface auth (static MCP token + OIDC + API keys as separate systems).**
  Authorization drift across three surfaces of an RCE product is the nightmare
  scenario. Rejected; one Account model behind all surfaces.

## Consequences

- The MCP milestone stays minimal: one vault-managed credential, no auth tables. The Account
  model is the *documented destination*, so the Accounts & Access milestone adds rows and roles instead of
  redesigning auth.
- The Relay stores password hashes (Console local login) and token hashes; it still
  never stores plaintext secrets at rest.
- **A credential binds to the surface that issued it.** One Account model and one
  authentication boundary behind all three surfaces does *not* make every credential
  portable between them: an API Token is a control-plane credential by construction,
  while a Console session cookie authenticates the Console and nothing else — the
  browser attaches it to `/api/v1` and `/mcp` too (the `__Host-` prefix forces
  `Path=/`), so the boundary bounds the lane by path rather than inheriting the
  browser's reach. What is scoped is one credential *form*; the Account, its role, and
  the audit attribution behind it are unchanged, so this is not the per-surface auth
  this ADR rejected above (#459).
- An OpenAPI document must be maintained and published; it doubles as the
  extension-builder documentation.
- Roles are coarse in v1. The pressure valve for finer grain is more Accounts, not
  more mechanism; per-token scoping gets revisited only with real demand.
- The finer-grained future is **Grants** (see GLOSSARY.md): per-Account rules over
  Operations × Selectors, managed as runtime objects via the Control API and Console.
  Grants can only narrow what Node Policy would allow, never widen it — the Node file
  is the root; the Relay layer only subtracts. Sequenced with the multi-principal RBAC
  milestone, not v1.

## Amendment (2026-09-15): configuration splits into a security floor and operator settings

**This one reverses part of a decision rather than restating it.** Invariant 11 read that
Relay configuration is *"operator-set at startup and unreachable from any API"* — all of it,
with no distinction between values. That is narrowed to: **anything that bounds who may
authenticate is unreachable from any API.** Taken by the owner on 2026-09-15 while establishing
`docs/specs/relay-configuration.md`, which specifies the result.

### What changed

Configuration becomes two tiers, split by what an attacker gains from changing the setting.

The **security floor** stays exactly where it was — a root-owned file on the host, with no code
path from any request: listen addresses, CA directory and store path, the OAuth issuer, audience,
claim and scope, the Console session lifetimes and the step-up freshness window,
`console_execution`, the approval webhook URL, secret file and timeout, and every secret file
path. These decide *who can authenticate at all* and *whether the gate exists*.

**Operator settings** become runtime objects in the Relay's store, changed by a human `admin` in
the Admin Console with step-up re-authentication, audited with old and new values, taking effect
on the next request: the read and mutate blast caps, the approval-gate rules, the minimum daemon
version, the `state:cert-expiring` fraction, the enrollment rate limits, the node cap, retention
and page-size limits.

**The blast caps and the approval-gate rules are Console-only.** No MCP tool and no Control API
route writes them, and none may be added: the capability layer holds the decision and the other
adapters narrow to nothing, which is invariant 10's "an adapter may offer less", not a second
control path. Only a human at a browser, re-entering their password, can widen what an AI-agent
may reach — a machine Account cannot hold a Console session at all.

Two smaller decisions came with it. There are **no configuration command-line flags**: one way to
set a value, so there is no precedence rule and nothing sensitive in a process listing. And the
floor is re-read on `SIGHUP`, **all-or-nothing** — an invalid value or a changed bind-time
setting refuses the whole reload, names the setting, and leaves the running configuration
untouched.

### Why the original wording was too broad

"Never Relay configuration" bundled two different things under one noun. The OAuth issuer and the
step-up window decide who may authenticate and how recently they proved it; an `admin` who could
edit those could mint themselves a new way in. The mutate blast cap is a dial an operator turns
as their confidence in the fleet grows, and requiring a file edit and a service restart to turn
it made the product worse without making that class of attack harder — the same `admin` could
already dispatch up to the existing cap, repeatedly.

Administering a Relay should not mean editing a file and restarting a service. What must stay
true is narrower and sharper: **no credential can change the terms on which credentials are
accepted.**

### What is given up, and accepted

The property "the API can never raise its own limits" becomes "the API cannot, and a human in the
Console can". A compromised human Console session with that Account's password can raise the
mutate cap to the whole fleet and delete every approval gate, then dispatch within the limits it
just set. Step-up and the audit trail are the controls; neither prevents it.

A root-set ceiling above the Console value — the file setting a maximum the Console could move
within — was offered and **declined** in favour of one source of truth per setting. The owner
accepted the residual risk explicitly on 2026-09-15; it is **R15** in
`docs/security/threat-model.md` and is recorded in the capability spec.

### Consumers

- **Invariant 11** is rewritten in `AGENTS.md`, keeping its number.
- **ADR-0004 and ADR-0012** are amended: the blast caps are still enforced on the Relay before
  dispatch, and are now operator settings rather than startup configuration.
- **ADR-0027** is amended: gate rules become store-backed and Console-editable; the webhook stays
  root-owned.
- `docs/security/threat-model.md` gains **R15** and restates invariant 11's row.
- `docs/specs/relay-configuration.md` is the behaviour; every other spec citing invariant 11 for
  a floor-tier value is unaffected.
