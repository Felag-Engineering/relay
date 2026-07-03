# Control API: a REST control-plane surface with a unified Account model

The Relay exposes **three user-facing surfaces**, all thin adapters over the single
control-plane capability layer (ADR-0009): the **MCP surface** (ADR-0003 — the AI-agent's
hands), the **Admin Console** (ADR-0009 — the human's eyes and lifecycle keys, no
execution), and the **Control API** — a general REST/JSON API for everything else: IaC
tooling (Ansible), CLIs, and extensions built on Gleipnir. The Control API is the
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

- v0.0.4 stays minimal: one vault-managed credential, no auth tables. The Account
  model is the *documented destination*, so v0.3.0 adds rows and roles instead of
  redesigning auth.
- The Relay stores password hashes (Console local login) and token hashes; it still
  never stores plaintext secrets at rest.
- An OpenAPI document must be maintained and published; it doubles as the
  extension-builder documentation.
- Roles are coarse in v1. The pressure valve for finer grain is more Accounts, not
  more mechanism; per-token scoping gets revisited only with real demand.
- The finer-grained future is **Grants** (see CONTEXT.md): per-Account rules over
  Operations × Selectors, managed as runtime objects via the Control API and Console.
  Grants can only narrow what Node Policy would allow, never widen it — the Node file
  is the root; the Relay layer only subtracts. Sequenced with the multi-principal RBAC
  milestone, not v1.
