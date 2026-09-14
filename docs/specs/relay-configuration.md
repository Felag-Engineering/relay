# Relay configuration

**Status:** stub — aspirational, not yet worked through with the owner (`2026-09-13`).

## Purpose

Relay configuration is the security floor an operator sets for a Relay before anything can
authenticate to it: where it listens, which CA it trusts and signs with, which identity provider
it believes, how far a single dispatch may reach, which dispatches wait for a human, and whether
the Console exists at all. It is set on the host, at startup, and no credential of any role can
reach it — so a stolen API Token or a jailbroken AI-agent can never raise its own limits.

It is also the operator's first contact with the product. Standing a Relay up should be a
file-and-service concern owned by the customer's config management, short enough to be
discoverable, and closed by default when the binary is run bare.

## Surfaces

- **The host, not the wire.** Startup configuration arrives as environment variables and
  equivalent command-line flags, delivered in production by a root-owned systemd unit and its
  `EnvironmentFile`. No MCP tool, Control API operation or Console screen reads or writes it.
- **The `relay` binary's local subcommands** — `bootstrap-token` and `console-password` today;
  `relay init` is decided by ADR-0030 and not built. Each exists only because no credential
  could yet exist to perform the act over the wire.
- **The first-party installer** (`relay-install.sh`, ADR-0033) — decided, not built.
- **Local operator levers that are not startup configuration** — the Freeze signal and its
  release reason. Uncertain whether these belong here or wholly in `freeze.md`.

## Behaviour

_To be established by interrogation._

Candidate claims, from the ADRs and the code — each to be confirmed, changed or dropped:

- No code path exists from a request on any surface to any configuration value: listeners, CA
  directory, store path, blast caps, the node cap, enrollment rate limits, the minimum daemon
  version, the `state:cert-expiring` fraction, the approval-gate rules path, the webhook, OAuth
  issuer settings, Console enablement and session bounds, and the step-up window.
- Every secret the Relay reads is named by a file path, never passed as a value.
- A secret file that is group- or world-accessible refuses startup.
- An environment variable overrides its equivalent flag.
- The binary run with no configuration comes up closed: the control plane off, the Console off,
  OAuth off, no approval gates.
- A malformed minimum daemon version, an out-of-range `state:cert-expiring` fraction, and a
  configured approval-gate path that cannot be loaded each refuse startup.
- Configuration is read once at startup; changing it takes a restart.
- The Relay needs no privilege: it runs as an unprivileged service account with an empty
  capability set and a read-only filesystem outside its state directory.
- Every `RELAY_*` setting the code reads appears in the shipped example `EnvironmentFile`.
- `relay init` is one idempotent first-boot transaction: CA, store, founding admin Account, its
  first API Token, a short-TTL first Enrollment Token and a rendered playbook — adopting, never
  recreating, anything that already exists.

## Refusals

_To be established by interrogation._

Candidate claims, from the ADRs and the code — each to be confirmed, changed or dropped:

- Any attempt to change configuration through MCP, the Control API or the Console has no route
  to refuse: the operation does not exist.
- Startup is refused, with the offending setting named, on each validation failure listed above.
- The `relay` binary refuses to grow a verb that a credentialed surface already covers.

## Governing ADRs and invariants

- **Invariant 11 / ADR-0010** — configuration is operator-set at startup and unreachable from
  any API; secrets are file paths; this spec is where that invariant's property is specified.
- **ADR-0030** — the `relay` binary may perform an act only if no credential could exist to
  perform it over the wire; bounds every local subcommand and `relay init`.
- **ADR-0023** — no shared control-plane secret exists in configuration; the first credential is
  bootstrapped locally into the store.
- **ADR-0024** — OAuth issuer, audience, claim, scope and public URL are Relay configuration.
- **ADR-0033** — the installer ships inside the release and runs `relay init`; no `curl | sh`.
- **Invariant 5 / ADR-0004, ADR-0012** — the per-class blast caps are configured here and
  nowhere else.
- **Invariant 14 / ADR-0014** — the minimum daemon version is the Relay's only lever over
  daemon versions, and is configuration.
- **Invariant 10 / ADR-0026** — the `console_execution` flag is root-owned configuration.
- **ADR-0027** — approval-gate rules and the webhook secret are root-owned files.

## Seams and proof

_Not yet written._

## Out of scope

- The founding admin Account, API Token minting and OAuth session semantics —
  `accounts-and-access.md`.
- Enrollment Tokens, join strings and enrollment bundles, including the one `init` renders —
  `enrollment.md`.
- What the blast caps, approval gates and Freeze *do* — `execution.md`, `approval.md`,
  `freeze.md`. This spec owns only that they are set here.
- Installing and configuring the relay-daemon on a Node — `daemon-installation.md`.
- Relay's own health and logs — `observability.md`.
- Runtime objects (Accounts, Tokens, Nodes, Jobs, approvals): managed over the wire, never here.

## Open questions

1. **Invalid values fall back silently.** A malformed blast cap, node cap, enrollment rate or
   boolean is logged as a warning and the default is used; only three settings refuse startup.
   Should every malformed security-floor value refuse startup instead?
2. **Documented defaults disagree with the binary.** The example `EnvironmentFile` says its
   values are the defaults, but the binary's own defaults for the CA directory, store path and
   hostname are relative, development-shaped paths. Which is the real default, and should a bare
   binary ever write a CA into its working directory?
3. **Env-over-flag precedence.** Today the environment wins over the flag. Is that the rule you
   want, or should a conflict between the two refuse startup?
4. **Is "restart to change" the contract?** There is no reload. Is that deliberate, and should
   the spec promise it so nobody adds a SIGHUP reload of the security floor?
5. **"Root-owned" is not what is checked.** Invariant 11 says a secret file must be root-owned
   and not world-readable; the webhook secret check refuses group- or world-accessible modes
   but does not check the owner, and the approval-gate file has a laxer bar. Which property do
   you want, per file?
6. **The `EnvironmentFile` mode is documented two ways** — `0600 root:relay` in the unit's
   comments, `0640 root:relay` in the packaging guide and example. Which?
7. **`relay init` and the installer are unbuilt.** Is their shape in ADR-0030/0033 still what
   you want — including `init` writing a config that enables the control plane while the bare
   binary stays closed?
8. **The playbook inlines a live Enrollment Token** (ADR-0030, marked interim). Is a vault
   placeholder now the target, and what TTL should `init`'s first token carry?
9. **Should the Relay refuse a configuration that is coherent but dangerous** — Console enabled
   without the control plane, a mutate cap above the read cap, a mutate cap of the whole fleet?
10. **Should the running configuration be visible?** Nothing on any surface reports the
    effective blast caps or gates. A read-only, non-secret echo would help an AI-agent explain a
    refusal — or is any read of configuration over the wire a line you don't want crossed?
11. **Is a config file the eventual shape?** ADR-0010 describes a root-owned config file; today
    it is environment variables and flags. Is env-and-unit the permanent delivery mechanism?
12. **Operator docs describe retired mechanisms.** The Relay install runbook still shows the
    retired shared control-plane credential and says no packaged unit exists. Confirm the
    runbook, not the ADRs, is stale.

## History

- `2026-09-13` — stub created to name the capability.
