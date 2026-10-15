# Relay configuration

**Status:** aspirational — worked through with the owner on `2026-09-15`, awaiting their review of
this draft. Describes intended behaviour, not the code (see the establishing phase in
`README.md`). Invariant 11 was rewritten and ADR-0010, ADR-0004, ADR-0012, ADR-0027 and
ADR-0030 amended on 2026-09-15 to match. Installation and secret-file intent revised with the
owner on 2026-10-15 to match ADR-0033's amendment of that date (milestone v0.6.5).

## Purpose

Relay configuration is what an operator fixes about a Relay: where it listens, which CA it signs
with, which identity provider it believes, how far one dispatch may reach, which dispatches wait
for a human, and whether the Console exists at all.

It is **two tiers, split by what an attacker gains from changing the setting.**

- The **security floor** is set on the host, in a root-owned file, and is unreachable from every
  surface. It is the small set that decides *who may authenticate at all* and *whether the gate
  exists*: listeners and TLS material, the identity provider Relay believes, the authentication
  windows, the approval notification path, and whether the Console may execute.
- **Operator settings** are runtime objects in the Relay's store, changed by a human `admin` in
  the Console with step-up re-authentication, audited, taking effect on the next request. They
  are the dials an operator genuinely turns as a fleet grows and confidence grows with it —
  including the blast caps and the approval-gate rules.

The tiering is the whole point: administering a Relay should not mean editing a file and
restarting a service, and no dial an operator turns should hand a stolen credential the ability
to authenticate as somebody else.

## Surfaces

| Surface | Access to the capability |
|---|---|
| **The host** | The security floor, as `RELAY_*` environment variables in a root-owned `EnvironmentFile` — placed by the Relay package beside its unit, or supplied to the Relay container by the host that runs it. Read at startup and on a reload signal |
| **Admin Console** | Every operator setting: read, and changed by a human `admin` with step-up. The only surface that writes configuration. Also renders the non-secret security floor, read-only |
| **Control API** | Reads the non-secret operator settings. **No write route exists, and none may be added** |
| **MCP** | Reads the non-secret operator settings, so an AI-agent can explain a refusal against the value that caused it. No write tool |
| **The `relay` binary's local subcommands** | `bootstrap-token` and `console-password` — first-boot acts that exist only because no credential can yet exist to perform them over the wire (ADR-0030) |

There are **no configuration command-line flags.** The binary accepts `--version`, `--help` and
its subcommands. One way to set a value means there is no precedence rule to reason about, and
nothing sensitive in a process listing.

## Behaviour

### The security floor

Set on the host only. No code path exists from any request to any of these values.

| Setting | Why it is here |
|---|---|
| gRPC and control-plane listen addresses, hostname for the server certificate | Bound at startup; a listener cannot be configured over itself |
| CA directory, store path | The trust anchor and the state; changing either is a different machine |
| OAuth issuer, audience, account claim, required scope, public URL | Whoever names the issuer decides who can authenticate |
| Console session maximum age and idle timeout, step-up freshness window | Authentication bounds. An `admin` who could widen their own step-up window has removed it |
| `console_execution` | Invariant 10 requires it root-owned |
| Approval webhook URL, secret file, timeout | Repointing it sends every approval request somewhere else and leaves the humans seeing nothing |
| Every secret file path | Secrets are named by path, never supplied as values |

A bare binary with no configuration **comes up closed**: the gRPC listener only, no control
plane, no Console, no OAuth, no approval notification. The CA directory, store path and
certificate hostname have **no defaults** — unset is a refusal naming the variable, because a
development-shaped default is a production deployment inheriting it silently.

### Operator settings

Runtime objects in the store, with built-in defaults, changed in the Console by a human `admin`
with step-up on every change, and audited with the setting, its old value, its new value, and
who changed it. A change applies to the next request; nothing already past its check is
revisited. Their `RELAY_*` variables are **not read** — a stale one left in the environment file
refuses startup rather than being silently ignored.

| Setting | Notes |
|---|---|
| Read and mutate blast caps | Raised and lowered as confidence grows |
| Approval-gate rules | Added, edited and removed as confidence grows |
| Minimum daemon version | Invariant 14's dispatch-level lever |
| `state:cert-expiring` fraction | Feeds one derived label |
| Enrollment rate limits, burst, tracked-IP ceiling | Flood protection tuned under load |
| Node cap | Capacity |
| Audit and Job retention, page-size limits | Housekeeping |
| Per-Account Console preferences | Per-Account, not fleet-wide (#442) |

**The blast caps and the approval-gate rules are Console-only.** No MCP tool and no Control API
route reads or writes them beyond the read described above, and none may be added. The
capability layer holds the decision, and the other adapters narrow to nothing — which is
invariant 10's "an adapter may offer less", not a second control path. The practical effect is
that only a human at a browser, re-entering their password, can widen the ceiling on what an
AI-agent may do; a machine Account cannot hold a Console session at all.

### Visibility

Non-secret operator settings are readable by any authenticated Account on every surface, so an
AI-agent that hits the mutate cap can name the cap it hit. The security floor is rendered in the
Console only, non-secret values only: file paths, the CA directory and the contents of any
secret file appear on no surface.

### Changing the floor: reload, and what a reload will not do

`SIGHUP` re-reads the floor from the environment file. The reload is **all-or-nothing**: the
whole file is validated, and if any value is invalid, or if any *bind-time* setting has changed
— listen addresses, CA directory, store path, certificate hostname — the entire reload is
refused, the log names the setting and says a restart is required, and the running configuration
is untouched. Nothing is ever half-applied, and a failed reload never exits the process.

Every reload is audited as a host-lever act, in the same lane as the Freeze signal's
`local-host`, listing what changed. Root on the box is a different root of authority from any
credential, and that is why the lever exists there and nowhere else.

The floor owns *which* file or directory is used. Changing the **contents** of TLS or CA material
is not a settings change: the server certificate already re-issues into the running listener, and
rotating the CA itself is a fleet-wide trust-anchor operation with its own steps and audit, not a
field on a screen.

### Validation

Every value is validated at startup and at reload, and an invalid one is a refusal naming the
setting — never a warning and a fallback to a default. A missing or unreadable floor file is a
refusal.

A configuration that **cannot work** is refused: the Console enabled without the control plane,
OAuth configured without an issuer. A configuration that is coherent but **probably a mistake** —
a mutate cap above the read cap — starts, with a prominent warning. The line is deliberate:
refusing the second class would make the Relay argue with an operator who has decided to trust
their fleet more.

### Secret files

Every secret is named by a path. The file must be **owned by root, readable by the Relay's
service group, and readable by nobody else** — `0640 root:relay` or tighter — or the Relay
refuses to start naming the file. The Relay checks the owner as well as the mode. The Relay
package creates a secrets directory with the same ownership for operators to place secret files
in, and the shipped `EnvironmentFile` is `0640 root:relay`. In the container, the same rule
applies to the mounted files as the container sees them.

The Relay's own CA private key is not an operator-supplied secret: the Relay writes it into its
state directory, owned by the service account and readable by nobody else, and refuses to start
if it finds it otherwise.

### Installation

Two production paths, documented as equals (ADR-0033, amended 2026-10-15):

- **The Relay package** (`.deb`, `.rpm`) on the platforms `daemon-installation.md` lists, less
  Alpine, where the container is the path. It installs the service account, the binary, the
  hardened unit, the `EnvironmentFile`, the state directory and the secrets directory; enables
  and starts the service;
  and prints a configuration guide that carries no secret, also installed as documentation.
  It never runs the first-boot command, because package-manager output lands in logs and that
  command prints credentials.
- **The Relay container image**, pinned by digest: unprivileged, no capabilities, read-only root
  filesystem, the CA and store on one durable volume, the security floor and secret files
  supplied by the host. It is a production path only once its documented deployment has had a
  human hardening review.

The hostname the Relay first starts with is written in the `EnvironmentFile`, never an implicit
default: the package writes the host's fully qualified name there once, at first install, and
the guide prints it so the operator can check it. The file is generated, not package-owned
configuration, so no upgrade rewrites it. Changing the hostname is an edit and a restart; it is
bind-time security floor, so a reload refuses it.

Remove keeps configuration, the CA and the store. `apt purge` removes configuration and the
store, and **never the CA**: it moves the CA directory aside with its ownership and modes intact
and prints where, because losing the CA invalidates every Node identity it issued and the whole
fleet must enroll again. Deleting it is a separate act by hand. `rpm` has no purge; removal
never deletes state and prints the paths to delete by hand.

### First boot

Install the package (or start the container), set the hostname, restart, then run the
first-boot command in a terminal: today `relay bootstrap-token` for the founding admin's first
API Token and `relay console-password` for their first Console credential, replaced by
`relay init` when it lands (ADR-0030). Everything else — Accounts, Nodes, Enrollment Tokens,
every operator setting — happens in the Console.

The Relay itself needs no privilege: an unprivileged service account, an empty capability set,
and a read-only filesystem outside its state directory.

## Refusals

| Refusal | Cause |
|---|---|
| No route exists | A configuration write attempted over MCP or the Control API. There is no endpoint to refuse it |
| Not authorized | An operator-setting change by a non-`admin`, a machine Account, or without fresh step-up |
| Startup refused, setting named | An invalid value, a missing required value (CA directory, store path, certificate hostname), an unreadable floor file, a secret file that is not root-owned or is readable beyond the Relay's service group, a CA private key readable by anyone but the service account, or an incoherent combination |
| Startup refused, stale variable named | A `RELAY_*` variable for a setting that now lives in the store |
| Reload refused | An invalid value, or a bind-time setting changed. The running configuration is unchanged and a restart is required |

## Governing ADRs and invariants

- **Invariant 11 / ADR-0010** — the invariant this capability implements, narrowed on
  2026-09-15 from *"configuration is unreachable from any API"* to *"no credential can change the
  terms on which credentials are accepted"*. Recorded in ADR-0010's amendment of that date.
- **Invariant 10 / ADR-0009, ADR-0026** — Console-only settings are an adapter offering less, not
  a parallel control path. `console_execution` stays root-owned.
- **Invariant 5 / ADR-0004, ADR-0012** — the blast caps remain enforced on the Relay before
  dispatch; only where they are set changed. Both ADRs carry a 2026-09-15 amendment saying so.
- **ADR-0027** — the approval gate. Amended 2026-09-15: its rules are store-backed and
  Console-edited; the webhook path stays root-owned.
- **ADR-0024** — OAuth issuer, audience, claim, scope and public URL are security floor.
- **ADR-0023** — no shared control-plane secret exists in configuration; the first credential is
  bootstrapped locally.
- **ADR-0030** — bounds the local subcommands. Amended 2026-09-15: when `relay init` lands it
  **replaces** `bootstrap-token` and `console-password` rather than joining them.
- **Invariant 14 / ADR-0014** — the minimum daemon version stays the Relay's only lever over
  daemon versions; it becomes an operator setting.
- **ADR-0033** — amended 2026-10-15: the Relay installs from an OS package rather than `relay-install.sh`, and
  the container image is a production path. Unbuilt.

## Seams and proof

Configuration is read once into a Config value at startup and replaced wholesale on a successful
reload; operator settings are read through a store-backed settings seam that the capability layer
consults, never a package-level variable a surface can reach. The Console's settings screens call
that seam; no other adapter holds a writer.

### What proves each claim

| Behaviour | Proven by | Seam |
|---|---|---|
| The shipped `EnvironmentFile` covers every setting the binary reads | `TestRelayEnvExampleCoversTheConfigSurface`, `TestRelayEnvExemptionsAreReal` | packaging |
| A gate-rules file that cannot be loaded fails closed | `TestLoadFailsClosed`, `TestLoadRefusesSymlink`, `TestLoadRefusesDirectory` | approval |
| A webhook secret file with loose permissions is refused | `TestSecretFilePermissionsAreEnforced` | approval notify |

Everything else in this spec is **unbuilt**. Today's binary takes flags and environment
variables with the environment winning, silently falls back to a default on most invalid values,
defaults the CA directory and store path to development-shaped relative paths, has no reload, no
store-backed settings, no Console settings screen, and checks the mode but never the owner of a
secret file. The gap is the backlog, not a defect to escalate.

## Out of scope

- The founding admin Account, Token minting, step-up and OAuth session semantics —
  `accounts-and-access.md`. This spec owns only where their bounds are set.
- Enrollment Tokens, join strings and bundles — `enrollment.md`.
- What the blast caps, approval gates and Freeze *do* — `execution.md`, `approval.md`,
  `freeze.md`.
- Configuring the relay-daemon on a Node, which is flags and environment from the customer's
  config management — `daemon-installation.md`.
- Relay's own health, metrics and logs — `observability.md`.
- Rotating CA or TLS material, which is an operation rather than a setting.

## Accepted residual risk

**A compromised human Console session can widen the fleet's ceiling.** With the blast caps and
approval-gate rules in the store and no root-set bound above them, an attacker holding a human
`admin` session and that Account's password can raise the mutate cap to the whole fleet and
remove every approval gate, then dispatch within the limits they just set. Step-up and the audit
trail are the controls; neither prevents it.

This was decided deliberately: a root-set ceiling above the Console value was offered and
declined in favour of one source of truth per setting. It is **R15** in
`docs/security/threat-model.md`, accepted by the owner on 2026-09-15 — invariant 11's "the API
can never raise its own limits" becomes "the API cannot, and a human in the Console can".

## Future work

- **`relay init`** — one idempotent first-boot command that **replaces** `bootstrap-token` and
  `console-password` rather than joining them, so the binary loses two verbs as it gains one
  (ADR-0030). The Relay package's configuration guide names it once it exists.
- **A root-set ceiling above the operator settings**, if the residual risk above proves real in
  practice.
- **Live reload of TLS material**, beyond the server certificate re-issue that already happens.
- **Configuration history in the Console** — who changed which dial and when, rendered from the
  audit trail rather than kept separately.

## Open questions

- **Does a second Relay against the same store see a settings change?** Single-Relay is assumed
  throughout; if that ever stops being true, store-backed settings need a cache-invalidation
  story that startup-only configuration never needed.
- **The operator runbook describes retired mechanisms** — the shared control-plane credential and
  "no packaged unit exists". Stale documentation rather than an open decision, but it is what an
  operator reads first.
