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

- The **security floor** is set on the host, in a root-owned file — or, for a container, in
  whatever its deployment injects — writable only by a root-equivalent human, and unreachable
  from every surface. It is the small set that decides *who may authenticate at all* and *whether the gate
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
| **The host** | The security floor, as `RELAY_*` environment variables: on a packaged host, in a root-owned `EnvironmentFile` placed beside the unit, read at startup and on a reload signal; in a container, injected by the deployment from a source only a root-equivalent human can write (invariant 11), read at startup only |
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

A bare binary with only its required values set **comes up closed**: the gRPC listener only, no control
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

**A container has no reload.** Its floor arrives as the environment its deployment injects, which
a running process cannot re-read; every floor change is a redeploy.

Every reload is audited as a host-lever act, in the same lane as the Freeze signal's
`local-host`, listing what changed. Root on the box is a different root of authority from any
credential, and that is why the lever exists there and nowhere else.

The floor owns *which* file or directory is used. Changing the **contents** of TLS or CA material
is not a settings change: the server certificate already re-issues into the running listener, and
rotating the CA itself is a fleet-wide trust-anchor operation with its own steps and audit, not a
field on a screen.

### Validation

Every value is validated at startup and at reload, and an invalid one is a refusal naming the
setting — never a warning and a fallback to a default. On a packaged host the floor file is
root-owned and writable by root alone; today systemd reads it and hands the Relay only its
values, so the Relay cannot check the file. Once the Relay reads the file itself — the reload
above names its path — a missing or unreadable floor file is a refusal, and so is one that
anyone but root can write. The deployment mode decides whether that check applies, never
whether a file happens to exist.

A configuration that **cannot work** is refused: the Console enabled without the control plane,
OAuth configured without an issuer. A configuration that is coherent but **probably a mistake** —
a mutate cap above the read cap — starts, with a prominent warning. The line is deliberate:
refusing the second class would make the Relay argue with an operator who has decided to trust
their fleet more.

### Secret files

Every secret is named by a path. **A secret file is readable by no principal but the Relay, and
writable by none but root — and, for material the Relay generates, the Relay** (invariant 11,
reworded 2026-10-15; not yet enforced, known-gap row 11, #864). In practice:

- an **operator-placed** secret — the webhook secret, OAuth and TLS key files — is owned by root
  and readable only by the Relay's group, with no write bit for the group, so the Relay can read
  it and never rewrite it (a file the Relay owned could be made writable again by the Relay
  itself; a read-only mount in a container is the one exception, since nothing can change it);
- a **Relay-generated** secret — its CA private key — is owned by the Relay's uid and readable by
  nobody else.

The Relay refuses to start on a secret file that breaks either rule, naming the file and checking
the owner as well as the mode. The package creates a secrets directory beneath `/etc/relay`,
owned by root and readable but not writable by the Relay's group; `/etc/relay` itself stays
root-owned too. Neither directory is writable by the Relay, because write access to a directory
would let it replace the root-owned files inside it.

**The floor's configuration is the operator's.** It is root-owned and writable by root alone,
wherever it is sourced. A compromised Relay process holds its secrets, which it needs anyway, but
cannot rewrite the operator's floor configuration or an operator-placed secret.

In the container, the secret-file rule applies to each mounted secret as the container sees it,
and the floor's source is held to the same property: writable only by a root-equivalent human,
never by a credential Relay issues or accepts or by an automated principal. A deployment driven
from a git branch that a CI system or an AI-agent's token can push to does not meet that today;
it is a known gap until the image's hardening review closes it (`AGENTS.md`, row 11).

### Installation

*(Designed for v0.6.5.)* Two deployment paths (ADR-0033, amended 2026-10-15). The package is
production from its first release. The image is a supported deployment path now and is called
production once a human hardening review of its documented deployment has closed the floor-source
gap; until then its documentation says so.

- **The Relay package** (`.deb`, `.rpm`) on the platforms `daemon-installation.md` lists, under
  that list's CI rule, where the edited configuration a Relay upgrade must preserve is its
  `EnvironmentFile`. It installs the Relay's Unix account, the binary, the hardened unit, the
  `EnvironmentFile`, the state directory and the secrets directory, and prints a configuration
  guide that carries no secret, also installed as documentation. **It enables the Relay and never
  starts it**: starting at install would mint the CA private key wherever the package is
  installed — inside an image bake, so every clone shares one key, or a container build with no
  running init. Enabling happens on first install only, only where systemd is running, and
  honours the distribution's presets. It never runs the first-boot command, because
  package-manager output lands in logs and that command prints credentials.
- **The Relay container image**, pinned by digest: unprivileged, no capabilities, read-only root
  filesystem, the CA and store on one durable volume, nothing in the image carrying
  configuration, the security floor injected by the deployment, and secret files mounted
  read-only. Anyone who can inspect the container can read the floor's values — settings, not
  secrets, except an approval webhook URL that is itself a capability URL — which is an accepted
  residual risk (R35) the hardening review must narrow.

The Relay packages are built the way the daemon's are: they wrap the release's guarded binary
and compile nothing, they are reproducible, they are listed in the release `SHA256SUMS`, and they
carry no signature of their own before v1.0.0 (`daemon-installation.md`, *Release integrity*).
The image is different: it is published to the registry rather than attached to the release, it
is not byte-reproducible, it is signed at its digest, and the `relay` binary inside it is the one
`SHA256SUMS` covers.

**The package writes the `EnvironmentFile` once, at first install**, and never again: the host's
fully qualified name as the certificate hostname — never an implicit default — the CA directory
and store path inside the state directory, the control plane and Admin Console enabled, and the
**control-plane listener bound to loopback**. Nothing is reachable off the host until the operator
widens that listener, which the guide says to do only after the first-boot command has run.
Enabling the control plane was assigned to `relay init` (ADR-0030, amended 2026-10-15). The file
is generated, not package-owned configuration, so no upgrade rewrites it. Changing the hostname
is an edit and a restart; it is bind-time security floor, so a reload refuses it.

Remove keeps configuration and state. `apt purge` removes configuration and **never destroys or
splits the state directory**: it moves the CA and the store aside together, re-owned by root and
readable by nobody else, and prints where. They stay together because the store holds the
revocation list — a CA restored without it would readmit every revoked Node whose certificate is
still valid — and losing the CA would force the whole fleet to enroll again. Deleting them is a
separate act by hand, and until then the purged host holds a live CA private key (R34). Purge
never deletes the Relay's Unix account, so no later account inherits its uid, and it deletes only
paths the package itself created. `rpm` has no purge; removal never deletes state and prints the
paths to delete by hand.

### First boot

Install the package, check `relay.env` (the hostname above all), start the Relay, then run the
first-boot command in a terminal: today `relay bootstrap-token` for the founding admin's first
API Token and `relay console-password` for their first Console credential; *(designed for
v0.6.5)* `relay init`, which replaces both (ADR-0030) and is what the package's guide names. Then
widen the control-plane listener if the Console is to be reached off the host. Everything else —
Accounts, Nodes, Enrollment Tokens, every operator setting — happens in the Console. Never
capture an image of a host after the Relay has first started: the CA private key would travel
with it.

The Relay itself needs no privilege: an unprivileged Unix account, an empty capability set, and
a read-only filesystem outside its state directory.

## Refusals

| Refusal | Cause |
|---|---|
| No route exists | A configuration write attempted over MCP or the Control API. There is no endpoint to refuse it |
| Not authorized | An operator-setting change by a non-`admin`, a machine Account, or without fresh step-up |
| Startup refused, setting named | An invalid value, a missing required value (CA directory, store path, certificate hostname), an unreadable floor file, or once the Relay reads it itself one that anyone but root can write, a secret file readable by anyone but the Relay or writable by anyone but root (or, for the CA private key, the Relay), or an incoherent combination |
| Startup refused, stale variable named | A `RELAY_*` variable for a setting that now lives in the store |
| Reload refused | An invalid value, or a bind-time setting changed. The running configuration is unchanged and a restart is required |

## Governing ADRs and invariants

- **Invariant 11 / ADR-0010** — the invariant this capability implements, narrowed on
  2026-09-15 from *"configuration is unreachable from any API"* to *"no credential can change the
  terms on which credentials are accepted"*. Recorded in ADR-0010's amendment of that date. Its
  secret-file clause was reworded on 2026-10-15 (ADR-0033; ADR-0010's amendment of that date):
  a secret file is readable only by the Relay and writable only by root (or the Relay, for what it
  generates); and wherever the floor is sourced, a container deployment's injected environment
  included, it is writable only by a root-equivalent human, never by a credential or automated
  principal.
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
  **replaces** `bootstrap-token` and `console-password` rather than joining them. Amended
  2026-10-15: the package, not `init`, writes the environment file.
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
store-backed settings, no Console settings screen, checks the mode but never the owner of a
secret file, reads the CA private key back with no mode or owner check, and never checks that the
floor file is root-owned (known-gap row 11). The gap is the backlog, not a defect to escalate.

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

**A purged Relay host keeps its CA private key.** No package operation destroys the CA, so
`apt purge` moves the state directory — CA and store together — aside instead of deleting it, and
the key stays on disk until someone deletes it by hand. Losing the CA by one mistyped command
would force the whole fleet to enroll again, and that was judged the worse outcome. Accepted by
the owner on 2026-10-15 and recorded as **R34**. The compensating controls: the moved directory is
root-owned and unreadable to every other account; purge prints where it went; and the
documentation that describes purge says to delete it, or destroy the host, when the Relay is gone
for good.

**A container deployment's floor values are readable by whoever can inspect it.** They are
settings, not secrets — every secret is a file path — except an approval webhook URL that is
itself a capability URL. Accepted by the owner on 2026-10-15 and recorded as **R35**, to be
narrowed by the image's hardening review before it is called production; the docker group is
root-equivalent on the host anyway. Who can *write* the floor is not a residual risk: a source a
credential or automated principal can write breaks invariant 11, and is a known gap.

## Future work

- **A root-set ceiling above the operator settings**, if the residual risk above proves real in
  practice.
- **Live reload of TLS material**, beyond the server certificate re-issue that already happens.
- **Configuration history in the Console** — who changed which dial and when, rendered from the
  audit trail rather than kept separately.

## Open questions

- **Does a second Relay against the same store see a settings change?** Single-Relay is assumed
  throughout; if that ever stops being true, store-backed settings need a cache-invalidation
  story that startup-only configuration never needed.
- **The operator runbook describes retired mechanisms** — the shared control-plane credential,
  "no packaged unit exists", and, since 2026-10-15, its Compose section's container-as-evaluation
  framing and its secret-file modes. Stale documentation rather than an open decision, but it is
  what an operator reads first; ADR-0033's amendment lists it for update.
