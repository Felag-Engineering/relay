# `relay init` and the boundary of the `relay` binary

**Status:** Accepted; amended by ADR-0033 and twice on 2026-10-16 (`init` adopts the running Relay's CA and store; the first admin is named at `init` and no Account name is reserved).

Standing up a Relay and joining five Nodes takes roughly fifty discrete acts today, and
the Relay-side share of that is choreography rather than decisions: edit the env file,
start the service, run `bootstrap-token`, extract `ca-cert.pem` from a `0700` state
directory, `curl` the mint endpoint using the cert you just extracted, copy the token out.
Each step is defensible; the sequence is not discoverable, and the ordering dependency
(you need the CA cert before you can mint anything) is invisible until it bites.

The shape of the fix is already proven. `docker/bootstrap.sh` and
`docker/mint-credential.sh` automate exactly this chain for the dev fleet, against the
real Control API, and have done since #298.

The risk in fixing it is regrowth. The official CLI (#137) was **built and then
deliberately removed** in v0.4.0: the Admin Console covers the same admin and execution
surface with better safety ergonomics, and the one workflow that appeared to require a
CLI — v0.8.0 signing — does not. A bootstrap command with no stated boundary becomes that
CLI again, one convenient verb at a time.

## Decision

**The `relay` binary may perform an act only if no credential could exist to perform it
over the wire.**

That is the whole line. It is the same reasoning ADR-0023 used for `bootstrap-token` and
ADR-0002 uses for Policy: root the first thing locally, in the filesystem, because there
is nothing else yet to root it in. Everything else has a credentialed surface and belongs
there.

**`relay init` is one atomic first-boot transaction spanning that boundary.** It creates
the CA, creates the store, ensures the founding admin Account, mints that Account's first
API Token, mints a first Enrollment Token, and renders an enrollment playbook.

Minting an Enrollment Token normally requires a credential, which would put it outside the
line. It is admitted here because *inside the transaction* the credential is one `init`
itself just created and has not yet emitted. The moment `init` returns, that path closes:
every subsequent Enrollment Token goes through `/api/v1` or the Console like everything
else.

**Explicitly outside the binary**, each because a credentialed surface already covers it:
listing or revoking anything, running Operations, managing Accounts, minting further
Enrollment Tokens, and editing Relay configuration (which no surface may reach at all —
invariant 11).

**`init` is idempotent.** An existing CA, store, or founding admin is adopted, never
recreated or repaired. Re-running reports state and does not silently re-emit secrets;
a fresh Enrollment Token requires asking for one explicitly.

**Falsifier:** `docker/bootstrap.sh` and `docker/mint-credential.sh` are deleted and the
dev fleet uses `relay init`. If it cannot replace both, it has not absorbed the
chicken-and-egg chain and the boundary is drawn in the wrong place.

## Consequences

The rendered playbook **inlines the Enrollment Token** (decided 2026-08-18, interim). That
puts a live credential in a file that gets copied to laptops and pasted into chat, so two
things are not optional: `init`'s first token defaults to a short TTL measured in hours,
and the rendered file carries its own expiry in a header comment. Rendering a
`{{ vault_… }}` placeholder instead is the improvement; it is not a blocker, and it is not
a substitute for the short TTL.

`relay init` writes `/etc/relay/relay.env` with `RELAY_CONTROL_ENABLED=true`, because a
Relay whose control plane is off is a server with nothing able to drive it — today's
default produces a valid admin token and no listener to spend it on. The **binary's**
default stays `false`: `init` makes the operator's initial configuration coherent, and
someone running the binary bare still gets the closed posture.

The rendering of an enrollment bundle is a **capability**, not an `init` feature
(invariant 10). `init` calls it locally; `/api/v1` exposes it; the Console renders it at
v0.7.0, where minting an Enrollment Token first becomes possible (v0.6.0 accepts zero
mutating routes). One implementation, three surfaces, in that order.

Reopening #137 remains the escape hatch if operators ask for a terminal surface once the
Console is real. This ADR does not reopen it; it draws the line that keeps `init` from
doing so by accident.

## Amendment (2026-09-15): `init` replaces the two local commands rather than joining them

`init` remains unbuilt and deferred. What is now decided is its **shape when it lands**: it
replaces `bootstrap-token` and `console-password` rather than being a third verb beside them, so
the binary loses two verbs as it gains one. That keeps this ADR's boundary — the binary widening
by accident, one convenient verb at a time, is the failure it exists to prevent.

Until then first boot is those two commands, and everything else — Accounts, Nodes, Enrollment
Tokens, every operator setting — happens in the Console. See `docs/specs/relay-configuration.md`.

## Amendment (2026-10-15): amended by ADR-0033 — the package writes the first configuration

Owner decision, 2026-10-15, recorded in ADR-0033's amendment of that date. The Relay now
installs from an OS package, and the package — not `relay init` — writes the Relay's configuration
file (`/etc/relay/relay.toml`, ADR-0043),
once, at first install, only if none exists: the host's fully qualified name as the certificate hostname, the CA
directory and store path, the control plane and the Admin Console enabled, and the
control-plane listener bound to loopback until the operator widens it. The reason
*Consequences* gives for enabling the control plane stands; only the writer changes. `init`,
when it lands, mints the founding credentials and does not write the configuration file. The
package installs the Relay and enables it where presets allow, but never starts it, and never runs `init`, because
package-manager output lands in logs and `init` prints credentials; the operator starts the
Relay and runs `init` in a terminal. The binary's own default for the control plane stays
`false`, and the boundary this ADR draws around the `relay` binary is unchanged: no verb is
added.

## Amendment (2026-10-16): `init` adopts the running Relay's CA and store

Owner decision, 2026-10-16, taken with the v0.6.5 design. *Decision* says `init` creates the CA
and the store; with the package model it does not. The Relay creates its CA and store at its
own first start, in its own state directory (ADR-0043), and `init` runs afterwards, as the
Relay's own Unix account, against that existing store: it refuses to run as root, so nothing it
writes is left owned by an account the Relay cannot use. Its acts are minting the founding
admin's first API Token and first Console credential, and taking over `bootstrap-token`'s
recovery role by an explicit request; it stays idempotent and never silently re-emits a secret.
Specified as RC-28 in `docs/specs/relay-configuration.md`. The boundary this ADR draws around
the `relay` binary is unchanged.

## Amendment (2026-10-16): the first admin is named at `init`, and no Account name is reserved

Owner decision, 2026-10-16, closing the open decision on how the first admin is created.
*Decision* says `init` ensures the founding admin Account: a fixed, reserved name the Relay seeds
at its own start (ADR-0023). The reservation exists only because the name is fixed, since a later
Account taking it would inherit the founding identity's audit history. Naming the admin removes
the reason for the reservation along with the reservation.

Where `init` creates the first admin, it does so only on a store that holds no human Account:
one human `admin` Account with the name the operator gives it, its Console password taken from
a prompt with no echo, its first API Token minted once. The Relay seeds no Account at start.
With any human Account present, `init` creates nothing and emits no secret, and a re-run reports
state; managing Accounts stays outside the binary, where *Decision* put it. Recovery is an
explicit request that names an enabled human `admin` and re-mints that Account's API Token,
audited; it refuses a disabled or non-admin Account. No Account is privileged by name, at `init`
or afterwards, so nothing is reserved against any creation path.

Rejected: a one-time setup code redeemed by the first Console visit. It makes a request create
the first credential, which invariant 11 places in the security floor, and ADR-0023's objection
stands: "only until first use" is a race, not a boundary.

Specified as RC-28 in `docs/specs/relay-configuration.md`. `accounts-and-access.md`'s
reserved-name clause and the Relay's start-time seeding end when `init` lands. The boundary this
ADR draws around the `relay` binary is unchanged.
