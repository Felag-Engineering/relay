# One server certificate, multi-SAN, and the fingerprint-pinned join string

**Status:** Accepted; amended 2026-10-16 (the wire form is a `/proto` message; `RELAY_JOIN` lives in the daemon's environment file); amended 2026-10-21 (a join string is consumed, never persisted on a Node; a mint names its use limit).

ADR-0048 supersedes the 2026-10-21 amendment where a mint form defaults to one use: the form asks
how many Nodes the token is for.

Three facts about the Relay's TLS surface, each defensible alone, together made enrollment
harder than it needed to be:

1. **Two server certificates.** `newServer` in `relay/cmd/relay/main.go` issued one for the Node
   plane (`serverCert`) and another for the control plane (`controlCert`), both from the Relay
   CA, both `[]string{cfg.Hostname}, nil`. The comment above `controlCert` stated the intent:
   *"separate listeners get separate certificates."*
2. **One SAN each.** A mismatch between `RELAY_HOSTNAME` and what daemons dial was, by the
   sample config's own admission (`relay.env.example`), *"the single most common first-run
   mistake."*
3. **The CA certificate is couriered by hand.** `RELAY_CA_BUNDLE_PATH` pointed at a PEM the
   operator extracted from a `0700` state directory and shipped to every Node. It carries no
   secret, but its **integrity** is what stops a MITM impersonating the Relay to a first-boot
   Node — and nothing on arrival verified it.

## Context that changed

**A browser is arriving.** The Admin Console (v0.6.0/v0.7.0) puts a human in front of the
control plane. Two certificates means two fingerprints for a person to reason about, for a
distinction — which listener — no human cares about and no threat model rests on. Both private
keys live in the same process address space; nothing rotates or scopes them independently. The
isolation was notional. The second fingerprint is not.

**Everything the operator copies is re-mintable.** The only unrecoverable artifact in the
deployment is the CA *private* key, and it is never copied by hand. The fear that made
hand-couriering the CA cert feel safe was misplaced.

**The window for a breaking change is open and closing.** `v0.1.0-beta` has not shipped; no
daemon is deployed anywhere. Replacing `RELAY_CA_BUNDLE_PATH` costs nothing now and would cost a
migration path in three months.

## Decision

**1. One server certificate serves both listeners.** Issued once, shared.

The two `tls.Config`s stay separate and must: the Node plane requires a client certificate for
every RPC except the certless `Enroll`; the control plane requires none. Sharing the
certificate must never share `ClientAuth`. This is the mTLS path, so it carries a structural
test rather than a comment.

**2. The certificate carries multiple SANs**: `-hostname`, every detected non-loopback IP,
loopback, plus a repeatable `-san` flag. `IssueServerCertificate(dnsNames, ipAddresses)` already
takes both slices; only the call sites change.

The detected-IP SANs take DNS off the critical path for evaluation — a Node can dial by address
on day one. The `-san` flag is load-bearing, because under decision 1 the daemons' internal name
and the Console's external name must both appear in **one** list where two certificates could
have covered them separately.

**3. The join string replaces `RELAY_CA_BUNDLE_PATH`.** One pasteable artifact:

```
glp_join_<base64(host:port · ca-fingerprint · enrollment-token)>
```

A single opaque token rather than a delimited triple. It inherits the API Token's `glp_` prefix
so that a leak is greppable and secret scanners recognise it (`control-plane-credential.md`), it
needs no shell quoting, and it is one field to copy rather than three to reassemble in order.

The daemon verifies that the chain the Relay presents roots in a certificate whose **SHA-256
digest over the CA certificate DER** matches the pinned value — the number
`openssl x509 -noout -fingerprint -sha256` prints and a browser shows, so an operator can
compute it independently with tools they already have. SPKI pinning would survive CA
re-issuance, but re-issuance here is a "burn it down" event (`ca-disaster-recovery.md`) that
re-enrolls the fleet anyway, and legibility is worth more than surviving an event that
invalidates everything else.

Replaced, not deprecated: `RELAY_CA_BUNDLE_PATH` is removed. There are no deployed daemons to
migrate, and two enrollment paths would mean two sets of failure modes forever.

This is a **strict integrity improvement**. The trust anchor is unchanged; its integrity now
travels welded to the secret the operator was already protecting, instead of in a separate file
nobody checksums.

**4. The join string seeds steady state; `RELAY_ADDR` still wins when set.**

The join string carries an address, but a daemon needs one for every reconnect long after the
string is gone. At enrollment the daemon persists the address alongside the identity it already
persists (`key.pem`, `cert.pem`, `ca_bundle.pem`, `node_id`) and uses it thereafter.
`RELAY_ADDR`, when set, overrides the persisted value on every start.

Both halves are load-bearing. Persisting means a fresh Node's env file is two lines —
`RELAY_JOIN` and `RELAY_NODE_LABELS` — and the operator never types the address twice. The
override keeps config management authoritative for steady state: repointing a fleet at a moved
Relay is a variable change pushed like every other Policy and config change, not a
state-directory edit on every Node.

`RELAY_JOIN` is consumed only when no identity exists, exactly as `RELAY_ENROLLMENT_TOKEN` was,
and is inert afterward.

**5. The server certificate rotates, through a `GetCertificate` callback.**

Designing decision 1 surfaced a live defect. The server certificate was minted once at process
start (`serverCert` and `controlCert` in `newServer`), held as a static `tls.Certificate`, and
carried `LeafValidity` — `336 * time.Hour`, the constant documented as *"the lifetime issued to
Node identity certificates"*. Nothing renewed it. **A Relay process running longer than
fourteen days serves an expired certificate**, every daemon's chain verification fails, and the
fleet fail-closes off. It went unseen because no Relay had yet run two continuous weeks: the dev
fleet is recreated constantly and beta had not shipped.

The listener re-issues from the in-process CA when the current leaf is within a jittered
fraction of expiry. The Relay holds its own CA, so this needs no network round trip and no new
on-disk secret — strictly cheaper than the daemon-side renewal ADR-0006 already specifies for
identity certificates.

**Longer-lived certificates are rejected**: they move the cliff rather than remove it, and
extend the life of a key that never rotates. A fleet-wide outage on a timer is not a thing to
make rarer; it is a thing to make impossible.

The server leaf also gets its own constant instead of borrowing `LeafValidity`. It is not an
identity credential, its lifetime answers to different reasoning, and one constant serving both
invites exactly this kind of silent coupling.

This defect predates every other decision here and is **fixable on its own** — it should not
wait on the rest of this ADR.

## Alternatives rejected

**An operator-supplied certificate for the control plane** (Let's Encrypt, corporate PKI),
rejected 2026-08-18. The Node plane must keep the private CA regardless — it mints Node
identities, and no public CA will issue those — so this buys a clean browser experience at the
price of two trust roots serving one product. Delegating Console trust to the public CA cartel,
when the operator already holds an out-of-band verified fingerprint, is a downgrade dressed as
an upgrade.

**ACME in the Relay.** An outbound network dependency and an ACME client inside a
security-critical binary, and public ACME needs a public DNS name most fleets do not have.

**Keeping two certificates.** Costs a second human-facing fingerprint from v0.6.0 onward and
buys isolation that does not exist in practice.

## Consequences

**The browser interstitial persists** until the operator imports the CA, and importing the CA is
the *only* documented path — not "click through", and not comparing the leaf fingerprint.

An earlier draft said to compare the leaf, and decision 5 makes that untenable: a browser's
"accept this certificate" exception pins the leaf, so it would break at every rotation. An
operator ritual that silently stops working is worse than none. `relay init` therefore prints
exactly **one** number — the CA fingerprint — which is what the join string pins, what verifies
the trust-store import, and what survives every rotation. One trust anchor, one number, three
uses.

That is SSH's model, honestly stated. For this threat model it is not an apology.

**MCP clients need the CA in their trust store.** Unchanged, but on the critical path the moment
"an AI-agent drives the fleet" is the point of the product. Worth testing against real clients
early rather than discovering it at a demo.

**OAuth (ADR-0024)** redirects land the browser on an origin trusted only after that import.
`RELAY_OAUTH_PUBLIC_URL` must name a host in the SAN list.

**Amends ADR-0005 and ADR-0006** on the mechanism of first-contact Relay authentication — pinned
CA bundle file becomes pinned CA fingerprint. Neither ADR's decision changes: the daemon still
refuses an untrusted Relay, `Enroll` is still the single certless RPC, and the Relay still
generates `node_id` itself.

**New domain language** (GLOSSARY.md, same change): **join string**. It is *not* a synonym for
Enrollment Token — GLOSSARY.md lists "join key" as a term to avoid for that reason. The join
string is the transport bundle; the token is one of its three fields.

## Amendment (2026-10-16): the wire form, and where the join string lives on a Node

Two refinements. Neither changes a decision above.

**The wire form is a `/proto` message.** Decision 3 wrote the format informally as
`glp_join_<base64(host:port · ca-fingerprint · enrollment-token)>`. The contract is the
`JoinString` message in `/proto` (invariant 8), carrying a format version, the Relay address
Nodes dial, the CA fingerprint and the Enrollment Token; the text after `glp_join_` is the
unpadded base64url of that message serialized, and a codec on each side decodes it. Neither
codec echoes its input or the token in an error.

**`RELAY_JOIN` lives in the daemon's environment file, and invariant 11 does not forbid it.**
Invariant 11 says secrets never pass through the environment or the command line. It binds the
Relay: it is the rule about the Relay's security floor (`relay-configuration.md`, RC-14) and it
reads "the Relay can read them". The daemon's enrollment secret is a different object with a
different life. It is consumed once, when no identity exists, and is inert on every later start
(decision 4; `daemon-installation.md`, DI-38). It lives in the daemon's root-owned `0600`
environment file, where `RELAY_ENROLLMENT_TOKEN` always lived; the daemon's default Policy hides
that file and the process environment from the wire (ADR-0022, amended 2026-10-16); and
`relay-daemon join` writes the line without echo and never takes the string in argv. The
residual is R16, widened by R36, and this amendment changes neither. Delivering the string
through systemd `LoadCredential=` or a fetch from the customer's secret store stays the named
fix in that spec's Future work; choosing it later changes the mechanism, not this decision.
Owner decision of 2026-10-16.

## Amendment (2026-10-21): a join string is consumed, never persisted on a Node

Owner decision, 2026-10-21, while migrating `docs/specs/enrollment.md` (EN-30, EN-31) and
amending `docs/specs/daemon-installation.md` (DI-42, DI-43). The 2026-10-16 amendment above
places `RELAY_JOIN` in the daemon's environment file, read by the daemon at start. That
placement is withdrawn.

**Decided.** Where a join string reaches a Node, it is consumed by the act that enrolls and is
written nowhere: `relay-daemon join` reads it from a prompt or standard input, enrolls in that
same process, persists only the identity and the Relay address, and starts the unit. The daemon
reads no join string at start, and `RELAY_JOIN` ceases to be a setting. A Node therefore holds
an Enrollment Token for the seconds an enrollment takes and at no other time, in memory only.

**Why.** The environment file left the token readable by the daemon's own `file.read` through
`/proc/<pid>/environ` and its per-pid and `thread-self` aliases under the shipped default
Policy (ADR-0022's recorded residuals), and in every backup or image of the Node taken after
first start (threat model R16, R36). A Policy deny cannot close that without naming paths no
operator should have to know, and a daemon-side floor that beats Policy was rejected by
ADR-0021. Removing the secret closes it; denying the path only bounds it.

**Also decided.** A mint names a positive `max_uses` or asks explicitly for unlimited use, and
is refused if it does neither; a surface that offers a mint form defaults to one use and a TTL
measured in hours (ADR-0030), while the Control API takes explicit values. This narrows
ADR-0006's "reusable" token to reusable-by-choice. A leaked token then enrolls one Node for
hours, not a fleet for a year.

The join string's wire form and the fingerprint pin are unchanged. `docs/specs/enrollment.md`
and `docs/specs/daemon-installation.md` carry the claims; the threat model's R16 and R36 close
when they are promoted.

## Amendment (2026-10-21): the daemon's address variables are renamed

Owner decision, 2026-10-21, before the first release made the names a contract. The
relay-daemon's `RELAY_ADDR` is now `RELAY_ADDRESS` and its `RELAY_ENROLL_ENDPOINT` is now
`RELAY_ENROLL_ADDRESS`. Decision 4 is unchanged: the join string seeds steady state, and
`RELAY_ADDRESS`, when set, overrides the persisted value on every start. The Relay's own retired
`RELAY_ADDR` keeps its name in the refusal list, so the two no longer share one.

