# One server certificate, multi-SAN, and the fingerprint-pinned join string

Three facts about the Relay's TLS surface, each defensible alone, which together make
enrollment harder than it needs to be:

1. **Two server certificates.** `main.go:391` issues one for the Node plane, `main.go:575`
   another for the control plane, both from the Relay CA, both
   `[]string{cfg.Hostname}, nil`. The comment at `main.go:572` states the intent:
   *"separate listeners get separate certificates."*
2. **One SAN each.** A mismatch between `RELAY_HOSTNAME` and what daemons dial is,
   by the sample config's own admission (`relay.env.example:35-37`), *"the single most
   common first-run mistake."*
3. **The CA certificate is couriered by hand.** `RELAY_CA_BUNDLE_PATH` points at a PEM the
   operator extracted from a `0700` state directory and shipped to every Node. It carries
   no secret, but its **integrity** is what stops a MITM impersonating the Relay to a
   first-boot Node — and nothing on arrival verifies it.

## Context that changed

**A browser is arriving.** The Admin Console (v0.6.0/v0.7.0) puts a human in front of the
control plane. Two certificates then means two fingerprints for a person to reason about,
for a distinction — which listener — that no human cares about and no threat model rests
on. Both private keys already live in the same process address space; nothing rotates or
scopes them independently. The isolation was notional. The second fingerprint is not.

**Everything the operator copies is re-mintable.** The only unrecoverable artifact in the
deployment is the CA *private* key, and it is the one thing never copied by hand. The fear
that made hand-couriering the CA cert feel safe was misplaced.

**The window for a breaking change is open and closing.** `v0.1.0-beta` has not shipped;
no daemon is deployed anywhere. Replacing `RELAY_CA_BUNDLE_PATH` costs nothing today and
would cost a migration path in three months.

## Decision

**1. One server certificate serves both listeners.** Issued once, shared.

The two `tls.Config`s stay separate and must: the Node plane requires a client certificate
for every RPC except the certless `Enroll`; the control plane requires none. Sharing the
certificate must never share `ClientAuth`. This is the mTLS path, so it carries a
structural test rather than a comment.

**2. The certificate carries multiple SANs**: `-hostname`, every detected non-loopback IP,
loopback, plus a repeatable `-san` flag. `IssueServerCertificate(dnsNames, ipAddresses)`
already takes both slices; only the call sites change.

The detected-IP SANs remove DNS from the critical path for evaluation — a Node can dial by
address on day one. The `-san` flag is load-bearing rather than a convenience, because
consequence of decision 1 is that daemons' internal name and the Console's external name
must now both appear in **one** list where two certificates could have covered them
separately.

**3. The join string replaces `RELAY_CA_BUNDLE_PATH`.** One pasteable artifact:

```
glp_join_<base64(host:port · ca-fingerprint · enrollment-token)>
```

A single opaque token rather than a delimited triple. It inherits the `glp_` prefix the
API Token already carries so that a leak is greppable and secret scanners recognise it
(`control-plane-credential.md`), it needs no shell quoting, and it is one field to copy
rather than three to reassemble in the right order.

The daemon verifies that the chain the Relay presents roots in a certificate whose
**SHA-256 digest over the CA certificate DER** matches the pinned value — the number
`openssl x509 -noout -fingerprint -sha256` prints and a browser shows, so an operator can
compute it independently with tools they already have. SPKI pinning would survive CA
re-issuance, but re-issuance here is a "burn it down" event
(`ca-disaster-recovery.md`) that re-enrolls the fleet anyway, and legibility is worth more
than surviving an event that invalidates everything else.

Replaced, not deprecated: `RELAY_CA_BUNDLE_PATH` is removed. There are no deployed daemons
to migrate, and two enrollment paths would mean two sets of failure modes forever.

This is a **strict integrity improvement**. The trust anchor is unchanged; what changes is
that its integrity now travels welded to the secret the operator was already protecting,
instead of in a separate file nobody checksums.

**4. The join string seeds steady state; `RELAY_ADDR` still wins when set.**

The join string carries an address, but a daemon needs one for every reconnect long after
the string is gone. At enrollment the daemon persists the address alongside the identity
it already persists (`key.pem`, `cert.pem`, `ca_bundle.pem`, `node_id`) and uses it
thereafter. `RELAY_ADDR`, when set, overrides the persisted value on every start.

Both halves are load-bearing. Persisting means a fresh Node's env file is two lines —
`RELAY_JOIN` and `RELAY_NODE_LABELS` — and the operator never types the address twice.
The override means config management stays authoritative for steady state: repointing a
fleet at a moved Relay is a variable change pushed the way every other Policy and config
change is pushed, not a state-directory edit on every Node.

`RELAY_JOIN` is consumed only when no identity exists, exactly as `RELAY_ENROLLMENT_TOKEN`
is today, and is inert afterward.

**5. The server certificate rotates, through a `GetCertificate` callback.**

Designing decision 1 surfaced a live defect. The server certificate is minted once at
process start (`main.go:391`, `main.go:575`), held as a static `tls.Certificate`, and
carries `LeafValidity` — `336 * time.Hour`, the constant documented as *"the lifetime
issued to Node identity certificates"*. Nothing renews it. **A Relay process running
longer than fourteen days serves an expired certificate**, every daemon's chain
verification fails, and the fleet fail-closes off. It has gone unseen because no Relay has
yet run two continuous weeks: the dev fleet is recreated constantly and beta has not
shipped.

The listener re-issues from the in-process CA when the current leaf is within a jittered
fraction of expiry. The Relay holds its own CA, so this needs no network round trip and no
new on-disk secret — it is strictly cheaper than the daemon-side renewal ADR-0006 already
specifies for identity certificates.

**Longer-lived certificates were the alternative and are rejected**: they move the cliff
rather than removing it, and they extend the life of a key that never rotates. The failure
mode is a fleet-wide outage on a timer, which is not a thing to make rarer — it is a thing
to make impossible.

The server leaf also stops borrowing `LeafValidity` and gets its own constant. It is not
an identity credential, its lifetime answers to different reasoning, and one constant
serving both invites exactly this kind of silent coupling.

This defect predates every other decision here and is **fixable on its own** — it should
not wait on the rest of this ADR.

## Alternatives rejected

**An operator-supplied certificate for the control plane** (Let's Encrypt, corporate PKI),
considered and rejected 2026-08-18. The Node plane must keep the private CA regardless —
it mints Node identities and no public CA will issue those — so this buys a clean browser
experience at the price of two trust roots serving one product. Delegating Console trust
to the public CA cartel, when the operator already holds an out-of-band verified
fingerprint, is a downgrade dressed as an upgrade.

**ACME in the Relay.** An outbound network dependency and an ACME client inside a
security-critical binary, and public ACME requires a public DNS name most fleets do not
have.

**Keeping two certificates.** Costs a second human-facing fingerprint from v0.6.0 onward
and buys isolation that does not exist in practice.

## Consequences

**The browser interstitial persists** until the operator imports the CA, and importing the
CA is the *only* documented path — not "click through", and not comparing the leaf
fingerprint.

Comparing the leaf is what an earlier draft of this ADR said, and decision 5 makes it
untenable: a browser's "accept this certificate" exception pins the leaf, so it would
break at every rotation. An operator ritual that silently stops working is worse than no
ritual. `relay init` therefore prints exactly **one** number — the CA fingerprint — which
is simultaneously what the join string pins, what verifies the trust-store import, and
what survives every rotation. One trust anchor, one number, three uses.

That is SSH's model, honestly stated. For this threat model it is not an apology.

**MCP clients need the CA in their trust store.** Unchanged from today, but it moves onto
the critical path the moment "an AI-agent drives the fleet" is the point of the product.
Worth testing against real clients early rather than discovering it at a demo.

**OAuth (ADR-0024)** redirects land the browser on an origin trusted only after that
import. `RELAY_OAUTH_PUBLIC_URL` must name a host in the SAN list.

**Amends ADR-0005 and ADR-0006** on the mechanism of first-contact Relay authentication —
pinned CA bundle file becomes pinned CA fingerprint. Neither ADR's decision changes: the
daemon still refuses an untrusted Relay, `Enroll` is still the single certless RPC, and
the Relay still generates `node_id` itself.

**New domain language** (GLOSSARY.md, same change): **join string**. Note it is *not* a
synonym for Enrollment Token — GLOSSARY.md already lists "join key" as a term to avoid for
exactly that reason. The join string is the transport bundle; the token is one of its
three fields.
