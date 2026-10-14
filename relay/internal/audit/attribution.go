package audit

import (
	"errors"
	"fmt"
	"strings"
)

// PrincipalLocalHost is the Principal (and Verified.AccountName, with an empty
// AccountID) of an act performed by root on the Relay host itself: the freeze
// signal (capability.localHostPrincipal) and the host credential levers.
// It is not an Account and holds no role.
const PrincipalLocalHost = "local-host"

// Attribution is the identity carried on every audit record, in **two
// structurally distinct lanes** (ADR-0027 decision 10, docs/specs/approval.md).
//
// The distinction is the whole point, not a nicety:
//
//   - **Verified** — the Relay authenticated this itself. The acting Account,
//     its role at the time, and the credential presented. A caller cannot
//     influence these fields by any means short of holding the credential.
//   - **Asserted** — the caller *claimed* this. Free-form, unauthenticated,
//     and stored verbatim.
//
// Blurring the two is how audit trails become fiction. A jailbroken AI-agent
// can assert anything it likes; it cannot forge the verified fields. That does
// not make the asserted lane worthless — for an honest orchestrator it is the
// join key back to the harness's own session logs, where the literal
// instruction lives. The prompt never crosses the MCP boundary; only tool
// calls do, so the asserted lane is the only thread back to intent.
//
// **The asserted lane is never an authorization input.** Nothing in Policy,
// the Authorizer, the blast cap, or the Freeze may read it. It is recorded and
// nothing else, and TestAssertedLaneIsNotAnAuthorizationInput pins that the
// authz path cannot see it.
type Attribution struct {
	Verified Verified
	Asserted Asserted
}

// Verified is the lane the Relay established itself, at the authentication
// boundary. Every field here is a fact about a credential the Relay checked.
type Verified struct {
	// AccountID is the acting Account's stable identifier — the join key that
	// survives a rename, which a name-only trail does not.
	AccountID string

	// AccountName is the Account's name as it read at the time of the action.
	AccountName string

	// Role is the authority the Account held **at that moment**, captured
	// rather than looked up later: "what could this Account do when it did
	// this" is unanswerable from a mutable row read months afterwards.
	Role string

	// TokenID is the public identifier of the credential presented — never the
	// secret, never its hash. It answers "which of this Account's five tokens
	// was used", which is what turns "revoke the compromised one" into a
	// targeted act rather than a guess.
	//
	// Empty when the action did not come through a token boundary (a local
	// signal on the Relay host, e.g. the Freeze lever), and for an OAuth
	// session, which presents no API Token at all.
	TokenID string

	// Source is WHERE the identity acted from: the peer address the Relay
	// read off the connection.
	//
	// Verified rather than asserted because the Relay observes it directly. A
	// value taken from a proxy header would be a claim and would belong in the
	// other lane; nothing populates this field from a header.
	//
	// Empty for a record written outside a network boundary — a local signal
	// on the Relay host, e.g. the Freeze lever.
	//
	// Required by docs/design/console/12-login.md: a sign-in trail without a
	// source cannot tell a brute force from a forgetful operator.
	Source string

	// Method is HOW the identity was established: "api_token" or "oauth"
	// (ADR-0024). Empty for a record written outside an authentication boundary.
	//
	// Recorded because the two call for different incident responses: a
	// compromised static credential is revoked here, while a compromised IdP
	// account is dealt with at the IdP and only then reflected here. A trail
	// that cannot tell them apart cannot tell you which lever to pull.
	Method string
}

// Asserted is the lane the caller supplied. Every field is caller-claimed,
// bounded, and stored verbatim.
type Asserted struct {
	// OnBehalfOf is a free-form user or team the caller claims to be acting
	// for ("ops-team", "mike"). Deliberately free-form and deliberately
	// untrusted: Relay never grows a native org chart, and federating real
	// groups from an IdP is the named later direction. Cheap, and honest about
	// its trust level.
	OnBehalfOf string

	// Traceparent is the W3C trace context header, if the caller sent one. It
	// makes a dispatch joinable to the caller's own distributed trace.
	//
	// Bounded and character-checked, but deliberately **not** parsed against
	// the W3C grammar: a future traceparent version must not start failing
	// here, and this field's value is as a join key, not as something the
	// Relay reasons about.
	Traceparent string

	// SessionRef is the caller's own session identifier — the AI-agent's
	// conversation or run id. The join key back to where the literal
	// instruction lives.
	SessionRef string

	// ChangeRef is a ticket, change request, or PR reference the caller
	// associates with the action.
	ChangeRef string
}

// IsZero reports whether the caller asserted nothing.
func (a Asserted) IsZero() bool {
	return a == Asserted{}
}

// MaxAssertedFieldBytes bounds every asserted field.
//
// Callers must not be able to size an audit record (the
// unbounded-deny-reason lesson): an unbounded field on a write-amplified,
// append-only table is a storage-exhaustion primitive handed to the least
// trusted input in the system. 256 bytes is far above any legitimate team
// name, session id, ticket ref, or traceparent (the W3C header is 55
// characters) and far below anything that matters at volume.
const MaxAssertedFieldBytes = 256

// ErrAssertedFieldTooLong is returned when an asserted field exceeds
// MaxAssertedFieldBytes.
var ErrAssertedFieldTooLong = errors.New("audit: asserted attribution field too long")

// ErrAssertedFieldInvalid is returned when an asserted field contains
// characters that have no business in an audit record.
var ErrAssertedFieldInvalid = errors.New("audit: asserted attribution field contains control characters")

// ValidateAsserted checks every asserted field against the bound and the
// character rule, returning a named error rather than silently fixing it.
//
// **Refuse, don't truncate.** A truncated join key joins to nothing, so
// silently shortening one produces an audit record that looks complete and
// isn't — worse than the caller being told to fix their header. The caller
// controls these values entirely and the fix is trivial.
//
// The character rule is the security-relevant half: a newline or a carriage
// return in an audit field is a log-forging vector, letting a caller inject
// what looks like a second record into any line-oriented view of the trail.
// Control characters more broadly can corrupt a terminal rendering the trail
// during an incident, which is exactly when it must be readable.
func ValidateAsserted(a Asserted) error {
	for _, f := range []struct{ name, value string }{
		{"on_behalf_of", a.OnBehalfOf},
		{"traceparent", a.Traceparent},
		{"session_ref", a.SessionRef},
		{"change_ref", a.ChangeRef},
	} {
		if len(f.value) > MaxAssertedFieldBytes {
			return fmt.Errorf("%w: %s is %d bytes, max %d",
				ErrAssertedFieldTooLong, f.name, len(f.value), MaxAssertedFieldBytes)
		}
		if i := strings.IndexFunc(f.value, isControl); i >= 0 {
			return fmt.Errorf("%w: %s", ErrAssertedFieldInvalid, f.name)
		}
	}
	return nil
}

// isControl reports whether r is a C0/C1 control character or DEL. Everything
// else — including any printable Unicode — is allowed: a team name may
// legitimately be non-ASCII, and the concern here is control characters, not
// alphabet.
func isControl(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)
}
