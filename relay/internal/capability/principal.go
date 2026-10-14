package capability

import "fmt"

// Principal is the **acting Account**, in the capability layer's proto-free
// form: who is asking the layer to act, threaded through the pipeline to the
// Authorizer and recorded on every audit entry.
//
// Since v0.3.0 this is no longer a pre-Account placeholder — it is a
// projection of a stored Account (internal/accounts). The projection is built
// at the authentication boundary (internal/controlplane), NOT here: the
// capability package's import allowlist is deliberately narrow (jobs +
// registry; see TestCapabilityImportsOnlyRegistryAndJobs), and #295 is not the
// change that should widen it. Holding a narrow value rather than the full
// Account also means an audit record captures who acted with what authority
// **at that moment**, not a pointer to a mutable row whose role may since have
// changed.
//
// AccountID is carried alongside Account (the name) so attribution survives a
// rename: the name is what a human reads, the ID is what joins.
//
// Naming: GLOSSARY.md's glossary prefers "Account" over "principal" in prose,
// and this type's *meaning* is now exactly an Account. The identifier keeps its
// name for the moment because renaming it touches every surface at once; the
// glossary entry records that the capability layer's `Principal` **is** the
// acting Account, so the two cannot drift in meaning even while the spelling
// lags.
type Principal struct {
	// AccountID is the stored Account's stable identifier; empty only for
	// pre-Account test fixtures.
	AccountID string
	// Account is the Account's unique name, as it appears in audit.
	Account string
	// Role is the Account's role at the time it authenticated.
	Role string

	// Kind is whether this Account is a human operator or a machine driver —
	// accounts.Kind's values, carried as a plain string so this package keeps
	// its narrow import allowlist (jobs + registry + approval).
	//
	// Authority is still the Role — a machine Account with the admin role has
	// admin's powers — but Kind IS an authorization input for the specific
	// decisions Role alone cannot answer:
	//
	//   - EngageFreeze requires a HUMAN Account (ADR-0013 amendment): a
	//     machine Account at operator halting the fleet is an AI-agent
	//     switching off its own overseers.
	//   - CancelJob's machine-Account scoping (#614, owner decision
	//     2026-09-17, execution.md §Cancellation): a human Account may cancel
	//     any Job, but a machine Account may cancel only a Job whose recorded
	//     requester is itself.
	//   - ADR-0027's confirmation ladder, whose rung 2 (self-confirmation) is
	//     human-requesters-only, because an AI-agent confirming its own proposal
	//     is the same actor answering twice.
	//
	// The empty value means "unknown", and every check written against this
	// field must treat unknown as MACHINE — the restrictive answer for all
	// three decisions above. That is why there is no PrincipalKind type with
	// a friendly zero value: the restrictive answer has to be the one you get
	// by forgetting to set it.
	Kind string

	// AuthMethod is HOW this identity was established: a static API Token or
	// an OAuth session. It is a verified fact — the Relay knows which
	// of its own paths accepted the credential — and it is what makes the two
	// session kinds distinguishable in audit, which #299 requires.
	//
	// Not an authorization input: authority is the Account's role, whichever
	// way the caller authenticated. In particular an OAuth session does NOT
	// make a call human-grade for approval gating — a human authorized the
	// session, not each model-generated call (ADR-0024).
	AuthMethod AuthMethod

	// Source is the peer address the request arrived from, as the
	// authentication boundary read it off the connection. It travels into the
	// audit trail's verified lane.
	//
	// Empty for a Principal built outside a network boundary (a local signal
	// on the Relay host, a fixture). Never populated from a caller-supplied
	// header: a claimed source is an assertion, and this is not the assertion
	// lane.
	Source string

	// TokenID is the public identifier of the API Token presented, empty when
	// the action did not arrive through a token boundary (a local signal on
	// the Relay host, or a test fixture).
	//
	// It is part of the *verified* lane: which of an Account's credentials
	// acted is a fact the Relay established, and it is what turns "revoke the
	// compromised one" into a targeted act rather than revoking all of them
	// and hoping. Never the secret and never its hash — the ID is safe to log.
	TokenID string
}

// AuthMethod names how an identity was established.
type AuthMethod string

const (
	// AuthMethodUnspecified is the zero value: a Principal built outside an
	// authentication boundary (a local signal on the Relay host, a fixture).
	AuthMethodUnspecified AuthMethod = ""

	// AuthMethodAPIToken is a static per-Account API Token.
	AuthMethodAPIToken AuthMethod = "api_token"

	// AuthMethodOAuth is a session authorized through the external IdP.
	AuthMethodOAuth AuthMethod = "oauth"

	// AuthMethodConsoleSession is a human's browser session in the Admin
	// Console (ADR-0009).
	//
	// Distinguishable from the other two in audit on purpose: the three call
	// for different incident responses. A compromised API Token is revoked
	// here, a compromised IdP account is dealt with at the IdP, and a
	// compromised Console session is ended by disabling the Account — which
	// cuts sessions already in flight, not merely the next sign-in.
	AuthMethodConsoleSession AuthMethod = "console_session"
)

// PrincipalKindHuman is the one Kind value that means "a person is behind this
// Account". It mirrors accounts.KindHuman's wire value; the mirror is asserted
// by a test in package accounts' consumer rather than by an import, for the
// import-allowlist reason on Principal.Kind.
//
// There is deliberately no PrincipalKindMachine constant to compare against.
// Every check must be written as `== PrincipalKindHuman`, so an unset, unknown,
// or future kind falls on the restrictive side by construction instead of by
// remembering to enumerate it.
const PrincipalKindHuman = "human"

// Human reports whether p is a human Account. Unknown kinds are not human.
func (p Principal) Human() bool { return p.Kind == PrincipalKindHuman }

// Attribution returns the string form of p recorded in audit.Record.Principal.
func (p Principal) Attribution() string {
	return p.String()
}

// String returns "account:role", or bare account if Role is unset.
func (p Principal) String() string {
	if p.Role == "" {
		return p.Account
	}
	return fmt.Sprintf("%s:%s", p.Account, p.Role)
}
