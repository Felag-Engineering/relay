package capability

import "fmt"

// Principal is the **acting Account**, in the capability layer's proto-free
// form: who is asking the layer to act, threaded through the pipeline to the
// Authorizer and recorded on every audit entry.
//
// Since v0.3.0 (#295) this is no longer a pre-Account placeholder — it is a
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
// Naming: CONTEXT.md's glossary prefers "Account" over "principal" in prose,
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
}

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
