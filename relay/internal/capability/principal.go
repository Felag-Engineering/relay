package capability

import "fmt"

// Principal identifies who is asking the capability layer to act, threaded
// through the pipeline to the Authorizer and recorded on every audit entry.
//
// Naming note: CONTEXT.md's Account glossary entry lists "principal" under
// _Avoid_ ("say machine Account"). v0.0.5 has no Account yet — the seeded
// credential arrives in v0.0.6 and full Accounts in v0.3.0 (ADR-0010) — so
// Principal is a deliberately thin, pre-Account placeholder rather than a
// second name for the same concept. It is expected to be replaced by (or
// rewritten in terms of) Account once that lands; flagged here rather than
// silently drifting from the glossary.
type Principal struct {
	Account string
	Role    string
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
