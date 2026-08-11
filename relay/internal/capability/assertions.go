package capability

import "context"

// Assertions is the caller-claimed half of the attribution triple
// (docs/design/approval-and-attribution.md, #300), carried through the
// capability pipeline so the audit sink can record it.
//
// It mirrors internal/audit.Asserted rather than importing it, for the same
// reason this package mirrors everything else: capability's import allowlist
// is deliberately narrow (registry + jobs), and a domain type crossing into it
// is how that boundary erodes. internal/auditsink owns the mapping.
//
// **Nothing may ever read these fields to make a decision.** They are recorded
// and nothing else. A field a caller controls must never be able to widen what
// a caller may do.
//
// That is enforced, not merely intended: Service.Run and Service.Plan strip
// assertions from the context before calling the Authorizer (see
// withoutAssertions), so an Authorizer implementation cannot reach them even
// though it is handed a context. The blast cap counts Nodes and takes no
// context at all, and Policy is evaluated on the Node, which never sees them.
// TestAssertionsAreNotAnAuthorizationInput pins the Authorizer half.
type Assertions struct {
	OnBehalfOf  string
	Traceparent string
	SessionRef  string
	ChangeRef   string
}

// IsZero reports whether the caller asserted nothing.
func (a Assertions) IsZero() bool { return a == Assertions{} }

// assertionsContextKey is unexported so no other package can collide with or
// forge this key (the standard Go context-key idiom, matching
// controlplane.principalContextKey).
type assertionsContextKey struct{}

// WithAssertions attaches caller-asserted attribution to ctx.
//
// Context-carried rather than threaded through every signature: assertions are
// inert metadata that must reach the audit sink from wherever a request
// entered, and adding a parameter to Run/Plan/CancelJob would put a
// caller-controlled value on the same footing as the Selector and the Action,
// which are decision inputs. A surface that forgets to attach them records no
// assertion — which is the honest outcome, since nothing was asserted through
// a channel the Relay saw.
//
// Only an authentication boundary should call this: the values are meant to
// come off a request the Relay just authenticated, already bounded and
// validated there.
func WithAssertions(ctx context.Context, a Assertions) context.Context {
	return context.WithValue(ctx, assertionsContextKey{}, a)
}

// AssertionsFromContext returns the assertions attached to ctx, or the zero
// value if none were.
func AssertionsFromContext(ctx context.Context) Assertions {
	a, _ := ctx.Value(assertionsContextKey{}).(Assertions)
	return a
}

// withoutAssertions returns ctx with any caller-asserted attribution masked.
//
// Used on the authorization call, so that a value the caller controls is not
// merely *unused* by today's Authorizer but *unreachable* by any future one.
// Documenting "don't read this" would have been the cheaper option and the
// weaker one — the first Authorizer to want a team name for a Grant lookup
// would find it sitting right there in the context.
func withoutAssertions(ctx context.Context) context.Context {
	return context.WithValue(ctx, assertionsContextKey{}, Assertions{})
}
