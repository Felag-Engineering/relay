package jobs

import (
	"context"
	"errors"
)

// A send guard lets whoever owns a Task's dispatch state withhold the wire
// send at the last moment, from inside a domain-typed Conduit (#943). The
// owner is capability's jobEngine for a live Job, or the dispatch Reconciler
// for a resend.
//
// The guard travels as a context value rather than a parameter because
// capability.Conduit.Dispatch(ctx, nodeID, task) is a domain-typed port:
// adding a parameter would change the port, every Conduit fake, the dev
// harness, and the Router's structural fit. Callers that set no guard keep
// today's behaviour unchanged.
//
// The guard is a predicate, not a decision the Conduit makes. The Conduit only
// asks it.

// ErrSendWithheld is returned by a Conduit whose caller's send guard reported
// that the send must not begin. A Conduit returns it ONLY if no part of the
// TaskRequest was handed to the Tunnel.
var ErrSendWithheld = errors.New("jobs: task send withheld: its sender's guard reported the send must not begin")

type sendGuardKey struct{}

// WithSendGuard returns ctx carrying withheld, a predicate a Conduit evaluates
// immediately before writing a Task to the Tunnel. A nil withheld returns ctx
// unchanged.
func WithSendGuard(ctx context.Context, withheld func() bool) context.Context {
	if withheld == nil {
		return ctx
	}
	return context.WithValue(ctx, sendGuardKey{}, withheld)
}

// SendWithheld reports whether the send guard in ctx says the send must not
// begin. With no guard it returns false.
func SendWithheld(ctx context.Context) bool {
	f, _ := ctx.Value(sendGuardKey{}).(func() bool)
	return f != nil && f()
}
