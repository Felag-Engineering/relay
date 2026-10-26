package jobs

import (
	"context"
	"sync"
)

// A Settlement is one Dispatch caller's claim on the result a Conduit
// delivers to it. A Conduit returns a Task's Result before the caller has
// persisted it, and in that window the Relay may resolve the Task as
// node-offline. A Conduit that delivers a result to a caller carrying a
// Settlement holds that result protected from the offline resolution until the
// caller settles: only the caller the result was delivered to can end the
// protection, and a caller that received nothing ends none.
//
// It travels as a context value, like the send guard, so the domain-typed
// Conduit port and every Conduit that ignores it stay unchanged.
type Settlement struct {
	mu       sync.Mutex
	settled  bool
	releases []func()
}

type settlementKey struct{}

// WithSettlement returns ctx carrying a new Settlement, and that Settlement.
// The caller passes the returned ctx to Dispatch and calls Settle once the
// result Dispatch returned is persisted, or will never be.
func WithSettlement(ctx context.Context) (context.Context, *Settlement) {
	s := &Settlement{}
	return context.WithValue(ctx, settlementKey{}, s), s
}

// SettlementFrom returns the Settlement in ctx, or nil.
func SettlementFrom(ctx context.Context) *Settlement {
	s, _ := ctx.Value(settlementKey{}).(*Settlement)
	return s
}

// Hold records release as the end of a protection the Conduit gives a result
// it delivered under s. It reports false, recording nothing, when s has
// already settled: the caller has finished, so there is nothing to protect.
// Hold never calls release, so a Conduit may call it holding its own lock.
func (s *Settlement) Hold(release func()) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settled {
		return false
	}
	s.releases = append(s.releases, release)
	return true
}

// Settle ends every protection held under s, once. It is safe to call on a nil
// Settlement and more than once.
func (s *Settlement) Settle() {
	if s == nil {
		return
	}
	s.mu.Lock()
	releases := s.releases
	s.releases = nil
	s.settled = true
	s.mu.Unlock()
	for _, release := range releases {
		release()
	}
}
