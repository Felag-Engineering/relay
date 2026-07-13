package revocation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/enroll"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/revocation"
)

// fakeLister is a test double for revocation.Registry. It returns a successive
// slice of Nodes on each call to List(); once all slices are exhausted it
// repeats the last one. SetRevoked is a no-op: these tests assert on the
// denylist, not on persisted registry state.
type fakeLister struct {
	calls   int
	perCall [][]registry.Node
}

func (f *fakeLister) List() []registry.Node {
	i := f.calls
	if i >= len(f.perCall) {
		i = len(f.perCall) - 1
	}
	f.calls++
	return f.perCall[i]
}

func (f *fakeLister) SetRevoked(string, time.Time) error { return nil }

// fakeTokenRevoker is a test double for revocation.TokenRevoker.
type fakeTokenRevoker struct{ err error }

func (f *fakeTokenRevoker) Revoke(_ context.Context, _ string) error { return f.err }

// newServiceFixture creates a Service wired to real InMemory implementations.
func newServiceFixture(t *testing.T) (
	svc *revocation.Service,
	d *revocation.Denylist,
	c *revocation.Connections,
	reg *registry.InMemory,
	tokenSvc *enroll.Service,
) {
	t.Helper()
	d = revocation.NewDenylist()
	c = revocation.NewConnections()
	reg = registry.NewInMemory()
	tokenSvc = enroll.NewService(enroll.NewMemoryRepository())
	svc = revocation.NewService(d, c, reg, tokenSvc)
	return svc, d, c, reg, tokenSvc
}

func TestService_RevokeNode_DenylistAndDisconnect(t *testing.T) {
	svc, d, c, _, _ := newServiceFixture(t)

	// Track a live connection before revoking.
	ctx, release := c.Track(context.Background(), "node-1")
	defer release()

	svc.RevokeNode("node-1")

	if !d.IsRevoked("node-1") {
		t.Error("node-1 should be in the denylist after RevokeNode")
	}
	select {
	case <-ctx.Done():
		// expected: live stream was torn down
	case <-time.After(time.Second):
		t.Error("live connection should have been canceled by RevokeNode")
	}
}

// TestService_RevokeNode_PersistsToRegistry asserts RevokeNode writes the
// revocation through to the registry (the authority), not just the in-memory
// denylist — this is what makes revocation survive a Relay restart (issue #133).
func TestService_RevokeNode_PersistsToRegistry(t *testing.T) {
	svc, d, _, reg, _ := newServiceFixture(t)

	if _, err := reg.Upsert(registry.Report{NodeID: "node-1", EnrollingTokenID: "tok-1"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	svc.RevokeNode("node-1")

	if !d.IsRevoked("node-1") {
		t.Error("node-1 should be in the denylist after RevokeNode")
	}
	n, ok := reg.Get("node-1")
	if !ok {
		t.Fatal("node-1 missing from registry after RevokeNode")
	}
	if n.RevokedAt.IsZero() {
		t.Error("RevokedAt should be persisted (non-zero) after RevokeNode")
	}
}

func TestService_RevokeToken_Cascade(t *testing.T) {
	svc, d, c, reg, tokenSvc := newServiceFixture(t)
	ctx := context.Background()

	// Create a token so RevokeToken can mark it revoked in the store.
	tok, plaintext, err := tokenSvc.Create(ctx, []string{"relay:env=test"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}
	tokenID := tok.ID

	// Two Nodes enrolled by tokenID; one enrolled by a different token.
	reg.Upsert(registry.Report{NodeID: "node-a", EnrollingTokenID: tokenID})     //nolint:errcheck
	reg.Upsert(registry.Report{NodeID: "node-b", EnrollingTokenID: tokenID})     //nolint:errcheck
	reg.Upsert(registry.Report{NodeID: "node-c", EnrollingTokenID: "other-tok"}) //nolint:errcheck

	// Track a live stream for node-a.
	connCtx, release := c.Track(ctx, "node-a")
	defer release()

	if err := svc.RevokeToken(ctx, tokenID); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	// Every Node enrolled by tokenID must be denylisted.
	if !d.IsRevoked("node-a") {
		t.Error("node-a should be denylisted after token cascade")
	}
	if !d.IsRevoked("node-b") {
		t.Error("node-b should be denylisted after token cascade")
	}
	// Non-matching Node must not be affected.
	if d.IsRevoked("node-c") {
		t.Error("node-c should not be denylisted (different token)")
	}

	// The live stream for node-a must have been torn down.
	select {
	case <-connCtx.Done():
		// expected
	case <-time.After(time.Second):
		t.Error("node-a's live connection should have been torn down by token cascade")
	}

	// The token itself must be dead: Validate now returns ErrRevoked.
	_, validateErr := tokenSvc.Validate(ctx, plaintext)
	if !errors.Is(validateErr, enroll.ErrRevoked) {
		t.Errorf("expected ErrRevoked after token revocation, got %v", validateErr)
	}
}

// TestService_RevokeToken_ToleratesUnknownToken verifies that RevokeToken does
// not error when the token_id is unknown in the store, and still denylists
// matching Nodes (cascade remains valid; the token may have been deleted).
func TestService_RevokeToken_ToleratesUnknownToken(t *testing.T) {
	svc, d, _, reg, _ := newServiceFixture(t)
	ctx := context.Background()

	reg.Upsert(registry.Report{NodeID: "node-x", EnrollingTokenID: "ghost-token"}) //nolint:errcheck

	if err := svc.RevokeToken(ctx, "ghost-token"); err != nil {
		t.Fatalf("RevokeToken with unknown token should not error, got %v", err)
	}
	if !d.IsRevoked("node-x") {
		t.Error("node-x should be denylisted despite ghost token being unknown")
	}
}

// TestService_RevokeToken_CatchesLateUpsert asserts that a Node whose registry
// Upsert lands AFTER the first List() snapshot is still caught by the re-scan.
//
// This covers the TOCTOU window: a daemon passes Validate just before the
// token-revoke barrier and writes its registry entry during or after the first
// scan. The bounded re-scan in RevokeToken must denylist it.
func TestService_RevokeToken_CatchesLateUpsert(t *testing.T) {
	d := revocation.NewDenylist()
	c := revocation.NewConnections()

	// The first List() call returns nothing (node hasn't been upserted yet).
	// All subsequent calls return the late Node, simulating a registry Upsert
	// that raced past the first snapshot.
	lister := &fakeLister{
		perCall: [][]registry.Node{
			{}, // first List(): node not yet visible
			{{NodeID: "node-late", EnrollingTokenID: "tok-abc"}},
		},
	}
	svc := revocation.NewService(d, c, lister, &fakeTokenRevoker{})

	if err := svc.RevokeToken(context.Background(), "tok-abc"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if !d.IsRevoked("node-late") {
		t.Error("node-late should be denylisted even though it appeared after the first scan")
	}
}
