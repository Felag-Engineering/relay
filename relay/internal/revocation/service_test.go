package revocation_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
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

// recorder is a test double for revocation.RevocationRecorder: it records
// every node_id it was called with, in call order, and returns failOn[nodeID]
// when set.
type recorder struct {
	mu     sync.Mutex
	got    []string
	failOn map[string]error
}

func (r *recorder) record(nodeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, nodeID)
	return r.failOn[nodeID]
}

// contains reports whether nodeID is anywhere in r.got.
func (r *recorder) contains(nodeID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range r.got {
		if n == nodeID {
			return true
		}
	}
	return false
}

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

// TestService_RevokeToken_RecordsEveryCascadedNode covers both the cascade's
// pre-existing denylist/teardown behavior and #557's recording requirement:
// every Node enrolled by the revoked token is recorded exactly once, a Node
// enrolled by a different token is untouched, and a Node already revoked
// before the cascade reaches it (node-d) gets no second record — the
// IsRevoked skip must still hold (#545/#487's causative-record rule).
func TestService_RevokeToken_RecordsEveryCascadedNode(t *testing.T) {
	svc, d, c, reg, tokenSvc := newServiceFixture(t)
	ctx := context.Background()

	// Create a token so RevokeToken can mark it revoked in the store.
	tok, plaintext, err := tokenSvc.Create(ctx, []string{"relay:env=test"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}
	tokenID := tok.ID

	// Two Nodes enrolled by tokenID; one enrolled by a different token; one
	// enrolled by tokenID but already revoked before the cascade runs.
	reg.Upsert(registry.Report{NodeID: "node-a", EnrollingTokenID: tokenID})     //nolint:errcheck
	reg.Upsert(registry.Report{NodeID: "node-b", EnrollingTokenID: tokenID})     //nolint:errcheck
	reg.Upsert(registry.Report{NodeID: "node-c", EnrollingTokenID: "other-tok"}) //nolint:errcheck
	reg.Upsert(registry.Report{NodeID: "node-d", EnrollingTokenID: tokenID})     //nolint:errcheck
	svc.RevokeNode("node-d")

	// Track a live stream for node-a.
	connCtx, release := c.Track(ctx, "node-a")
	defer release()

	rec := &recorder{}
	if err := svc.RevokeToken(ctx, tokenID, rec.record); err != nil {
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

	// The recorder must have been called for exactly node-a and node-b, in
	// either order, and NOT for node-c (different token) or node-d (already
	// revoked — the IsRevoked skip must suppress a second record).
	if len(rec.got) != 2 {
		t.Fatalf("recorder calls = %v, want exactly 2", rec.got)
	}
	if !rec.contains("node-a") || !rec.contains("node-b") {
		t.Errorf("recorder calls = %v, want {node-a, node-b}", rec.got)
	}
	if rec.contains("node-c") {
		t.Errorf("recorder was called for node-c, want it untouched (different token)")
	}
	if rec.contains("node-d") {
		t.Errorf("recorder was called for node-d, want no second record for an already-revoked Node")
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

	rec := &recorder{}
	if err := svc.RevokeToken(ctx, "ghost-token", rec.record); err != nil {
		t.Fatalf("RevokeToken with unknown token should not error, got %v", err)
	}
	if !d.IsRevoked("node-x") {
		t.Error("node-x should be denylisted despite ghost token being unknown")
	}
}

// TestService_RevokeToken_RecordsNodeFoundOnRescan asserts that a Node whose
// registry Upsert lands AFTER the first List() snapshot is both denylisted
// AND recorded by the re-scan.
//
// This covers the TOCTOU window: a daemon passes Validate just before the
// token-revoke barrier and writes its registry entry during or after the
// first scan. The bounded re-scan in RevokeToken must denylist AND record it
// — this reddens if recording is ever hoisted out of the pass loop to run
// only against the first List() snapshot.
func TestService_RevokeToken_RecordsNodeFoundOnRescan(t *testing.T) {
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

	rec := &recorder{}
	if err := svc.RevokeToken(context.Background(), "tok-abc", rec.record); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if !d.IsRevoked("node-late") {
		t.Error("node-late should be denylisted even though it appeared after the first scan")
	}
	if len(rec.got) != 1 || rec.got[0] != "node-late" {
		t.Errorf("recorder calls = %v, want exactly [node-late]", rec.got)
	}
}

// TestService_RevokeToken_RecordFailureDoesNotStopTheCascade covers the
// failure posture that deliberately inverts #487's: when the recorder fails
// mid-cascade, RevokeToken must still denylist EVERY matching Node —
// including the one whose record failed — record every one of them (the
// failure is noted, not swallowed), and report the shortfall via
// ErrCascadeNotRecorded rather than aborting or silently succeeding.
func TestService_RevokeToken_RecordFailureDoesNotStopTheCascade(t *testing.T) {
	svc, d, _, reg, tokenSvc := newServiceFixture(t)
	ctx := context.Background()

	tok, _, err := tokenSvc.Create(ctx, []string{"relay:env=test"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}
	tokenID := tok.ID

	const nodeCount = 20
	nodeIDs := make([]string, nodeCount)
	for i := range nodeIDs {
		nodeIDs[i] = fmt.Sprintf("node-%02d", i+1)
		if _, err := reg.Upsert(registry.Report{NodeID: nodeIDs[i], EnrollingTokenID: tokenID}); err != nil {
			t.Fatalf("Upsert(%s): %v", nodeIDs[i], err)
		}
	}

	rec := &recorder{failOn: map[string]error{"node-07": errors.New("audit store unavailable")}}
	err = svc.RevokeToken(ctx, tokenID, rec.record)
	if !errors.Is(err, revocation.ErrCascadeNotRecorded) {
		t.Fatalf("RevokeToken error = %v, want errors.Is(err, ErrCascadeNotRecorded)", err)
	}

	for _, id := range nodeIDs {
		if !d.IsRevoked(id) {
			t.Errorf("%s should be denylisted even though its record failed", id)
		}
		if !rec.contains(id) {
			t.Errorf("recorder should have been called for %s", id)
		}
	}
}

// TestService_RevokeToken_NilRecorderRevokesNothing covers the structural
// guarantee that a nil recorder is refused, not treated as "skip recording":
// no Node may be denylisted and the token must not even be revoked in the
// store.
func TestService_RevokeToken_NilRecorderRevokesNothing(t *testing.T) {
	svc, d, _, reg, tokenSvc := newServiceFixture(t)
	ctx := context.Background()

	tok, plaintext, err := tokenSvc.Create(ctx, []string{"relay:env=test"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}
	reg.Upsert(registry.Report{NodeID: "node-a", EnrollingTokenID: tok.ID}) //nolint:errcheck

	err = svc.RevokeToken(ctx, tok.ID, nil)
	if !errors.Is(err, revocation.ErrRecorderRequired) {
		t.Fatalf("RevokeToken(nil recorder) error = %v, want errors.Is(err, ErrRecorderRequired)", err)
	}
	if d.IsRevoked("node-a") {
		t.Error("node-a should not be denylisted when the recorder is nil")
	}

	// The token itself must still Validate — RevokeToken must return before
	// touching the token store.
	if _, validateErr := tokenSvc.Validate(ctx, plaintext); validateErr != nil {
		t.Errorf("token should still Validate after a nil-recorder RevokeToken call, got %v", validateErr)
	}
}
