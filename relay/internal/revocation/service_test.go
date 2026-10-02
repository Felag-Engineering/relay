package revocation_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/enroll"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/revocation"
)

// silenceLogs swaps slog's default logger for one that discards everything,
// restoring the previous default on cleanup. The cascade's RevokeNode and
// flush both log per Node (slog.Info/slog.Error), so a test that drives
// ~1,005 Nodes through it would otherwise flood test output with no bearing
// on what the test asserts. revocation.Service takes no logger of its own —
// it calls the log/slog package functions directly — so this is the only way
// to quiet it without a production change outside this plan.
func silenceLogs(t *testing.T) {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
}

// fakeLister is a test double for revocation.Registry. It returns a successive
// slice of Nodes on each call to ListChecked(); once all slices are exhausted
// it repeats the last one. errs, when set, is the error returned alongside
// the slice for the call at that index (nil past its end), modelling a
// registry read that failed or came back short. SetRevoked is a no-op: these
// tests assert on the denylist, not on persisted registry state.
//
// mu guards calls, the double's OWN bookkeeping — it says nothing about the
// product under test. Without it, two cascades List()-ing this double at
// once (the AC3 concurrency test) would report a data race in the double
// itself under test-relay-race, not in revocation.Service. perCall is
// read-only after construction, so it needs no lock.
type fakeLister struct {
	mu      sync.Mutex
	calls   int
	perCall [][]registry.Node
	errs    []error
}

func (f *fakeLister) ListChecked() ([]registry.Node, error) {
	f.mu.Lock()
	call := f.calls
	i := call
	if i >= len(f.perCall) {
		i = len(f.perCall) - 1
	}
	f.calls++
	f.mu.Unlock()
	var err error
	if call < len(f.errs) {
		err = f.errs[call]
	}
	return f.perCall[i], err
}

func (f *fakeLister) SetRevoked(string, time.Time) error { return nil }

// SetRevokedAll is a no-op for the same reason SetRevoked is: these tests
// assert on the denylist, not on persisted registry state.
func (f *fakeLister) SetRevokedAll([]string, time.Time) ([]string, error) { return nil, nil }

// fakeTokenRevoker is a test double for revocation.TokenRevoker.
type fakeTokenRevoker struct{ err error }

func (f *fakeTokenRevoker) Revoke(_ context.Context, _ string) error { return f.err }

// recorder is a test double for revocation.RevocationRecorder: it records
// every node_id it was called with (across every call, in call order), the
// calls themselves (one entry per call, in call order), and returns
// failCalls[call index] for the call at that 1-based index when set — failure
// is per CALL now, since a call covers a chunk rather than one Node.
type recorder struct {
	mu        sync.Mutex
	calls     [][]string
	got       []string
	failCalls map[int]error

	// revokedAtRecordTime, when set, is consulted INSIDE record() to observe
	// whether the Node was already denylisted at the moment the record was
	// written. It is the only way to see the record-BEFORE-revoke ordering the
	// cascade's comment calls load-bearing: post-hoc assertions cannot tell the
	// two orders apart, so swapping those two calls would otherwise be a silent
	// refactor. A code review pointed out the gap.
	revokedAtRecordTime func(nodeID string) bool
	recordedAfterRevoke []string

	// hook, when set, runs inside record with r.mu NOT held, so a test can
	// block one record call mid-flight (waiting on its own channel) without
	// blocking anything else that calls contains on this same recorder from
	// another goroutine.
	hook func(nodeIDs []string)
}

func (r *recorder) record(nodeIDs []string) error {
	if r.hook != nil {
		r.hook(nodeIDs)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	callIndex := len(r.calls) + 1
	r.calls = append(r.calls, append([]string(nil), nodeIDs...))
	for _, nodeID := range nodeIDs {
		r.got = append(r.got, nodeID)
		if r.revokedAtRecordTime != nil && r.revokedAtRecordTime(nodeID) {
			r.recordedAfterRevoke = append(r.recordedAfterRevoke, nodeID)
		}
	}
	return r.failCalls[callIndex]
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

// blockingRegistry is a test double for revocation.Registry over a real
// registry.InMemory: List delegates unchanged, but SetRevokedAll for a chunk
// containing one configured node id blocks until release is closed before
// delegating too.
//
// This is what makes the record-committed-but-registry-write-in-flight
// window inside revokeChunk reachable deterministically: without it, that
// window is only microseconds wide and a test racing it would flake instead
// of reliably exercising it. The cascade now reaches the registry once per
// chunk (#607), so the reachable window is "a chunk whose record has
// committed and whose registry write is in flight", not a per-Node
// SetRevoked mid-loop — the SetRevoked override this double used to carry is
// gone because nothing in this suite reaches it anymore: blockingRegistry is
// constructed in exactly one place (the cascade test below), and the cascade
// never calls SetRevoked. The embedded *registry.InMemory still supplies
// SetRevoked — which is what the concurrent RevokeNodeRecorded(node-b) in
// that test reaches — so the type still satisfies revocation.Registry
// without an explicit override.
type blockingRegistry struct {
	*registry.InMemory

	blockID    string
	release    chan struct{}
	entered    chan struct{}
	enteredOne sync.Once
}

// newBlockingRegistry wraps reg, blocking SetRevokedAll(nodeIDs, ...) until
// release is closed, when blockID is among nodeIDs. entered is closed the
// instant that call is made, so a test can wait for "inside the block"
// before proceeding rather than racing it with a sleep.
func newBlockingRegistry(reg *registry.InMemory, blockID string, release chan struct{}) *blockingRegistry {
	return &blockingRegistry{
		InMemory: reg,
		blockID:  blockID,
		release:  release,
		entered:  make(chan struct{}),
	}
}

func (b *blockingRegistry) SetRevokedAll(nodeIDs []string, at time.Time) ([]string, error) {
	if slices.Contains(nodeIDs, b.blockID) {
		// A second SetRevokedAll call containing blockID cannot happen today
		// — but this double should not itself panic on a double-close if
		// that ever changes.
		b.enteredOne.Do(func() { close(b.entered) })
		<-b.release
	}
	// Block BEFORE delegating, exactly as the old SetRevoked override did, so
	// no InMemory lock is held while parked.
	return b.InMemory.SetRevokedAll(nodeIDs, at)
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
// registry Upsert lands AFTER the first ListChecked() snapshot is both denylisted
// AND recorded by the re-scan.
//
// This covers the TOCTOU window: a daemon passes Validate just before the
// token-revoke barrier and writes its registry entry during or after the
// first scan. The bounded re-scan in RevokeToken must denylist AND record it
// — this reddens if recording is ever hoisted out of the pass loop to run
// only against the first ListChecked() snapshot.
func TestService_RevokeToken_RecordsNodeFoundOnRescan(t *testing.T) {
	d := revocation.NewDenylist()
	c := revocation.NewConnections()

	// The first ListChecked() call returns nothing (node hasn't been upserted yet).
	// All subsequent calls return the late Node, simulating a registry Upsert
	// that raced past the first snapshot.
	lister := &fakeLister{
		perCall: [][]registry.Node{
			{}, // first ListChecked(): node not yet visible
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

// TestService_RevokeToken_RegistryReadFailureFailsLoudly is G-E0's revocation
// half: a registry read that fails or comes back short must never let the
// cascade report success, because the Nodes it could not see are still
// trusted (invariant 6). The first pass reads cleanly; the re-scan reads one
// more matching Node but reports an error. Both Nodes that WERE read must be
// revoked (over-denying beats under-denying), and RevokeToken must return
// ErrCascadeIncomplete — and must NOT return ErrCascadeNotRecorded, which the
// Control API reads as "every Node was revoked".
func TestService_RevokeToken_RegistryReadFailureFailsLoudly(t *testing.T) {
	silenceLogs(t)
	d := revocation.NewDenylist()
	c := revocation.NewConnections()

	lister := &fakeLister{
		perCall: [][]registry.Node{
			{{NodeID: "node-a", EnrollingTokenID: "tok-abc"}},
			{
				{NodeID: "node-a", EnrollingTokenID: "tok-abc"},
				{NodeID: "node-b", EnrollingTokenID: "tok-abc"},
			},
		},
		errs: []error{nil, errors.New("store unavailable")},
	}
	svc := revocation.NewService(d, c, lister, &fakeTokenRevoker{})

	rec := &recorder{}
	err := svc.RevokeToken(context.Background(), "tok-abc", rec.record)
	if !errors.Is(err, revocation.ErrCascadeIncomplete) {
		t.Fatalf("RevokeToken error = %v, want errors.Is(err, ErrCascadeIncomplete)", err)
	}
	if errors.Is(err, revocation.ErrCascadeNotRecorded) {
		t.Errorf("RevokeToken error = %v must not claim ErrCascadeNotRecorded: that "+
			"tells the Control API every Node was revoked", err)
	}
	for _, id := range []string{"node-a", "node-b"} {
		if !d.IsRevoked(id) {
			t.Errorf("%s was read but not denylisted: a short read must still revoke what it saw", id)
		}
	}
	if lister.calls != 2 {
		t.Errorf("ListChecked calls = %d, want 2: the cascade must stop at the failed read", lister.calls)
	}
}

// TestService_RevokeToken_RecordFailureDoesNotStopTheCascade covers the
// failure posture that deliberately inverts #487's: when the recorder fails
// on a chunk, RevokeToken must still denylist EVERY matching Node —
// including every one in the failed chunk — record every one of them (the
// failure is noted, not swallowed), and report the shortfall via
// ErrCascadeNotRecorded rather than aborting or silently succeeding.
//
// N is sized to two full chunks plus a remainder (2*CascadeRecordChunk + 5),
// so there are exactly 3 recorder calls of sizes CascadeRecordChunk,
// CascadeRecordChunk, and 5. Failing the first and third call — unequal chunk
// sizes — makes "count calls", "count total", and "count only the first
// failure" mutations of the shortfall count all go red: only "sum the sizes
// of the failed calls" survives.
func TestService_RevokeToken_RecordFailureDoesNotStopTheCascade(t *testing.T) {
	silenceLogs(t)
	svc, d, _, reg, tokenSvc := newServiceFixture(t)
	ctx := context.Background()

	tok, _, err := tokenSvc.Create(ctx, []string{"relay:env=test"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}
	tokenID := tok.ID

	const nodeCount = 2*revocation.CascadeRecordChunk + 5
	nodeIDs := make([]string, nodeCount)
	for i := range nodeIDs {
		nodeIDs[i] = fmt.Sprintf("node-%05d", i+1)
		if _, err := reg.Upsert(registry.Report{NodeID: nodeIDs[i], EnrollingTokenID: tokenID}); err != nil {
			t.Fatalf("Upsert(%s): %v", nodeIDs[i], err)
		}
	}

	rec := &recorder{
		failCalls: map[int]error{
			1: errors.New("audit store unavailable"),
			3: errors.New("audit store unavailable"),
		},
		revokedAtRecordTime: d.IsRevoked,
	}
	err = svc.RevokeToken(ctx, tokenID, rec.record)
	if !errors.Is(err, revocation.ErrCascadeNotRecorded) {
		t.Fatalf("RevokeToken error = %v, want errors.Is(err, ErrCascadeNotRecorded)", err)
	}
	var shortfall *revocation.CascadeShortfall
	if !errors.As(err, &shortfall) {
		t.Fatalf("RevokeToken error = %v, want it to carry a *CascadeShortfall", err)
	}
	wantUnrecorded := revocation.CascadeRecordChunk + 5
	if shortfall.Unrecorded != wantUnrecorded {
		t.Errorf("shortfall.Unrecorded = %d, want exactly %d — the count an operator reads "+
			"to size the audit gap must be the number that actually failed", shortfall.Unrecorded, wantUnrecorded)
	}
	if shortfall.Total != nodeCount {
		t.Errorf("shortfall.Total = %d, want %d", shortfall.Total, nodeCount)
	}

	// The record is written BEFORE the revoke, which the cascade's comment calls
	// load-bearing: recording after would mean a crash between the two leaves a
	// Node revoked with no record -- the exact state this issue closes.
	if len(rec.recordedAfterRevoke) != 0 {
		t.Errorf("these Nodes were recorded AFTER being denylisted: %v — the cascade must "+
			"record first, so a crash between the two cannot lose the record", rec.recordedAfterRevoke)
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

// TestService_RevokeToken_RecordsInChunksNotPerNode is #563's core claim: an
// N-Node cascade calls the recorder in chunks of at most
// revocation.CascadeRecordChunk Nodes, not once per Node and not once for the
// whole cascade. It goes red if the loop reverts to one call per Node (too
// many calls) or to one unbounded call (one call covering all of N).
func TestService_RevokeToken_RecordsInChunksNotPerNode(t *testing.T) {
	silenceLogs(t)
	svc, d, _, reg, tokenSvc := newServiceFixture(t)
	ctx := context.Background()

	tok, _, err := tokenSvc.Create(ctx, []string{"relay:env=test"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}
	tokenID := tok.ID

	const nodeCount = 2*revocation.CascadeRecordChunk + 5
	nodeIDs := make([]string, nodeCount)
	for i := range nodeIDs {
		nodeIDs[i] = fmt.Sprintf("node-%05d", i+1)
		if _, err := reg.Upsert(registry.Report{NodeID: nodeIDs[i], EnrollingTokenID: tokenID}); err != nil {
			t.Fatalf("Upsert(%s): %v", nodeIDs[i], err)
		}
	}

	rec := &recorder{revokedAtRecordTime: d.IsRevoked}
	if err := svc.RevokeToken(ctx, tokenID, rec.record); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	if len(rec.calls) != 3 {
		t.Fatalf("recorder was called %d times, want exactly 3 (chunked calls)", len(rec.calls))
	}
	seen := make(map[string]int, nodeCount)
	for _, call := range rec.calls {
		if len(call) > revocation.CascadeRecordChunk {
			t.Errorf("recorder call had %d Nodes, want at most %d (cascadeRecordChunk)",
				len(call), revocation.CascadeRecordChunk)
		}
		for _, id := range call {
			seen[id]++
		}
	}
	if len(seen) != nodeCount {
		t.Fatalf("recorder calls covered %d distinct Nodes, want %d", len(seen), nodeCount)
	}
	for _, id := range nodeIDs {
		if seen[id] != 1 {
			t.Errorf("%s was recorded %d times across all calls, want exactly 1", id, seen[id])
		}
	}
	if len(rec.recordedAfterRevoke) != 0 {
		t.Errorf("these Nodes were recorded AFTER being denylisted: %v", rec.recordedAfterRevoke)
	}
}

// TestService_RevokeToken_DedupesDuplicateListEntryWithinChunk covers the
// `pending` guard directly: List() returning the same NodeID twice inside one
// pass, before any flush, must still record and revoke that Node exactly
// once, and CascadeShortfall must count it once — not twice — toward
// Total/Unrecorded. Every registry.List() implementation returns unique IDs
// today, so nothing else in this suite reaches the duplicate branch the
// guard exists for; removing it leaves the rest of the suite green.
func TestService_RevokeToken_DedupesDuplicateListEntryWithinChunk(t *testing.T) {
	const tokenID = "tok-dup"
	duplicated := []registry.Node{
		{NodeID: "node-a", EnrollingTokenID: tokenID},
		{NodeID: "node-a", EnrollingTokenID: tokenID},
		{NodeID: "node-b", EnrollingTokenID: tokenID},
	}

	t.Run("non-failing recorder records each id exactly once", func(t *testing.T) {
		d := revocation.NewDenylist()
		c := revocation.NewConnections()
		lister := &fakeLister{perCall: [][]registry.Node{duplicated}}
		svc := revocation.NewService(d, c, lister, &fakeTokenRevoker{})

		rec := &recorder{}
		if err := svc.RevokeToken(context.Background(), tokenID, rec.record); err != nil {
			t.Fatalf("RevokeToken: %v", err)
		}

		counts := make(map[string]int, 2)
		for _, id := range rec.got {
			counts[id]++
		}
		if counts["node-a"] != 1 {
			t.Errorf("node-a appeared %d times across recorder calls, want exactly 1", counts["node-a"])
		}
		if counts["node-b"] != 1 {
			t.Errorf("node-b appeared %d times across recorder calls, want exactly 1", counts["node-b"])
		}
		if len(rec.got) != 2 {
			t.Errorf("recorder saw %v (%d ids), want exactly the 2 distinct Nodes", rec.got, len(rec.got))
		}
	})

	t.Run("failing recorder reports the distinct count, not the duplicate count", func(t *testing.T) {
		d := revocation.NewDenylist()
		c := revocation.NewConnections()
		lister := &fakeLister{perCall: [][]registry.Node{duplicated}}
		svc := revocation.NewService(d, c, lister, &fakeTokenRevoker{})

		rec := &recorder{failCalls: map[int]error{1: errors.New("audit store unavailable")}}
		err := svc.RevokeToken(context.Background(), tokenID, rec.record)
		var shortfall *revocation.CascadeShortfall
		if !errors.As(err, &shortfall) {
			t.Fatalf("RevokeToken error = %v, want a *CascadeShortfall", err)
		}
		if shortfall.Total != 2 {
			t.Errorf("shortfall.Total = %d, want 2 (the distinct Node count, not the 3 duplicated List entries)",
				shortfall.Total)
		}
		if shortfall.Unrecorded != 2 {
			t.Errorf("shortfall.Unrecorded = %d, want 2", shortfall.Unrecorded)
		}
	})
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
