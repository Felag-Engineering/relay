package revocation_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/enroll"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	"github.com/Felag-Engineering/relay/relay/internal/revocation"
)

// waitTimeout is the ceiling every synchronisation channel in this file
// waits against, so a broken lock hangs the offending test for a bounded
// time and fails it, rather than hanging `go test` itself.
const waitTimeout = 2 * time.Second

// trackingTokenRevoker wraps a real *enroll.Service and records which
// token ids it was called with and in what order — the direct evidence for
// whether RevokeToken's token lock (#605), not just its recorder callback,
// serialises concurrent calls for the same token id.
type trackingTokenRevoker struct {
	inner *enroll.Service

	mu         sync.Mutex
	calledWith []string
}

func (t *trackingTokenRevoker) Revoke(ctx context.Context, id string) error {
	t.mu.Lock()
	t.calledWith = append(t.calledWith, id)
	t.mu.Unlock()

	return t.inner.Revoke(ctx, id)
}

func (t *trackingTokenRevoker) calls() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.calledWith...)
}

// TestService_RevokeToken_SerialisesConcurrentRevokesOfTheSameToken is AC1:
// two concurrent RevokeToken calls for the same token id never have their
// recorder calls, or their underlying token-store Revoke calls, in flight at
// the same time, and every cascaded Node is recorded exactly once across
// both calls — the second call's re-run cascade finds every Node already
// denylisted and records nothing.
//
// It proves the TOKEN lock specifically, not just the node locks the two
// cascades happen to share: call 1 is blocked inside its recorder hook —
// which RevokeToken only reaches after it has already called the token
// store's Revoke (step 1) — while still holding the token lock, and the test
// asserts the token store has seen exactly one call before releasing it. If
// the token lock degenerated into a no-op, call 2 could reach the token
// store while call 1 is still blocked, and this assertion would catch it
// deterministically instead of relying on a race window narrow enough that
// it usually doesn't fire.
func TestService_RevokeToken_SerialisesConcurrentRevokesOfTheSameToken(t *testing.T) {
	silenceLogs(t)
	ctx := context.Background()

	d := revocation.NewDenylist()
	c := revocation.NewConnections()
	reg := registry.NewInMemory()
	tokenSvc := enroll.NewService(enroll.NewMemoryRepository())
	tracker := &trackingTokenRevoker{inner: tokenSvc}
	svc := revocation.NewService(d, c, reg, tracker)

	tok, _, err := tokenSvc.Create(ctx, []string{"relay:env=test"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}

	const nodeCount = 50
	nodeIDs := make([]string, nodeCount)
	for i := range nodeIDs {
		nodeIDs[i] = fmt.Sprintf("node-%03d", i)
		if _, err := reg.Upsert(registry.Report{NodeID: nodeIDs[i], EnrollingTokenID: tok.ID}); err != nil {
			t.Fatalf("Upsert(%s): %v", nodeIDs[i], err)
		}
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	rec := &recorder{hook: func([]string) {
		once.Do(func() { close(entered) })
		<-release
	}}

	errCh1 := make(chan error, 1)
	go func() { errCh1 <- svc.RevokeToken(ctx, tok.ID, rec.record) }()

	select {
	case <-entered:
	case <-time.After(waitTimeout):
		t.Fatal("call 1 never reached record — test setup broken")
	}

	// Call 1 has already called the token store's Revoke (RevokeToken's step
	// 1 runs before the node scan that leads here) and is now blocked in
	// record, still holding the token lock.
	if calls := tracker.calls(); len(calls) != 1 {
		t.Fatalf("token store calls = %v before call 2 starts, want exactly 1", calls)
	}

	errCh2 := make(chan error, 1)
	go func() { errCh2 <- svc.RevokeToken(ctx, tok.ID, rec.record) }()

	select {
	case err := <-errCh2:
		t.Fatalf("RevokeToken call 2 returned (%v) while call 1 still holds the token lock", err)
	case <-time.After(100 * time.Millisecond):
		// expected: still blocked on the token lock
	}
	if calls := tracker.calls(); len(calls) != 1 {
		t.Errorf("token store calls = %v while call 1 still holds the token lock, want still "+
			"exactly 1 — call 2 must not reach the token store until call 1 releases the lock", calls)
	}

	close(release)

	var errs [2]error
	select {
	case errs[0] = <-errCh1:
	case <-time.After(waitTimeout):
		t.Fatal("RevokeToken call 1 never finished after being released")
	}
	select {
	case errs[1] = <-errCh2:
	case <-time.After(waitTimeout):
		t.Fatal("RevokeToken call 2 never finished after call 1 released the token lock")
	}

	for i, err := range errs {
		if err != nil {
			t.Errorf("RevokeToken call %d: %v, want nil", i, err)
		}
	}

	if calls := tracker.calls(); len(calls) != 2 {
		t.Errorf("token store Revoke calls = %v, want exactly 2 (one per RevokeToken call; the "+
			"second cascade still revokes the already-revoked token, which enroll.Service.Revoke "+
			"tolerates idempotently)", calls)
	}

	counts := make(map[string]int, nodeCount)
	for _, id := range rec.got {
		counts[id]++
	}
	for _, id := range nodeIDs {
		if !d.IsRevoked(id) {
			t.Errorf("%s should be denylisted after either cascade", id)
		}
		if counts[id] != 1 {
			t.Errorf("%s was recorded %d times across both calls, want exactly 1 — the second "+
				"call's cascade must find every Node already denylisted and record nothing", id, counts[id])
		}
	}
}

// TestService_RevokeToken_DifferentTokensRunConcurrently is AC3: two
// cascades for two different tokens are genuinely concurrent, not merely
// interleaved by a scheduler. Each cascade's recorder signals that it has
// entered record and then waits for the OTHER cascade's signal — a
// rendezvous that can only complete if both are inside record() at once. A
// global lock (rather than one keyed on token id) would make this test hang
// until its own timeout fires and fails it.
func TestService_RevokeToken_DifferentTokensRunConcurrently(t *testing.T) {
	silenceLogs(t)
	ctx := context.Background()
	svc, _, _, reg, tokenSvc := newServiceFixture(t)

	tokA, _, err := tokenSvc.Create(ctx, []string{"relay:env=test"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("Create token A: %v", err)
	}
	tokB, _, err := tokenSvc.Create(ctx, []string{"relay:env=test"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("Create token B: %v", err)
	}
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a", EnrollingTokenID: tokA.ID}); err != nil {
		t.Fatalf("Upsert(node-a): %v", err)
	}
	if _, err := reg.Upsert(registry.Report{NodeID: "node-b", EnrollingTokenID: tokB.ID}); err != nil {
		t.Fatalf("Upsert(node-b): %v", err)
	}

	enteredA := make(chan struct{})
	enteredB := make(chan struct{})
	var onceA, onceB sync.Once

	recA := &recorder{hook: func([]string) {
		onceA.Do(func() { close(enteredA) })
		select {
		case <-enteredB:
		case <-time.After(waitTimeout):
			t.Error("token A's cascade timed out waiting for token B's cascade to also be " +
				"inside record — the lock appears to have degenerated into a global one")
		}
	}}
	recB := &recorder{hook: func([]string) {
		onceB.Do(func() { close(enteredB) })
		select {
		case <-enteredA:
		case <-time.After(waitTimeout):
			t.Error("token B's cascade timed out waiting for token A's cascade to also be " +
				"inside record — the lock appears to have degenerated into a global one")
		}
	}}

	var wg sync.WaitGroup
	var errA, errB error
	wg.Add(2)
	go func() { defer wg.Done(); errA = svc.RevokeToken(ctx, tokA.ID, recA.record) }()
	go func() { defer wg.Done(); errB = svc.RevokeToken(ctx, tokB.ID, recB.record) }()
	wg.Wait()

	if errA != nil {
		t.Errorf("RevokeToken(tokA): %v", errA)
	}
	if errB != nil {
		t.Errorf("RevokeToken(tokB): %v", errB)
	}
	if !recA.contains("node-a") {
		t.Error("token A's cascade should have recorded node-a")
	}
	if !recB.contains("node-b") {
		t.Error("token B's cascade should have recorded node-b")
	}
}

// TestService_RevokeNodeRecorded_WritesNoSecondRecordAfterACascadeRecordedTheNode
// is AC2's cascade-first interleaving: a cascade's record call for node-a is
// blocked in flight when a concurrent RevokeNodeRecorded call for node-a
// arrives. The single-Node call must block on node-a's lock — proven by
// observing it has not returned before the cascade is released — and once
// unblocked must write no second record, because by then the cascade
// already has.
func TestService_RevokeNodeRecorded_WritesNoSecondRecordAfterACascadeRecordedTheNode(t *testing.T) {
	ctx := context.Background()
	svc, d, _, reg, tokenSvc := newServiceFixture(t)

	tok, _, err := tokenSvc.Create(ctx, []string{"relay:env=test"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a", EnrollingTokenID: tok.ID}); err != nil {
		t.Fatalf("Upsert(node-a): %v", err)
	}

	entered := make(chan struct{})
	proceed := make(chan struct{})
	var once sync.Once
	cascadeRec := &recorder{hook: func([]string) {
		once.Do(func() { close(entered) })
		<-proceed
	}}

	cascadeErrCh := make(chan error, 1)
	go func() { cascadeErrCh <- svc.RevokeToken(ctx, tok.ID, cascadeRec.record) }()

	select {
	case <-entered:
	case <-time.After(waitTimeout):
		t.Fatal("cascade never reached record — test setup broken")
	}

	singleRec := &recorder{}
	singleErrCh := make(chan error, 1)
	go func() { singleErrCh <- svc.RevokeNodeRecorded(ctx, "node-a", singleRec.record) }()

	// The single-Node call must still be blocked on node-a's lock: the
	// cascade holds it from before record() is called until after RevokeNode
	// runs, and record() is still blocked right now.
	select {
	case err := <-singleErrCh:
		t.Fatalf("RevokeNodeRecorded returned (%v) while the cascade still holds node-a's lock", err)
	case <-time.After(100 * time.Millisecond):
		// expected: still blocked
	}

	close(proceed)

	var cascadeErr error
	select {
	case cascadeErr = <-cascadeErrCh:
	case <-time.After(waitTimeout):
		t.Fatal("cascade never finished after being released")
	}
	if cascadeErr != nil {
		t.Errorf("RevokeToken: %v", cascadeErr)
	}

	var singleErr error
	select {
	case singleErr = <-singleErrCh:
	case <-time.After(waitTimeout):
		t.Fatal("RevokeNodeRecorded never returned after the cascade released node-a's lock")
	}
	if singleErr != nil {
		t.Errorf("RevokeNodeRecorded: %v, want nil — a Node this process already recorded a "+
			"cascade revocation for must still revoke successfully", singleErr)
	}

	if !d.IsRevoked("node-a") {
		t.Error("node-a should be denylisted")
	}
	if len(singleRec.got) != 0 {
		t.Errorf("the single-Node recorder was called with %v, want it never called — the cascade "+
			"already recorded node-a", singleRec.got)
	}
	if len(cascadeRec.got) != 1 || cascadeRec.got[0] != "node-a" {
		t.Errorf("cascade recorder saw %v, want exactly [node-a]", cascadeRec.got)
	}
}

// TestService_RevokeNodeRecorded_NoSecondRecordWhileAChunkIsRecordedButNotYetRevoked
// is AC2's literal window: a chunk of two Nodes whose record call has
// already returned, so both are marked recorded, but whose revokeAll call is
// still in progress — the chunk's SetRevokedAll (containing node-a) is
// blocked.
//
// #607 changed what this window looks like: revokeAll denylists the WHOLE
// chunk (phase 1) before it makes its one SetRevokedAll call (phase 2), so
// by the time that call is blocked, both node-a and node-b are ALREADY
// denylisted — a strictly stronger property than the one this test asserted
// before #607, when the chunk's revoke loop denylisted one Node at a time
// and node-b (sorted after node-a by registry.InMemory.List) would still be
// waiting its turn. That per-Node ordering dependency on List's sort order
// is gone: the chunk is one call now, and ordering within it is irrelevant
// to what this test proves. What the Node lock still covers is the
// record-committed-but-teardown-incomplete window: node-a and node-b are
// denylisted, but revokeAll's phase (3) Disconnect has not run for either of
// them yet. A concurrent RevokeNodeRecorded for node-b must still block on
// its lock — still held by the chunk until revokeAll finishes — and then
// write no second record.
func TestService_RevokeNodeRecorded_NoSecondRecordWhileAChunkIsRecordedButNotYetRevoked(t *testing.T) {
	ctx := context.Background()

	d := revocation.NewDenylist()
	c := revocation.NewConnections()
	baseReg := registry.NewInMemory()
	release := make(chan struct{})
	blockingReg := newBlockingRegistry(baseReg, "node-a", release)
	tokenSvc := enroll.NewService(enroll.NewMemoryRepository())
	svc := revocation.NewService(d, c, blockingReg, tokenSvc)

	tok, _, err := tokenSvc.Create(ctx, []string{"relay:env=test"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}
	if _, err := baseReg.Upsert(registry.Report{NodeID: "node-a", EnrollingTokenID: tok.ID}); err != nil {
		t.Fatalf("Upsert(node-a): %v", err)
	}
	if _, err := baseReg.Upsert(registry.Report{NodeID: "node-b", EnrollingTokenID: tok.ID}); err != nil {
		t.Fatalf("Upsert(node-b): %v", err)
	}

	cascadeRec := &recorder{}
	cascadeErrCh := make(chan error, 1)
	go func() { cascadeErrCh <- svc.RevokeToken(ctx, tok.ID, cascadeRec.record) }()

	select {
	case <-blockingReg.entered:
	case <-time.After(waitTimeout):
		t.Fatal("cascade never reached the chunk's blocked SetRevokedAll — test setup broken")
	}

	// At this instant: the chunk's record call has already returned (it ran
	// before revokeAll, which is now blocked in SetRevokedAll for the chunk
	// containing node-a), so both Nodes are marked recorded; and BOTH are
	// already denylisted, because revokeAll's phase (1) denylists the whole
	// chunk before phase (2) ever touches the store. Neither has had its
	// live-Tunnel teardown (phase (3)) yet.
	if !d.IsRevoked("node-a") || !d.IsRevoked("node-b") {
		t.Fatalf("both Nodes should already be denylisted while the chunk's registry write is in flight: node-a=%v node-b=%v",
			d.IsRevoked("node-a"), d.IsRevoked("node-b"))
	}

	singleRec := &recorder{}
	singleErrCh := make(chan error, 1)
	go func() { singleErrCh <- svc.RevokeNodeRecorded(ctx, "node-b", singleRec.record) }()

	select {
	case err := <-singleErrCh:
		t.Fatalf("RevokeNodeRecorded(node-b) returned (%v) while the chunk still holds its lock", err)
	case <-time.After(100 * time.Millisecond):
		// expected: still blocked
	}

	close(release)

	select {
	case cascadeErr := <-cascadeErrCh:
		if cascadeErr != nil {
			t.Errorf("RevokeToken: %v", cascadeErr)
		}
	case <-time.After(waitTimeout):
		t.Fatal("cascade never finished after node-a's SetRevoked was released")
	}

	var singleErr error
	select {
	case singleErr = <-singleErrCh:
	case <-time.After(waitTimeout):
		t.Fatal("RevokeNodeRecorded(node-b) never returned after the chunk finished")
	}
	if singleErr != nil {
		t.Errorf("RevokeNodeRecorded(node-b): %v, want nil", singleErr)
	}

	if !d.IsRevoked("node-a") || !d.IsRevoked("node-b") {
		t.Errorf("both Nodes should be denylisted at the end: node-a=%v node-b=%v",
			d.IsRevoked("node-a"), d.IsRevoked("node-b"))
	}
	if len(singleRec.got) != 0 {
		t.Errorf("the single-Node recorder was called with %v, want it never called", singleRec.got)
	}
	if n := cascadeRec.calls[0]; len(n) != 2 {
		t.Fatalf("cascade recorder's one call carried %v, want both node-a and node-b", n)
	}
}

// TestService_RevokeNodeRecorded_CascadeSkipsANodeRecordedByAConcurrentSingleRevoke
// is AC2's single-Node-first interleaving: a RevokeNodeRecorded call for
// node-a is blocked inside record (still holding node-a's lock, and node-a
// is NOT yet denylisted — RevokeNode has not run). A cascade covering node-a
// starts concurrently and must block acquiring node-a's lock. Once the
// single-Node call finishes and denylists node-a, the cascade's own
// pre-existing IsRevoked filter (unchanged by #605, now evaluated under the
// lock) drops node-a from its chunk, so the cascade never calls record for
// it.
func TestService_RevokeNodeRecorded_CascadeSkipsANodeRecordedByAConcurrentSingleRevoke(t *testing.T) {
	ctx := context.Background()
	svc, d, _, reg, tokenSvc := newServiceFixture(t)

	tok, _, err := tokenSvc.Create(ctx, []string{"relay:env=test"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a", EnrollingTokenID: tok.ID}); err != nil {
		t.Fatalf("Upsert(node-a): %v", err)
	}

	entered := make(chan struct{})
	proceed := make(chan struct{})
	var once sync.Once
	singleRec := &recorder{hook: func([]string) {
		once.Do(func() { close(entered) })
		<-proceed
	}}

	singleErrCh := make(chan error, 1)
	go func() { singleErrCh <- svc.RevokeNodeRecorded(ctx, "node-a", singleRec.record) }()

	select {
	case <-entered:
	case <-time.After(waitTimeout):
		t.Fatal("single-Node call never reached record — test setup broken")
	}
	if d.IsRevoked("node-a") {
		t.Fatal("node-a should not be denylisted yet — RevokeNode has not run")
	}

	cascadeRec := &recorder{}
	cascadeErrCh := make(chan error, 1)
	go func() { cascadeErrCh <- svc.RevokeToken(ctx, tok.ID, cascadeRec.record) }()

	// The cascade must block trying to acquire node-a's lock.
	select {
	case err := <-cascadeErrCh:
		t.Fatalf("RevokeToken returned (%v) while the single-Node call still holds node-a's lock", err)
	case <-time.After(100 * time.Millisecond):
		// expected: still blocked
	}

	close(proceed)

	select {
	case singleErr := <-singleErrCh:
		if singleErr != nil {
			t.Errorf("RevokeNodeRecorded: %v", singleErr)
		}
	case <-time.After(waitTimeout):
		t.Fatal("RevokeNodeRecorded never finished after being released")
	}

	select {
	case cascadeErr := <-cascadeErrCh:
		if cascadeErr != nil {
			t.Errorf("RevokeToken: %v", cascadeErr)
		}
	case <-time.After(waitTimeout):
		t.Fatal("cascade never finished after node-a's lock was released")
	}

	if !d.IsRevoked("node-a") {
		t.Error("node-a should be denylisted")
	}
	if cascadeRec.contains("node-a") {
		t.Error("the cascade should never have recorded node-a — its own IsRevoked filter, " +
			"evaluated under the lock, must have dropped it")
	}

	total := 0
	for _, id := range singleRec.got {
		if id == "node-a" {
			total++
		}
	}
	for _, id := range cascadeRec.got {
		if id == "node-a" {
			total++
		}
	}
	if total != 1 {
		t.Errorf("node-a was recorded %d times across both recorders, want exactly 1", total)
	}
}

// TestService_RevokeNodeRecorded_RacingCascadeRecordsEachNodeOnce is AC2's
// -race criterion: run under `go test -race`, this repeatedly starts a
// cascade and a single-Node revoke for one of the cascaded Nodes at the same
// instant, with a fresh Service each iteration, and asserts every Node ends
// up denylisted with exactly one record.
func TestService_RevokeNodeRecorded_RacingCascadeRecordsEachNodeOnce(t *testing.T) {
	silenceLogs(t)
	ctx := context.Background()

	const iterations = 50
	const nodeCount = 20

	for iter := 0; iter < iterations; iter++ {
		d := revocation.NewDenylist()
		c := revocation.NewConnections()
		reg := registry.NewInMemory()
		tokenSvc := enroll.NewService(enroll.NewMemoryRepository())
		svc := revocation.NewService(d, c, reg, tokenSvc)

		tok, _, err := tokenSvc.Create(ctx, []string{"relay:env=test"}, 24*time.Hour)
		if err != nil {
			t.Fatalf("iter %d: Create token: %v", iter, err)
		}
		nodeIDs := make([]string, nodeCount)
		for i := range nodeIDs {
			nodeIDs[i] = fmt.Sprintf("node-%02d", i)
			if _, err := reg.Upsert(registry.Report{NodeID: nodeIDs[i], EnrollingTokenID: tok.ID}); err != nil {
				t.Fatalf("iter %d: Upsert(%s): %v", iter, nodeIDs[i], err)
			}
		}

		cascadeRec := &recorder{}
		singleRec := &recorder{}
		start := make(chan struct{})
		var wg sync.WaitGroup
		var cascadeErr, singleErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			cascadeErr = svc.RevokeToken(ctx, tok.ID, cascadeRec.record)
		}()
		go func() {
			defer wg.Done()
			<-start
			singleErr = svc.RevokeNodeRecorded(ctx, nodeIDs[0], singleRec.record)
		}()
		close(start)
		wg.Wait()

		if cascadeErr != nil {
			t.Fatalf("iter %d: RevokeToken: %v", iter, cascadeErr)
		}
		if singleErr != nil {
			t.Fatalf("iter %d: RevokeNodeRecorded: %v", iter, singleErr)
		}

		counts := make(map[string]int, nodeCount)
		for _, id := range cascadeRec.got {
			counts[id]++
		}
		for _, id := range singleRec.got {
			counts[id]++
		}
		for _, id := range nodeIDs {
			if !d.IsRevoked(id) {
				t.Fatalf("iter %d: %s should be denylisted", iter, id)
			}
			if counts[id] != 1 {
				t.Fatalf("iter %d: %s was recorded %d times, want exactly 1", iter, id, counts[id])
			}
		}
	}
}

// TestService_RevokeNodeRecorded_RecordsWhenTheNodeWasDenylistedWithoutARecord
// is the backstop this design protects: denylist membership alone must
// never suppress a record. Each sub-test denylists a Node through one of the
// three production paths that do so without writing a node_revoke record,
// then asserts RevokeNodeRecorded still writes one — proof that the
// suppression is keyed on a record this process actually wrote, never on
// denylist membership.
func TestService_RevokeNodeRecorded_RecordsWhenTheNodeWasDenylistedWithoutARecord(t *testing.T) {
	ctx := context.Background()

	t.Run("self-denylisted after a failed enrollment", func(t *testing.T) {
		svc, d, _, _, _ := newServiceFixture(t)

		// The exact call enroll/handler.go's post-Upsert revocation recheck
		// makes through NodeDenylister.RevokeNode.
		svc.RevokeNode("node-self")
		if !d.IsRevoked("node-self") {
			t.Fatal("node-self should be denylisted by RevokeNode")
		}

		rec := &recorder{}
		if err := svc.RevokeNodeRecorded(ctx, "node-self", rec.record); err != nil {
			t.Fatalf("RevokeNodeRecorded: %v", err)
		}
		if !rec.contains("node-self") {
			t.Error("RevokeNodeRecorded should have written a record: this Node was denylisted " +
				"with no record at all")
		}
		if len(rec.got) != 1 || rec.got[0] != "node-self" {
			t.Errorf("recorder saw %v, want exactly [node-self]", rec.got)
		}
	})

	t.Run("denylist rehydrated at startup", func(t *testing.T) {
		svc, d, _, _, _ := newServiceFixture(t)

		// What relay/cmd/relay/main.go's startup rehydration does directly on
		// the Denylist, bypassing RevokeNode entirely.
		d.Add("node-rehydrated")

		rec := &recorder{}
		if err := svc.RevokeNodeRecorded(ctx, "node-rehydrated", rec.record); err != nil {
			t.Fatalf("RevokeNodeRecorded: %v", err)
		}
		if !rec.contains("node-rehydrated") {
			t.Error("RevokeNodeRecorded should have written a record: this Node was denylisted " +
				"with no record at all")
		}
		if len(rec.got) != 1 || rec.got[0] != "node-rehydrated" {
			t.Errorf("recorder saw %v, want exactly [node-rehydrated]", rec.got)
		}
	})

	t.Run("a cascade chunk whose record failed", func(t *testing.T) {
		silenceLogs(t)
		svc, d, _, reg, tokenSvc := newServiceFixture(t)

		tok, _, err := tokenSvc.Create(ctx, []string{"relay:env=test"}, 24*time.Hour)
		if err != nil {
			t.Fatalf("Create token: %v", err)
		}
		if _, err := reg.Upsert(registry.Report{NodeID: "node-unrecorded", EnrollingTokenID: tok.ID}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}

		cascadeRec := &recorder{failCalls: map[int]error{1: errors.New("audit store unavailable")}}
		cascadeErr := svc.RevokeToken(ctx, tok.ID, cascadeRec.record)
		if !errors.Is(cascadeErr, revocation.ErrCascadeNotRecorded) {
			t.Fatalf("RevokeToken error = %v, want errors.Is(err, ErrCascadeNotRecorded)", cascadeErr)
		}
		if !d.IsRevoked("node-unrecorded") {
			t.Fatal("node-unrecorded should be denylisted even though its record failed")
		}

		rec := &recorder{}
		if err := svc.RevokeNodeRecorded(ctx, "node-unrecorded", rec.record); err != nil {
			t.Fatalf("RevokeNodeRecorded: %v", err)
		}
		if !rec.contains("node-unrecorded") {
			t.Error("RevokeNodeRecorded should have written a record: the cascade's record call " +
				"for this Node failed, so no record for it exists")
		}
	})
}

// TestService_RevokeNodeRecorded_RecordsAgainForARepeatOperatorRevoke pins
// the boundary of the suppression: TWO calls to RevokeNodeRecorded for the
// same Node — a repeat operator revoke, today's behaviour — must both
// record. Only a cascade's record suppresses a later single-Node record;
// RevokeNodeRecorded itself never marks recordedSet.
func TestService_RevokeNodeRecorded_RecordsAgainForARepeatOperatorRevoke(t *testing.T) {
	ctx := context.Background()
	svc, d, _, _, _ := newServiceFixture(t)

	rec := &recorder{}
	if err := svc.RevokeNodeRecorded(ctx, "node-repeat", rec.record); err != nil {
		t.Fatalf("first RevokeNodeRecorded: %v", err)
	}
	if err := svc.RevokeNodeRecorded(ctx, "node-repeat", rec.record); err != nil {
		t.Fatalf("second RevokeNodeRecorded: %v", err)
	}

	if !d.IsRevoked("node-repeat") {
		t.Error("node-repeat should be denylisted")
	}
	if len(rec.calls) != 2 {
		t.Fatalf("recorder was called %d times, want exactly 2 — a repeat operator revoke "+
			"still records", len(rec.calls))
	}
	count := 0
	for _, id := range rec.got {
		if id == "node-repeat" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("node-repeat was recorded %d times, want exactly 2", count)
	}
}

// TestService_RevokeNodeRecorded_RecordFailureDoesNotRevoke is #487's
// fail-closed half, now proven at the Service seam: when record errors, the
// Node must not be denylisted and its registry row must not be touched.
func TestService_RevokeNodeRecorded_RecordFailureDoesNotRevoke(t *testing.T) {
	ctx := context.Background()
	svc, d, _, reg, _ := newServiceFixture(t)

	if _, err := reg.Upsert(registry.Report{NodeID: "node-fail"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	recordErr := errors.New("audit store unavailable")
	rec := &recorder{failCalls: map[int]error{1: recordErr}}

	err := svc.RevokeNodeRecorded(ctx, "node-fail", rec.record)
	if !errors.Is(err, recordErr) {
		t.Fatalf("RevokeNodeRecorded error = %v, want errors.Is(err, recordErr)", err)
	}
	if d.IsRevoked("node-fail") {
		t.Error("node-fail should not be denylisted when the record fails")
	}
	n, ok := reg.Get("node-fail")
	if !ok {
		t.Fatal("node-fail missing from registry")
	}
	if !n.RevokedAt.IsZero() {
		t.Error("node-fail's RevokedAt should not be set when the record fails")
	}
}

// TestService_RevokeNodeRecorded_NilRecorderRevokesNothing mirrors
// RevokeToken's nil-recorder guarantee: a nil recorder is refused before the
// Node's lock is even acquired, and the Node is left untouched.
func TestService_RevokeNodeRecorded_NilRecorderRevokesNothing(t *testing.T) {
	ctx := context.Background()
	svc, d, _, reg, _ := newServiceFixture(t)

	if _, err := reg.Upsert(registry.Report{NodeID: "node-nil"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	err := svc.RevokeNodeRecorded(ctx, "node-nil", nil)
	if !errors.Is(err, revocation.ErrRecorderRequired) {
		t.Fatalf("RevokeNodeRecorded(nil recorder) error = %v, want errors.Is(err, ErrRecorderRequired)", err)
	}
	if d.IsRevoked("node-nil") {
		t.Error("node-nil should not be denylisted when the recorder is nil")
	}
}

// TestService_RevokeToken_CancelledWhileWaitingRevokesNothing covers
// context-honouring on RevokeToken's token lock: a caller whose context is
// already cancelled when it tries to acquire a token lock held by an
// in-flight cascade gets ctx.Err() back and touches nothing — the token
// store's Revoke is called by the first cascade only, never by the
// cancelled second call.
func TestService_RevokeToken_CancelledWhileWaitingRevokesNothing(t *testing.T) {
	ctx := context.Background()

	d := revocation.NewDenylist()
	c := revocation.NewConnections()
	reg := registry.NewInMemory()
	tokenSvc := enroll.NewService(enroll.NewMemoryRepository())
	tracker := &trackingTokenRevoker{inner: tokenSvc}
	svc := revocation.NewService(d, c, reg, tracker)

	tok, _, err := tokenSvc.Create(ctx, []string{"relay:env=test"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}
	if _, err := reg.Upsert(registry.Report{NodeID: "node-held", EnrollingTokenID: tok.ID}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	entered := make(chan struct{})
	proceed := make(chan struct{})
	var once sync.Once
	firstRec := &recorder{hook: func([]string) {
		once.Do(func() { close(entered) })
		<-proceed
	}}

	firstErrCh := make(chan error, 1)
	go func() { firstErrCh <- svc.RevokeToken(ctx, tok.ID, firstRec.record) }()

	select {
	case <-entered:
	case <-time.After(waitTimeout):
		t.Fatal("first cascade never reached record — the token lock is held by then")
	}

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	secondRec := &recorder{}
	secondErr := svc.RevokeToken(cancelledCtx, tok.ID, secondRec.record)
	if !errors.Is(secondErr, context.Canceled) {
		t.Fatalf("second RevokeToken error = %v, want errors.Is(err, context.Canceled)", secondErr)
	}
	if len(secondRec.got) != 0 {
		t.Errorf("the cancelled call recorded %v, want nothing", secondRec.got)
	}

	close(proceed)
	select {
	case firstErr := <-firstErrCh:
		if firstErr != nil {
			t.Errorf("first RevokeToken: %v", firstErr)
		}
	case <-time.After(waitTimeout):
		t.Fatal("first cascade never finished after being released")
	}

	if calls := tracker.calls(); len(calls) != 1 || calls[0] != tok.ID {
		t.Errorf("token store Revoke calls = %v, want exactly one call, from the first cascade only",
			calls)
	}
}
