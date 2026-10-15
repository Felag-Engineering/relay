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

// contentionHook is one call's synchronisation point for singleConnRegistry:
// beforeAcquire runs before the double takes its modelled connection,
// whileHeld runs after. Both are optional.
type contentionHook struct {
	beforeAcquire func()
	whileHeld     func()
}

// singleConnRegistry is a test double for revocation.Registry over a real
// registry.InMemory that models the store's single connection
// (store.Open's SetMaxOpenConns(1)) as a buffered channel of capacity 1:
// acquire sends into it, release receives from it, so a second acquire
// attempt while the first is outstanding blocks — and a non-blocking send
// from outside, tried while the channel is full, fails, which is the
// double's own proof of exclusivity.
//
// It records, under its own mutex (never the embedded InMemory's lock):
// chunks (a COPY of the ids passed to each SetRevokedAll call, in call
// order — never the slice itself, because
// registry.Repository.SetRevokedAll's read-only-borrow contract forbids
// retaining nodeIDs, and revokeChunk relies on exactly that contract to
// skip its own defensive copy before calling it), perNode (how many times
// the per-Node SetRevoked was reached — the cascade must never reach it),
// and log (an ordered event log of chunk-N-start, chunk-N-end and
// other-get entries).
type singleConnRegistry struct {
	*registry.InMemory

	conn chan struct{}

	mu      sync.Mutex
	calls   int
	chunks  [][]string
	perNode int
	log     []string
	hooks   map[int]contentionHook
}

func newSingleConnRegistry(reg *registry.InMemory) *singleConnRegistry {
	return &singleConnRegistry{InMemory: reg, conn: make(chan struct{}, 1)}
}

// setHook registers the hook for SetRevokedAll's 0-based callIndex-th call.
func (s *singleConnRegistry) setHook(callIndex int, h contentionHook) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hooks == nil {
		s.hooks = make(map[int]contentionHook)
	}
	s.hooks[callIndex] = h
}

func (s *singleConnRegistry) appendLog(entry string) {
	s.mu.Lock()
	s.log = append(s.log, entry)
	s.mu.Unlock()
}

func (s *singleConnRegistry) acquire() { s.conn <- struct{}{} }
func (s *singleConnRegistry) release() { <-s.conn }

// SetRevokedAll is the cascade's persistence path in this double. It looks
// up its own call's hook BEFORE taking the connection (so beforeAcquire can
// park a later call while an earlier one still holds it), then takes the
// connection and runs whileHeld before delegating to the embedded InMemory.
func (s *singleConnRegistry) SetRevokedAll(nodeIDs []string, at time.Time) ([]string, error) {
	s.mu.Lock()
	idx := s.calls
	s.calls++
	h := s.hooks[idx]
	s.chunks = append(s.chunks, append([]string(nil), nodeIDs...))
	s.mu.Unlock()

	if h.beforeAcquire != nil {
		h.beforeAcquire()
	}

	s.acquire()
	defer s.release()
	s.appendLog(fmt.Sprintf("chunk-%d-start", idx))

	if h.whileHeld != nil {
		h.whileHeld()
	}

	missing, err := s.InMemory.SetRevokedAll(nodeIDs, at)
	s.appendLog(fmt.Sprintf("chunk-%d-end", idx))
	return missing, err
}

// SetRevoked is the per-Node path this whole issue exists to stop the
// cascade from reaching. Kept reachable (and connection-modelled) only so
// perNode can prove it stayed at zero.
func (s *singleConnRegistry) SetRevoked(nodeID string, at time.Time) error {
	s.acquire()
	defer s.release()
	s.mu.Lock()
	s.perNode++
	s.mu.Unlock()
	return s.InMemory.SetRevoked(nodeID, at)
}

func (s *singleConnRegistry) ListChecked() ([]registry.Node, error) {
	s.acquire()
	defer s.release()
	return s.InMemory.ListChecked()
}

// Get is the "other store call" this file's contention test drives through
// the modelled connection. The cascade itself never calls Get — only
// ListChecked — so an "other-get" log entry is unambiguous evidence of an
// unrelated caller.
func (s *singleConnRegistry) Get(nodeID string) (registry.Node, bool) {
	s.acquire()
	defer s.release()
	s.appendLog("other-get")
	return s.InMemory.Get(nodeID)
}

// TestService_RevokeToken_AnotherStoreCallRunsBetweenChunks is acceptance
// criterion 3: a slow store, and another store call completing during a
// large cascade.
//
// WHAT #607 CHANGES IS THE NUMBER of store round-trips the cascade makes:
// ceil(N/cascadeRecordChunk) transactions instead of N autocommits, i.e. one
// commit per chunk instead of one per Node. This test proves exactly that
// and nothing more: three SetRevokedAll calls sized 500/500/5 for
// 2*CascadeRecordChunk+5 Nodes, perNode == 0, and an unrelated store call
// (Get) completing between two of the cascade's chunks while the cascade is
// provably still in flight. The interleave ALONE would have been true
// before this change too — store.Open's SetMaxOpenConns(1) serialises
// STATEMENTS, not transactions, so another store call already completes
// between two of today's per-Node autocommits; the round-trip count would
// not. It measures no wall-clock, deliberately: a fake cannot reproduce
// SQLite's per-commit fsync, and a timing assertion here would be a flake.
func TestService_RevokeToken_AnotherStoreCallRunsBetweenChunks(t *testing.T) {
	silenceLogs(t)
	d := revocation.NewDenylist()
	c := revocation.NewConnections()
	baseReg := registry.NewInMemory()
	reg := newSingleConnRegistry(baseReg)
	tokenSvc := enroll.NewService(enroll.NewMemoryRepository())
	svc := revocation.NewService(d, c, reg, tokenSvc)
	ctx := context.Background()

	tok, _, err := tokenSvc.Create(ctx, []string{"relay:env=test"}, 24*time.Hour)
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}

	const nodeCount = 2*revocation.CascadeRecordChunk + 5
	nodeIDs := make([]string, nodeCount)
	for i := range nodeIDs {
		nodeIDs[i] = fmt.Sprintf("node-%05d", i+1)
		if _, err := baseReg.Upsert(registry.Report{NodeID: nodeIDs[i], EnrollingTokenID: tok.ID}); err != nil {
			t.Fatalf("Upsert(%s): %v", nodeIDs[i], err)
		}
	}

	chunk0Held := make(chan struct{})
	var chunk0HeldOnce sync.Once
	releaseChunk0 := make(chan struct{})
	chunk1Pending := make(chan struct{})
	var chunk1PendingOnce sync.Once
	releaseChunk1 := make(chan struct{})

	reg.setHook(0, contentionHook{
		whileHeld: func() {
			chunk0HeldOnce.Do(func() { close(chunk0Held) })
			<-releaseChunk0
		},
	})
	reg.setHook(1, contentionHook{
		beforeAcquire: func() {
			chunk1PendingOnce.Do(func() { close(chunk1Pending) })
			<-releaseChunk1
		},
	})

	rec := &recorder{}
	errCh := make(chan error, 1)
	go func() { errCh <- svc.RevokeToken(ctx, tok.ID, rec.record) }()

	select {
	case <-chunk0Held:
	case <-time.After(waitTimeout):
		t.Fatal("cascade never reached chunk 0's whileHeld hook — test setup broken")
	}

	// The connection is genuinely exclusive while chunk 0's transaction is
	// in flight: a non-blocking try-send must fail. This is also the COST
	// side of the trade made visible — while a chunk transaction is in
	// flight the single connection is unavailable to anyone else.
	select {
	case reg.conn <- struct{}{}:
		t.Fatal("connection accepted a second holder while chunk 0's transaction was in flight")
	default:
		// expected: connection is exclusively held
	}

	close(releaseChunk0)

	select {
	case <-chunk1Pending:
	case <-time.After(waitTimeout):
		t.Fatal("cascade never reached chunk 1's beforeAcquire hook — test setup broken")
	}

	// At this instant: chunk 0 has committed and released the connection,
	// chunk 1 has not taken it, and two chunks remain — a deterministic
	// point with the cascade provably in flight and the connection provably
	// free.
	if _, ok := reg.Get(nodeIDs[0]); !ok {
		t.Fatalf("Get(%s): not found", nodeIDs[0])
	}

	select {
	case err := <-errCh:
		t.Fatalf("cascade returned (%v) before chunk 1 was released", err)
	default:
		// expected: still in flight, parked in chunk 1's beforeAcquire
	}

	close(releaseChunk1)

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RevokeToken: %v", err)
		}
	case <-time.After(waitTimeout):
		t.Fatal("cascade never finished after chunk 1 was released")
	}

	reg.mu.Lock()
	chunks := reg.chunks
	perNode := reg.perNode
	log := reg.log
	reg.mu.Unlock()

	if len(chunks) != 3 {
		t.Fatalf("SetRevokedAll call count = %d, want 3", len(chunks))
	}
	wantSizes := []int{revocation.CascadeRecordChunk, revocation.CascadeRecordChunk, 5}
	for i, want := range wantSizes {
		if len(chunks[i]) != want {
			t.Errorf("chunk %d size = %d, want %d", i, len(chunks[i]), want)
		}
	}
	if perNode != 0 {
		t.Errorf("per-Node SetRevoked was called %d times, want 0 — the cascade must never reach the per-Node autocommit", perNode)
	}

	for _, id := range nodeIDs {
		if !d.IsRevoked(id) {
			t.Errorf("%s should be denylisted", id)
			continue
		}
		n, ok := baseReg.Get(id)
		if !ok || n.RevokedAt.IsZero() {
			t.Errorf("%s should carry a non-zero RevokedAt", id)
		}
	}

	chunk0End := indexOfLogEntry(log, "chunk-0-end")
	chunk2End := indexOfLogEntry(log, "chunk-2-end")
	otherGet := indexOfLogEntry(log, "other-get")
	if chunk0End < 0 || chunk2End < 0 || otherGet < 0 {
		t.Fatalf("log missing expected entries: %v", log)
	}
	if otherGet <= chunk0End || otherGet >= chunk2End {
		t.Errorf("other-get at index %d, want strictly between chunk-0-end (%d) and chunk-2-end (%d): log=%v",
			otherGet, chunk0End, chunk2End, log)
	}
}

func indexOfLogEntry(log []string, entry string) int {
	for i, e := range log {
		if e == entry {
			return i
		}
	}
	return -1
}

// erroringSetRevokedAllRegistry is a test double for revocation.Registry
// whose SetRevokedAll always fails, modelling a persistent batch failure
// across an entire cascade. ListChecked delegates to the embedded InMemory
// unchanged; SetRevoked either delegates too (so revokeAll's per-Node
// fallback can be proven to persist) or also fails (so the denylist and the
// live-Tunnel teardown can be proven unconditional even when nothing
// persists at all), depending on failSetRevoked.
type erroringSetRevokedAllRegistry struct {
	*registry.InMemory

	failSetRevoked bool
}

func (r *erroringSetRevokedAllRegistry) SetRevokedAll([]string, time.Time) ([]string, error) {
	return nil, errors.New("store unavailable")
}

func (r *erroringSetRevokedAllRegistry) SetRevoked(nodeID string, at time.Time) error {
	if r.failSetRevoked {
		return errors.New("store unavailable")
	}
	return r.InMemory.SetRevoked(nodeID, at)
}

// TestService_RevokeToken_StoreFailureStillRevokes is AC2's store half, and
// also proves #607's security-review fallback: a batch persistence failure
// is logged, never returned, never stops the denylist or the live-Tunnel
// teardown — over-denying beats under-denying, the same posture RevokeNode
// and revokeAll state — and revokeAll falls back to a per-Node SetRevoked so
// a single batch fault does not cost the whole chunk's durable revocations.
func TestService_RevokeToken_StoreFailureStillRevokes(t *testing.T) {
	cases := []struct {
		name           string
		failSetRevoked bool
		// wantPersisted asserts the fallback actually reaches the registry
		// when SetRevoked can succeed; wantPersisted is false only for the
		// both-fail case, which exists to prove phases (1) and (3) run
		// unconditionally even when nothing at all persists.
		wantPersisted bool
	}{
		{name: "PerNodeFallbackPersists", failSetRevoked: false, wantPersisted: true},
		{name: "BothBatchAndPerNodeFail", failSetRevoked: true, wantPersisted: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			silenceLogs(t)
			d := revocation.NewDenylist()
			c := revocation.NewConnections()
			baseReg := registry.NewInMemory()
			reg := &erroringSetRevokedAllRegistry{InMemory: baseReg, failSetRevoked: tc.failSetRevoked}
			tokenSvc := enroll.NewService(enroll.NewMemoryRepository())
			svc := revocation.NewService(d, c, reg, tokenSvc)
			ctx := context.Background()

			tok, _, err := tokenSvc.Create(ctx, []string{"relay:env=test"}, 24*time.Hour)
			if err != nil {
				t.Fatalf("Create token: %v", err)
			}

			nodeIDs := []string{"node-a", "node-b", "node-c"}
			trackedCtx := make(map[string]context.Context, len(nodeIDs))
			for _, id := range nodeIDs {
				if _, err := baseReg.Upsert(registry.Report{NodeID: id, EnrollingTokenID: tok.ID}); err != nil {
					t.Fatalf("Upsert(%s): %v", id, err)
				}
				nodeCtx, release := c.Track(ctx, id)
				defer release()
				trackedCtx[id] = nodeCtx
			}

			rec := &recorder{}
			if err := svc.RevokeToken(ctx, tok.ID, rec.record); err != nil {
				t.Fatalf("RevokeToken: %v, want nil — a persist failure must be logged, never returned", err)
			}

			for _, id := range nodeIDs {
				if !d.IsRevoked(id) {
					t.Errorf("%s should be denylisted despite the persist failure", id)
				}
				select {
				case <-trackedCtx[id].Done():
					// expected: live Tunnel torn down
				default:
					t.Errorf("%s's tracked context should be cancelled (live-Tunnel teardown) despite the persist failure", id)
				}

				n, ok := baseReg.Get(id)
				persisted := ok && !n.RevokedAt.IsZero()
				if persisted != tc.wantPersisted {
					t.Errorf("%s RevokedAt persisted = %v, want %v", id, persisted, tc.wantPersisted)
				}
			}
		})
	}
}
