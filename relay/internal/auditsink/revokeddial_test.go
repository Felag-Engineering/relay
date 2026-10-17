package auditsink

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
)

type fakeDialClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeDialClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeDialClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newDialClock() *fakeDialClock {
	return &fakeDialClock{t: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
}

func dialRecords(t *testing.T, repo audit.Repository, nodeID string) []audit.Record {
	t.Helper()
	all, err := repo.ByNode(context.Background(), nodeID)
	if err != nil {
		t.Fatalf("ByNode: %v", err)
	}
	var out []audit.Record
	for _, r := range all {
		if r.Kind == audit.KindRevokedNodeDial {
			out = append(out, r)
		}
	}
	return out
}

func dialTimes(r *RevokedDialRecorder, node string, n int) {
	for i := 0; i < n; i++ {
		r.RevokedDial(node)
	}
}

func TestRevokedDialRecorder_FirstDialRecordedAtOnce(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	clk := newDialClock()
	r := NewRevokedDialRecorder(New(repo), clk.Now)

	r.RevokedDial("node-a")

	recs := dialRecords(t, repo, "node-a")
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	got := recs[0]
	if got.NodeID != "node-a" || got.Reason != "suppressed=0" {
		t.Errorf("record = NodeID %q Reason %q, want node-a / suppressed=0", got.NodeID, got.Reason)
	}
	if got.Principal != "" || got.Attribution != (audit.Attribution{}) {
		t.Errorf("record carries an actor: Principal %q Attribution %+v", got.Principal, got.Attribution)
	}
	if !got.Timestamp.Equal(clk.Now()) {
		t.Errorf("Timestamp = %v, want %v", got.Timestamp, clk.Now())
	}
}

func TestRevokedDialRecorder_ThrottledWithinTheHour(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	clk := newDialClock()
	r := NewRevokedDialRecorder(New(repo), clk.Now)

	dialTimes(r, "node-a", 5)
	clk.Advance(59*time.Minute + 59*time.Second)
	r.RevokedDial("node-a")

	if n := len(dialRecords(t, repo, "node-a")); n != 1 {
		t.Fatalf("records = %d, want 1", n)
	}
}

func TestRevokedDialRecorder_NextRecordCarriesTheSuppressedCount(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	clk := newDialClock()
	r := NewRevokedDialRecorder(New(repo), clk.Now)

	dialTimes(r, "node-a", 5)
	clk.Advance(time.Hour)
	r.RevokedDial("node-a")

	recs := dialRecords(t, repo, "node-a")
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2", len(recs))
	}
	if recs[1].Reason != "suppressed=4" {
		t.Errorf("second Reason = %q, want suppressed=4 (the 4 dials after the first)", recs[1].Reason)
	}

	r.RevokedDial("node-a")
	if n := len(dialRecords(t, repo, "node-a")); n != 2 {
		t.Fatalf("records after another dial in the new window = %d, want 2", n)
	}
}

func TestRevokedDialRecorder_ThrottleIsPerNode(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	r := NewRevokedDialRecorder(New(repo), newDialClock().Now)

	dialTimes(r, "node-a", 3)
	r.RevokedDial("node-b")

	if n := len(dialRecords(t, repo, "node-b")); n != 1 {
		t.Fatalf("node-b records = %d, want 1", n)
	}
	if n := len(dialRecords(t, repo, "node-a")); n != 1 {
		t.Fatalf("node-a records = %d, want 1", n)
	}
}

// failFirstAppend fails its first Append and delegates every other call.
type failFirstAppend struct {
	audit.Repository
	failed atomic.Bool
}

func (f *failFirstAppend) Append(ctx context.Context, r audit.Record) error {
	if f.failed.CompareAndSwap(false, true) {
		return errors.New("store unavailable")
	}
	return f.Repository.Append(ctx, r)
}

func TestRevokedDialRecorder_WriteFailureLosesNoCount(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	clk := newDialClock()
	r := NewRevokedDialRecorder(New(&failFirstAppend{Repository: repo}), clk.Now)

	r.RevokedDial("node-a")
	if n := len(dialRecords(t, repo, "node-a")); n != 0 {
		t.Fatalf("records after a failed write = %d, want 0", n)
	}

	clk.Advance(revokedDialWindow)
	r.RevokedDial("node-a")
	recs := dialRecords(t, repo, "node-a")
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	if recs[0].Reason != "suppressed=1" {
		t.Errorf("Reason = %q, want suppressed=1", recs[0].Reason)
	}
}

// commitThenFailAppend persists each record and then reports an error, as a
// commit whose acknowledgement is lost does.
type commitThenFailAppend struct {
	audit.Repository
	attempts atomic.Int32
}

func (f *commitThenFailAppend) Append(ctx context.Context, r audit.Record) error {
	f.attempts.Add(1)
	if err := f.Repository.Append(ctx, r); err != nil {
		return err
	}
	return errors.New("commit acknowledgement lost")
}

func TestRevokedDialRecorder_AmbiguousFailureNeverDuplicatesWithinTheWindow(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	store := &commitThenFailAppend{Repository: repo}
	clk := newDialClock()
	r := NewRevokedDialRecorder(New(store), clk.Now)

	dialTimes(r, "node-a", 5)
	clk.Advance(revokedDialWindow - time.Second)
	dialTimes(r, "node-a", 5)
	if n := len(dialRecords(t, repo, "node-a")); n != 1 {
		t.Fatalf("records within the window = %d, want 1", n)
	}
	if got := store.attempts.Load(); got != 1 {
		t.Fatalf("attempts within the window = %d, want 1", got)
	}

	clk.Advance(time.Second)
	r.RevokedDial("node-a")
	recs := dialRecords(t, repo, "node-a")
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2", len(recs))
	}
	if recs[1].Reason != "suppressed=10" {
		t.Errorf("Reason = %q, want suppressed=10", recs[1].Reason)
	}
}

// failingAppend fails every Append while failing is set and counts attempts.
type failingAppend struct {
	audit.Repository
	failing  atomic.Bool
	attempts atomic.Int32
}

func (f *failingAppend) Append(ctx context.Context, r audit.Record) error {
	f.attempts.Add(1)
	if f.failing.Load() {
		return errors.New("store unavailable")
	}
	return f.Repository.Append(ctx, r)
}

func TestRevokedDialRecorder_FailingStoreIsAttemptedAtMostOncePerWindow(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	store := &failingAppend{Repository: repo}
	store.failing.Store(true)
	clk := newDialClock()
	r := NewRevokedDialRecorder(New(store), clk.Now)

	dialTimes(r, "node-a", 10)
	if got := store.attempts.Load(); got != 1 {
		t.Fatalf("attempts within one window = %d, want 1", got)
	}

	clk.Advance(revokedDialWindow)
	dialTimes(r, "node-a", 10)
	if got := store.attempts.Load(); got != 2 {
		t.Fatalf("attempts after one window = %d, want 2", got)
	}

	store.failing.Store(false)
	clk.Advance(revokedDialWindow)
	r.RevokedDial("node-a")
	recs := dialRecords(t, repo, "node-a")
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	if recs[0].Reason != "suppressed=20" {
		t.Errorf("Reason = %q, want suppressed=20", recs[0].Reason)
	}
}

func TestRevokedDialRecorder_ConcurrentFirstDialsRecordOnce(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	r := NewRevokedDialRecorder(New(repo), newDialClock().Now)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.RevokedDial("node-a")
		}()
	}
	wg.Wait()

	if n := len(dialRecords(t, repo, "node-a")); n != 1 {
		t.Fatalf("records = %d, want 1", n)
	}
}

func TestRevokedDialRecorder_EmptyNodeIDIsIgnored(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	r := NewRevokedDialRecorder(New(repo), newDialClock().Now)

	r.RevokedDial("")

	all, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("records = %d, want 0", len(all))
	}
}
