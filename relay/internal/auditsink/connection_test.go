package auditsink

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
)

func connectionRecords(t *testing.T, repo audit.Repository, nodeID, kind string) []audit.Record {
	t.Helper()
	all, err := repo.ByNode(context.Background(), nodeID)
	if err != nil {
		t.Fatalf("ByNode: %v", err)
	}
	var out []audit.Record
	for _, r := range all {
		if r.Kind == kind {
			out = append(out, r)
		}
	}
	return out
}

func entryCount(r *ConnectionRecorder) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

func boolp(b bool) *bool { return &b }

// fp returns a well-formed fingerprint made of one repeated hex character.
func fp(c byte) string { return strings.Repeat(string(c), 64) }

func versionEvents(r *ConnectionRecorder, node string, n int) {
	for i := 0; i < n; i++ {
		r.DaemonVersionChanged(node, "0.1.0", "0.2.0")
	}
}

// Proves NC-33.
func TestPolicyChangedReason(t *testing.T) {
	tests := []struct {
		name string
		c    PolicyChange
		n    int
		want string
	}{
		{
			"both set, raw exec true to false",
			PolicyChange{fp('a'), fp('b'), boolp(true), boolp(false)}, 3,
			"policy_fingerprint_before=" + fp('a') + " policy_fingerprint_after=" + fp('b') + " raw_exec_before=true raw_exec_after=false changes=3",
		},
		{
			"before fingerprint empty",
			PolicyChange{"", fp('b'), boolp(false), boolp(false)}, 1,
			"policy_fingerprint_before=none policy_fingerprint_after=" + fp('b') + " raw_exec_before=false raw_exec_after=false changes=1",
		},
		{
			"raw exec unknown",
			PolicyChange{fp('a'), fp('b'), nil, nil}, 2,
			"policy_fingerprint_before=" + fp('a') + " policy_fingerprint_after=" + fp('b') + " raw_exec_before=unknown raw_exec_after=unknown changes=2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := policyChangedReason(tt.c, tt.n); got != tt.want {
				t.Errorf("Reason = %q, want %q", got, tt.want)
			}
		})
	}
}

// Proves NC-34.
func TestDaemonVersionChangedReason(t *testing.T) {
	tests := []struct {
		name          string
		before, after string
		want          string
	}{
		{"downgrade", "0.2.0", "0.1.9", "version_before=0.2.0 version_after=0.1.9 downgrade=true changes=1"},
		{"upgrade", "0.1.9", "0.2.0", "version_before=0.1.9 version_after=0.2.0 downgrade=false changes=1"},
		{"empty before", "", "0.2.0", "version_before=none version_after=0.2.0 downgrade=unknown changes=1"},
		{"empty after", "0.2.0", "", "version_before=0.2.0 version_after=none downgrade=unknown changes=1"},
		{"valid semver over the length bound", "0.2.0", "1.0.0-" + strings.Repeat("a", 250), "version_before=0.2.0 version_after=none downgrade=unknown changes=1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := daemonVersionChangedReason(tt.before, tt.after, 1); got != tt.want {
				t.Errorf("Reason = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCertChangedReason(t *testing.T) {
	if got, want := certChangedReason(fp('a'), fp('b'), 2),
		"cert_fingerprint_before="+fp('a')+" cert_fingerprint_after="+fp('b')+" changes=2"; got != want {
		t.Errorf("Reason = %q, want %q", got, want)
	}
	if got, want := certChangedReason("", fp('b'), 1),
		"cert_fingerprint_before=none cert_fingerprint_after="+fp('b')+" changes=1"; got != want {
		t.Errorf("Reason = %q, want %q", got, want)
	}
}

func TestStreamReplacedReason(t *testing.T) {
	for n, want := range map[int]string{1: "replacements=1", 7: "replacements=7"} {
		if got := streamReplacedReason(n); got != want {
			t.Errorf("streamReplacedReason(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestConnectionReasons_MalformedValueRendersNone(t *testing.T) {
	short := fp('a')[:63]
	upper := strings.ToUpper(fp('a'))

	got := daemonVersionChangedReason("1.0.0 changes=99", "0.2.0", 4)
	if want := "version_before=none version_after=0.2.0 downgrade=unknown changes=4"; got != want {
		t.Errorf("version Reason = %q, want %q", got, want)
	}
	for _, bad := range []string{short, upper} {
		got := certChangedReason(bad, fp('b'), 4)
		if want := "cert_fingerprint_before=none cert_fingerprint_after=" + fp('b') + " changes=4"; got != want {
			t.Errorf("cert Reason for %q = %q, want %q", bad, got, want)
		}
		got = policyChangedReason(PolicyChange{FingerprintAfter: bad}, 4)
		if strings.Count(got, "changes=") != 1 || !strings.Contains(got, "policy_fingerprint_after=none") {
			t.Errorf("policy Reason for %q = %q", bad, got)
		}
	}
}

// Proves NC-36, NC-39.
func TestConnectionRecorder_FirstEventRecordedAtOnce(t *testing.T) {
	kinds := []struct {
		kind   string
		record func(r *ConnectionRecorder)
		suffix string
	}{
		{audit.KindNodePolicyChanged, func(r *ConnectionRecorder) {
			r.PolicyChanged("node-a", PolicyChange{FingerprintAfter: fp('a')})
		}, "changes=1"},
		{audit.KindNodeDaemonVersionChanged, func(r *ConnectionRecorder) { r.DaemonVersionChanged("node-a", "0.1.0", "0.2.0") }, "changes=1"},
		{audit.KindNodeCertChanged, func(r *ConnectionRecorder) { r.CertChanged("node-a", fp('a'), fp('b')) }, "changes=1"},
		{audit.KindNodeStreamReplaced, func(r *ConnectionRecorder) { r.StreamReplaced("node-a") }, "replacements=1"},
	}
	for _, k := range kinds {
		t.Run(k.kind, func(t *testing.T) {
			_, repo, _ := openSinkStore(t)
			clk := newDialClock()
			r := NewConnectionRecorder(New(repo), clk.Now)

			k.record(r)

			recs := connectionRecords(t, repo, "node-a", k.kind)
			if len(recs) != 1 {
				t.Fatalf("records = %d, want 1", len(recs))
			}
			got := recs[0]
			if got.NodeID != "node-a" || !strings.HasSuffix(got.Reason, k.suffix) {
				t.Errorf("record = NodeID %q Reason %q, want node-a / ...%s", got.NodeID, got.Reason, k.suffix)
			}
			if got.Principal != "" || got.Attribution != (audit.Attribution{}) {
				t.Errorf("record carries an actor: Principal %q Attribution %+v", got.Principal, got.Attribution)
			}
			if !got.Timestamp.Equal(clk.Now()) {
				t.Errorf("Timestamp = %v, want %v", got.Timestamp, clk.Now())
			}
			if len(got.Args) != 0 || len(got.Selector) != 0 {
				t.Errorf("record carries Args %v / Selector %v", got.Args, got.Selector)
			}
		})
	}
}

// Proves NC-39.
func TestConnectionRecorder_ThrottledWithinTheWindow(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	clk := newDialClock()
	r := NewConnectionRecorder(New(repo), clk.Now)

	versionEvents(r, "node-a", 5)
	clk.Advance(connectionWindow - time.Second)
	versionEvents(r, "node-a", 1)

	if n := len(connectionRecords(t, repo, "node-a", audit.KindNodeDaemonVersionChanged)); n != 1 {
		t.Fatalf("records = %d, want 1", n)
	}
}

// Proves NC-39.
func TestConnectionRecorder_NextRecordCarriesTheCountAndItsOwnValues(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	clk := newDialClock()
	r := NewConnectionRecorder(New(repo), clk.Now)

	r.DaemonVersionChanged("node-a", "0.1.0", "0.2.0")
	for _, v := range []string{"0.4.1", "0.4.2", "0.4.3", "0.4.4"} {
		r.DaemonVersionChanged("node-a", "0.4.0", v)
	}
	clk.Advance(connectionWindow)
	r.DaemonVersionChanged("node-a", "0.3.0", "0.2.0")
	r.DaemonVersionChanged("node-a", "0.9.0", "0.9.1")

	recs := connectionRecords(t, repo, "node-a", audit.KindNodeDaemonVersionChanged)
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2", len(recs))
	}
	want := "version_before=0.3.0 version_after=0.2.0 downgrade=true changes=5"
	if recs[1].Reason != want {
		t.Errorf("Reason = %q, want %q", recs[1].Reason, want)
	}
	for _, rec := range recs {
		if strings.Contains(rec.Reason, "0.4.") || strings.Contains(rec.Reason, "0.9.") {
			t.Errorf("a suppressed event's value appears in %q", rec.Reason)
		}
	}
}

// Proves NC-36, NC-39.
func TestConnectionRecorder_KindsAreThrottledIndependently(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	clk := newDialClock()
	r := NewConnectionRecorder(New(repo), clk.Now)

	versionEvents(r, "node-a", 3)
	r.CertChanged("node-a", fp('a'), fp('b'))
	r.PolicyChanged("node-a", PolicyChange{FingerprintAfter: fp('a')})
	r.StreamReplaced("node-a")

	for _, kind := range []string{
		audit.KindNodeDaemonVersionChanged, audit.KindNodeCertChanged,
		audit.KindNodePolicyChanged, audit.KindNodeStreamReplaced,
	} {
		if n := len(connectionRecords(t, repo, "node-a", kind)); n != 1 {
			t.Errorf("%s records = %d, want 1", kind, n)
		}
	}
}

// Proves NC-39.
func TestConnectionRecorder_NodesAreThrottledIndependently(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	r := NewConnectionRecorder(New(repo), newDialClock().Now)

	versionEvents(r, "node-a", 3)
	versionEvents(r, "node-b", 1)

	for _, node := range []string{"node-a", "node-b"} {
		if n := len(connectionRecords(t, repo, node, audit.KindNodeDaemonVersionChanged)); n != 1 {
			t.Errorf("%s records = %d, want 1", node, n)
		}
	}
}

// Proves NC-36.
func TestConnectionRecorder_WriteFailureLosesNoCount(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	clk := newDialClock()
	r := NewConnectionRecorder(New(&failFirstAppend{Repository: repo}), clk.Now)

	r.StreamReplaced("node-a")
	if n := len(connectionRecords(t, repo, "node-a", audit.KindNodeStreamReplaced)); n != 0 {
		t.Fatalf("records after a failed write = %d, want 0", n)
	}

	clk.Advance(connectionWindow)
	r.StreamReplaced("node-a")
	recs := connectionRecords(t, repo, "node-a", audit.KindNodeStreamReplaced)
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	if recs[0].Reason != "replacements=2" {
		t.Errorf("Reason = %q, want replacements=2", recs[0].Reason)
	}
}

func TestConnectionRecorder_FailedWriteKeepsTheWindowClosed(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	store := &failingAppend{Repository: repo}
	store.failing.Store(true)
	clk := newDialClock()
	r := NewConnectionRecorder(New(store), clk.Now)

	versionEvents(r, "node-a", 10)
	if got := store.attempts.Load(); got != 1 {
		t.Fatalf("attempts within one window = %d, want 1", got)
	}

	clk.Advance(connectionWindow)
	versionEvents(r, "node-a", 10)
	if got := store.attempts.Load(); got != 2 {
		t.Fatalf("attempts after one window = %d, want 2", got)
	}

	store.failing.Store(false)
	clk.Advance(connectionWindow)
	versionEvents(r, "node-a", 1)
	recs := connectionRecords(t, repo, "node-a", audit.KindNodeDaemonVersionChanged)
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	if !strings.HasSuffix(recs[0].Reason, "changes=21") {
		t.Errorf("Reason = %q, want changes=21", recs[0].Reason)
	}
}

func TestConnectionRecorder_AmbiguousFailureNeverDuplicatesWithinTheWindow(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	store := &commitThenFailAppend{Repository: repo}
	clk := newDialClock()
	r := NewConnectionRecorder(New(store), clk.Now)

	versionEvents(r, "node-a", 5)
	clk.Advance(connectionWindow - time.Second)
	versionEvents(r, "node-a", 5)
	if n := len(connectionRecords(t, repo, "node-a", audit.KindNodeDaemonVersionChanged)); n != 1 {
		t.Fatalf("records within the window = %d, want 1", n)
	}
	if got := store.attempts.Load(); got != 1 {
		t.Fatalf("attempts within the window = %d, want 1", got)
	}
}

func TestConnectionRecorder_FailedWriteLogsOneWarningAndReturns(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	store := &failingAppend{Repository: repo}
	store.failing.Store(true)
	var buf bytes.Buffer
	sink := New(store, WithLogger(slog.New(slog.NewTextHandler(&buf, nil))))
	r := NewConnectionRecorder(sink, newDialClock().Now)

	for i := 0; i < 4; i++ {
		r.DaemonVersionChanged("node-a", "0.1.0", "0.2.0")
	}

	out := buf.String()
	if n := strings.Count(out, "node connection record not written"); n != 1 {
		t.Errorf("warnings = %d, want 1; log: %s", n, out)
	}
	if strings.Contains(out, "0.1.0") || strings.Contains(out, "0.2.0") {
		t.Errorf("the log carries a before or after value: %s", out)
	}
}

// Proves NC-36, NC-39.
func TestConnectionRecorder_SweepDropsIdleEntriesAndKeepsPending(t *testing.T) {
	t.Run("idle entries go, at most once per window", func(t *testing.T) {
		_, repo, _ := openSinkStore(t)
		clk := newDialClock()
		r := NewConnectionRecorder(New(repo), clk.Now)

		r.StreamReplaced("node-a")
		clk.Advance(5 * time.Minute)
		r.StreamReplaced("node-b")
		clk.Advance(5 * time.Minute)
		r.StreamReplaced("node-c") // sweeps node-a out
		if got := entryCount(r); got != 2 {
			t.Fatalf("entries at t0+10m = %d, want 2", got)
		}
		clk.Advance(5 * time.Minute)
		r.StreamReplaced("node-d") // node-b has expired, but no sweep yet
		if got := entryCount(r); got != 3 {
			t.Fatalf("entries at t0+15m = %d, want 3", got)
		}
		clk.Advance(5 * time.Minute)
		r.StreamReplaced("node-e") // sweeps node-b and node-c out
		if got := entryCount(r); got != 2 {
			t.Fatalf("entries at t0+20m = %d, want 2", got)
		}
	})

	t.Run("a pending count survives the sweep", func(t *testing.T) {
		_, repo, _ := openSinkStore(t)
		clk := newDialClock()
		r := NewConnectionRecorder(New(repo), clk.Now)

		r.StreamReplaced("node-a")
		r.StreamReplaced("node-a")
		clk.Advance(connectionWindow)
		r.StreamReplaced("node-b") // sweeps; node-a has a pending count
		if got := entryCount(r); got != 2 {
			t.Fatalf("entries = %d, want 2", got)
		}
		r.StreamReplaced("node-a")
		recs := connectionRecords(t, repo, "node-a", audit.KindNodeStreamReplaced)
		if len(recs) != 2 || recs[1].Reason != "replacements=2" {
			t.Errorf("records = %+v, want a second with replacements=2", recs)
		}
	})

	t.Run("a pending change count survives the sweep", func(t *testing.T) {
		_, repo, _ := openSinkStore(t)
		clk := newDialClock()
		r := NewConnectionRecorder(New(repo), clk.Now)

		r.PolicyChanged("node-a", PolicyChange{FingerprintAfter: fp('a')})
		r.PolicyChanged("node-a", PolicyChange{FingerprintAfter: fp('a')})
		clk.Advance(connectionWindow)
		r.DaemonVersionChanged("node-b", "0.1.0", "0.2.0") // sweeps; node-a has a pending count
		if got := entryCount(r); got != 2 {
			t.Fatalf("entries = %d, want 2", got)
		}
		r.PolicyChanged("node-a", PolicyChange{FingerprintAfter: fp('b')})
		recs := connectionRecords(t, repo, "node-a", audit.KindNodePolicyChanged)
		if len(recs) != 2 || !strings.HasSuffix(recs[1].Reason, "changes=2") {
			t.Errorf("records = %+v, want a second ending changes=2", recs)
		}
	})
}

// Proves NC-36.
func TestConnectionRecorder_FailedEntrySurvivesTheSweep(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	clk := newDialClock()
	r := NewConnectionRecorder(New(&failFirstAppend{Repository: repo}), clk.Now)

	r.StreamReplaced("node-a")
	clk.Advance(connectionWindow)
	r.StreamReplaced("node-b") // sweeps
	if got := entryCount(r); got != 2 {
		t.Fatalf("entries = %d, want 2 (the failed entry and node-b)", got)
	}
	r.StreamReplaced("node-a")
	recs := connectionRecords(t, repo, "node-a", audit.KindNodeStreamReplaced)
	if len(recs) != 1 || recs[0].Reason != "replacements=2" {
		t.Errorf("records = %+v, want one with replacements=2", recs)
	}
}

// Proves NC-36.
func TestConnectionRecorder_ConcurrentFirstEventsRecordOnce(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	r := NewConnectionRecorder(New(repo), newDialClock().Now)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.StreamReplaced("node-a")
		}()
	}
	wg.Wait()

	if n := len(connectionRecords(t, repo, "node-a", audit.KindNodeStreamReplaced)); n != 1 {
		t.Fatalf("records = %d, want 1", n)
	}
}

func TestConnectionRecorder_EmptyNodeIDIsIgnored(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	r := NewConnectionRecorder(New(repo), newDialClock().Now)

	r.PolicyChanged("", PolicyChange{})
	r.DaemonVersionChanged("", "0.1.0", "0.2.0")
	r.CertChanged("", fp('a'), fp('b'))
	r.StreamReplaced("")

	all, err := repo.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 0 {
		t.Errorf("records = %d, want 0", len(all))
	}
	if got := entryCount(r); got != 0 {
		t.Errorf("entries = %d, want 0", got)
	}
}

// Proves NC-36.
func TestConnectionRecorder_ReplacementsInsideTheWindowAreCarriedByTheNextRecord(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	clk := newDialClock()
	r := NewConnectionRecorder(New(repo), clk.Now)
	rows := func() []audit.Record {
		return connectionRecords(t, repo, "node-a", audit.KindNodeStreamReplaced)
	}

	r.StreamReplaced("node-a")
	recs := rows()
	if len(recs) != 1 || recs[0].Reason != "replacements=1" {
		t.Fatalf("records after the first = %+v, want one with replacements=1", recs)
	}

	for range 3 {
		r.StreamReplaced("node-a")
	}
	clk.Advance(connectionWindow - time.Second)
	r.StreamReplaced("node-a")
	if n := len(rows()); n != 1 {
		t.Fatalf("records inside the window = %d, want 1", n)
	}

	clk.Advance(time.Second)
	r.StreamReplaced("node-a")
	recs = rows()
	if len(recs) != 2 || recs[1].Reason != "replacements=5" {
		t.Fatalf("records after the window = %+v, want a second with replacements=5", recs)
	}

	r.StreamReplaced("node-a")
	if n := len(rows()); n != 2 {
		t.Errorf("records inside the new window = %d, want 2", n)
	}
}
