package events

import (
	"testing"
	"time"
)

func TestBus_FourPublishers_SubscriberFiltersByKind(t *testing.T) {
	b := NewBus()

	sub := b.Subscribe([]Kind{KindJob}, "")
	defer sub.Close()

	b.PublishRegistry(RegistryEvent{Transition: TransitionConnected, NodeID: "node-1"})
	b.PublishJob(JobEvent{Transition: JobCreated, JobID: "job-1"})
	b.PublishToolCall(ToolCallEvent{Tool: "list_nodes"})
	b.PublishEnrollment(EnrollmentEvent{Outcome: EnrollmentAccepted})

	select {
	case ev := <-sub.C():
		if ev.Kind != KindJob || ev.Job == nil || ev.Job.JobID != "job-1" {
			t.Fatalf("unexpected event: %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the job event")
	}

	select {
	case ev := <-sub.C():
		t.Fatalf("subscriber filtered on KindJob received a second event: %+v", ev)
	default:
	}
}

func TestBus_MonotonicIDsAcrossInterleavedKinds(t *testing.T) {
	b := NewBus()
	sub := b.Subscribe([]Kind{KindRegistry, KindJob}, "")
	defer sub.Close()

	b.PublishRegistry(RegistryEvent{Transition: TransitionConnected, NodeID: "n1"})
	b.PublishJob(JobEvent{Transition: JobCreated, JobID: "j1"})
	b.PublishRegistry(RegistryEvent{Transition: TransitionDisconnected, NodeID: "n1"})

	var seqs []uint64
	for i := 0; i < 3; i++ {
		select {
		case ev := <-sub.C():
			seqs = append(seqs, ev.Seq)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for events")
		}
	}
	for i := 1; i < len(seqs); i++ {
		if seqs[i] <= seqs[i-1] {
			t.Fatalf("sequence not strictly increasing: %v", seqs)
		}
	}
}

func TestBus_ResumeInsideBuffer_MissesNothing(t *testing.T) {
	b := NewBus()

	var fourthID string
	for i := 1; i <= 10; i++ {
		id := publishAndCapture(t, b, i)
		if i == 4 {
			fourthID = id
		}
	}

	sub := b.Subscribe([]Kind{KindJob}, fourthID)
	defer sub.Close()

	for want := 5; want <= 10; want++ {
		select {
		case ev := <-sub.C():
			if ev.Kind == KindGap {
				t.Fatalf("unexpected gap event resuming inside the buffer: %+v", ev)
			}
			if ev.Job == nil || ev.Job.Nodes != want {
				t.Fatalf("want job %d, got %+v", want, ev)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for job %d", want)
		}
	}

	select {
	case ev := <-sub.C():
		t.Fatalf("unexpected extra event: %+v", ev)
	default:
	}
}

// publishAndCapture publishes one distinguishable JobEvent and returns its
// assigned ID, captured through a throwaway subscription so the publish
// itself stays untouched by the assertion machinery.
func publishAndCapture(t *testing.T, b *Bus, n int) string {
	t.Helper()
	probe := b.Subscribe([]Kind{KindJob}, "")
	defer probe.Close()
	b.PublishJob(JobEvent{Transition: JobCreated, Nodes: n})
	select {
	case ev := <-probe.C():
		return ev.ID
	case <-time.After(time.Second):
		t.Fatal("timed out capturing published event id")
		return ""
	}
}

func TestBus_ResumeOutsideBuffer_YieldsSingleGap(t *testing.T) {
	b := NewBus(WithRetention(3, time.Hour))

	var firstID string
	for i := 1; i <= 10; i++ {
		id := publishAndCapture(t, b, i)
		if i == 1 {
			firstID = id
		}
	}

	sub := b.Subscribe([]Kind{KindJob}, firstID)
	defer sub.Close()

	select {
	case ev := <-sub.C():
		if ev.Kind != KindGap || ev.Gap == nil || ev.Gap.Reason != GapEvicted {
			t.Fatalf("want GapEvicted, got %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the gap event")
	}

	select {
	case ev := <-sub.C():
		t.Fatalf("gap must not be followed by a replay: %+v", ev)
	default:
	}
}

// TestBus_ResumeReplayOverflow_YieldsSingleGapDeterministically reproduces
// the reviewer's cycle-1 finding: a resume whose replay backlog exceeds
// subscriberBuffer must never deliver a gap-free-looking partial prefix and
// then strand the subscriber in silence. It must see a single gap
// DETERMINISTICALLY, at Subscribe time — not "eventually, if a live event
// happens along."
func TestBus_ResumeReplayOverflow_YieldsSingleGapDeterministically(t *testing.T) {
	b := NewBus()

	var firstID string
	for i := 1; i <= subscriberBuffer+50; i++ {
		id := publishAndCapture(t, b, i)
		if i == 1 {
			firstID = id
		}
	}

	sub := b.Subscribe([]Kind{KindJob}, firstID)
	defer sub.Close()

	select {
	case ev := <-sub.C():
		if ev.Kind != KindGap || ev.Gap == nil || ev.Gap.Reason != GapReplayOverflow {
			t.Fatalf("want GapReplayOverflow, got %+v", ev)
		}
		if ev.Gap.RequestedID != firstID {
			t.Fatalf("want RequestedID %q, got %+v", firstID, ev.Gap)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber was stranded: no gap event ever arrived for an overflowing replay backlog")
	}

	select {
	case ev := <-sub.C():
		t.Fatalf("gap must not be followed by a replay: %+v", ev)
	default:
	}
}

func TestBus_ForeignEpoch_YieldsGapEpochChanged(t *testing.T) {
	b := NewBus()
	b.PublishJob(JobEvent{Transition: JobCreated})

	sub := b.Subscribe([]Kind{KindJob}, "deadbeef-5")
	defer sub.Close()

	select {
	case ev := <-sub.C():
		if ev.Kind != KindGap || ev.Gap == nil || ev.Gap.Reason != GapEpochChanged {
			t.Fatalf("want GapEpochChanged, got %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the gap event")
	}
}

func TestBus_EmptyLastEventID_LiveOnlyNoGap(t *testing.T) {
	b := NewBus()
	b.PublishJob(JobEvent{Transition: JobCreated})

	sub := b.Subscribe([]Kind{KindJob}, "")
	defer sub.Close()

	select {
	case ev := <-sub.C():
		t.Fatalf("fresh subscription with no Last-Event-ID must not replay: %+v", ev)
	default:
	}

	b.PublishJob(JobEvent{Transition: JobCompleted})
	select {
	case ev := <-sub.C():
		if ev.Kind == KindGap {
			t.Fatalf("fresh subscription must never gap: %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the live event")
	}
}

func TestBus_AgeEviction(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b := NewBus(WithClock(func() time.Time { return now }))

	// Two events at T, resumed from the FIRST one's ID after both age out —
	// evictedThrough must land strictly above the requested Seq (both were
	// evicted, not just the one the client is resuming from) for this to be
	// a real gap rather than a clean resume at the eviction boundary.
	firstID := publishAndCapture(t, b, 1)
	publishAndCapture(t, b, 2)

	now = now.Add(11 * time.Minute)
	b.PublishJob(JobEvent{Transition: JobCompleted}) // triggers the age prune

	sub := b.Subscribe([]Kind{KindJob}, firstID)
	defer sub.Close()

	select {
	case ev := <-sub.C():
		if ev.Kind != KindGap || ev.Gap.Reason != GapEvicted {
			t.Fatalf("want GapEvicted after age eviction, got %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the gap event")
	}
}

func TestBus_CountEviction_AtExactly1000(t *testing.T) {
	b := NewBus()
	for i := 0; i < 1001; i++ {
		b.PublishJob(JobEvent{Transition: JobCreated, Nodes: i})
	}
	r := b.rings[KindJob]
	if got := len(r.events); got != defaultMaxEvents {
		t.Fatalf("want %d retained events, got %d", defaultMaxEvents, got)
	}
	if r.evictedThrough != 1 {
		t.Fatalf("want evictedThrough == 1 (the first published Seq), got %d", r.evictedThrough)
	}
}

func TestBus_SlowConsumer_NeverBlocksAndEventuallyGaps(t *testing.T) {
	b := NewBus()
	sub := b.Subscribe([]Kind{KindJob}, "")
	defer sub.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < subscriberBuffer+10; i++ {
			b.PublishJob(JobEvent{Transition: JobCreated, Nodes: i})
		}
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("PublishJob blocked on a full subscriber channel")
	}

	// Drain the full buffer, then publish once more so the queued gap
	// notice — already pending from the drops above — gets its chance to
	// be delivered.
	for i := 0; i < subscriberBuffer; i++ {
		<-sub.C()
	}
	b.PublishJob(JobEvent{Transition: JobCompleted})

	select {
	case ev := <-sub.C():
		if ev.Kind != KindGap || ev.Gap.Reason != GapSlowConsumer {
			t.Fatalf("want GapSlowConsumer, got %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the slow-consumer gap")
	}
}

func TestBus_DisjointSubscriptionsAreIndependent(t *testing.T) {
	b := NewBus()
	jobSub := b.Subscribe([]Kind{KindJob}, "")
	defer jobSub.Close()
	registrySub := b.Subscribe([]Kind{KindRegistry}, "")
	defer registrySub.Close()

	b.PublishJob(JobEvent{Transition: JobCreated})

	select {
	case ev := <-jobSub.C():
		if ev.Kind != KindJob {
			t.Fatalf("want job event, got %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the job event")
	}

	select {
	case ev := <-registrySub.C():
		t.Fatalf("registry subscription received a job event: %+v", ev)
	default:
	}
}

func TestBus_CloseIsIdempotent_AndPublishAfterCloseDoesNotPanic(t *testing.T) {
	b := NewBus()
	sub := b.Subscribe([]Kind{KindJob}, "")
	sub.Close()
	sub.Close() // must not panic

	b.PublishJob(JobEvent{Transition: JobCreated}) // must not panic
}

func TestBus_RaceGuard(t *testing.T) {
	b := NewBus()
	done := make(chan struct{})

	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			b.PublishJob(JobEvent{Transition: JobCreated, Nodes: i})
			b.PublishRegistry(RegistryEvent{Transition: TransitionConnected})
		}
	}()

	for i := 0; i < 50; i++ {
		sub := b.Subscribe([]Kind{KindJob, KindRegistry}, "")
		go func(s *Subscription) {
			for range s.C() {
			}
		}(sub)
		sub.Close()
	}

	<-done
}

// TestBus_RecentReturnsRetainedHistoryOldestFirst is the bootstrap the Console
// renders before it connects: Subscribe with an empty Last-Event-ID is
// live-only, so without Recent a page opened thirty seconds after a failed
// playbook would render an empty list — "nothing tried", which is the one
// conclusion an operator must not draw.
func TestBus_RecentReturnsRetainedHistoryOldestFirst(t *testing.T) {
	b := NewBus()
	b.PublishEnrollment(EnrollmentEvent{Outcome: EnrollmentRejected, TokenID: "first"})
	b.PublishJob(JobEvent{Transition: JobCreated, JobID: "job-1"})
	b.PublishEnrollment(EnrollmentEvent{Outcome: EnrollmentRejected, TokenID: "second"})

	got := b.Recent([]Kind{KindEnrollment}, 10)
	if len(got) != 2 {
		t.Fatalf("Recent returned %d events, want the 2 enrollments", len(got))
	}
	if got[0].Enrollment.TokenID != "first" || got[1].Enrollment.TokenID != "second" {
		t.Fatalf("Recent is not oldest-first: %q then %q",
			got[0].Enrollment.TokenID, got[1].Enrollment.TokenID)
	}
	if got[0].Seq >= got[1].Seq {
		t.Fatalf("Recent did not order by Seq: %d then %d", got[0].Seq, got[1].Seq)
	}
}

// TestBus_RecentClampsToN keeps the NEWEST n, not the oldest: a screen is read
// in the order of what matters now.
func TestBus_RecentClampsToN(t *testing.T) {
	b := NewBus()
	for i := 0; i < 5; i++ {
		b.PublishEnrollment(EnrollmentEvent{Outcome: EnrollmentRejected, TokenID: string(rune('a' + i))})
	}

	got := b.Recent([]Kind{KindEnrollment}, 2)
	if len(got) != 2 {
		t.Fatalf("Recent(2) returned %d events", len(got))
	}
	if got[0].Enrollment.TokenID != "d" || got[1].Enrollment.TokenID != "e" {
		t.Fatalf("Recent(2) returned %q, %q — want the two newest",
			got[0].Enrollment.TokenID, got[1].Enrollment.TokenID)
	}
	if n := b.Recent([]Kind{KindEnrollment}, 0); n != nil {
		t.Fatalf("Recent(0) returned %d events, want none", len(n))
	}
}

// TestBus_RecentTreatsRepeatedAndUnknownKindsAsSets pins the single-kind fast
// path's edges: a kind named twice is still one kind (its ring's tail, not a
// doubled one), and a kind with no ring yields nothing rather than a panic.
func TestBus_RecentTreatsRepeatedAndUnknownKindsAsSets(t *testing.T) {
	b := NewBus()
	b.PublishEnrollment(EnrollmentEvent{Outcome: EnrollmentRejected, TokenID: "a"})
	b.PublishEnrollment(EnrollmentEvent{Outcome: EnrollmentRejected, TokenID: "b"})

	got := b.Recent([]Kind{KindEnrollment, KindEnrollment}, 10)
	if len(got) != 2 {
		t.Fatalf("Recent with a repeated kind returned %d events, want 2", len(got))
	}
	if got := b.Recent([]Kind{Kind("no-such-kind")}, 10); len(got) != 0 {
		t.Fatalf("Recent of an unknown kind returned %d events, want none", len(got))
	}
}

// TestBus_RecentMergesKindsAndFiltersTheRest: one process-global sequence
// multiplexing the kinds asked for, and nothing from the kinds that were not.
func TestBus_RecentMergesKindsAndFiltersTheRest(t *testing.T) {
	b := NewBus()
	b.PublishToolCall(ToolCallEvent{Tool: "raw_exec"})
	b.PublishEnrollment(EnrollmentEvent{Outcome: EnrollmentAccepted})
	b.PublishJob(JobEvent{Transition: JobCreated})

	got := b.Recent([]Kind{KindEnrollment, KindJob}, 10)
	if len(got) != 2 {
		t.Fatalf("Recent returned %d events, want 2", len(got))
	}
	if got[0].Kind != KindEnrollment || got[1].Kind != KindJob {
		t.Fatalf("Recent merged out of order: %s then %s", got[0].Kind, got[1].Kind)
	}
	for _, ev := range got {
		if ev.Kind == KindToolCall {
			t.Fatal("Recent returned a kind that was not asked for")
		}
	}
}

// TestBus_RecentEvictsByAge holds the honesty property day one's copy depends
// on: the screen says "no attempts in the last RetentionWindow()", so Recent
// must not hand it anything older.
func TestBus_RecentEvictsByAge(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b := NewBus(WithClock(func() time.Time { return now }))

	b.PublishEnrollment(EnrollmentEvent{Outcome: EnrollmentRejected, TokenID: "old"})
	now = now.Add(defaultMaxAge + time.Minute)

	if got := b.Recent([]Kind{KindEnrollment}, 10); len(got) != 0 {
		t.Fatalf("Recent returned %d events past the retention window", len(got))
	}
}

// TestBus_RetentionWindowReportsThisBusesBound, not the package default: a
// screen renders the number this method returns, so a Bus built with a
// different bound must report the one it actually has or the copy is a lie.
func TestBus_RetentionWindowReportsThisBusesBound(t *testing.T) {
	if got := NewBus().RetentionWindow(); got != defaultMaxAge {
		t.Errorf("RetentionWindow() = %s, want the default %s", got, defaultMaxAge)
	}
	if got := NewBus(WithRetention(10, time.Minute)).RetentionWindow(); got != time.Minute {
		t.Errorf("RetentionWindow() = %s, want the configured 1m", got)
	}
}
