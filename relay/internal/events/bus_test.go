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
