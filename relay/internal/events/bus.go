package events

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// defaultMaxEvents and defaultMaxAge are the retention bounds every
	// production Bus uses (#416): a per-publisher ring holds at most 1,000
	// events or 10 minutes of them, whichever comes first. WithRetention
	// overrides both, for tests only — per invariant 11 there is deliberately
	// no flag, RELAY_* env var or route for either bound.
	defaultMaxEvents = 1000
	defaultMaxAge    = 10 * time.Minute

	// subscriberBuffer is the fixed per-Subscription channel capacity. One
	// Subscription serves one Console session — the Console's SSE route
	// creates exactly one per session and Closes it when the request ends.
	subscriberBuffer = 256
)

// publisherKinds is the fixed set of kinds that own a ring buffer. KindGap
// is deliberately absent: it has no publisher and no ring — see the Kind
// doc comment.
var publisherKinds = []Kind{KindRegistry, KindJob, KindToolCall, KindEnrollment}

// Bus is the Relay's one in-process event seam. Construct it with NewBus;
// the composition root (cmd/relay/main.go) owns the single instance every
// producer and every Console session's Subscription shares.
//
// Every publish and every Subscribe/Close takes the same mutex, which is
// what makes "no event can slip between replay and live" (Subscribe) and
// "a publish after Close never panics" (Close) true by construction rather
// than by care at each call site.
type Bus struct {
	epoch string
	seq   uint64
	rings map[Kind]*ring
	subs  map[*Subscription]struct{}
	now   func() time.Time

	maxEvents int
	maxAge    time.Duration

	mu sync.Mutex
}

// Option configures a Bus built by NewBus.
type Option func(*Bus)

// WithClock overrides the Bus's clock (production default: time.Now, UTC).
// Mirrors capability.WithExecClock / mcp.WithClock — a test seam for age
// eviction, never a production knob.
func WithClock(now func() time.Time) Option {
	return func(b *Bus) { b.now = now }
}

// WithRetention overrides the default retention bounds (1,000 events / 10
// minutes). Test-only: see the no-RELAY_*-env-var note on
// defaultMaxEvents/defaultMaxAge above.
func WithRetention(max int, age time.Duration) Option {
	return func(b *Bus) {
		b.maxEvents = max
		b.maxAge = age
	}
}

// NewBus builds a Bus with a fresh, random per-process epoch: 8 bytes,
// hex-encoded. The epoch is folded into every Event ID (epoch + "-" + seq)
// so a client resuming with a Last-Event-ID from BEFORE a Relay restart is
// told GapEpochChanged rather than silently fed a stream that only looks
// continuous — IDs restart at 1 on every restart, and a foreign epoch is
// how Subscribe tells the two apart.
func NewBus(opts ...Option) *Bus {
	b := &Bus{
		rings:     make(map[Kind]*ring, len(publisherKinds)),
		subs:      make(map[*Subscription]struct{}),
		now:       func() time.Time { return time.Now().UTC() },
		maxEvents: defaultMaxEvents,
		maxAge:    defaultMaxAge,
	}
	for _, k := range publisherKinds {
		b.rings[k] = &ring{}
	}

	epochBytes := make([]byte, 8)
	if _, err := rand.Read(epochBytes); err != nil {
		// Only fails if the OS entropy source is broken, which is
		// unrecoverable; same treatment as enroll.randomNodeID and
		// capability.defaultID, but NewBus has no error to return.
		panic("events: mint epoch: " + err.Error())
	}
	b.epoch = hex.EncodeToString(epochBytes)

	for _, o := range opts {
		o(b)
	}
	return b
}

// ring is one publisher's bounded event history: "1,000 events or 10
// minutes, whichever first" (the acceptance criterion, verbatim).
// evictedThrough is the high-water mark of the last Seq this ring ever
// evicted — Subscribe's gap decision (GapEvicted) is "does the caller's
// Last-Event-ID name a Seq at or below this".
type ring struct {
	events         []Event
	evictedThrough uint64
}

// prune drops events older than maxAge, measured against now. Lazy — called
// on publish and on subscribe, never by a background goroutine, so the Bus
// has no lifecycle to own.
func (r *ring) prune(now time.Time, maxAge time.Duration) {
	cutoff := now.Add(-maxAge)
	i := 0
	for i < len(r.events) && r.events[i].At.Before(cutoff) {
		i++
	}
	if i == 0 {
		return
	}
	if evicted := r.events[i-1].Seq; evicted > r.evictedThrough {
		r.evictedThrough = evicted
	}
	r.events = r.events[i:]
}

// append adds ev, then evicts the oldest entries once the ring exceeds
// maxEvents — the count half of "1,000 events or 10 minutes, whichever
// first".
func (r *ring) append(ev Event, maxEvents int) {
	r.events = append(r.events, ev)
	if over := len(r.events) - maxEvents; over > 0 {
		if evicted := r.events[over-1].Seq; evicted > r.evictedThrough {
			r.evictedThrough = evicted
		}
		r.events = r.events[over:]
	}
}

// PublishRegistry publishes one registry transition. See ring/publish and,
// for why this never blocks, publish's doc comment.
func (b *Bus) PublishRegistry(e RegistryEvent) {
	b.publish(KindRegistry, Event{Registry: &e})
}

// PublishJob publishes one Job-grained transition.
func (b *Bus) PublishJob(e JobEvent) {
	b.publish(KindJob, Event{Job: &e})
}

// PublishToolCall publishes one MCP tools/call invocation.
func (b *Bus) PublishToolCall(e ToolCallEvent) {
	b.publish(KindToolCall, Event{ToolCall: &e})
}

// PublishEnrollment publishes one Enroll attempt outcome.
func (b *Bus) PublishEnrollment(e EnrollmentEvent) {
	b.publish(KindEnrollment, Event{Enrollment: &e})
}

// publish assigns kind's ring the next monotonic ID, appends, and
// non-blockingly fans out to every subscriber whose kind set contains kind.
//
// Non-blocking is load-bearing, not an optimization: these four publishers
// sit on the tunnel-connect, enrollment, and dispatch paths, so a slow
// Console must never be able to block a Node connecting or a Job
// dispatching. A subscriber whose channel is full is told the truth (gap)
// on its next chance to receive, rather than served a spliced stream — see
// Subscription.trySend.
func (b *Bus) publish(kind Kind, ev Event) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	r := b.rings[kind]
	r.prune(now, b.maxAge)

	b.seq++
	ev.ID = b.epoch + "-" + strconv.FormatUint(b.seq, 10)
	ev.Seq = b.seq
	ev.Kind = kind
	ev.At = now

	r.append(ev, b.maxEvents)

	for sub := range b.subs {
		if sub.kinds[kind] {
			sub.trySend(ev)
		}
	}
}

// Subscribe registers a new Subscription for kinds, replaying from
// lastEventID under the SAME lock acquisition that decides whether a replay
// is even possible — so no event can slip between the replay snapshot and
// going live.
//
// Gap decision, in order (see the package doc and GapReason):
//
//  1. lastEventID == "": a fresh session. No replay, no gap — it goes live
//     only.
//  2. lastEventID doesn't parse as "epoch-seq", or its epoch isn't this
//     Bus's: GapEpochChanged. This is what makes a Relay restart honest.
//  3. Any subscribed ring's evictedThrough exceeds the requested Seq:
//     GapEvicted.
//  4. The retained backlog (every event with Seq > the requested one,
//     across the subscribed rings) is larger than subscriberBuffer:
//     GapReplayOverflow. Nothing was evicted — the events are all still
//     there — but they cannot all fit through one bounded channel at
//     Subscribe time, so this is reported exactly like every other gap
//     rather than attempted and left to fail silently partway through.
//  5. Otherwise: replay every retained event across the subscribed rings
//     with Seq > the requested one, merged in ascending Seq order — one
//     process-global sequence multiplexing all kinds (spec 11: one
//     connection per Console session), even though the ring buffers
//     themselves are per-publisher.
//
// When gapped, the single KindGap event is the only thing delivered — no
// replay follows it. This holds unconditionally, including when the
// backlog a valid resume point would replay is itself larger than a single
// Subscription's channel: see the GapReplayOverflow branch below. A
// doomed partial delivery — the first subscriberBuffer events landing in
// the channel, looking perfectly ordered and gap-free, with the rest (and
// the gap notice that should follow them) silently dropped because the
// channel is a freshly-created, unread one — would strand the caller in
// silence forever, since nothing but a later LIVE publish ever flushes a
// pendingGap, and no such publish is guaranteed to happen.
func (b *Bus) Subscribe(kinds []Kind, lastEventID string) *Subscription {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	kindSet := b.pruneKinds(kinds, now)

	sub := &Subscription{
		bus:   b,
		kinds: kindSet,
		ch:    make(chan Event, subscriberBuffer),
	}

	switch gap, seq, replay := b.resumePlan(kindSet, lastEventID); {
	case gap != nil:
		gap.At = now
		sub.trySend(*gap)
	case replay:
		events := b.replayBacklog(kindSet, seq)
		if len(events) > subscriberBuffer {
			// The backlog exists and is fully retained — this is not
			// GapEvicted, nothing was evicted — but it cannot fit through
			// one bounded channel at Subscribe time. Deliver a single gap
			// as the SOLE event, exactly like every other gap reason,
			// rather than a trySend loop that would silently truncate at
			// event 256 and leave the rest (including any gap notice)
			// stuck behind a full, unread channel.
			gap := gapEvent(GapReplayOverflow, lastEventID)
			gap.At = now
			sub.trySend(gap)
		} else {
			for _, ev := range events {
				sub.trySend(ev)
			}
		}
	default:
		// A fresh session (lastEventID == ""): no replay, no gap — live
		// only.
	}

	b.subs[sub] = struct{}{}
	return sub
}

// pruneKinds returns kinds as a set, first pruning each kind's ring against
// the age bound as of now. Kinds with no ring are kept in the set and simply
// have nothing to prune. Called with b.mu already held.
func (b *Bus) pruneKinds(kinds []Kind, now time.Time) map[Kind]bool {
	kindSet := make(map[Kind]bool, len(kinds))
	for _, k := range kinds {
		kindSet[k] = true
		if r, ok := b.rings[k]; ok {
			r.prune(now, b.maxAge)
		}
	}
	return kindSet
}

// replayBacklog collects every retained event across kinds' rings with
// Seq > seq, merged in ascending Seq order. Called with b.mu already held.
func (b *Bus) replayBacklog(kinds map[Kind]bool, seq uint64) []Event {
	var events []Event
	for k := range kinds {
		r, ok := b.rings[k]
		if !ok {
			continue
		}
		for _, ev := range r.events {
			if ev.Seq > seq {
				events = append(events, ev)
			}
		}
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Seq < events[j].Seq })
	return events
}

// Recent returns the last n retained events across kinds, oldest first, after
// pruning each requested ring against the age bound.
//
// It exists because Subscribe with an empty Last-Event-ID is live-only. A
// screen that only subscribed would render an empty list for everything that
// happened before the page was opened — a day-one watch loaded thirty seconds
// after a failed playbook would show nothing, and "nothing tried" is the one
// conclusion an operator must not draw from a screen that cannot see the
// difference. A reader bootstraps from Recent, then resumes the stream from the
// newest ID it was handed, so nothing is shown twice and nothing falls between
// the two.
//
// Recent never synthesises a gap: the caller is asking for whatever history
// survives, not for a continuous stream, and it is told nothing about what
// aged out. n <= 0 returns nil.
func (b *Bus) Recent(kinds []Kind, n int) []Event {
	if n <= 0 {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	kindSet := b.pruneKinds(kinds, b.now())

	// One kind is the common case — a screen subscribes to what it renders —
	// and a single ring is already ascending by Seq, so take its tail
	// directly. This matters because every publisher takes b.mu, including
	// enrollment and dispatch: the merge-and-sort path below is O(n log n)
	// over up to maxEvents entries, and running it under this lock for the
	// one-kind case would put a page refresh in front of a Node enrolling.
	if len(kindSet) == 1 {
		r, ok := b.rings[kinds[0]]
		if !ok {
			return nil
		}
		tail := r.events
		if len(tail) > n {
			tail = tail[len(tail)-n:]
		}
		return append([]Event(nil), tail...)
	}

	// Seq 0 is below every published event, so this is "everything retained",
	// merged in ascending Seq order by the same helper Subscribe replays with.
	events := b.replayBacklog(kindSet, 0)
	if len(events) > n {
		events = events[len(events)-n:]
	}
	return events
}

// RetentionWindow is the age half of this Bus's retention bound: nothing it
// holds is older than this, whatever the count bound allowed.
//
// A method rather than an exported constant, because a screen that watches
// this seam STATES the window it can see — day one says "no enrollment
// attempts in the last N minutes" and that sentence has to be true of the bus
// it is actually reading, not of the default a differently-constructed one
// might not have. A constant would be right until the first WithRetention.
//
// Not configuration: there is no flag and no RELAY_* env var for it (see
// defaultMaxAge), and nothing can set it through any surface.
func (b *Bus) RetentionWindow() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.maxAge
}

// resumePlan implements Subscribe's gap decision. Exactly one of its three
// outcomes holds:
//
//   - gap != nil: lastEventID names a foreign epoch or an evicted point —
//     the caller must deliver ONLY this gap notice (its At is unset;
//     Subscribe fills it in) and replay nothing.
//   - replay == true: lastEventID resolved to seq inside every subscribed
//     ring's retained window — the caller replays events with Seq > seq.
//   - neither (gap == nil, replay == false): lastEventID == "", a fresh
//     session — no replay, no gap, live only.
//
// Called with b.mu already held.
func (b *Bus) resumePlan(kinds map[Kind]bool, lastEventID string) (gap *Event, seq uint64, replay bool) {
	if lastEventID == "" {
		return nil, 0, false
	}

	epoch, seqStr, cut := strings.Cut(lastEventID, "-")
	parsedSeq, err := strconv.ParseUint(seqStr, 10, 64)
	if !cut || err != nil || epoch != b.epoch {
		ev := gapEvent(GapEpochChanged, lastEventID)
		return &ev, 0, false
	}

	// Replay covers events with Seq > seq — the ring already retaining
	// exactly Seq is fine; only a Seq strictly below the ring's eviction
	// mark is a real gap.
	for k := range kinds {
		if r, exists := b.rings[k]; exists && r.evictedThrough > parsedSeq {
			ev := gapEvent(GapEvicted, lastEventID)
			return &ev, 0, false
		}
	}

	return nil, parsedSeq, true
}

// gapEvent builds a KindGap Event. Unexported and reachable only from
// Subscribe's gapFor and from Subscription.trySend's slow-consumer branch —
// there is no exported constructor and no Publish method for it (see the
// Kind doc comment and TestExactlyFourPublishMethods).
func gapEvent(reason GapReason, requestedID string) Event {
	return Event{Kind: KindGap, Gap: &GapEvent{Reason: reason, RequestedID: requestedID}}
}

// Subscription is one Console session's live (and, at creation, replayed)
// view of the Bus, filtered to the Kinds it asked for.
type Subscription struct {
	bus   *Bus
	kinds map[Kind]bool
	ch    chan Event

	// pendingGap is set when trySend could not deliver — the channel was
	// full. Once set, delivery is paused: no further real event is pushed
	// to ch until the gap notice itself gets through, so the stream never
	// looks continuous across the hole it just told the truth about.
	pendingGap *GapReason
}

// C returns the Subscription's event channel. Closed by Close.
func (s *Subscription) C() <-chan Event {
	return s.ch
}

// Close deregisters s and closes its channel. Idempotent: a second Close,
// or a publish racing a Close, is safe — both take the Bus's single mutex,
// so a publish can never send on a channel Close is in the middle of
// closing.
func (s *Subscription) Close() {
	s.bus.mu.Lock()
	defer s.bus.mu.Unlock()
	if _, ok := s.bus.subs[s]; !ok {
		return
	}
	delete(s.bus.subs, s)
	close(s.ch)
}

// trySend delivers ev to s without ever blocking. If s has a pending gap
// notice, delivering THAT is attempted first (and, on success, clears the
// pending state) before ev itself is even tried — a subscriber that fell
// behind receives its gap notice before anything published after the hole,
// never interleaved with it. Either send that would block instead marks (or
// re-marks) the subscription gapped and returns without blocking the
// caller — this is what makes Bus.publish and Bus.Subscribe's replay loop
// both non-blocking regardless of how slow or absent the reader is.
func (s *Subscription) trySend(ev Event) {
	if s.pendingGap != nil {
		select {
		case s.ch <- gapEvent(*s.pendingGap, ""):
			s.pendingGap = nil
		default:
			return
		}
	}
	select {
	case s.ch <- ev:
	default:
		reason := GapSlowConsumer
		s.pendingGap = &reason
	}
}
