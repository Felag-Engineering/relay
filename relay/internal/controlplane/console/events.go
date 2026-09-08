package console

// events.go is the Console's ONE live-read path: GET /console/events, a
// server-sent-event stream over the in-process event seam (#416).
//
// # One route, extended per screen — never one route per screen
//
// Spec 11: "One connection per Console session, multiplexing all event kinds;
// screens subscribe to the kinds they render." Day one (#427) implements the
// `enrollment` kind and nothing else. Activity (#422) EXTENDS this route with
// its own projection; a second streaming route would be a second live path and
// would have to be unbuilt (invariant 10).
//
// # Every kind names the role that may see it
//
// This route's own Route.MinRole is RoleViewer (#464), so Register's
// mount-time gate places a floor at "any valid role" and refuses nothing an
// authenticated principal can be — it is not double-gating, and the per-kind
// table below stays the only control that discriminates between kinds. Day
// one (#427) recorded the earlier, ungated state as a deliberate absence and
// said the absence stops being right the moment a second kind is added.
// Activity (#422) adds one, so the gate is here: consoleEventKinds carries a
// MinRole per kind and handleEvents checks it against the acting Principal
// before a stream is opened. Today every admitted kind sits AT the route's
// RoleViewer floor (consoleEventKinds below), not above it; the per-kind
// table is the thing that must move when a kind needing more than Viewer is
// added, not this route's MinRole. A valid role clears the route gate
// unconditionally and is judged again per kind; an INVALID role reaches that
// same per-kind check and is refused there with 403 (events.go, below),
// exactly as before #464 — the route passes it through unwrapped because its
// MinRole is RoleViewer, so #464 changed nothing about where an invalid role
// is refused on this particular route.
//
// THE DISCLOSURE TABLE — for each admitted kind, what the PROJECTION carries
// and why that role:
//
//   - enrollment (viewer): a source address, the PUBLIC half of a token ID,
//     and a refusal reason. Unchanged from #427; every authenticated
//     principal may see them.
//
//   - job (viewer): the JOB ID, a TRANSITION WORD and a TIMESTAMP, and
//     nothing else. Deliberately NOT the Selector, NOT the Operation, NOT the
//     Account, NOT the outcome counts, even though events.JobEvent carries
//     all of them. Viewer-level because accounts.Role defines viewer as "may
//     read ... Jobs and audit", and the same principal can already read the
//     whole dispatch record — with argv — from /console/activity and from
//     /console/jobs/{id}. THE PROJECTION IS THE PRIMARY CONTROL HERE; the
//     role check is the second one.
//
// Two kinds the seam carries STAY OUT, and why:
//
//   - tool_call: events.ToolCallEvent carries raw_exec's full argv. Admitting
//     it is #424's business and needs its own role decision, not a widening
//     that inherits this one.
//   - registry: events.RegistryEvent carries no attribution at all, so it
//     could only ever produce the unattributed rows spec 04's "Must not
//     appear" forbids.
//
// What the gate BUYS today is not a restriction — both admitted kinds are
// viewer-level. It is (a) fail-closed refusal of an unrecognised role, and
// (b) making the next widening impossible to do without naming a role in the
// same edit. TestConsoleEvents_EveryKindNamesTheRoleThatMaySeeIt is the
// tripwire, and it asserts the allowlist's exact SIZE for that reason.
//
// # THE SUBSCRIPTION IS A RECORDED READ (#539)
//
// A subscription to this route is a read of the fleet's live activity, and
// ADR-0025 audits it exactly as it audits QueryJobs or ListNodes: one
// KindRead record, written through capability.Service.RecordEventSubscription
// (the read lane, never a RecordRead call in this package — invariant 10),
// BEFORE d.Events.Subscribe runs.
//
// PER SUBSCRIPTION, NOT PER EVENT. events.Bus.Subscribe builds its kind set
// once, at open, and exposes no method that widens a live Subscription — so
// one record, naming the kinds asked for, completely describes what could
// ever cross the stream for its whole life, including, once #543 admits
// tool_call, whether raw_exec argv could. Recording per event would be the
// first read on this Relay whose trail entry described a RESULT rather than
// a FILTER (ADR-0025 decision 2 forbids exactly that), and would tie the
// trail's write rate to fleet activity times open Console tabs, synchronously
// and fail-closed, on the pump path below — a trail hiccup would kill every
// open Console. What this trades away, plainly: the trail can say who opened
// a watch, over which kinds, and whether it resumed, never which events
// actually crossed or when the stream closed. There is no close record, so
// exposure duration is an open interval an auditor infers from elsewhere.
// Nothing in this codebase may come to depend on the trail answering "did
// this session see Job X's argv" — it does not, and per RecordEventSubscription's
// own doc comment, it will not without a deliberate, separate decision.
//
// A RECONNECT IS ITS OWN RECORD, for free: recording is per HTTP REQUEST, not
// per logical session, so a resume writes a second record naming resume=yes.
// This matters because a resume replays the bus's retained backlog
// immediately on Subscribe — the reconnecting request's exposure window
// starts BEFORE its own timestamp, up to the bus's retention bound. A record
// that did not say "this resumed" would understate exactly the subscriptions
// most likely to be interesting.
//
// FAIL CLOSED, on #450's reasoning verbatim: the record is written before
// Subscribe, so a failure to record means no Subscription was ever created,
// nothing was buffered and nothing replayed — the refusal can honestly say
// nothing was disclosed. There is deliberately no mid-stream audit write and
// therefore no mid-stream failure to decide: that is the direct consequence
// of recording being per-subscription (above), not a separate dodge. Should
// anything ever reintroduce a write during or at the end of an open stream —
// per-event/per-batch recording, a periodic "still open" record, or a
// close/duration record — fail-closed stops being available for it: the
// disclosure will already have happened by the time such a write could fail,
// and a refused close-record could only be logged, never used to undo the
// stream. Decide that separately, deliberately, if it ever comes up; #543
// admitting tool_call does not, because the kind set stays fixed at Subscribe.
//
// THE STREAM SUBSCRIBES TO WHAT THE TRAIL RECORDED, NEVER TO A SEPARATELY
// COMPUTED SET (#539 fix round, Finding 1). The earlier shape of this file
// built wanted.Kinds and wanted.Names in the same loop and argued from that
// sentence alone that they could not drift. A security review defeated the
// argument with one line: replace the wanted.Names argument to
// RecordEventSubscription with strings.Split(r.URL.Query().Get("kinds"), ",")
// — re-deriving what gets RECORDED from the raw query string instead of
// reusing what the loop built — and the entire suite still passed, because
// for a clean query string the re-derivation happens to equal the original.
// The comment was true and the property was still unenforced.
// capability.Service.RecordEventSubscription now returns the canonicalised
// names it actually recorded, and THAT return value — not wanted.Kinds, not
// a second parse of the query string — is the only thing kindsFromNames
// below ever turns into d.Events.Subscribe's argument. A caller cannot
// subscribe to a kind set the trail does not hold a record of, because after
// a successful call there is no other kind set in scope to subscribe with.
//
// # Projection, not marshalling
//
// Nothing here marshals an events.Event. Each kind is projected field by field
// into an explicit struct, for two reasons: a field added to the seam's event
// types later cannot silently reach a browser, and display copy stays in Go —
// one reason table shared by the server-rendered rows and the live ones, so the
// two paths can never word the same refusal differently.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/events"
)

// sseKeepalive and sseWriteTimeout are vars rather than consts for ONE reason:
// the regression test for the HTTP/2 stream teardown described below has to
// watch several keepalive intervals pass, and at the shipping values that is
// forty seconds in the standard test gate. They are unexported, unreachable
// from any surface, and never read from configuration (invariant 11).
var (
	// sseKeepalive is how often a comment frame is written when nothing is
	// happening. It keeps intermediaries from buffering an idle response
	// and, together with the write deadline below, is what turns a dead
	// peer into a returned handler instead of a parked goroutine.
	sseKeepalive = 20 * time.Second

	// sseWriteTimeout bounds ONE frame write, and is armed only for the
	// duration of that write.
	//
	// Why it is needed: the control-plane server sets no WriteTimeout
	// (controlplane/server.go), which is what makes a long-lived response
	// possible at all — and also what makes an unbounded write possible. A
	// client that stops reading without closing the connection (a closed
	// laptop, a dropped link) fills the socket buffer and leaves w.Write
	// blocked with nothing to interrupt it. The keepalive does not rescue
	// that: the keepalive write is itself the write that blocks, and the
	// request context is never cancelled because nothing cancelled it.
	//
	// Why it is CLEARED IMMEDIATELY AFTER EACH WRITE, which is not optional:
	// over HTTP/2 — and the control-plane listener serves h2, since it sets
	// no NextProtos/TLSNextProto and every browser negotiates it — a write
	// deadline is not a bound on a blocking write at all. It arms a
	// PER-STREAM TIMER, and when that timer expires net/http's h2 server
	// sends RST_STREAM(INTERNAL_ERROR) whether or not a write is pending. A
	// deadline left armed therefore kills every idle stream on a fixed
	// schedule: with a 10s deadline and a 20s keepalive, the stream dies at
	// 30s, every time, and the client reconnects successfully and dies again
	// forever. Set it, write, clear it.
	sseWriteTimeout = 10 * time.Second
)

const (
	// maxConcurrentStreams and maxStreamsPerPrincipal bound how many of
	// these a Relay will hold open at once.
	//
	// This is not resource tidiness. Bus.publish walks the entire
	// subscription set holding the bus's single global mutex, and it is
	// called from enrollment, from tunnel-connect and from dispatch — so an
	// unbounded stream count lets the LOWEST role add O(N) work to the lock
	// that gates a Node enrolling and a Job dispatching. Spec 11 says one
	// connection per Console session, so the per-principal cap can be tight;
	// it is above one only so a reconnect overlapping its predecessor, or a
	// second tab, is not refused.
	//
	// There are now TWO live screens (day one and Activity), which still fits
	// inside a cap of four. A THIRD must revisit this number deliberately
	// rather than discovering it: this is a lock-contention control on the
	// path a Node enrolls and a Job dispatches, not tidiness.
	maxConcurrentStreams = 64

	// maxStreamsPerPrincipal is a CONST (#539 fix round, Finding 3 — it was a
	// mutable package var for one release, restored here): its correctness
	// as a var depended on this package never calling t.Parallel, and
	// nothing enforced that. It is still unexported, unreachable from any
	// surface, and never read from configuration (invariant 11); the test
	// seam events_audit_test.go's B7 needs is now streamLimiter.perCap
	// below, a FIELD initialised from this const rather than the const
	// itself, so shrinking the cap for one test mutates one *streamLimiter
	// instance instead of a value every concurrent test in this package
	// shares.
	maxStreamsPerPrincipal = 4
)

// consoleEventKind is one admitted kind and the lowest role that may see its
// projection.
type consoleEventKind struct {
	Kind    events.Kind
	MinRole accounts.Role
}

// consoleEventKinds is the CLOSED allowlist of kinds this route will serve.
// Every entry names a role; see this file's disclosure table for what each
// one's projection carries and why that role is the right one.
var consoleEventKinds = map[string]consoleEventKind{
	"enrollment": {events.KindEnrollment, accounts.RoleViewer},
	"job":        {events.KindJob, accounts.RoleViewer},
}

// sseEnrollment is the projection of one enrollment attempt.
//
// NodeID is deliberately absent: day one navigates to the fleet view the
// moment an attempt is accepted, and never needs it.
type sseEnrollment struct {
	Outcome string `json:"outcome"` // "accepted" | "rejected"

	// Reason is the humanised refusal text, chosen in Go, and is present
	// ONLY on a rejection.
	//
	// That omission is not tidiness. enroll.Server publishes its success
	// with no Reason at all, and eventsink's exhaustive switch maps the
	// resulting zero value through its safe default to
	// events.ReasonInternal — so every ACCEPTED attempt reaches this seam
	// carrying "internal". Rendering it unconditionally would label the
	// first successful enrollment on a brand-new fleet "accepted —
	// internal error", on the one screen whose entire job is that moment.
	Reason string `json:"reason,omitempty"`

	// TokenID is the PUBLIC half of the presented credential, never the
	// secret half and never the plaintext (events.EnrollmentEvent).
	TokenID string `json:"token_id"`
	Source  string `json:"source"`
	At      string `json:"at"` // UTC, the same format screenFuncs "stamp" renders
}

// sseJob is the projection of one Job-grained transition.
//
// THREE STRINGS. events.JobEvent also carries the Selector, the Operation,
// the Account, the risk class, the Node count and eight per-outcome counts,
// and NONE of them crosses this seam: a field that never crosses cannot leak
// through it, and the client needs only "which row, and did it finish".
//
// That is also what keeps the live lane from becoming a second renderer. The
// browser cannot build an Activity row out of this, because the facts a row
// needs are not here — so it counts and it reloads, which is what spec 11's
// "reload the affected region rather than splicing" asks for.
type sseJob struct {
	JobID string `json:"job_id"`

	// Transition is "created", "completed" or "cancelled" — events.JobEvent's
	// own closed vocabulary, passed through rather than re-worded, because
	// the client uses it as a data attribute and not as display copy.
	Transition string `json:"transition"`

	At string `json:"at"` // UTC, the same format screenFuncs "stamp" renders
}

// sseGap is the projection of the seam's own admission that it could not
// deliver a continuous stream. Text is display copy, chosen here for the same
// reason every other string on this route is.
type sseGap struct {
	Text string `json:"text"`
}

// streamLimiter bounds concurrent streams, in total and per principal. One
// instance per route table (handleEvents closes over it), so the bound is
// process-wide and not per-request.
//
// perCap holds the per-principal bound as a FIELD, initialised from the
// maxStreamsPerPrincipal const by newStreamLimiter, rather than reading the
// const directly in acquire (#539 fix round, Finding 3). That is the whole
// fix: the const stays a const — nothing in production code needs it to
// vary — and events_audit_test.go's B7 shrinks ONE *streamLimiter instance's
// field instead of a package-wide var every concurrent test in this package
// would otherwise share.
type streamLimiter struct {
	mu     sync.Mutex
	total  int
	per    map[string]int
	perCap int
}

// newStreamLimiter builds the limiter handleEvents uses in production, with
// the per-principal cap at its shipped default.
func newStreamLimiter() *streamLimiter {
	return &streamLimiter{perCap: maxStreamsPerPrincipal}
}

// acquire takes a slot for key, or reports which bound refused it.
func (l *streamLimiter) acquire(key string) (ok bool, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= maxConcurrentStreams {
		return false, "this Relay is already holding as many live Console streams as it will"
	}
	if l.per[key] >= l.perCap {
		return false, "this Account already has as many live Console streams open as it may"
	}
	if l.per == nil {
		l.per = map[string]int{}
	}
	l.per[key]++
	l.total++
	return true, ""
}

func (l *streamLimiter) release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.per[key] <= 1 {
		delete(l.per, key)
		return
	}
	l.per[key]--
}

// handleEvents streams the kinds named in ?kinds= until the client goes away.
func handleEvents(d Deps) http.HandlerFunc {
	return newEventsHandler(d, newStreamLimiter())
}

// newEventsHandler is handleEvents parameterised by an explicit
// *streamLimiter. Production has exactly one caller, handleEvents above,
// which supplies the shipped default (newStreamLimiter). The parameter
// exists for events_audit_test.go's B7 (#539 fix round, Finding 3): it
// needs a per-principal cap of 1 to reach the limiter's refusal without
// holding maxConcurrentStreams-many streams open, and does it by
// constructing a *streamLimiter with perCap set directly, rather than by
// mutating a package-wide value every concurrent test in this package would
// otherwise share.
func newEventsHandler(d Deps, limiter *streamLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		wanted, ok := parseEventKinds(r.URL.Query().Get("kinds"))
		if !ok {
			http.Error(w,
				"this Console event stream serves the kinds \"enrollment\" and \"job\", and "+
					"nothing else. Name them explicitly in ?kinds=.",
				http.StatusBadRequest)
			return
		}
		if d.Events == nil {
			http.Error(w,
				"the Console cannot open a live event stream: the event seam was not wired into "+
					"this Relay. This is a configuration or build problem, not a quiet fleet.",
				http.StatusServiceUnavailable)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			// Refuse loudly rather than serve a stream that would be
			// buffered until it looked broken.
			http.Error(w, "the Console cannot stream events through this server",
				http.StatusInternalServerError)
			return
		}

		// Bounded before anything is subscribed. The key is the acting
		// principal, resolved by the authentication boundary — every route
		// this package registers sits behind it (Register's contract), so a
		// missing one is a defensive 500 and never a decision made here.
		p, ok := principal(w, r)
		if !ok {
			return
		}
		// The role check, BEFORE a stream slot is taken: a refused caller must
		// not consume one. accounts.Role.AtLeast is used rather than a switch
		// precisely for its fail-closed direction — it ranks an unrecognised
		// role at zero and returns false for every valid want, so an empty,
		// corrupted or future role is REFUSED here rather than admitted.
		//
		// POSITION (1 of 4, #539): the read record below must come AFTER
		// this check, never before it. A refused caller disclosed nothing,
		// and recording a 403 as a read would put non-accesses into read
		// egress's enumeration count — the same reasoning DescribeNode's
		// "record the probe" precedent does NOT extend to a role refusal,
		// because a 403 is not a probe for the existence of anything.
		if !accounts.Role(p.Role).AtLeast(wanted.Needed) {
			http.Error(w,
				"the event kind \""+wanted.NeededFor+"\" needs the role \""+string(wanted.Needed)+"\" on this "+
					"Console. The whole request is refused rather than served without that kind: "+
					"a live region missing one of the kinds it asked for is blind and looks healthy.",
				http.StatusForbidden)
			return
		}

		key := p.AccountID
		if key == "" {
			key = p.Account
		}
		// POSITION (2 of 4, #539): the read record below must come AFTER
		// this acquire, not before it. The 429 is the cheap refusal this
		// code already orders first; an audit-store write in front of it
		// would let any viewer already at their cap make this Relay perform
		// a durable write per attempt — unbounded work behind a bounded
		// check. DescribeNode's "record the probe" precedent does not apply
		// here either: a 429 is not a probe for the existence of anything.
		if allowed, why := limiter.acquire(key); !allowed {
			// 429 with an explanation, and a Retry-After, because the
			// client's own backoff is what will act on it.
			w.Header().Set("Retry-After", "30")
			http.Error(w, why+". Close a Console tab and try again.", http.StatusTooManyRequests)
			return
		}
		defer limiter.release(key)

		// A manual re-open cannot set a header, and the client does its own
		// jittered backoff (spec 11) rather than relying on EventSource's
		// fixed retry — so the query parameter is not a convenience, it is
		// the only way a reconnect can resume.
		lastEventID := r.Header.Get("Last-Event-ID")
		if lastEventID == "" {
			lastEventID = r.URL.Query().Get("last_event_id")
		}

		if d.Queries == nil {
			unavailable(w, "the audit and Job query lane")
			return
		}
		// POSITION (3 of 4, #539): the read record MUST be written before
		// Subscribe, non-negotiable. Subscribe registers this request with
		// the bus, and a resume replays the retained backlog immediately —
		// a record written after Subscribe could not honestly claim that
		// nothing was disclosed.
		//
		// recorded is what actually gets subscribed to, below — never
		// wanted.Kinds (#539 fix round, Finding 1). wanted.Names and
		// wanted.Kinds being built by the same loop was the ORIGINAL
		// argument for why the record and the stream could not drift; a
		// security review showed it was unenforced, because nothing stopped
		// a future edit from re-deriving the RecordEventSubscription
		// argument from somewhere else while leaving the Subscribe argument
		// alone. Building Subscribe's kind set from RecordEventSubscription's
		// own return value removes that possibility structurally: after a
		// successful call, this handler has no OTHER kind list to give
		// Subscribe.
		recorded, err := d.Queries.RecordEventSubscription(r.Context(), p, wanted.Names, lastEventID != "")
		if err != nil {
			readFailed(w, err, "this live event watch")
			return
		}
		kinds, known := kindsFromNames(recorded, consoleEventKinds)
		if !known {
			// Defensive, and should not be reachable for a request that
			// already passed parseEventKinds above: canonicalEventKinds
			// (capability/readlane.go) only sorts and dedups the names this
			// handler validated against consoleEventKinds, so its return
			// should always resolve here too. If it ever does not — a
			// future divergence between the two allowlists, say — refusing
			// is the only safe response: the read has ALREADY been
			// recorded, so opening a stream with a guessed-at kind set
			// would let the record and the stream disagree, which is
			// exactly the failure this whole mechanism exists to prevent.
			http.Error(w, "the Console could not resolve its own recorded kind set to a live stream",
				http.StatusInternalServerError)
			return
		}

		sub := d.Events.Subscribe(kinds, lastEventID)
		// Mandatory. Bus.Close is the only thing that deletes a
		// Subscription from the bus, and every publish fans out to every
		// registered one — a leaked Subscription is a permanent map entry
		// and a 256-slot channel per abandoned request, forever.
		defer sub.Close()

		h := w.Header()
		h.Set("Content-Type", "text/event-stream")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		keepalive := time.NewTicker(sseKeepalive)
		defer keepalive.Stop()

		rc := http.NewResponseController(w)
		// Belt and braces. net/http clears the write deadline itself after
		// each HTTP/1.x request, and each h2 stream owns its own timer, so
		// nothing is known to leak — but the loop below has several exits
		// and none of them should be able to leave a timer armed.
		defer func() { _ = rc.SetWriteDeadline(time.Time{}) }()

		write := func(frame string) bool {
			// Tolerating ErrNotSupported is for httptest.ResponseRecorder,
			// which cannot take a deadline. It is a real hole if a
			// ResponseWriter WRAPPER is ever added to this chain that
			// implements Flush (so it passes the gate above) without
			// Unwrap: the deadline would silently stop being set on a real
			// connection. TestConsoleEvents_WriteDeadlinesSurviveTheMiddleware
			// asserts, over a real connection on both transports, that this
			// branch is not taken in production.
			if err := rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout)); err != nil &&
				!errors.Is(err, http.ErrNotSupported) {
				return false
			}
			if _, err := io.WriteString(w, frame); err != nil {
				return false
			}
			flusher.Flush()
			// Disarm. See sseWriteTimeout: over HTTP/2 a deadline left set
			// is a countdown to RST_STREAM, not a bound on a write.
			_ = rc.SetWriteDeadline(time.Time{})
			return true
		}

		for {
			select {
			case <-r.Context().Done():
				return
			case ev, open := <-sub.C():
				if !open {
					// Close closed the channel. Reading `ev :=` alone
					// would spin on zero values.
					return
				}
				frame, renderable := frameEvent(ev)
				if !renderable {
					continue
				}
				if !write(frame) {
					return
				}
			case <-keepalive.C:
				if !write(": keepalive\n\n") {
					return
				}
			}
		}
	}
}

// eventSubscription is one parsed ?kinds= request: the events.Kind values,
// the exact allowlist names that produced them, and the role gate they
// impose together.
//
// Kinds is NOT what handleEvents hands to d.Events.Subscribe (#539 fix
// round, Finding 1) — that argument is built by kindsFromNames from
// RecordEventSubscription's own return value, so the record and the stream
// cannot drift even under a future edit. Kinds still exists here because
// resolveEventKinds' own tests (dayone_test.go) assert on it directly — most
// usefully, that a refusal returns it nil — and because computing it beside
// Names, from the same allowlist lookup, is what keeps this function honest
// about the fact that every admitted name has both. Names is left
// un-deduped and in request order: events.Bus.Subscribe already folds Kinds
// to a set internally, and the read lane's canonicalEventKinds sorts and
// dedups Names before it lands in the trail, so doing either job here would
// be duplicated work with no consumer.
type eventSubscription struct {
	Kinds     []events.Kind
	Names     []string
	Needed    accounts.Role
	NeededFor string
}

// parseEventKinds resolves a comma-separated kinds parameter against the closed
// allowlist. An empty or unrecognised parameter is refused rather than defaulted:
// this route must never widen by omission.
//
// It also returns the HIGHEST MinRole across the requested kinds, and the name
// of the kind that set it. The whole request is then admitted or refused
// together — a client that asked for job,enrollment and silently got only one
// of them would render a live region that is blind and looks healthy.
func parseEventKinds(param string) (eventSubscription, bool) {
	return resolveEventKinds(param, consoleEventKinds)
}

// resolveEventKinds is parseEventKinds against an explicit allowlist, so the
// accumulation below can be tested against a table this package would never
// ship — which is the only way to test what it does with a MinRole that is not
// a role.
//
// sub.Names is appended in the SAME LOOP, from the SAME `name` variable, that
// appends sub.Kinds, never reconstructed later by re-splitting param — that
// is still true and still worth keeping, because it means sub.Names is a
// faithful record of what this handler actually validated. It is NOT, on its
// own, what keeps the trail and the stream from drifting (#539 fix round,
// Finding 1 corrected the doc comment that used to claim otherwise): nothing
// stopped a later edit from handing something OTHER than sub.Names to
// RecordEventSubscription while still handing sub.Kinds to Subscribe. That
// guarantee now lives in handleEvents building Subscribe's argument from
// RecordEventSubscription's own return value via kindsFromNames, not here.
func resolveEventKinds(param string, allow map[string]consoleEventKind) (sub eventSubscription, ok bool) {
	if param == "" {
		return eventSubscription{}, false
	}
	for _, raw := range strings.Split(param, ",") {
		name := strings.TrimSpace(raw)
		entry, known := allow[name]
		if !known {
			return eventSubscription{}, false
		}
		// An entry whose MinRole is not a role AT ALL is a bug in the table,
		// and the safe reading of a bug in an authz table is REFUSE. It is
		// checked here, before the accumulation below, because the maximum is
		// only well-defined over comparable values: `needed` starts as the
		// empty role, `Role.AtLeast` is false whenever EITHER side is invalid,
		// and an unconditional "raise on !AtLeast" therefore OVERWRITES an
		// invalid requirement with the next valid one — making the result
		// depend on the order the caller listed the kinds in. Refusing here is
		// what lets the loop below be a real maximum.
		if !entry.MinRole.Valid() {
			return eventSubscription{}, false
		}
		sub.Kinds = append(sub.Kinds, entry.Kind)
		sub.Names = append(sub.Names, name)
		// Every MinRole reaching this line is valid, so AtLeast is a total
		// order and this is the maximum. The first entry raises `needed` from
		// the empty role, which satisfies nothing.
		if !sub.Needed.AtLeast(entry.MinRole) {
			sub.Needed, sub.NeededFor = entry.MinRole, name
		}
	}
	return sub, true
}

// kindsFromNames maps names — the CANONICAL names RecordEventSubscription
// just recorded, always, never a set computed independently — back onto the
// events.Kind values d.Events.Subscribe needs, against the same allowlist
// resolveEventKinds validated them against in the first place.
//
// This is the structural half of #539's Finding 1 fix: handleEvents calls
// this on RecordEventSubscription's return value and nothing else, so the
// kind set a stream is opened with is always the one the trail already holds
// a record of — there is no code path left that lets the two disagree,
// because there is no second kind list in scope to disagree with.
//
// A name RecordEventSubscription returns that this map does not recognise
// reports ok=false rather than silently dropping it or guessing: every name
// reaching this function passed resolveEventKinds' own lookup against the
// same allow map moments earlier, so this should be unreachable in
// production, and treating it as anything other than a refusal would be
// exactly the kind of "probably fine" this ticket exists to rule out.
func kindsFromNames(names []string, allow map[string]consoleEventKind) (kinds []events.Kind, ok bool) {
	kinds = make([]events.Kind, 0, len(names))
	for _, name := range names {
		entry, known := allow[name]
		if !known {
			return nil, false
		}
		kinds = append(kinds, entry.Kind)
	}
	return kinds, true
}

// frameEvent renders one event as an SSE frame, or reports that this route does
// not render it.
func frameEvent(ev events.Event) (string, bool) {
	switch ev.Kind {
	case events.KindEnrollment:
		if ev.Enrollment == nil {
			return "", false
		}
		return frame("id: "+ev.ID+"\n", "enrollment", projectEnrollment(*ev.Enrollment, ev.At))

	case events.KindJob:
		if ev.Job == nil {
			return "", false
		}
		return frame("id: "+ev.ID+"\n", "job", projectJob(*ev.Job, ev.At))

	case events.KindGap:
		// NO id: line, not even an empty one. A gap has no position on the
		// sequence it reports a hole in, and an empty id: resets a
		// browser's own Last-Event-ID to "" — which would turn the next
		// reconnect into a fresh session instead of a resume.
		return frame("", "gap", sseGap{Text: gapText(ev.Gap)})

	default:
		return "", false
	}
}

// frame assembles one SSE frame.
//
// json.Marshal escapes newlines inside strings, so no value in the PAYLOAD can
// break the frame's line structure. That guarantee does NOT extend to idLine,
// which is raw concatenation of events.Event.ID — a newline there would split
// one frame into two and let a publisher forge an event on this stream. The
// bus mints IDs as hex plus a sequence number (internal/events), so no such ID
// exists; this is pinned by TestConsoleEvents_FrameIDsCannotBreakFrameStructure
// HERE, where the property is relied on, rather than two packages away where
// it happens to be true.
func frame(idLine, name string, payload any) (string, bool) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", false
	}
	return idLine + "event: " + name + "\ndata: " + string(data) + "\n\n", true
}

// projectEnrollment maps one attempt onto what a browser is allowed to see.
func projectEnrollment(e events.EnrollmentEvent, at time.Time) sseEnrollment {
	p := sseEnrollment{
		Outcome: string(e.Outcome),
		TokenID: e.TokenID,
		Source:  e.Source,
		At:      at.UTC().Format("2006-01-02 15:04:05Z"),
	}
	// See sseEnrollment.Reason: an accepted attempt's reason is meaningless
	// and, as the seam actually delivers it, actively misleading.
	if e.Outcome == events.EnrollmentRejected {
		p.Reason = enrollmentReasonText(e.Reason)
	}
	return p
}

// projectJob maps one Job transition onto what a browser is allowed to see.
//
// Written as an explicit three-field literal rather than a copy of the event,
// so that a field added to events.JobEvent later cannot reach a browser by
// arriving in a struct nobody re-read. See sseJob for what is deliberately
// absent.
func projectJob(e events.JobEvent, at time.Time) sseJob {
	return sseJob{
		JobID:      e.JobID,
		Transition: string(e.Transition),
		At:         at.UTC().Format("2006-01-02 15:04:05Z"),
	}
}

// enrollmentReasonText is the ONE humanisation of a Relay-side refusal, used by
// this stream and by day one's server-rendered rows alike.
//
// These reasons never travel on the wire to the enrolling daemon — every
// rejection Enroll returns still collapses to one codes.PermissionDenied, so
// this vocabulary cannot become an enrollment oracle (enroll.AttemptEvent).
func enrollmentReasonText(r events.EnrollmentReason) string {
	switch r {
	case events.ReasonExpired:
		return "the token had expired"
	case events.ReasonRevoked:
		return "the token had been revoked"
	case events.ReasonUnknown:
		return "no such token"
	case events.ReasonExhausted:
		return "the token had reached its maximum number of uses"
	case events.ReasonMalformed:
		// Deliberately not "the token was malformed". enroll raises this for
		// an empty token or CSR AND for a self-reported label outside the
		// `node:` namespace — a fault in the daemon's own configuration, not
		// in the credential. Naming only the credential sends an operator to
		// re-copy something that was never wrong.
		return "the enrollment request was malformed — an empty token or CSR, " +
			"or a self-label outside the node: namespace"
	case events.ReasonRateLimited:
		return "too many attempts from this source"
	case events.ReasonAtCapacity:
		return "this Relay is at its Node capacity"
	case events.ReasonRevokedMidEnrollment:
		return "the token was revoked while the Node was enrolling"
	case events.ReasonInternal:
		return "the Relay failed to complete the enrollment"
	default:
		return "refused for a reason this Console does not recognise"
	}
}

// gapText says what a gap means in the words the screen needs, rather than
// leaking the seam's reason vocabulary into a browser.
func gapText(g *events.GapEvent) string {
	if g != nil && g.Reason == events.GapEpochChanged {
		return "The Relay restarted, so this watch cannot continue where it left off."
	}
	return "The live watch fell behind and cannot show a continuous history."
}
