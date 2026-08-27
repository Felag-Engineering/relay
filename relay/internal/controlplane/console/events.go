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
// # This route carries NO role check, and that is a decision
//
// Route.MinRole is presentation — Register never consults it, so the entry in
// the route table places no gate anywhere. For `enrollment` that is right: an
// attempt carries a source address, the PUBLIC half of a token ID and a
// refusal reason, and every authenticated principal may see them.
//
// It stops being right the moment a further kind is added. events.KindToolCall
// carries raw_exec's full argv; events.KindJob carries Selectors and Operation
// names. ANY KIND BEYOND `enrollment` REQUIRES AN EXPLICIT IN-HANDLER ROLE
// CHECK against the acting Principal, added in the same change that admits the
// kind. TestConsoleEvents_HasNoRoleGateBecauseEnrollmentNeedsNone exists so
// that the absence stays deliberate rather than becoming forgotten.
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
	maxConcurrentStreams   = 64
	maxStreamsPerPrincipal = 4
)

// consoleEventKinds is the CLOSED allowlist of kinds this route will serve.
// Adding to it is the change that requires the role check described above.
var consoleEventKinds = map[string]events.Kind{
	"enrollment": events.KindEnrollment,
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

// sseGap is the projection of the seam's own admission that it could not
// deliver a continuous stream. Text is display copy, chosen here for the same
// reason every other string on this route is.
type sseGap struct {
	Text string `json:"text"`
}

// streamLimiter bounds concurrent streams, in total and per principal. One
// instance per route table (handleEvents closes over it), so the bound is
// process-wide and not per-request.
type streamLimiter struct {
	mu    sync.Mutex
	total int
	per   map[string]int
}

// acquire takes a slot for key, or reports which bound refused it.
func (l *streamLimiter) acquire(key string) (ok bool, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= maxConcurrentStreams {
		return false, "this Relay is already holding as many live Console streams as it will"
	}
	if l.per[key] >= maxStreamsPerPrincipal {
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
	limiter := &streamLimiter{}

	return func(w http.ResponseWriter, r *http.Request) {
		kinds, ok := parseEventKinds(r.URL.Query().Get("kinds"))
		if !ok {
			http.Error(w,
				"this Console event stream serves the kind \"enrollment\" and nothing else. "+
					"Name it explicitly in ?kinds=.",
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
		key := p.AccountID
		if key == "" {
			key = p.Account
		}
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

// parseEventKinds resolves a comma-separated kinds parameter against the closed
// allowlist. An empty or unrecognised parameter is refused rather than defaulted:
// this route must never widen by omission.
func parseEventKinds(param string) ([]events.Kind, bool) {
	if param == "" {
		return nil, false
	}
	var kinds []events.Kind
	for _, name := range strings.Split(param, ",") {
		kind, ok := consoleEventKinds[strings.TrimSpace(name)]
		if !ok {
			return nil, false
		}
		kinds = append(kinds, kind)
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

// frame assembles one SSE frame. json.Marshal escapes newlines inside strings,
// so no rendered value can break the frame's line structure.
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
