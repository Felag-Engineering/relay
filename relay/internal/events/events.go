// Package events is the Relay's in-process event seam: one bounded,
// in-memory pub/sub with exactly four publishers — registry transitions, Job
// transitions, MCP tool calls, and enrollment attempts — feeding the Admin
// Console's live views, which read it through the Console's SSE route.
//
// The load-bearing property (ADR-0025; D9 in
// docs/design/console/99-open-decisions.md): this package carries tool-call
// ARGUMENTS and never read RESULTS. That is enforced structurally, not just
// by convention, on the mcp package's no_dispatch precedent
// (controlplane/mcp/no_dispatch_test.go): this package may import nothing
// but the standard library, so it can never even NAME a result-shaped type —
// capability.NodeResult, jobs.Task/jobs.Result, and the mcp wire structs all
// carry captured Stdout/Stderr (dispatch.go:44, jobs.go:140). A field-level
// allowlist on ToolCallEvent (below, and mirrored in package mcp's own copy
// of the type) is layered on top, so the property survives someone inlining
// a bare string field. See no_read_output_test.go for the AST guards that
// hold both of these still.
//
// Each producing package owns its own seam type (mcp.ToolCallEvent,
// enroll.AttemptEvent, capability.JobEvent) and never imports this package
// directly — internal/eventsink is the only place they meet events, for
// exactly the reason internal/auditsink is the only place capability meets
// audit.
package events

import "time"

// Kind distinguishes the four publishers, plus the bus-synthesised gap
// notice.
type Kind string

const (
	KindRegistry   Kind = "registry"
	KindJob        Kind = "job"
	KindToolCall   Kind = "tool_call"
	KindEnrollment Kind = "enrollment"

	// KindGap is NOT a publisher — there is no PublishGap. It is synthesised
	// by the Bus itself, only inside Subscribe (a resume that lands outside
	// the retained window) and inside a publish's own fan-out (a subscriber
	// that fell behind) — see bus.go. TestExactlyFourPublishMethods pins
	// this: none of the four exported Publish* methods may mention
	// GapEvent.
	KindGap Kind = "gap"
)

// Event is one item on the bus. Exactly one payload pointer is set, selected
// by Kind.
type Event struct {
	ID   string
	Seq  uint64
	Kind Kind
	At   time.Time

	Registry   *RegistryEvent
	Job        *JobEvent
	ToolCall   *ToolCallEvent
	Enrollment *EnrollmentEvent
	Gap        *GapEvent
}

// RegistryTransition is one of the three registry facts the Console's fleet
// view needs. Heartbeats are deliberately absent: UpdateLastSeen publishes
// nothing at all — internal/eventsink's ObserveRegistry decorator is where
// that omission is enforced, because at a 100k-Node fleet the heartbeat rate
// would evict the connect/disconnect history the Console actually needs,
// thirty times a second.
type RegistryTransition string

const (
	TransitionConnected     RegistryTransition = "connected"
	TransitionDisconnected  RegistryTransition = "disconnected"
	TransitionLabelsChanged RegistryTransition = "labels_changed"
)

// RegistryEvent is one registry transition. RelayLabels is set only on
// TransitionLabelsChanged.
type RegistryEvent struct {
	Transition  RegistryTransition
	NodeID      string
	RelayLabels map[string]string
}

// JobTransition is one of the Job-grained lifecycle facts the Console's Job
// view needs. There is deliberately no per-Task transition and no TaskID
// field on JobEvent: the bus is Job-grained, never Task-grained.
type JobTransition string

const (
	JobCreated   JobTransition = "created"
	JobCompleted JobTransition = "completed"
	JobCancelled JobTransition = "cancelled"
)

// JobEvent is one Job-grained transition. Succeeded/Failed/Timeout/Denied/
// Cancelled/Unreachable/VersionRefused/Unsupported are per-outcome COUNTS
// only — never a per-Node result set, and never Stdout/Stderr. Counts are
// the Job-grained fact; nothing downstream of this type can hold output.
type JobEvent struct {
	Transition JobTransition
	JobID      string
	Account    string
	AccountID  string
	Selector   string
	Operation  string
	RiskClass  string
	Nodes      int

	Succeeded      int
	Failed         int
	Timeout        int
	Denied         int
	Cancelled      int
	Unreachable    int
	VersionRefused int
	Unsupported    int
}

// ToolCallEvent is one MCP tools/call invocation. It carries ARGUMENTS —
// file paths, Selectors, and for raw_exec the full argv; that is the whole
// point of this publisher — and nothing else. Adding a result, output, or
// content field here is precisely the failure no_read_output_test.go exists
// to catch: this bus must never be able to ship what a tool call read back
// or produced, only what it was asked to do (ADR-0025).
type ToolCallEvent struct {
	Tool               string
	Account            string
	AccountID          string
	Arguments          map[string]string
	ArgumentsTruncated bool
}

// EnrollmentOutcome is whether an Enroll attempt was accepted or rejected.
type EnrollmentOutcome string

const (
	EnrollmentAccepted EnrollmentOutcome = "accepted"
	EnrollmentRejected EnrollmentOutcome = "rejected"
)

// EnrollmentReason is the closed vocabulary of Relay-side rejection reasons
// (the Console's day-one screen consumes these). It is deliberately distinct from
// the collapsed codes.PermissionDenied every rejection returns over the
// wire (enroll.Server.Enroll) — the reason travels on this authenticated,
// in-process bus only, never in the RPC response, so it can never become an
// enrollment oracle for the (unauthenticated) enrolling daemon.
type EnrollmentReason string

const (
	ReasonExpired              EnrollmentReason = "expired"
	ReasonRevoked              EnrollmentReason = "revoked"
	ReasonUnknown              EnrollmentReason = "unknown"
	ReasonExhausted            EnrollmentReason = "exhausted"
	ReasonMalformed            EnrollmentReason = "malformed"
	ReasonRateLimited          EnrollmentReason = "rate_limited"
	ReasonAtCapacity           EnrollmentReason = "at_capacity"
	ReasonRevokedMidEnrollment EnrollmentReason = "revoked_mid_enrollment"
	ReasonInternal             EnrollmentReason = "internal"
	ReasonInvalidScope         EnrollmentReason = "invalid_scope"
)

// EnrollmentEvent is one Enroll attempt, accepted or rejected. TokenID is
// the PUBLIC half of the presented credential (the part before
// enroll.secretSep) and is empty when the presented credential did not
// split that way — the plaintext credential never reaches this type at all,
// let alone this field.
type EnrollmentEvent struct {
	Outcome EnrollmentOutcome
	Reason  EnrollmentReason
	TokenID string
	NodeID  string
	Source  string
}

// GapReason is why a Subscription was told gap instead of being handed a
// spliced-together stream.
type GapReason string

const (
	// GapEvicted: the caller's Last-Event-ID names a point the ring buffer
	// no longer retains (aged out or count-evicted).
	GapEvicted GapReason = "evicted"

	// GapEpochChanged: the caller's Last-Event-ID names a foreign epoch — a
	// Relay restart mints a new one, so IDs from before it can never be
	// honored as if the stream were continuous.
	GapEpochChanged GapReason = "epoch_changed"

	// GapSlowConsumer: this Subscription's channel was full, so a live
	// event was dropped rather than blocking the publisher.
	GapSlowConsumer GapReason = "slow_consumer"

	// GapReplayOverflow: the caller's Last-Event-ID names a point still
	// retained by every subscribed ring, but the resulting backlog is
	// larger than a single Subscription's channel can hold. The events
	// were not evicted — GapEvicted would be misleading — they simply
	// cannot all be delivered through one bounded channel at Subscribe
	// time, so Subscribe reports the gap up front instead of delivering a
	// gap-free-looking partial prefix and silently stranding the caller.
	GapReplayOverflow GapReason = "replay_overflow"
)

// GapEvent is the seam's honest admission that it could not deliver a
// continuous stream. RequestedID is the Last-Event-ID the caller presented,
// empty for GapSlowConsumer (nothing was requested; delivery just fell
// behind).
//
// A GapEvent's ID and Seq are always the zero value: a gap has no position
// of its own on the sequence it is reporting a hole in. Subscribe and
// publish's slow-consumer branch fill in only At. The Console's SSE route
// omits the `id:` field for a gap event entirely rather than render an empty
// one — an empty `id:` resets a browser EventSource's own Last-Event-ID to
// "", which would turn the NEXT reconnect into a fresh session instead of a
// resume.
type GapEvent struct {
	Reason      GapReason
	RequestedID string
}
