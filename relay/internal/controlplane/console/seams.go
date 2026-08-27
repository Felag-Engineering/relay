package console

// seams.go declares everything the Console READS. Every interface here is
// satisfied by an object the composition root already holds and already hands
// to the Control API or the MCP surface — none is constructed here, and none of
// them can write anything.
//
// # Why narrow interfaces rather than the real types
//
// Three reasons, in ascending order of how much they matter.
//
// The small one: a screen becomes testable with a struct literal instead of a
// store, a CA and a listener.
//
// The structural one: `no_dispatch_test.go` fails any file in this package that
// type-asserts a narrowed reader back to `registry.Repository`. That guard only
// means something if the Console is HANDED something narrow in the first place —
// an interface with `List` and `Get` on it cannot reach `SetRelayLabels`,
// `SetRevoked`, or `Upsert`, so "the Console cannot change the fleet" is a fact
// about the types rather than a promise about the handlers.
//
// The load-bearing one: reads and writes reach the Relay through different
// doors, and the door is visible in the type. Every method below is a
// projection. Nothing here dispatches, decides, or mutates — the capability
// layer owns all three (invariant 10), and the Console's job is to render what
// it is told and to ask through the same seam every other surface asks through.
//
// # What is deliberately missing
//
// There is no Relay configuration of any kind: no blast cap, no listener, no CA,
// no session lifetime (invariant 11). The one field on Deps that looks like
// configuration — Execution — is a mirror the composition root sets, not a value
// this package can read from anywhere.
//
// There is also no audit QUERY. AuditReader offers whole-trail and by-key reads
// only, because that is what the store offers today; the filtered, paginated,
// per-principal query lane is issue #441 and belongs in the capability layer
// where the Control API can share it. Until it lands, the screens that read the
// trail cap what they render and SAY they capped it — see auditWindow.

import (
	"context"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// FleetReader is the registry, read-only. registry.Repository satisfies it.
//
// Note what is absent: Upsert, SetRelayLabels, SetRevoked. The v0.7.0 label
// management issue (#430) adds writes through the capability layer, NOT by
// widening this interface — a Console that could write a label directly would
// be a second control path, and `relay:` is the security-lane namespace.
type FleetReader interface {
	List() []registry.Node
	Get(nodeID string) (registry.Node, bool)
}

// Liveness answers "is there a live Tunnel to this Node right now".
// *dispatch.Router satisfies it.
//
// This is a separate seam from FleetReader because it is a different KIND of
// fact. The registry's LastSeen is durable history; connectedness is a property
// of a socket that exists this instant. Rendering "last seen 4s ago" as online
// is how a fleet view shows green while every Task resolves `unreachable` —
// ADR-0004 fails a matched-but-disconnected Node fast, without dispatching, and
// the screen has to agree with that or it is lying.
type Liveness interface {
	Connected(nodeID string) bool
}

// PolicyReader is the display-only cache of each Node's daemon-reported
// effective Policy (ADR-0011, invariant 12). *policyview.Cache satisfies it.
//
// "Display-only" is not a disclaimer, it is the invariant: the Relay never
// evaluates Policy and never sets it. This seam returns what a daemon REPORTED,
// with ok=false for a Node that has not reconnected since the last restart —
// which node detail must render as "not reported" rather than as an empty
// Policy, because an empty Policy reads as "this Node permits nothing" and that
// is a different and much more alarming claim.
type PolicyReader interface {
	Get(nodeID string) (policyview.Snapshot, bool)
}

// AuditReader is the append-only trail, read-only. audit.Repository satisfies
// it.
//
// Append is deliberately absent. The Console does cause audit records — a
// sign-in writes one — but it causes them by calling consoleauth, which records
// its own; a screen that could append directly could author history.
type AuditReader interface {
	List(ctx context.Context) ([]audit.Record, error)
	ByJob(ctx context.Context, jobID string) ([]audit.Record, error)
	ByNode(ctx context.Context, nodeID string) ([]audit.Record, error)
}

// ApprovalReader is the pending-approval queue, read-only (ADR-0027).
// *capability.Service satisfies it.
//
// DecideApproval is absent, and that absence is v0.6.0's acceptance criterion
// "zero mutating routes in the Console". Deciding arrives in v0.7.0 (#435)
// behind step-up — and when it does it comes through the capability layer's
// decision method, which is the same one the Control API calls, so quorum,
// audience, requester-exclusion and channel strength are one implementation.
type ApprovalReader interface {
	PendingApprovals(ctx context.Context) ([]approval.Request, error)
	Approval(ctx context.Context, id string) (approval.Request, error)
}

// JobReader reads a Job and its Tasks. The composition root's jobResultReader
// adapter satisfies it.
//
// Task carries captured Stdout/Stderr. Job detail renders it for mutate-class
// Tasks and does NOT render it for read-class ones — ADR-0025 says read output
// is not retained, and the Console must not become the place it quietly is.
type JobReader interface {
	Job(ctx context.Context, jobID string) (jobs.Job, error)
	Tasks(ctx context.Context, jobID string) ([]jobs.Task, error)
}

// FreezeReader reports whether the Relay-wide Freeze is engaged (ADR-0013), for
// the control-plane banner. capability.FreezeStore's read half; the store's
// freeze repository satisfies it.
//
// Engage and Release are absent. Freeze is the top rung of the incident ladder
// and reaches the fleet; it arrives in v0.7.0 through the capability layer,
// which is where its human-principal-only rule already lives (#397).
type FreezeReader interface {
	Frozen(ctx context.Context) (bool, error)
}

// auditWindow caps how many trail records any one screen renders.
//
// The store's only read is "all of it, ordered by timestamp", so a fleet with a
// year of history would have the Console materialise the year and render the
// tail. That is a real limit and this is a real cap, not a page size: there is
// no cursor to follow it with until #441 lands the query lane.
//
// Every screen that hits this cap SAYS SO on the page. A truncated list that
// looks complete is worse than a short one — an operator scanning for a refusal
// that happened yesterday would conclude it never happened.
const auditWindow = 200

// windowed returns the last n records of rs, newest first, and whether the
// window elided anything.
//
// Newest first is a reversal: the repository orders by ascending timestamp
// because that is the order things happened, and a trail is read in the order
// things happened. A SCREEN is read in the order of what matters now, and what
// matters now is the most recent thing.
func windowed(rs []audit.Record, n int) (out []audit.Record, truncated bool) {
	if n <= 0 || len(rs) == 0 {
		return nil, len(rs) > 0
	}
	truncated = len(rs) > n
	if truncated {
		rs = rs[len(rs)-n:]
	}
	out = make([]audit.Record, 0, len(rs))
	for i := len(rs) - 1; i >= 0; i-- {
		out = append(out, rs[i])
	}
	return out, truncated
}
