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
// The filtered, paginated, per-principal audit/Job query lane landed in the
// capability layer as issue #441 — see QueryReader below. Job detail was the
// first screen to migrate onto it (#423) and reads nothing else: its counts
// are one aggregate row and its Task rows are small per-outcome pages, so
// the screen is bounded by construction at 10,000 Nodes rather than capped
// after the fact. Read egress (#425) migrated next and reads nothing else
// either. Activity (#422) followed, reading BOTH halves of the lane: its
// dispatch rows come from QueryJobs one row per Job at any fan-out, and
// everything else from QueryAudit. AuditReader still offers whole-trail and
// by-Node reads for the screens that have not migrated yet (agent history,
// node detail — #424); until each does, it keeps capping what it renders
// and SAYING it capped it — see auditWindow.

import (
	"context"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/events"
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
// ByJob is deliberately absent: it loaded every record for a Job — including
// every Node's captured output — to render one screen, and that screen (Job
// detail) now reads one bounded page through QueryReader instead. Nothing
// else asked for it, so the seam does not keep offering it.
type AuditReader interface {
	List(ctx context.Context) ([]audit.Record, error)
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

// QueryReader is the capability layer's read lane (#441): filtered,
// paginated, aggregating queries over the audit trail and over Jobs/Tasks.
// *capability.Service satisfies it, exactly as ApprovalReader is satisfied
// above — nothing here dispatches or decides, and the narrowed method set is
// what keeps this package's grip on the capability layer to reads only.
//
// Job detail (#423) was its first consumer, read egress (#425) its second
// and Activity (#422) its third; agent history (#424) follows. Landing the
// seam ahead of any screen using it is what let all four be built against
// one settled contract instead of four independently-guessed ones.
type QueryReader interface {
	QueryAudit(ctx context.Context, p capability.Principal, f capability.AuditFilter, page capability.PageRequest) (capability.AuditPage, error)
	AuditCounts(ctx context.Context, p capability.Principal, f capability.AuditFilter, bucket time.Duration) ([]capability.PrincipalBucket, error)
	AuditReach(ctx context.Context, p capability.Principal, f capability.AuditFilter) (capability.Reach, error)
	QueryJobs(ctx context.Context, p capability.Principal, f capability.JobFilter, page capability.PageRequest) (capability.JobPage, error)
	QueryTasks(ctx context.Context, p capability.Principal, f capability.TaskFilter, page capability.PageRequest) (capability.TaskPage, error)
}

// TrustReader is the two numbers a machine needs in order to decide whether
// this Relay is the one it was told to join (spec 10, ADR-0031). The
// composition root's consoleTrustReader satisfies it.
//
// Two plain strings, deliberately: this package never imports internal/ca, so
// no screen can reach a CA object, a private key, or the certificate issuance
// path from a rendered page.
//
// These are SHA-256 digests over PUBLIC certificate DER. They identify a
// certificate and authenticate nothing on their own, they are derived at
// runtime from certificates this Relay's own CA minted, and they are therefore
// not the "Relay configuration value" spec 10's fifth acceptance criterion
// forbids — nothing here was set by an operator and nothing here is settable
// from any surface.
//
// Note what is still absent, because this is the seam most likely to grow into
// the settings page invariant 11 and foundations rule 7 both forbid: no
// address, no listener, no port, no certificate validity, no CA object. The
// address a Node dials is delivered by whatever installs the daemon, not by
// this Console — and ADR-0031's join string, once built, will carry it.
type TrustReader interface {
	CAFingerprint() string
	ServerFingerprint() string
}

// EventReader is the in-process event seam (#416), read-only. *events.Bus
// satisfies it.
//
// The absence is the load-bearing part, exactly as with AuditReader above: no
// Publish method crosses this seam, so a Console file holding an EventReader
// cannot author a registry transition, a Job transition, a tool call or an
// enrollment attempt. The Console watches history; it never writes it.
//
// TWO guards, because the interface alone is not enough. This package now
// imports internal/events, so a handler could type-assert an EventReader back
// to *events.Bus and recover all four publishers — the same recovery
// no_dispatch_test.go already forbids for registry.Repository. So:
// TestConsole_EventSeamCannotPublish pins the method set here, and
// no_dispatch_test.go fails any non-test file in this package that NAMES
// events.Bus in a type assertion — directly, through a local alias, or through
// an anonymous interface declaring a Publish method — and refuses a dot-import
// of the package, which would erase the qualifier the guard matches on.
//
// Subscribe and Recent both take a kind set, and both accept ANY Kind: the
// narrowing to what a given screen may see is done by the HANDLER's closed
// allowlist (events.go), not by this type. That distinction matters, because
// KindToolCall carries raw_exec's full argv.
//
// RetentionWindow is here so a screen can state the window it can actually
// see, read off the bus it is actually reading (events.Bus.RetentionWindow).
type EventReader interface {
	Subscribe(kinds []events.Kind, lastEventID string) *events.Subscription
	Recent(kinds []events.Kind, n int) []events.Event
	RetentionWindow() time.Duration
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
