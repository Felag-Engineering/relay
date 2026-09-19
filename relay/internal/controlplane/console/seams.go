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
// There are now TWO write seams on Deps — JobCanceller (cancel.go, #595) and
// ApprovalDecider (decide.go, #453) — and neither lives in this file, on
// purpose: each gets its own file so this file's "every seam here is
// read-only" claim stays true of seams.go without qualification.
//
// The filtered, paginated, per-principal audit/Job query lane landed in the
// capability layer as issue #441 — see QueryReader below. Job detail was the
// first screen to migrate onto it (#423) and reads nothing else: its counts
// are one aggregate row and its Task rows are small per-outcome pages, so
// the screen is bounded by construction at 10,000 Nodes rather than capped
// after the fact. Read egress (#425) migrated next and reads nothing else
// either. Activity (#422) followed, reading BOTH halves of the lane: its
// dispatch rows come from QueryJobs one row per Job at any fan-out, and
// everything else from QueryAudit. #450 then added the lane's REGISTRY half
// and moved the fleet listing and node detail onto it, which is what made
// those two screens audited (ADR-0025) rather than merely bounded. #542
// moved agent history onto QueryAudit too, reshaping its 200-record WINDOW
// into a 200-row PAGE with an Older link — the last of #450's writing-time
// exemptions to close.
//
// AuditReader now serves exactly ONE thing: node detail's Recent Tasks panel
// and its node_revoke lookup, both read BY NODE through ByNode. That panel is
// covered by the describe_node record node detail already writes for the Node
// it is about; migrating it onto the lane's paging is its own reshaping work,
// not #542's, and until it does AuditReader keeps capping what it renders
// and SAYING it capped it — see nodeTaskRows (node.go).

import (
	"context"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
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
//
// ALSO NOTE WHAT IS ABSENT ON THE OTHER SIDE: a read through here leaves no
// trace. ADR-0025 audits reads because `read` means "cannot change Node
// state", not "safe to see", and the fleet's shape is exactly the disclosure
// it names first. #450 moved the fleet listing and node detail onto
// QueryReader below, which records before it answers; the comparison screen is
// the one caller left here, and read_audit_test.go carries that exemption in
// writing. A new screen reads through QueryReader.
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
//
// List is deliberately absent too, since #542: it was agent history's own
// whole-trail read, and agent history is the last screen that reasoned about
// the trail as one unbounded slice. Deleting the method rather than merely
// leaving it unused is the cheap half of a structural win — a future screen
// physically cannot re-acquire the whole trail through Deps, because there is
// no method here to call. ByNode is what remains, for node detail's Recent
// Tasks panel and its node_revoke lookup.
type AuditReader interface {
	ByNode(ctx context.Context, nodeID string) ([]audit.Record, error)
}

// ApprovalReader is the approval queue and the approval object, read-only
// (ADR-0027). *capability.Service satisfies all five methods.
//
// DecideApproval is still absent FROM THIS INTERFACE, which is still
// read-only — the decision method lives on ApprovalDecider in decide.go
// (#453), for the same reason JobCanceller lives in cancel.go rather than
// here: this file's "every seam here is read-only" header stays true without
// qualification. RequestGrant and RevokeGrant both remain absent from every
// seam this package holds. RevokeGrant is worth naming explicitly because it
// is the one a future editor is most likely to add — closing a window feels
// safer than opening one — and it is still a write on the approval mechanism.
// Deciding, where it is offered, comes through the capability layer's
// decision method, the same one the Control API and MCP call, so quorum,
// audience, requester-exclusion and channel strength stay one implementation.
//
// The three reads beyond the queue are what the approval object renders:
// LastApprovedOfSameShape is the anti-fatigue diff's lookup (#415, D10),
// ActiveGrants tells the queue which pending Requests are Grants, and
// GrantForApproval resolves one Request's Grant IN EVERY STATE — the prior
// Grant a diff compares against is usually the expired or exhausted one
// ActiveGrants cannot return.
type ApprovalReader interface {
	PendingApprovals(ctx context.Context) ([]approval.Request, error)
	Approval(ctx context.Context, id string) (approval.Request, error)
	LastApprovedOfSameShape(ctx context.Context, r approval.Request) (approval.Request, error)
	ActiveGrants(ctx context.Context) ([]approval.Grant, error)
	GrantForApproval(ctx context.Context, requestID string) (approval.Grant, error)
}

// AccountReader is the Account registry and its API Tokens, read-only (#654,
// spec 15). *capability.Service satisfies both methods, which landed on it in
// #653 (PR #657), so no adapter is built for this seam.
//
// EVERY WRITE VERB ON THE ACCOUNT LANE IS ABSENT: CreateAccount,
// SetAccountRole, SetAccountEnabled, MintAPIToken and RevokeAPIToken. As with
// ApprovalReader's RevokeGrant above, one of those is worth naming on its own
// — MintAPIToken is the one a future editor is most likely to add, because
// "the Accounts screen needs a mint button" sounds like a rendering problem.
// It is not: minting is a reveal-once credential issue, it belongs to the
// write half (#655) with its own seam and its own step-up, and it stays off
// this interface however convenient it looks.
//
// Both reads authorize in the capability layer — ControlAccountRead and
// ControlAPITokenRead, both floored at admin (authz.go) — so this Console
// narrows to exactly what that layer permits and widens nothing
// (invariant 10). The Console's own MinRole on the route is the SAME admin
// floor, which makes it mount-time absence rather than a second opinion.
//
// WHAT THESE TWO READS DO NOT DO IS LEAVE A RECORD. Both are authorized and
// answered and write no audit row on success (capability/accountadmin.go's
// header); only a REFUSED read is recorded, through refuseControl. So "who
// holds an identity on this control plane" can be read off this Relay without
// the trail knowing — a gap tracked by #659 against the capability layer,
// where the fix belongs. It is not an ADR-0025 defect (decision 1 scopes to
// non-dispatching read TOOLS, and these are ControlActions), and it is not
// fixable here: a RecordRead call inside this package is exactly what
// read_audit_test.go refuses. console.go's Deps.Accounts paragraph and the
// consoleReadAudit entry for GET /console/accounts say the same thing, so
// whichever of the three a reader lands on tells the whole story.
//
// Account(ctx, p, id) — the single-Account read — is deliberately NOT here.
// The read half selects an Account out of the list it already holds, so
// nothing calls it, and this file's culture is to delete an unused method
// rather than offer it (see AuditReader's List and ByJob). #655 adds it back
// if its writes need it.
type AccountReader interface {
	Accounts(ctx context.Context, p capability.Principal) ([]accounts.Account, error)
	APITokens(ctx context.Context, p capability.Principal, accountID string) ([]accounts.APIToken, error)
}

// QueryReader is the capability layer's read lane (#441): filtered,
// paginated, aggregating queries over the audit trail and over Jobs/Tasks.
// *capability.Service satisfies it, exactly as ApprovalReader is satisfied
// above — nothing here dispatches or decides, and the narrowed method set is
// what keeps this package's grip on the capability layer to reads only.
//
// Job detail (#423) was its first consumer, read egress (#425) its second,
// Activity (#422) its third, and agent history (#542) its fourth. Landing the
// seam ahead of any screen using it is what let all four be built against
// one settled contract instead of four independently-guessed ones.
//
// #450 added the REGISTRY half — ListNodes and DescribeNode. They are on this
// seam rather than on FleetReader for the reason the whole issue exists: a
// read that goes through the capability layer is audited by construction
// (ADR-0025), and a read that goes through FleetReader is not audited at all.
// The fleet listing and node detail were the two screens whose reads
// disclosed the most and recorded the least; they now ask here.
//
// Note the asymmetry with FleetReader, which is deliberate rather than
// leftover: FleetReader still exists, still carries List and Get, and the
// comparison screen still uses it. What a future editor must not do is reach
// for it on a NEW screen because it is one line shorter — read_audit_test.go
// is the guard that makes that choice visible instead of silent.
type QueryReader interface {
	// The registry half (#450). ListNodes is the fleet enumeration;
	// DescribeNode is one Node plus its fingerprint peer counts, which the
	// lane computes so a single-Node screen never has to enumerate the fleet
	// to render two integers.
	ListNodes(ctx context.Context, p capability.Principal) ([]registry.Node, error)
	DescribeNode(ctx context.Context, p capability.Principal, nodeID string) (capability.NodeDetail, error)

	QueryAudit(ctx context.Context, p capability.Principal, f capability.AuditFilter, page capability.PageRequest) (capability.AuditPage, error)
	AuditCounts(ctx context.Context, p capability.Principal, f capability.AuditFilter, bucket time.Duration) ([]capability.PrincipalBucket, error)
	AuditReach(ctx context.Context, p capability.Principal, f capability.AuditFilter) (capability.Reach, error)
	QueryJobs(ctx context.Context, p capability.Principal, f capability.JobFilter, page capability.PageRequest) (capability.JobPage, error)
	QueryTasks(ctx context.Context, p capability.Principal, f capability.TaskFilter, page capability.PageRequest) (capability.TaskPage, error)

	// RecordEventSubscription is the odd one out (#539): the only method here
	// that records a read and returns the canonical form of what it recorded
	// rather than a page of rows. What it covers is read through EventReader
	// below, not through this interface — a subscription to the live event
	// stream is a read of the fleet's activity exactly as QueryJobs is, and
	// ADR-0025 audits it the same way, but the ROWS cross a different seam
	// (Subscribe), never this one. handleEvents calls this BEFORE
	// d.Events.Subscribe; the two must stay adjacent, because a record
	// written after Subscribe could not honestly claim nothing was disclosed.
	//
	// The returned []string is load-bearing, not a convenience (#539 fix
	// round, Finding 1): handleEvents MUST build d.Events.Subscribe's kind
	// list from this return value, never from a kind list it computed
	// earlier or re-derived from the request — that is what makes it
	// structurally impossible for the stream to carry a kind set the record
	// does not name. See capability.Service.RecordEventSubscription's doc
	// comment for the mutation this closes.
	RecordEventSubscription(ctx context.Context, p capability.Principal, kinds []string, resumed bool) ([]string, error)
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
//
// A Subscription through here is a read the trail must know about (#539,
// ADR-0025): handleEvents calls QueryReader.RecordEventSubscription
// immediately before Subscribe, naming the same kinds this call is about to
// carry. The two calls must stay adjacent in handleEvents — this interface
// has no way to enforce that itself, since Subscribe and the record it
// requires live on two different seams.
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
