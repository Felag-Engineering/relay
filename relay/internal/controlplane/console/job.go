package console

// job.go is the record of one dispatch (spec 13).
//
// # The whole design problem
//
// It must be legible at 3 Nodes and at 10,000. Those are not the same screen
// rendered at two sizes — at 3 Nodes an operator wants every row, and at 10,000
// a list of rows is an insult. Two things resolve it:
//
//   - the SEGMENTED OUTCOME BAR, which carries a floor width for minority
//     segments, because 14 denies out of 10,000 is 0.14% of the bar and is the
//     entire reason anyone opened the page;
//   - ORDERING BY INTEREST rather than alphabetically: denied first, then the
//     failures, then the three different kinds of never-ran, then success LAST.
//     Success is the mode, and the mode is the least informative thing here.
//
// # Bounded by construction, not capped after the fact
//
// The counts come from ONE aggregate row — capability.QueryJobs filtered to
// this Job — so the bar is EXACT at any fan-out without a single Task being
// materialised. Rows come from at most one small page per outcome, and the
// success group fetches nothing at all unless the Job is small or the operator
// asked for it. A ten-thousand-Node Job therefore costs the same page as a
// three-Node one, and the screen can never be made to load 10,000 rows by
// anything a caller types in the URL.
//
// The counts being exact is what makes the elision honest: every group states
// how many of its Nodes it listed, and clustering below a sampled group says
// what it clustered over. A page that prints a number it did not compute has
// nothing to offer an operator reading it during an incident.
//
// # The denied group is the showpiece
//
// It renders the Policy rule that fired, verbatim, in mono, with a link to that
// Node's effective Policy. Slate, never red. A deny is the product working
// correctly, and if it ever renders as a failure the product is arguing against
// itself. Denies are clustered BY RULE: when they all fired the same one the
// page says so and shows it once, and when they differ each rule is shown with
// the count that fired it.
//
// # Read-class Jobs carry no output, at any age
//
// ADR-0025: reading is exfiltration, and the AUDIT TRAIL never retains read
// output. This page shows a read Job's outcomes and timings and does not
// promise a detail view that will show the output later, because there will not
// be one here.
//
// It says that precisely, because the stronger sentence is not true: the Task
// row still holds what the daemon sent until the Job is collected (store/
// tasks.go persists it unconditionally) and the Control API and MCP both hand
// it back. Telling an incident responder the bytes do not exist, when a
// GET /api/v1/jobs/{job_id} away they do, is a claim this code cannot back.
//
// The gate is the DECLARED risk class on the Task (tasks.risk_class, carried
// through capability.TaskRow), not a name this package recognises. The read
// lane has already stripped output for every Task whose class is not mutate;
// this page then declines to render it a second time, so a wrong guess about
// an Operation's class cannot turn into retained output on screen.
//
// # The page's one control (v0.7.0, #595)
//
// Cancel is offered to operator and above while any Task is unresolved, and
// it is the capability layer's decision, not this page's — cancelOffered
// (cancel.go) only narrows what is drawn to what routesFor would let this
// session reach. The result block below the header reads the job_cancel
// audit record (cancelRecord), never a query-string flash, so a crafted link
// cannot make this page claim a Task "was asked to stop" that never was.
// That read is CONDITIONAL — only when something is cancelled or still in
// flight — so a complete Job with nothing cancelled pays exactly what it did
// before this issue (TestJob_TenThousandNodesRendersNoList's
// auditCalls == 1 guard).
//
// # Attribution (#455)
//
// The approval half of the header is rendered from the ONE d.Approvals.Approval
// read buildJobView already made for the plan hash — no new read, no new audit
// record. Each approver's lane follows Decision.AccountID exactly as the
// requester's own chip follows RequesterAccountID above: an approval carrying a
// name but no AccountID renders dashed, never hard-coded verified. The
// approver's own on-behalf-of assertion (ADR-0029) stays in that same dashed
// lane, beside the decider's chip rather than merged into it. A Grant-released
// Job never shows a plan hash in the Job's slot: the Grant's Request.PlanHash is
// a hash over the Grant's Scope, not over this Job's Plan, and showing it there
// would train an operator to compare the wrong two hashes. The approval's own
// requester is shown, with its own trust chip, only when it differs from the
// Job's — release happens on the plan hash alone, so the Account that parked
// the approval need not be the Account that dispatched.

import (
	"cmp"
	"context"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// outcomeInterest orders the result groups. Lower sorts first.
//
// This is the spec's ordering made executable, and it is worth stating why each
// position is where it is: a deny means Policy made a decision and someone
// should read it; a failure means something ran and broke; the three never-rans
// are diagnostics about the fleet rather than about the command; a cancel is a
// human's own act; success is what was supposed to happen.
var outcomeInterest = map[jobs.Outcome]int{
	jobs.OutcomeDeniedByPolicy: 0,
	jobs.OutcomeFailure:        1,
	jobs.OutcomeTimeout:        2,
	jobs.OutcomeUnreachable:    3,
	jobs.OutcomeVersionRefused: 4,
	jobs.OutcomeUnsupported:    5,
	jobs.OutcomeCancelled:      6,
	jobs.OutcomeSuccess:        7,
}

const (
	// jobGroupRows is how many Nodes one group lists by default. It mirrors
	// fleet.go's deviationRows for the same reason: past a couple of dozen
	// rows a group has stopped being read and started being scrolled past.
	jobGroupRows = 25

	// jobGroupExpanded is the ceiling when an operator explicitly expands one
	// group with ?show=. "Show all" on a 9,797-Node group is still not a list
	// of 9,797 — the request is honoured up to a bound the page states, which
	// is the difference between a disclosure ladder and a denial-of-service
	// an operator inflicts on themselves.
	jobGroupExpanded = 100

	// legibleJob is the Task count at or below which EVERY group lists
	// everything, success included. Mirrors fleet.go's legibleGroup: "a list
	// is a bug" is a claim about ten thousand Nodes, not about three, and a
	// three-Node Job whose successes are collapsed has hidden the whole Job.
	legibleJob = 50

	// maxOutputBytes bounds how much of one Task's captured output is
	// rendered. The daemon's own cap is 1 MiB (daemon/src/config.rs
	// MAX_OUTPUT_BYTES), which is a reasonable thing to store and an
	// unreasonable thing to put on a screen once per Node.
	maxOutputBytes = 2048

	// maxJobIDBytes bounds the path segment before it becomes a query filter.
	// A Job ID this Relay issued is 32 hex characters; anything longer is not
	// one, and refusing it here keeps a caller-controlled value out of the
	// read lane's audit record. Matches the read lane's own bound.
	maxJobIDBytes = 128
)

// clusterFloor is the number of identical results at which a cluster collapses
// to "N identical — one shown" instead of listing each.
const clusterFloor = 3

// taskRow is one Node's result within a group.
type taskRow struct {
	NodeID   string
	NodeHref string

	// ExitCode is rendered only when ShowExit. Three producers put a sentinel
	// here, never a real process result. The daemon uses -1 for "no exit
	// status": denied before spawn, spawn failure, signal kill, timeout kill.
	// A Relay-synthesized outcome (unreachable, version_refused) carries a
	// zero that means nothing at all. And since #632, the Relay itself writes
	// -1 on a failure row whose daemon report the wire boundary refused as a
	// protocol violation — the Task may well have executed; what happened
	// there is unknown.
	//
	// The Control API omits the field for the same reason (execution.go makes
	// it a pointer). Rendering "exit -1" beside a deny invites an operator to
	// read "did not run" as a real process result, and "exit 0" beside
	// `unreachable` is worse: it says the thing succeeded.
	ExitCode int32

	// ShowExit is true only when the code says something the outcome does not
	// already imply. `success` implies zero, so "exit 0" beside a success chip
	// is noise — and worse than noise here, because .exit is painted in the
	// failure colour, and the budget reserves muted red for failure and timeout
	// and nothing else, ever. A green row with a red "exit 0" on it spends the
	// one alarming colour in the product on the least alarming event in it.
	ShowExit bool
	Output   string

	// Clipped is set when Output was cut to maxOutputBytes. It says only what
	// this page can stand behind — how much of what the Relay stored is on
	// screen. Whether the DAEMON truncated the Task's output at its own 1 MiB
	// cap is not readable from the Task lane (jobs.TaskSummary carries no
	// Truncated field and the tasks table has no column for it), so the page
	// does not claim either way.
	Clipped bool

	Deny *Deny

	// RuleKnown says the Deny's rule is the DAEMON'S VERDICT rather than
	// denyText's explanation of why there is none. It is what the deny
	// group's clustering keys on being true: the explanation is identical on
	// every Node, so clustering on it would report agreement between Nodes
	// that this Relay never observed.
	RuleKnown bool

	// Sent is true when this Task's DispatchedAt is non-zero (#595). It is
	// what the cancelled group clusters on: MarkCancelled (store/tasks.go)
	// only transitions a still-Pending Task and never sets DispatchedAt, so
	// a zero value on a cancelled Task means it never left the Relay at
	// all, and a non-zero one means it was sent and then stopped.
	Sent bool
}

// outcomeGroup is one collapsible block: every Node that reported one outcome.
type outcomeGroup struct {
	Outcome jobs.Outcome
	Label   string

	// Count is EXACT at any fan-out — it comes from the Job aggregate, not
	// from counting the rows below it. Listed is how many of those Nodes this
	// render actually fetched, and Elided is the rest.
	Count  int
	Listed int
	Elided int

	// Sampled reports that the rows below are a page of the group rather than
	// the group. Everything computed FROM the rows — the clusters — then says
	// so, because "9,797 identical" over 25 sampled rows is a number the page
	// did not compute.
	Sampled bool

	// ShowAllHref is the one-more-click expansion, capped at ShowAllCount.
	ShowAllHref  string
	ShowAllCount int

	// RowsError is set when the group's row query failed. The heading and the
	// count still render — they came from the aggregate, which succeeded — so
	// a failed row fetch costs the operator the detail and never the page.
	RowsError bool

	// Clusters group identical output within the group — or, in the denied
	// group, identical RULES. "9,797 identical (view one) · 3 differ" is the
	// pre-aggregation stand-in for the v0.9.0 histogram primitive, laid out so
	// that primitive slots into the same component: it replaces what computes
	// the counts and nothing about the shape of the answer.
	Clusters []outputCluster

	// SharedRule is set when every deny the page listed fired the same rule
	// AND the page listed all of them. Then the rule is shown once and the
	// page says so, instead of printing one identical block per Node.
	SharedRule string

	// Open is whether the group renders expanded. Anything interesting is open;
	// success is not, because success is the mode.
	Open bool
}

// outputCluster is a set of Nodes that reported the byte-identical thing —
// captured output in most groups, the deciding Policy rule in the denied one.
type outputCluster struct {
	// Key is what the rows share. It is not rendered: the rows carry the
	// output and Deny carries the rule, and printing the key as well would
	// print the same bytes twice.
	Key   string
	Count int
	Rows  []taskRow

	// Deny is the refusal every row in this cluster reported, set only in the
	// denied group. One block per rule, with the count that fired it.
	Deny *Deny

	// RuleKnown mirrors taskRow.RuleKnown for the cluster's rows, so the label
	// can say "N fired this rule" only when that is what happened.
	RuleKnown bool

	// NeverSent mirrors taskRow.Sent (inverted) for the cluster's rows, set
	// only in the cancelled group (#595): it is what lets the label say
	// "N never sent" for one cluster and "N sent and then stopped" for the
	// other, so the two kinds never read as one "identical" thing.
	NeverSent bool

	// Representative is true for a cluster rendered as "N identical, here is
	// one". A cluster of one is not a cluster and renders as itself.
	Representative bool
}

type jobView struct {
	ID string

	// Created is the dispatch time. There is deliberately no FINISHED
	// timestamp: jobs.JobSummary carries no completion time, and the only way
	// to compute one is MAX(resolved_at) over every Task — which is the
	// full-table read this screen exists to not do. State says running or
	// complete, which is the question the header is actually asked.
	Created time.Time
	State   string

	Operation string
	// RawExecTier is set only from the recorded ActionKind through
	// jobRowName, never from a name — the same rule as activityRow.
	RawExecTier bool
	Args        string
	Risk        string
	RiskClass   jobs.RiskClass
	ReadClass   bool

	Principal  string
	Verified   bool
	OnBehalfOf string

	// RequesterKind is the requester's kind as the Job row recorded it when
	// the Job was created (capability.JobSummary.RequesterKind): "human",
	// "machine", or empty for a Job that recorded none. It is read from
	// nothing else — not the dispatch record (which carries no kind), and
	// never the Account registry, which would report the Account's kind
	// today and relabel history once an Account is converted (#540;
	// 04-activity.md, "Kind is never read from the registry").
	// A Job whose Principal fell back to the dispatch record has no recorded
	// requester on its row, so this is empty for it too.
	RequesterKind string

	ApprovalID   string
	ApprovalHref string
	GrantID      string

	// Approval carries who gated this dispatch, under which rule, at what
	// quorum, and what the Relay-authored Summary told them — rendered from
	// the same Approval() read that already resolved the plan hash below, so
	// the auditor never has to open a second screen. Nil when the dispatch
	// was never gated, or when the approval record itself could not be
	// resolved (see ApprovalError and ApprovalReaderMissing).
	Approval *jobApproval

	// ApprovalError is set when v.ApprovalID names a record that could not be
	// read. ApprovalReaderMissing is set when this Console has no approval
	// seam wired at all. The two are stated distinctly: one is a store
	// failure, the other is a deployment that never wired the read.
	ApprovalError         bool
	ApprovalReaderMissing bool

	// DispatchFound mirrors dispatchRecord's own ok return. It is false for a
	// normal in-flight Job — the Job engine writes the dispatch record only
	// after the dispatch returns — and the Plan note below must not claim
	// such a Job "was not gated by an approval", which is a fact it cannot
	// know yet.
	DispatchFound bool

	// Plan is the Plan this Job was DISPATCHED against, rendered by the shared
	// renderer. It carries no verdicts (a dispatched Job has outcomes, not
	// predictions) and no cap: the Console is never told a blast cap and must
	// not grow a path to one (invariant 11).
	Plan Plan

	// PlanHashKnown is false for an ungated dispatch. Nothing in the Relay
	// retains a plan hash for one, so the page says that rather than showing
	// some other identifier in the hash's place.
	PlanHashKnown bool

	FanOut   int
	InFlight int
	Bar      OutcomeBar
	Groups   []outcomeGroup

	// TrailError is set when the dispatch record could not be read. The
	// aggregate half of the page is unaffected, so the page renders and names
	// what is missing from it.
	TrailError bool

	// Cancel is the rendered control (#595), set only when v.InFlight is
	// above zero AND cancelOffered(d, caller's role) is true. Nil omits the
	// control entirely rather than rendering a disabled one — the same
	// mount-time-absence posture every gated route in this package takes.
	Cancel *JobCancel

	// CancelRequest is set when a job_cancel audit record exists for this
	// Job (cancelRecord) — the non-forgeable source for "a cancel was asked
	// for, by whom, when". Nil when no cancel was ever requested, which
	// includes a Job whose Tasks read cancelled because IT was halted some
	// other way (a future incident-ladder action): the page must not
	// attribute that to a cancel request it cannot prove happened.
	CancelRequest *cancelRequest

	// CancelledCount mirrors sum.Counts[jobs.OutcomeCancelled] — the exact
	// count from the aggregate, never a count of rows this page fetched.
	CancelledCount int

	// CancelTrailError is set when the job_cancel record could not be read.
	// The rest of the page is unaffected: the groups below come from the
	// Tasks, not from this read.
	CancelTrailError bool

	Found bool
}

// cancelRequest is the rendered form of one job_cancel audit record: who
// asked and when. capability.AuditRow's Principal/Verified/Timestamp,
// projected the same way v.Principal/v.Verified already are above.
type cancelRequest struct {
	Principal string
	Verified  bool
	At        time.Time
}

// jobDecider is one approving Decision, projected onto the same verified/
// asserted grammar as the requester chip above it.
type jobDecider struct {
	// Account and Verified are the decider's own identity — the VERIFIED lane
	// only when the decision itself carried an Account ID, exactly the rule
	// the page already applies to the requester (Verified = AccountID != "").
	// An unattributed decision must never render as though the Relay
	// authenticated it.
	Account  string
	Verified bool

	// Kind is deciderKind(Decision.DeciderHuman): "human" or "machine", read
	// from the decision's own record and never from the Account registry
	// (#540). Both render as the kind label beside the chip, so a machine-
	// issued approval never reads like a person's and a person's is not the
	// unmarked case.
	Kind string

	// OnBehalfOf is the decider's own asserted human (ADR-0029) — the caller
	// said this decision speaks for someone; nothing checked it. It renders in
	// its own dashed chip, never folded into Account's lane.
	OnBehalfOf string

	Channel string
	At      string
	Reason  string
}

// jobApproval is the approval that released this Job, rendered on the Job
// screen itself rather than requiring a second one. Built from the same
// approval.Request read buildJobView already made for the plan hash.
type jobApproval struct {
	// Rules is Request.MatchedRules — which gate rule parked this dispatch.
	Rules []string

	// Summary is the Relay-authored description the approver was shown,
	// stored at park time and never re-rendered from today's fleet.
	Summary string

	// Signed and Required are the quorum. Required is 0 for a record with no
	// stored Requirement, and the template says so rather than claiming
	// "0 of 0".
	Signed   int
	Required int

	// Short is true when the record holds fewer approvals than Required — a
	// defensive render, stated and never hidden, for a record this page did
	// not expect to see incomplete on a released Job.
	Short bool

	// Deciders holds only the APPROVING Decisions, in stored order. A
	// released Job's Request carries no terminal deny (one is terminal), so
	// this is every decision that mattered.
	Deciders []jobDecider

	// ViaGrant is true when this Job was released by a Grant rather than by
	// its own Plan being approved directly. The approvers below approved a
	// window, not this plan.
	ViaGrant bool

	// ParkedBy/ParkedByVerified are who asked for the approval itself, and
	// ParkedByDiffers is true only when that Account is not the Job's own
	// requester — release happens on the plan hash alone (capability.
	// checkApproval), so the two need not match, and the page shows the
	// approval's own requester only in that uncommon case.
	ParkedBy         string
	ParkedByVerified bool
	ParkedByDiffers  bool
}

// newJobApproval projects one approval.Request onto the Job screen's
// attribution section. jobRequesterID and jobRequesterName are the Job's own
// requester, verified-lane-first, used only to decide ParkedByDiffers.
func newJobApproval(req approval.Request, viaGrant bool, jobRequesterID, jobRequesterName string) *jobApproval {
	a := &jobApproval{
		Rules:    req.MatchedRules,
		Summary:  req.Summary,
		Signed:   countApprovals(req),
		Required: req.Require.Count,
		ViaGrant: viaGrant,
	}
	a.Short = a.Required > 0 && a.Signed < a.Required

	for _, dec := range req.Decisions {
		// One denial is terminal (approval.Decision), so a released Job's
		// record carries no terminal deny — but a fixture or a future replay
		// could still hand this function one, and rendering it as though it
		// released the Job would be the wrong story.
		if !dec.Approve {
			continue
		}
		a.Deciders = append(a.Deciders, jobDecider{
			Account:    dec.Account,
			Verified:   dec.AccountID != "",
			Kind:       verifiedKind(dec.AccountID != "", deciderKind(dec.DeciderHuman)),
			OnBehalfOf: dec.OnBehalfOf,
			Channel:    dec.Channel.String(),
			At:         stampOrAbsent(dec.At),
			Reason:     dec.Reason,
		})
	}

	a.ParkedBy = cmp.Or(req.RequestedBy, "unattributed")
	a.ParkedByVerified = req.RequestedByID != ""
	// Compare by Account ID whenever either side has one; only when BOTH are
	// unverified does the comparison fall back to the name, so two different
	// unattributed requesters are never read as the same Account merely
	// because neither carries an ID.
	if req.RequestedByID != "" || jobRequesterID != "" {
		a.ParkedByDiffers = req.RequestedByID != jobRequesterID
	} else {
		a.ParkedByDiffers = req.RequestedBy != jobRequesterName
	}
	return a
}

func handleJob(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jobID := r.PathValue("job_id")

		// The read lane takes a capability.Principal, so this screen reads the
		// one the Authenticator injected as well as the Page the shell needs.
		// Both are context reads; page() resolves the same principal itself.
		caller, ok := principal(w, r)
		if !ok {
			return
		}
		pg, ok := page(d, w, r, "Job "+shortHash(jobID))
		if !ok {
			return
		}
		pg.Banner = banner(d, r)

		if d.Queries == nil {
			unavailable(w, "the Job and Task query lane")
			return
		}
		d, lane := latched(d)
		// Refused before it reaches the read lane rather than after: the value
		// is caller-controlled and the lane records it in the append-only
		// trail as the read's own selector.
		if len(jobID) > maxJobIDBytes {
			renderMissingJob(w, pg, jobID)
			return
		}

		ctx := r.Context()
		// ONE aggregate row: the Job's identity, its fan-out, and its exact
		// per-outcome tally, with no Task materialised at any fan-out.
		found, err := d.Queries.QueryJobs(ctx, caller,
			capability.JobFilter{JobID: jobID}, capability.PageRequest{Limit: 1})
		if err != nil {
			readFailed(w, err, "this Job's record")
			return
		}
		if len(found.Jobs) == 0 {
			renderMissingJob(w, pg, jobID)
			return
		}

		v := buildJobView(ctx, d, r, caller, accounts.Role(caller.Role), pg.CSRFToken, found.Jobs[0])
		if refusedUnaudited(w, lane, "this Job's record") {
			return
		}
		renderScreen(w, pg, jobTmpl, v)
	}
}

// renderMissingJob renders the not-found placeholder with a 404.
func renderMissingJob(w http.ResponseWriter, pg Page, jobID string) {
	w.WriteHeader(http.StatusNotFound)
	renderScreen(w, pg, jobTmpl, jobView{ID: jobID})
}

func buildJobView(ctx context.Context, d Deps, r *http.Request, caller capability.Principal, role accounts.Role, csrfToken string, sum capability.JobSummary) jobView {
	v := jobView{
		Found:   true,
		ID:      sum.JobID,
		Created: sum.CreatedAt,
		State:   jobStateText(sum.State),
		// The DECLARED class, from tasks.risk_class — not this package's
		// name-list inference. A Template Operation the Console has never
		// heard of is still classified by the catalog that dispatched it.
		RiskClass:      sum.RiskClass,
		Risk:           jobs.RiskClassName(sum.RiskClass),
		ReadClass:      sum.RiskClass == jobs.RiskClassRead,
		Principal:      sum.Requester,
		Verified:       sum.RequesterAccountID != "",
		RequesterKind:  verifiedKind(sum.RequesterAccountID != "", sum.RequesterKind),
		FanOut:         sum.Total,
		InFlight:       sum.Unresolved,
		Bar:            barFrom(sum.Counts),
		CancelledCount: sum.Counts[jobs.OutcomeCancelled],
	}
	v.Operation, v.RawExecTier = jobRowName(sum)

	if sum.Requester == "" {
		// The chip below falls back to the dispatch record's principal, which
		// carries no kind; a kind from the Job row must never sit beside a
		// name the Job row did not supply.
		v.RequesterKind = ""
	}

	if sum.Unresolved > 0 && cancelOffered(d, role) {
		v.Cancel = &JobCancel{Action: cancelJobAction(sum.JobID), CSRFToken: csrfToken}
	}
	// Conditional on purpose (#595): the read exists to explain a cancel, and
	// a Job with nothing cancelled and nothing in flight has nothing a
	// cancel could explain. This is what keeps
	// TestJob_TenThousandNodesRendersNoList's auditCalls==1 guard true —
	// see the file header.
	if v.CancelledCount > 0 || sum.Unresolved > 0 {
		if row, ok, err := cancelRecord(ctx, d, caller, sum.JobID); err != nil {
			v.CancelTrailError = true
		} else if ok {
			v.CancelRequest = &cancelRequest{Principal: row.Principal, Verified: row.Verified.AccountID != "", At: row.Timestamp}
		}
	}

	// The dispatch record, as ONE bounded row rather than the Job's whole
	// trail. Everything below comes from the dispatch that created the Job;
	// within one Job every per-Node dispatch row is written from the same base
	// record, so any of them answers these questions identically. (Reading the
	// Operation off a LATER record would silently follow a re-drive, which is
	// why this asks the trail for dispatch rows and nothing else.)
	var dispatchPrincipal string
	if row, ok, err := dispatchRecord(ctx, d, caller, sum.JobID); err != nil {
		v.TrailError = true
	} else if ok {
		v.DispatchFound = true
		dispatchPrincipal = row.Principal
		v.Args = argsSummary(row.Args, row.RawExecArgv)
		v.OnBehalfOf = row.Asserted.OnBehalfOf
		v.ApprovalID = row.ApprovalID
		v.GrantID = row.GrantID
		if v.Operation == "" {
			// Not Raw Exec here: that would already have filled v.Operation.
			// A Job whose summary is unspecified but whose dispatch record is
			// really Raw Exec reads "dispatch" with no chip, as it was blank before.
			fb := sum
			fb.OperationName = row.OperationName
			v.Operation, v.RawExecTier = jobRowName(fb)
		}
		// JobSummary.Requester is the VERIFIED lane only. A principal with no
		// Account renders blank rather than "unattributed" unless the trail's
		// own principal string is used as the fallback, exactly as
		// principalText does on every other screen.
		v.Principal = cmp.Or(v.Principal, row.Principal, "unattributed")
	} else {
		v.Principal = cmp.Or(v.Principal, "unattributed")
	}
	if v.ApprovalID != "" {
		v.ApprovalHref = "/console/approvals/" + v.ApprovalID
	}

	v.Plan = Plan{
		Selector: sum.Selector,
		// The Selector is not readable while the Job runs — it lives in the
		// dispatch audit record, which is written after the dispatch returns.
		// The slot holds this until then, so the block resolves rather than
		// growing a line (foundations rule 6).
		SelectorNote: "the Selector is recorded in the audit trail when the dispatch completes",
		// Fixed at dispatch: every Task is created before the first one runs,
		// so the fan-out does not move while the Job does.
		Matched:   sum.Total,
		RiskClass: sum.RiskClass,
		// Cap is deliberately absent. The Console is never told a blast cap
		// and has no path to one (invariant 11); on a dispatched Job the cap
		// has already been applied, on the Relay, before anything ran.
	}
	if v.ApprovalID != "" {
		if d.Approvals == nil {
			// A distinct state from a failed read (finding 9): this Console
			// was never wired with an approval seam at all, which is a
			// deployment fact, not a store outage.
			v.ApprovalReaderMissing = true
		} else if req, err := d.Approvals.Approval(ctx, v.ApprovalID); err != nil {
			v.ApprovalError = true
		} else {
			// A Grant's PlanHash hashes the Grant's Scope, never this Job's
			// Plan (capability/approval_grant.go). Showing it in the Job's
			// plan-hash slot would be a different hash presented as the one
			// an operator is trained to compare.
			if v.GrantID == "" && req.PlanHash != "" {
				v.Plan.Hash = req.PlanHash
				v.PlanHashKnown = true
			}
			v.Approval = newJobApproval(req, v.GrantID != "", sum.RequesterAccountID, cmp.Or(sum.Requester, dispatchPrincipal))
		}
	}

	v.Groups = jobGroups(ctx, d, caller, sum, r.URL.Query().Get("show"), v.Operation)
	return v
}

// dispatchRecord reads the Job's dispatch record — one row, filtered by the
// trail's own indexes, in place of every record the Job ever produced.
//
// The screen this replaced loaded ALL of them, each carrying that Node's
// captured stdout and stderr: at 10,000 Nodes and the daemon's 1 MiB output
// cap, a single page view could ask the store for gigabytes.
func dispatchRecord(ctx context.Context, d Deps, caller capability.Principal, jobID string) (capability.AuditRow, bool, error) {
	trail, err := d.Queries.QueryAudit(ctx, caller, capability.AuditFilter{
		JobID: jobID,
		Kinds: []string{audit.KindDispatch},
	}, capability.PageRequest{Limit: 1})
	if err != nil {
		return capability.AuditRow{}, false, err
	}
	if len(trail.Rows) == 0 {
		// NORMAL, not an error: the Job engine writes the dispatch record
		// after the dispatch returns, so an in-flight Job has none yet. The
		// aggregate above still describes it completely.
		return capability.AuditRow{}, false, nil
	}
	return trail.Rows[0], true, nil
}

// cancelRecord reads the newest job_cancel audit record for jobID — one
// bounded row, shaped exactly like dispatchRecord above, and for the same
// reason: it is the non-forgeable source for "a cancel was asked for, by
// whom, when", so the result block never has to trust a query-string flash.
// The read lane orders newest first, so Limit 1 is the most recent request
// if more than one was ever made.
func cancelRecord(ctx context.Context, d Deps, caller capability.Principal, jobID string) (capability.AuditRow, bool, error) {
	trail, err := d.Queries.QueryAudit(ctx, caller, capability.AuditFilter{
		JobID: jobID,
		Kinds: []string{audit.KindJobCancel},
	}, capability.PageRequest{Limit: 1})
	if err != nil {
		return capability.AuditRow{}, false, err
	}
	if len(trail.Rows) == 0 {
		// NORMAL, not an error: a Job whose Tasks read cancelled without ever
		// being asked to (a halted mutate Job, say) has no job_cancel row at
		// all, and the page must not invent one.
		return capability.AuditRow{}, false, nil
	}
	return trail.Rows[0], true, nil
}

// jobGroups builds one group per outcome the Job actually produced, ordered by
// interest, fetching at most one bounded page of Tasks for each.
//
// It is driven by the COUNT MAP, never by the rows: a group whose rows were not
// fetched — the success group on a large Job — still renders its heading and
// its exact count. The counts are the answer; the rows are the evidence.
func jobGroups(ctx context.Context, d Deps, caller capability.Principal, sum capability.JobSummary, show, operation string) []outcomeGroup {
	outcomes := make([]jobs.Outcome, 0, len(sum.Counts))
	for o := range sum.Counts {
		outcomes = append(outcomes, o)
	}
	sort.Slice(outcomes, func(i, j int) bool {
		return outcomeInterest[outcomes[i]] < outcomeInterest[outcomes[j]]
	})

	readClass := sum.RiskClass != jobs.RiskClassMutate
	groups := make([]outcomeGroup, 0, len(outcomes))
	for _, o := range outcomes {
		label := jobs.OutcomeName(o)
		expanded := show == label
		g := outcomeGroup{
			Outcome: o,
			Label:   label,
			Count:   sum.Counts[o],
			// Everything interesting opens. Success does not: it is the mode,
			// and a page that opens the mode by default has buried the three
			// denies under nine thousand successes.
			Open:         o != jobs.OutcomeSuccess || expanded,
			ShowAllCount: jobGroupExpanded,
		}

		limit := jobRowLimit(o, sum.Total, expanded)
		var rows []taskRow
		if limit > 0 {
			var err error
			if rows, err = jobRows(ctx, d, caller, sum.JobID, o, limit, readClass, operation); err != nil {
				g.RowsError = true
			}
		}

		g.Listed = len(rows)
		// Elision describes rows this page CHOSE not to list. A failed fetch
		// withheld nothing by design, so it elides nothing: saying "none of
		// these 2 Nodes is listed, at this size the count is the answer" over
		// a store error is a false explanation printed beside the true one,
		// and the "list the first 100" link it carries re-runs the query that
		// just failed — during the outage that failed it.
		if !g.RowsError {
			if g.Elided = g.Count - g.Listed; g.Elided < 0 {
				g.Elided = 0
			}
			g.Sampled = g.Elided > 0
			if g.Sampled && limit < jobGroupExpanded {
				g.ShowAllHref = "?show=" + label
			}
		}

		switch o {
		case jobs.OutcomeDeniedByPolicy:
			// The spec's "when they differ, group by rule" — so when they do
			// NOT differ, there is exactly one cluster and the page can say so.
			//
			// Only when the rules are KNOWN. On a read-class Job every rule is
			// denyText's identical explanation of why there is no rule, so
			// collapsing on it would claim N Nodes fired one Policy rule — a
			// fact the Relay deliberately threw away — and hide every Node ID
			// but the first behind that claim.
			known := rulesAreKnown(rows)
			g.Clusters = clusterRows(rows, denyRuleKey, known)
			if known && len(g.Clusters) == 1 && !g.Sampled && g.Listed > 1 {
				g.SharedRule = g.Clusters[0].Key
			}
		case jobs.OutcomeCancelled:
			// Never sent and sent-then-stopped are two different facts (#595)
			// and must never merge into one "identical" row: the deny
			// branch's rule (above) clusters on the thing that AGREES; here
			// the two clusters are the two things that CANNOT agree with each
			// other. But within the "sent" side, cancelKey also keys on
			// Output — a sent-then-stopped Task carries captured output just
			// like any other resolved Task (daemon/src/executor.rs's
			// Outcome::Cancelled returns it), so three of them reporting
			// different output must not fold into one cluster either, the
			// same rule the default branch below applies to every other
			// outcome. cluster is !readClass for the same reason: a
			// read-class Job's output is already withheld, so there is
			// nothing to cluster on.
			g.Clusters = clusterRows(rows, cancelKey, !readClass)
		default:
			// readClass suppresses the "N reported identical output" label: on
			// a read Job there IS no retained output, every row's is the empty
			// string, and saying they all reported the same thing describes the
			// Relay's retention policy as if it were a fact about the fleet.
			g.Clusters = clusterRows(rows, func(r taskRow) string { return r.Output }, !readClass)
		}
		groups = append(groups, g)
	}
	return groups
}

// denyRuleKey clusters the denied group by the rule that fired. The nil check
// is not decoration: a row's Deny is set from its own Outcome, and this group
// is assembled from a store-side outcome filter, so a store that ever returned
// a mismatched row would otherwise take the whole page down.
func denyRuleKey(r taskRow) string {
	if r.Deny == nil {
		return ""
	}
	return r.Deny.Rule
}

// cancelKey clusters the cancelled group first by whether the Task ever left
// the Relay (#595) — "which of two facts about this cancel is true of this
// Task", which must never merge into one cluster no matter how many rows
// share either one — and, within the "sent" side, by Output too: a
// sent-then-stopped Task can carry different captured output from another
// one, and folding those into a single "identical" cluster would drop
// output clusterRows exists to keep visible everywhere else on this page.
// "\x00" cannot appear in Sent-plus-Output, so the two sides of the key
// never collide with each other.
func cancelKey(r taskRow) string {
	if r.Sent {
		return "sent\x00" + r.Output
	}
	return "never sent"
}

// rulesAreKnown reports whether every listed deny carried the daemon's own
// verdict, which is what makes clustering them by rule mean anything.
//
// An empty group is not "known": there is nothing to have agreed.
func rulesAreKnown(rows []taskRow) bool {
	for _, r := range rows {
		if !r.RuleKnown {
			return false
		}
	}
	return len(rows) > 0
}

// jobRowLimit is the disclosure ladder, as a number.
//
// Zero means "fetch nothing": the success group of a large Job renders as its
// count alone, which is the acceptance criterion "no list until explicitly
// requested" made structural rather than promised. The click that follows is
// bounded too — jobGroupExpanded, not the group — and the page says so rather
// than offering a "show all" it would not honour.
func jobRowLimit(o jobs.Outcome, total int, expanded bool) int {
	switch {
	case expanded:
		return jobGroupExpanded
	case o != jobs.OutcomeSuccess:
		return jobGroupRows
	case total <= legibleJob:
		return legibleJob
	default:
		return 0
	}
}

// jobRows fetches one bounded page of one outcome's Tasks.
func jobRows(ctx context.Context, d Deps, caller capability.Principal, jobID string, o jobs.Outcome, limit int, readClass bool, operation string) ([]taskRow, error) {
	outcome := o
	fetched, err := d.Queries.QueryTasks(ctx, caller,
		capability.TaskFilter{JobID: jobID, Outcome: &outcome},
		capability.PageRequest{Limit: limit})
	if err != nil {
		return nil, err
	}
	rows := make([]taskRow, 0, len(fetched.Tasks))
	for _, t := range fetched.Tasks {
		rows = append(rows, newTaskRow(t, readClass, operation))
	}
	return rows, nil
}

// newTaskRow projects one capability.TaskRow onto what the page renders.
//
// jobReadClass is the JOB's declared class and withheld is the TASK's: output
// renders only when both say mutate. The read lane has already stripped
// non-mutate output before it got here (readlane.go's QueryTasks), so this is
// the second of two independent gates on the same rule, which is what makes
// "read output never renders" a property of the code rather than of one
// package remembering.
func newTaskRow(t capability.TaskRow, jobReadClass bool, operation string) taskRow {
	row := taskRow{
		NodeID:   t.NodeID,
		NodeHref: "/console/nodes/" + t.NodeID,
		ExitCode: t.ExitCode,
		ShowExit: hasRealExitStatus(t.Outcome, t.ExitCode) && t.ExitCode != 0,
		Sent:     !t.DispatchedAt.IsZero(),
	}
	// "Not mutate", not "is read": an unrecognised or unspecified class must
	// default to withholding the bytes, matching the read lane's own strip
	// condition rather than this codebase's usual unspecified-means-mutate
	// guardrail default.
	withheld := t.RiskClass != jobs.RiskClassMutate
	// The DENY RULE is read output too. The daemon explains a refusal in the
	// Task's own stderr, so a read-class deny's rule is bytes the trail
	// deliberately never kept (ADR-0025) — rendering them here because they
	// happened to arrive on the Task row would be the same egress by a quieter
	// route. denyText then says the rule is not recorded IN THE TRAIL for a
	// read, rather than blaming the daemon for the Relay's own retention rule.
	stderr := t.Stderr
	if withheld {
		stderr = nil
	}

	if t.Outcome == jobs.OutcomeDeniedByPolicy {
		// The rule is the DAEMON'S VERDICT only when the daemon actually sent
		// one. Otherwise denyText returns an explanation of why there is none,
		// and that sentence is identical on every Node — so it must never be
		// clustered as "these N all fired the same rule", which is a fact
		// about Policy the page does not have.
		row.RuleKnown = trimmed(stderr) != ""
		// Clipped exactly as captured output is, and for the same reason: a
		// Node controls its own stderr, the daemon's cap is 1 MiB, and the
		// deny group lists up to 100 of them. An unbounded rule made the ONE
		// screen whose whole claim is boundedness the cheapest way to make the
		// Relay render 100 MiB of HTML on a refresh.
		rule, clipped := clip(denyText(stderr, "", withheld), maxOutputBytes)
		row.Deny = &Deny{
			NodeID:        t.NodeID,
			OperationName: operation,
			// The daemon's verdict, verbatim. jobs.TaskSummary carries no
			// Reason field, so on this lane the rule is what the daemon said
			// in the Task's own output or it is nothing — and denyText says
			// which of those it was rather than inventing a rule.
			Rule:        rule,
			RuleClipped: clipped,
			PolicyHref:  "/console/nodes/" + t.NodeID,
			// DraftRuleHref is deliberately empty: it targets the Policy fix
			// screen (spec 07), which is not built in v0.6.0, and a link to a
			// screen that does not exist is worse than no link. See spec 13's
			// annotation.
			Boundary: DenyBoundaryApply,
		}
		return row
	}
	if !jobReadClass && !withheld {
		row.Output, row.Clipped = clip(combinedOutput(t.Stdout, stderr), maxOutputBytes)
	}
	return row
}

func barFrom(counts map[jobs.Outcome]int) OutcomeBar {
	oc := make([]OutcomeCount, 0, len(counts))
	for o, n := range counts {
		oc = append(oc, OutcomeCount{Outcome: o, Count: n})
	}
	return NewOutcomeBar(oc)
}

// clusterRows groups rows by key, largest cluster first.
//
// cluster=false lists every row instead of collapsing: it is what a read-class
// Job gets, where every key is the empty string and "3 Nodes reported identical
// output" would be a claim about the Relay's retention policy dressed up as a
// fact about the fleet.
func clusterRows(rows []taskRow, key func(taskRow) string, cluster bool) []outputCluster {
	byKey := map[string][]taskRow{}
	var order []string
	for _, r := range rows {
		k := key(r)
		if _, seen := byKey[k]; !seen {
			order = append(order, k)
		}
		byKey[k] = append(byKey[k], r)
	}
	out := make([]outputCluster, 0, len(order))
	for _, k := range order {
		rs := byKey[k]
		c := outputCluster{Key: k, Count: len(rs), Rows: rs, Deny: rs[0].Deny, RuleKnown: rs[0].RuleKnown, NeverSent: !rs[0].Sent}
		if len(rs) >= clusterFloor && cluster {
			// "N identical — here is one." Rendering 9,797 identical rows is
			// the behaviour clustering exists to prevent; the label says how
			// many were collapsed, so the count is never hidden even though
			// the rows are.
			c.Representative = true
			c.Rows = rs[:1]
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// hasRealExitStatus reports whether a Task's exit code came from a process that
// actually ran. Whether it is worth SCREEN is a separate question — see
// taskRow.ShowExit.
//
// Only success and failure can carry one. A deny never spawned; a timeout or
// cancel was killed; unreachable and version_refused never left the Relay; and
// unsupported means Policy was never even asked.
func hasRealExitStatus(outcome jobs.Outcome, code int32) bool {
	switch outcome {
	case jobs.OutcomeSuccess, jobs.OutcomeFailure:
		return code >= 0
	default:
		return false
	}
}

func combinedOutput(stdout, stderr []byte) string {
	var b strings.Builder
	b.Write(stdout)
	if len(stderr) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.Write(stderr)
	}
	return strings.TrimRight(b.String(), "\n")
}

// clip bounds one Task's rendered output, cutting back to a rune boundary so a
// split multi-byte character does not become a replacement glyph.
func clip(s string, max int) (string, bool) {
	if len(s) <= max {
		return s, false
	}
	cut := s[:max]
	for len(cut) > 0 {
		r, size := utf8.DecodeLastRuneInString(cut)
		if r != utf8.RuneError || size != 1 {
			break
		}
		cut = cut[:len(cut)-1]
	}
	return cut, true
}

func jobStateText(st jobs.JobState) string {
	if st == jobs.JobStateRunning {
		return "running"
	}
	return "complete"
}

var jobTmpl = newScreen("job", `
{{if not .Found}}
<div class="placeholder"><p>No Job with the id <code>{{.ID}}</code> appears in this Relay's records.</p>
<p><a href="/console/activity?kind=dispatch">Back to dispatches</a>.</p></div>
{{else}}

<section class="jobhead">
  <div class="jhrow">
    <span class="chip risk" data-risk="{{.Risk}}">{{.Risk}}</span>
    {{if .RawExecTier}}<span class="chip" data-tier="raw_exec">Raw Exec</span>{{end}}
    {{if .Operation}}<code class="jobop">{{.Operation}}</code>{{else}}<span class="dim">dispatch</span>{{end}}
    {{with .Args}}<span class="mono dim">{{.}}</span>{{end}}
  </div>
  <div class="jhrow">
    {{template "trust-chip" (trust .Principal .Verified)}}{{template "kind-label" .RequesterKind}}
    {{with .OnBehalfOf}}{{template "trust-chip" (trust . false)}}<span class="dim">on behalf of (claimed by the caller, not checked)</span>{{end}}
    {{if .ApprovalHref}}released by approval <a href="{{.ApprovalHref}}"><code>{{short .ApprovalID}}</code></a>{{end}}
    {{with .GrantID}}<span class="grant" title="A human approved a window this plan fell inside, not this plan.">grant {{short .}}</span>{{end}}
  </div>
  <div class="jhrow">
    <span class="dim">job</span> <code>{{short .ID}}</code>
    <span class="chip" data-state="{{.State}}">{{.State}}</span>
    {{if .InFlight}}<span class="overcap">{{.InFlight}} still in flight</span>{{end}}
    <span class="dim">dispatched {{stamp .Created}}</span>
    {{with .Cancel}}{{template "job-cancel" .}}{{end}}
  </div>
</section>

{{with .Approval}}
<section class="jobapproval" aria-label="Approval">
  <p>gated by rule {{if .Rules}}<code>{{join ", " .Rules}}</code>{{else}}no gate rule recorded{{end}}</p>
  <p>{{if gt .Required 0}}<b>{{.Signed}}</b> of {{.Required}} {{plural .Required "approval" "approvals"}}{{else}}no quorum recorded{{end}}{{if .Short}} <span class="gap">The record holds fewer approvals than the rule required. This page cannot tell why the Job was released.</span>{{end}}</p>
  {{if .ParkedByDiffers}}<p>approval parked by {{template "trust-chip" (trust .ParkedBy .ParkedByVerified)}} <span class="dim">{{if .ViaGrant}}— the Account that requested the Grant{{else}}— not the Account that requested this Job; the approval was released on its plan hash{{end}}</span></p>{{end}}
  {{range .Deciders}}
  <div class="decider">
    {{template "trust-chip" (trust .Account .Verified)}}{{template "kind-label" .Kind}}
    <span>{{if eq .At "not recorded"}}approved, time not recorded{{else}}approved {{.At}}{{end}}</span> <code>{{.Channel}}</code>
    {{with .OnBehalfOf}}{{template "trust-chip" (trust . false)}}<span class="dim">answering for (claimed by the deciding client, not checked)</span>{{end}}
    {{with .Reason}}<span class="dim">{{.}}</span>{{end}}
  </div>
  {{end}}
  {{if not .Deciders}}<p class="dim">no approving decision recorded</p>{{end}}
  {{with .Summary}}<p class="summary"><b>What the Relay showed the approver</b> <span class="dim">(Relay-authored, stored when the approval was requested and shown exactly as stored)</span><br>{{.}}</p>{{end}}
  {{if .ViaGrant}}<p class="note">These approvers approved a Grant — a window this plan fell inside — not this plan. The summary above describes the window.</p>{{end}}
</section>
{{end}}
{{if .ApprovalReaderMissing}}
<p class="gap">The approval reader is not available on this Console, so who approved this Job, under
which rule and when is not shown here. The dispatch record says it was released by approval
<code>{{short .ApprovalID}}</code>.</p>
{{end}}
{{if .ApprovalError}}
<p class="gap">The approval record <code>{{short .ApprovalID}}</code> could not be read, so who
approved this Job, under which rule and when is missing here. The dispatch record says it was
released by that approval.</p>
{{end}}

<p class="lanekey">{{template "trust-chip" (trust "verified" true)}} the Relay authenticated this identity ·
{{template "trust-chip" (trust "asserted" false)}} the caller claimed this; nothing checked it ·
<span class="kind">human</span> / <span class="kind">machine</span> the verified Account&#39;s kind as the
record wrote it at the time, shown only where it did; on an approval, machine means &ldquo;not
recorded as human&rdquo;</p>

{{template "plan" .Plan}}
<p class="note">This is the Plan as it stood at dispatch, not a fresh one. The set of Nodes was fixed
when the Tasks were created and does not change while the Job runs.
{{if not .PlanHashKnown}}
{{if .TrailError}}The dispatch record could not be read, so whether this dispatch was gated by an approval is not known here.
{{else if .GrantID}}This dispatch was released by a Grant. The Grant's approval covered a window, not this plan, so no plan hash was retained for it. The Job's own id is not a plan hash.
{{else if or .ApprovalError .ApprovalReaderMissing}}The approval record could not be read here, so the plan hash it committed to is not shown.
{{else if .ApprovalID}}The approval record holds no plan hash, so none is shown here.
{{else if not .DispatchFound}}{{if .InFlight}}The dispatch record is not written yet, so whether it was gated is not known.{{else}}No dispatch record was found for this Job, so whether it was gated is not known.{{end}}
{{else}}This dispatch was not gated by an approval, so no plan hash was retained
for it. The Job's own id is not a plan hash.
{{end}}
{{end}}</p>

{{if .TrailError}}
<p class="gap">The dispatch record for this Job could not be read. What was asked for is missing
from the header above: the arguments, the on-behalf-of claim, and any approval. The outcomes below
are unaffected, because they come from the Tasks, not from the audit trail.</p>
{{end}}

{{if .CancelRequest}}
<div class="cancelresult">
  <p>Cancel requested by {{template "trust-chip" (trust .CancelRequest.Principal .CancelRequest.Verified)}}
  at {{stamp .CancelRequest.At}}. Cancel only ever asks.</p>
  {{if .CancelledCount}}
  <p><b>{{.CancelledCount}}</b> {{plural .CancelledCount "Task reads" "Tasks read"}} cancelled. The
  cancelled group below shows which never left the Relay and which were stopped after they were sent.</p>
  {{else}}
  <p>No Task reads cancelled.</p>
  {{end}}
  {{if .InFlight}}
  <p><b>{{.InFlight}}</b> still in flight. Each Task already sent was asked to stop if its Node is connected.
  This is best-effort: each one will report what actually happened, which may be its real outcome if it
  finished first.</p>
  {{end}}
  <p>Tasks that had already finished keep the outcome they really had.</p>
</div>
{{end}}
{{if .CancelTrailError}}
<p class="gap">The cancel request for this Job could not be read, so who asked for it and when is
missing above. The groups below are unaffected: they come from the Tasks, not from this record.</p>
{{end}}

{{if .Bar.Total}}{{template "outcome-bar" .Bar}}{{end}}

{{if .ReadClass}}
<p class="gap"><b>This was a read.</b> A read carries data off the Node, so the audit trail records
that it happened and never what it returned: it keeps this Job&#39;s outcomes and timings and never
its output. What the daemon sent still sits on the Task rows until the Job is collected, and is
readable through <code>GET /api/v1/jobs/{job_id}</code>. This page never shows it, at any age, so
the Console can never become a lasting place to read that output from.</p>
{{end}}

{{range .Groups}}
<details class="ogroup"{{if .Open}} open{{end}}>
  <summary>
    <span class="chip outcome" data-outcome="{{.Label}}">{{.Label}}</span>
    <b>{{.Count}}</b> {{plural .Count "Node" "Nodes"}}
    {{if .Elided}}<span class="dim">{{if .Listed}}{{.Listed}} of {{.Count}} listed{{else}}none listed{{end}}</span>{{end}}
    {{if eq .Label "success"}}<span class="dim">the usual result, folded so the exceptions stand out</span>{{end}}
  </summary>

  {{if .RowsError}}
  <p class="note">The per-Node results for this group could not be read. The count above is exact —
  it comes from the Job's own tally, not from this list.</p>
  {{end}}

  {{if .Elided}}
  <p class="note">{{if .Listed}}The count above is exact; everything below is computed over the
  {{.Listed}} listed.{{else}}None of these {{.Count}} Nodes is listed: at this size the count is
  the answer and the list is not.{{end}}
  {{if .ShowAllHref}}<a href="{{.ShowAllHref}}">List the first {{.ShowAllCount}}</a>.{{end}}</p>
  {{end}}

  {{if eq .Label "denied_by_policy"}}
    {{if .SharedRule}}
    <p class="note">Every one of these {{.Count}} denials fired the same rule. It is shown once.</p>
    {{end}}
    {{range .Clusters}}
      <div class="cluster">
        {{if gt .Count 1}}<div class="clabel"><b>{{.Count}}</b> {{plural .Count "Node" "Nodes"}}
          {{if .RuleKnown}}fired this rule{{else}}were refused, and the deciding rule is recorded for none of them{{end}}{{if .Representative}} &mdash; one shown{{end}}.</div>{{end}}
        {{range .Rows}}
          <div class="trow"><a href="{{.NodeHref}}"><code>{{.NodeID}}</code></a></div>
        {{end}}
      </div>
      {{with .Deny}}{{template "deny-block" .}}{{end}}
    {{end}}
  {{else if eq .Label "cancelled"}}
    {{range .Clusters}}
      <div class="cluster">
        <div class="clabel"><b>{{.Count}}</b> {{plural .Count "Node" "Nodes"}}
          {{if .NeverSent}}never sent &mdash; marked cancelled on the Relay{{else}}sent and then stopped &mdash; the Node reported cancelled{{end}}{{if .Representative}} &mdash; one shown{{end}}.</div>
        {{range .Rows}}
          <div class="trow"><a href="{{.NodeHref}}"><code>{{.NodeID}}</code></a></div>
          {{with .Output}}<pre class="taskout">{{.}}</pre>{{end}}
          {{if .Clipped}}<p class="note">Shown to the first 2 KB of what the Relay stored.</p>{{end}}
        {{end}}
      </div>
    {{end}}
  {{else}}
    {{range .Clusters}}
      <div class="cluster">
        {{if .Representative}}
          <div class="clabel"><b>{{.Count}}</b> {{plural .Count "Node" "Nodes"}} reported identical output — one shown.</div>
        {{end}}
        {{range .Rows}}
          <div class="trow">
            <a href="{{.NodeHref}}"><code>{{.NodeID}}</code></a>
            {{if .ShowExit}}<span class="exit">exit {{.ExitCode}}</span>{{end}}
          </div>
          {{with .Output}}<pre class="taskout">{{.}}</pre>{{end}}
          {{if .Clipped}}<p class="note">Shown to the first 2 KB of what the Relay stored.</p>{{end}}
        {{end}}
      </div>
    {{end}}
  {{end}}
</details>
{{end}}
{{end}}
`)
