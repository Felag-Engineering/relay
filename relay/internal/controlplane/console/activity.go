package console

// activity.go is the live stream and the audit trail, deliberately ONE surface
// (spec 04).
//
// # Why one screen and not two
//
// "What is happening" and "what happened" are the same events read at different
// distances. Building them as two screens means two renderers of one event type,
// and two renderers of one event type drift: the live view gains a chip the
// history view lacks, the history view gains a filter the live view cannot
// express, and eventually an operator watching the stream and an auditor reading
// the trail disagree about what the fleet did. Same rows, same chips, one
// renderer — live tail on is "now", filtered is history.
//
// # Where the Job-grained collapse happens
//
// IN SQL, not here. auditsink writes ONE DISPATCH RECORD PER NODE RESULT, so a
// 4,000-Node Job is 4,000 audit rows and any audit page (max 500) of it
// collapses to a single row — which satisfies "one row" by losing the Jobs
// list. So dispatch rows are served by capability.QueryJobs, whose store
// implementation returns one row per Job with an EXACT per-outcome tally
// computed in the aggregate. The cost is FLAT from 3 Nodes to 10,000: the same
// "bounded by construction, not capped after the fact" doctrine job.go states.
//
// Non-dispatch events are first-class rows, not a footnote: approvals, token
// mints, Freeze transitions and sign-ins are things that happened to the fleet,
// and an operator who has to look in a second place for "who minted that token"
// has a trail with a hole in it. They come from capability.QueryAudit.
//
// # The two lanes, and their page boundary
//
// The two lanes page INDEPENDENTLY, each with its own opaque keyset cursor, and
// the rendered page is both pages merged by time. Every row from both is
// rendered — the merge is never truncated, because losing rows from an audit
// trail is the one thing this screen must never do. The consequence is stated
// on the page: a page boundary is not a single instant unless a `kind` filter
// has left only one lane running, which is exactly the Jobs-list case.
//
// # Why the live lane renders NOTHING
//
// It counts, and the click reloads. Spec 11: "reload the affected region rather
// than splicing", and "incoming events queue behind an explicit control. Build
// it once." Any script that built a row would be a SECOND RENDERER of
// activityRow and a second implementation of NewOutcomeBar's minority-floor and
// growWeight quantisation — which is what spec 04's fourth acceptance criterion
// forbids. So the client only ever bumps a counter and sets one data-jobstate
// attribute on a row already on screen.
//
// The trade-off that buys, recorded rather than discovered: THE OUTCOME BAR
// DOES NOT REPAINT LIVE. A Job that finishes while the page is open says so, in
// place, and the counts arrive on the explicit reload.
//
// # There is no Jobs destination
//
// This screen filtered to dispatch IS the Jobs list (open decision D6), and it
// is structural: with `?kind=dispatch` the audit lane is not queried at all.
// The filter is a linkable URL state rather than a widget an operator has to
// reconstruct, which is what makes "the Jobs list" a thing you can send someone.

import (
	"context"
	"encoding/csv"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/events"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// jobPageSize, auditPageSize and exportPages bound one render.
//
// Code constants, unreachable from any request (invariant 11), and both page
// sizes are far below capability.MaxPageSize, which clamps them again on the
// way through the read lane. The export re-runs the same filter across at most
// exportPages pages PER LANE and says so in its own final row: an unbounded
// export is an unbounded read of the trail behind one link.
const (
	jobPageSize   = 25
	auditPageSize = 50
	exportPages   = 10

	// maxOnBehalfOfChars mirrors the read lane's own bound on the asserted
	// filter (capability's maxOnBehalfOfBytes), which mirrors audit's
	// MaxAssertedFieldBytes. Repeated as a constant rather than imported
	// because the capability layer's is unexported; the seam refuses a longer
	// value regardless, and this only decides whether the operator is told
	// which value was wrong or handed a 500.
	maxOnBehalfOfChars = 256
)

// rowKind is the family a row belongs to, which is what the filter chips select
// and what decides a row's shape. It is coarser than audit.Kind on purpose: an
// operator filters for "approvals", not for the four distinct approval record
// kinds the trail distinguishes.
type rowKind string

const (
	rowDispatch rowKind = "dispatch"
	rowApproval rowKind = "approval"
	rowToken    rowKind = "token"
	rowNode     rowKind = "node"
	rowFreeze   rowKind = "freeze"
	rowAuth     rowKind = "auth"
	rowAccount  rowKind = "account"
	rowRead     rowKind = "read"
	rowRefusal  rowKind = "refusal"
	rowOther    rowKind = "other"
)

// rowKindOrder is every family, in the order the chips render. It is also the
// set kindsOfFamily must be TOTAL over.
var rowKindOrder = []rowKind{
	rowDispatch, rowRead, rowRefusal, rowApproval, rowFreeze,
	rowNode, rowToken, rowAccount, rowAuth, rowOther,
}

// kindOf maps a trail record onto a row family.
func kindOf(k string) rowKind {
	switch k {
	case audit.KindDispatch:
		return rowDispatch
	case audit.KindRead:
		return rowRead
	case audit.KindRefusal:
		return rowRefusal
	case audit.KindApprovalRequested, audit.KindApprovalGrantRequested,
		audit.KindApprovalDecided, audit.KindApprovalExpired,
		audit.KindApprovalPendingObserved:
		return rowApproval
	case audit.KindTokenMint, audit.KindTokenRevoke, audit.KindAPITokenMint, audit.KindAPITokenRevoke:
		return rowToken
	case audit.KindNodeRevoke:
		return rowNode
	case audit.KindFreezeEngage, audit.KindFreezeRelease:
		return rowFreeze
	case audit.KindLoginSucceeded, audit.KindLoginFailed, audit.KindLoginThrottled, audit.KindLogout,
		audit.KindStepUp, audit.KindStepUpFailed, audit.KindStepUpThrottled:
		return rowAuth
	case audit.KindAccountCreate, audit.KindAccountRole, audit.KindAccountEnable, audit.KindAccountDisable:
		return rowAccount
	default:
		return rowOther
	}
}

// kindsByFamily is the INVERSE of kindOf, computed once from audit.Kinds()
// rather than hand-written beside it.
//
// Derived, not enumerated, because the two lists would have to agree and only
// one of them is ever edited. Every audit kind lands in exactly one family by
// construction, including the ones kindOf does not name — job_cancel and plan
// both fall to `other`, and `other` is a real, selectable family for exactly
// that reason.
var kindsByFamily = buildKindsByFamily()

func buildKindsByFamily() map[rowKind][]string {
	m := map[rowKind][]string{}
	for _, k := range audit.Kinds() {
		f := kindOf(k)
		m[f] = append(m[f], k)
	}
	return m
}

// noSuchAuditKind is a kind no Record can carry. It is what kindsOfFamily
// returns for a family the audit vocabulary has nothing in.
//
// This exists because capability.AuditFilter's contract is that THE ZERO VALUE
// MATCHES EVERY ROW: an empty Kinds slice means ALL KINDS, not none. So a
// filter derived from a family with no kinds would not narrow the trail, it
// would render the WHOLE trail under that family's heading — the exact failure
// a filter must never have. Matching nothing is the truthful answer, and this
// is how it is spelled.
const noSuchAuditKind = "\x00no-such-audit-kind"

// kindsOfFamily returns the audit kinds a row family covers. It is TOTAL over
// rowKind and NEVER returns an empty slice — see noSuchAuditKind.
func kindsOfFamily(f rowKind) []string {
	ks := kindsByFamily[f]
	if len(ks) == 0 {
		return []string{noSuchAuditKind}
	}
	return append([]string(nil), ks...)
}

// activityLaneExcluded is the audit vocabulary the DEFAULT feed does not
// request from the trail lane, each with a reason:
//
//   - dispatch — served Job-grained by QueryJobs. A dispatch record is
//     per-Node, and four thousand of them are one row.
//   - read — the trail's OWN read records, including the two this screen
//     writes on every page view (capability's read lane records every query).
//     Left out of the default feed so the screen does not fill with itself
//     being read; one click away through the `read` chip, and their home is
//     the Read-egress screen.
//
// Neither is hidden: both are reachable as their own family.
var activityLaneExcluded = []string{audit.KindDispatch, audit.KindRead}

// activityTrailKinds is what the default feed asks the trail lane for:
// everything except the two above. Derived from audit.Kinds() so that a kind
// added to internal/audit appears here without anyone remembering to add it.
var activityTrailKinds = defaultTrailKinds()

func defaultTrailKinds() []string {
	excluded := map[string]bool{}
	for _, k := range activityLaneExcluded {
		excluded[k] = true
	}
	var out []string
	for _, k := range audit.Kinds() {
		if !excluded[k] {
			out = append(out, k)
		}
	}
	return out
}

// activityRow is one rendered event — the ONE renderer, fed by two
// constructors (dispatchRowFromJob and eventRowFromTrail) and rendered by one
// template block.
//
// It carries NO Stdout, Stderr, Output or Truncated field, at any age. Neither
// seam behind it has one either (ADR-0025), so there is nothing here to strip.
type activityRow struct {
	Kind rowKind
	// EventKind is the exact audit kind, shown in mono. The coarse family
	// decides the shape; the exact kind is what an auditor quotes.
	EventKind string

	// at is the sort key for the two-lane merge. When is the rendered form;
	// the template never sees this one.
	at time.Time

	When    string
	Summary string

	// Principal and Verified are the trust chip. OnBehalfOf is the asserted
	// lane and is rendered as a SEPARATE, dashed chip — never merged into the
	// verified one. A jailbroken agent can assert anything it likes; the whole
	// point of the two-chip grammar is that it cannot make its claim look like
	// something the Relay checked.
	Principal  string
	Verified   bool
	OnBehalfOf string

	// RequesterKind is "human" or "machine" as the Job row recorded it when
	// the Job was created (capability.JobSummary.RequesterKind), and empty
	// everywhere else: on a Job that recorded none, and on every non-dispatch
	// row, whose audit record carries no kind. It is NEVER looked up from the
	// Account registry, which would report the Account's kind today and
	// relabel history once an Account is converted (#540; 03-agent-sessions.md,
	// "Kind (machine or human) is not on the rail").
	RequesterKind string

	Selector string
	NodeID   string
	NodeHref string

	Operation string
	Args      string
	Risk      string

	// State is #498's `.chip.state` vocabulary (currently just
	// "approved"/"denied", #545): a decision's structured answer.
	// dispatchRowFromJob leaves it empty — a Job is not a Decision.
	State string

	JobID   string
	JobHref string

	// LiveHandle marks the row the live client may flip: the DISPATCH row for
	// a Job, and only that.
	//
	// It is a separate flag from JobID because several trail rows carry a Job
	// id without being that Job — a job_cancel names the Job it cancelled. The
	// client looks a row up by '.ev[data-job-id="..."]' and takes the first
	// match, so putting the handle on every row that mentions a Job would let
	// a cancellation row be relabelled "completed after this page was
	// rendered", which is a sentence about the wrong row.
	LiveHandle bool

	// OpIsLink says the row's head renders the Operation as a link to the
	// Job. When it does not — a job_cancel names a Job but ran no Operation —
	// the head renders the summary and the Job link moves to the meta line,
	// rather than rendering an empty <code> element linking somewhere.
	OpIsLink bool

	// Outcomes are the per-Job rollup: the segmented bar and its key.
	Outcomes OutcomeBar
	FanOut   int

	// InFlight is how many of the Job's Tasks have not resolved yet.
	InFlight int

	// Unrecorded marks a dispatch the Relay cannot attribute, and Pending
	// distinguishes the two reasons — which are DIFFERENT CLAIMS and must not
	// share a sentence.
	//
	// The Job engine writes its audit record after the dispatch returns, so a
	// Job with Tasks still unresolved has no requester YET; that is normal and
	// temporary, and the row says the attribution is coming. A Job whose Tasks
	// have ALL resolved and still has no requester is not waiting for
	// anything: the trail should carry a dispatch record for it and does not.
	// Spec 04 legislates about exactly that row — "if attribution is missing,
	// that is a bug to surface, not a blank to render" — so it is surfaced as
	// one instead of promising an attribution that will never arrive.
	Unrecorded bool
	Pending    bool

	ApprovalID   string
	ApprovalHref string

	// GrantID is set only when a batch/window Grant released this dispatch.
	// Rendered separately from ApprovalID because the distinction — "a human
	// approved THIS plan" versus "a human approved a window this plan fell
	// inside" — is one an auditor needs and cannot recover from the approval
	// id alone.
	GrantID string

	// ApprovalAnswer, DecisionChannel, and PlanHash are the export-only
	// counterpart to State (#545): plain strings, fed from trailFacts,
	// carried so the CSV export can name a decision's structured answer even
	// though the page itself only ever renders State's chip form.
	ApprovalAnswer  string
	DecisionChannel string
	PlanHash        string

	Reason string

	// ReadClass marks a row whose output was never retained.
	ReadClass bool
}

// activityFilter is this screen's LINKABLE STATE, parsed from the URL and
// rendered back into every link on the page.
//
// Everything except Q reaches a SEAM rather than being applied to the fetched
// page, which is the difference between a filter and a highlighter: a filter
// applied in Go after a page of 50 comes back returns three rows and an
// "older" link, and an operator reads that as "three things happened".
type activityFilter struct {
	// Kind selects the lanes. Empty runs both; "dispatch" runs the Job lane
	// alone; anything else runs the trail lane alone, narrowed to that
	// family's audit kinds.
	Kind string

	Account    string // the VERIFIED lane
	OnBehalfOf string // the ASSERTED lane
	Op         string
	Outcome    string // a jobs.OutcomeName, or ""

	// Window is a relative range ("15m", "1h", "24h", "7d"); Since and Until
	// are the resolved absolute bounds, whether they came from Window or from
	// explicit RFC3339 parameters.
	Window       string
	SinceParam   string
	UntilParam   string
	Since, Until time.Time

	// Q refines the FETCHED PAGE by substring, and nothing else. It is
	// labelled as such on the screen: inventing a second query grammar here
	// would guarantee it and the read lane's disagree about what
	// `outcome:denied` means.
	Q string

	// Job and Audit are each lane's own position. See lanePos: a cursor
	// alone cannot say "this lane is finished", and an empty one means
	// "start from the top".
	Job   lanePos
	Audit lanePos
}

// lanePos is where one lane is, and whether it has anywhere left to go.
//
// Done is not a convenience. The two lanes page INDEPENDENTLY, so one runs out
// before the other, and an empty cursor in the URL is indistinguishable from
// "start from the top" — so an exhausted lane silently RESTARTED AT PAGE ONE
// on the next "Older", re-rendering its newest rows under an older heading and
// always reporting another page, which made the "Older" chain infinite. That
// is the mirror image of losing rows from an audit trail, and this screen must
// not do either. So exhaustion is REPRESENTABLE IN THE URL, as its own
// parameter rather than as a sentinel value inside an opaque cursor the store
// owns the encoding of.
type lanePos struct {
	Cursor string
	Done   bool
}

// activityWindows is the closed vocabulary of relative ranges.
var activityWindows = []struct {
	Value string
	Label string
	Dur   time.Duration
}{
	{"15m", "last 15 minutes", 15 * time.Minute},
	{"1h", "last hour", time.Hour},
	{"24h", "last 24 hours", 24 * time.Hour},
	{"7d", "last 7 days", 7 * 24 * time.Hour},
}

// parseActivityFilter reads the filter out of the URL, returning a note for
// anything it could not read.
//
// A value it does not understand is DROPPED AND NAMED, never silently applied
// as something else: a time range that quietly became "everything" is how an
// auditor concludes an event did not happen.
func parseActivityFilter(r *http.Request, now time.Time) (activityFilter, string) {
	q := r.URL.Query()
	f := activityFilter{
		Kind:       strings.TrimSpace(q.Get("kind")),
		Account:    strings.TrimSpace(q.Get("account")),
		OnBehalfOf: strings.TrimSpace(q.Get("on_behalf_of")),
		Op:         strings.TrimSpace(q.Get("op")),
		Outcome:    strings.TrimSpace(q.Get("outcome")),
		Window:     strings.TrimSpace(q.Get("window")),
		SinceParam: strings.TrimSpace(q.Get("since")),
		UntilParam: strings.TrimSpace(q.Get("until")),
		Q:          q.Get("q"),
		Job:        lanePos{Cursor: q.Get("jc"), Done: q.Get("jdone") == "1"},
		Audit:      lanePos{Cursor: q.Get("ac"), Done: q.Get("adone") == "1"},
	}

	var notes []string
	// The read lane bounds this field and REFUSES a longer one (capability's
	// validateOnBehalfOf). Catching it here turns a 500 on a hand-built URL
	// into a page that says which value was too long, which is the same
	// courtesy the time range gets below.
	if len(f.OnBehalfOf) > maxOnBehalfOfChars {
		notes = append(notes, "on_behalf_of is longer than the "+strconv.Itoa(maxOnBehalfOfChars)+
			" bytes an asserted identity can be recorded as, so it was ignored")
		f.OnBehalfOf = ""
	}
	if f.Outcome != "" && outcomeFromLabel(f.Outcome) == nil {
		notes = append(notes, "the outcome "+quoted(f.Outcome)+" is not one this Relay records, so it was ignored")
		f.Outcome = ""
	}

	// An explicit range beats a relative one, and asking for both is a
	// contradiction rather than a preference — say so.
	if f.Window != "" {
		d, ok := windowDuration(f.Window)
		switch {
		case !ok:
			notes = append(notes, "the time window "+quoted(f.Window)+" is not one this screen offers, so it was ignored")
			f.Window = ""
		case f.SinceParam != "" || f.UntilParam != "":
			notes = append(notes, "both a relative window and an explicit range were given; the explicit range was used")
			f.Window = ""
		default:
			f.Since = now.Add(-d)
		}
	}
	if f.SinceParam != "" {
		if t, err := time.Parse(time.RFC3339, f.SinceParam); err == nil {
			f.Since = t
		} else {
			notes = append(notes, "since= is not an RFC 3339 timestamp, so it was ignored")
			f.SinceParam = ""
		}
	}
	if f.UntilParam != "" {
		if t, err := time.Parse(time.RFC3339, f.UntilParam); err == nil {
			f.Until = t
		} else {
			notes = append(notes, "until= is not an RFC 3339 timestamp, so it was ignored")
			f.UntilParam = ""
		}
	}
	// The read lane refuses a range that runs backwards. Catching it here
	// means the operator is told which half was wrong instead of being handed
	// the seam's validation error.
	if !f.Since.IsZero() && !f.Until.IsZero() && !f.Until.After(f.Since) {
		notes = append(notes, "until must be after since; the range was ignored")
		f.Since, f.Until, f.SinceParam, f.UntilParam, f.Window = time.Time{}, time.Time{}, "", "", ""
	}

	return f, strings.Join(notes, "; ")
}

func quoted(s string) string { return "\"" + s + "\"" }

func windowDuration(v string) (time.Duration, bool) {
	for _, w := range activityWindows {
		if w.Value == v {
			return w.Dur, true
		}
	}
	return 0, false
}

// outcomeFromLabel is the inverse of jobs.OutcomeName over the eight outcomes a
// Task can report. nil means "not an outcome", never "any outcome".
func outcomeFromLabel(label string) *jobs.Outcome {
	for _, o := range []jobs.Outcome{
		jobs.OutcomeSuccess, jobs.OutcomeFailure, jobs.OutcomeTimeout,
		jobs.OutcomeDeniedByPolicy, jobs.OutcomeCancelled, jobs.OutcomeUnreachable,
		jobs.OutcomeVersionRefused, jobs.OutcomeUnsupported,
	} {
		if jobs.OutcomeName(o) == label {
			outcome := o
			return &outcome
		}
	}
	return nil
}

// base renders the filter as a URL at page one of both lanes — what every link
// on the page except "Older" wants.
func (f activityFilter) base() string { return f.href(lanePos{}, lanePos{}) }

// href renders the filter back into a URL, with the two lane positions
// replaced. A zero lanePos drops both of its parameters, which is page one.
func (f activityFilter) href(job, audit lanePos) string {
	v := url.Values{}
	set := func(name, value string) {
		if value != "" {
			v.Set(name, value)
		}
	}
	set("kind", f.Kind)
	set("account", f.Account)
	set("on_behalf_of", f.OnBehalfOf)
	set("op", f.Op)
	set("outcome", f.Outcome)
	set("window", f.Window)
	set("since", f.SinceParam)
	set("until", f.UntilParam)
	set("q", f.Q)
	set("jc", job.Cursor)
	set("ac", audit.Cursor)
	// Carried as their own parameters so that "finished" survives the round
	// trip. Without them the next request reads an empty cursor as page one.
	if job.Done {
		set("jdone", "1")
	}
	if audit.Done {
		set("adone", "1")
	}
	if len(v) == 0 {
		return "/console/activity"
	}
	return "/console/activity?" + v.Encode()
}

// narrowing reports whether anything at all was asked for. It is what decides
// between "nothing matches" and "nothing has been recorded yet", which are
// different claims: the first is about a filter and the second is about the
// fleet, and making the first on a fresh Relay tells an operator their filter
// is wrong when the trail is simply empty.
func (f activityFilter) narrowing() bool {
	return f.Kind != "" || f.Account != "" || f.OnBehalfOf != "" || f.Op != "" ||
		f.Outcome != "" || f.Q != "" || !f.Since.IsZero() || !f.Until.IsZero()
}

// withKind returns the filter with a different kind and no cursors — what a
// chip links to. Selecting the current kind CLEARS it, so a chip is a toggle.
func (f activityFilter) withKind(k rowKind) activityFilter {
	if f.Kind == string(k) {
		f.Kind = ""
	} else {
		f.Kind = string(k)
	}
	f.Job, f.Audit = lanePos{}, lanePos{}
	return f
}

type activityView struct {
	Rows  []activityRow
	Kinds []kindChip

	Filter   activityFilter
	Windows  []choice
	Outcomes []choice

	// Note carries anything parseActivityFilter could not read.
	Note string

	// UnknownKind is set when ?kind= named no family at all. NOTHING is
	// queried in that case: an unrecognised filter must not fall back to
	// "everything", which is the one direction a filter must never fail.
	UnknownKind string

	// DispatchOnly and TrailOnly say which lanes ran, which is what makes the
	// page boundary note honest — with one lane the boundary IS a single
	// instant.
	DispatchOnly bool
	TrailOnly    bool

	// Exhausted says both lanes have already been paged to their end.
	Exhausted bool

	JobPageSize   int
	AuditPageSize int

	// Narrowing says the operator asked for something. See
	// activityFilter.narrowing.
	Narrowing bool

	OlderHref  string
	ResetHref  string
	ExportHref string
	ReadsHref  string

	// ReadsLeftOutHref is set ONLY when no kind filter is set — the one case
	// in which the feed leaves the `read` family out (activityLaneExcluded).
	// It is the `read` chip's own href, so following it keeps every other
	// filter (an Account, a window) in place. The template draws the visible
	// read-records sentence beside the kind chips from it: a responder
	// filtering to one Account must be told, where they are looking, that
	// its enumeration is not in this feed.
	ReadsLeftOutHref string

	Live Live
}

// kindChip is one family link. It carries NO COUNT, and that is a deletion
// rather than an omission: the counts this screen used to print were only ever
// computable because the entire window was in memory. Counting per family
// across a paginated trail would take one aggregate query per family, each of
// which writes its own read record — ten extra rows in the append-only trail
// to render ten numbers. job.go states the rule this follows: a page that
// prints a number it did not compute has nothing to offer an operator.
//
// The cost, stated: the chips now show every family, including ones with no
// rows in the current range. They are a map of the vocabulary, not a summary
// of the page.
type kindChip struct {
	Kind    rowKind
	Current bool
	Href    string
}

// choice is one option in a filter select. Built in Go from the SAME closed
// vocabularies the rows render from, so a filter can never offer a value no
// row could carry.
type choice struct {
	Value    string
	Label    string
	Selected bool
}

func handleActivity(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The read lane takes a capability.Principal, exactly as Job detail
		// does. Both are context reads; page() resolves the same principal
		// itself for the shell.
		caller, ok := principal(w, r)
		if !ok {
			return
		}
		p, ok := page(d, w, r, "Activity")
		if !ok {
			return
		}
		p.Banner = banner(d, r)

		if d.Queries == nil {
			unavailable(w, "the audit and Job query lane")
			return
		}
		// Every read this page and its CSV export make goes through the
		// latch: the "a page whose read cannot be audited is not served" rule
		// is one call rather than a branch per read (screen.go).
		d, lane := latched(d)

		f, note := parseActivityFilter(r, d.now())

		jobLane, trailKinds, known := activityLanes(f)
		// A lane that ran out stays out. Without this an exhausted lane
		// restarts at page one on every "Older" — see lanePos.
		ranJob := jobLane && !f.Job.Done
		ranTrail := len(trailKinds) > 0 && !f.Audit.Done
		if !ranTrail {
			trailKinds = nil
		}
		if known && r.URL.Query().Get("format") == "csv" {
			// The export always starts from page one of both lanes: a file
			// an auditor keeps must not silently begin where some link
			// happened to leave off.
			writeActivityCSV(r.Context(), w, lane, d, caller, f, jobLane, activityLaneKinds(f))
			return
		}

		v := activityView{
			Filter:        f,
			Note:          note,
			JobPageSize:   jobPageSize,
			AuditPageSize: auditPageSize,
			DispatchOnly:  ranJob && !ranTrail,
			TrailOnly:     !ranJob && ranTrail,
			// Both lanes finished. Only reachable by hand-editing the URL —
			// the "Older" link is not drawn in this state — but "nothing
			// matches" would be a lie about the filter rather than about the
			// position, so it gets its own sentence.
			Exhausted: known && !ranJob && !ranTrail,
			ResetHref: "/console/activity",
			ReadsHref: "/console/reads",
			Narrowing: f.narrowing(),
			Windows:   windowChoices(f.Window),
			Outcomes:  outcomeChoices(f.Outcome),
			Kinds:     kindChips(f),
		}
		if f.Kind == "" {
			for _, c := range v.Kinds {
				if c.Kind == rowRead {
					v.ReadsLeftOutHref = c.Href
				}
			}
		}
		if !known {
			v.UnknownKind = f.Kind
			renderScreen(w, p, activityTmpl, v)
			return
		}

		rows, jobNext, auditNext, err := fetchActivity(r.Context(), d, caller, f, ranJob, trailKinds,
			capability.PageRequest{Limit: jobPageSize, Cursor: f.Job.Cursor},
			capability.PageRequest{Limit: auditPageSize, Cursor: f.Audit.Cursor})
		if err != nil {
			readFailed(w, err, "the audit and Job query lane")
			return
		}
		if refusedUnaudited(w, lane, "the audit and Job query lane") {
			return
		}
		v.Rows = rows

		// BOTH lane positions travel, always, and a lane that came back with
		// no Next travels as FINISHED rather than as an empty cursor. "Older"
		// is drawn only while some lane has a real next page, so the chain
		// terminates instead of looping over a restarted lane forever.
		nextJob, nextAudit := f.Job, f.Audit
		if ranJob {
			nextJob = lanePos{Cursor: jobNext, Done: jobNext == ""}
		}
		if ranTrail {
			nextAudit = lanePos{Cursor: auditNext, Done: auditNext == ""}
		}
		if jobNext != "" || auditNext != "" {
			v.OlderHref = f.href(nextJob, nextAudit)
		}
		v.ExportHref = f.base() + exportSuffix(f)

		// The live region, only where the current view actually renders
		// dispatch rows. A screen with no live seam — or a filter with no
		// live kind in it — must not load a script that sits there queueing
		// events the view would never show.
		if d.Events != nil && ranJob {
			v.Live = Live{
				Wired:       true,
				Endpoint:    "/console/events?kinds=job",
				LastEventID: newestJobEventID(d.Events),
				ShowHref:    f.base(),
				CountNote: "The number counts job events on the stream, not rows that will appear. " +
					"This page's filter does not narrow the stream. " +
					"One Job announces itself more than once: when it is created, and again when it completes.",
			}
			p.Scripts = []string{"/console/assets/stream.js", "/console/assets/activity.js"}
		}

		renderScreen(w, p, activityTmpl, v)
	}
}

// activityLaneKinds is activityLanes' trail half, for the export — which
// always starts at page one and therefore never skips a lane for position.
func activityLaneKinds(f activityFilter) []string {
	_, kinds, _ := activityLanes(f)
	return kinds
}

// activityLanes decides which lanes a filter SELECTS. Whether a selected lane
// still has anything to give is lanePos's question, answered by the caller.
//
// known=false means ?kind= named no family. The caller queries NOTHING in that
// case rather than falling back to both lanes: a filter nobody recognises must
// narrow to nothing, never widen to everything.
func activityLanes(f activityFilter) (jobLane bool, trailKinds []string, known bool) {
	switch {
	case f.Kind == "":
		return true, activityTrailKinds, true
	case f.Kind == string(rowDispatch):
		// THE JOBS LIST. The audit lane is not queried at all — assertable as
		// a call count, not as a claim about what rendered.
		return true, nil, true
	default:
		for _, k := range rowKindOrder {
			if f.Kind == string(k) {
				return false, kindsOfFamily(k), true
			}
		}
		return false, nil, false
	}
}

// fetchActivity runs the active lanes and merges them, newest first.
func fetchActivity(ctx context.Context, d Deps, caller capability.Principal, f activityFilter,
	jobLane bool, trailKinds []string, jobPage, auditPage capability.PageRequest,
) (rows []activityRow, jobNext, auditNext string, err error) {
	if jobLane {
		page, err := d.Queries.QueryJobs(ctx, caller, capability.JobFilter{
			RequesterAccountID: f.Account,
			OnBehalfOf:         f.OnBehalfOf,
			Operation:          f.Op,
			Since:              f.Since,
			Until:              f.Until,
		}, jobPage)
		if err != nil {
			return nil, "", "", err
		}
		outcome := outcomeFromLabel(f.Outcome)
		for _, sum := range page.Jobs {
			// EXACT, because the counts come from the aggregate: the
			// predicate is "this Job produced at least one X". Applied here
			// and not in the query because JobFilter has no outcome field —
			// see the page's own note about what that costs.
			if outcome != nil && sum.Counts[*outcome] == 0 {
				continue
			}
			rows = append(rows, dispatchRowFromJob(sum))
		}
		jobNext = page.Next
	}

	if len(trailKinds) > 0 {
		filter := capability.AuditFilter{
			Kinds:      trailKinds,
			AccountID:  f.Account,
			OnBehalfOf: f.OnBehalfOf,
			Outcome:    outcomeFromLabel(f.Outcome),
			Since:      f.Since,
			Until:      f.Until,
		}
		if f.Op != "" {
			filter.Operations = []string{f.Op}
		}
		page, err := d.Queries.QueryAudit(ctx, caller, filter, auditPage)
		if err != nil {
			return nil, "", "", err
		}
		for _, row := range page.Rows {
			rows = append(rows, eventRowFromTrail(factsOfRow(row)))
		}
		auditNext = page.Next
	}

	if f.Q != "" {
		kept := rows[:0]
		for _, row := range rows {
			if matchesQuery(row, f.Q) {
				kept = append(kept, row)
			}
		}
		rows = kept
	}

	// Both lanes return newest-first, so a stable sort by time interleaves
	// them without disturbing either lane's own order among equal timestamps.
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].at.After(rows[j].at) })
	return rows, jobNext, auditNext, nil
}

func kindChips(f activityFilter) []kindChip {
	chips := make([]kindChip, 0, len(rowKindOrder))
	for _, k := range rowKindOrder {
		chips = append(chips, kindChip{
			Kind:    k,
			Current: f.Kind == string(k),
			Href:    f.withKind(k).base(),
		})
	}
	return chips
}

func windowChoices(current string) []choice {
	out := make([]choice, 0, len(activityWindows))
	for _, w := range activityWindows {
		out = append(out, choice{Value: w.Value, Label: w.Label, Selected: w.Value == current})
	}
	return out
}

// outcomeChoices renders the eight outcomes through jobs.OutcomeName, which is
// also what outcomeFromLabel inverts — one vocabulary, read in both
// directions, so the select cannot offer a value the parser rejects.
func outcomeChoices(current string) []choice {
	all := []jobs.Outcome{
		jobs.OutcomeSuccess, jobs.OutcomeFailure, jobs.OutcomeTimeout,
		jobs.OutcomeDeniedByPolicy, jobs.OutcomeCancelled, jobs.OutcomeUnreachable,
		jobs.OutcomeVersionRefused, jobs.OutcomeUnsupported,
	}
	out := make([]choice, 0, len(all))
	for _, o := range all {
		label := jobs.OutcomeName(o)
		out = append(out, choice{Value: label, Label: label, Selected: label == current})
	}
	return out
}

// exportSuffix appends format=csv to a href the filter already built.
func exportSuffix(f activityFilter) string {
	if strings.Contains(f.base(), "?") {
		return "&format=csv"
	}
	return "?format=csv"
}

// newestJobEventID is the resume point the live region starts from: the newest
// Job event the seam still retains, so the stream picks up where this render
// stopped rather than replaying a window the page already accounts for.
func newestJobEventID(r EventReader) string {
	recent := r.Recent([]events.Kind{events.KindJob}, 1)
	if len(recent) == 0 {
		return ""
	}
	return recent[len(recent)-1].ID
}

// matchesQuery is a substring match over the fields an operator would type.
//
// Deliberately not a query language, and deliberately applied to the FETCHED
// PAGE only. The real filter — principal, Operation, outcome, time range, with
// cursor pagination — is the capability layer's read lane, and inventing a
// second grammar here would guarantee the two disagree about what
// `outcome:denied` means.
func matchesQuery(row activityRow, q string) bool {
	q = strings.TrimSpace(strings.ToLower(q))
	if q == "" {
		return true
	}
	hay := strings.ToLower(strings.Join([]string{
		row.EventKind, row.Summary, row.Principal, row.OnBehalfOf, row.Selector,
		row.NodeID, row.Operation, row.Args, row.JobID, row.Reason, row.ApprovalID, row.GrantID,
		row.State,
	}, " "))
	for _, term := range strings.Fields(q) {
		if !strings.Contains(hay, term) {
			return false
		}
	}
	return true
}

// dispatchRowFromJob builds the Job-grained dispatch row from ONE aggregate
// summary.
//
// NodeID stays empty, structurally: capability.JobSummary has no such field. A
// Job spans its Selector's whole fan-out, and rendering the Node from whichever
// Task record happened to build the row would say the Job targeted one machine
// when it targeted many. Per-Node results are on the Job's own page.
func dispatchRowFromJob(sum capability.JobSummary) activityRow {
	row := activityRow{
		Kind:      rowDispatch,
		EventKind: audit.KindDispatch,
		at:        sum.CreatedAt,
		When:      sum.CreatedAt.UTC().Format("2006-01-02 15:04:05Z"),
		Operation: jobOperationText(sum.OperationName, sum.ActionKind),
		Args:      argsSummary(sum.Args, sum.RawExecArgv),
		// The DECLARED class, from tasks.risk_class — never this package's
		// name inference. A Template Operation the Console has never heard of
		// is still classified by the catalog that dispatched it.
		ReadClass:     sum.RiskClass == jobs.RiskClassRead,
		Selector:      sum.Selector,
		FanOut:        sum.Total,
		InFlight:      sum.Unresolved,
		Outcomes:      barFrom(sum.Counts),
		JobID:         sum.JobID,
		JobHref:       "/console/jobs/" + sum.JobID,
		Principal:     sum.Requester,
		Verified:      sum.RequesterAccountID != "",
		RequesterKind: verifiedKind(sum.RequesterAccountID != "", sum.RequesterKind),
		OnBehalfOf:    sum.OnBehalfOf,
		ApprovalID:    sum.ApprovalID,
		GrantID:       sum.GrantID,
	}
	if sum.RiskClass != jobs.RiskClassUnspecified {
		row.Risk = jobs.RiskClassName(sum.RiskClass)
	}
	row.Summary = row.Operation
	row.OpIsLink = row.Operation != ""
	row.LiveHandle = true
	if sum.ApprovalID != "" {
		row.ApprovalHref = "/console/approvals/" + sum.ApprovalID
	}
	if sum.Requester == "" {
		// The Job engine publishes JobCompleted BEFORE its audit record is
		// written, so a Job can be on this screen with no requester yet. Say
		// that, rather than "unattributed", which claims the Relay looked —
		// but say it ONLY while the Job is still running. See activityRow.
		row.Unrecorded = true
		row.Pending = sum.Unresolved > 0
	}
	return row
}

// eventRowFromTrail builds every non-dispatch row from the trail lane.
func eventRowFromTrail(f trailFacts) activityRow {
	row := activityRow{
		Kind:            kindOf(f.Kind),
		EventKind:       f.Kind,
		at:              f.Timestamp,
		When:            f.Timestamp.UTC().Format("2006-01-02 15:04:05Z"),
		Principal:       principalText(f),
		Verified:        f.VerifiedAccountID != "",
		OnBehalfOf:      f.OnBehalfOf,
		Selector:        f.Selector,
		NodeID:          f.NodeID,
		Operation:       operationText(f),
		Args:            argsText(f),
		Reason:          f.Reason,
		Summary:         summarize(f),
		ApprovalID:      f.ApprovalID,
		GrantID:         f.GrantID,
		State:           approvalStateChip(f),
		ApprovalAnswer:  f.ApprovalAnswer,
		DecisionChannel: f.DecisionChannel,
		PlanHash:        f.PlanHash,
	}
	// The trail carries no declared risk class, so this lane INFERS one — the
	// one place this package guesses, with its limits written down in
	// vocab.go. The Job lane above never calls it.
	//
	// The chip is drawn only for the families that DESCRIBE SOMETHING THAT
	// RUNS. A Freeze engage or a sign-in has no risk class at all, and riskOf
	// answers "mutate" for both because mutate is the safe direction for an
	// unrecognised OPERATION — an answer that is right for its question and
	// meaningless as a badge on a sign-in. Labelling every row on the trail
	// `mutate` would teach an operator to ignore the chip on the rows where it
	// is the whole point. Same set agent history draws it for.
	risk := riskOf(f)
	switch row.Kind {
	case rowDispatch, rowRead, rowRefusal, rowApproval:
		row.Risk = jobs.RiskClassName(risk)
	}
	row.ReadClass = risk == jobs.RiskClassRead
	if f.NodeID != "" {
		row.NodeHref = "/console/nodes/" + f.NodeID
	}
	if f.ApprovalID != "" {
		row.ApprovalHref = "/console/approvals/" + f.ApprovalID
	}
	if f.JobID != "" {
		row.JobID = f.JobID
		row.JobHref = "/console/jobs/" + f.JobID
		row.OpIsLink = row.Operation != ""
	}
	return row
}

// summarize renders the one-line description of a non-dispatch event.
//
// It is a switch and not a format string on the record because these events are
// not variations of one thing: a Freeze release and a sign-in have nothing in
// common except that they happened, and prose that pretends otherwise reads as
// machine output rather than as a trail.
func summarize(f trailFacts) string {
	switch f.Kind {
	case audit.KindFreezeEngage:
		return "engaged the Relay-wide Freeze — no new Tasks dispatch"
	case audit.KindFreezeRelease:
		return "released the Freeze"
	case audit.KindJobCancel:
		return "cancelled Job " + shortHash(f.JobID)
	case audit.KindTokenMint:
		return "minted an Enrollment Token"
	case audit.KindTokenRevoke:
		return "revoked an Enrollment Token — every Node it enrolled is revoked with it"
	case audit.KindNodeRevoke:
		return "revoked Node " + f.NodeID
	case audit.KindAPITokenMint:
		return "minted an API Token"
	case audit.KindAPITokenRevoke:
		return "revoked an API Token"
	case audit.KindAccountCreate:
		return "created an Account"
	case audit.KindAccountRole:
		return "changed an Account's role"
	case audit.KindAccountEnable:
		return "enabled an Account"
	case audit.KindAccountDisable:
		return "disabled an Account"
	case audit.KindLoginSucceeded:
		return "signed in to the Console"
	case audit.KindLoginFailed:
		return "failed a Console sign-in"
	case audit.KindLoginThrottled:
		return "was throttled signing in"
	case audit.KindLogout:
		return "signed out"
	case audit.KindStepUp:
		return "re-proved presence for a step-up"
	case audit.KindStepUpFailed:
		return "failed a step-up re-authentication"
	case audit.KindStepUpThrottled:
		return "was throttled re-authenticating for a step-up"
	case audit.KindApprovalRequested:
		return "parked a dispatch for approval"
	case audit.KindApprovalGrantRequested:
		// #546: a Grant is an ask for STANDING authority over many future
		// dispatches, so it must not read as one Plan waiting for one answer.
		return "requested an Approval grant"
	case audit.KindApprovalPendingObserved:
		return "re-drove a dispatch that is already parked"
	case audit.KindApprovalDecided:
		// Same discriminators as agents.go's agentCallFrom, no new vocabulary:
		// GrantID is RevokeGrant's structural marker (#538); the structured
		// answer (#545) otherwise names which way the decision went; a
		// pre-#545 decision with neither falls back to the original sentence.
		switch {
		case f.GrantID != "":
			return "revoked an Approval grant"
		case f.ApprovalAnswer == audit.ApprovalAnswerApproved:
			return "approved a parked dispatch"
		case f.ApprovalAnswer == audit.ApprovalAnswerDenied:
			return "denied a parked dispatch"
		default:
			return "answered an approval request"
		}
	case audit.KindApprovalExpired:
		return "an approval request expired unanswered"
	case audit.KindRefusal:
		return "was refused"
	case audit.KindPlan:
		return "resolved a Preflight — nothing executed"
	case audit.KindRead:
		// A read that reached a Node arrives as a read-class DISPATCH and is
		// rolled up by Job through the Job lane. What lands here is the other
		// family: the non-dispatching tools that read the Relay's own registry
		// and Operation catalogue.
		//
		// These rendered as the bare word "read" — no target, no Node, no
		// outcome — while the very same records drove the Read-egress screen's
		// enumeration panel. The trail had the fact and this surface, which is
		// billed as the trail, declined to say it.
		//
		// readTargetOf is reused rather than reimplemented, and that is the
		// point: the first attempt here read ActionKind, which is empty on
		// these records — the tool name lives in OperationName — so Activity
		// said "the registry" while Read egress said "list_nodes" about the
		// same audit row. Two screens naming one thing two ways is how an
		// operator stops trusting either.
		return "enumerated " + readTargetOf(f)
	case audit.KindProtocolViolation:
		return "a Node reported something the wire contract does not permit"
	default:
		return f.Kind
	}
}

// --- Export -----------------------------------------------------------------

// activityCSVHeader is the export's column list. There is NO OUTPUT COLUMN and
// there can never be one: neither capability.AuditRow nor capability.JobSummary
// has a field to fill it from (ADR-0025).
var activityCSVHeader = []string{
	"when", "family", "audit_kind", "principal", "verified", "on_behalf_of",
	"selector", "node_id", "operation", "args", "risk_class",
	"job_id", "fan_out", "in_flight", "outcomes", "approval_id", "grant_id",
	"approval_answer", "decision_channel", "plan_hash", "reason",
}

// writeActivityCSV re-runs the same filter across at most exportPages pages per
// lane and streams the result as an attachment.
//
// A GET, so Secure's safe-method short-circuit applies and no CSRF token is
// involved — it mutates nothing. It does append two read records per page it
// walks, exactly as rendering the screen does; the trail records the export as
// the reads it actually is.
func writeActivityCSV(ctx context.Context, w http.ResponseWriter, lane *auditLatch, d Deps, caller capability.Principal,
	f activityFilter, jobLane bool, trailKinds []string,
) {
	var rows []activityRow
	// Each lane walks from page one to ITS OWN end. A lane that runs out is
	// zeroed rather than re-driven with an empty cursor: an empty cursor is
	// page one, so the shorter lane would otherwise contribute its first page
	// again on every iteration — the same row repeated ten times, in the file
	// an auditor keeps. See lanePos.
	var job, aud lanePos
	capped := false
	for i := 0; ; i++ {
		runJob := jobLane && !job.Done
		runTrail := len(trailKinds) > 0 && !aud.Done
		if !runJob && !runTrail {
			break
		}
		if i == exportPages {
			capped = true
			break
		}
		kinds := trailKinds
		if !runTrail {
			kinds = nil
		}
		page, jobNext, auditNext, err := fetchActivity(ctx, d, caller, f, runJob, kinds,
			capability.PageRequest{Limit: jobPageSize, Cursor: job.Cursor},
			capability.PageRequest{Limit: auditPageSize, Cursor: aud.Cursor})
		if err != nil {
			readFailed(w, err, "the audit and Job query lane")
			return
		}
		rows = append(rows, page...)
		if runJob {
			job = lanePos{Cursor: jobNext, Done: jobNext == ""}
		}
		if runTrail {
			aud = lanePos{Cursor: auditNext, Done: auditNext == ""}
		}
	}

	// The export is checked before a single byte of it is written: a file an
	// auditor keeps must never be half a download plus an error.
	if refusedUnaudited(w, lane, "the audit and Job query lane") {
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="relay-activity.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write(activityCSVHeader)
	for _, row := range rows {
		_ = cw.Write(activityCSVRecord(row))
	}
	// The cap is stated IN THE FILE, because an export is read somewhere this
	// page's prose is not.
	note := "# this export holds every row this Relay returned for the filter"
	if capped {
		note = "# THIS EXPORT IS INCOMPLETE: it stopped after " + strconv.Itoa(exportPages) +
			" pages per lane. Narrow the filter or follow the range."
	}
	_ = cw.Write([]string{note})
	cw.Flush()
}

func activityCSVRecord(row activityRow) []string {
	verified := "asserted"
	if row.Verified {
		verified = "verified"
	}
	var outcomes []string
	for _, seg := range row.Outcomes.Segments {
		outcomes = append(outcomes, seg.Label+"="+strconv.Itoa(seg.Count))
	}
	fields := []string{
		row.When, string(row.Kind), row.EventKind, row.Principal, verified, row.OnBehalfOf,
		row.Selector, row.NodeID, row.Operation, row.Args, row.Risk,
		row.JobID, strconv.Itoa(row.FanOut), strconv.Itoa(row.InFlight), strings.Join(outcomes, " "),
		row.ApprovalID, row.GrantID,
		row.ApprovalAnswer, row.DecisionChannel, row.PlanHash, row.Reason,
	}
	for i, v := range fields {
		fields[i] = csvSafe(v)
	}
	return fields
}

// csvSafe neutralises spreadsheet formula injection.
//
// Not theoretical here: an argv element is caller-controlled, arrives in the
// export verbatim, and legitimately starts with '-'. A field opening with
// '=', '+', '-', '@', a tab or a carriage return is evaluated as a FORMULA by
// every major spreadsheet, and this file's whole audience is an auditor
// opening it in one. The leading apostrophe is the standard neutralisation and
// it is visible, which is the right trade: a value that looks slightly odd
// beats a value that executes.
func csvSafe(v string) string {
	if v == "" {
		return v
	}
	switch v[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + v
	}
	return v
}

var activityTmpl = newScreen("activity", `
<form class="viewbar" method="get" action="/console/activity">
  {{with .Filter.Kind}}<input type="hidden" name="kind" value="{{.}}">{{end}}
  <label class="vlabel" for="account">Principal</label>
  <input id="account" name="account" value="{{.Filter.Account}}" placeholder="Account id" spellcheck="false" autocomplete="off">
  <label class="vlabel" for="on_behalf_of">On behalf of</label>
  <input id="on_behalf_of" name="on_behalf_of" value="{{.Filter.OnBehalfOf}}" placeholder="asserted" spellcheck="false" autocomplete="off">
  <label class="vlabel" for="op">Operation</label>
  <input id="op" name="op" value="{{.Filter.Op}}" placeholder="service.restart" spellcheck="false" autocomplete="off">
  <label class="vlabel" for="outcome">Outcome</label>
  <select id="outcome" name="outcome">
    <option value="">any outcome</option>
    {{range .Outcomes}}<option value="{{.Value}}"{{if .Selected}} selected{{end}}>{{.Label}}</option>{{end}}
  </select>
  <label class="vlabel" for="window">When</label>
  <select id="window" name="window">
    <option value="">all recorded time</option>
    {{range .Windows}}<option value="{{.Value}}"{{if .Selected}} selected{{end}}>{{.Label}}</option>{{end}}
  </select>
  <label class="vlabel" for="q">Refine</label>
  <input id="q" name="q" value="{{.Filter.Q}}" placeholder="substring, this page only" spellcheck="false" autocomplete="off">
  <button type="submit">Apply</button>
  {{if .Rows}}<span class="vcount">{{len .Rows}} {{plural (len .Rows) "event" "events"}}</span>{{end}}
  <a class="act" href="{{.ResetHref}}">Clear</a>
</form>

{{with .Note}}<p class="gap"><b>Part of this URL could not be read:</b> {{.}}.</p>{{end}}

<div class="kindbar">
  {{range .Kinds}}<a class="kchip{{if .Current}} on{{end}}" href="{{.Href}}">{{.Kind}}</a>{{end}}
</div>
{{with .ReadsLeftOutHref}}<p class="kindnote">Read records &mdash; every Account&#39;s enumeration and
every read of this trail &mdash; are left out of this feed: <a href="{{.}}">show them</a>, or see
<a href="{{$.ReadsHref}}">Read egress</a>.</p>{{end}}

{{if .UnknownKind}}
<p class="gap"><b>There is no row kind called &ldquo;{{.UnknownKind}}&rdquo;.</b> Nothing was queried:
an unrecognised filter narrows to nothing here rather than falling back to everything, because a
filter that quietly widens is how an auditor comes to read the whole trail believing it is one
slice of it. Pick a kind above, or <a href="{{.ResetHref}}">clear the filter</a>.</p>
{{else}}

{{template "live-region" .Live}}

<div class="feed">
{{range .Rows}}
  <article class="ev" data-kind="{{.Kind}}"{{if .LiveHandle}} data-job-id="{{.JobID}}"{{end}}>
    <div class="evwhen"><time datetime="{{.When}}">{{.When}}</time><span class="evkind">{{.EventKind}}</span></div>
    <div class="evbody">
      <div class="evhead">
        {{if .Unrecorded}}
          {{if .Pending}}<span class="dim">attribution is recorded when the dispatch completes</span>
          {{else}}<span class="unattrib" title="Every dispatch writes an audit record naming the principal that asked for it. This Job finished without one, which is a defect in the trail rather than an anonymous caller.">this dispatch finished with no recorded principal &mdash; the trail should carry one</span>{{end}}
        {{else}}{{template "trust-chip" (trust .Principal .Verified)}}{{template "kind-label" .RequesterKind}}{{end}}
        {{with .OnBehalfOf}}{{template "trust-chip" (trust . false)}}{{end}}
        {{if .OpIsLink}}<a class="evop" href="{{.JobHref}}"><code>{{.Operation}}</code></a>
        {{else}}<span class="evsum">{{.Summary}}</span>{{end}}
        {{with .Risk}}<span class="chip risk" data-risk="{{.}}">{{.}}</span>{{end}}
        {{with .State}}<span class="chip state" data-state="{{.}}">{{.}}</span>{{end}}
      </div>
      {{with .Args}}<div class="evargs mono">{{.}}</div>{{end}}
      <div class="evmeta">
        {{with .Selector}}<code class="selector">{{.}}</code>{{end}}
        {{if .FanOut}}<span class="fanmath">{{.FanOut}} {{plural .FanOut "Node" "Nodes"}}</span>{{end}}
        {{if .InFlight}}<span class="overcap">{{.InFlight}} still in flight</span>{{end}}
        {{if .NodeHref}}<a href="{{.NodeHref}}"><code>{{.NodeID}}</code></a>{{end}}
        {{if and .JobHref (not .OpIsLink)}}<a href="{{.JobHref}}">Job <code>{{short .JobID}}</code></a>{{end}}
        {{with .ApprovalHref}}<a href="{{.}}">approval</a>{{end}}
        {{with .GrantID}}<span class="grant" title="A Grant released this: a human approved a window that this Plan fell inside, not this Plan itself.">grant {{short .}}</span>{{end}}
      </div>
      {{if .Outcomes.Total}}{{template "outcome-bar" .Outcomes}}{{end}}
      {{if .LiveHandle}}<div class="evliveslot">
        <span class="evlive" data-when="completed">completed after this page was rendered &mdash; reload to see its outcomes</span>
        <span class="evlive" data-when="cancelled">cancelled after this page was rendered &mdash; reload to see its outcomes</span>
      </div>{{end}}
      {{with .Reason}}<div class="evreason">{{.}}</div>{{end}}
      {{if .ReadClass}}<div class="evnote">Output was not retained. Nothing here will show it later.</div>{{end}}
    </div>
  </article>
{{else}}
  {{if .Exhausted}}<p class="dim">There is nothing older for this filter.
  <a href="{{.ResetHref}}">Start again</a>.</p>
  {{else if .Narrowing}}<p class="dim">Nothing matches.</p>
  {{else}}<p class="dim">Nothing has been recorded yet.</p>{{end}}
{{end}}
</div>

<div class="pager">
  {{with .OlderHref}}<a class="act" href="{{.}}">Older</a>{{end}}
  {{with .ExportHref}}<a href="{{.}}">Export this filter as CSV</a>{{end}}
</div>

{{if .Filter.Q}}
<p class="gap"><b>Refine</b> matches text within the rows already on this page. It does not search
the trail; the other fields do.</p>
{{end}}

{{if .Filter.Outcome}}
<p class="gap"><b>Outcome narrows dispatch rows after the page is fetched.</b> A Job has no single
outcome, so this keeps every Job that produced at least one <code>{{.Filter.Outcome}}</code>. The Job
query cannot filter by outcome, so a filtered page can come back short while &ldquo;Older&rdquo; still
leads somewhere. For every other row kind, the outcome is applied in the query.</p>
{{end}}

<details class="about">
<summary>About this screen</summary>

<p class="gap"><b>Each page holds up to {{.JobPageSize}} dispatches and up to {{.AuditPageSize}} other
events, merged by time.</b>
{{if or .DispatchOnly .TrailOnly}}This filter reads only one of the two, so a page ends at a single moment.
{{else}}Dispatches and other events are paged separately, so a page does not end at a single moment.
Following &ldquo;Older&rdquo; continues both from where they stopped; neither starts again.{{end}}</p>

<p class="gap"><b>The default feed leaves out the trail&#39;s own read records.</b> Reading the trail
writes to it: this page adds a read record each time it fetches dispatches or other events. A feed
that included them would fill with the operator&#39;s own reloads. They are one click away as
<a href="/console/activity?kind=read">kind=read</a>, and their home is
<a href="{{.ReadsHref}}">Read egress</a>. Nothing is hidden.</p>

<p class="gap"><b>Two row kinds cannot be shown here yet: enrollments and label changes.</b> The
audit trail holds no record of either. An enrollment exists only on the live event stream, for a few
minutes, and label management is not built. Splicing those few minutes into a feed you can scroll
back through would put rows on this screen that vanish as you read, which is worse than leaving them
out.</p>

<p class="gap"><b>The filter box carries no Selector and no Node.</b> The Job query has a field for
neither. A Job spans its Selector&#39;s whole fan-out, so it has no single Node. A Node filter that
narrowed only the other events would silently drop every dispatch row from the page.</p>

<p class="gap"><b>Every reload is an audited read</b>, whether you use the reload button above or
the browser&#39;s own.</p>

<p class="gap"><b>The chips above list every family this Relay records, including empty ones.</b>
They carry no counts. Counting each family across the whole trail would take one query per family,
and each query adds its own record to the append-only trail &mdash; ten extra rows
to print ten numbers. A page that prints a number it did not compute has nothing to offer an
operator reading it during an incident.</p>
</details>

{{end}}
`)
