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
// Only tool calls are rows: dispatches, and the approvals, refusals,
// Preflights, reads and cancels that come from capability.QueryAudit.
// Freeze transitions, Node revokes, Enrollment Token events and other
// non-call records stay on the trail without being drawn here (spec 04,
// Grain; owner decision 2026-10-01). Sign-ins, step-up, Account changes and
// API Token mints and revokes are NOT among them either — those change who
// can get in rather than what happened to the fleet, and they are the
// admin-only Access screen's rows instead (access.go, spec 20, D17).
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
// # The collapse and Console reads
//
// Kept in callfeed.go. The order is fixed:
// reads made from a Console session are left out in the fetch (fetchActivity),
// then consecutive identical rows fold, and only then does Cancel attach, so
// each running Job keeps exactly one Cancel.
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
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/events"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
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
	rowPlan     rowKind = "plan"
	rowCancel   rowKind = "cancel"
	rowApproval rowKind = "approval"
	rowRead     rowKind = "read"
	rowRefusal  rowKind = "refusal"

	// rowAccess is NOT an Activity family: it marks a kind that belongs to
	// the Access screen (access.go, spec 20) instead — sign-in, step-up,
	// account and api-token records. It is deliberately never in
	// rowKindOrder, so no default Kinds filter and no chip filter this
	// screen sends can ever name one of those 13 kinds, and
	// ?kind=<an Access family> falls to the unknown-kind case exactly as
	// ?kind=nonesuch does (spec 04's "not on this screen, for any role").
	rowAccess rowKind = "access"

	// rowNotACall is NOT an Activity family either: it marks a trail record
	// that is not a tool call — Freeze transitions, Node revokes, Enrollment
	// Token events, protocol_violation, revoked Node dials, and any kind nobody has classified
	// (spec 04, Grain; owner decision 2026-10-01). Like rowAccess it is never
	// in rowKindOrder, so it is never a chip, never in the default Kinds and
	// never reachable by ?kind=, which falls to the unknown-kind case.
	rowNotACall rowKind = "not-a-call"
)

// rowKindOrder is every family, in the order the chips render. It is also the
// set kindsOfFamily must be TOTAL over.
var rowKindOrder = []rowKind{
	rowDispatch, rowPlan, rowApproval, rowRefusal, rowRead, rowCancel,
}

// activityNonCallKinds are the trail kinds this screen deliberately does not
// draw: records of fleet events that are not tool calls. They stay on the
// audit trail. The list is hand-kept on purpose, so that
// TestActivity_EveryAuditKindIsClassified fails on a kind nobody classified
// rather than a new kind quietly landing in either place.
var activityNonCallKinds = []string{
	audit.KindFreezeEngage, audit.KindFreezeRelease,
	audit.KindNodeRevoke, audit.KindTokenMint, audit.KindTokenRevoke,
	audit.KindProtocolViolation, audit.KindRevokedNodeDial,
}

// kindOf maps a trail record onto a row family.
func kindOf(k string) rowKind {
	if _, ok := accessKindOf(k); ok {
		return rowAccess
	}
	switch k {
	case audit.KindDispatch, audit.KindDispatchIntent:
		return rowDispatch
	case audit.KindPlan:
		return rowPlan
	case audit.KindJobCancel:
		return rowCancel
	case audit.KindRead:
		return rowRead
	case audit.KindRefusal:
		return rowRefusal
	case audit.KindApprovalRequested, audit.KindApprovalGrantRequested,
		audit.KindApprovalDecided, audit.KindApprovalExpired,
		audit.KindApprovalPendingObserved:
		return rowApproval
	default:
		// Fails closed: a kind no tool-call family claims is not drawn.
		return rowNotACall
	}
}

// kindsByFamily is the INVERSE of kindOf, computed once from audit.Kinds()
// rather than hand-written beside it.
//
// Derived, not enumerated, because the two lists would have to agree and only
// one of them is ever edited. Every audit kind lands in exactly one family by
// construction, including the ones kindOf does not name. Kinds outside
// rowKindOrder's families (Access, not-a-call) are mapped but never requested.
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
//   - dispatch_intent — the Job-level intent record, also served by
//     QueryJobs: it is the Job row's Recording state, not a row of its own.
//   - read — the trail's OWN read records, including the two this screen
//     writes on every page view (capability's read lane records every query).
//     Left out of the default feed so the screen does not fill with itself
//     being read; one click away through the `read` chip.
//
// Both are ONE CLICK AWAY, reachable as their own family. activityAccessKinds
// below is excluded too, but is not: see its own comment.
var activityLaneExcluded = []string{audit.KindDispatch, audit.KindDispatchIntent, audit.KindRead}

// activityAccessKinds is every kind Access (spec 20) owns — accessAllKinds
// itself, named again here rather than re-derived so the two screens'
// vocabularies cannot drift apart. Unlike activityLaneExcluded above, these
// are not on this screen for any role: their home is the admin-only Access
// screen (spec 04's Grain, D17), not a chip on this one.
var activityAccessKinds = accessAllKinds

// activityTrailKinds is what the default feed asks the trail lane for: the
// tool-call families' kinds, except activityLaneExcluded and
// activityAccessKinds. A new audit kind does not appear here automatically: it
// must be classified, and TestActivity_EveryAuditKindIsClassified enforces it.
var activityTrailKinds = defaultTrailKinds()

func defaultTrailKinds() []string {
	excluded := map[string]bool{}
	for _, k := range activityLaneExcluded {
		excluded[k] = true
	}
	for _, k := range activityAccessKinds {
		excluded[k] = true
	}
	var out []string
	for _, k := range audit.Kinds() {
		if !excluded[k] && slices.Contains(rowKindOrder, kindOf(k)) {
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
	// verified one. A jailbroken AI-agent can assert anything it likes; the whole
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
	// relabel history once an Account is converted (04-activity.md, "Kind is
	// never read from the registry").
	RequesterKind string

	Selector string
	NodeID   string
	NodeHref string

	Operation string
	Args      string
	Risk      string

	// State is the `.chip.state` vocabulary (currently just
	// "approved"/"denied"): a decision's structured answer.
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

	// AccountID is the verified Account ID, empty when none was verified. It is
	// exported ONLY so it joins the collapse key (activityCollapseKey): two
	// Accounts sharing a display name must never fold into one row. It is never
	// rendered.
	AccountID string

	// Calls is how many calls this row stands for: 1 unless the collapse folded
	// a run of consecutive identical rows into it. FirstWhen is the When of the
	// OLDEST call in such a run, in the same absolute UTC format as When, and is
	// set only when Calls is above 1.
	Calls     int
	FirstWhen string

	// Outcomes are the per-Job rollup: the segmented bar and its key.
	Outcomes OutcomeBar
	FanOut   int

	// InFlight is how many of the Job's Tasks have not resolved yet.
	InFlight int

	// Outcome is a trail row's result chip (callOutcome); empty draws none.
	Outcome string

	// Running is a Job-lane row with Tasks not yet resolved. It is keyed on
	// Unresolved, not on State: JobStateRunning is iota 0, so a zero-value
	// summary reads as running. Job detail gates its Cancel on Unresolved
	// (job.go), which is what "offered exactly as Job detail's is" means.
	Running bool
	// OutcomeUnrecorded is a finished Job-lane row whose dispatch intent is on
	// the trail with none, or only some, of its outcome rows. The
	// predicate is capability.JobSummary.OutcomeUnrecorded; this only renders
	// it. OutcomePartial picks the wording: some outcome rows exist.
	OutcomeUnrecorded bool
	OutcomePartial    bool
	// Resolved is Total minus Unresolved, drawn as "resolved of total" on a
	// Running row.
	Resolved int
	// RawExecTier marks a Job whose ActionKind is Raw Exec. It is the ONLY
	// source of "this is the Raw Exec tier"; it is never inferred from a name.
	RawExecTier bool
	// AwaitingRecord is a Running row with no audit-joined field joined yet:
	// the Job engine writes its dispatch record after the dispatch returns.
	// The template draws its evnote for it.
	AwaitingRecord bool
	// RunningHref is where a Running row links up to: its entry in Running
	// now when the Job is on that section's current page, else the section.
	// Set by the handler after the fetch and never by the constructors.
	// Cancel lives in Running now and not on this row.
	RunningHref string

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
	// counterpart to State: plain strings, fed from trailFacts,
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

	// The relative window or explicit range, shared with Access.
	timeRange

	// Q refines the FETCHED PAGE by substring, and nothing else. It is
	// labelled as such on the screen: inventing a second query grammar here
	// would guarantee it and the read lane's disagree about what
	// `outcome:denied` means.
	Q string

	// ShowConsole is ?console=show: reads made from a Console session are
	// listed and counted instead of left out (spec 04, "Reads made from this
	// Console"). It widens the view, so narrowing ignores it.
	ShowConsole bool

	// Job and Audit are each lane's own position. See lanePos: a cursor
	// alone cannot say "this lane is finished", and an empty one means
	// "start from the top".
	Job   lanePos
	Audit lanePos

	// Running is Running now's own position (?rc=, ?ro=), independent of
	// Job and Audit: paging one never moves the other.
	Running runningPos
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

// queryLaneName names the audit and Job query lane in the unavailable and
// read-failed pages every screen that reads it renders.
const queryLaneName = "the audit and Job query lane"

// lanePosAfter is where a lane stands once it has returned next as its next
// page: an empty next means the lane ran out, which travels as FINISHED rather
// than as an empty cursor that the next request would read as page one.
func lanePosAfter(next string) lanePos { return lanePos{Cursor: next, Done: next == ""} }

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

// timeRange is the relative-window/explicit-range half of a screen's
// filter, extracted from parseActivityFilter so Activity and Access
// (access.go) parse one range rather than two that could drift.
//
// Window is a relative range ("15m", "1h", "24h", "7d"); Since and Until are
// the resolved absolute bounds, whether they came from Window or from
// explicit RFC3339 parameters.
type timeRange struct {
	Window       string
	SinceParam   string
	UntilParam   string
	Since, Until time.Time
}

// setParams writes the range's raw parameters into v, omitting empty ones —
// the inverse of parseTimeRange, shared so both screens round-trip a range
// identically.
func (t timeRange) setParams(v url.Values) {
	for name, value := range map[string]string{"window": t.Window, "since": t.SinceParam, "until": t.UntilParam} {
		if value != "" {
			v.Set(name, value)
		}
	}
}

// parseTimeRange reads a relative window or an explicit range out of the
// window, since and until query values, returning a note for anything it could not read.
//
// A value it does not understand is DROPPED AND NAMED, never silently
// applied as something else: a time range that quietly became "everything"
// is how an auditor concludes an event did not happen. The note strings are
// load-bearing beyond this file — activity_test.go and standing_notes_test.go
// match on them byte-identically, and access_test.go will too.
func parseTimeRange(q url.Values, now time.Time) (timeRange, []string) {
	t := timeRange{
		Window:     strings.TrimSpace(q.Get("window")),
		SinceParam: strings.TrimSpace(q.Get("since")),
		UntilParam: strings.TrimSpace(q.Get("until")),
	}
	var notes []string

	// An explicit range beats a relative one, and asking for both is a
	// contradiction rather than a preference — say so.
	if t.Window != "" {
		d, ok := windowDuration(t.Window)
		switch {
		case !ok:
			notes = append(notes, "the time window "+quoted(t.Window)+" is not offered here, so it was ignored")
			t.Window = ""
		case t.SinceParam != "" || t.UntilParam != "":
			notes = append(notes, "both a relative window and an explicit range were given; the explicit range was used")
			t.Window = ""
		default:
			t.Since = now.Add(-d)
		}
	}
	if t.SinceParam != "" {
		if v, err := time.Parse(time.RFC3339, t.SinceParam); err == nil {
			t.Since = v
		} else {
			notes = append(notes, "since= is not an RFC 3339 timestamp, so it was ignored")
			t.SinceParam = ""
		}
	}
	if t.UntilParam != "" {
		if v, err := time.Parse(time.RFC3339, t.UntilParam); err == nil {
			t.Until = v
		} else {
			notes = append(notes, "until= is not an RFC 3339 timestamp, so it was ignored")
			t.UntilParam = ""
		}
	}
	// The read lane refuses a range that runs backwards. Catching it here
	// means the operator is told which half was wrong instead of being handed
	// the seam's validation error.
	if !t.Since.IsZero() && !t.Until.IsZero() && !t.Until.After(t.Since) {
		notes = append(notes, "until must be after since; the range was ignored")
		t.Since, t.Until, t.SinceParam, t.UntilParam, t.Window = time.Time{}, time.Time{}, "", "", ""
	}

	return t, notes
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
		Kind:        strings.TrimSpace(q.Get("kind")),
		Account:     strings.TrimSpace(q.Get("account")),
		OnBehalfOf:  strings.TrimSpace(q.Get("on_behalf_of")),
		Op:          strings.TrimSpace(q.Get("op")),
		Outcome:     strings.TrimSpace(q.Get("outcome")),
		Q:           q.Get("q"),
		ShowConsole: q.Get(consoleParam) == consoleShow,
		Job:         lanePos{Cursor: q.Get("jc"), Done: q.Get("jdone") == "1"},
		Audit:       lanePos{Cursor: q.Get("ac"), Done: q.Get("adone") == "1"},
		Running:     runningPos{Cursor: q.Get("rc")},
	}
	// ro only numbers Running now's range, so one that cannot be read, is out
	// of bounds, or has no cursor to number from, is dropped without a note.
	if ro, err := strconv.Atoi(q.Get("ro")); err == nil && ro > 0 && ro <= maxRunningOffset && f.Running.Cursor != "" {
		f.Running.Offset = ro
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

	tr, trNotes := parseTimeRange(q, now)
	f.timeRange = tr
	notes = append(notes, trNotes...)

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
	v := f.query(job, audit)
	if len(v) == 0 {
		return "/console/activity"
	}
	return "/console/activity?" + v.Encode()
}

// query is the filter's parameters with the two lane positions replaced, so a
// control that builds its own URL (Refresh) reuses exactly what href encodes.
func (f activityFilter) query(job, audit lanePos) url.Values {
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
	f.setParams(v)
	set("q", f.Q)
	if f.ShowConsole {
		set(consoleParam, consoleShow)
	}
	set("jc", job.Cursor)
	set("ac", audit.Cursor)
	set("rc", f.Running.Cursor)
	if f.Running.Offset > 0 {
		set("ro", strconv.Itoa(f.Running.Offset))
	}
	// Carried as their own parameters so that "finished" survives the round
	// trip. Without them the next request reads an empty cursor as page one.
	if job.Done {
		set("jdone", "1")
	}
	if audit.Done {
		set("adone", "1")
	}
	return v
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

	// ReadsLeftOutHref is set ONLY when no kind filter is set — the one case
	// in which the feed leaves the `read` family out (activityLaneExcluded).
	// It is the `read` chip's own href, so following it keeps every other
	// filter (an Account, a window) in place. The template draws the visible
	// read-records sentence beside the kind chips from it: a responder
	// filtering to one Account must be told, where they are looking, that
	// its enumeration is not in this feed.
	ReadsLeftOutHref string

	Live Live

	// CSRFToken serves Running now's Cancel forms.
	CSRFToken string

	// RunningNow is the section above the stream (activity_runningnow.go).
	RunningNow runningNowView

	// Scrolled says this page was reached by following Older; NewestHref is
	// the way back.
	Scrolled   bool
	NewestHref string

	// Refresh reloads this exact view, lane positions included.
	Refresh Refresh

	// AllAccountsHref is this view with ?account= cleared and everything else
	// kept: the Show every Account link.
	AllAccountsHref string

	// ReadsExcluded says the filter does not select read records, so reads
	// made from this Console cannot be on the page.
	ReadsExcluded bool

	// ConsoleInForce says the filter selects read records, which is the only
	// case in which reads made from this Console can be on the page at all, so
	// the page states the rule. ShowConsole is ?console=show. ConsoleLeftOut is
	// how many of PageCalls calls the default left out; AllConsoleReads says
	// that was every one of them.
	ConsoleInForce    bool
	ShowConsole       bool
	ConsoleLeftOut    int
	PageCalls         int
	AllConsoleReads   bool
	ConsoleToggleHref string

	// CollapseNote says what the collapse did to the page; EventCount is the
	// calls the rendered rows stand for, which is what the viewbar counts.
	CollapseNote string
	EventCount   int
}

// kindChip is one family link. It carries NO COUNT, deliberately: a count is
// computable only with the entire window in memory. Counting per family
// across a paginated trail would take one aggregate query per family, each of
// which writes its own read record — one extra row in the append-only trail
// for every number it would print. job.go states the rule this follows: a
// page that prints a number it did not compute has nothing to offer an
// operator.
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
			unavailable(w, queryLaneName)
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

		v := newActivityView(f, note, p.CSRFToken, known, ranJob, ranTrail)
		if !known {
			v.UnknownKind = f.Kind
			renderScreen(w, p, activityTmpl, v)
			return
		}

		fetch, err := fetchActivity(r.Context(), d, caller, f, ranJob, trailKinds,
			capability.PageRequest{Limit: jobPageSize, Cursor: f.Job.Cursor},
			capability.PageRequest{Limit: auditPageSize, Cursor: f.Audit.Cursor})
		if err != nil {
			readFailed(w, err, queryLaneName)
			return
		}
		if refusedUnaudited(w, lane, queryLaneName) {
			return
		}
		rn, err := fetchRunningNow(r.Context(), d, caller, f)
		if err != nil {
			readFailed(w, err, queryLaneName)
			return
		}
		if refusedUnaudited(w, lane, queryLaneName) {
			return
		}
		v.fill(d, caller, f, fetch, rn, ranJob, ranTrail)

		if live, scripts := activityLive(d, f, ranJob, v.RunningNow); live.Wired {
			v.Live, p.Scripts = live, scripts
		}

		renderScreen(w, p, activityTmpl, v)
	}
}

// newActivityView is the page chrome that depends on the filter alone: its
// choices, links and lane-position flags, before any row is fetched.
func newActivityView(f activityFilter, note, csrfToken string, known, ranJob, ranTrail bool) activityView {
	v := activityView{
		Filter:        f,
		Note:          note,
		JobPageSize:   jobPageSize,
		AuditPageSize: auditPageSize,
		// Both lanes finished. Only reachable by hand-editing the URL —
		// the "Older" link is not drawn in this state — but "nothing
		// matches" would be a lie about the filter rather than about the
		// position, so it gets its own sentence.
		Exhausted: known && !ranJob && !ranTrail,
		// Clear resets every filter, account and console included, so it is
		// deliberately not among the links that keep them (spec 04).
		ResetHref:     "/console/activity",
		Narrowing:     f.narrowing(),
		Windows:       windowChoices(f.Window),
		Outcomes:      outcomeChoices(f.Outcome),
		Kinds:         kindChips(f),
		ReadsExcluded: !slices.Contains(activityLaneKinds(f), audit.KindRead),
	}
	v.CSRFToken = csrfToken
	v.Refresh = newRefresh("/console/activity", f.query(f.Job, f.Audit))
	if f.Kind == "" {
		for _, c := range v.Kinds {
			if c.Kind == rowRead {
				v.ReadsLeftOutHref = c.Href
			}
		}
	}
	return v
}

// fill sets everything that depends on the fetched rows: the Console-read
// statement, the links that move the filter, the collapsed stream, Running now
// and the Older and Export links.
func (v *activityView) fill(d Deps, caller capability.Principal, f activityFilter, fetch activityFetch,
	rn capability.JobPage, ranJob, ranTrail bool) {
	jobNext, auditNext := fetch.JobNext, fetch.AuditNext
	v.Rows = fetch.Rows

	// What the filter SELECTS decides whether the Console-read rule is
	// stated, not which lane this page position happened to run, so an Older
	// page whose trail lane is finished still states it.
	v.ShowConsole = f.ShowConsole
	v.ConsoleInForce = !v.ReadsExcluded
	v.ConsoleLeftOut, v.PageCalls = fetch.ConsoleLeftOut, fetch.PageCalls
	v.AllConsoleReads = v.ConsoleLeftOut > 0 && v.ConsoleLeftOut == v.PageCalls
	toggle := f
	toggle.ShowConsole = !f.ShowConsole
	v.ConsoleToggleHref = toggle.href(f.Job, f.Audit)
	everyone := f
	everyone.Account = ""
	// Running now follows ?account=, so its set changes with it and its
	// old position means nothing under the new one.
	everyone.Running = runningPos{}
	v.AllAccountsHref = everyone.base()
	v.Scrolled = f.Job != (lanePos{}) || f.Audit != (lanePos{})
	if v.Scrolled {
		v.NewestHref = f.base()
	}

	v.Rows = collapseActivityRows(v.Rows)
	fc, fr := foldedSummary(v.Rows, func(r activityRow) int { return r.Calls })
	v.CollapseNote = collapseNote(fc, fr)
	for _, r := range v.Rows {
		v.EventCount += r.Calls
	}

	// Cancel follows Job detail literally: a Job with Unresolved Tasks
	// and a role the route is mounted for. It is drawn in Running now and
	// nowhere on the stream, so a Job draws at most one per page by
	// construction, whichever pages the two are on. A stream row links up
	// to its entry when the entry is on this page, else to the section.
	v.RunningNow = buildRunningNow(rn, f, d.now(), cancelOffered(d, accounts.Role(caller.Role)))
	linkRunningRows(v.Rows, v.RunningNow)

	// BOTH lane positions travel, always, and a lane that came back with
	// no Next travels as FINISHED rather than as an empty cursor. "Older"
	// is drawn only while some lane has a real next page, so the chain
	// terminates instead of looping over a restarted lane forever.
	nextJob, nextAudit := f.Job, f.Audit
	if ranJob {
		nextJob = lanePosAfter(jobNext)
	}
	if ranTrail {
		nextAudit = lanePosAfter(auditNext)
	}
	if jobNext != "" || auditNext != "" {
		v.OlderHref = f.href(nextJob, nextAudit)
	}
	// writeActivityCSV walks the same fetchActivity from page one with
	// ShowConsole forced on, so with no rows, no left-out Console reads
	// and no further page the file would be empty: offer no link to it.
	if v.Scrolled || len(v.Rows) > 0 || v.ConsoleLeftOut > 0 || v.OlderHref != "" {
		v.ExportHref = f.base() + exportSuffix(f)
	}
}

// linkRunningRows points each running dispatch row at its Running now entry
// when the entry is on this page, else at the section.
func linkRunningRows(rows []activityRow, rn runningNowView) {
	inRunningNow := map[string]bool{}
	for _, e := range rn.Entries {
		inRunningNow[e.JobID] = true
	}
	for i := range rows {
		r := &rows[i]
		if r.Kind != rowDispatch || !r.Running || r.JobID == "" {
			continue
		}
		r.RunningHref = "#running-now"
		if inRunningNow[r.JobID] {
			r.RunningHref = "#rn-" + r.JobID
		}
	}
}

// activityLive is the live region and the scripts that drive it, only where
// the current view renders something the client can flip: dispatch rows, or
// Running now's entries (a Job finishing is marked in place there, whatever
// the kind filter). A screen with no live seam — or a view with neither — must
// not load a script that sits there queueing events nothing would show; it
// gets the zero Live.
func activityLive(d Deps, f activityFilter, ranJob bool, rn runningNowView) (Live, []string) {
	if d.Events == nil || (!ranJob && len(rn.Entries) == 0) {
		return Live{}, nil
	}
	return Live{
		Wired:       true,
		Endpoint:    "/console/events?kinds=job",
		LastEventID: newestJobEventID(d.Events),
		ShowHref:    f.base(),
		CountNote:   liveCountNote,
	}, []string{"/console/assets/stream.js", "/console/assets/activity.js"}
}

// liveCountNote qualifies the live region's counter (04-activity.md, "Live but
// stable"): it counts the kinds=job stream, which this page's filter does not
// narrow and on which one Job appears more than once.
const liveCountNote = "Counts job events, not rows; this page's filter does not narrow them, and a Job announces itself more than once."

// activityCollapseKey is the collapse's key for one row, and whether the row
// may fold at all.
//
// The key is every exported field of the row except When, FirstWhen and Calls:
// a superset of what the template renders. encoding/json
// serialises exactly the exported fields and html/template can only read
// exported fields, so any field the template renders is in the key by
// construction, with no hand-kept list. Some exported fields are not rendered
// (AccountID and Resolved among them); including them can only stop a fold,
// never cause one. The unexported at is left out, and is not
// rendered. activityRow holds slices (Outcomes.Segments), so == cannot compare
// rows the way it compares agentCall.
//
// A Job row stands for one Job and carries the live handle, so it never
// folds. A denial is the highest-information row on a trust surface and never
// folds either (Agents' rule); on this screen a denied outcome reaches the
// feed mainly on Job rows, which the first rule already excludes, so this is
// the guard for any trail row that renders one. A Marshal error is
// "not collapsible": an error never causes a fold.
func activityCollapseKey(r activityRow) (string, bool) {
	if r.Kind == rowDispatch || r.Outcome == jobs.OutcomeName(jobs.OutcomeDeniedByPolicy) {
		return "", false
	}
	r.When, r.FirstWhen, r.Calls = "", "", 0
	b, err := json.Marshal(r)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// collapseActivityRows folds each run of CONSECUTIVE identical rows (spec 04,
// "Polling") into one row carrying its call count. Rows arrive
// newest-first, so the row folded in is older and FirstWhen ends up the oldest
// call's When. See foldRuns for why it never reaches past an adjacent row.
func collapseActivityRows(rows []activityRow) []activityRow {
	return foldRuns(rows, activityCollapseKey, func(run *activityRow, older activityRow) {
		run.Calls += older.Calls
		run.FirstWhen = older.When
	})
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

// activityFetch is what one fetchActivity call returns.
type activityFetch struct {
	Rows []activityRow

	JobNext, AuditNext string

	// ConsoleLeftOut is how many fetched trail rows the Console-read default
	// dropped, out of PageCalls: every call the two lanes returned, counted
	// before the Console exclusion and before the Refine. Under ?account= the
	// lanes are already scoped to that Account, so both are its calls.
	ConsoleLeftOut, PageCalls int
}

// fetchActivity runs the active lanes and merges them, newest first.
//
// Reads made from a Console session are left out here, over the page the trail
// lane already returned (spec 04): the query, its filter and its page size are
// untouched, so no read is added or widened. It is done on the AuditRow,
// before eventRowFromTrail, because the authentication method is only there.
func fetchActivity(ctx context.Context, d Deps, caller capability.Principal, f activityFilter,
	jobLane bool, trailKinds []string, jobPage, auditPage capability.PageRequest,
) (activityFetch, error) {
	var out activityFetch
	var rows []activityRow
	if jobLane {
		page, err := d.Queries.QueryJobs(ctx, caller, capability.JobFilter{
			RequesterAccountID: f.Account,
			OnBehalfOf:         f.OnBehalfOf,
			Operation:          f.Op,
			Since:              f.Since,
			Until:              f.Until,
		}, jobPage)
		if err != nil {
			return activityFetch{}, err
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
			out.PageCalls++
			rows = append(rows, dispatchRowFromJob(sum))
		}
		out.JobNext = page.Next
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
			return activityFetch{}, err
		}
		out.PageCalls += len(page.Rows)
		for _, row := range page.Rows {
			if !f.ShowConsole && consoleRead(row) {
				out.ConsoleLeftOut++
				continue
			}
			rows = append(rows, eventRowFromTrail(factsOfRow(row)))
		}
		out.AuditNext = page.Next
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
	out.Rows = rows
	return out, nil
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
		row.State, row.Outcome,
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
	operation, rawExecTier := jobRowName(sum)
	row := activityRow{
		Kind:      rowDispatch,
		EventKind: audit.KindDispatch,
		at:        sum.CreatedAt,
		When:      utcStamp(sum.CreatedAt),
		Operation: operation,
		Args:      argsSummary(sum.Args, sum.RawExecArgv),
		// The DECLARED class, from tasks.risk_class — never this package's
		// name inference. A Template Operation the Console has never heard of
		// is still classified by the catalog that dispatched it.
		ReadClass:         sum.RiskClass == jobs.RiskClassRead,
		Selector:          sum.Selector,
		FanOut:            sum.Total,
		InFlight:          sum.Unresolved,
		Running:           sum.Unresolved > 0,
		OutcomeUnrecorded: sum.OutcomeUnrecorded(),
		OutcomePartial:    sum.Recording == jobs.JobRecordingOutcomePartial,
		Resolved:          sum.Total - sum.Unresolved,
		RawExecTier:       rawExecTier,
		Outcomes:          barFrom(sum.Counts),
		JobID:             sum.JobID,
		JobHref:           "/console/jobs/" + sum.JobID,
		Principal:         sum.Requester,
		Verified:          sum.RequesterAccountID != "",
		AccountID:         sum.RequesterAccountID,
		Calls:             1,
		RequesterKind:     verifiedKind(sum.RequesterAccountID != "", sum.RequesterKind),
		OnBehalfOf:        sum.OnBehalfOf,
		ApprovalID:        sum.ApprovalID,
		GrantID:           sum.GrantID,
	}
	if sum.RiskClass != jobs.RiskClassUnspecified {
		row.Risk = jobs.RiskClassName(sum.RiskClass)
	}
	row.Summary = row.Operation
	if row.Summary == "" {
		// Neither an Operation name nor the Raw Exec ActionKind: say what the
		// row is rather than render an empty cell.
		row.Summary = "dispatch"
	}
	row.OpIsLink = row.Operation != ""
	row.LiveHandle = true
	// "No audit-joined field has been joined yet": JobSummary documents each
	// of these as LEFT-JOINed from the per-Job dispatch aggregate and empty
	// until it is written. An empty Selector alone is not the signal, since a
	// recorded dispatch may legitimately carry one. The template draws its
	// no-dispatch-record-yet note from it.
	row.AwaitingRecord = row.Running && sum.Selector == "" && len(sum.Args) == 0 &&
		len(sum.RawExecArgv) == 0 && sum.ApprovalID == "" && sum.GrantID == "" &&
		sum.OnBehalfOf == ""
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

// jobRowName names a Job row's Operation, and says whether the Job is the Raw
// Exec tier. The tier is read from ActionKind FIRST and from nothing else: the
// conspicuous tier must never be impersonated by a name an Operation author
// chose. A denied run_operation of an Operation literally named raw_exec
// becomes a Job (policy denial is a Task outcome), so the collision is
// reachable, not hypothetical. Every other Operation keeps its bare name.
func jobRowName(sum capability.JobSummary) (operation string, rawExecTier bool) {
	switch {
	case sum.ActionKind == jobs.ActionRawExec:
		return rawExecActionKind, true
	case sum.OperationName == rawExecActionKind:
		return "run_operation · " + sum.OperationName, false
	default:
		return sum.OperationName, false
	}
}

// trailRowName is jobRowName's trail-lane twin: the tier is read from
// ActionKind or RawExecArgv first, and an Operation whose name collides with
// the tier's spelling is prefixed so it cannot impersonate Raw Exec. Node
// detail's Recent Tasks names its rows through it too.
func trailRowName(f trailFacts) (operation string, rawExecTier bool) {
	switch {
	case f.ActionKind == rawExecActionKind || len(f.RawExecArgv) > 0:
		return rawExecActionKind, true
	case f.OperationName == rawExecActionKind:
		return "run_operation · " + f.OperationName, false
	default:
		return operationText(f), false
	}
}

// eventRowFromTrail builds every non-dispatch row from the trail lane.
func eventRowFromTrail(f trailFacts) activityRow {
	trailName, trailRawExec := trailRowName(f)
	row := activityRow{
		Kind:            kindOf(f.Kind),
		EventKind:       f.Kind,
		at:              f.Timestamp,
		When:            utcStamp(f.Timestamp),
		Principal:       principalText(f),
		Verified:        f.VerifiedAccountID != "",
		AccountID:       f.VerifiedAccountID,
		Calls:           1,
		OnBehalfOf:      f.OnBehalfOf,
		Selector:        f.Selector,
		NodeID:          f.NodeID,
		Operation:       trailName,
		RawExecTier:     trailRawExec,
		Args:            argsText(f),
		Reason:          f.Reason,
		Summary:         summarize(f),
		ApprovalID:      f.ApprovalID,
		GrantID:         f.GrantID,
		ApprovalAnswer:  f.ApprovalAnswer,
		DecisionChannel: f.DecisionChannel,
		PlanHash:        f.PlanHash,
	}
	row.Outcome, row.State = callOutcome(f)
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
	// is the whole point. Same set AI-agent history draws it for.
	risk := riskOf(f)
	switch row.Kind {
	case rowDispatch, rowRead, rowRefusal, rowApproval, rowPlan, rowCancel:
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
// not variations of one thing: an approval decision and a Cancel
// have nothing in common except that they happened, and prose that pretends
// otherwise reads as machine output rather than as a trail.
func summarize(f trailFacts) string {
	switch f.Kind {
	case audit.KindJobCancel:
		// "cancelled" is a Task outcome word and would claim the Job's fate
		// (GLOSSARY Cancellation, ADR-0013); the row records only the ask.
		return "asked to cancel Job " + shortHash(f.JobID)
	case audit.KindApprovalRequested:
		return "parked a dispatch for approval"
	case audit.KindApprovalGrantRequested:
		// A Grant is an ask for STANDING authority over many future
		// dispatches, so it must not read as one Plan waiting for one answer.
		return "requested an Approval grant"
	case audit.KindApprovalPendingObserved:
		return "re-drove a dispatch that is already parked"
	case audit.KindApprovalDecided:
		// Same discriminators as agents.go's agentCallFrom, no new vocabulary:
		// GrantID is RevokeGrant's structural marker; the structured
		// answer otherwise names which way the decision went; a
		// decision recorded with neither falls back to the original sentence.
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
		// outcome — while the very same records drove the since-retired
		// Read-egress screen's enumeration panel. The trail had the fact and
		// this surface, which is billed as the trail, declined to say it.
		//
		// readTargetOf is reused rather than reimplemented, and that is the
		// point: the first attempt here read ActionKind, which is empty on
		// these records — the tool name lives in OperationName — so Activity
		// said "the registry" while the Read-egress screen, retired
		// 2026-10-01, said "list_nodes" about the same audit row. Two screens
		// naming one thing two ways is how an operator stops trusting either.
		return "enumerated " + readTargetOf(f)
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
	// The export is the fetched rows, not the screen: it includes reads made
	// from this Console and never collapses, so its closing line stays true.
	f.ShowConsole = true
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
		page, err := fetchActivity(ctx, d, caller, f, runJob, kinds,
			capability.PageRequest{Limit: jobPageSize, Cursor: job.Cursor},
			capability.PageRequest{Limit: auditPageSize, Cursor: aud.Cursor})
		if err != nil {
			readFailed(w, err, queryLaneName)
			return
		}
		rows = append(rows, page.Rows...)
		if runJob {
			job = lanePosAfter(page.JobNext)
		}
		if runTrail {
			aud = lanePosAfter(page.AuditNext)
		}
	}

	// The export is checked before a single byte of it is written: a file an
	// auditor keeps must never be half a download plus an error.
	if refusedUnaudited(w, lane, queryLaneName) {
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
<p class="lede">Calls the Relay received, and what they did to the fleet.</p>

{{template "refresh" .Refresh}}
{{if not .UnknownKind}}<p class="refreshlimit">Every Refresh is an audited read made from this Console.</p>{{end}}

<form class="viewbar" method="get" action="/console/activity">
  {{with .Filter.Kind}}<input type="hidden" name="kind" value="{{.}}">{{end}}
  {{if .Filter.ShowConsole}}<input type="hidden" name="console" value="show">{{end}}
  <div class="vfield">
    <label class="vlabel" for="account">Principal</label>
    <input id="account" name="account" value="{{.Filter.Account}}" placeholder="e.g. acct-…" spellcheck="false" autocomplete="off">
  </div>
  <div class="vfield">
    <label class="vlabel" for="on_behalf_of">On behalf of</label>
    <input id="on_behalf_of" name="on_behalf_of" value="{{.Filter.OnBehalfOf}}" placeholder="e.g. alice@example.com" spellcheck="false" autocomplete="off">
  </div>
  <div class="vfield">
    <label class="vlabel" for="op">Operation</label>
    <input id="op" name="op" value="{{.Filter.Op}}" placeholder="e.g. service.restart" spellcheck="false" autocomplete="off">
  </div>
  <div class="vfield">
    <label class="vlabel" for="outcome">Outcome</label>
    <select id="outcome" name="outcome">
      <option value="">any outcome</option>
      {{range .Outcomes}}<option value="{{.Value}}"{{if .Selected}} selected{{end}}>{{.Label}}</option>{{end}}
    </select>
  </div>
  <div class="vfield">
    <label class="vlabel" for="window">When</label>
    <select id="window" name="window">
      <option value="">all recorded time</option>
      {{range .Windows}}<option value="{{.Value}}"{{if .Selected}} selected{{end}}>{{.Label}}</option>{{end}}
    </select>
  </div>
  <div class="vfield">
    <label class="vlabel" for="q">Refine</label>
    <input id="q" name="q" value="{{.Filter.Q}}" placeholder="e.g. nginx (this page only)" spellcheck="false" autocomplete="off">
  </div>
  <button type="submit">Apply</button>
  {{if .Rows}}<span class="vcount">{{.EventCount}} {{plural .EventCount "event" "events"}}</span>{{end}}
  <a class="act" href="{{.ResetHref}}">Clear</a>
</form>

{{with .Note}}<p class="gap"><b>Part of this URL could not be read:</b> {{.}}.</p>{{end}}

<div class="kindbar">
  {{range .Kinds}}<a class="kchip{{if .Current}} on{{end}}" href="{{.Href}}">{{.Kind}}</a>{{end}}
</div>
{{with .ReadsLeftOutHref}}<p class="kindnote">Read records are left out of this feed: <a href="{{.}}">show them</a>.</p>{{end}}

{{if .UnknownKind}}
<p class="gap"><b>There is no row kind called &ldquo;{{.UnknownKind}}&rdquo;</b>, so nothing was queried: <a href="{{.ResetHref}}">clear the filter</a>.</p>
{{else}}

{{if .ConsoleInForce}}
<p class="scoped consolecalls">{{if .ShowConsole -}}
  Reads made from this Console are shown. <a href="{{.ConsoleToggleHref}}">Leave them out</a>.
{{- else -}}
  Reads made from this Console are left out{{if .ConsoleLeftOut}}: {{.ConsoleLeftOut}} of the {{.PageCalls}} {{plural .PageCalls "call" "calls"}} on this page{{end}}. <a href="{{.ConsoleToggleHref}}">Show them</a>.
{{- end}}</p>
{{end}}
{{if .Filter.Account}}<p class="scoped">Showing one Account only. <a href="{{.AllAccountsHref}}">Show every Account</a>.</p>{{end}}

<section class="runningnow" id="running-now" aria-label="Running now">
  <div class="ftitle">Running now <span class="phint">Longest-running first; not narrowed by the kind chips or the time window.</span></div>
  {{with .RunningNow}}
  {{if .Entries}}<p class="rncount">{{.Matching}} running{{if .From}} &middot; {{.From}}&ndash;{{.To}}{{end}}</p>
  <ol class="rnlist">
  {{range .Entries}}
    <li class="rnentry" id="{{.Anchor}}" data-rn-job-id="{{.JobID}}">
      <div class="evhead">
        {{if .Principal}}{{template "trust-chip" (trust .Principal .Verified)}}{{template "kind-label" .RequesterKind}}
        {{else}}<span class="dim">attribution is recorded when the dispatch completes</span>{{end}}
        {{if .RawExecTier}}<span class="chip" data-tier="raw_exec">Raw Exec</span>{{end}}
        {{if .Operation}}<a class="evop" href="{{.JobHref}}"><code>{{.Operation}}</code></a>
        {{else}}<span class="evsum">{{.Summary}}</span>{{end}}
      </div>
      <div class="evmeta">
        <time datetime="{{.Started}}">running for {{.RunningFor}}</time>
        <span class="overcap">{{.Resolved}} of {{.Total}} Tasks resolved</span>
        <a href="{{.JobHref}}">Job <code>{{short .JobID}}</code></a>
        {{if .CancelAction}}{{template "job-cancel" (cancelControl .CancelAction $.CSRFToken)}}{{end}}
      </div>
      <div class="rnliveslot">
        <span class="rnlive" data-when="completed">finished after this page was rendered &mdash; reload to see its outcomes</span>
        <span class="rnlive" data-when="cancelled">cancelled after this page was rendered &mdash; reload to see its outcomes</span>
      </div>
    </li>
  {{end}}
  </ol>
  {{else if .Paged}}<p class="dim">Nothing further is running. <a href="{{.FirstHref}}">Longest-running first</a>.</p>
  {{else if .AccountScoped}}<p class="dim">This Account has nothing running.</p>
  {{else}}<p class="dim">Nothing is running.</p>{{end}}
  {{if or .NextHref (and .FirstHref .Entries)}}<div class="pager">
    {{with .NextHref}}<a class="act" href="{{.}}">Next longest-running</a>{{end}}
    {{if .Entries}}{{with .FirstHref}}<a href="{{.}}">Longest-running first</a>{{end}}{{end}}
  </div>{{end}}
  {{end}}
</section>

{{template "live-region" .Live}}

<div class="feed">
{{range .Rows}}
  <article class="ev" data-kind="{{.Kind}}"{{if .LiveHandle}} data-job-id="{{.JobID}}"{{end}} data-calls="{{.Calls}}">
    <div class="evwhen"><time datetime="{{.When}}">{{.When}}</time><span class="evkind">{{.EventKind}}</span></div>
    <div class="evbody">
      <div class="evhead">
        {{if .Unrecorded}}
          {{if .Pending}}<span class="dim">attribution is recorded when the dispatch completes</span>
          {{else}}<span class="unattrib" title="Every dispatch records who asked; this gap is a trail defect, not an anonymous caller.">this dispatch finished with no recorded principal &mdash; the trail should carry one</span>{{end}}
        {{else}}{{template "trust-chip" (trust .Principal .Verified)}}{{template "kind-label" .RequesterKind}}{{end}}
        {{with .OnBehalfOf}}{{template "trust-chip" (trust . false)}}{{end}}
        {{if .RawExecTier}}<span class="chip" data-tier="raw_exec">Raw Exec</span>{{end}}
        {{if .OpIsLink}}<a class="evop" href="{{.JobHref}}"><code>{{.Operation}}</code></a>
        {{else}}<span class="evsum">{{.Summary}}</span>{{end}}
        {{with .Risk}}<span class="chip risk" data-risk="{{.}}">{{.}}</span>{{end}}
        {{if .State}}<span class="chip state" data-state="{{.State}}">{{.State}}</span>{{else}}{{with .Outcome}}<span class="chip outcome" data-outcome="{{.}}">{{.}}</span>{{end}}{{end}}
        {{if .Running}}<span class="chip" data-state="running" title="This Job has Tasks not yet resolved.">running</span>{{end}}
        {{if .OutcomeUnrecorded}}{{if .OutcomePartial}}<span class="chip outcomeunk" data-state="outcome-unknown">outcome partly unknown</span>{{else}}<span class="chip outcomeunk" data-state="outcome-unknown">intent recorded · outcome unknown</span>{{end}}{{end}}
        {{if gt .Calls 1}}<span class="chip calls" title="Consecutive identical calls, collapsed for display. Each one is on the audit trail.">x{{.Calls}}</span>{{end}}
      </div>
      {{with .Args}}<div class="evargs mono">{{.}}</div>{{end}}
      <div class="evmeta">
        {{if and .Operation (not .OpIsLink)}}<code>{{.Operation}}</code>{{end}}
        {{with .Selector}}<code class="selector">{{.}}</code>{{end}}
        {{if .FanOut}}<span class="fanmath">{{.FanOut}} {{plural .FanOut "Node" "Nodes"}}</span>{{end}}
        {{if .Running}}<span class="overcap">{{.Resolved}} of {{.FanOut}} Tasks resolved</span>{{end}}
        {{if .NodeHref}}<a href="{{.NodeHref}}"><code>{{.NodeID}}</code></a>{{end}}
        {{if and .JobHref (not .OpIsLink)}}<a href="{{.JobHref}}">Job <code>{{short .JobID}}</code></a>{{end}}
        {{with .ApprovalHref}}<a href="{{.}}">approval</a>{{end}}
        {{with .GrantID}}<span class="grant" title="An Approval grant released this: a human approved a window, not this plan.">grant {{short .}}</span>{{end}}
        {{with .RunningHref}}<a class="rnlink" href="{{.}}">in Running now</a>{{end}}
      </div>
      {{if .AwaitingRecord}}<div class="evnote">No dispatch record is joined to it yet, so its Selector, arguments and approver are not shown.</div>{{end}}
      {{if .Outcomes.Total}}{{template "outcome-bar" .Outcomes}}{{end}}
      {{if .LiveHandle}}<div class="evliveslot">
        <span class="evlive" data-when="completed">completed after this page was rendered &mdash; reload to see its outcomes</span>
        <span class="evlive" data-when="cancelled">cancelled after this page was rendered &mdash; reload to see its outcomes</span>
      </div>{{end}}
      {{with .Reason}}<div class="evreason">{{.}}</div>{{end}}
      {{if .ReadClass}}<div class="evnote">Output was not retained; nothing here will show it later.</div>{{end}}
      {{if gt .Calls 1}}<div class="evnote">{{.Calls}} consecutive identical calls, {{.FirstWhen}} to {{.When}}; each one is on the audit trail.</div>{{end}}
    </div>
  </article>
{{else}}
  {{if .AllConsoleReads}}<p class="dim">{{if .Filter.Account}}This Account has no calls on this page other than reads made from this Console.{{else}}No calls on this page other than reads made from this Console.{{end}}</p>
  {{else if .Exhausted}}<p class="dim">There is nothing older for this filter.
  <a href="{{.ResetHref}}">Start again</a>.</p>
  {{else if .Narrowing}}<p class="dim">Nothing matches.</p>
  {{else}}<p class="dim">Nothing has been recorded yet.</p>{{end}}
{{end}}
</div>

{{with .CollapseNote}}<p class="gap">{{.}}</p>{{end}}

{{if .Scrolled}}<p class="gap">These are not the most recent events. <a href="{{.NewestHref}}">Newest</a>.</p>{{end}}

<div class="pager">
  {{with .OlderHref}}<a class="act" href="{{.}}">Older</a>{{end}}
  {{with .ExportHref}}<a href="{{.}}">Export this filter as CSV</a>{{end}}
</div>
<p class="note">Each page holds up to {{.JobPageSize}} dispatches and {{.AuditPageSize}} other events, paged separately.</p>

{{if .Filter.Q}}
<p class="gap"><b>Refine</b> matches text within the rows already on this page; it does not search the trail.</p>
{{end}}

{{if .Filter.Outcome}}
<p class="gap"><b>Outcome keeps Jobs with at least one <code>{{.Filter.Outcome}}</code> Task</b>; a short page is not the end.</p>
{{end}}

{{end}}
`)
