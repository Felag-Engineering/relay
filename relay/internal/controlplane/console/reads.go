package console

// reads.go answers the question the architecture itself says is the important
// one, and which nothing in the product could previously answer: what has been
// read, by whom, from where (spec 17).
//
// # Why reading is the exposure that matters
//
// ADR-0021 establishes that reading is exfiltration BY CONSTRUCTION — a read
// result flows to the model provider, and there is no version of that which
// isn't disclosure. ADR-0022 builds a confidentiality deny-list around exactly
// that. ADR-0025 makes every read auditable and fails the read closed when the
// audit write fails.
//
// All of that machinery existed and nothing surfaced any of it. This screen is
// the first place the product admits, out loud, that reading is the risk.
//
// # A map of exposure surface, not a data browser
//
// The AUDIT TRAIL never retains read output (ADR-0025), so it can say a read
// HAPPENED, by whom, of what, and when — never what it contained.
//
// That is stated precisely, in job.go's words, because the stronger sentence is
// not true: the Task row still holds what the daemon sent until the Job is
// collected, and GET /api/v1/jobs/{job_id} returns it. Nothing here will, at
// any age or aggregation, because a screen that did would become the durable
// place read output is read from — the largest single concentration of
// confidential data in the deployment, sitting behind a browser session.
//
// The same rule covers the DENY RULE, which is read output by another name: the
// daemon explains a refusal in the Task's own stderr, and for a read-class Task
// those are bytes the trail deliberately never kept. This screen renders no
// deny explanation for any row — it names the Node's effective Policy instead.
//
// # Counting two ways, both labelled
//
// One `file.read` across 4,000 Nodes is ONE path and FOUR THOUSAND exposures.
// Which number matters depends on the question — "what did it see" versus "how
// far did it reach" — so both are shown and neither is called "reads".
//
// # Bounded by construction, not capped after the fact
//
// Every figure comes from the capability layer's read lane (#441), in AT MOST
// NINE queries whose count does not move with fleet size, Job size or trail
// size. Nothing here iterates Jobs to fetch their dispatch records: that N+1 is
// what makes cost scale with volume, and it would write one audit record per
// Job per page view.
//
//	Q1 QueryJobs   read-class Jobs in the window -> the observed read vocabulary
//	Q2 AuditReach  dispatch rows for that vocabulary  -> exposures/targets/Nodes
//	Q3 AuditReach  the same, refused                  -> the exact refusal triple
//	Q4 AuditCounts the same, by principal and bucket  -> volume and baseline
//	Q5 QueryAudit  the same, refused                  -> the refusal rows
//	Q6 QueryAudit  the same                           -> the by-target table
//	Q7 AuditReach  KindRead rows -> the exact enumeration total
//	Q8 QueryAudit  KindRead rows -> the by-tool table
//	Q9 AuditCounts KindRead rows -> enumerations by principal
//
// Q2-Q6 are SKIPPED ENTIRELY when the vocabulary is empty. That is the single
// most important correctness invariant on the page: capability.AuditFilter's
// zero value matches every Row, so an AuditReach over Kinds:[dispatch] with an
// empty Operations list would count EVERY MUTATE DISPATCH in the window and
// report the whole fleet's mutate traffic as read egress.
//
// # The class is DECLARED, never guessed
//
// The read/mutate split comes from tasks.risk_class through
// capability.JobFilter.RiskClass (invariant 13) — the same declared class
// job.go renders — and the Operation NAME SET the audit half needs is derived
// from those Jobs at request time. capability.AuditFilter carries no risk
// class, so without the derivation this screen would need a hardcoded name
// list; a Template Operation a customer added would then be counted as a
// mutate, which is an UNDERCOUNT of exposure on the one screen that must not
// undercount it.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

const (
	// readJobPage is how many read-class Jobs are scanned for the declared
	// read vocabulary. It bounds the ONE thing on this page that is not an
	// aggregate over the whole window, and the page says so when it bites.
	readJobPage = 200

	// readTargetRows, readRefusalRows and readEnumRows are the three table
	// pages. Every headline number above them is an exact aggregate, so a
	// short page shortens the evidence and never the count.
	readTargetRows  = capability.MaxPageSize
	readRefusalRows = 50
	readEnumRows    = 200

	// maxReadOperations mirrors capability.AuditFilter.validate's own cap on
	// Operations. Past it the busiest Operations are kept and the page reports
	// how many it dropped, rather than sending a filter the lane will refuse.
	maxReadOperations = 32

	// maxOperationNameBytes mirrors the SAME validator's per-entry bound. One
	// over-long Operation name on one read Job would otherwise make every
	// audit-lane query in the window fail validation, which takes the WHOLE
	// SCREEN down for that window rather than dropping one row.
	maxOperationNameBytes = 64

	// readBuckets is how many buckets the window is cut into for the
	// per-principal baseline. Twelve is enough for "this hour is unlike the
	// preceding eleven" and coarse enough that the lane's MinAuditBucket floor
	// never silently changes the shape of the series.
	readBuckets = 12

	// maxFilterValueBytes and maxPathPrefixBytes bound the caller-controlled
	// filter values BEFORE they reach the read lane, on job.go's rule: the
	// lane records its filter in the append-only trail as the read's own
	// selector, and capability.AuditFilter.validate bounds Kinds, Operations
	// and ArgValuePrefix but NOT AccountID or NodeID.
	maxFilterValueBytes = 128
	maxPathPrefixBytes  = 256
)

// readWindow is one entry of the closed window vocabulary.
//
// Closed, not a parsed duration: the aggregate paths refuse a window wider
// than capability.MaxAggregateWindow and refuse one that does not end after it
// starts, and both refusals arrive as a 500 on a URL a caller typed. A closed
// set cannot produce either.
type readWindow struct {
	Key      string
	Label    string
	Duration time.Duration
}

var readWindows = []readWindow{
	{"24h", "24 hours", 24 * time.Hour},
	{"7d", "7 days", 7 * 24 * time.Hour},
	{"30d", "30 days", 30 * 24 * time.Hour},
}

// readWindowDefault is the window an operator gets without asking. Spec 17's
// question is "what has this agent read this week".
const readWindowDefault = "7d"

// readsFilter is the whole caller-controlled surface of this screen, resolved
// and bounded before any of it reaches the read lane.
type readsFilter struct {
	Window       readWindow
	Since, Until time.Time

	// Principal is a verified Account id, Operation an Operation name, and
	// PathPrefix a prefix of the `path` argument. Each is empty when absent or
	// when it was refused, and a refusal is reported in Notes.
	Principal  string
	NodeID     string
	Operation  string
	PathPrefix string

	// Notes are the stated consequences of parsing: a window that was not
	// recognised, a value that was too long to pass on. They are rendered.
	Notes []string
}

// enumApplies reports whether the control-plane enumeration lane can honestly
// be shown under this filter.
//
// An enumeration reads the Relay's own registry and catalogue: it has no
// Operation from the Node catalog and no `path` argument, so neither of those
// two filters can be applied to it. Showing an UNFILTERED enumeration panel
// beside a page the operator has scoped to `file.read /etc` would be a count
// answering a different question than the one on screen.
func (f readsFilter) enumApplies() bool { return f.Operation == "" && f.PathPrefix == "" }

// href renders this filter as a link, optionally with a different window.
func (f readsFilter) href(window string) string {
	q := url.Values{}
	if window == "" {
		window = f.Window.Key
	}
	q.Set("window", window)
	for name, v := range map[string]string{
		"principal": f.Principal,
		"node":      f.NodeID,
		"op":        f.Operation,
		"path":      f.PathPrefix,
	} {
		if v != "" {
			q.Set(name, v)
		}
	}
	return "/console/reads?" + q.Encode()
}

// parseReadsFilter resolves the query string into a filter that is safe to
// hand to the read lane: the window is drawn from a closed set and every
// caller-controlled string is inside its byte bound or dropped with a note.
func parseReadsFilter(q url.Values, now time.Time) readsFilter {
	f := readsFilter{Window: readWindowFor(readWindowDefault)}
	if key := q.Get("window"); key != "" {
		if w, ok := lookupReadWindow(key); ok {
			f.Window = w
		} else {
			// The value itself is NOT echoed. It is caller-controlled and
			// nothing here needs it to explain what happened.
			f.Notes = append(f.Notes, "The window asked for is not one of 24 hours, 7 days or 30 days, so this page shows "+f.Window.Label+".")
		}
	}
	f.Until = now
	f.Since = now.Add(-f.Window.Duration)

	f.Principal = f.bounded(q.Get("principal"), maxFilterValueBytes, "principal")
	f.NodeID = f.bounded(q.Get("node"), maxFilterValueBytes, "Node")
	f.Operation = f.bounded(q.Get("op"), maxFilterValueBytes, "Operation")
	f.PathPrefix = f.bounded(q.Get("path"), maxPathPrefixBytes, "path")
	return f
}

// bounded returns v when it is within max bytes, and otherwise drops it and
// states the refusal. Refused HERE rather than at the lane: the value would
// otherwise be written into the append-only trail as the read record's own
// selector, and the lane bounds the filter's list fields but not its
// single-value ones.
func (f *readsFilter) bounded(v string, max int, what string) string {
	if len(v) <= max {
		return v
	}
	f.Notes = append(f.Notes, fmt.Sprintf(
		"The %s filter was longer than %d bytes and was refused before it reached the query lane, so it is not applied here and was not recorded as a search.",
		what, max))
	return ""
}

func lookupReadWindow(key string) (readWindow, bool) {
	for _, w := range readWindows {
		if w.Key == key {
			return w, true
		}
	}
	return readWindow{}, false
}

func readWindowFor(key string) readWindow {
	w, _ := lookupReadWindow(key)
	return w
}

// readPrincipal is one Account's row in the by-principal table.
//
// There are deliberately no per-principal DISTINCT target or Node columns:
// computing them exactly would take one AuditReach per principal, which is the
// per-row fan-out this page is built to avoid. The drill-down link renders the
// WHOLE SCREEN scoped to one Account instead, where the headline figures ARE
// that Account's exact ones — which is spec 17's first acceptance criterion
// read literally.
type readPrincipal struct {
	Name      string
	AccountID string
	Verified  bool
	Href      string

	// Calls is reads that reached a Node; Enum is control-plane
	// enumerations. Two families, two columns, never one total.
	Calls int
	Enum  int

	// Refused is joined from the LISTED refusal rows, not from the Jobs
	// lane. See readsView.Refused for why.
	Refused int

	Trend     string
	TrendRise bool
}

type readTarget struct {
	Target string
	Calls  int

	// Nodes is DISTINCT Nodes, not records carrying a Node id. The first build
	// counted records, so `file.read /etc/shadow` run five times across three
	// machines read "15 Nodes" on a three-Node fleet — a number larger than the
	// fleet, on the screen whose entire job is to say how far an agent reached.
	Nodes int
	// Refused counts reads a Node's Policy denied. These are the most
	// interesting rows on the screen: an agent repeatedly asking for something
	// the deny-list refuses is either misconfigured or probing, and both are
	// worth a look.
	Refused int
}

// readRefusal is one refused read. It carries WHAT was asked for and WHERE —
// and no explanation, because the deciding rule is the daemon's own stderr and
// the trail never kept it for a read (ADR-0025).
type readRefusal struct {
	Target    string
	NodeID    string
	NodeHref  string
	Principal string
	Verified  bool
	When      time.Time
}

type readsView struct {
	Window     string
	WindowKey  string
	WindowLine []readWindowLink
	Notes      []string

	// Scope is the active filter, for the chips and for the scoped-page
	// sentence. Every value here has already passed its byte bound.
	Principal   string
	NodeID      string
	Operation   string
	PathPrefix  string
	Scoped      bool
	EnumApplies bool

	// Any is whether anything has been read at all. On a fresh Relay the
	// headline row would otherwise render five zeroed statistics, and spec
	// 10's first acceptance criterion is that with zero Nodes no screen
	// renders an empty table or a zeroed statistic — a row of zeros is a
	// measurement, and it says "we measured your exposure and it is nil"
	// where the truth is that nothing has happened yet.
	Any bool

	// Calls, Targets and Nodes describe reads that reached a NODE — bytes
	// pulled off a machine by a read-class Operation. All three are EXACT over
	// the window: one aggregate row, computed store-side over every matching
	// Record rather than over the page below.
	//
	// They are meaningless unless ReadsKnown. A figure this page did not
	// obtain must never render, because the zero value of an int and an exact
	// count of nothing are the same three pixels and OPPOSITE claims — the
	// second says "your fleet was not read", which is the strongest sentence
	// on the screen and the one an incident responder would act on.
	ReadsKnown bool
	Calls      int
	Targets    int
	Nodes      int

	// Refused, RefusedTargets and RefusedNodes are the same three figures for
	// refusals alone, from their OWN aggregate. "Do not bury them" made
	// structural: the number cannot shrink because a sample was short, and it
	// never competes with volume for a table slot.
	//
	// RefusedKnown gates them for the reason above, and it is the sharpest
	// case of it on the page: a failed refusal aggregate rendering as an exact
	// "0 refused by Policy" DIRECTLY ABOVE a listed refusal of /etc/shadow is
	// the page contradicting itself in favour of the reassuring half.
	RefusedKnown   bool
	Refused        int
	RefusedTargets int
	RefusedNodes   int

	// Enumerations describes the other family: the non-dispatching tools
	// (`list_nodes`, `list_operations`, `describe_node`, `get_job`) and the
	// read lane's own trail queries, which read the Relay's own registry and
	// catalogue and never touch a Node.
	//
	// Both are exposure and both are counted — knowing an agent enumerated a
	// 10,000-Node estate four hundred times is worth a look. They are reported
	// SEPARATELY because blending them makes each number mean less: a
	// headline of "13 read calls / 6 distinct targets" that mixes
	// `file.read /etc/shadow` with `list_operations` softens the one figure
	// this screen's entire argument rests on, and the mixed rows carried
	// "0 Nodes" where every neighbouring row carried a real reach.
	//
	// EnumKnown is false both when the aggregate failed AND when the lane was
	// deliberately not queried (see EnumApplies) — a tile is shown only where
	// this page actually measured something.
	EnumKnown    bool
	Enumerations int

	// Any is whether a KNOWN figure is non-zero; Measured is whether any
	// figure was obtained at all. The two are different pages: "nothing has
	// been read" is a measurement, and it must not be manufactured by queries
	// that failed.
	Measured bool

	Principals  []readPrincipal
	TargetRows  []readTarget
	Refusals    []readRefusal
	EnumTargets []readTarget

	// The three tables are pages. Each says so when it did not see everything.
	TargetsSampled  bool
	TargetsListed   int
	RefusalsSampled bool
	RefusalsListed  int
	EnumSampled     bool
	EnumListed      int

	// JobsSampled and OpsElided are the two ways the derived read vocabulary
	// can be short of the truth, and both are stated on the page — with the
	// bound that produced them, so the sentence carries the number rather
	// than a promise about one.
	JobsSampled bool
	JobPageSize int
	OpsElided   int
	OpsCap      int

	// OpsRefused counts read Operations dropped because the lane would refuse
	// the name outright. Reported apart from OpsElided: one is this page
	// choosing the busiest 32, the other is a name the query lane will not
	// accept at all.
	OpsRefused   int
	OpsNameBytes int

	// OpsEmpty is the join guard: no read-class Job in the window, so the
	// audit lane was not queried AT ALL. Distinct from "nothing happened".
	OpsEmpty bool

	// Queries is how many read records this page view wrote. Rendered rather
	// than asserted in prose, because the count changes with the guard.
	Queries int

	// One flag per QUERY, not per section. Q3 (the exact refusal count) and
	// Q5 (the refusal rows) fail independently and mean different things, so
	// a single RefusalsError could only produce a note that named neither.
	TargetsError      bool
	RefusedCountError bool
	RefusalsError     bool
	EnumCountError    bool
	EnumError         bool
	PrincipalsError   bool
}

// readWindowLink is one entry of the window selector.
type readWindowLink struct {
	Label   string
	Href    string
	Current bool
}

func handleReads(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The read lane takes a capability.Principal, so this screen reads the
		// one the Authenticator injected as well as the Page the shell needs.
		caller, ok := principal(w, r)
		if !ok {
			return
		}
		p, ok := page(d, w, r, "Read egress")
		if !ok {
			return
		}
		p.Banner = banner(d, r)

		if d.Queries == nil {
			unavailable(w, "the audit and Job query lane")
			return
		}
		d, lane := latched(d)

		v, ok := buildReadsView(r.Context(), d, caller, parseReadsFilter(r.URL.Query(), d.now()))
		if refusedUnaudited(w, lane, "the read-egress figures") {
			return
		}
		if !ok {
			unreadable(w, "the read-egress figures")
			return
		}
		renderScreen(w, p, readsTmpl, v)
	}
}

// buildReadsView runs the page's queries in order. ok=false means the two
// queries the page cannot be honest without — the declared vocabulary and the
// headline aggregate — failed; every other failure marks its own section and
// leaves the rest of the page rendering, on jobGroups' precedent.
func buildReadsView(ctx context.Context, d Deps, caller capability.Principal, f readsFilter) (readsView, bool) {
	v := readsView{
		JobPageSize:  readJobPage,
		OpsCap:       maxReadOperations,
		OpsNameBytes: maxOperationNameBytes,
		Window:       f.Window.Label,
		WindowKey:    f.Window.Key,
		Notes:        f.Notes,
		Principal:    f.Principal,
		NodeID:       f.NodeID,
		Operation:    f.Operation,
		PathPrefix:   f.PathPrefix,
		Scoped:       f.Principal != "",
		EnumApplies:  f.enumApplies(),
	}
	for _, w := range readWindows {
		v.WindowLine = append(v.WindowLine, readWindowLink{
			Label: w.Label, Href: f.href(w.Key), Current: w.Key == f.Window.Key,
		})
	}

	// Q1. The DECLARED class, from tasks.risk_class through
	// JobFilter.RiskClass — never a name this package recognises.
	readClass := jobs.RiskClassRead
	v.Queries++
	jobPage, err := d.Queries.QueryJobs(ctx, caller, capability.JobFilter{
		RiskClass:          &readClass,
		RequesterAccountID: f.Principal,
		Operation:          f.Operation,
		Since:              f.Since,
		Until:              f.Until,
	}, capability.PageRequest{Limit: readJobPage})
	if err != nil {
		return readsView{}, false
	}
	v.JobsSampled = len(jobPage.Jobs) >= readJobPage || jobPage.Next != ""

	ops, elided, overlong := readOpsFromJobs(jobPage.Jobs, f.Operation)
	v.OpsElided, v.OpsRefused = elided, overlong
	v.OpsEmpty = len(ops) == 0
	bucket := f.Window.Duration / readBuckets

	deniedOutcome := jobs.OutcomeDeniedByPolicy
	dispatched := capability.AuditFilter{
		Kinds:      []string{audit.KindDispatch},
		Operations: ops,
		AccountID:  f.Principal,
		NodeID:     f.NodeID,
		Since:      f.Since,
		Until:      f.Until,
	}
	if f.PathPrefix != "" {
		dispatched.ArgKey = "path"
		dispatched.ArgValuePrefix = f.PathPrefix
	}
	refused := dispatched
	refused.Outcome = &deniedOutcome

	// THE JOIN GUARD. An empty Operations list emits no operation_name
	// condition at all, so this filter would match every mutate dispatch in
	// the window and report it as read egress.
	if !v.OpsEmpty {
		v.Queries++
		reach, err := d.Queries.AuditReach(ctx, caller, dispatched)
		if err != nil {
			return readsView{}, false
		}
		v.Calls, v.Targets, v.Nodes = reach.Calls, reach.DistinctTargets, reach.DistinctNodes
		v.ReadsKnown = true

		v.Queries++
		if denied, err := d.Queries.AuditReach(ctx, caller, refused); err != nil {
			v.RefusedCountError = true
		} else {
			v.Refused, v.RefusedTargets, v.RefusedNodes = denied.Calls, denied.DistinctTargets, denied.DistinctNodes
			v.RefusedKnown = true
		}

		v.Queries++
		buckets, err := d.Queries.AuditCounts(ctx, caller, dispatched, bucket)
		if err != nil {
			v.PrincipalsError = true
		}

		v.Queries++
		var refusalRows []capability.AuditRow
		if page, err := d.Queries.QueryAudit(ctx, caller, refused,
			capability.PageRequest{Limit: readRefusalRows}); err != nil {
			v.RefusalsError = true
		} else {
			refusalRows = page.Rows
			v.Refusals = refusalRowsOf(page.Rows)
			v.RefusalsListed = len(page.Rows)
			v.RefusalsSampled = page.Next != "" || (v.RefusedKnown && v.Refused > len(page.Rows))
		}

		v.Queries++
		if page, err := d.Queries.QueryAudit(ctx, caller, dispatched,
			capability.PageRequest{Limit: readTargetRows}); err != nil {
			v.TargetsError = true
		} else {
			v.TargetRows = aggregateTargets(page.Rows)
			v.TargetsListed = len(page.Rows)
			v.TargetsSampled = page.Next != "" || v.Calls > len(page.Rows)
		}

		v.Principals = principalRows(buckets, nil, refusalRows, f.Since, f.Until, bucket)
	}

	if v.EnumApplies {
		enumerated := capability.AuditFilter{
			Kinds:     []string{audit.KindRead},
			AccountID: f.Principal,
			NodeID:    f.NodeID,
			Since:     f.Since,
			Until:     f.Until,
		}
		v.Queries++
		if reach, err := d.Queries.AuditReach(ctx, caller, enumerated); err != nil {
			v.EnumCountError = true
		} else {
			v.Enumerations = reach.Calls
			v.EnumKnown = true
		}

		v.Queries++
		if page, err := d.Queries.QueryAudit(ctx, caller, enumerated,
			capability.PageRequest{Limit: readEnumRows}); err != nil {
			v.EnumError = true
		} else {
			v.EnumTargets = aggregateTargets(page.Rows)
			v.EnumListed = len(page.Rows)
			v.EnumSampled = page.Next != "" || (v.EnumKnown && v.Enumerations > len(page.Rows))
		}

		// Q9 exists so that an Account which has ONLY enumerated still appears
		// in the by-principal table — including on a page where the join guard
		// fired and the Node-read lane was never queried. Without it the table
		// would be empty on a page simultaneously reporting N enumerations,
		// and spec 17's first acceptance criterion is about the principal, not
		// about one of its two families.
		v.Queries++
		if buckets, err := d.Queries.AuditCounts(ctx, caller, enumerated, bucket); err != nil {
			v.PrincipalsError = true
		} else {
			v.Principals = principalRows(nil, buckets, nil, f.Since, f.Until, bucket).mergeInto(v.Principals)
		}
	}

	sortPrincipals(v.Principals)
	// Only figures this page ACTUALLY OBTAINED may speak. Any drives the
	// headline; Measured is what separates "nothing has been read" — a
	// measurement — from "nothing could be measured", which two failed
	// aggregates would otherwise render as the first.
	v.Any = (v.ReadsKnown && v.Calls > 0) ||
		(v.RefusedKnown && v.Refused > 0) ||
		(v.EnumKnown && v.Enumerations > 0)
	v.Measured = v.ReadsKnown || v.RefusedKnown || v.EnumKnown
	return v, true
}

// readOpsFromJobs derives the read vocabulary actually observed in the window
// from the DECLARED class of the Jobs that ran.
//
// THE DECLARED CLASS IS RE-CHECKED HERE, and that is not belt-and-braces
// decoration. Q1 asks the Job lane for read-class Jobs, but if this function
// trusts the answer then the ONE gate protecting the page's most important
// invariant lives in another package's SQL, and a QueryReader that satisfies
// the interface while ignoring JobFilter.RiskClass puts mutate Operation names
// straight into four AuditFilter.Operations lists — at which point the page
// reports the fleet's mutate dispatches as read egress under headings that say
// "read". Not reachable through any input today; single-gated is still the
// wrong number of gates for this particular rule, and the weaker `ask` rule
// below is already double-gated.
//
// ask, when non-empty, is INTERSECTED rather than passed through: a caller
// asking for `service.restart` on the read-egress screen gets an empty set and
// a stated refusal, never mutate rows.
//
// The result is SORTED, so the filter recorded in the append-only trail as
// this page's own search reads the same way on every view.
func readOpsFromJobs(js []capability.JobSummary, ask string) (ops []string, elided, overlong int) {
	count := map[string]int{}
	refused := map[string]bool{}
	for _, j := range js {
		// The DECLARED class, checked here as well as asked for at the seam.
		if j.RiskClass != jobs.RiskClassRead {
			continue
		}
		// Raw Exec has no Operation name and is always mutate-class, so it
		// cannot appear here; an empty name would become an
		// `operation_name IN ('')` condition, which is not the filter anyone
		// meant to write.
		if j.OperationName == "" {
			continue
		}
		if ask != "" && j.OperationName != ask {
			continue
		}
		// The lane refuses an entry over 64 bytes for the WHOLE filter, so one
		// over-long name would take down every figure on the page for this
		// window. Dropped and counted instead.
		if len(j.OperationName) > maxOperationNameBytes {
			refused[j.OperationName] = true
			continue
		}
		count[j.OperationName]++
	}
	overlong = len(refused)
	names := make([]string, 0, len(count))
	for name := range count {
		names = append(names, name)
	}
	// Busiest first, so a vocabulary wider than the lane's cap keeps the
	// Operations that carry the volume rather than the alphabetically early
	// ones.
	sort.Slice(names, func(i, j int) bool {
		if count[names[i]] != count[names[j]] {
			return count[names[i]] > count[names[j]]
		}
		return names[i] < names[j]
	})
	if len(names) > maxReadOperations {
		elided = len(names) - maxReadOperations
		names = names[:maxReadOperations]
	}
	sort.Strings(names)
	return names, elided, overlong
}

// aggregateTargets groups one page of rows by what was read.
func aggregateTargets(rows []capability.AuditRow) []readTarget {
	byTarget := map[string]*readTarget{}
	nodes := map[string]map[string]bool{}
	var order []string
	for _, row := range rows {
		target := readTargetOf(factsOfRow(row))
		t, seen := byTarget[target]
		if !seen {
			t = &readTarget{Target: target}
			byTarget[target] = t
			order = append(order, target)
		}
		t.Calls++
		if row.NodeID != "" {
			if nodes[target] == nil {
				nodes[target] = map[string]bool{}
			}
			nodes[target][row.NodeID] = true
		}
		if row.Outcome == jobs.OutcomeDeniedByPolicy {
			t.Refused++
		}
	}
	out := make([]readTarget, 0, len(order))
	for _, target := range order {
		t := byTarget[target]
		t.Nodes = len(nodes[target])
		out = append(out, *t)
	}
	// Refused first, then volume. The deny-list catching something is the row
	// worth reading; the rest is background.
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Refused > 0) != (out[j].Refused > 0) {
			return out[i].Refused > 0
		}
		if out[i].Calls != out[j].Calls {
			return out[i].Calls > out[j].Calls
		}
		return out[i].Target < out[j].Target
	})
	return out
}

// refusalRowsOf projects the refused page onto what the page renders — which
// is what was asked for and where, and NOTHING about why.
func refusalRowsOf(rows []capability.AuditRow) []readRefusal {
	out := make([]readRefusal, 0, len(rows))
	for _, row := range rows {
		r := readRefusal{
			Target:    readTargetOf(factsOfRow(row)),
			NodeID:    row.NodeID,
			Principal: principalText(factsOfRow(row)),
			Verified:  row.Verified.AccountID != "",
			When:      row.Timestamp,
		}
		if row.NodeID != "" {
			r.NodeHref = "/console/nodes/" + row.NodeID
		}
		out = append(out, r)
	}
	return out
}

// principalList is the by-principal table under construction.
type principalList []readPrincipal

// principalRows builds one row per Account from the two bucket series and the
// listed refusals.
//
// Refusals are joined from the REFUSAL ROWS rather than from the Jobs lane,
// and that choice is the honest one of the two. The Jobs lane's
// Counts[denied_by_policy] is a per-Job Task tally over a 200-Job page: an
// in-flight Job has Task rows and no audit rows at all, and the two lanes
// filter on different timestamps (a Job's created_at against a Record's ts).
// A column built that way can EXCEED the exact headline beside it. Built from
// the refusal page, every number in this table and the one above it comes from
// one lane, one window and one filter — short, when the page was short, and
// the table says so.
func principalRows(reads, enums []capability.PrincipalBucket, refusals []capability.AuditRow,
	since, until time.Time, bucket time.Duration) principalList {
	byAccount := map[string]*readPrincipal{}
	var order []string
	at := func(accountID, name string) *readPrincipal {
		p, seen := byAccount[accountID]
		if !seen {
			p = &readPrincipal{AccountID: accountID, Verified: accountID != ""}
			if accountID != "" {
				p.Href = "/console/reads?principal=" + url.QueryEscape(accountID)
			}
			byAccount[accountID] = p
			order = append(order, accountID)
		}
		if p.Name == "" {
			p.Name = name
		}
		return p
	}

	series := map[string][]capability.PrincipalBucket{}
	for _, b := range reads {
		p := at(b.AccountID, b.AccountName)
		p.Calls += b.Count
		series[b.AccountID] = append(series[b.AccountID], b)
	}
	for _, b := range enums {
		at(b.AccountID, b.AccountName).Enum += b.Count
	}
	for _, row := range refusals {
		at(row.Verified.AccountID, principalText(factsOfRow(row))).Refused++
	}

	out := make(principalList, 0, len(order))
	for _, accountID := range order {
		p := byAccount[accountID]
		if p.Name == "" {
			p.Name = "unattributed"
		}
		p.Trend, p.TrendRise = trendOf(series[accountID], since, until, bucket)
		out = append(out, *p)
	}
	return out
}

// mergeInto folds l into base, matching on Account id.
func (l principalList) mergeInto(base principalList) principalList {
	index := map[string]int{}
	for i, p := range base {
		index[p.AccountID] = i
	}
	for _, p := range l {
		i, seen := index[p.AccountID]
		if !seen {
			base = append(base, p)
			continue
		}
		base[i].Enum += p.Enum
		if base[i].Name == "unattributed" && p.Name != "" {
			base[i].Name = p.Name
		}
	}
	return base
}

func sortPrincipals(ps []readPrincipal) {
	sort.SliceStable(ps, func(i, j int) bool {
		if ps[i].Calls+ps[i].Enum != ps[j].Calls+ps[j].Enum {
			return ps[i].Calls+ps[i].Enum > ps[j].Calls+ps[j].Enum
		}
		return ps[i].Name < ps[j].Name
	})
}

// trendOf compares an Account's most recent COMPLETE bucket against the MEAN
// OF THE EARLIER COMPLETE ONES — its own baseline, which is spec 17's "a
// machine Account whose read volume jumped tenfold this week is the single
// most useful row this screen can produce".
//
// Against its own baseline, not against the window total and not against other
// Accounts: a busy Account is not interesting, and a quiet one that suddenly
// is not quiet is.
//
// INCOMPLETE BUCKETS ARE DROPPED, both ends. The store buckets on an absolute
// grid, and the window's edges fall wherever they fall, so the newest bucket
// covers only the fraction of itself that has happened yet and the oldest is
// clipped by Since. Comparing a fraction of a bucket against eleven whole ones
// biases the ratio DOWN — a systematic false negative on the column this
// screen exists for — and leaving a clipped bucket in the baseline biases it
// UP. The cost is stated on the page: a spike inside the current bucket is not
// marked until that bucket closes.
func trendOf(buckets []capability.PrincipalBucket, since, until time.Time, bucket time.Duration) (text string, rise bool) {
	whole := make([]capability.PrincipalBucket, 0, len(buckets))
	for _, b := range buckets {
		if b.Start.Before(since) || b.Start.Add(bucket).After(until) {
			continue
		}
		whole = append(whole, b)
	}
	if len(whole) < 3 {
		// Two points are not a baseline. Saying nothing is better than
		// calling the second half of a pair a trend.
		return "", false
	}
	sort.SliceStable(whole, func(i, j int) bool { return whole[i].Start.Before(whole[j].Start) })
	last := whole[len(whole)-1].Count
	var earlier int
	for _, b := range whole[:len(whole)-1] {
		earlier += b.Count
	}
	mean := float64(earlier) / float64(len(whole)-1)
	if mean <= 0 || float64(last) < 2*mean {
		return "level against its own baseline", false
	}
	return fmt.Sprintf("%.0f× its own baseline", float64(last)/mean), true
}

// readTargetName names WHAT was read, in the terms an operator would search
// for. It is the shared core of the two wrappers below.
//
// It iterates audit.TargetArgKeys rather than a local list, because the store
// builds the COALESCE behind AuditReach's distinct-target count from that same
// slice (internal/store/auditquery.go's reachTargetExpr): a divergent order
// here would make this page's headline and its table disagree about how many
// distinct things were read.
//
// ONE RESIDUAL DIVERGENCE, deliberately kept: the store's COALESCE stops at
// the first key PRESENT and this stops at the first key present and NON-EMPTY,
// so a Record carrying an explicitly empty `path` alongside a `unit` would key
// differently on the two sides. The non-empty rule is what Activity renders
// today, and no catalog Operation carries two of these keys, so the case is
// not reachable — but it is the kind of thing that becomes reachable quietly.
func readTargetName(operationName, actionKind string, args map[string]string) string {
	if operationName == "" {
		if actionKind != "" {
			return actionKind
		}
		return "registry read"
	}
	// The path argument is the interesting half of a file read. Where an
	// Operation has one, the target is "operation path" so that two reads of
	// different files do not collapse into one row.
	for _, key := range audit.TargetArgKeys {
		if v, ok := args[key]; ok && v != "" {
			return operationName + " " + v
		}
	}
	return operationName
}

// Both families of caller reach this core through vocab.go's trailFacts
// projection — readTargetOf(factsOfRecord(rec)) for a whole-trail Record and
// readTargetOf(factsOfRow(row)) for a read-lane Row — so the "one core" this
// comment promises is one function reached one way, not two wrappers that
// could drift apart.

var readsTmpl = newScreen("reads", `
<p class="lede">Reading is exfiltration by construction: a read result flows to whoever asked, and
for an AI-agent that means the model provider. This screen is a map of that exposure — <b>who read
what, from where, and when</b>. It cannot show you the contents, at any age, and it is not going
to grow the ability to.</p>

<p class="gap"><b>The audit trail keeps outcomes and timings and never read output</b> (ADR-0025):
reading is exfiltration, so what left a Node is audited and what it said is not. That is the precise
claim, because the stronger one would be false &mdash; what the daemon sent still lives on the Task
rows until the Job is collected, and is readable through <code>GET /api/v1/jobs/{job_id}</code>.
Nothing on this page will show it, at any age or aggregation, because a screen that did would become
the durable place read output is read from.</p>

<p class="scoped">
{{range .WindowLine}}{{if .Current}}<b>{{.Label}}</b>{{else}}<a href="{{.Href}}">{{.Label}}</a>{{end}}
{{end}}
{{if .Scoped}}<span class="dim">scoped to</span> <code>{{.Principal}}</code>{{end}}
{{with .NodeID}}<span class="dim">on</span> <code>{{.}}</code>{{end}}
{{with .Operation}}<span class="dim">operation</span> <code>{{.}}</code>{{end}}
{{with .PathPrefix}}<span class="dim">path</span> <code>{{.}}</code>{{end}}
</p>

{{range .Notes}}<p class="gap">{{.}}</p>{{end}}

{{if .Any}}
<div class="statrow">
  {{if .ReadsKnown}}
  <div class="stat"><b>{{.Calls}}</b><span>{{plural .Calls "read from a Node" "reads from Nodes"}}</span></div>
  <div class="stat"><b>{{.Targets}}</b><span>distinct {{plural .Targets "target" "targets"}}</span></div>
  <div class="stat"><b>{{.Nodes}}</b><span>{{plural .Nodes "Node touched" "Nodes touched"}}</span></div>
  {{end}}
  {{if .RefusedKnown}}<a class="stat decision" href="#refused"><b>{{.Refused}}</b><span>refused by Policy</span></a>{{end}}
  {{if .EnumKnown}}<div class="stat"><b>{{.Enumerations}}</b><span>control-plane {{plural .Enumerations "enumeration" "enumerations"}}</span></div>{{end}}
</div>
<p class="note">Two different numbers on purpose. One <code>file.read</code> across 4,000 Nodes is
one target and four thousand exposures; which one matters depends on whether you are asking what
was seen or how far it reached. Enumerations are counted apart from all three: listing the
registry is exposure — it hands over the shape of your estate — but it is not bytes off a machine,
and a headline that mixes the two makes both softer than they are.
Every figure shown above is exact over the {{.Window}} shown: each is one aggregate computed over
every matching record, not a tally of the rows in the tables below. A figure this page did not
compute — because the query failed, or because the lane was deliberately not queried — is ABSENT
rather than rendered as a zero, since an exact zero is the strongest claim on this screen.</p>
{{else if .Measured}}
<p class="dim">Nothing has been read in this window.</p>
{{else}}
<p class="dim">None of this window&#39;s figures could be computed, so this page makes no claim about
exposure either way. See the notes below.</p>
{{end}}

<section class="panel">
  <h3>By principal</h3>
  {{if .PrincipalsError}}
  <p class="note">The per-principal figures could not be read. Any counts above are unaffected:
  they come from their own aggregates.</p>
  {{end}}
  {{if .Principals}}
  <div class="tablescroll">
  <table class="rows">
    <thead><tr><th>Account</th><th class="num">Node reads</th><th class="num">Enumerations</th><th class="num">Refused</th><th>Against its own baseline</th><th></th></tr></thead>
    <tbody>
    {{range .Principals}}
      <tr>
        <td>{{template "trust-chip" (trust .Name .Verified)}}</td>
        <td class="num">{{.Calls}}</td>
        <td class="num">{{.Enum}}</td>
        <td class="num">{{.Refused}}</td>
        <td><span class="trend{{if .TrendRise}} rise{{end}}">{{.Trend}}</span></td>
        <td>{{with .Href}}<a href="{{.}}">only this Account</a>{{end}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  <p class="note">A machine Account whose read volume jumps against its own baseline is the single
  most useful row this screen can produce, so the trend column compares an Account&#39;s most recent
  COMPLETE bucket of this window against the mean of the earlier complete ones — its own history,
  never the fleet&#39;s and never the window total. A bucket clipped by either edge of the window is
  left out of both sides: it is systematically smaller than a whole one, and comparing a fraction
  against eleven wholes would hide the very spike this column exists to show. The cost is latency —
  a spike inside the bucket that is still filling is not marked until it closes.
  Node reads and enumerations stay in their own columns; the baseline is built from Node reads. The
  refused column is counted over the refusals LISTED below, so it can be short where that table is;
  the exact refusal total is the figure above.</p>
  {{else if .Measured}}<p class="dim">No Account has read anything in this window.</p>
  {{else}}<p class="dim">Not computed.</p>{{end}}
</section>

<section class="panel">
  <h3>By target &mdash; read from Nodes</h3>
  {{if .TargetsError}}
  <p class="note">The by-target rows could not be read. The counts above are exact — they come from
  the window&#39;s own aggregate, not from this list.</p>
  {{end}}
  {{if .TargetRows}}
  <div class="tablescroll">
  <table class="rows">
    <thead><tr><th>Target</th><th class="num">Calls</th><th class="num">Nodes</th><th class="num">Refused</th></tr></thead>
    <tbody>
    {{range .TargetRows}}
      <tr{{if .Refused}} class="denyrow"{{end}}>
        <td><code>{{.Target}}</code></td>
        <td class="num">{{.Calls}}</td>
        <td class="num">{{.Nodes}}</td>
        <td class="num">{{.Refused}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{if .TargetsSampled}}<p class="note">The counts above are exact; this table is computed over the
  most recent {{.TargetsListed}} records in the window.</p>{{end}}
  {{else if .ReadsKnown}}<p class="dim">Nothing has been read from a Node.</p>
  {{else}}<p class="dim">The Node-read lane was not queried for this window — see the note below.</p>{{end}}
</section>

<section class="panel" id="refused">
  <h3>Refused by Policy</h3>
  {{if .RefusedCountError}}
  <p class="note"><b>The exact refusal count could not be computed and is not shown.</b> Any
  refusals listed here are real; how many there were in total is not known on this page, and a zero
  in its place would have been a claim rather than a measurement.</p>
  {{end}}
  {{if .RefusalsError}}
  <p class="note">The refusal rows could not be read, so none is listed below.</p>
  {{end}}
  {{if .RefusedKnown}}
  <p class="scoped"><b>{{.Refused}}</b> {{plural .Refused "read was refused" "reads were refused"}} by a
  Node&#39;s Policy in this window, across <b>{{.RefusedTargets}}</b>
  {{plural .RefusedTargets "target" "targets"}} and <b>{{.RefusedNodes}}</b>
  {{plural .RefusedNodes "Node" "Nodes"}}. A refusal is Policy working: something asked and a Node
  said no, which is the product doing exactly what it is for. The three figures are exact over the
  window: they come from their own aggregate, so a refusal can never be hidden by a table that was
  too short to reach it.</p>
  {{end}}
  {{if .Refusals}}
  <div class="tablescroll">
  <table class="rows">
    <thead><tr><th>Target</th><th>Node</th><th>Account</th><th>When</th></tr></thead>
    <tbody>
    {{range .Refusals}}
      <tr class="denyrow">
        <td><code>{{.Target}}</code></td>
        <td>{{if .NodeHref}}<a href="{{.NodeHref}}"><code>{{.NodeID}}</code></a>{{else}}<span class="dim">&mdash;</span>{{end}}</td>
        <td>{{template "trust-chip" (trust .Principal .Verified)}}</td>
        <td class="num">{{stamp .When}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{if .RefusalsSampled}}<p class="note">The count above is exact; the
  {{.RefusalsListed}} most recent refusals are listed.</p>{{end}}
  {{else if .RefusedKnown}}<p class="dim">No read was refused in this window.</p>
  {{else}}<p class="dim">The refusal lane was not queried for this window — see the note below.</p>{{end}}
  <p class="gap"><b>The deciding rule is not shown, and not for want of looking.</b> The daemon
  explains a refusal in the Task&#39;s own output, and for a read-class Task the audit trail never
  retains that output (ADR-0025) — so the rule is absent from the trail by design rather than
  missing by accident. Open the Node to read its effective Policy, which is where the rule lives.
  The trail also cannot say a refusal came from the confidentiality deny-list specifically: it
  records that this Node&#39;s Policy refused, and that is the claim this page makes.</p>
</section>

<section class="panel">
  <h3>Control-plane enumeration and trail queries</h3>
  {{if not .EnumApplies}}
  <p class="dim">Not shown under an Operation or path filter: an enumeration reads the Relay&#39;s own
  registry and catalogue, so it carries neither, and a panel that ignored the filter would answer a
  different question than the rest of this page. The headline carries no enumeration figure for the
  same reason.</p>
  {{else}}
  {{if .EnumCountError}}<p class="note">The exact enumeration count could not be computed and is not
  shown.</p>{{end}}
  {{if .EnumError}}<p class="note">The enumeration rows could not be read.</p>{{end}}
  {{if .NodeID}}
  <p class="note">Filtered to one Node, like everything else on this page. Most enumerations name no
  Node at all — only the tools that take one (<code>describe_node</code>, <code>get_job</code>) can
  match a Node filter — so both this table and the figure above it are narrower here than the
  window&#39;s enumeration traffic, and deliberately so.</p>
  {{end}}
  {{if .EnumTargets}}
  <div class="tablescroll">
  <table class="rows">
    <thead><tr><th>Tool</th><th class="num">Calls</th></tr></thead>
    <tbody>
    {{range .EnumTargets}}
      <tr>
        <td><code>{{.Target}}</code></td>
        <td class="num">{{.Calls}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  </div>
  {{if .EnumSampled}}<p class="note">The count above is exact; this table is computed over the most
  recent {{.EnumListed}} records in the window.</p>{{end}}
  <p class="note">These read the Relay&#39;s own registry, Operation catalogue and audit trail, never
  a Node, so they have no reach and no Policy verdict — Policy is a Node&#39;s and there is no Node
  here. They still disclose: the shape of the estate, its labels, and what the fleet will permit. An
  agent that enumerates far more than it reads is mapping rather than working.</p>
  {{else if .EnumKnown}}<p class="dim">Nothing has been enumerated.</p>
  {{else}}<p class="dim">Not computed.</p>{{end}}
  {{end}}
</section>

<p class="gap"><b>Reading this page is itself a read, and it is counted here.</b> The Relay records a
read of the trail as a read, so this view wrote {{.Queries}} {{plural .Queries "record" "records"}}
that the next view of it will count. The enumeration figure above is not merely affected by that
later — it already includes it: the read lane writes its record BEFORE the query runs, so the
enumeration aggregate has counted every query this page had already made, itself included. On an
otherwise idle Relay the figure therefore never settles below about seven and climbs by nine per
refresh. These records are labelled rather than filtered out: hiding them would take a second
hardcoded name list — the exact smell this screen was rebuilt to remove — and &ldquo;who queried the
audit trail&rdquo; is legitimately part of read egress.</p>

{{if .OpsEmpty}}
<p class="gap"><b>The audit lane was not queried for Node reads.</b>
{{if .Operation}}No read-class Job ran <code>{{.Operation}}</code> in this window, so it is not part
of the read vocabulary here and nothing was counted for it. If that Operation is a mutate, this
screen is the wrong place to look for it: an Operation filter is intersected with the read-class
Operations actually observed, never passed through.{{else}}No read-class Job ran in this window, so
there was no Operation to count reads for.{{end}}
The Operation filter is what keeps this page reading dispatch records for READS: without one, the
same query matches every mutate dispatch in the window, so it is not run at all.</p>
{{end}}

<p class="gap"><b>The two halves of this page read different clocks.</b> The read vocabulary comes
from Jobs CREATED in this window; every figure comes from audit records TIMESTAMPED in it, and a
Job&#39;s dispatch records are written after the dispatch returns. So a read-class Job created just
before this window whose records land inside it contributes no Operation to the vocabulary, and its
reads are missing from every figure above — and if it were the only one, this page would say the
lane was not queried while matching records existed. Same class of gap as the {{.JobPageSize}}-Job
page and the {{.OpsCap}}-Operation cap below, and it closes when the audit record carries a risk
class of its own.</p>

{{if .JobsSampled}}
<p class="gap"><b>The read vocabulary is drawn from the most recent {{.JobPageSize}}
read-class Jobs</b> in this window, by their DECLARED risk class. A read Operation used only outside
that page is missed here, and from every audit figure above. This is the one accuracy cost of the
audit record not carrying a risk class of its own.</p>
{{end}}

{{if .OpsElided}}
<p class="gap">{{.OpsElided}} further read {{plural .OpsElided "Operation was" "Operations were"}}
observed and not counted: the query lane caps an Operation filter at {{.OpsCap}}
entries, so the busiest are kept.</p>
{{end}}

{{if .OpsRefused}}
<p class="gap">{{.OpsRefused}} read {{plural .OpsRefused "Operation is" "Operations are"}} left out
because the name is longer than {{.OpsNameBytes}} bytes, which the query lane refuses outright.
Dropping the name costs one row; sending it would have failed every figure on this page for this
window.</p>
{{end}}

<p class="gap"><b>Two filters this screen does not offer.</b> Selector filtering, because the read
lane&#39;s audit filter carries no Selector field and adding one is a change to three packages, not
to this screen. Export, for the same reason it is not faked: an auditor&#39;s CSV needs its own
escaping rules and its own tests, and shipping it untested here would be worse than saying it is
not built. Principal, Operation, Node, path prefix and window all work, and every one of them is
recorded in the trail as this page&#39;s own search.</p>
`)
