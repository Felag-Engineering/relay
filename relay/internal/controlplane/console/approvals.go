package console

// approvals.go is the queue (spec 14) and the single approval object (spec
// 08). The queue is read-only, structurally; the object carries the decision
// control since #453 — see the two section headers below.
//
// # Why there is no Approve button here, and will not be one on a row
//
// Deciding happens on the approval OBJECT, never in the list. A row-level
// Approve control would let someone approve without seeing what they approved,
// which is the entire failure the approval mechanism exists to prevent — a
// human who clicks through a queue is a rubber stamp with an audit trail, and an
// audit trail of rubber stamps is worse than no gate at all, because it looks
// like oversight.
//
// The asymmetry is deliberate and worth stating: a BULK DENY is safe in a way
// bulk approve is not, because refusing without reading fails closed. That
// arrives in v0.7.0 with step-up and a reason.
//
// # Order by urgency, never by arrival
//
// An approval that lapses because it sat below the fold is a failure of this
// screen. Nearest expiry first, on the DURATION and never on the rendered
// string, with a lapsed request LAST — see buildApprovalRows.
//
// # Where the approval object's facts come from, and what it cannot say
//
// Three sources, and the card labels each one:
//
//   - The Request itself: summary, plan hash, quorum, audience, decisions.
//   - The Grant, for a Request whose subject is a Scope rather than a Plan
//     (GrantForApproval).
//   - The park's own audit record, joined on approval_id, for the Selector as
//     written and the arguments — the ONLY place either is stored.
//
// And one thing no source has: THE RESOLVED FAN-OUT. A park creates no Job at
// all (approval.Service), so there is no Job, no Task and no Results anywhere
// for the record being rendered — the number of Nodes is prose inside the
// Relay-authored Summary and nothing else. So the card says the fan-out cannot
// be compared rather than inferring one. Nothing here is EVER parsed out of
// Summary: that prose exists precisely so a human is not asked to trust a
// machine's own description, and re-deriving a number from it would hand back
// the fidelity the summary was invented to protect.
//
// # The queue stays structurally read-only; the object does not
//
// The Console's approval seam (seams.go) has five reads on it and STILL no
// decision method, no RequestGrant and no RevokeGrant — deciding (#453) is
// reached through ApprovalDecider, its OWN seam in decide.go, for the same
// reason JobCanceller lives in cancel.go rather than here. The queue below
// remains read-only exactly as before: NO FORM, NO BUTTON and NO INPUT, every
// filter an anchor. The approval OBJECT is now the one place in the Console a
// decision can be made, which is the point of the header above — deciding
// happens on the object, never in the list, and that reasoning does not
// weaken because a demo wants fewer clicks.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// expiryPressure is the window inside which a pending approval renders as
// urgent. This is the one place in the Console where a countdown earns its keep.
const expiryPressure = 15 * time.Minute

// maxApprovalFilterBytes bounds every value this screen reads off its own
// query string.
//
// Deliberately separate from reads.go's maxFilterValueBytes, which happens to
// carry the same number for an unrelated reason: that one bounds values BEFORE
// they reach the read lane, and this one bounds values that reach no seam at
// all. One constant would tie two independent policies together and make one
// of the two doc comments false the first time either moved.
//
// A value longer than this is DROPPED rather than truncated: a truncated
// filter would silently match something the operator did not type. None of
// these values reaches a seam — they are compared in memory against rows the
// capability layer already returned — so the bound is about what gets rendered
// back into the page and carried through the filter links, not about a query.
const maxApprovalFilterBytes = 128

// The three answers this Console can give about whether a pending Request is
// waiting on the caller, computed from the record and the caller alone.
const (
	waitingYes = "yes"
	waitingNo  = "no"

	// waitingUnknown is the honest answer for a Request with an EMPTY audience:
	// the audience is unrestricted, and the role floor for deciding lives in
	// the capability layer (Route.MinRole), which this surface never
	// second-guesses.
	waitingUnknown = "unknown"
)

const (
	scopeMine = "mine"
	scopeAll  = "all"
)

type approvalRow struct {
	ID   string
	Href string

	Summary   string
	Operation string
	Risk      string

	Requester string
	Verified  bool

	Signed   int
	Required int

	TTL    string
	Urgent bool
	Lapsed bool

	// ttl and created are the SORT KEYS, and they are deliberately not the
	// rendered ones. Sorting on the string TTL puts "10m left" before "12h
	// left" before "5m left", which is how the most urgent request in the
	// queue ends up in the middle of it.
	ttl     time.Duration
	created time.Time

	MatchedRules []string
	PlanHash     string

	// shapeKey groups pending approvals of the SAME SHAPE, and Identical counts
	// how many share it. Approving three alike requests one at a time without
	// noticing they are alike is precisely the fatigue failure the grouping
	// exists to catch.
	//
	// It is the stored shape key (#415): the Action, its risk class, its shape
	// arguments and the normalised Selector, WITHOUT the resolved fan-out. A
	// record with no comparable shape — pre-#415 rows carry a legacy key —
	// groups with NOTHING rather than with every other such record.
	//
	// IT IS UNEXPORTED, AND THAT IS A SECURITY PROPERTY RATHER THAN A STYLE
	// CHOICE. html/template refuses an unexported field at execution time, so
	// "the shape key never reaches a template" is a fact about this type and
	// not a promise defended by a test. The key is an unsalted SHA-256 over a
	// much smaller preimage than a plan hash — for Raw Exec every argv element
	// is in it — so a rendered key, a data- attribute carrying one, or a
	// ?shape= lookup parameter would be an offline-confirmation oracle over a
	// brute-forceable preimage. What the screen renders instead is ShapeGroup:
	// a per-render ordinal that says "these two are alike" and identifies
	// nothing outside this page.
	//
	// It is a rendering hint and never an authorization: a decision still binds
	// to the plan hash, and two rows sharing this key may well cover different
	// Node sets.
	shapeKey   string
	Identical  int
	ShapeGroup string

	// IsGrant and ScopeLine: a Grant renders as EXACTLY ONE ROW (spec 14). That
	// is structural rather than defended — the queue lists Requests, and there
	// is exactly one Request per Grant — so nothing here may ever grow a row
	// per released Job. The released Jobs live on the CARD.
	IsGrant   bool
	ScopeLine string

	// Waiting, Own and ExcludedRequester are what the Console can say about the
	// caller's relation to this row. See approvalStanding.
	Waiting           string
	Own               bool
	ExcludedRequester bool
}

// filterOption is one filter value, rendered as an ANCHOR. There is no form,
// no button and no input on this screen.
type filterOption struct {
	Label string
	Href  string
	Count int
	On    bool
}

type filterGroup struct {
	Name    string
	Options []filterOption

	// More is how many values of this dimension exist beyond the ones offered,
	// stated rather than silently dropped.
	More int
}

// approvalFilter is the queue's filter, parsed from the query string and
// compared IN MEMORY. No value here reaches a seam.
type approvalFilter struct {
	Who    string
	Op     string
	Risk   string
	Quorum string
	Scope  string
}

type approvalsView struct {
	Rows []approvalRow

	// Count is the volume signal spec 14 asks for and is ALWAYS the whole
	// pending queue: "a queue that is suddenly forty deep is itself
	// information". A filtered count would hide exactly the thing it is for.
	Count  int
	Shown  int
	Hidden int
	Wired  bool

	// HiddenByScope is how many rows the AUDIENCE filter removed, counted
	// apart from Hidden. The screen says "hiding N addressed to somebody else",
	// and attributing to the audience what a risk filter did is the screen
	// explaining itself wrongly.
	HiddenByScope int

	Filters  []filterGroup
	Filtered bool

	// ScopeMine is set when the "waiting on me" filter is in force, and
	// ScopeDefaulted when it was applied because it is the DEFAULT rather than
	// because it was asked for.
	ScopeMine      bool
	ScopeDefaulted bool

	// ScopeNotApplied is the never-empty-the-screen rule: the default filter
	// would have emptied a queue that has entries in it, so it was not applied
	// and the screen says so. A defaulted filter that turns a full queue into
	// "Nothing is waiting" is the worst lie this screen can tell.
	ScopeNotApplied bool

	AllHref   string
	ClearHref string

	// GrantsUnreadable degrades the Scope lines and nothing else. A grant-store
	// hiccup must not cost an operator the whole queue at the moment something
	// in it is expiring.
	GrantsUnreadable bool
}

func handleApprovals(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The caller is read for eligibility — "waiting on me" — and for
		// nothing else. It is a context read, exactly as page() does its own.
		caller, ok := principal(w, r)
		if !ok {
			return
		}
		p, ok := page(d, w, r, "Approvals")
		if !ok {
			return
		}
		p.Banner = banner(d, r)

		if d.Approvals == nil {
			renderScreen(w, p, approvalsTmpl, approvalsView{})
			return
		}
		// The queue's trail reads (the Scope lines a Grant row carries) go
		// through the latch, so a queue whose reads cannot be audited is not
		// served — one rule, no per-screen exception (screen.go).
		d, lane := latched(d)
		ctx := r.Context()
		reqs, err := d.Approvals.PendingApprovals(ctx)
		if err != nil {
			unavailable(w, "the approval queue (it returned an error)")
			return
		}

		// A grant-store failure degrades the SCOPE LINES and nothing else. The
		// queue is what an operator opens when something is about to lapse, so
		// it must not 500 over a seam that decorates some of its rows.
		grants, grantsErr := activeGrantsByRequest(ctx, d)
		rows := buildApprovalRows(reqs, grants, caller, d.now())
		v := buildApprovalsView(rows, parseApprovalFilter(r.URL.Query()))
		v.GrantsUnreadable = grantsErr != nil
		if refusedUnaudited(w, lane, "the approval queue's audit trail") {
			return
		}
		renderScreen(w, p, approvalsTmpl, v)
	}
}

// activeGrantsByRequest indexes the live Grants by the Request that authorized
// them, which is the only handle the queue has: the queue lists Requests, and
// nothing on a Request says it is a grant request.
//
// A Grant whose window has not opened yet is not Active, so its row renders
// without a Scope line — its Relay-authored Summary is still SummarizeScope
// prose and still reads as a grant. Closing that would cost one
// GrantForApproval per row, which is not worth it on a screen whose length is
// bounded by human attention.
func activeGrantsByRequest(ctx context.Context, d Deps) (map[string]approval.Grant, error) {
	grants, err := d.Approvals.ActiveGrants(ctx)
	if err != nil {
		return nil, err
	}
	byRequest := make(map[string]approval.Grant, len(grants))
	for _, g := range grants {
		byRequest[g.RequestID] = g
	}
	return byRequest, nil
}

func buildApprovalRows(reqs []approval.Request, grants map[string]approval.Grant, caller capability.Principal, now time.Time) []approvalRow {
	identical := map[string]int{}
	for _, req := range reqs {
		if key := identicalKey(req); key != "" {
			identical[key]++
		}
	}

	rows := make([]approvalRow, 0, len(reqs))
	for _, req := range reqs {
		key := identicalKey(req)
		alike := 1
		if key != "" {
			alike = identical[key]
		}
		ttl := req.ExpiresAt.Sub(now)
		standing := approvalStandingFor(req, caller)
		row := approvalRow{
			ID:                req.ID,
			Href:              "/console/approvals/" + req.ID,
			Summary:           req.Summary,
			Operation:         approvalOperation(req),
			Risk:              RiskLabel(req.RiskClass),
			Requester:         req.RequestedBy,
			Verified:          req.RequestedByID != "",
			Signed:            countApprovals(req),
			Required:          req.Require.Count,
			TTL:               renderTTL(ttl),
			ttl:               ttl,
			created:           req.CreatedAt,
			Urgent:            ttl > 0 && ttl <= expiryPressure,
			Lapsed:            ttl <= 0,
			MatchedRules:      req.MatchedRules,
			PlanHash:          req.PlanHash,
			shapeKey:          key,
			Identical:         alike,
			Waiting:           standing.Waiting,
			Own:               standing.Own,
			ExcludedRequester: standing.ExcludedRequester,
		}
		if g, ok := grants[req.ID]; ok {
			row.IsGrant = true
			row.ScopeLine = grantRowLine(g)
		}
		rows = append(rows, row)
	}

	// Nearest expiry first, on the DURATION, with a lapsed request LAST.
	//
	// Lapsed-last reverses what this screen used to do. An undecidable request
	// at the top of the queue pushes decidable ones below the fold, which is
	// the exact failure spec 14 names — and capability.PendingApprovals already
	// filters past-deadline rows, so a lapsed row here means the clock moved
	// under the render and is rare by construction.
	//
	// Spec 14 also asks for "then largest fan-out" as the tiebreak. THAT IS NOT
	// IMPLEMENTED AND CANNOT BE: the approval record carries no fan-out, and a
	// park creates no Job to count Tasks on. #462 stays open for it rather than
	// this comment promising something the data cannot support. The tiebreak is
	// creation time and then ID, which is arbitrary but STABLE — a queue that
	// reorders between two renders of the same data is its own hazard.
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Lapsed != rows[j].Lapsed {
			return rows[j].Lapsed
		}
		if rows[i].ttl != rows[j].ttl {
			// Within the lapsed group the order flips: most recently lapsed
			// first. "It expired a minute ago" is a different conversation from
			// "it expired on Tuesday", and the recent one is the one somebody
			// may still be waiting on an answer about.
			if rows[i].Lapsed {
				return rows[i].ttl > rows[j].ttl
			}
			return rows[i].ttl < rows[j].ttl
		}
		if !rows[i].created.Equal(rows[j].created) {
			return rows[i].created.Before(rows[j].created)
		}
		return rows[i].ID < rows[j].ID
	})

	assignShapeGroups(rows)
	return rows
}

// assignShapeGroups labels each multi-member shape group with a PER-RENDER
// ORDINAL — "A", "B" — in the order the groups first appear.
//
// The ordinal is what the template renders. The key itself never leaves this
// package (see approvalRow.shapeKey): an ordinal says "these two are alike",
// which is the entire informational content of the grouping, and identifies
// nothing outside this page.
func assignShapeGroups(rows []approvalRow) {
	labels := map[string]string{}
	for i := range rows {
		if rows[i].Identical < 2 || rows[i].shapeKey == "" {
			continue
		}
		label, ok := labels[rows[i].shapeKey]
		if !ok {
			label = shapeGroupLabel(len(labels))
			labels[rows[i].shapeKey] = label
		}
		rows[i].ShapeGroup = label
	}
}

// shapeGroupLabel renders the nth group ordinal: A..Z, then AA, AB, and so on.
func shapeGroupLabel(n int) string {
	label := ""
	for {
		label = string(rune('A'+n%26)) + label
		n = n/26 - 1
		if n < 0 {
			return label
		}
	}
}

// grantRowLine is the one row a Grant occupies (spec 14, spec 08): its Scope,
// its ceiling, its use limit and its window, in one line.
//
// Never one row per released Job. A Grant that fragments into per-Job rows has
// defeated the mechanism before anyone opens it — the released Jobs are listed
// on the CARD, where the human deciding can see how much of the window has
// already been spent.
func grantRowLine(g approval.Grant) string {
	what := "raw exec"
	if len(g.Scope.Operations) > 0 {
		ops := append([]string(nil), g.Scope.Operations...)
		sort.Strings(ops)
		what = strings.Join(ops, ", ")
		if g.Scope.RawExec {
			what += ", and raw exec"
		}
	}
	// A Scope has no namespace term (#482), so this row never carries one. This
	// caller is fed only by ActiveGrants (buildApprovalRows), and Grant.Active
	// refuses a pre-#482 legacy-pinned Grant, so a dead pin can never reach
	// here to render as if it still covered anything.
	return strings.Join([]string{
		"Grant",
		what,
		"any namespace",
		"up to " + strconv.Itoa(g.Scope.MaxFanOut) + " Nodes per dispatch",
		strconv.Itoa(g.MaxUses) + " dispatches",
		"until " + g.ExpiresAt.UTC().Format("2006-01-02 15:04Z"),
	}, " · ")
}

// approvalStanding is what this Console can say — from the RECORD and the
// CALLER alone — about a pending Request's relation to the caller.
type approvalStanding struct {
	// Waiting is waitingYes, waitingNo or waitingUnknown.
	Waiting string

	// Own is true when the caller is the verified requester. Their own item is
	// never hidden from them (spec 14's "requester excluded" state: "the
	// requester sees their own item and cannot act on it; say why rather than
	// hiding the control").
	Own bool

	// ExcludedRequester is Own under requester_allowed: false — the
	// separation-of-duties tier, where a second person must sign.
	ExcludedRequester bool
}

// approvalStandingFor computes the caller's relation to req.
//
// BOTH SIDES OF EVERY IDENTITY COMPARISON MUST BE NON-EMPTY. A Request may
// legitimately carry no verified requester, and a Principal may carry no
// Account ID; comparing "" to "" would classify every unattributed record as
// the caller's own, which is both wrong on screen and the kind of wrong that
// makes a test pass while meaning nothing.
//
// The role floor is NOT consulted here and must not be. Who may decide is the
// capability layer's answer (ApprovalAuthorizer), and a surface that
// second-guessed it would be a second control path — so an unrestricted
// audience yields waitingUnknown, which the filter treats as "possibly yours"
// rather than "not yours".
func approvalStandingFor(req approval.Request, caller capability.Principal) approvalStanding {
	s := approvalStanding{Waiting: waitingUnknown}

	if req.RequestedByID != "" && caller.AccountID != "" && req.RequestedByID == caller.AccountID {
		s.Own = true
		s.ExcludedRequester = !req.Require.RequesterAllowed
	}
	if s.ExcludedRequester {
		// They can read it; they cannot sign it. It is not waiting on them.
		s.Waiting = waitingNo
		return s
	}
	if req.Require.AudienceMalformed() {
		// The domain admits no decider for a malformed audience (a blank
		// entry), so it is definitely not waiting on this caller. Consuming
		// the domain predicate rather than re-deciding it is invariant 10: an
		// adapter narrows only.
		s.Waiting = waitingNo
		return s
	}
	if len(req.Require.Audience) == 0 {
		return s
	}
	for _, a := range req.Require.Audience {
		if caller.Account != "" && strings.EqualFold(a, caller.Account) {
			s.Waiting = waitingYes
			return s
		}
	}
	s.Waiting = waitingNo
	return s
}

// mine reports whether a row survives the "waiting on me" filter.
//
// It EXCLUDES ONLY WHAT IS DEFINITELY NOT THE CALLER'S: a named audience that
// does not include them. An unknown standing is kept, because hiding the rows
// this Console cannot classify — while showing the ones it can — is the spec's
// own failure ("an approver arriving from a link should not have to find their
// own item in someone else's list") with the sign flipped. A caller's OWN
// request is kept too, excluded requester or not: they must see it, and the
// card tells them why they cannot sign it.
func (r approvalRow) mine() bool { return r.Waiting != waitingNo || r.Own }

func parseApprovalFilter(q url.Values) approvalFilter {
	return approvalFilter{
		Who:    filterValue(q, "who"),
		Op:     filterValue(q, "op"),
		Risk:   filterValue(q, "risk"),
		Quorum: filterValue(q, "quorum"),
		Scope:  filterValue(q, "scope"),
	}
}

func filterValue(q url.Values, key string) string {
	v := q.Get(key)
	if len(v) > maxApprovalFilterBytes {
		return ""
	}
	return v
}

// matches applies every filter EXCEPT scope, which has the never-empty rule
// wrapped around it (see buildApprovalsView).
func (f approvalFilter) matches(r approvalRow) bool {
	if f.Who != "" && !strings.EqualFold(f.Who, r.Requester) {
		return false
	}
	if f.Op != "" && f.Op != r.Operation {
		return false
	}
	if f.Risk != "" && f.Risk != r.Risk {
		return false
	}
	switch f.Quorum {
	case "unsigned":
		if r.Signed != 0 {
			return false
		}
	case "partial":
		if r.Signed == 0 || r.Signed >= r.Required {
			return false
		}
	}
	return true
}

func (f approvalFilter) value(key string) string {
	switch key {
	case "who":
		return f.Who
	case "op":
		return f.Op
	case "risk":
		return f.Risk
	case "quorum":
		return f.Quorum
	case "scope":
		return f.Scope
	}
	return ""
}

// with renders this screen's URL with one filter set (or cleared, for an empty
// value), preserving the others.
//
// There is deliberately NO shape parameter, and there never will be: a shape
// lookup key in a URL is an offline-confirmation oracle over a brute-forceable
// preimage (see approvalRow.shapeKey).
func (f approvalFilter) with(key, value string) string {
	q := url.Values{}
	for _, k := range []string{"who", "op", "risk", "quorum", "scope"} {
		if v := f.value(k); v != "" {
			q.Set(k, v)
		}
	}
	if value == "" {
		q.Del(key)
	} else {
		q.Set(key, value)
	}
	if len(q) == 0 {
		return "/console/approvals"
	}
	return "/console/approvals?" + q.Encode()
}

// toggle returns the URL that turns this value on, or off when it is already on.
func (f approvalFilter) toggle(key, value string) string {
	if f.value(key) == value {
		return f.with(key, "")
	}
	return f.with(key, value)
}

func buildApprovalsView(rows []approvalRow, f approvalFilter) approvalsView {
	v := approvalsView{
		Wired:     true,
		Count:     len(rows),
		Filters:   approvalFilterGroups(rows, f),
		AllHref:   f.with("scope", scopeAll),
		ClearHref: "/console/approvals?scope=" + scopeAll,
	}

	narrowed := make([]approvalRow, 0, len(rows))
	for _, r := range rows {
		if f.matches(r) {
			narrowed = append(narrowed, r)
		}
	}

	shown := narrowed
	scope := f.Scope
	defaulted := scope == ""
	if defaulted {
		scope = scopeMine
	}
	if scope == scopeMine {
		mine := make([]approvalRow, 0, len(narrowed))
		for _, r := range narrowed {
			if r.mine() {
				mine = append(mine, r)
			}
		}
		switch {
		case defaulted && len(mine) == 0 && len(narrowed) > 0:
			// The default would have emptied a queue that has entries in it.
			// Render everything and say the filter was not applied.
			v.ScopeNotApplied = true
		default:
			shown = mine
			v.ScopeMine = true
			v.ScopeDefaulted = defaulted
			v.HiddenByScope = len(narrowed) - len(mine)
		}
	}

	if v.ScopeNotApplied {
		// The chip bar is built before the never-empty rule runs, so the
		// "waiting on me" chip would otherwise render as ON beside a paragraph
		// saying it was not applied.
		clearWaitingChip(v.Filters)
	}

	v.Rows = shown
	v.Shown = len(shown)
	v.Hidden = len(rows) - len(shown)
	v.Filtered = v.Hidden > 0
	return v
}

func clearWaitingChip(groups []filterGroup) {
	for _, g := range groups {
		if g.Name != "waiting" {
			continue
		}
		for i := range g.Options {
			g.Options[i].On = false
		}
	}
}

// maxRequesterFilters bounds how many requester chips the bar offers. The rest
// are counted and stated rather than silently dropped.
const maxRequesterFilters = 8

// approvalFilterGroups builds the filter bar. Every count is over the WHOLE
// pending queue, not over the current selection, so the numbers answer "how
// much is there" rather than "how much of what I already chose".
func approvalFilterGroups(rows []approvalRow, f approvalFilter) []filterGroup {
	if len(rows) == 0 {
		return nil
	}

	waiting := 0
	requesters := map[string]int{}
	ops := map[string]int{}
	risks := map[string]int{}
	unsigned, partial := 0, 0
	for _, r := range rows {
		if r.mine() {
			waiting++
		}
		if r.Requester != "" {
			requesters[r.Requester]++
		}
		ops[r.Operation]++
		risks[r.Risk]++
		switch {
		case r.Signed == 0:
			unsigned++
		case r.Signed < r.Required:
			partial++
		}
	}
	groups := []filterGroup{{
		Name: "waiting",
		Options: []filterOption{
			{Label: "waiting on me", Href: f.with("scope", scopeMine), Count: waiting, On: f.Scope != scopeAll},
			{Label: "everything", Href: f.with("scope", scopeAll), Count: len(rows), On: f.Scope == scopeAll},
		},
	}}

	names := make([]string, 0, len(requesters))
	for name := range requesters {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if requesters[names[i]] != requesters[names[j]] {
			return requesters[names[i]] > requesters[names[j]]
		}
		return names[i] < names[j]
	})
	who := filterGroup{Name: "requester"}
	if len(names) > maxRequesterFilters {
		who.More = len(names) - maxRequesterFilters
		names = names[:maxRequesterFilters]
	}
	for _, name := range names {
		who.Options = append(who.Options, filterOption{
			Label: name, Href: f.toggle("who", name), Count: requesters[name], On: strings.EqualFold(f.Who, name),
		})
	}
	if len(who.Options) > 0 {
		groups = append(groups, who)
	}

	groups = append(groups,
		countedGroup("operation", "op", f, ops),
		countedGroup("risk", "risk", f, risks),
	)

	quorum := filterGroup{Name: "quorum"}
	for _, opt := range []struct {
		label string
		count int
	}{{"unsigned", unsigned}, {"partial", partial}} {
		if opt.count == 0 {
			continue
		}
		quorum.Options = append(quorum.Options, filterOption{
			Label: opt.label, Href: f.toggle("quorum", opt.label), Count: opt.count, On: f.Quorum == opt.label,
		})
	}
	if len(quorum.Options) > 0 {
		groups = append(groups, quorum)
	}

	out := groups[:0]
	for _, g := range groups {
		if len(g.Options) > 0 {
			out = append(out, g)
		}
	}
	return out
}

// countedGroup renders one filter dimension whose values come from the rows
// themselves, in a stable order.
func countedGroup(name, key string, f approvalFilter, counts map[string]int) filterGroup {
	values := make([]string, 0, len(counts))
	for v := range counts {
		values = append(values, v)
	}
	sort.Strings(values)
	g := filterGroup{Name: name}
	// One value is not a filter — it selects everything and says nothing.
	if len(values) < 2 {
		return g
	}
	for _, v := range values {
		g.Options = append(g.Options, filterOption{
			Label: v, Href: f.toggle(key, v), Count: counts[v], On: f.value(key) == v,
		})
	}
	return g
}

// --- The approval object (spec 08) ------------------------------------------

// decisionRow is one recorded answer.
type decisionRow struct {
	Account string
	Approve bool
	Reason  string
	Channel string
	Human   bool

	// At is the stamped decision time and Ago its relative form. It is
	// PERSISTED (approval_decisions.decided_at) and read back by the store;
	// the card left it blank until #468 noticed, which turned "mike signed 2h
	// ago" into "mike signed".
	At  string
	Ago string
}

// approvalAction is what the park's audit record says was asked for: the
// Selector AS WRITTEN and the arguments. It is the ONLY place either is stored
// — approval_requests carries neither.
//
// It is built for a PLAN park and never for a Grant. RequestGrant records its
// audit entry with no Selector and no Action at all, so a Grant's park row
// carries an empty Selector, an "unspecified" ActionKind and no arguments —
// rendering that as an action block labelled "read from the park's audit
// record" would be a fabrication on exactly the record type spec 08 calls a
// Grant. A Grant renders its Scope instead (grantCard).
type approvalAction struct {
	// Wired, Unreadable and Missing are three DIFFERENT absences and the card
	// says which: the query lane was not wired, it failed, or the park's audit
	// write did not land (Service joins that error, so a durable Request with
	// no audit record is a real state). None of them may render as "there were
	// no arguments".
	Wired      bool
	Unreadable bool
	Missing    bool

	// Known gates the Selector line on the record carrying a real ActionKind.
	//
	// This is the SelectorShape.Known distinction (#415) applied at render
	// time, and it is the highest-consequence thing on this card. An empty
	// stored Selector is AMBIGUOUS: Selector.String() returns "" both for "no
	// Selector was recorded" and for a Selector with no predicates — and a
	// Selector with no predicates MATCHES EVERY NODE. Rendering the second as
	// "(none)" would tell a human that the widest dispatch there is targeted
	// nothing.
	Known     bool
	Selector  string
	FleetWide bool

	// Args is the rendered form the card shows; args is the same arguments as
	// the map the audit row carried.
	//
	// Both, deliberately. The diff must compare what the reader can see beside
	// it, but comparing the RENDERED string means splitting "k=v k=v" on
	// whitespace — and an argument value containing a space ("msg=hello world")
	// then diffs as a truncation. The map is the comparison; the string is the
	// display.
	Args string
	args map[string]string
}

// releasedJob is one Job a Grant has released so far.
type releasedJob struct {
	ID   string
	Href string
}

// grantCard is the Scope disclosure for a Request whose subject is a Scope
// rather than a Plan.
type grantCard struct {
	Present bool

	Account    string
	Risk       string
	Operations []string
	RawExec    bool
	Namespace  string
	MaxFanOut  int
	Starts     string
	Expires    string
	MaxUses    int
	Progress   string

	// LegacyNamespacePin is set only for a Grant stored before #482 removed
	// namespace pinning. Such a Grant is never Active and covers nothing (see
	// approval.Grant.Active); the card says so rather than reusing the prose
	// written for a live Scope.
	LegacyNamespacePin string

	Revoked      bool
	RevokedBy    string
	RevokedAt    string
	RevokeReason string

	JobsWired      bool
	JobsUnreadable bool
	Jobs           []releasedJob
	JobCap         int

	// JobsComplete is false when the walk below stopped before the trail did,
	// which is the honest state to render: the list then names the most recent
	// Jobs and may not name every one.
	JobsComplete bool
}

// diffChange is one field that moved between a prior approval and this one.
type diffChange struct {
	Field string
	From  string
	To    string
}

// approvalDiff is the anti-fatigue callout: "same as what you approved Tue
// 14:02 — except the fan-out ceiling grew 10 -> 500".
//
// Everything in it is built from STORED data. Nothing is parsed out of Summary,
// ever: the summary carries the node count as prose, and re-deriving a number
// from prose is precisely the fidelity trap the Relay-authored summary exists
// to prevent.
type approvalDiff struct {
	Comparable bool
	Kind       string

	PriorID        string
	PriorHref      string
	PriorWhen      string
	PriorAgo       string
	PriorApprovers []string

	SamePlanHash  bool
	PlanHashKnown bool

	Changes []diffChange

	// NotComparable names what this Relay cannot compare, in words, on the
	// card. It always carries the fan-out for a Plan — see buildApprovalDiff.
	NotComparable []string

	// Absence is the stated reason there is no comparison at all. Three cases,
	// all said out loud rather than papered over with an empty callout.
	Absence string
}

type approvalView struct {
	Found bool
	ID    string

	Summary   string
	Operation string
	Risk      string
	PlanHash  string

	Requester string
	Verified  bool

	// State is the four-value approval vocabulary the card colours on:
	// pending, approved, denied, expired. It is NOT a Task outcome and must
	// never borrow one — a denied approval is not a Task that was denied by
	// Policy, and a pending one is not "unsupported".
	State    string
	Pending  bool
	Signed   int
	Required int

	Audience         []string
	RequesterAllowed bool

	// AudienceMalformed is Requirement.AudienceMalformed() — a blank entry in
	// the audience — carried through as its own flag rather than left for the
	// template to infer from Audience. A malformed audience is NON-EMPTY (it
	// names at least one blank entry), so rendering it through the same
	// {{with .Audience}} branch as a real audience would read as "these named
	// Accounts may decide", when the domain admits none of them (#608 cycle
	// 2). The predicate is consumed from the domain, never re-decided here
	// (invariant 10: an adapter narrows only).
	AudienceMalformed bool

	// CallerIsExcludedRequester makes the exclusion EXPLICIT to the one person
	// it affects, rather than leaving them to work out why nothing is
	// addressed to them.
	CallerIsExcludedRequester bool

	Created string
	Expires string
	TTL     string
	Urgent  bool

	MatchedRules []string
	Decisions    []decisionRow
	Approvers    []decisionRow

	JobID   string
	JobHref string

	Diff   approvalDiff
	Action approvalAction
	Grant  grantCard

	// GrantUnreadable is the third state of the Grant lookup: this Request may
	// authorize a Scope and the store could not say. The card renders neither
	// the Scope nor the Plan action block, and says which question is open.
	GrantUnreadable bool

	// Decide carries the decision form's data (#453). Nil means no control —
	// for every reason: the seams are unwired, the caller's role is below the
	// floor, this Request is not pending, the caller is the excluded
	// requester, the caller already signed, this Request authorizes a Grant,
	// or the Grant lookup itself failed. See buildApprovalView for the full
	// conjunction, and the five fields below for which specific reason the
	// card names when Decide is nil.

	// CallerAlreadySigned is true when the caller's OWN Account already
	// recorded a Decision on this Request (count:2's partial-state case).
	// Computed with BOTH sides of the identity comparison non-empty,
	// following approvalStandingFor's stated rule (approvalStandingFor's
	// doc): comparing "" to "" would mark every unattributed decision as the
	// caller's own. CallerSignedAt is that decision's stamp, for the card's
	// "you signed this at …" sentence.
	CallerAlreadySigned bool
	CallerSignedAt      string

	// DecideSeamsUnwired and CallerRoleBelowFloor name two more of the five
	// reasons the card can offer no control, purely for that explanation —
	// neither is a security decision, both mirror what decideOffered already
	// decided rather than re-deciding it. CallerRoleBelowFloor is real and
	// reachable: the CARD's own mount floor is RoleViewer, so a viewer can
	// read a pending Request perfectly well and simply is not offered the
	// control the operator-floor decide route requires.
	DecideSeamsUnwired   bool
	CallerRoleBelowFloor bool

	Decide *approvalDecideControl
}

// approvalDecideControl is the decision form's rendered data (#453).
//
// Authorising is the step-up prompt's object (spec 11: "a step-up prompt must
// state what it is authorising"), built from the stored Relay-authored
// Summary plus the Operation category — never re-derived or parsed out of
// prose. See decideAuthorising.
type approvalDecideControl struct {
	Action      string
	CSRFToken   string
	PlanHash    string
	Authorising string
}

// decideAuthorising builds the step-up prompt's object from fields the
// domain already computed, never by parsing Summary further.
func decideAuthorising(operation, summary string) string {
	return "Authorising this " + operation + ": " + summary
}

func handleApproval(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("approval_id")
		caller, ok := principal(w, r)
		if !ok {
			return
		}
		p, ok := page(d, w, r, "Approval "+shortHash(id))
		if !ok {
			return
		}
		p.Banner = banner(d, r)

		// Spec 08's first line: "mobile-first and self-contained — no nav,
		// nothing competing, one card". An approver arrives here from a link,
		// on a phone, mid-something-else. This is the ONLY route that sets it.
		p.Focus = true

		if d.Approvals == nil {
			unavailable(w, "the approval queue")
			return
		}
		req, err := d.Approvals.Approval(r.Context(), id)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			renderScreen(w, p, approvalTmpl, approvalView{ID: id})
			return
		}
		// This card's trail reads — the park record, the anti-fatigue diff,
		// and a Grant's released Jobs — each flatten their failure into a
		// display flag, which is right for a store that failed and wrong for
		// a trail that cannot record. The latch keeps the second case a
		// refusal without restructuring the builders (screen.go).
		d, lane := latched(d)
		v := buildApprovalView(r.Context(), d, caller, req, d.now(), p.CSRFToken)
		if refusedUnaudited(w, lane, "this approval's audit trail") {
			return
		}
		renderScreen(w, p, approvalTmpl, v)
	}
}

// buildApprovalView assembles the card.
//
// NOTE FOR ANYONE OPTIMISING: every QueryAudit below writes a read-audit record
// of its own (ADR-0025, fail-closed), so rendering this card appends rows to the
// trail — TWO for a Plan card (this record's park and the prior one's), and one
// to eight for a Grant card, which walks the dispatch trail for the Jobs the
// Grant released (see releasedJobPages). That is the design working, and it
// matches Job detail. Do not "optimise" the audit away — but do keep the count
// bounded and honest, because each of those reads is also this principal's own
// exposure on the read-egress screen.
func buildApprovalView(ctx context.Context, d Deps, caller capability.Principal, req approval.Request, now time.Time, csrfToken string) approvalView {
	ttl := req.ExpiresAt.Sub(now)
	lapsed := req.State == approval.StatePending && req.PastDeadline(now)
	v := approvalView{
		Found:             true,
		ID:                req.ID,
		Summary:           req.Summary,
		Operation:         approvalOperation(req),
		Risk:              RiskLabel(req.RiskClass),
		PlanHash:          req.PlanHash,
		Requester:         req.RequestedBy,
		Verified:          req.RequestedByID != "",
		State:             approvalState(req, now),
		Pending:           req.State == approval.StatePending && !lapsed,
		Signed:            countApprovals(req),
		Required:          req.Require.Count,
		Audience:          req.Require.Audience,
		AudienceMalformed: req.Require.AudienceMalformed(),
		RequesterAllowed:  req.Require.RequesterAllowed,
		Created:           req.CreatedAt.UTC().Format("2006-01-02 15:04:05Z"),
		Expires:           req.ExpiresAt.UTC().Format("2006-01-02 15:04:05Z"),
		TTL:               renderTTL(ttl),
		Urgent:            ttl > 0 && ttl <= expiryPressure,
		MatchedRules:      req.MatchedRules,
		JobID:             req.JobID,
	}
	v.CallerIsExcludedRequester = approvalStandingFor(req, caller).ExcludedRequester
	if req.JobID != "" {
		v.JobHref = "/console/jobs/" + req.JobID
	}
	for _, dec := range req.Decisions {
		row := decisionRow{
			Account: dec.Account,
			Approve: dec.Approve,
			Reason:  dec.Reason,
			Channel: dec.Channel.String(),
			Human:   dec.DeciderHuman,
			At:      stampOrAbsent(dec.At),
			Ago:     decisionAgo(dec.At, now),
		}
		v.Decisions = append(v.Decisions, row)
		if dec.Approve {
			v.Approvers = append(v.Approvers, row)
		}
		// Both sides non-empty, following approvalStandingFor's stated rule:
		// comparing "" to "" would mark every unattributed Decision as the
		// caller's own.
		if dec.AccountID != "" && caller.AccountID != "" && dec.AccountID == caller.AccountID {
			v.CallerAlreadySigned = true
			v.CallerSignedAt = row.At
		}
	}

	grant, lookup := grantForApproval(ctx, d, req.ID)
	switch lookup {
	case grantFound:
		v.Grant = buildGrantCard(ctx, d, caller, grant)
	case grantIsAPlan:
		// Fetched ONCE and used twice: the action block below and the diff's
		// current-side arguments are the same audit record.
		v.Action = buildApprovalAction(ctx, d, caller, req.ID)
	case grantUnreadable:
		// Neither block. The action block would describe a Plan this Request
		// may well not be.
		v.GrantUnreadable = true
	}
	v.Diff = buildApprovalDiff(ctx, d, caller, req, grant, lookup, v.Action, now)

	v.DecideSeamsUnwired = d.Decide == nil || d.Auth == nil
	v.CallerRoleBelowFloor = !accounts.Role(caller.Role).AtLeast(accounts.RoleOperator)

	// Every one of these is an EXPLANATION of a refusal the domain would make
	// anyway, never the control itself: the POST is refused by the
	// capability layer and the domain regardless of what was drawn here
	// (invariant 10 — an adapter narrows only). Decide is populated only when
	// every one holds, so the absence of a form is never the only thing
	// standing between a caller and a decision.
	if decideOffered(d, accounts.Role(caller.Role)) &&
		v.Pending &&
		!v.CallerIsExcludedRequester &&
		!v.CallerAlreadySigned &&
		!v.Grant.Present &&
		!v.GrantUnreadable &&
		!v.AudienceMalformed {
		v.Decide = &approvalDecideControl{
			Action:      decideApprovalAction(req.ID),
			CSRFToken:   csrfToken,
			PlanHash:    req.PlanHash,
			Authorising: decideAuthorising(v.Operation, v.Summary),
		}
	}
	return v
}

// approvalState renders the state the card colours on.
//
// A pending Request past its deadline reads as EXPIRED even before the sweeper
// retires it: the clock, not the sweeper, is what makes it undecidable, and
// offering "pending" for something nobody can answer is the screen lying about
// what a human can still do.
func approvalState(req approval.Request, now time.Time) string {
	if req.State == approval.StatePending && req.PastDeadline(now) {
		return "expired"
	}
	return req.State.String()
}

// grantLookup is the THREE answers "is this Request a Grant request?" has.
//
// Three rather than two, because the capability layer went out of its way to
// make the distinction available: approval.ErrGrantNotFound travels unwrapped
// precisely so a surface can tell "this is not a Grant" from "the store did not
// answer". Collapsing them would render a standing authorization as a one-off
// Plan — no ceiling, no window, no use limit, and an action block reading
// "arguments — none recorded" — which is the most dangerous sentence this
// screen could produce once v0.7.0 lets someone act on it.
type grantLookup int

const (
	// grantIsAPlan: no Grant cites this Request. Most Requests are this.
	grantIsAPlan grantLookup = iota
	// grantFound: the Request authorizes this Scope.
	grantFound
	// grantUnreadable: the store failed, so this Request MIGHT authorize a
	// Scope and this screen cannot say. It renders as neither.
	grantUnreadable
)

func grantForApproval(ctx context.Context, d Deps, requestID string) (approval.Grant, grantLookup) {
	g, err := d.Approvals.GrantForApproval(ctx, requestID)
	switch {
	case err == nil:
		return g, grantFound
	case errors.Is(err, approval.ErrGrantNotFound):
		return approval.Grant{}, grantIsAPlan
	default:
		return approval.Grant{}, grantUnreadable
	}
}

func buildGrantCard(ctx context.Context, d Deps, caller capability.Principal, g approval.Grant) grantCard {
	ops := append([]string(nil), g.Scope.Operations...)
	sort.Strings(ops)
	namespace := "any namespace"
	if g.LegacyNamespacePin != "" {
		namespace = "retired " + g.LegacyNamespacePin + ": pin — covers nothing"
	}
	c := grantCard{
		Present:            true,
		Account:            g.Scope.Account,
		Risk:               RiskLabel(g.Scope.RiskClass),
		Operations:         ops,
		RawExec:            g.Scope.RawExec,
		Namespace:          namespace,
		LegacyNamespacePin: g.LegacyNamespacePin,
		MaxFanOut:          g.Scope.MaxFanOut,
		Starts:             g.StartsAt.UTC().Format("2006-01-02 15:04:05Z"),
		Expires:            g.ExpiresAt.UTC().Format("2006-01-02 15:04:05Z"),
		MaxUses:            g.MaxUses,
		Progress:           g.Progress(),
		Revoked:            g.Revoked(),
		JobCap:             releasedJobCap,
	}
	if c.Revoked {
		c.RevokedBy = g.RevokedBy
		c.RevokedAt = stampOrAbsent(g.RevokedAt)
		c.RevokeReason = g.RevokeReason
	}

	c.JobsWired = d.Queries != nil
	if c.JobsWired {
		list, complete, err := releasedJobs(ctx, d, caller, g.ID)
		c.Jobs, c.JobsComplete, c.JobsUnreadable = list, complete, err != nil
	}
	return c
}

// releasedJobCap bounds the released-Job list in JOBS; releasedJobPages and
// releasedJobPageSize bound the walk that finds them.
//
// The walk exists because the audit trail fans a dispatch out to ONE RECORD PER
// NODE (auditsink.Sink.Record: "Tasks are the audit unit"). A Grant with 20 uses
// over 200 Nodes produces about 4,000 rows, so a small page might name one Job —
// and a card stating a cap of 50 Jobs beside a list of one would be
// understating by two orders of magnitude while looking complete. There is no
// cheaper path: JobFilter has no GrantID.
//
// THE PAGE SIZE IS THE MAXIMUM ON PURPOSE, and it is a security property rather
// than a performance one. Every QueryAudit writes its own read-audit record
// (ADR-0025, fail-closed) and every one of those lands on the read-egress
// screen as this principal's own exposure. At 50 rows a page, one grant card
// cost twenty appends and inflated that principal's read count twentyfold per
// view — a viewer refreshing the URL was a 20x amplifier on an append-only
// table and on a security screen. At 500 the same 1,000-row trail costs two.
//
// The obvious further "optimisation" — stop as soon as a page contributes no
// new Job — MUST NOT be made: with 500 rows to a page and a wide dispatch, a
// whole page is routinely one Job's Nodes, and stopping there would silently
// drop every later Job. That is exactly the undercount this walk exists to
// avoid.
const (
	releasedJobCap      = 50
	releasedJobPages    = 8
	releasedJobPageSize = capability.MaxPageSize
)

// releasedJobs lists the DISTINCT Jobs a Grant has released, newest first.
//
// complete is true only when the walk reached the end of the matching trail. A
// walk that stopped at either bound renders as "the most recent Jobs, which may
// not be every one" rather than as a complete list.
func releasedJobs(ctx context.Context, d Deps, caller capability.Principal, grantID string) (out []releasedJob, complete bool, err error) {
	seen := map[string]bool{}
	cursor := ""
	for page := 0; page < releasedJobPages; page++ {
		res, queryErr := d.Queries.QueryAudit(ctx, caller, capability.AuditFilter{
			GrantID: grantID,
			Kinds:   []string{audit.KindDispatch},
		}, capability.PageRequest{Limit: releasedJobPageSize, Cursor: cursor})
		if queryErr != nil {
			return nil, false, queryErr
		}
		for _, row := range res.Rows {
			if row.JobID == "" || seen[row.JobID] {
				continue
			}
			seen[row.JobID] = true
			out = append(out, releasedJob{ID: row.JobID, Href: "/console/jobs/" + row.JobID})
			if len(out) >= releasedJobCap {
				return out, false, nil
			}
		}
		cursor = res.Next
		if cursor == "" {
			return out, true, nil
		}
	}
	return out, false, nil
}

// parkRecord reads the record that CREATED one Request: an INDEXED point read
// on approval_id (idx_audit_approval), not a scan.
//
// BOTH creating kinds are named (#546). A Request is created either by a
// dispatch parking (approval_requested) or by a batch/window Grant being asked
// for (approval_grant_requested), and this read is how the approvals screen
// finds the ask behind a pending Request. Naming only the first would have made
// every grant-backed approval report "no park record" — the request would still
// be listed and still be decidable, but the screen would stop being able to say
// who asked or why, which is most of what it is for. That is the failure mode a
// split kind invites, and the one audit's partition machinery cannot catch:
// this filter is a point read, not a classification.
func parkRecord(ctx context.Context, d Deps, caller capability.Principal, approvalID string) (capability.AuditRow, bool, error) {
	trail, err := d.Queries.QueryAudit(ctx, caller, capability.AuditFilter{
		ApprovalID: approvalID,
		Kinds:      []string{audit.KindApprovalRequested, audit.KindApprovalGrantRequested},
	}, capability.PageRequest{Limit: 1})
	if err != nil {
		return capability.AuditRow{}, false, err
	}
	if len(trail.Rows) == 0 {
		return capability.AuditRow{}, false, nil
	}
	return trail.Rows[0], true, nil
}

func buildApprovalAction(ctx context.Context, d Deps, caller capability.Principal, approvalID string) approvalAction {
	a := approvalAction{Wired: d.Queries != nil}
	if !a.Wired {
		return a
	}
	row, found, err := parkRecord(ctx, d, caller, approvalID)
	switch {
	case err != nil:
		a.Unreadable = true
		return a
	case !found:
		a.Missing = true
		return a
	}
	a.Known = row.ActionKind != "" && row.ActionKind != unspecifiedActionKind
	a.Selector = row.Selector
	a.FleetWide = a.Known && row.Selector == ""
	a.Args = argsSummary(row.Args, row.RawExecArgv)
	a.args = row.Args
	return a
}

// unspecifiedActionKind is how the audit trail spells "no Action was recorded".
const unspecifiedActionKind = "unspecified"

// buildApprovalDiff is spec 08's anti-fatigue callout, and the rule it follows
// is that it renders ONLY WHAT IS GENUINELY STORED and NAMES WHAT IT CANNOT
// COMPARE.
//
// A GRANT gets real numbers. HashGrantShape covers the account, the risk
// class, the raw-exec opt-in and the Operations set, and DELIBERATELY EXCLUDES
// the fan-out ceiling, the window and the use limit — so two Grants sharing a
// shape key can differ only in those three, and all three are columns on
// approval_grants. That is exactly the spec's headline sentence. The
// namespace field it hashes is only ever a legacy pin (#482): a Scope has no
// namespace term, so it is empty for every Grant this Console can create and
// carries meaning only for a pre-#482 Grant.
//
// A PLAN gets shape identity plus a scale-argument diff. The shape key already
// guarantees the Operation, its risk class, its shape arguments and the
// normalised Selector are identical, so the card says that as fact; what can
// still differ is the scale arguments (from each park's audit record) and the
// FAN-OUT, which THIS RELAY CANNOT PRODUCE. A park creates no Job at all, so
// there is no Job, no Task and no Results for the record being rendered — only
// for a prior one that already ran. "1,180 -> 2,214" is therefore unavailable,
// and the callout says so in words rather than inferring it from the summary.
func buildApprovalDiff(ctx context.Context, d Deps, caller capability.Principal, req approval.Request, grant approval.Grant, lookup grantLookup, action approvalAction, now time.Time) approvalDiff {
	isGrant := lookup == grantFound
	diff := approvalDiff{Kind: "plan"}
	if isGrant {
		diff.Kind = "grant"
	}

	// Nothing is compared when the Grant lookup failed. Comparing as a Plan
	// would label a Grant's diff with a Plan's vocabulary — and the honest
	// answer is that this screen does not yet know which of the two it is
	// looking at.
	if lookup == grantUnreadable {
		diff.Absence = "This Request may authorize a Scope, and the Grant store could not be read, so nothing is being compared to it."
		return diff
	}

	// Not asked at all rather than asked and refused. The capability layer
	// refuses an empty or legacy shape key anyway, and not asking is the
	// clearer statement of intent: a record whose shape was never computed has
	// no comparable prior BY CONSTRUCTION.
	if req.ShapeKey == "" || approval.IsLegacyShapeKey(req.ShapeKey) {
		diff.Absence = "This record's shape was never computed, so nothing can be compared to it."
		return diff
	}

	prior, err := d.Approvals.LastApprovedOfSameShape(ctx, req)
	if err != nil {
		if errors.Is(err, approval.ErrNotFound) {
			diff.Absence = "Nothing of this shape has been approved on this Relay before."
		} else {
			diff.Absence = "The last approval of this shape could not be read, so this record is not being compared to anything."
		}
		return diff
	}

	diff.Comparable = true
	diff.PriorID = prior.ID
	diff.PriorHref = "/console/approvals/" + prior.ID
	at := approvedAt(prior)
	diff.PriorWhen = stampOrAbsent(at)
	diff.PriorAgo = decisionAgo(at, now)
	for _, dec := range prior.Decisions {
		if dec.Approve && dec.Account != "" {
			diff.PriorApprovers = append(diff.PriorApprovers, dec.Account)
		}
	}
	diff.PlanHashKnown = req.PlanHash != "" && prior.PlanHash != ""
	diff.SamePlanHash = diff.PlanHashKnown && req.PlanHash == prior.PlanHash

	if isGrant {
		priorGrant, err := d.Approvals.GrantForApproval(ctx, prior.ID)
		if err != nil {
			diff.NotComparable = append(diff.NotComparable,
				"the Scope that was approved last time — its Grant is not in this Relay's store")
			return diff
		}
		diff.Changes = grantChanges(priorGrant, grant)
		return diff
	}

	// The fan-out, always, and first: it is the thing the spec's own example
	// sentence compares, and the one number no source here has.
	diff.NotComparable = append(diff.NotComparable, "fan-out")

	priorAction := buildApprovalAction(ctx, d, caller, prior.ID)
	if !action.Wired || !action.Known || !priorAction.Known {
		diff.NotComparable = append(diff.NotComparable,
			"the arguments — the inputs for that comparison are not in the audit trail")
		return diff
	}
	diff.Changes = argChanges(priorAction, action)
	return diff
}

// grantChanges compares two Grants of the SAME SHAPE. By construction they can
// differ only in the three bounds HashGrantShape excludes, and all three are
// stored columns — so this is a real, numeric diff with nothing inferred.
func grantChanges(prior, current approval.Grant) []diffChange {
	var changes []diffChange
	if prior.Scope.MaxFanOut != current.Scope.MaxFanOut {
		changes = append(changes, diffChange{
			Field: "fan-out ceiling",
			From:  strconv.Itoa(prior.Scope.MaxFanOut) + " Nodes",
			To:    strconv.Itoa(current.Scope.MaxFanOut) + " Nodes",
		})
	}
	if priorSpan, span := prior.ExpiresAt.Sub(prior.StartsAt), current.ExpiresAt.Sub(current.StartsAt); priorSpan != span {
		changes = append(changes, diffChange{Field: "window", From: renderSpan(priorSpan), To: renderSpan(span)})
	}
	if prior.MaxUses != current.MaxUses {
		changes = append(changes, diffChange{
			Field: "use limit",
			From:  strconv.Itoa(prior.MaxUses) + " dispatches",
			To:    strconv.Itoa(current.MaxUses) + " dispatches",
		})
	}
	return changes
}

// argChanges diffs the two park records' arguments key by key.
//
// Both records share a shape key, so every SHAPE argument is identical by
// construction and anything this finds is SCALE — "except 1.24.0 -> 1.25.0",
// which is the case the callout exists for. Raw Exec produces nothing here and
// that is correct: every argv element is shape, so two Raw Execs of the same
// shape ran the same argv.
func argChanges(prior, current approvalAction) []diffChange {
	priorArgs, currentArgs := prior.args, current.args
	keys := make([]string, 0, len(priorArgs)+len(currentArgs))
	for k := range priorArgs {
		keys = append(keys, k)
	}
	for k := range currentArgs {
		if _, dup := priorArgs[k]; !dup {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var changes []diffChange
	for _, k := range keys {
		from, was := priorArgs[k]
		to, is := currentArgs[k]
		if was && is && from == to {
			continue
		}
		if !was {
			from = "(absent)"
		}
		if !is {
			to = "(absent)"
		}
		changes = append(changes, diffChange{Field: k, From: from, To: to})
	}
	return changes
}

// approvedAt is when a resolved Request was decided.
func approvedAt(req approval.Request) time.Time {
	if !req.ResolvedAt.IsZero() {
		return req.ResolvedAt
	}
	var at time.Time
	for _, dec := range req.Decisions {
		if dec.Approve && dec.At.After(at) {
			at = dec.At
		}
	}
	return at
}

func stampOrAbsent(t time.Time) string {
	if t.IsZero() {
		return "not recorded"
	}
	return t.UTC().Format("2006-01-02 15:04:05Z")
}

func decisionAgo(t time.Time, now time.Time) string {
	if t.IsZero() {
		return ""
	}
	return timeSince(t, now)
}

// renderSpan renders a window length for a human.
func renderSpan(d time.Duration) string {
	switch {
	case d <= 0:
		return "none"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + "m"
	default:
		return strconv.Itoa(int(d.Hours())) + "h"
	}
}

// approvalOperation names what was parked, from the STRUCTURED fields.
//
// Never parsed out of Summary. The summary is Relay-authored prose a human
// reads; the ActionKind is what the role floor for deciding is computed from,
// and deriving one from the other would make the authorization ladder depend on
// string formatting.
func approvalOperation(req approval.Request) string {
	switch req.ActionKind {
	case jobs.ActionRawExec:
		return "raw_exec"
	case jobs.ActionOperation:
		return "run_operation"
	default:
		return "dispatch"
	}
}

// identicalKey groups pending requests of the same shape (#415, D10).
//
// "" means NOT GROUPABLE, and buildApprovalRows counts such a row alone. A
// record whose shape key is empty or legacy has a shape nobody can recompute,
// and putting all of them in one bucket would tell an approver that a set of
// records with nothing in common are alike — the precise "materially different
// action reads as routine" failure the shape key exists to avoid.
func identicalKey(req approval.Request) string {
	if req.ShapeKey == "" || approval.IsLegacyShapeKey(req.ShapeKey) {
		return ""
	}
	return req.ShapeKey
}

func countApprovals(req approval.Request) int {
	n := 0
	for _, d := range req.Decisions {
		if d.Approve {
			n++
		}
	}
	return n
}

func renderTTL(d time.Duration) string {
	if d <= 0 {
		return "expired"
	}
	if d < time.Minute {
		return strconv.Itoa(int(d.Seconds())) + "s left"
	}
	if d < time.Hour {
		return strconv.Itoa(int(d.Minutes())) + "m left"
	}
	return strconv.Itoa(int(d.Hours())) + "h left"
}

var approvalsTmpl = newScreen("approvals", `
{{if not .Wired}}
<p class="dim">The approval queue is not wired into this Console.</p>
{{else if not .Count}}
<div class="empty">
  <h2>Nothing is waiting.</h2>
  <p>An empty approval queue is good news. When a gate rule parks a dispatch, it appears here with
  the Plan it is asking you to authorise.</p>
</div>
{{else}}
<p class="lede"><b>{{.Count}}</b> {{plural .Count "dispatch is" "dispatches are"}} waiting for a
human. Ordered by <b>nearest expiry</b>, never by arrival — a request that lapses because it sat
below the fold is a failure of this screen. A request that has already lapsed sorts <b>last</b>:
an undecidable row at the top pushes the decidable ones under it.</p>

{{if .GrantsUnreadable}}<p class="note">The Grant store could not be read, so a row that is a Grant
does not carry its Scope line here. Nothing else on this screen is affected.</p>{{end}}

{{with .Filters}}
<div class="kindbar">
{{range .}}<span class="fgroup">{{.Name}}</span>{{range .Options}}<a class="kchip{{if .On}} on{{end}}" href="{{.Href}}">{{.Label}} <b>{{.Count}}</b></a>{{end}}{{if .More}}<span class="dim">and {{.More}} more, not offered as filters</span>{{end}}{{end}}
</div>
{{end}}

{{if .ScopeNotApplied}}
<p class="note"><b>"Waiting on me" was not applied.</b> Nothing in this queue names you, and a
default filter that turns a full queue into "nothing is waiting" is worse than a long list. All
{{.Count}} {{plural .Count "request is" "requests are"}} shown.</p>
{{else if .ScopeMine}}
<p class="note">Showing the {{.Shown}} {{plural .Shown "request" "requests"}} that may be waiting on
you{{if .HiddenByScope}}, and hiding {{.HiddenByScope}} addressed to somebody else{{end}}.
<a href="{{.AllHref}}">Show everything</a>. A request with no named audience is shown rather than
hidden: who may decide is the capability layer's answer, and this screen never second-guesses it.</p>
{{else if .Filtered}}
<p class="note">Showing {{.Shown}} of {{.Count}}. <a href="{{.ClearHref}}">Clear the filters</a>.</p>
{{end}}

{{if not .Rows}}
<div class="empty">
  <h2>Nothing here matches.</h2>
  <p>{{.Count}} {{plural .Count "request is" "requests are"}} waiting; none of them matches these
  filters. <a href="{{.ClearHref}}">Show everything</a>.</p>
</div>
{{else}}
<div class="queue">
{{range .Rows}}
  <a class="qrow{{if .Urgent}} urgent{{end}}{{if .Lapsed}} lapsed{{end}}" href="{{.Href}}">
    <div class="qmain">
      <div class="qhead">
        <span class="chip risk" data-risk="{{.Risk}}">{{.Risk}}</span>
        <code>{{.Operation}}</code>
        {{template "trust-chip" (trust .Requester .Verified)}}
      </div>
      <div class="qsummary">{{.Summary}}</div>
      {{with .ScopeLine}}<div class="qscope">{{.}}</div>{{end}}
      {{with .MatchedRules}}<div class="qrules">parked by <code>{{join ", " .}}</code></div>{{end}}
      {{if .ExcludedRequester}}<div class="qrules">you asked for this one, and the rule that parked it
      does not let a requester sign their own</div>{{end}}
    </div>
    <div class="qside">
      <div class="quorum"><b>{{.Signed}}</b> of {{.Required}} signed</div>
      <div class="qttl">{{.TTL}}</div>
      {{if gt .Identical 1}}<div class="qshape">{{.Identical}} pending of the same shape (group {{.ShapeGroup}})</div>{{end}}
    </div>
  </a>
{{end}}
</div>
{{end}}

<p class="note">There is no Approve control on a row, and there will not be one. A decision is made
on the approval itself, with its Plan in front of you — approving from a list is approving without
seeing what you approved. Deciding arrives with step-up in the administration milestone.</p>
{{end}}
`)

var approvalTmpl = newScreen("approval", `
{{if not .Found}}
<div class="placeholder"><p>No approval request with the id <code>{{.ID}}</code> exists on this
Relay.</p><p><a href="/console/approvals">Back to the queue</a>.</p></div>
{{else}}
<p class="back"><a href="/console/approvals">Approvals</a></p>

<section class="diff">
{{if .Diff.Comparable}}
  <div class="diffhead">Compared with <a href="{{.Diff.PriorHref}}">the last approval of this
  shape</a>, approved {{.Diff.PriorWhen}}{{with .Diff.PriorAgo}} ({{.}}){{end}}{{with .Diff.PriorApprovers}}
  by {{join ", " .}}{{end}}:</div>
  {{if .Diff.Changes}}
    {{range .Diff.Changes}}<p class="diffchange">{{.Field}} {{.From}} → {{.To}}</p>{{end}}
  {{else}}
    <p class="nodiff">Nothing this Relay is able to compare has changed since then.</p>
  {{end}}
  {{if .Diff.PlanHashKnown}}<p class="note">{{if .Diff.SamePlanHash}}Both records carry the same plan
  hash, which means the same action over the same resolved Nodes.{{else}}The two plan hashes differ,
  so something about the scale moved — and this Relay cannot say by how much.{{end}}</p>{{end}}
  {{with .Diff.NotComparable}}<p class="note">Not compared: {{join "; " .}}.</p>{{end}}
  {{if eq .Diff.Kind "plan"}}<p class="note">The resolved fan-out is not stored on the approval
  record, and a park creates <b>no Job at all</b> — so there is no Task and no result anywhere to
  count Nodes from for this record. The count in the sentence below is Relay-authored prose, and
  this screen never reads a number back out of it.</p>{{end}}
{{else}}
  <p class="nodiff">{{.Diff.Absence}}</p>
{{end}}
</section>

<section class="panel">
  <div class="jhrow">
    <span class="chip risk" data-risk="{{.Risk}}">{{.Risk}}</span>
    <code class="jobop">{{.Operation}}</code>
    <span class="chip state" data-state="{{.State}}">{{.State}}</span>
    {{if .Urgent}}<span class="overcap">{{.TTL}}</span>{{else}}<span class="dim">{{.TTL}}</span>{{end}}
  </div>

  <p class="summary">{{.Summary}}</p>
  <p class="note">That sentence is written by the Relay, not by the caller. An agent chose the
  Operation; it did not choose one word a human reads about it.</p>

  <dl class="kv">
    <dt class="baseline">requested by</dt><dd class="baseline">{{template "trust-chip" (trust .Requester .Verified)}}</dd>
    <dt>plan hash</dt><dd><code class="planhash" title="This is what a decision commits to — not the prose above it.">{{.PlanHash}}</code></dd>
    {{with .MatchedRules}}<dt>parked by</dt><dd><code>{{join ", " .}}</code></dd>{{end}}
    <dt>created</dt><dd>{{.Created}}</dd>
    {{with .JobHref}}<dt>job</dt><dd><a href="{{.}}">{{short $.JobID}}</a></dd>{{end}}
  </dl>
</section>

{{if .GrantUnreadable}}
<section class="panel">
  <h3>What was asked for</h3>
  <p class="note">This Relay could not say whether this Request authorizes a <b>Scope</b> — a Grant
  covering many future dispatches — or one Plan: the Grant store did not answer. Neither is shown,
  because the two are not interchangeable and guessing the narrower one is the dangerous direction.
  Reload, or read the Request through the Control API.</p>
</section>
{{else if .Grant.Present}}
<section class="panel">
  <h3>The Scope</h3>
  {{if .Grant.LegacyNamespacePin}}
  <p class="note"><b>This Grant covers nothing.</b> It was stored before namespace pinning was
  removed from a Scope (#482) and carries a retired pin (<code>{{.Grant.LegacyNamespacePin}}</code>).
  Ignoring the pin would widen what it covers, so approving it releases no dispatch; revoke it to
  close it for the record.</p>
  {{else}}
  <p class="note">This Request's subject is a <b>Scope</b> rather than one Plan. Approving it
  pre-approves every dispatch inside these walls until the window closes, so the walls are the whole
  of what is being agreed to.</p>
  {{end}}
  <details class="scope">
    <summary>Expand the Scope</summary>
    <dl class="kv">
      <dt>account</dt><dd>{{.Grant.Account}}</dd>
      <dt>risk class</dt><dd><span class="chip risk" data-risk="{{.Grant.Risk}}">{{.Grant.Risk}}</span></dd>
      <dt>operations</dt><dd>{{if .Grant.Operations}}<code>{{join ", " .Grant.Operations}}</code>{{else}}none{{end}}{{if .Grant.RawExec}} · <b>raw exec is included</b>{{end}}</dd>
      <dt>selector</dt><dd>{{.Grant.Namespace}}</dd>
      <dt>ceiling</dt><dd>at most <b>{{.Grant.MaxFanOut}}</b> Nodes per dispatch</dd>
      <dt>window</dt><dd>{{.Grant.Starts}} until {{.Grant.Expires}}</dd>
      <dt>uses</dt><dd>{{.Grant.MaxUses}} dispatches · {{.Grant.Progress}}</dd>
      {{if .Grant.Revoked}}<dt>revoked</dt><dd>{{.Grant.RevokedAt}} by {{.Grant.RevokedBy}}{{with .Grant.RevokeReason}} — {{.}}{{end}}</dd>{{end}}
    </dl>
    {{if not .Grant.JobsWired}}
    <p class="note">The audit query lane is not wired into this Console, so the Jobs this Grant has
    released cannot be listed here.</p>
    {{else if .Grant.JobsUnreadable}}
    <p class="note">The Jobs this Grant has released could not be read from the audit trail.</p>
    {{else if not .Grant.Jobs}}
    <p class="note">This Grant has released no Jobs yet.</p>
    {{else}}
    <p class="note">Jobs released so far, newest first — at most {{.Grant.JobCap}} are
    listed{{if not .Grant.JobsComplete}}, and this list stopped before the trail did, so it names the
    most recent Jobs rather than every one: the trail records one row per Node, so a wide Grant
    produces thousands of them{{end}}.</p>
    <ul class="joblist">{{range .Grant.Jobs}}<li><a href="{{.Href}}">{{short .ID}}</a></li>{{end}}</ul>
    {{end}}
  </details>
  <p class="note"><b>Approving a Grant requires expanding this Scope at least once.</b> That
  enforcement arrives with the decision controls in the administration milestone; this Console
  cannot decide anything yet, so nothing here is gating on it.</p>
  {{if not .Grant.LegacyNamespacePin}}
  <p class="note">The quorum below was derived at this Scope's <b>widest admissible dispatch</b>:
  count, channel, requester exclusion and decision deadline (TTL) are priced at the strictest any
  covered dispatch would have faced, and the approver audience is the <b>union</b> of those
  dispatches' audiences (a rule with no audience makes the merged audience unrestricted).</p>
  {{end}}
</section>
{{else}}
<section class="panel">
  <h3>What was asked for</h3>
  {{if not .Action.Wired}}
  <p class="note">The audit query lane is not wired into this Console, so the Selector and the
  arguments cannot be shown. They are not missing from the Relay; this screen cannot reach them.</p>
  {{else if .Action.Unreadable}}
  <p class="note">The park's audit record could not be read, so the Selector and the arguments are
  not shown. This is a read failure, not an empty record.</p>
  {{else if .Action.Missing}}
  <p class="note">This Relay's trail carries no <code>approval_requested</code> record for this
  Request. The park's audit write can fail after the Request is already durable, so the Selector and
  the arguments are absent from the trail — <b>which is not the same as there having been
  none</b>.</p>
  {{else}}
  <dl class="kv">
    {{if .Action.Known}}
    <dt>selector</dt>
    <dd>{{if .Action.FleetWide}}<b>every Node</b> (no Selector terms){{else}}<code class="selector">{{.Action.Selector}}</code>{{end}}</dd>
    {{end}}
    <dt>arguments</dt><dd>{{if .Action.Args}}<code>{{.Action.Args}}</code>{{else}}none recorded{{end}}</dd>
  </dl>
  <p class="note">Read from this Request's own park record in the audit trail — the only place
  the Selector as written and the arguments are stored.{{if not .Action.Known}} That record carries
  no Action kind, so the Selector is <b>not</b> shown: an empty stored Selector means either "none
  was recorded" or "no terms, which matches every Node", and this screen will not guess which.{{end}}</p>
  <p class="note">The <b>resolved fan-out is not stored on the approval record</b>. A park creates no
  Job, so there is no Task and no result to count.</p>
  {{end}}
</section>
{{end}}

<section class="panel">
  <h3>Quorum and expiry</h3>
  <dl class="kv">
    <dt>quorum</dt><dd><b>{{.Signed}}</b> of {{.Required}} {{plural .Required "approval" "approvals"}}{{range .Approvers}} · {{.Account}} signed{{with .Ago}} {{.}}{{end}}{{end}}</dd>
    {{if .AudienceMalformed}}<dt>audience</dt><dd><b>malformed</b> — this rule's audience contains a
    blank entry, so <b>no Account may decide it</b>; this request will expire unsigned</dd>
    {{else}}{{with .Audience}}<dt>audience</dt><dd>{{join ", " .}}</dd>{{else}}<dt>audience</dt><dd>unrestricted — the role floor for deciding is enforced by the capability layer, not by this screen</dd>{{end}}{{end}}
    <dt>expires</dt><dd>{{.Expires}} · {{.TTL}}</dd>
  </dl>
  {{if not .RequesterAllowed}}<p class="note">The requester may not sign their own request; a second
  person must.</p>{{end}}
  {{if .CallerIsExcludedRequester}}<p class="note"><b>You are that requester.</b> You can read this
  card, and the rule that parked it means somebody else has to answer it. Nothing is hidden from you
  here — the exclusion is stated rather than made to look like an absence.</p>{{end}}
</section>

{{if .Decisions}}
<section class="panel">
  <h3>Decisions</h3>
  <table class="rows">
    <thead><tr><th scope="col">Account</th><th scope="col">Answer</th><th scope="col">When</th><th scope="col">Channel</th><th scope="col">Note</th></tr></thead>
    <tbody>
    {{range .Decisions}}
      <tr>
        <td>{{template "trust-chip" (trust .Account true)}}{{if not .Human}}<span class="dim">machine</span>{{end}}</td>
        <td><span class="chip state" data-state="{{if .Approve}}approved{{else}}denied{{end}}">{{if .Approve}}approved{{else}}denied{{end}}</span></td>
        <td>{{.At}}{{with .Ago}} <span class="dim">({{.}})</span>{{end}}</td>
        <td><code>{{.Channel}}</code></td>
        <td>{{.Reason}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  <p class="note">The channel is recorded rather than assumed. A decision that arrived over a
  credential the requesting session does not hold is evidence; one that arrived in-band is a
  delivery convenience, and the difference is the whole security property.</p>
</section>
{{end}}

{{with .Decide}}
<form method="post" action="{{.Action}}" class="decideform">
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  <input type="hidden" name="plan_hash" value="{{.PlanHash}}">
  <label for="decide-reason">Reason (optional) — the only part of the record that says why</label>
  <textarea id="decide-reason" name="reason" rows="2"></textarea>
  <label for="decide-password">{{.Authorising}}</label>
  <input id="decide-password" name="password" type="password" autocomplete="current-password" required>
  <div class="decideanswers">
    <button type="submit" name="answer" value="approve" class="decideanswer">Approve</button>
    <button type="submit" name="answer" value="deny" class="decideanswer">Deny</button>
  </div>
</form>
{{else}}
  {{if .Pending}}
    {{if .CallerIsExcludedRequester}}
    <p class="gap"><b>You cannot decide this one.</b> You are the requester this rule excludes — see
    above for why. A second, distinct Account has to answer. Answer through the Control API's
    decision endpoint if a different Account needs to.</p>
    {{else if .CallerAlreadySigned}}
    <p class="gap"><b>You already signed this at {{.CallerSignedAt}}.</b> A second, distinct approver
    is needed to complete this request's quorum — deciding again would not be that second signature.
    A different Account can still answer, here or through the Control API.</p>
    {{else if or .Grant.Present .GrantUnreadable}}
    <p class="gap"><b>This Console does not decide a Grant.</b> {{if .GrantUnreadable}}The Grant store
    could not be read, so this Console cannot tell whether this Request authorizes a Scope or a single
    Plan, and will not decide either while that is unknown.{{else}}This Request authorizes a Scope, not
    one Plan, and spec 08 requires a Grant's Scope to have been expanded at least once before it is
    approved — this Console does not enforce that yet.{{end}} Answer it through the Control API.</p>
    {{else if .DecideSeamsUnwired}}
    <p class="gap"><b>Deciding is not wired into this Relay's Console.</b> Answer through the Control
    API's decision endpoint instead — the same code path, and the one that always decides.</p>
    {{else if .CallerRoleBelowFloor}}
    <p class="gap"><b>Your role cannot decide this.</b> Deciding requires the operator role or above.
    Answer through the Control API if your Account holds it.</p>
    {{else}}
    <p class="gap"><b>Deciding is not offered to you on this Request.</b> Answer through the Control
    API's decision endpoint instead — the same code path, and the one that always decides.</p>
    {{end}}
  {{else if eq .State "expired"}}
  <p class="gap"><b>The TTL lapsed at {{.Expires}}.</b> The dispatch was never released and this
  request can no longer be answered. The requester has to ask again, which creates a new Request with
  its own plan hash — an approval is a decision about a moment, not a standing permission.</p>
  {{else}}
  <p class="gap"><b>This request was {{.State}}.</b> The decisions above name who answered, over which
  channel, and when. Approvals are not re-openable: a late answer cannot revive a resolved Request.</p>
  {{end}}
{{end}}
{{end}}
`)
