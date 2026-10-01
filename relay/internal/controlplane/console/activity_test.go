package console

// activity_test.go is spec 04's acceptance criteria and the properties the
// migration onto the capability layer's read lane (#441) had to preserve.
//
// It has its own file rather than a corner of screens_test.go because the
// screen now reads TWO lanes and every interesting assertion is about which
// lane ran, what filter reached it, and what the page said about the boundary
// between them.

import (
	"context"
	"encoding/csv"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/events"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// activityDeps is renderableDeps with a query lane the test controls.
func activityDeps(q *fakeQueries) Deps {
	d := renderableDeps()
	d.Queries = q
	return d
}

// TestActivity_FourThousandNodeJobIsOneRow is spec 04's first acceptance
// criterion and the screen's grain rule.
//
// The collapse happens in SQL, not here: one aggregate row per Job carrying an
// EXACT per-outcome tally. So the assertion is not only "one row" — it is that
// no Task was materialised to produce it, which is what makes the screen cost
// the same at 4,000 Nodes as at three.
func TestActivity_FourThousandNodeJobIsOneRow(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{{
		JobID:         "job-1",
		CreatedAt:     testNow,
		OperationName: "service.restart",
		RiskClass:     jobs.RiskClassMutate,
		Selector:      "role=web",
		Requester:     "gleipnir",
		Total:         4000,
		Counts:        map[jobs.Outcome]int{jobs.OutcomeSuccess: 3986, jobs.OutcomeDeniedByPolicy: 14},
	}}}

	body := get(t, newTestHandler(activityDeps(q), accounts.RoleAdmin), "/console/activity?kind=dispatch").Body.String()

	if n := strings.Count(body, `<article class="ev"`); n != 1 {
		t.Errorf("a 4,000-Node Job rendered %d rows, want exactly 1", n)
	}
	if !strings.Contains(body, "4000 Nodes") {
		t.Error("the Job row does not report its fan-out")
	}
	if len(q.taskLimits) != 0 {
		t.Errorf("the screen materialised Tasks (%v) — the tally comes from the aggregate, "+
			"and a Job list that fetches Tasks is not bounded at 4,000 Nodes", q.taskLimits)
	}

	// The 14 denies must clear the minority floor: 0.35% of the bar is the
	// entire reason anyone opened the page.
	bar := barFrom(map[jobs.Outcome]int{jobs.OutcomeSuccess: 3986, jobs.OutcomeDeniedByPolicy: 14})
	if bar.Total != 4000 {
		t.Errorf("the outcome bar totals %d, want 4000", bar.Total)
	}
	var denied *Segment
	for i := range bar.Segments {
		if bar.Segments[i].Outcome == jobs.OutcomeDeniedByPolicy {
			denied = &bar.Segments[i]
		}
	}
	if denied == nil {
		t.Fatal("the 14 denies did not appear in the outcome bar")
	}
	if denied.Width < minSegmentPercent {
		t.Errorf("the deny segment is %.2f%% wide, below the %.1f%% floor", denied.Width, minSegmentPercent)
	}
}

// TestActivity_DispatchFilterIsTheJobsListAndQueriesNothingElse is decision D6
// made STRUCTURAL. "This screen filtered to dispatch is the Jobs list" is
// asserted as a call count, not as a claim about what rendered: with that
// filter the audit lane is not queried at all.
func TestActivity_DispatchFilterIsTheJobsListAndQueriesNothingElse(t *testing.T) {
	q := &fakeQueries{}
	get(t, newTestHandler(activityDeps(q), accounts.RoleAdmin), "/console/activity?kind=dispatch")

	// The Jobs list's one read, and Running now's.
	if q.jobCalls != 2 {
		t.Errorf("?kind=dispatch made %d Job queries, want exactly 2 (the list and Running now)", q.jobCalls)
	} else if isRunningNowRead(q.jobFilters[0]) || !isRunningNowRead(q.jobFilters[1]) {
		t.Errorf("?kind=dispatch's Job reads are not [the list, Running now]: %+v", q.jobFilters)
	}
	if q.auditCalls != 0 {
		t.Errorf("?kind=dispatch queried the audit lane %d times — the Jobs list must not read the "+
			"trail, because a dispatch record is per-Node and 4,000 of them are one row", q.auditCalls)
	}

	// And the unfiltered feed runs both.
	both := &fakeQueries{}
	get(t, newTestHandler(activityDeps(both), accounts.RoleAdmin), "/console/activity")
	if both.jobCalls != 2 || both.auditCalls != 1 {
		t.Errorf("the unfiltered feed made %d Job and %d audit queries, want 2 (the stream's and Running now's) and 1",
			both.jobCalls, both.auditCalls)
	} else if isRunningNowRead(both.jobFilters[0]) || !isRunningNowRead(both.jobFilters[1]) {
		t.Errorf("the unfiltered feed's Job reads are not [the stream, Running now]: %+v", both.jobFilters)
	}
}

// TestActivity_FiltersReachTheSeamRatherThanThePage is the regression this
// screen's whole migration exists to prevent.
//
// A filter applied in Go after an unfiltered page comes back renders three
// rows and an "older" link, and an operator reads that as "three things
// happened". Every filter except the explicitly page-local `q` must land on
// BOTH filters, in the query.
func TestActivity_FiltersReachTheSeamRatherThanThePage(t *testing.T) {
	q := &fakeQueries{}
	since := "2026-08-20T00:00:00Z"
	until := "2026-08-26T00:00:00Z"
	get(t, newTestHandler(activityDeps(q), accounts.RoleAdmin),
		"/console/activity?account=acc-1&op=service.restart&on_behalf_of=agent-7&since="+since+"&until="+until)

	if len(q.jobFilters) != 2 || len(q.auditFilters) != 1 {
		t.Fatalf("got %d Job and %d audit filters, want the stream's and Running now's, and 1", len(q.jobFilters), len(q.auditFilters))
	}
	if !isRunningNowRead(q.jobFilters[1]) || q.jobFilters[1].RequesterAccountID != "acc-1" {
		t.Errorf("the second Job read is not Running now's, scoped to the Account alone: %+v", q.jobFilters[1])
	}
	jf, af := q.jobFilters[0], q.auditFilters[0]

	if jf.RequesterAccountID != "acc-1" || af.AccountID != "acc-1" {
		t.Errorf("account= did not reach both seams: job=%q audit=%q", jf.RequesterAccountID, af.AccountID)
	}
	if jf.OnBehalfOf != "agent-7" || af.OnBehalfOf != "agent-7" {
		t.Errorf("on_behalf_of= did not reach both seams: job=%q audit=%q", jf.OnBehalfOf, af.OnBehalfOf)
	}
	if jf.Operation != "service.restart" || len(af.Operations) != 1 || af.Operations[0] != "service.restart" {
		t.Errorf("op= did not reach both seams: job=%q audit=%v", jf.Operation, af.Operations)
	}
	wantSince, _ := time.Parse(time.RFC3339, since)
	wantUntil, _ := time.Parse(time.RFC3339, until)
	if !jf.Since.Equal(wantSince) || !af.Since.Equal(wantSince) {
		t.Errorf("since= did not reach both seams: job=%v audit=%v", jf.Since, af.Since)
	}
	if !jf.Until.Equal(wantUntil) || !af.Until.Equal(wantUntil) {
		t.Errorf("until= did not reach both seams: job=%v audit=%v", jf.Until, af.Until)
	}
}

// TestActivity_AuditorAnswersAllFourFromOneRow is spec 04's second acceptance
// criterion: "who asked, for whom, who approved, what happened", with the
// verified/asserted distinction visible WITHOUT HOVERING.
//
// Two chips, never one. The Relay authenticated the requester; the caller
// merely CLAIMED the on-behalf-of, and a jailbroken AI-agent can claim anything —
// the whole point of the grammar is that its claim cannot be made to look like
// something the Relay checked.
func TestActivity_AuditorAnswersAllFourFromOneRow(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{{
		JobID:              "job-1",
		CreatedAt:          testNow,
		OperationName:      "service.restart",
		RiskClass:          jobs.RiskClassMutate,
		Requester:          "gleipnir",
		RequesterAccountID: "acct-1",
		OnBehalfOf:         "agent-7",
		ApprovalID:         "appr-9",
		Total:              3,
		Counts:             map[jobs.Outcome]int{jobs.OutcomeSuccess: 3},
	}}}

	body := get(t, newTestHandler(activityDeps(q), accounts.RoleAdmin), "/console/activity?kind=dispatch").Body.String()

	if !strings.Contains(body, `data-trust="verified" title="The Relay authenticated this identity.">gleipnir<`) {
		t.Error("the requester is not rendered as a VERIFIED chip")
	}
	if !strings.Contains(body, `data-trust="asserted" title="The caller claimed this. Nothing checked it.">agent-7<`) {
		t.Error("the on-behalf-of is not rendered as a SEPARATE, asserted chip — merging the two " +
			"lanes, or passing verified for the asserted one, is how an audit trail becomes fiction")
	}
	if !strings.Contains(body, `href="/console/approvals/appr-9"`) {
		t.Error("the row does not link to the approval that released it")
	}
	if !strings.Contains(body, "service.restart") {
		t.Error("the row does not say what happened")
	}
}

// TestActivity_EveryAuditKindIsClassified. Every audit kind is exactly one of:
// an Access kind (Access's, never this screen's), a kind in activityNonCallKinds
// (on the trail, deliberately not drawn here), or a tool-call kind whose family
// is in rowKindOrder. A kind added to internal/audit and classified in none of
// them fails here, so it is neither silently hidden nor silently shown.
func TestActivity_EveryAuditKindIsClassified(t *testing.T) {
	excluded := map[string]bool{}
	for _, k := range activityLaneExcluded {
		excluded[k] = true
	}
	requested := map[string]bool{}
	for _, k := range activityTrailKinds {
		if excluded[k] {
			t.Errorf("%q is in BOTH activityTrailKinds and activityLaneExcluded", k)
		}
		requested[k] = true
	}
	nonCall := map[string]bool{}
	for _, k := range activityNonCallKinds {
		nonCall[k] = true
		if _, ok := accessKindOf(k); ok {
			t.Errorf("%q is in activityNonCallKinds and is an Access kind", k)
		}
	}

	for _, k := range audit.Kinds() {
		if _, ok := accessKindOf(k); ok {
			// An Access kind is neither requested nor excluded BY THIS
			// SCREEN: it is not this screen's vocabulary at all, and it must
			// not be reachable through any of its chips — see the inverse
			// sweep below.
			if requested[k] || excluded[k] || nonCall[k] {
				t.Errorf("Access kind %q is also classified on Activity — the two screens must "+
					"partition the audit vocabulary, not share a kind", k)
			}
			continue
		}
		if nonCall[k] {
			if got := kindOf(k); got != rowNotACall {
				t.Errorf("non-call kind %q maps to family %q, want rowNotACall", k, got)
			}
			if requested[k] || excluded[k] {
				t.Errorf("non-call kind %q is also requested or excluded by the default feed", k)
			}
			continue
		}
		family := kindOf(k)
		if !slices.Contains(rowKindOrder, family) {
			t.Errorf("audit kind %q is classified nowhere (family %q): classify it: a tool-call family, "+
				"or activityNonCallKinds", k, family)
			continue
		}
		if !requested[k] && !excluded[k] {
			t.Errorf("audit kind %q is neither requested by the default feed nor excluded from it "+
				"with a reason — it would simply never appear on the trail", k)
		}
		// And it is reachable through its family's chip.
		if !containsString(kindsOfFamily(family), k) {
			t.Errorf("audit kind %q maps to family %q, whose kind list does not contain it — the "+
				"chip would not show it", k, family)
		}
	}

	// The inverse: no Activity family's chip may reach an Access kind.
	// rowAccess not being in rowKindOrder guarantees this structurally;
	// this pins it by name rather than by construction alone.
	for _, family := range rowKindOrder {
		for _, k := range kindsOfFamily(family) {
			if _, ok := accessKindOf(k); ok {
				t.Errorf("Activity family %q's chip reaches Access kind %q", family, k)
			}
		}
	}
}

// TestActivity_KindsOfFamilyIsTotalAndNeverEmpty is R4, and it is the one that
// FAILS OPEN if it is missing.
//
// capability.AuditFilter's contract is that the ZERO VALUE MATCHES EVERY ROW,
// so an empty Kinds slice means ALL KINDS. A family whose kind list came back
// empty would therefore render the ENTIRE TRAIL under that family's heading —
// a filter that silently widens, which is the one direction a filter must
// never fail.
func TestActivity_KindsOfFamilyIsTotalAndNeverEmpty(t *testing.T) {
	for _, family := range rowKindOrder {
		got := kindsOfFamily(family)
		if len(got) == 0 {
			t.Errorf("kindsOfFamily(%q) is empty — an empty Kinds slice matches EVERY audit kind, "+
				"so ?kind=%s would render the whole trail", family, family)
		}
	}

	// plan and job_cancel are families of their own (spec 04, Row kinds).
	if got := kindOf(audit.KindPlan); got != rowPlan {
		t.Errorf("kindOf(plan) = %q, want %q", got, rowPlan)
	}
	if got := kindOf(audit.KindJobCancel); got != rowCancel {
		t.Errorf("kindOf(job_cancel) = %q, want %q", got, rowCancel)
	}
	// A kind no family claims, and a Node's protocol_violation, are not drawn.
	for _, k := range []string{audit.KindProtocolViolation, "no-such-kind"} {
		if got := kindOf(k); got != rowNotACall {
			t.Errorf("kindOf(%q) = %q, want rowNotACall", k, got)
		}
	}

	// A family with no audit kind at all still narrows to nothing. There is
	// no such family today; the sentinel is what keeps that from mattering.
	if got := kindsOfFamily(rowKind("no-such-family")); len(got) != 1 || got[0] != noSuchAuditKind {
		t.Errorf("kindsOfFamily on an unknown family = %v, want the match-nothing sentinel", got)
	}
}

// TestActivity_AccessFamiliesAreNotKinds pins the seam D17 split the audit
// vocabulary at: kindOf sends every one of Access's 15 kinds to rowAccess,
// which is deliberately absent from rowKindOrder and from
// activityTrailKinds.
func TestActivity_AccessFamiliesAreNotKinds(t *testing.T) {
	n := 0
	for _, k := range audit.Kinds() {
		if _, ok := accessKindOf(k); !ok {
			continue
		}
		n++
		if got := kindOf(k); got != rowAccess {
			t.Errorf("kindOf(%q) = %q, want rowAccess", k, got)
		}
		if containsString(activityTrailKinds, k) {
			t.Errorf("activityTrailKinds contains Access kind %q", k)
		}
	}
	if n != 15 {
		t.Fatalf("the loop classified %d Access kinds, want exactly 15 — the assertions above proved "+
			"nothing about the rest of the vocabulary", n)
	}

	for _, family := range rowKindOrder {
		if family == rowAccess {
			t.Error("rowKindOrder contains rowAccess — it must never be a selectable chip")
		}
		if family == rowNotACall {
			t.Error("rowKindOrder contains rowNotACall — it must never be a selectable chip")
		}
	}
}

// TestActivity_FleetEventsAreNotFamilies: Activity lists tool calls only (spec
// 04, Grain). Freeze transitions, Node revokes, Enrollment Token events and
// protocol_violation stay on the trail, are never requested, and ?kind= cannot
// reach them.
func TestActivity_FleetEventsAreNotFamilies(t *testing.T) {
	want := []rowKind{rowDispatch, rowPlan, rowApproval, rowRefusal, rowRead, rowCancel}
	if !slices.Equal(rowKindOrder, want) {
		t.Errorf("rowKindOrder = %v, want exactly %v", rowKindOrder, want)
	}
	for _, k := range activityNonCallKinds {
		if got := kindOf(k); got != rowNotACall {
			t.Errorf("kindOf(%q) = %q, want rowNotACall", k, got)
		}
		if containsString(activityTrailKinds, k) {
			t.Errorf("activityTrailKinds requests the non-call kind %q", k)
		}
	}
	for _, kind := range []string{"freeze", "node", "token", "other"} {
		q := &fakeQueries{}
		body := get(t, newTestHandler(activityDeps(q), accounts.RoleAdmin), "/console/activity?kind="+kind).Body.String()
		if !strings.Contains(body, "There is no row kind called") {
			t.Errorf("?kind=%s is not refused as an unknown row kind", kind)
		}
		if q.auditCalls != 0 || q.jobCalls != 0 {
			t.Errorf("?kind=%s queried the trail (%d) or the Jobs (%d)", kind, q.auditCalls, q.jobCalls)
		}
	}
}

// TestActivity_ShowsNoAccessRowForAnyRole is spec 04's "No sign-in, step-up,
// Account or API Token row appears here, for any role" acceptance line,
// store-backed against the same 15-kind trail access_test.go seeds, plus a
// fakeQueries variant proving the seam itself narrows to nothing rather than
// merely that nothing renders.
func TestActivity_ShowsNoAccessRowForAnyRole(t *testing.T) {
	d, sink, st, actor := accessStoreDeps(t)
	seedAccessTrail(t, sink, st, actor)

	paths := []string{
		"/console/activity", "/console/activity?kind=auth", "/console/activity?kind=account",
		"/console/activity?kind=api-token", "/console/activity?kind=sign-in", "/console/activity?kind=step-up",
		"/console/activity?kind=access",
	}
	for _, role := range sessionRoles {
		h := newTestHandler(d, role)
		for _, path := range paths {
			body := get(t, h, path).Body.String()
			for _, k := range accessAllKinds {
				if strings.Contains(body, `<span class="evkind">`+k+`<`) {
					t.Errorf("role=%s %s renders Access kind %q", role, path, k)
				}
			}
			for _, label := range []string{"auth", "account", "api-token", "sign-in", "step-up"} {
				if strings.Contains(body, `class="kchip on">`+label+`<`) {
					t.Errorf("role=%s %s draws a current chip labelled %q", role, path, label)
				}
			}
		}
	}

	fq := &fakeQueries{}
	h := newTestHandler(activityDeps(fq), accounts.RoleAdmin)
	for _, path := range paths {
		get(t, h, path)
	}
	for _, f := range fq.auditFilters {
		for _, k := range f.Kinds {
			if _, ok := accessKindOf(k); ok {
				t.Errorf("an Activity request sent Access kind %q to the audit lane", k)
			}
		}
	}
}

// TestActivity_UnknownKindQueriesNothing. An unrecognised filter must narrow to
// nothing, never fall back to everything: a filter that quietly widens is how
// an auditor comes to read the whole trail believing it is one slice of it.
func TestActivity_UnknownKindQueriesNothing(t *testing.T) {
	q := &fakeQueries{
		jobs: []capability.JobSummary{{JobID: "job-1", CreatedAt: testNow}},
		rows: []capability.AuditRow{{Kind: audit.KindRefusal, Timestamp: testNow}},
	}
	body := get(t, newTestHandler(activityDeps(q), accounts.RoleAdmin), "/console/activity?kind=everything").Body.String()

	if q.jobCalls != 0 || q.auditCalls != 0 {
		t.Errorf("an unrecognised kind ran %d Job and %d audit queries, want 0 of each",
			q.jobCalls, q.auditCalls)
	}
	if !strings.Contains(body, "There is no row kind called") {
		t.Error("the screen does not say the kind was not recognised")
	}
	if strings.Contains(body, `<article class="ev"`) {
		t.Error("an unrecognised kind rendered rows — the filter fell back to everything")
	}
}

// TestActivity_DefaultFeedOmitsTheTrailsOwnReads. Reading the trail WRITES to
// it, so a default feed that included read records would fill with the
// operator's own refreshes. One click away, never hidden.
func TestActivity_DefaultFeedOmitsTheTrailsOwnReads(t *testing.T) {
	q := &fakeQueries{rows: []capability.AuditRow{
		{Kind: audit.KindRead, OperationName: "list_nodes", Timestamp: testNow},
	}}
	h := newTestHandler(activityDeps(q), accounts.RoleAdmin)

	body := get(t, h, "/console/activity").Body.String()
	if containsString(q.auditFilters[0].Kinds, audit.KindRead) {
		t.Error("the default feed asks the trail for its own read records")
	}
	if strings.Contains(body, "enumerated list_nodes") {
		t.Error("the default feed rendered a read record")
	}
	if !strings.Contains(body, `href="/console/activity?kind=read"`) {
		t.Error("the screen does not link to the read records it left out — omitting them silently " +
			"is hiding them")
	}

	one := &fakeQueries{rows: q.rows}
	filtered := get(t, newTestHandler(activityDeps(one), accounts.RoleAdmin), "/console/activity?kind=read").Body.String()
	if !strings.Contains(filtered, "enumerated list_nodes") {
		t.Error("?kind=read does not render the trail's read records")
	}
}

// TestActivity_ReadRowCarriesNoOutputAtAnyAge is spec 04's fifth acceptance
// criterion, in two halves: the row struct has nowhere to put output, and a
// read-class Job says so on the page.
func TestActivity_ReadRowCarriesNoOutputAtAnyAge(t *testing.T) {
	assertNoOutputField(t, "console.activityRow", activityRow{})

	q := &fakeQueries{jobs: []capability.JobSummary{{
		JobID: "job-1", CreatedAt: testNow,
		// A name this package's own read list has NEVER heard of. The class
		// is the DECLARED one from tasks.risk_class, so the chip must still
		// say "read" — an inference by name would call this a mutate.
		OperationName: "acme.inventory.dump",
		RiskClass:     jobs.RiskClassRead,
		Total:         1,
		Counts:        map[jobs.Outcome]int{jobs.OutcomeSuccess: 1},
	}}}
	body := get(t, newTestHandler(activityDeps(q), accounts.RoleAdmin), "/console/activity?kind=dispatch").Body.String()

	if !strings.Contains(body, `data-risk="read"`) {
		t.Error("a read-class Job did not render the read chip — the class must come from " +
			"sum.RiskClass, never from inferring it by Operation name")
	}
	if !strings.Contains(body, "Output was not retained") {
		t.Error("a read row does not say its output was never kept")
	}
}

// assertNoOutputField is ADR-0025 as a structural property: a row type with a
// field for output is a row type someone will fill.
func assertNoOutputField(t *testing.T, name string, v any) {
	t.Helper()
	rt := reflect.TypeOf(v)
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		switch f.Name {
		case "Stdout", "Stderr", "Output", "Truncated":
			t.Errorf("%s has a %s field — no screen may retain read output (ADR-0025)", name, f.Name)
		}
		if f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.Uint8 {
			t.Errorf("%s.%s is a []byte — the only bytes a Task produces are its output", name, f.Name)
		}
	}
}

// TestActivity_InFlightJobSaysAttributionIsNotYetRecorded. The Job engine
// publishes the completion BEFORE it writes the audit record, so a Job can be
// on this screen with no requester yet.
//
// Spec 04 says a row the Relay cannot attribute must not appear as a blank.
// "unattributed" is also wrong — it claims the Relay looked and found nobody.
func TestActivity_InFlightJobSaysAttributionIsNotYetRecorded(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{{
		JobID: "job-1", CreatedAt: testNow, OperationName: "service.restart",
		Total: 3, Unresolved: 3,
	}}}
	body := get(t, newTestHandler(activityDeps(q), accounts.RoleAdmin), "/console/activity?kind=dispatch").Body.String()

	if !strings.Contains(body, "attribution is recorded when the dispatch completes") {
		t.Error("an unattributed in-flight Job does not say why it has no requester")
	}
	if strings.Contains(body, "unattributed") {
		t.Error("an in-flight Job renders the word \"unattributed\" — the Relay has not looked yet")
	}
	if !strings.Contains(body, "0 of 3 Tasks resolved") {
		t.Error("the row does not report how many Tasks have not resolved")
	}
}

// TestActivity_OlderLinkCarriesBothLaneCursors. The two lanes page
// independently, so dropping one cursor because that lane happened to end
// would silently restart it at page one — and the operator would read the same
// rows again believing they were older ones.
func TestActivity_OlderLinkCarriesBothLaneCursors(t *testing.T) {
	q := &fakeQueries{jobNext: "jc-2", auditNext: "ac-2"}
	h := newTestHandler(activityDeps(q), accounts.RoleAdmin)

	body := get(t, h, "/console/activity").Body.String()
	older := hrefContaining(t, body, "jc=jc-2")
	if !strings.Contains(older, "ac=ac-2") {
		t.Fatalf("the older link is %q — it must carry BOTH lanes' cursors", older)
	}

	// And following it passes both through as PageRequest.Cursor.
	follow := &fakeQueries{}
	get(t, newTestHandler(activityDeps(follow), accounts.RoleAdmin), unescapeHref(t, older))
	if len(follow.jobPages) != 1 || follow.jobPages[0].Cursor != "jc-2" {
		t.Errorf("the Job lane resumed from %+v, want cursor jc-2", follow.jobPages)
	}
	if len(follow.auditPages) != 1 || follow.auditPages[0].Cursor != "ac-2" {
		t.Errorf("the audit lane resumed from %+v, want cursor ac-2", follow.auditPages)
	}
}

// TestActivity_PageStatesItsTwoLaneBoundary. The merge is never truncated, so
// the page cannot claim to be an instant — and it must say so rather than let
// an operator infer it.
func TestActivity_PageStatesItsTwoLaneBoundary(t *testing.T) {
	both := get(t, newTestHandler(activityDeps(&fakeQueries{}), accounts.RoleAdmin), "/console/activity").Body.String()
	if !strings.Contains(both, "a page does not end at a single moment") {
		t.Error("the two-lane feed does not state that its page boundary is not an instant")
	}

	one := get(t, newTestHandler(activityDeps(&fakeQueries{}), accounts.RoleAdmin), "/console/activity?kind=dispatch").Body.String()
	if !strings.Contains(one, "a page ends at a single moment") {
		t.Error("a single-lane filter does not say its page boundary IS an instant")
	}
}

// TestActivity_OutcomeOnTheJobLaneSaysWhatItCosts is R8, decided and stated
// rather than left to be discovered: the Job query has no outcome column, so
// the filter is applied to the fetched page while the cursor comes from the
// unfiltered one.
func TestActivity_OutcomeOnTheJobLaneSaysWhatItCosts(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{
		// Both are finished, so Complete: the zero State is Running (iota 0),
		// and a running Job is in Running now whatever the outcome filter says.
		{JobID: "job-denied", CreatedAt: testNow, OperationName: "service.restart", State: jobs.JobStateComplete,
			Counts: map[jobs.Outcome]int{jobs.OutcomeDeniedByPolicy: 1, jobs.OutcomeSuccess: 9}, Total: 10},
		{JobID: "job-clean", CreatedAt: testNow, OperationName: "service.restart", State: jobs.JobStateComplete,
			Counts: map[jobs.Outcome]int{jobs.OutcomeSuccess: 10}, Total: 10},
	}}
	body := get(t, newTestHandler(activityDeps(q), accounts.RoleAdmin),
		"/console/activity?kind=dispatch&outcome=denied_by_policy").Body.String()

	if !strings.Contains(body, "job-denied") {
		t.Error("the Job that produced a deny was filtered out")
	}
	if strings.Contains(body, "job-clean") {
		t.Error("a Job with no deny survived ?outcome=denied_by_policy")
	}
	if !strings.Contains(body, "Outcome narrows dispatch rows after the page is fetched") {
		t.Error("the page does not say that the dispatch outcome filter is applied after the fetch — " +
			"an operator would read a short page as 'this is everything'")
	}

	// The trail lane, by contrast, filters in the QUERY.
	trail := &fakeQueries{}
	get(t, newTestHandler(activityDeps(trail), accounts.RoleAdmin),
		"/console/activity?kind=refusal&outcome=denied_by_policy")
	if len(trail.auditFilters) != 1 || trail.auditFilters[0].Outcome == nil ||
		*trail.auditFilters[0].Outcome != jobs.OutcomeDeniedByPolicy {
		t.Errorf("outcome= did not reach the audit filter: %+v", trail.auditFilters)
	}
}

// TestActivity_UnreadableAndUnwiredLanesRefuseRatherThanRenderingEmpty. An
// empty feed reads as "nothing has happened", which is a claim about the fleet
// made because a seam was missing or broken.
func TestActivity_UnreadableAndUnwiredLanesRefuseRatherThanRenderingEmpty(t *testing.T) {
	d := renderableDeps()
	d.Queries = nil
	rec := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/activity")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("Activity with no query lane wired = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not an empty fleet") {
		t.Error("the refusal does not distinguish a wiring problem from an empty trail")
	}

	broken := get(t, newTestHandler(activityDeps(&fakeQueries{jobsErr: constErr("store down")}), accounts.RoleAdmin),
		"/console/activity")
	if broken.Code != http.StatusInternalServerError {
		t.Errorf("Activity with a failing query lane = %d, want 500", broken.Code)
	}
	if !strings.Contains(broken.Body.String(), "not a configuration problem") {
		t.Error("a runtime query failure is reported as a wiring problem")
	}
}

// TestActivity_LiveRegionOnlyWhereTheViewRendersDispatchRows. A screen with no
// live kind in its filter must not mount a script that sits there queueing
// events the view would never show.
func TestActivity_LiveRegionOnlyWhereTheViewRendersDispatchRows(t *testing.T) {
	d := activityDeps(&fakeQueries{})
	d.Events = newFakeEvents()
	h := newTestHandler(d, accounts.RoleAdmin)

	for _, path := range []string{"/console/activity", "/console/activity?kind=dispatch"} {
		body := get(t, h, path).Body.String()
		if !strings.Contains(body, "data-live-region") {
			t.Errorf("%s renders no live region", path)
		}
		if !strings.Contains(body, `src="/console/assets/stream.js"`) ||
			!strings.Contains(body, `src="/console/assets/activity.js"`) {
			t.Errorf("%s does not load the live scripts", path)
		}
		if !strings.Contains(body, `data-events="/console/events?kinds=job"`) {
			t.Errorf("%s does not name the stream it watches", path)
		}
		if strings.Contains(body, `class="pulse"`) {
			t.Errorf("%s draws a pulsing dot in the live region", path)
		}
		if !strings.Contains(body, `data-when="on">Live.`) {
			t.Errorf("%s does not state its live condition in words", path)
		}
	}

	off := get(t, h, "/console/activity?kind=refusal").Body.String()
	if strings.Contains(off, "data-live-region") {
		t.Error("?kind=refusal renders a live region, but the refusal family has no live kind on the stream")
	}
	if strings.Contains(off, "stream.js") || strings.Contains(off, "activity.js") {
		t.Error("?kind=refusal mounts the live scripts for a view that can never update")
	}
	// And day one's off-state sentence must not appear here: it says live
	// updates are not available on this RELAY, which would be false.
	if strings.Contains(off, "Live updates are not available on this Relay") {
		t.Error("Activity rendered day one's off-state copy, which is false on this screen")
	}

	unwired := activityDeps(&fakeQueries{})
	unwired.Events = nil
	if body := get(t, newTestHandler(unwired, accounts.RoleAdmin), "/console/activity").Body.String(); strings.Contains(body, "data-live-region") {
		t.Error("Activity renders a live region with no event seam wired")
	}
}

// TestActivity_LiveCounterSaysWhatItCounts is R14. sseJob carries only a Job
// id, a transition and a time, so the client cannot tell whether an incoming
// event matches the page's filter — and one Job announces itself twice
// (created, then completed). The counter is therefore filter-blind and
// double-counts, and the copy beside it must say what it actually counts.
func TestActivity_LiveCounterSaysWhatItCounts(t *testing.T) {
	d := activityDeps(&fakeQueries{})
	d.Events = newFakeEvents()
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/activity").Body.String()

	if !strings.Contains(body, "counts job events on the stream, not rows that will appear") {
		t.Error("the live counter does not say that it counts stream events rather than rows")
	}
	if !strings.Contains(body, "One Job announces itself more than once") {
		t.Error("the live counter does not admit that it double-counts")
	}
	if !strings.Contains(body, `id="live-new-count"`) {
		t.Error("there is no counter element for the client to write into")
	}
}

// TestActivity_LiveRegionResumesFromTheNewestRetainedJobEvent. Without a
// resume point the reconnect replays the seam's whole retained window, which
// would count every retained Job again on every reconnect.
func TestActivity_LiveRegionResumesFromTheNewestRetainedJobEvent(t *testing.T) {
	d := activityDeps(&fakeQueries{})
	bus := newFakeEvents()
	d.Events = bus
	bus.publishJob(events.JobEvent{Transition: events.JobCreated, JobID: "job-1"})
	bus.publishJob(events.JobEvent{Transition: events.JobCompleted, JobID: "job-1"})

	newest := bus.Recent([]events.Kind{events.KindJob}, 10)
	if len(newest) != 2 {
		t.Fatalf("the bus retained %d Job events, want 2", len(newest))
	}
	want := newest[len(newest)-1].ID

	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/activity").Body.String()
	if !strings.Contains(body, `data-last-event-id="`+want+`"`) {
		t.Errorf("the live region does not resume from the newest retained Job event (%q)", want)
	}
}

// TestActivity_ExportCarriesNoOutputColumn. The export is the one place a row
// leaves this screen as data, and it is read in a spreadsheet by an auditor.
func TestActivity_ExportCarriesNoOutputColumn(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{{
		JobID: "job-1", CreatedAt: testNow, OperationName: "raw_exec",
		ActionKind: jobs.ActionRawExec, RiskClass: jobs.RiskClassMutate,
		// An argv element that a spreadsheet would evaluate as a formula.
		RawExecArgv: []string{"-c", "id"},
		Requester:   "gleipnir", RequesterAccountID: "acct-1",
		Total: 1, Counts: map[jobs.Outcome]int{jobs.OutcomeSuccess: 1},
	}}}
	rec := get(t, newTestHandler(activityDeps(q), accounts.RoleAdmin), "/console/activity?kind=dispatch&format=csv")

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type = %q, want text/csv", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") {
		t.Errorf("Content-Disposition = %q, want an attachment", cd)
	}

	body := rec.Body.String()
	header := strings.SplitN(body, "\n", 2)[0]
	for _, banned := range []string{"stdout", "stderr", "output"} {
		if strings.Contains(strings.ToLower(header), banned) {
			t.Errorf("the export header carries a %q column (ADR-0025): %s", banned, header)
		}
	}
	for _, want := range []string{"on_behalf_of", "approval_id", "grant_id", "job_id"} {
		if !strings.Contains(header, want) {
			t.Errorf("the export header is missing %q — an auditor's export must carry the "+
				"attribution the screen shows: %s", want, header)
		}
	}
	// Formula injection: an argv element is caller-controlled and legitimately
	// starts with '-'.
	if !strings.Contains(body, "'-c id") {
		t.Errorf("a field starting with '-' was exported unneutralised — a spreadsheet evaluates "+
			"it as a formula:\n%s", body)
	}
}

// TestActivity_ExportCarriesTheDecisionAnswer (#545) extends
// TestActivity_ExportCarriesNoOutputColumn's header list with the three
// structured decision columns, plus body assertions that an approved row's
// CSV line names "approved" and a denied row's names "denied".
func TestActivity_ExportCarriesTheDecisionAnswer(t *testing.T) {
	q := &fakeQueries{rows: []capability.AuditRow{
		{
			Kind: audit.KindApprovalDecided, Timestamp: testNow, ApprovalID: "appr-one",
			ApprovalAnswer: capability.ApprovalAnswerApproved, DecisionChannel: "out_of_band", PlanHash: "hash-one",
		},
		{
			Kind: audit.KindApprovalDecided, Timestamp: testNow.Add(time.Minute), ApprovalID: "appr-two",
			ApprovalAnswer: capability.ApprovalAnswerDenied, DecisionChannel: "in_band", PlanHash: "hash-two",
		},
	}}
	rec := get(t, newTestHandler(activityDeps(q), accounts.RoleAdmin), "/console/activity?format=csv")

	// Parsed as CSV and addressed BY COLUMN NAME, not searched as text.
	//
	// The first version of this test asserted strings.Contains(line, "approved")
	// and was vacuous twice over: the approval id "appr-approved" contains the
	// substring "approved", so the assertion was satisfied by its own needle and
	// passed with the answer column written empty; and a value landing in the
	// WRONG column still appears somewhere on the line. activityCSVHeader and
	// activityCSVRecord are two independent positional lists, and a shuffle
	// between them is exactly the silent failure this has to catch — so the ids
	// here are deliberately "appr-one"/"appr-two", carrying no answer word.
	r := csv.NewReader(strings.NewReader(rec.Body.String()))
	// The export ends with a "#" note line explaining what the file holds; it is
	// not a table row, and encoding/csv skips it natively rather than us
	// trimming lines by hand.
	r.Comment = '#'
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("the export is not valid CSV: %v", err)
	}
	if len(records) < 3 {
		t.Fatalf("want a header and two rows, got %d records", len(records))
	}
	col := map[string]int{}
	for i, name := range records[0] {
		col[name] = i
	}
	for _, want := range []string{"approval_answer", "decision_channel", "plan_hash"} {
		if _, ok := col[want]; !ok {
			t.Fatalf("the export header is missing %q: %v", want, records[0])
		}
	}

	byApprovalID := map[string][]string{}
	for _, r := range records[1:] {
		byApprovalID[r[col["approval_id"]]] = r
	}
	for _, tc := range []struct {
		id, answer, channel, hash string
	}{
		{"appr-one", "approved", "out_of_band", "hash-one"},
		{"appr-two", "denied", "in_band", "hash-two"},
	} {
		r, ok := byApprovalID[tc.id]
		if !ok {
			t.Fatalf("no exported row for approval id %q", tc.id)
		}
		if got := r[col["approval_answer"]]; got != tc.answer {
			t.Errorf("%s approval_answer = %q, want %q", tc.id, got, tc.answer)
		}
		if got := r[col["decision_channel"]]; got != tc.channel {
			t.Errorf("%s decision_channel = %q, want %q", tc.id, got, tc.channel)
		}
		if got := r[col["plan_hash"]]; got != tc.hash {
			t.Errorf("%s plan_hash = %q, want %q", tc.id, got, tc.hash)
		}
	}
}

// TestActivity_ExportIsBoundedAndSaysSo. An unbounded export behind one link
// is an unbounded read of the trail, and it appends a read record per page it
// walks.
func TestActivity_ExportIsBoundedAndSaysSo(t *testing.T) {
	// A lane that never runs out of pages. exportPages is the only thing that
	// stops the walk.
	q := &endlessQueries{}
	d := renderableDeps()
	d.Queries = q
	rec := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/activity?format=csv")

	body := rec.Body.String()
	if !strings.Contains(body, "THIS EXPORT IS INCOMPLETE") {
		t.Errorf("an export that hit its page cap does not say so in the file:\n%s", body)
	}
	if q.jobCalls > exportPages || q.auditCalls > exportPages {
		t.Errorf("the export walked %d Job and %d audit pages, past the cap of %d",
			q.jobCalls, q.auditCalls, exportPages)
	}
}

// TestActivity_ChipsCarryNoCountAndCoverEveryFamily. The counts were deleted
// rather than approximated; the cost, stated on the page, is that the chips
// now list every family including empty ones.
func TestActivity_ChipsCarryNoCountAndCoverEveryFamily(t *testing.T) {
	chips := kindChips(activityFilter{Kind: "dispatch"})
	if len(chips) != len(rowKindOrder) {
		t.Fatalf("got %d chips, want one per family (%d)", len(chips), len(rowKindOrder))
	}
	for _, c := range chips {
		if c.Href == "" {
			t.Errorf("the %q chip links nowhere", c.Kind)
		}
	}
	if !chips[0].Current || chips[0].Kind != rowDispatch {
		t.Errorf("the current family is not marked: %+v", chips[0])
	}
	// Selecting the current family CLEARS it, so a chip is a toggle.
	if chips[0].Href != "/console/activity" {
		t.Errorf("the current chip links to %q, want the unfiltered feed", chips[0].Href)
	}
}

// TestActivity_UnreadableFilterValuesAreNamedNotApplied. A time range that
// quietly became "everything" is how an auditor concludes an event did not
// happen.
func TestActivity_UnreadableFilterValuesAreNamedNotApplied(t *testing.T) {
	q := &fakeQueries{}
	body := get(t, newTestHandler(activityDeps(q), accounts.RoleAdmin),
		"/console/activity?since=yesterday&outcome=exploded").Body.String()

	if !strings.Contains(body, "Part of this URL could not be read") {
		t.Error("an unreadable filter value was applied or dropped silently")
	}
	if len(q.auditFilters) != 1 {
		t.Fatalf("got %d audit filters, want 1", len(q.auditFilters))
	}
	if !q.auditFilters[0].Since.IsZero() || q.auditFilters[0].Outcome != nil {
		t.Errorf("an unreadable value reached the seam anyway: %+v", q.auditFilters[0])
	}

	// A backwards range is refused HERE, with which half was wrong, rather
	// than being handed to the read lane to reject.
	back := &fakeQueries{}
	rev := get(t, newTestHandler(activityDeps(back), accounts.RoleAdmin),
		"/console/activity?since=2026-08-26T00:00:00Z&until=2026-08-20T00:00:00Z").Body.String()
	if !strings.Contains(rev, "until must be after since") {
		t.Error("a backwards range does not say which half was wrong")
	}
	if len(back.auditFilters) != 1 || !back.auditFilters[0].Since.IsZero() {
		t.Errorf("a backwards range reached the seam: %+v", back.auditFilters)
	}
}

// TestActivity_RelativeWindowResolvesAgainstTheRenderClock.
func TestActivity_RelativeWindowResolvesAgainstTheRenderClock(t *testing.T) {
	q := &fakeQueries{}
	get(t, newTestHandler(activityDeps(q), accounts.RoleAdmin), "/console/activity?window=1h")

	if len(q.jobFilters) != 2 {
		t.Fatalf("got %d Job filters, want the stream's and Running now's", len(q.jobFilters))
	}
	if want := testNow.Add(-time.Hour); !q.jobFilters[0].Since.Equal(want) {
		t.Errorf("window=1h resolved to Since=%v, want %v", q.jobFilters[0].Since, want)
	}
	if !isRunningNowRead(q.jobFilters[1]) {
		t.Errorf("the window narrowed Running now: %+v", q.jobFilters[1])
	}
}

// TestActivity_SpecConflictsAreStatedRatherThanFaked. Spec 04's filter box asks
// for Selector and Node, and neither has a backing field. The screen says so
// instead of rendering something that looks like them, and says it lists tool
// calls and nothing else.
func TestActivity_SpecConflictsAreStatedRatherThanFaked(t *testing.T) {
	body := get(t, newTestHandler(activityDeps(&fakeQueries{}), accounts.RoleAdmin), "/console/activity").Body.String()

	for _, want := range []string{
		"This screen lists tool calls and nothing else.",
		"The filter box carries no Selector and no Node.",
		"list every family this screen shows, including empty ones",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the screen does not state %q — an omission nobody wrote down reads as an oversight", want)
		}
	}
}

// --- helpers ----------------------------------------------------------------

// hrefContaining returns the href attribute containing want.
func hrefContaining(t *testing.T, body, want string) string {
	t.Helper()
	for i := 0; ; {
		rel := strings.Index(body[i:], `href="`)
		if rel < 0 {
			t.Fatalf("no href contains %q", want)
		}
		start := i + rel + len(`href="`)
		end := strings.Index(body[start:], `"`)
		if end < 0 {
			t.Fatalf("unterminated href near %q", body[start:min(start+40, len(body))])
		}
		href := body[start : start+end]
		if strings.Contains(href, want) {
			return href
		}
		i = start + end
	}
}

// unescapeHref turns a rendered href back into a request path. html/template
// escapes '&' as "&amp;", which is correct in HTML and not a URL.
func unescapeHref(t *testing.T, href string) string {
	t.Helper()
	path := strings.ReplaceAll(href, "&amp;", "&")
	if _, err := url.Parse(path); err != nil {
		t.Fatalf("the rendered href %q is not a URL: %v", href, err)
	}
	return path
}

// endlessQueries is a read lane that always reports another page. It exists to
// prove the export's cap is what ends the walk, rather than the data happening
// to run out.
type endlessQueries struct {
	jobCalls   int
	auditCalls int
}

// The registry half of the lane, unused by this fixture: Activity reads the
// trail, never the fleet. Present only to satisfy QueryReader.
func (q *endlessQueries) ListNodes(context.Context, capability.Principal, string) (capability.NodeListing, error) {
	return capability.NodeListing{}, nil
}

func (q *endlessQueries) DescribeNode(context.Context, capability.Principal, string) (capability.NodeDetail, error) {
	return capability.NodeDetail{}, capability.ErrNodeNotFound
}

func (q *endlessQueries) QueryAudit(_ context.Context, _ capability.Principal, _ capability.AuditFilter, page capability.PageRequest) (capability.AuditPage, error) {
	q.auditCalls++
	return capability.AuditPage{
		Rows: []capability.AuditRow{{Kind: audit.KindRefusal, Timestamp: testNow}},
		Next: "ac-next", Limit: page.Limit,
	}, nil
}

func (q *endlessQueries) AuditCounts(context.Context, capability.Principal, capability.AuditFilter, time.Duration) ([]capability.PrincipalBucket, error) {
	return nil, nil
}

func (q *endlessQueries) AuditReach(context.Context, capability.Principal, capability.AuditFilter) (capability.Reach, error) {
	return capability.Reach{}, nil
}

func (q *endlessQueries) QueryJobs(_ context.Context, _ capability.Principal, f capability.JobFilter, page capability.PageRequest) (capability.JobPage, error) {
	// Running now's read is not the stream lane this fake scripts: answered
	// empty and left out of its bookkeeping.
	if f.Order == jobs.JobOrderOldestFirst {
		return capability.JobPage{Limit: page.Limit}, nil
	}
	q.jobCalls++
	return capability.JobPage{
		Jobs: []capability.JobSummary{{JobID: "job-1", CreatedAt: testNow}},
		Next: "jc-next", Limit: page.Limit,
	}, nil
}

func (q *endlessQueries) QueryTasks(context.Context, capability.Principal, capability.TaskFilter, capability.PageRequest) (capability.TaskPage, error) {
	return capability.TaskPage{}, nil
}

// RecordEventSubscription is unused by Activity, which never opens the
// events route: present only to satisfy QueryReader (#539).
func (q *endlessQueries) RecordEventSubscription(_ context.Context, _ capability.Principal, kinds []string, _ bool) ([]string, error) {
	return kinds, nil
}

// TestActivity_TheRiskChipIsOnlyOnRowsThatRan. riskOf answers "mutate" for
// anything it does not recognise, because mutate is the safe direction for an
// unrecognised OPERATION. A Freeze engage is not an unrecognised Operation, it
// is not an Operation — and a `mutate` badge on every sign-in teaches an
// operator to ignore the chip on the rows where it is the whole point.
func TestActivity_TheRiskChipIsOnlyOnRowsThatRan(t *testing.T) {
	for _, c := range []struct {
		kind string
		want bool
	}{
		{audit.KindRefusal, true},
		{audit.KindApprovalRequested, true},
		{audit.KindRead, true},
		{audit.KindPlan, true},
		{audit.KindJobCancel, true},
		{audit.KindFreezeEngage, false},
	} {
		row := eventRowFromTrail(factsOfRow(capability.AuditRow{Kind: c.kind, Timestamp: testNow}))
		if got := row.Risk != ""; got != c.want {
			t.Errorf("%s row has a risk chip = %v (%q), want %v", c.kind, got, row.Risk, c.want)
		}
	}
}

// TestActivity_OnlyTheDispatchRowCarriesTheLiveHandle. The client looks a row
// up by data-job-id and takes the FIRST match, so a job_cancel row — which
// names the Job it cancelled — must not carry the handle. Otherwise a Job
// completing would relabel the cancellation row "completed after this page was
// rendered", which is a sentence about the wrong row.
func TestActivity_OnlyTheDispatchRowCarriesTheLiveHandle(t *testing.T) {
	q := &fakeQueries{
		jobs: []capability.JobSummary{{JobID: "job-1", CreatedAt: testNow, OperationName: "service.restart"}},
		rows: []capability.AuditRow{{Kind: audit.KindJobCancel, JobID: "job-1", Timestamp: testNow}},
	}
	body := get(t, newTestHandler(activityDeps(q), accounts.RoleAdmin), "/console/activity").Body.String()

	if n := strings.Count(body, `data-job-id="job-1"`); n != 1 {
		t.Errorf("%d rows carry the live handle for job-1, want exactly 1 (the dispatch row)", n)
	}
	if n := strings.Count(body, "evliveslot"); n != 1 {
		t.Errorf("%d rows reserve a completion slot, want exactly 1", n)
	}
	// The cancel row still LINKS to the Job; it just is not the Job.
	if !strings.Contains(body, `<a href="/console/jobs/job-1">Job `) {
		t.Error("the job_cancel row lost its link to the Job it cancelled")
	}
}

// scriptedQueries hands each lane a FIXED NUMBER OF PAGES, independently, and
// records every cursor it was handed.
//
// fakeQueries cannot express the case that matters: both its lanes end
// together, so a screen that restarted an exhausted lane at page one looked
// identical to one that did not. Here the Job lane runs out first and the
// audit lane keeps going, which is the ordinary shape of a real trail — one
// dispatch a day, a hundred sign-ins.
type scriptedQueries struct {
	jobPageCount   int
	auditPageCount int

	jobCursors   []string
	auditCursors []string
}

// The registry half of the lane, unused by this fixture (see endlessQueries).
func (q *scriptedQueries) ListNodes(context.Context, capability.Principal, string) (capability.NodeListing, error) {
	return capability.NodeListing{}, nil
}

func (q *scriptedQueries) DescribeNode(context.Context, capability.Principal, string) (capability.NodeDetail, error) {
	return capability.NodeDetail{}, capability.ErrNodeNotFound
}

// pageIndex reads the page number back out of a cursor this fake minted.
// Empty is page zero, which is exactly the ambiguity the bug lived in.
func (q *scriptedQueries) pageIndex(cursor string) int {
	if cursor == "" {
		return 0
	}
	n := 0
	for _, c := range cursor[1:] {
		n = n*10 + int(c-'0')
	}
	return n
}

func (q *scriptedQueries) cursorFor(i int) string { return "p" + strconv.Itoa(i) }

func (q *scriptedQueries) QueryJobs(_ context.Context, _ capability.Principal, f capability.JobFilter, page capability.PageRequest) (capability.JobPage, error) {
	// Running now's read is not a stream page: answered empty and left out of
	// the stream's cursor bookkeeping.
	if f.Order == jobs.JobOrderOldestFirst {
		return capability.JobPage{Limit: page.Limit}, nil
	}
	q.jobCursors = append(q.jobCursors, page.Cursor)
	i := q.pageIndex(page.Cursor)
	if i >= q.jobPageCount {
		return capability.JobPage{Limit: page.Limit}, nil
	}
	out := capability.JobPage{
		Jobs:  []capability.JobSummary{{JobID: "job-" + q.cursorFor(i), CreatedAt: testNow.Add(-time.Duration(i) * time.Minute), OperationName: "service.restart"}},
		Limit: page.Limit,
	}
	if i+1 < q.jobPageCount {
		out.Next = q.cursorFor(i + 1)
	}
	return out, nil
}

func (q *scriptedQueries) QueryAudit(_ context.Context, _ capability.Principal, _ capability.AuditFilter, page capability.PageRequest) (capability.AuditPage, error) {
	q.auditCursors = append(q.auditCursors, page.Cursor)
	i := q.pageIndex(page.Cursor)
	if i >= q.auditPageCount {
		return capability.AuditPage{Limit: page.Limit}, nil
	}
	out := capability.AuditPage{
		// The marker goes in the SELECTOR, not the ID: an AuditRow's ID is
		// not rendered on the screen or in the export, so a test keyed on it
		// would pass whatever the page did.
		Rows: []capability.AuditRow{{
			ID: "a-" + q.cursorFor(i), Selector: "sel-" + q.cursorFor(i),
			Kind: audit.KindRefusal, Timestamp: testNow.Add(-time.Duration(i) * time.Minute),
		}},
		Limit: page.Limit,
	}
	if i+1 < q.auditPageCount {
		out.Next = q.cursorFor(i + 1)
	}
	return out, nil
}

func (q *scriptedQueries) AuditCounts(context.Context, capability.Principal, capability.AuditFilter, time.Duration) ([]capability.PrincipalBucket, error) {
	return nil, nil
}

func (q *scriptedQueries) AuditReach(context.Context, capability.Principal, capability.AuditFilter) (capability.Reach, error) {
	return capability.Reach{}, nil
}

func (q *scriptedQueries) QueryTasks(context.Context, capability.Principal, capability.TaskFilter, capability.PageRequest) (capability.TaskPage, error) {
	return capability.TaskPage{}, nil
}

// RecordEventSubscription is unused by Activity, which never opens the
// events route: present only to satisfy QueryReader (#539).
func (q *scriptedQueries) RecordEventSubscription(_ context.Context, _ capability.Principal, kinds []string, _ bool) ([]string, error) {
	return kinds, nil
}

// TestActivity_AnExhaustedLaneStaysExhausted is the bug an empty cursor hides.
//
// The two lanes page independently, so one runs out first. An empty cursor in
// the URL means "start from the top", not "this lane is finished" — so the
// short lane RESTARTED AT PAGE ONE on every "Older", re-rendering its newest
// rows under an older heading and reporting another page every time, which
// made the chain infinite. Losing rows from an audit trail and repeating them
// forever are the same defect seen from two sides.
func TestActivity_AnExhaustedLaneStaysExhausted(t *testing.T) {
	q := &scriptedQueries{jobPageCount: 1, auditPageCount: 3}
	d := renderableDeps()
	d.Queries = q
	h := newTestHandler(d, accounts.RoleAdmin)

	path := "/console/activity"
	seen := map[string]int{}
	for page := 1; page <= 6; page++ {
		body := get(t, h, path).Body.String()
		for _, row := range []string{"job-p0", "sel-p0", "sel-p1", "sel-p2"} {
			if strings.Contains(body, row) {
				seen[row]++
			}
		}
		if page == 1 && !strings.Contains(body, "job-p0") {
			t.Fatal("the first page does not carry the Job lane's only row")
		}
		older := strings.Contains(body, ">Older<")
		if !older {
			if page == 1 {
				t.Fatal("the first page offers no Older link, so the fake is not scripted as intended")
			}
			break
		}
		if page == 6 {
			t.Fatal("the Older chain never terminated — an exhausted lane is restarting at page one")
		}
		path = unescapeHref(t, olderHref(t, body))
		if !strings.Contains(path, "adone=1") && !strings.Contains(path, "ac=") {
			t.Fatalf("the Older link lost the audit lane entirely: %q", path)
		}
	}

	for row, n := range seen {
		if n != 1 {
			t.Errorf("the row %s was rendered on %d pages — paging must not repeat a row", row, n)
		}
	}
	if len(q.jobCursors) != 1 {
		t.Errorf("the Job lane was queried %d times (%v) — it ran out on page one and must not be "+
			"re-driven with an empty cursor, which is page one again", len(q.jobCursors), q.jobCursors)
	}
}

// TestActivity_ExportWalksEachLaneToItsOwnEnd is the same defect in the file an
// auditor keeps, where it is worse: the short lane contributed its first page
// again on every iteration, so one Job row appeared ten times in the export.
func TestActivity_ExportWalksEachLaneToItsOwnEnd(t *testing.T) {
	q := &scriptedQueries{jobPageCount: 1, auditPageCount: 3}
	d := renderableDeps()
	d.Queries = q
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/activity?format=csv").Body.String()

	for _, row := range []string{"job-p0", "sel-p0", "sel-p1", "sel-p2"} {
		if n := strings.Count(body, row); n != 1 {
			t.Errorf("the export carries %s %d times, want exactly 1:\n%s", row, n, body)
		}
	}
	if len(q.jobCursors) != 1 {
		t.Errorf("the export queried the Job lane %d times (%v) — a lane that ran out must be "+
			"dropped, not re-driven from page one", len(q.jobCursors), q.jobCursors)
	}
	if strings.Contains(body, "THIS EXPORT IS INCOMPLETE") {
		t.Error("an export that reached the end of both lanes claims to be incomplete")
	}
}

// TestActivity_ExhaustedPositionSaysSoRatherThanNothingMatches. Only reachable
// by hand-editing the URL, but "nothing matches" would be a claim about the
// FILTER when the truth is about the POSITION.
func TestActivity_ExhaustedPositionSaysSoRatherThanNothingMatches(t *testing.T) {
	q := &scriptedQueries{jobPageCount: 1, auditPageCount: 1}
	d := renderableDeps()
	d.Queries = q
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/activity?jdone=1&adone=1").Body.String()

	if !strings.Contains(body, "There is nothing older for this filter.") {
		t.Error("both lanes exhausted does not say so")
	}
	if strings.Contains(body, "Nothing matches") || strings.Contains(body, "Nothing has been recorded yet") {
		t.Error("an exhausted position is reported as an empty filter or an empty trail")
	}
	if len(q.jobCursors) != 0 || len(q.auditCursors) != 0 {
		t.Errorf("a finished lane was queried anyway: job=%v audit=%v", q.jobCursors, q.auditCursors)
	}
}

// TestActivity_UnattributableFinishedJobDoesNotPromiseAnAttribution.
//
// The in-flight sentence is honest while a Job is running and FALSE once it is
// not: a finished Job with no requester is not waiting for one, the trail
// simply has no dispatch record for it. Spec 04 legislates about exactly that
// row — "a bug to surface, not a blank to render" — so the two cases get two
// sentences.
func TestActivity_UnattributableFinishedJobDoesNotPromiseAnAttribution(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{{
		JobID: "job-orphan", CreatedAt: testNow, OperationName: "service.restart",
		// Finished, so Complete: the zero State is Running (iota 0).
		State: jobs.JobStateComplete,
		Total: 3, Unresolved: 0, Counts: map[jobs.Outcome]int{jobs.OutcomeSuccess: 3},
	}}}
	body := get(t, newTestHandler(activityDeps(q), accounts.RoleAdmin), "/console/activity?kind=dispatch").Body.String()

	if strings.Contains(body, "attribution is recorded when the dispatch completes") {
		t.Error("a FINISHED Job with no requester promises an attribution that will never arrive — " +
			"the dispatch already completed")
	}
	if !strings.Contains(body, "the trail should carry one") {
		t.Error("a finished, unattributable dispatch is not surfaced as the defect it is")
	}
	if strings.Contains(body, "unattributed") {
		t.Error("the row renders the bare word \"unattributed\", which claims the Relay looked and " +
			"found an anonymous caller")
	}
}

// TestActivity_TrailKindsFitTheReadLanesOwnCap. AuditFilter.validate refuses
// more than 32 kinds, and the default feed requests every kind but two. The
// eleventh new audit kind would turn the DEFAULT FEED into a 500 — and
// TestActivity_EveryAuditKindIsClassified, the test someone would look at
// while adding a kind, would stay green.
func TestActivity_TrailKindsFitTheReadLanesOwnCap(t *testing.T) {
	if n := len(activityTrailKinds); n > 32 {
		t.Errorf("the default feed requests %d audit kinds; capability.AuditFilter.validate refuses "+
			"more than 32, so the unfiltered screen is a 500. Split the lane or raise the cap "+
			"deliberately.", n)
	}
	for _, family := range rowKindOrder {
		if n := len(kindsOfFamily(family)); n > 32 {
			t.Errorf("the %q family requests %d audit kinds, past the read lane's cap of 32", family, n)
		}
	}
}

// TestActivity_OverlongOnBehalfOfIsNamedNotForwarded. The read lane refuses a
// value longer than it could ever have been recorded as, so without this the
// operator gets a 500 for a URL rather than a page saying which value was
// wrong.
func TestActivity_OverlongOnBehalfOfIsNamedNotForwarded(t *testing.T) {
	q := &fakeQueries{}
	long := strings.Repeat("a", maxOnBehalfOfChars+1)
	rec := get(t, newTestHandler(activityDeps(q), accounts.RoleAdmin), "/console/activity?on_behalf_of="+long)

	if rec.Code != http.StatusOK {
		t.Errorf("an over-long on_behalf_of = %d, want 200 with an explanation", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "on_behalf_of is longer than") {
		t.Error("the page does not say which value was too long")
	}
	// The stream's read and Running now's: neither may carry the value.
	if len(q.jobFilters) != 2 || q.jobFilters[0].OnBehalfOf != "" || q.jobFilters[1].OnBehalfOf != "" {
		t.Errorf("an over-long value reached the seam: %+v", q.jobFilters)
	}
}

// olderHref returns the pager's Older link, scoped to the pager so that a kind
// chip's href cannot be mistaken for it.
func olderHref(t *testing.T, body string) string {
	t.Helper()
	start := strings.Index(body, `<div class="pager">`)
	if start < 0 {
		t.Fatal("the page has no pager")
	}
	end := strings.Index(body[start:], "</div>")
	if end < 0 {
		t.Fatal("the pager is never closed")
	}
	return hrefContaining(t, body[start:start+end], "/console/activity")
}

// TestSummarize_ApprovalDecisionNamesWhichWayItWent covers the Activity
// sentence, which the chip tests do not reach.
//
// It exists because a code review found this branch had NO coverage at all:
// swapping "approved" and "denied" in summarize left every test in the suite
// green. The chip and the prose are two independent renderings of one fact, so
// asserting the chip proves nothing about the sentence beside it — and the
// sentence is what an operator reads on a screen whose whole job is saying what
// happened. Verified by mutation: the swap reddens the approved and denied
// cases below.
//
// The four cases are the four the record can actually be in, and each names a
// DIFFERENT sentence, so no two can be satisfied by the same output.
func TestSummarize_ApprovalDecisionNamesWhichWayItWent(t *testing.T) {
	cases := []struct {
		name string
		f    trailFacts
		want string
	}{
		{
			name: "a revocation is not a Decision",
			f:    trailFacts{Kind: audit.KindApprovalDecided, GrantID: "grant-1"},
			want: "revoked an Approval grant",
		},
		{
			name: "approved",
			f:    trailFacts{Kind: audit.KindApprovalDecided, ApprovalAnswer: audit.ApprovalAnswerApproved},
			want: "approved a parked dispatch",
		},
		{
			name: "denied",
			f:    trailFacts{Kind: audit.KindApprovalDecided, ApprovalAnswer: audit.ApprovalAnswerDenied},
			want: "denied a parked dispatch",
		},
		{
			// The #487 guard, in prose rather than in a chip: a pre-#545 row
			// records no answer, and the sentence must not invent one.
			name: "answerless pre-#545 row keeps the original sentence",
			f:    trailFacts{Kind: audit.KindApprovalDecided},
			want: "answered an approval request",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := summarize(tc.f); got != tc.want {
				t.Errorf("summarize() = %q, want %q", got, tc.want)
			}
		})
	}

	// A revocation that ALSO carries an answer must still read as a revocation:
	// GrantID is the structural discriminator and is checked first. Without
	// this, reordering the switch is a behaviour-preserving edit no test can
	// see, because a real revocation carries no answer.
	both := trailFacts{
		Kind: audit.KindApprovalDecided, GrantID: "grant-1",
		ApprovalAnswer: audit.ApprovalAnswerApproved,
	}
	if got, want := summarize(both), "revoked an Approval grant"; got != want {
		t.Errorf("summarize(revocation carrying an answer) = %q, want %q — GrantID is "+
			"the structural discriminator and must be checked before the answer", got, want)
	}
}
