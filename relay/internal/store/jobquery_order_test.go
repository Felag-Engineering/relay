package store

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// The Job query's direction and count (#795): oldest-first with a cursor that
// walks that way, and an opt-in count of matching Jobs that ignores paging.
//
// Fixtures use whole-second created_at and exact ties only. created_at is
// stored as trimmed RFC3339Nano text, so within one second the byte order and
// the time order of two stamps can differ; whole seconds and exact ties sit on
// the side of that where the two agree.

// orderFixture is five Jobs, one of them tied with another on created_at.
// Oldest first they are job-1, job-2, job-3, job-4, job-5.
func orderFixture(t *testing.T, st *Store) {
	t.Helper()
	ctx := context.Background()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	for _, j := range []struct {
		id string
		at time.Duration
	}{
		{"job-1", 0},
		{"job-2", time.Second},
		{"job-3", time.Second}, // ties job-2: job_id breaks it
		{"job-4", 2 * time.Second},
		{"job-5", 3 * time.Second},
	} {
		createJobFixture(t, ctx, st, j.id, base.Add(j.at), []jobs.Task{
			{ID: j.id + "-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, State: jobs.DispatchStatePending},
		})
	}
}

// walkJobs follows Next from page one with the given limit and returns every
// Job ID in the order met, and each page's Matching.
func walkJobs(t *testing.T, st *Store, q jobs.JobQuery, limit int) (ids []string, matching []int) {
	t.Helper()
	cursor := ""
	for i := 0; i < 20; i++ {
		page, err := st.JobQueries().QueryJobs(context.Background(), q, limit, cursor)
		if err != nil {
			t.Fatalf("QueryJobs(cursor %q): %v", cursor, err)
		}
		for _, j := range page.Jobs {
			ids = append(ids, j.JobID)
		}
		matching = append(matching, page.Matching)
		if page.Next == "" {
			return ids, matching
		}
		cursor = page.Next
	}
	t.Fatal("paging did not end")
	return nil, nil
}

// The default is what every caller before #795 relies on: newest first, and
// no count. This is the evidence that adding the fields changed nothing for
// them.
func TestJobQuery_DefaultOrderIsNewestFirstAndCountsNothing(t *testing.T) {
	st, _ := openTestStore(t)
	orderFixture(t, st)

	ids, matching := walkJobs(t, st, jobs.JobQuery{}, 2)
	if want := []string{"job-5", "job-4", "job-3", "job-2", "job-1"}; !slices.Equal(ids, want) {
		t.Errorf("default order = %v, want %v", ids, want)
	}
	for i, m := range matching {
		if m != 0 {
			t.Errorf("page %d carries Matching = %d without CountMatching", i, m)
		}
	}
}

func TestJobQuery_OldestFirstPagesInThatDirection(t *testing.T) {
	st, _ := openTestStore(t)
	orderFixture(t, st)

	ids, _ := walkJobs(t, st, jobs.JobQuery{Order: jobs.JobOrderOldestFirst}, 2)
	if want := []string{"job-1", "job-2", "job-3", "job-4", "job-5"}; !slices.Equal(ids, want) {
		t.Errorf("oldest-first order = %v, want %v (ties by job_id, no gaps, no repeats)", ids, want)
	}

	// The last page ends the walk, and a page that exactly fills the limit
	// does not invent another.
	page, err := st.JobQueries().QueryJobs(context.Background(), jobs.JobQuery{Order: jobs.JobOrderOldestFirst}, 5, "")
	if err != nil {
		t.Fatalf("QueryJobs: %v", err)
	}
	if len(page.Jobs) != 5 || page.Next != "" {
		t.Errorf("a page holding every Job = %d Jobs, Next %q; want 5 and none", len(page.Jobs), page.Next)
	}
}

func TestJobQuery_CountMatchingIgnoresPaging(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

	mine := jobs.Requester{AccountID: "acct-x", AccountName: "x", Kind: "human"}
	theirs := jobs.Requester{AccountID: "acct-y", AccountName: "y", Kind: "human"}
	task := func(id string, state jobs.DispatchState) []jobs.Task {
		return []jobs.Task{{ID: id + "-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}, State: state, Outcome: jobs.OutcomeSuccess}}
	}
	for i, j := range []struct {
		id    string
		who   jobs.Requester
		state jobs.DispatchState
	}{
		{"run-x1", mine, jobs.DispatchStatePending},
		{"run-x2", mine, jobs.DispatchStateDispatched},
		{"run-x3", mine, jobs.DispatchStatePending},
		{"run-y1", theirs, jobs.DispatchStatePending},
		{"done-x1", mine, jobs.DispatchStateResolved},
		{"done-y1", theirs, jobs.DispatchStateResolved},
	} {
		createJobFixtureBy(t, ctx, st, j.id, j.who, base.Add(time.Duration(i)*time.Second), task(j.id, j.state))
	}

	running := jobs.JobStateRunning
	q := jobs.JobQuery{
		State: &running, RequesterAccountID: "acct-x",
		Order: jobs.JobOrderOldestFirst, CountMatching: true,
	}
	first, err := st.JobQueries().QueryJobs(ctx, q, 1, "")
	if err != nil {
		t.Fatalf("QueryJobs: %v", err)
	}
	if first.Matching != 3 || len(first.Jobs) != 1 || first.Jobs[0].JobID != "run-x1" {
		t.Fatalf("page one = %d Jobs %v, Matching %d; want run-x1 alone and Matching 3", len(first.Jobs), first.Jobs, first.Matching)
	}
	second, err := st.JobQueries().QueryJobs(ctx, q, 1, first.Next)
	if err != nil {
		t.Fatalf("QueryJobs(page two): %v", err)
	}
	if second.Matching != 3 || len(second.Jobs) != 1 || second.Jobs[0].JobID != "run-x2" {
		t.Errorf("page two = %v, Matching %d; want run-x2 and the same Matching 3: the count ignores the cursor", second.Jobs, second.Matching)
	}
	all, err := st.JobQueries().QueryJobs(ctx, q, 50, "")
	if err != nil {
		t.Fatalf("QueryJobs(limit 50): %v", err)
	}
	if all.Matching != 3 {
		t.Errorf("Matching = %d with a limit of 50, want 3: the count ignores the limit", all.Matching)
	}

	q.CountMatching = false
	none, err := st.JobQueries().QueryJobs(ctx, q, 1, "")
	if err != nil {
		t.Fatalf("QueryJobs(no count): %v", err)
	}
	if none.Matching != 0 {
		t.Errorf("Matching = %d without CountMatching, want 0", none.Matching)
	}
}

// A cursor minted in one direction must never be accepted in the other: it
// would silently walk the wrong way, or reset to page one, which loops a
// paging client forever.
func TestJobQuery_ACursorIsRefusedInTheOtherDirection(t *testing.T) {
	st, _ := openTestStore(t)
	orderFixture(t, st)
	ctx := context.Background()

	newest, err := st.JobQueries().QueryJobs(ctx, jobs.JobQuery{}, 2, "")
	if err != nil || newest.Next == "" {
		t.Fatalf("newest-first page one: Next %q, err %v", newest.Next, err)
	}
	oldest, err := st.JobQueries().QueryJobs(ctx, jobs.JobQuery{Order: jobs.JobOrderOldestFirst}, 2, "")
	if err != nil || oldest.Next == "" {
		t.Fatalf("oldest-first page one: Next %q, err %v", oldest.Next, err)
	}

	if _, err := st.JobQueries().QueryJobs(ctx, jobs.JobQuery{Order: jobs.JobOrderOldestFirst}, 2, newest.Next); !errors.Is(err, jobs.ErrInvalidCursor) {
		t.Errorf("a newest-first cursor in an oldest-first query: err = %v, want ErrInvalidCursor", err)
	}
	if _, err := st.JobQueries().QueryJobs(ctx, jobs.JobQuery{}, 2, oldest.Next); !errors.Is(err, jobs.ErrInvalidCursor) {
		t.Errorf("an oldest-first cursor in a newest-first query: err = %v, want ErrInvalidCursor", err)
	}
	// The same refusal with a count asked for, which opens a transaction on the other path.
	if _, err := st.JobQueries().QueryJobs(ctx, jobs.JobQuery{Order: jobs.JobOrderOldestFirst, CountMatching: true}, 2, "not-a-cursor"); !errors.Is(err, jobs.ErrInvalidCursor) {
		t.Errorf("a malformed cursor with a count: err = %v, want ErrInvalidCursor", err)
	}
}

func TestJobQuery_AnUnknownOrderIsAnError(t *testing.T) {
	st, _ := openTestStore(t)
	if _, err := st.JobQueries().QueryJobs(context.Background(), jobs.JobQuery{Order: jobs.JobOrder(99)}, 2, ""); err == nil {
		t.Error("an unknown order was answered rather than refused")
	}
}

// The count shares jobQueryFrom and buildJobWhere with the page, but leaves the
// audit aggregate out unless a condition reads it. That is only safe if the two
// still agree on every filter, so the property is asserted over each one:
// Matching equals the number of Jobs met by paging the same filter to the end.
func TestJobQuery_CountMatchesPagingEveryFilter(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

	ann := jobs.Requester{AccountID: "acct-ann", AccountName: "ann", Kind: "human"}
	bob := jobs.Requester{AccountID: "acct-bob", AccountName: "bob", Kind: "human"}
	for i, j := range []struct {
		id    string
		who   jobs.Requester
		op    string
		risk  jobs.RiskClass
		state jobs.DispatchState
		audit bool // a dispatch audit row asserting on-behalf-of agent-7
	}{
		{"j1", ann, "system.facts", jobs.RiskClassRead, jobs.DispatchStatePending, true},
		{"j2", ann, "system.facts", jobs.RiskClassRead, jobs.DispatchStateResolved, false},
		{"j3", bob, "service.restart", jobs.RiskClassMutate, jobs.DispatchStatePending, true},
		{"j4", bob, "service.restart", jobs.RiskClassMutate, jobs.DispatchStateResolved, true},
		{"j5", ann, "service.restart", jobs.RiskClassMutate, jobs.DispatchStateDispatched, false},
		{"j6", bob, "system.facts", jobs.RiskClassRead, jobs.DispatchStateResolved, false},
	} {
		at := base.Add(time.Duration(i) * time.Second)
		createJobFixtureBy(t, ctx, st, j.id, j.who, at, []jobs.Task{
			{ID: j.id + "-t1", NodeID: "node-1", Action: jobs.Action{Kind: jobs.ActionOperation, OperationName: j.op, RiskClass: j.risk}, State: j.state, Outcome: jobs.OutcomeSuccess},
		})
		if j.audit {
			dispatchAuditRecordFull(t, ctx, st, "audit-"+j.id, j.id, "node-1", jobs.OutcomeSuccess, at)
		}
	}

	running, complete := jobs.JobStateRunning, jobs.JobStateComplete
	mutate := jobs.RiskClassMutate
	filters := map[string]jobs.JobQuery{
		"none":                  {},
		"running":               {State: &running},
		"complete":              {State: &complete},
		"requester":             {RequesterAccountID: "acct-bob"},
		"operation":             {Operation: "service.restart"},
		"risk":                  {RiskClass: &mutate},
		"since":                 {Since: base.Add(2 * time.Second)},
		"until":                 {Until: base.Add(3 * time.Second)},
		"window":                {Since: base.Add(time.Second), Until: base.Add(4 * time.Second)},
		"on behalf":             {OnBehalfOf: "agent-7"},
		"on behalf and running": {OnBehalfOf: "agent-7", State: &running},
		"job":                   {JobID: "j3"},
		"job and on behalf":     {JobID: "j3", OnBehalfOf: "agent-7"},
		"nothing matches":       {Operation: "no.such.operation"},
	}
	for name, q := range filters {
		for _, order := range []jobs.JobOrder{jobs.JobOrderNewestFirst, jobs.JobOrderOldestFirst} {
			q.Order = order
			ids, _ := walkJobs(t, st, q, 2)

			q.CountMatching = true
			page, err := st.JobQueries().QueryJobs(ctx, q, 2, "")
			if err != nil {
				t.Fatalf("%s: QueryJobs: %v", name, err)
			}
			if page.Matching != len(ids) {
				t.Errorf("%s (order %d): Matching = %d, but paging to the end meets %d Jobs %v", name, order, page.Matching, len(ids), ids)
			}
		}
	}
}

// planOf returns the EXPLAIN QUERY PLAN detail lines of stmt.
func planOf(t *testing.T, st *Store, stmt string, args []any) string {
	t.Helper()
	rows, err := st.db.QueryContext(context.Background(), `EXPLAIN QUERY PLAN `+stmt, args...)
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN: %v", err)
	}
	defer rows.Close() //nolint:errcheck
	var plan strings.Builder
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatalf("scan plan row: %v", err)
		}
		plan.WriteString(detail + "\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate plan: %v", err)
	}
	return plan.String()
}

// The count runs on every Activity view, which a viewer can reach. The audit
// aggregate reads every dispatch row in the trail, so a count that does not
// filter on it must not plan it at all; one that does (on-behalf-of) must.
func TestJobQuery_CountTouchesTheAuditTrailOnlyWhenTheFilterDoes(t *testing.T) {
	st, _ := openTestStore(t)
	running := jobs.JobStateRunning

	stmt, args := jobQueryCount(jobs.JobQuery{State: &running, RequesterAccountID: "acct-x"})
	if plan := planOf(t, st, stmt, args); strings.Contains(plan, "audit") {
		t.Errorf("a count with no on-behalf-of filter plans the audit table:\n%s", plan)
	}

	stmt, args = jobQueryCount(jobs.JobQuery{OnBehalfOf: "agent-7"})
	if plan := planOf(t, st, stmt, args); !strings.Contains(plan, "audit") {
		t.Errorf("a count filtered on on-behalf-of does not join the audit table, so it cannot be right:\n%s", plan)
	}
}
