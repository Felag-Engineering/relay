package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// queryRecord builds a minimal, valid audit.Record for the query-lane tests
// below, overridden field by field per test.
func queryRecord(id string, ts time.Time) audit.Record {
	return audit.Record{
		ID:        id,
		Timestamp: ts,
		Kind:      audit.KindDispatch,
		Principal: "gleipnir:operator",
		Attribution: audit.Attribution{
			Verified: audit.Verified{AccountID: "acct-1", AccountName: "gleipnir", Role: "operator"},
		},
		Selector:      "relay:env=prod",
		JobID:         "job-" + id,
		NodeID:        "node-1",
		ActionKind:    "operation",
		OperationName: "file.read",
		Args:          map[string]string{"path": "/etc/hosts"},
		Outcome:       jobs.OutcomeSuccess,
		Stdout:        []byte("should never come back through the query lane"),
	}
}

// TestAuditQuery_FilterComposition is acceptance line 21: a query for `read`
// kinds over one Account in one window returns in one call.
func TestAuditQuery_FilterComposition(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	repo := st.Audit()
	queries := st.AuditQueries()

	base := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

	matching := queryRecord("match", base)
	matching.Kind = audit.KindRead
	matching.Attribution.Verified.AccountID = "acct-target"

	wrongKind := queryRecord("wrong-kind", base)
	wrongKind.Attribution.Verified.AccountID = "acct-target"

	wrongAccount := queryRecord("wrong-account", base)
	wrongAccount.Kind = audit.KindRead
	wrongAccount.Attribution.Verified.AccountID = "acct-other"

	outsideWindow := queryRecord("outside-window", base.Add(48*time.Hour))
	outsideWindow.Kind = audit.KindRead
	outsideWindow.Attribution.Verified.AccountID = "acct-target"

	for _, r := range []audit.Record{matching, wrongKind, wrongAccount, outsideWindow} {
		if err := repo.Append(ctx, r); err != nil {
			t.Fatalf("append %s: %v", r.ID, err)
		}
	}

	page, err := queries.Query(ctx, audit.Query{
		Kinds:     []string{audit.KindRead},
		AccountID: "acct-target",
		Since:     base.Add(-time.Hour),
		Until:     base.Add(time.Hour),
	}, 0, "")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(page.Rows) != 1 || page.Rows[0].ID != "match" {
		t.Fatalf("Query rows = %+v, want exactly [match]", page.Rows)
	}
}

// TestAuditQuery_EachFilterAlone exercises Kind, AccountID, OnBehalfOf,
// NodeID, Operations, Outcome, JobID, ApprovalID, and GrantID independently.
func TestAuditQuery_EachFilterAlone(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	repo := st.Audit()
	queries := st.AuditQueries()

	ts := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

	target := queryRecord("target", ts)
	target.Attribution.Asserted.OnBehalfOf = "ops-team"
	target.ApprovalID = "appr-1"
	target.GrantID = "grant-1"

	decoy := queryRecord("decoy", ts)
	decoy.NodeID = "node-2"
	decoy.JobID = "job-decoy"
	decoy.OperationName = "system.facts"
	decoy.Outcome = jobs.OutcomeFailure
	decoy.Attribution.Verified.AccountID = "acct-2"
	decoy.Attribution.Asserted.OnBehalfOf = "other-team"

	for _, r := range []audit.Record{target, decoy} {
		if err := repo.Append(ctx, r); err != nil {
			t.Fatalf("append %s: %v", r.ID, err)
		}
	}

	success := jobs.OutcomeSuccess
	cases := []struct {
		name string
		q    audit.Query
	}{
		{"AccountID", audit.Query{AccountID: "acct-1"}},
		{"OnBehalfOf", audit.Query{OnBehalfOf: "ops-team"}},
		{"NodeID", audit.Query{NodeID: "node-1"}},
		{"Operations", audit.Query{Operations: []string{"file.read"}}},
		{"Outcome", audit.Query{Outcome: &success}},
		{"JobID", audit.Query{JobID: "job-target"}},
		{"ApprovalID", audit.Query{ApprovalID: "appr-1"}},
		{"GrantID", audit.Query{GrantID: "grant-1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			page, err := queries.Query(ctx, c.q, 0, "")
			if err != nil {
				t.Fatalf("Query: %v", err)
			}
			if len(page.Rows) != 1 || page.Rows[0].ID != "target" {
				t.Errorf("rows = %+v, want exactly [target]", page.Rows)
			}
		})
	}
}

// TestAuditQuery_Pagination pages through a fixture at a small limit and
// asserts exact set equality with an unpaginated read (no duplicates, no
// gaps), then inserts new rows between page calls and asserts an
// already-issued cursor still returns only rows older than it — acceptance
// line 22, stable under concurrent appends.
func TestAuditQuery_Pagination(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	repo := st.Audit()
	queries := st.AuditQueries()

	base := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	const n = 10
	var ids []string
	for i := 0; i < n; i++ {
		id := padID(i)
		ids = append(ids, id)
		if err := repo.Append(ctx, queryRecord(id, base.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}
	// Three rows sharing one timestamp, so the paged walk crosses a TIE and
	// not only distinct instants (#656). Without the audit_id tie-break these
	// three are ordered arbitrarily, and the keyset predicate then skips or
	// repeats whichever of them straddles a page boundary.
	for _, id := range []string{"id-02a", "id-02b", "id-02c"} {
		ids = append(ids, id)
		if err := repo.Append(ctx, queryRecord(id, base.Add(2*time.Minute))); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}

	var got []string
	cursor := ""
	pages := 0
	for {
		page, err := queries.Query(ctx, audit.Query{}, 3, cursor)
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(page.Rows) == 0 {
			t.Fatalf("page %d returned zero rows before Next was empty", pages)
		}
		for _, r := range page.Rows {
			got = append(got, r.ID)
		}
		pages++
		if page.Next == "" {
			break
		}
		cursor = page.Next
		if pages > len(ids) {
			t.Fatalf("paging did not terminate after %d pages", pages)
		}
	}

	sort.Strings(got)
	want := append([]string{}, ids...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("paged IDs = %v, want %v (no duplicates, no gaps)", got, want)
	}

	// A cursor issued mid-walk must still return only OLDER rows after a
	// concurrent append — the new row sorts newest and lands on a page the
	// caller already turned, never inside the one about to be fetched.
	firstPage, err := queries.Query(ctx, audit.Query{}, 3, "")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	issuedCursor := firstPage.Next
	if issuedCursor == "" {
		t.Fatal("expected a Next cursor from the first page of 10 records at limit 3")
	}

	if err := repo.Append(ctx, queryRecord("inserted-after-cursor", base.Add(time.Hour))); err != nil {
		t.Fatalf("append inserted-after-cursor: %v", err)
	}

	nextPage, err := queries.Query(ctx, audit.Query{}, 100, issuedCursor)
	if err != nil {
		t.Fatalf("Query with issued cursor: %v", err)
	}
	for _, r := range nextPage.Rows {
		if r.ID == "inserted-after-cursor" {
			t.Fatalf("a row appended after the cursor was issued leaked into the next page")
		}
	}
}

// padID zero-pads i into a fixed-width ID so lexical and numeric sort agree
// in test assertions.
func padID(i int) string {
	return fmt.Sprintf("id-%02d", i)
}

// TestAuditQuery_MalformedCursor asserts a garbage or foreign cursor is
// audit.ErrInvalidCursor, never a silent reset to page one.
func TestAuditQuery_MalformedCursor(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	queries := st.AuditQueries()

	for _, cursor := range []string{"not-base64!!!", "aGVsbG8", "==="} {
		_, err := queries.Query(ctx, audit.Query{}, 0, cursor)
		if !errors.Is(err, audit.ErrInvalidCursor) {
			t.Errorf("cursor %q: err = %v, want audit.ErrInvalidCursor", cursor, err)
		}
	}
}

// TestAuditQuery_ArgPrefixEscaping stores a value containing LIKE
// metacharacters and filters with a prefix containing both, asserting a
// literal (not pattern) match.
func TestAuditQuery_ArgPrefixEscaping(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	repo := st.Audit()
	queries := st.AuditQueries()

	ts := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

	literal := queryRecord("literal", ts)
	literal.Args = map[string]string{"path": "/etc/50%_off.conf"}

	decoy := queryRecord("decoy", ts)
	decoy.Args = map[string]string{"path": "/etc/50Xoff.conf"} // would match if % / _ were not escaped

	for _, r := range []audit.Record{literal, decoy} {
		if err := repo.Append(ctx, r); err != nil {
			t.Fatalf("append %s: %v", r.ID, err)
		}
	}

	page, err := queries.Query(ctx, audit.Query{ArgKey: "path", ArgValuePrefix: "/etc/50%_o"}, 0, "")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(page.Rows) != 1 || page.Rows[0].ID != "literal" {
		t.Fatalf("rows = %+v, want exactly [literal] (escaped %% and _ must match literally)", page.Rows)
	}
}

// TestAuditQuery_FractionalTimestamps covers records with 0, 3, and 9
// fractional digits: every one is returned exactly once, a Since/Until window
// that brackets them includes all of them, and — since #656 — they come back
// in the right ORDER. Set membership alone passed while the whole-second row
// was sorting to the wrong end of its second.
func TestAuditQuery_FractionalTimestamps(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	repo := st.Audit()
	queries := st.AuditQueries()

	base := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	fixtures := []struct {
		id string
		ts time.Time
	}{
		{"zero-frac", base},
		{"milli-frac", base.Add(123 * time.Millisecond)},
		{"nano-frac", base.Add(123456789 * time.Nanosecond)},
	}
	for _, f := range fixtures {
		if err := repo.Append(ctx, queryRecord(f.id, f.ts)); err != nil {
			t.Fatalf("append %s: %v", f.id, err)
		}
	}

	page, err := queries.Query(ctx, audit.Query{
		Since: base.Add(-time.Second),
		Until: base.Add(time.Second),
	}, 0, "")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(page.Rows) != len(fixtures) {
		t.Fatalf("rows = %d, want %d (every fractional-digit variant)", len(page.Rows), len(fixtures))
	}

	seen := map[string]bool{}
	for _, r := range page.Rows {
		seen[r.ID] = true
	}
	for _, f := range fixtures {
		if !seen[f.id] {
			t.Errorf("fixture %s missing from the windowed query", f.id)
		}
	}

	// Newest first: the 9-digit fraction is the latest instant, the
	// whole-second row the earliest. Before #656 the whole-second row came
	// back FIRST, because RFC3339Nano trimmed its fraction away and "Z" sorts
	// above ".".
	gotOrder := make([]string, len(page.Rows))
	for i, r := range page.Rows {
		gotOrder[i] = r.ID
	}
	wantOrder := []string{"nano-frac", "milli-frac", "zero-frac"}
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Errorf("rows = %v, want %v — the read lane is newest-first, and a shorter fraction must not sort after a longer one (#656)", gotOrder, wantOrder)
	}
}

// TestAuditQuery_CursorIssuedBeforeTheMigrationDoesNotRepeatARow is the
// regression for the silent infinite loop (#656).
//
// The cursor's ts has never been the stored bytes: ts is declared TIMESTAMP,
// so the driver parses the column into a time.Time and database/sql renders
// it back as TRIMMED RFC3339Nano. A cursor an older binary issued therefore
// carries "...T00:00:03Z" while the migrated row holds
// "...T00:00:03.000000000Z" — and "." (0x2E) sorts below "Z" (0x5A), so the
// row compares as OLDER than its own cursor and is returned again, forever.
//
// Rejecting such cursors is not implementable: a cursor issued before 0024
// and one issued after are byte-identical. decodeAuditCursor normalises
// instead.
func TestAuditQuery_CursorIssuedBeforeTheMigrationDoesNotRepeatARow(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	queries := st.AuditQueries()

	// Four rows in the pre-0024 format, newest last.
	legacy := []struct{ id, ts string }{
		{"row-1", "2026-08-20T00:00:01Z"},
		{"row-2", "2026-08-20T00:00:02Z"},
		{"row-3", "2026-08-20T00:00:03Z"},
		{"row-4", "2026-08-20T00:00:04Z"},
	}
	for _, r := range legacy {
		insertLegacyAuditRow(t, st.db, r.id, r.ts)
	}

	// The cursor the OLD binary issued after page one: the scanned (trimmed)
	// ts of the newest row, and that row's id.
	staleCursor := encodeCursor2("2026-08-20T00:00:04Z", "row-4")

	runMigration0024(t, st.db)

	page, err := queries.Query(ctx, audit.Query{}, 1, staleCursor)
	if err != nil {
		t.Fatalf("Query with a pre-0024 cursor: %v", err)
	}
	if len(page.Rows) != 1 || page.Rows[0].ID != "row-3" {
		t.Fatalf("page 2 with a pre-0024 cursor returned %+v again — the cursor mis-seeks, and a paging client loops on one row forever (#656)", page.Rows)
	}
}

// TestAuditQuery_PagesExactlyOnceAcrossFractionalWidths walks the whole trail
// one row at a time over mixed fractional widths and repeated timestamps:
// every row exactly once, newest first, terminating.
func TestAuditQuery_PagesExactlyOnceAcrossFractionalWidths(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	repo := st.Audit()
	queries := st.AuditQueries()

	base := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	fixtures := []struct {
		id     string
		offset time.Duration
	}{
		{"r0", 0},
		{"r1", 1},
		{"r2", 100 * time.Millisecond},
		{"r3", 123456789},
		{"r4", time.Second},
		{"r5", time.Second}, // a deliberate tie with r4
		{"r6", time.Second + 500*time.Millisecond},
		{"r7", 2 * time.Second},
		{"r8", 2*time.Second + 999999999},
		{"r9", 3 * time.Second},
	}
	for _, f := range fixtures {
		if err := repo.Append(ctx, queryRecord(f.id, base.Add(f.offset))); err != nil {
			t.Fatalf("append %s: %v", f.id, err)
		}
	}

	var got []string
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > len(fixtures) {
			t.Fatalf("paged walk did not terminate after %d pages over %d rows (#656)", pages, len(fixtures))
		}
		page, err := queries.Query(ctx, audit.Query{}, 1, cursor)
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(page.Rows) == 0 {
			t.Fatalf("page %d returned zero rows before Next was empty", pages)
		}
		got = append(got, page.Rows[0].ID)
		if page.Next == "" {
			break
		}
		cursor = page.Next
	}

	want := []string{"r9", "r8", "r7", "r6", "r5", "r4", "r3", "r2", "r1", "r0"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("paged walk returned %v over %d pages, want %v — keyset pagination over a fixed-width ts must cover every row exactly once, newest first (#656)", got, len(got), want)
	}
}

// TestAuditQuery_CursorRejectsAnUnparseableTimestamp pins the fail-loud half
// of the normalisation: a cursor whose ts is not a timestamp is refused, never
// compared as raw text.
func TestAuditQuery_CursorRejectsAnUnparseableTimestamp(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()

	_, err := st.AuditQueries().Query(ctx, audit.Query{}, 0, encodeCursor2("lunchtime", "id-1"))
	if !errors.Is(err, audit.ErrInvalidCursor) {
		t.Errorf("err = %v, want audit.ErrInvalidCursor — a cursor whose timestamp does not parse must be refused, never compared as raw text", err)
	}
}

// TestAuditQuery_CountsByPrincipal_ParsesFractionalTimestamps pins that
// strftime('%s', ts) parses the stored RFC3339Nano format even with 9
// fractional digits — a build without that behaviour must mis-bucket
// loudly (a wrong count), not silently.
func TestAuditQuery_CountsByPrincipal_ParsesFractionalTimestamps(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	repo := st.Audit()
	queries := st.AuditQueries()

	hour0 := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	hour1 := hour0.Add(time.Hour)
	hour2 := hour0.Add(2 * time.Hour)

	recs := []audit.Record{
		queryRecord("a1", hour0),
		queryRecord("a2", hour0.Add(30*time.Minute)),
		queryRecord("a3", hour1.Add(123456789*time.Nanosecond)), // 9 fractional digits
		queryRecord("b1", hour2),
	}
	recs[3].Attribution.Verified.AccountID = "acct-2"
	recs[3].Attribution.Verified.AccountName = "second-account"

	for _, r := range recs {
		if err := repo.Append(ctx, r); err != nil {
			t.Fatalf("append %s: %v", r.ID, err)
		}
	}

	buckets, err := queries.CountsByPrincipal(ctx, audit.Query{}, time.Hour)
	if err != nil {
		t.Fatalf("CountsByPrincipal: %v", err)
	}

	want := map[string]int{
		"acct-1@" + hour0.Format(time.RFC3339): 2,
		"acct-1@" + hour1.Format(time.RFC3339): 1,
		"acct-2@" + hour2.Format(time.RFC3339): 1,
	}
	got := map[string]int{}
	for _, b := range buckets {
		got[b.AccountID+"@"+b.Start.Format(time.RFC3339)] = b.Count
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buckets = %v, want %v", got, want)
	}

	// Ascending order.
	for i := 1; i < len(buckets); i++ {
		if buckets[i].Start.Before(buckets[i-1].Start) {
			t.Errorf("buckets not ascending: %+v", buckets)
		}
	}
}

// TestAuditQuery_ReachCounts is the console/reads.go:55-62 regression: one
// file.read across 3 Nodes is 1 target / 3 Nodes, and the COALESCE order
// matches audit.TargetArgKeys.
func TestAuditQuery_ReachCounts(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	repo := st.Audit()
	queries := st.AuditQueries()

	ts := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	for i, nodeID := range []string{"node-1", "node-2", "node-3"} {
		r := queryRecord(nodeIDSuffixed(i), ts)
		r.NodeID = nodeID
		r.Args = map[string]string{"path": "/etc/hosts"}
		if err := repo.Append(ctx, r); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	reach, err := queries.ReachCounts(ctx, audit.Query{})
	if err != nil {
		t.Fatalf("ReachCounts: %v", err)
	}
	if reach.Calls != 3 {
		t.Errorf("Calls = %d, want 3", reach.Calls)
	}
	if reach.DistinctTargets != 1 {
		t.Errorf("DistinctTargets = %d, want 1 (same operation+path across all three)", reach.DistinctTargets)
	}
	if reach.DistinctNodes != 3 {
		t.Errorf("DistinctNodes = %d, want 3", reach.DistinctNodes)
	}

	// COALESCE precedence: a record with BOTH "path" and "file" set must be
	// targeted by "path" — audit.TargetArgKeys' order.
	if len(audit.TargetArgKeys) < 2 || audit.TargetArgKeys[0] != "path" || audit.TargetArgKeys[1] != "file" {
		t.Fatalf("audit.TargetArgKeys changed shape; update this test's precedence assertion: %v", audit.TargetArgKeys)
	}
	both := queryRecord("both-keys", ts)
	both.NodeID = "node-4"
	both.Args = map[string]string{"path": "/etc/hosts", "file": "/should/not/be/used"}
	if err := repo.Append(ctx, both); err != nil {
		t.Fatalf("append both-keys: %v", err)
	}
	reach, err = queries.ReachCounts(ctx, audit.Query{NodeID: "node-4"})
	if err != nil {
		t.Fatalf("ReachCounts: %v", err)
	}
	if reach.DistinctTargets != 1 {
		t.Errorf("DistinctTargets = %d, want 1 (path takes precedence over file)", reach.DistinctTargets)
	}
}

func nodeIDSuffixed(i int) string {
	return fmt.Sprintf("reach-%d", i)
}

// TestAuditRow_NoOutputFields is a reflect test pinning D2/acceptance line
// 22: no field of audit.Row is []byte and none is named Stdout, Stderr,
// Truncated, or Output.
func TestAuditRow_NoOutputFields(t *testing.T) {
	typ := reflect.TypeOf(audit.Row{})
	forbidden := map[string]bool{"Stdout": true, "Stderr": true, "Truncated": true, "Output": true}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if forbidden[f.Name] {
			t.Errorf("audit.Row has a %s field — the query lane must never carry read output", f.Name)
		}
		if f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.Uint8 {
			t.Errorf("audit.Row.%s is []byte — the query lane must never carry a BLOB", f.Name)
		}
	}
}

// TestAuditQuery_DecisionAnswerRoundTrips (#545): the QUERY lane's own column
// list (auditQueryColumns / scanAuditQueryRow) is independent of audit.go's
// INSERT/SELECT — Repository.List() exercises one, QueryRepository.Query()
// the other — so the answer, Channel, and PlanHash have to round-trip through
// THIS lane too, or a column dropped from auditQueryColumns would pass
// TestAudit_DecisionAnswerRoundTrips while silently breaking every read
// surface built on Query (Activity, agent history).
func TestAuditQuery_DecisionAnswerRoundTrips(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	repo := st.Audit()
	queries := st.AuditQueries()

	at := time.Date(2026, 8, 16, 9, 0, 0, 0, time.UTC)
	approved := audit.Record{
		ID: "q1", Timestamp: at, Kind: audit.KindApprovalDecided,
		Principal: "ana:operator", ApprovalID: "appr-1",
		ApprovalAnswer: audit.ApprovalAnswerApproved, DecisionChannel: "out_of_band", PlanHash: "hash-1",
	}
	answerless := audit.Record{
		ID: "q2", Timestamp: at.Add(time.Minute), Kind: audit.KindApprovalDecided,
		Principal: "ops-console:admin", ApprovalID: "appr-2", GrantID: "grant-1",
	}
	for _, r := range []audit.Record{approved, answerless} {
		if err := repo.Append(ctx, r); err != nil {
			t.Fatalf("append %s: %v", r.ID, err)
		}
	}

	page, err := queries.Query(ctx, audit.Query{}, 0, "")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(page.Rows) != 2 {
		t.Fatalf("Query returned %d rows, want 2", len(page.Rows))
	}
	byID := map[string]audit.Row{}
	for _, r := range page.Rows {
		byID[r.ID] = r
	}
	if got := byID["q1"]; got.ApprovalAnswer != audit.ApprovalAnswerApproved || got.DecisionChannel != "out_of_band" || got.PlanHash != "hash-1" {
		t.Errorf("approved row = %+v, want answer/channel/hash from the write", got)
	}
	if got := byID["q2"]; got.ApprovalAnswer != "" || got.DecisionChannel != "" || got.PlanHash != "" {
		t.Errorf("answerless row = %+v, want all three empty", got)
	}
}

// TestCheckBucketCount is F1's bucket-count guard (#441 cycle-2 security
// review), tested against a synthetic groupCount rather than materialising
// audit.MaxCountBuckets+1 rows in a real database.
func TestCheckBucketCount(t *testing.T) {
	if err := checkBucketCount(audit.MaxCountBuckets); err != nil {
		t.Errorf("checkBucketCount(%d) [at the limit] = %v, want nil", audit.MaxCountBuckets, err)
	}
	if err := checkBucketCount(audit.MaxCountBuckets + 1); !errors.Is(err, audit.ErrInvalidFilter) {
		t.Errorf("checkBucketCount(%d) [over the limit] = %v, want audit.ErrInvalidFilter", audit.MaxCountBuckets+1, err)
	}
	if err := checkBucketCount(0); err != nil {
		t.Errorf("checkBucketCount(0) = %v, want nil", err)
	}
}

// TestAuditQuery_CountsByPrincipal_GuardDoesNotFalsePositive proves the
// bucket-count guard is actually wired into CountsByPrincipal's normal path
// (not just unit-tested in isolation): a small, ordinary fixture stays well
// under audit.MaxCountBuckets and must not be refused.
func TestAuditQuery_CountsByPrincipal_GuardDoesNotFalsePositive(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	repo := st.Audit()
	queries := st.AuditQueries()

	ts := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	if err := repo.Append(ctx, queryRecord("guard-1", ts)); err != nil {
		t.Fatalf("append: %v", err)
	}

	buckets, err := queries.CountsByPrincipal(ctx, audit.Query{}, time.Hour)
	if err != nil {
		t.Fatalf("CountsByPrincipal: %v", err)
	}
	if len(buckets) != 1 {
		t.Fatalf("buckets = %d, want 1", len(buckets))
	}
}

// TestReachTargetExpr_RejectsInvalidTargetArgKey is F4 (#441 cycle-2
// security review): audit.TargetArgKeys is a package-level var interpolated
// directly into SQL by reachTargetExpr, so each key is validated against
// auditArgKeyPattern before that interpolation happens. Not attacker-
// reachable today (nothing assigns to TargetArgKeys), but this pins the
// defense-in-depth so a future assignment fails closed instead of building
// an unvalidated SQL fragment.
func TestReachTargetExpr_RejectsInvalidTargetArgKey(t *testing.T) {
	original := audit.TargetArgKeys
	defer func() { audit.TargetArgKeys = original }()

	audit.TargetArgKeys = []string{"path", "'; DROP TABLE audit; --"}
	if _, err := reachTargetExpr(); err == nil {
		t.Fatal("reachTargetExpr() with an invalid TargetArgKeys entry = nil error, want a rejection")
	}

	audit.TargetArgKeys = []string{"path", "file", "unit", "service"}
	if _, err := reachTargetExpr(); err != nil {
		t.Errorf("reachTargetExpr() with the real TargetArgKeys = %v, want nil", err)
	}
}
