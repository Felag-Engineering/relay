package console

// activity_collapse_test.go proves spec 04's "Polling" on Activity (#541): a run
// of consecutive rows that render identically folds into one row carrying its
// call count, so an Account making 200 get_job calls does not push everything
// else off the page. The Agents collapse tests are ported here.
//
// Fixtures are sized against auditPageSize (50) and jobPageSize (25), and no
// test changes a page size: the collapse is over the fetched page and never
// reaches past its boundary.

import (
	"html"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// feedRows splits a rendered Activity page into one string per rendered row,
// newest first.
func feedRows(body string) []string {
	parts := strings.Split(body, `<article class="ev" data-kind="`)
	if len(parts) == 0 {
		return nil
	}
	return parts[1:]
}

var dataCallsRE = regexp.MustCompile(`data-calls="(\d+)"`)

func callsOfRow(t *testing.T, block string) int {
	t.Helper()
	m := dataCallsRE.FindStringSubmatch(block)
	if m == nil {
		t.Fatalf("a row carries no data-calls:\n%s", block)
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

func rowCalls(t *testing.T, body string) []int {
	t.Helper()
	var out []int
	for _, b := range feedRows(body) {
		out = append(out, callsOfRow(t, b))
	}
	return out
}

// pollRead is one identical get_job poll, authenticated with an API Token so
// it is not a read made from a Console session.
func pollRead(v capability.VerifiedIdentity, age time.Duration) capability.AuditRow {
	return capability.AuditRow{
		Kind: audit.KindRead, OperationName: "get_job", JobID: "job-1",
		Timestamp: testNow.Add(-age), Verified: v,
	}
}

func polls(v capability.VerifiedIdentity, n int, firstAge time.Duration) []capability.AuditRow {
	var rows []capability.AuditRow
	for i := 0; i < n; i++ {
		rows = append(rows, pollRead(v, firstAge+time.Duration(i)*time.Second))
	}
	return rows
}

func assertEveryAuditLimitIs(t *testing.T, q *fakeQueries, want int) {
	t.Helper()
	for _, l := range q.auditLimits {
		if l != want {
			t.Errorf("an audit read asked for %d rows, want %d", l, want)
		}
	}
}

func TestActivity_PollingCollapsesWithinThePage(t *testing.T) {
	poller, other := apiIdentity("acct-poll", "poller", "operator"), apiIdentity("acct-other", "other", "operator")
	rows := []capability.AuditRow{
		{Kind: audit.KindRead, OperationName: "list_nodes", Timestamp: testNow, Verified: other},
	}
	rows = append(rows, polls(poller, 49, time.Second)...)
	q := &fakeQueries{rows: rows}
	body := activityAs(t, q, "/console/activity?kind=read")

	blocks := feedRows(body)
	if len(blocks) != 2 {
		t.Fatalf("rows = %d, want 2 (list_nodes and one folded get_job)", len(blocks))
	}
	// Neither fixture read is made from a Console session, so the sentence
	// carries no count.
	if strings.Contains(body, "Reads made from this Console are left out:") {
		t.Error("the page counts Console reads, but no fixture row is one")
	}
	if got := rowCalls(t, body); got[0] != 1 || got[1] != 49 {
		t.Errorf("data-calls = %v, want [1 49]", got)
	}
	if !strings.Contains(blocks[1], `<span class="chip calls"`) || !strings.Contains(blocks[1], ">×49<") {
		t.Errorf("the folded row has no ×49 chip:\n%s", blocks[1])
	}
	if !strings.Contains(body, `class="vcount">50 events<`) {
		t.Errorf("the viewbar does not count the 50 calls:\n%s", body)
	}
	if strings.Contains(body, "collapsed into") {
		t.Errorf("the page says in a sentence what the collapse did:\n%s", body)
	}
	assertEveryAuditLimitIs(t, q, auditPageSize)
	if strings.Contains(body, ">Older<") {
		t.Error("an Older link is drawn for a page that holds everything")
	}
}

func TestActivity_TwoHundredPollsDoNotPushTheOtherAccountOff(t *testing.T) {
	poller, other := apiIdentity("acct-poll", "poller", "operator"), apiIdentity("acct-other", "other", "operator")

	t.Run("kind=read", func(t *testing.T) {
		rows := []capability.AuditRow{{Kind: audit.KindRead, OperationName: "list_nodes", Timestamp: testNow, Verified: other}}
		rows = append(rows, polls(poller, 200, time.Second)...)
		q := &fakeQueries{rows: rows}
		body := activityAs(t, q, "/console/activity?kind=read")

		if got := rowCalls(t, body); len(got) != 2 || got[0] != 1 || got[1] != 49 {
			t.Errorf("data-calls = %v, want [1 49]: the polls actually on the page, never 200", got)
		}
		if !strings.Contains(body, ">Older<") {
			t.Error("no Older link although 151 polls are on later pages")
		}
		assertEveryAuditLimitIs(t, q, auditPageSize)
	})

	t.Run("the default feed", func(t *testing.T) {
		rows := polls(poller, 200, time.Second)
		rows = append(rows, refusalBy(other, 300*time.Second, "the other Account's refusal"))
		q := &fakeQueries{rows: rows}
		body := activityAs(t, q, "/console/activity")

		if containsString(q.auditFilters[0].Kinds, audit.KindRead) {
			t.Fatal("the default feed requested read records")
		}
		if !strings.Contains(body, "the other Account&#39;s refusal") {
			t.Errorf("the refusal is not on page one:\n%s", body)
		}
		if strings.Contains(body, "get_job") {
			t.Error("a poll rendered on the default feed")
		}
	})
}

func TestActivity_CollapseNeverReachesPastThePageBoundary(t *testing.T) {
	q := &fakeQueries{rows: polls(apiIdentity("acct-poll", "poller", "operator"), 120, time.Second)}
	path := "/console/activity?kind=read"
	older := regexp.MustCompile(`<a class="act" href="([^"]*)">Older</a>`)

	for _, want := range []int{50, 50, 20} {
		body := activityAs(t, q, path)
		if got := rowCalls(t, body); len(got) != 1 || got[0] != want {
			t.Fatalf("%s: data-calls = %v, want [%d]", path, got, want)
		}
		m := older.FindStringSubmatch(body)
		if m == nil {
			break
		}
		path = html.UnescapeString(m[1])
	}
	if want := 3; len(q.auditPages) != want {
		t.Errorf("pages read = %d, want %d", len(q.auditPages), want)
	}
}

func TestActivity_CollapseIsConsecutiveOnly(t *testing.T) {
	who := apiIdentity("acct-1", "alice", "operator")
	read := func(tool string, age time.Duration) capability.AuditRow {
		return capability.AuditRow{Kind: audit.KindRead, OperationName: tool, Timestamp: testNow.Add(-age), Verified: who}
	}
	q := &fakeQueries{rows: []capability.AuditRow{
		read("list_nodes", time.Second), read("list_nodes", 2*time.Second),
		read("list_operations", 3*time.Second), read("list_nodes", 4*time.Second),
	}}
	body := activityAs(t, q, "/console/activity?kind=read")
	if got := rowCalls(t, body); len(got) != 3 || got[0] != 2 || got[1] != 1 || got[2] != 1 {
		t.Errorf("data-calls = %v, want [2 1 1]: A, A, B, A folds to A(2), B, A", got)
	}
}

func TestActivity_ARawExecBetweenTwoRunsStaysItsOwnRow(t *testing.T) {
	who := apiIdentity("acct-1", "alice", "operator")
	raw := finishedJob("job-raw", "alice", "acct-1")
	raw.ActionKind = jobs.ActionRawExec
	raw.OperationName = ""
	raw.RawExecArgv = []string{"systemctl", "restart", "nginx"}
	raw.CreatedAt = testNow.Add(-3 * time.Second)
	q := &fakeQueries{
		rows: []capability.AuditRow{
			refusalBy(who, time.Second, "same"), refusalBy(who, 2*time.Second, "same"), refusalBy(who, 4*time.Second, "same"),
		},
		jobs: []capability.JobSummary{raw},
	}
	blocks := feedRows(activityAs(t, q, "/console/activity"))
	if len(blocks) != 3 {
		t.Fatalf("rows = %d, want refusal x2, raw_exec, refusal", len(blocks))
	}
	wantKinds := []string{`refusal"`, `dispatch"`, `refusal"`}
	for i, b := range blocks {
		if !strings.HasPrefix(b, wantKinds[i]) {
			t.Errorf("row %d = %.40q, want kind %s", i, b, wantKinds[i])
		}
	}
	if callsOfRow(t, blocks[0]) != 2 || !strings.Contains(blocks[1], `data-tier="raw_exec"`) || callsOfRow(t, blocks[2]) != 1 {
		t.Error("the Raw Exec row did not keep the two refusal runs apart")
	}
}

func TestActivity_JobRowsNeverCollapse(t *testing.T) {
	a, b := finishedJob("job-a", "alice", "acct-1"), finishedJob("job-b", "alice", "acct-1")
	b.CreatedAt = a.CreatedAt.Add(-time.Second)
	got := rowCalls(t, activityAs(t, &fakeQueries{jobs: []capability.JobSummary{a, b}}, "/console/activity"))
	if len(got) != 2 || got[0] != 1 || got[1] != 1 {
		t.Errorf("data-calls = %v, want two Job rows of one call each", got)
	}
}

func TestActivity_ACollapsedRowCarriesACountChipWhoseTitleIsItsSpan(t *testing.T) {
	who := apiIdentity("acct-1", "alice", "operator")
	q := &fakeQueries{rows: []capability.AuditRow{
		refusalBy(who, time.Second, "same"), refusalBy(who, 2*time.Second, "same"), refusalBy(who, 3*time.Second, "same"),
	}}
	blocks := feedRows(activityAs(t, q, "/console/activity"))
	if len(blocks) != 1 {
		t.Fatalf("rows = %d, want 1", len(blocks))
	}
	b := blocks[0]
	if callsOfRow(t, b) != 3 || !strings.Contains(b, ">×3<") {
		t.Errorf("the row does not say it stands for 3 calls:\n%s", b)
	}
	if !strings.Contains(b, `title="2026-08-25 11:59:57Z to 2026-08-25 11:59:59Z"`) {
		t.Errorf("the chip does not give the run's absolute span:\n%s", b)
	}
	if strings.Contains(b, "consecutive identical calls") {
		t.Error("the row restates the collapse in a sentence")
	}
	if strings.Contains(b, "ago") {
		t.Error("the row gives a relative time")
	}
}

func TestActivity_ACollapsedRunIsAChipNotASentence(t *testing.T) {
	who := apiIdentity("acct-1", "alice", "operator")
	q := &fakeQueries{rows: []capability.AuditRow{refusalBy(who, time.Second, "same"), refusalBy(who, 2*time.Second, "same")}}
	body := activityAs(t, q, "/console/activity")
	if !strings.Contains(body, `class="chip calls"`) || !strings.Contains(body, ">×2<") {
		t.Errorf("the folded refusals have no ×2 chip:\n%s", body)
	}
	for _, gone := range []string{"collapsed into", "on the audit trail"} {
		if strings.Contains(body, gone) {
			t.Errorf("the page says %q in a sentence", gone)
		}
	}
}

func TestActivity_ScopedCollapseFoldsOnlyWhatItShows(t *testing.T) {
	a, b := apiIdentity("acct-a", "a", "operator"), apiIdentity("acct-b", "b", "operator")
	read := func(v capability.VerifiedIdentity, age time.Duration) capability.AuditRow {
		return capability.AuditRow{Kind: audit.KindRead, OperationName: "list_nodes", Timestamp: testNow.Add(-age), Verified: v}
	}
	q := &fakeQueries{rows: []capability.AuditRow{read(a, time.Second), read(b, 2*time.Second), read(a, 3*time.Second)}}
	got := rowCalls(t, activityAs(t, q, "/console/activity?kind=read&account=acct-a"))
	if len(got) != 1 || got[0] != 2 {
		t.Errorf("data-calls = %v, want acct-a's two reads folded into one row", got)
	}
}

func TestActivity_TheExportIsNeverCollapsed(t *testing.T) {
	who := apiIdentity("acct-1", "alice", "operator")
	q := &fakeQueries{rows: []capability.AuditRow{
		refusalBy(who, time.Second, "same"), refusalBy(who, 2*time.Second, "same"), refusalBy(who, 3*time.Second, "same"),
	}}
	body := get(t, newTestHandler(activityDeps(q), accounts.RoleAdmin), "/console/activity?format=csv").Body.String()
	if n := strings.Count(body, ",refusal,"); n != 3 {
		t.Errorf("the export holds %d refusal lines, want 3:\n%s", n, body)
	}
}

func TestActivity_ARunningJobKeepsExactlyOneCancelAfterCollapse(t *testing.T) {
	who := apiIdentity("acct-1", "alice", "operator")
	running := runningJob("job-1", "alice", "acct-1")
	running.Selector = "role=web"
	q := &fakeQueries{
		jobs: []capability.JobSummary{running},
		rows: []capability.AuditRow{refusalBy(who, time.Second, "same"), refusalBy(who, 2*time.Second, "same")},
	}
	body := activityRunning(t, q, accounts.RoleAdmin, "/console/activity")
	if n := strings.Count(body, `class="jobcancel"`); n != 1 {
		t.Errorf("cancel forms = %d, want exactly 1", n)
	}
}

// --- The key --------------------------------------------------------------------

func collapseProbeBase() activityRow {
	return activityRow{
		Kind: rowRefusal, EventKind: audit.KindRefusal, When: "2026-08-25 12:00:00Z",
		Principal: "alice", AccountID: "acct-1", Calls: 1,
		Outcomes: OutcomeBar{Segments: make([]Segment, 1)},
	}
}

type probeStep struct {
	field int
	slice bool
}

// probePaths lists every leaf reachable through exported fields, descending into
// nested structs and into the elements of slices.
func probePaths(t *testing.T, typ reflect.Type, prefix []probeStep, name string, visit func([]probeStep, string)) {
	t.Helper()
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		steps := append(append([]probeStep(nil), prefix...), probeStep{field: i})
		n := name + f.Name
		switch {
		case f.Type.Kind() == reflect.Struct:
			probePaths(t, f.Type, steps, n+".", visit)
		case f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.Struct:
			steps[len(steps)-1].slice = true
			probePaths(t, f.Type.Elem(), steps, n+"[].", visit)
		default:
			visit(steps, n)
		}
	}
}

func setProbe(t *testing.T, row *activityRow, steps []probeStep, name string) {
	t.Helper()
	v := reflect.ValueOf(row).Elem()
	for i, s := range steps {
		v = v.Field(s.field)
		if s.slice {
			if v.Len() == 0 {
				v.Set(reflect.MakeSlice(v.Type(), 1, 1))
			}
			v = v.Index(0)
		}
		if i < len(steps)-1 {
			continue
		}
		switch v.Kind() {
		case reflect.String:
			v.SetString("zz-probe")
		case reflect.Bool:
			v.SetBool(true)
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			v.SetInt(7)
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			v.SetUint(7)
		case reflect.Float32, reflect.Float64:
			v.SetFloat(1.5)
		default:
			t.Fatalf("the key sweep cannot probe %s (kind %s): decide whether it belongs in the collapse key", name, v.Kind())
		}
	}
}

// TestActivityCollapseKey_CoversEveryExportedField: every exported leaf of the
// row changes the key, except the run's own bookkeeping. A field added to
// activityRow is therefore in the key automatically, or this fails naming it.
func TestActivityCollapseKey_CoversEveryExportedField(t *testing.T) {
	base := collapseProbeBase()
	baseKey, ok := activityCollapseKey(base)
	if !ok {
		t.Fatal("the probe base cannot fold at all")
	}
	bookkeeping := map[string]bool{"When": true, "FirstWhen": true, "Calls": true, "CancelAction": true}

	probePaths(t, reflect.TypeOf(base), nil, "", func(steps []probeStep, name string) {
		row := collapseProbeBase()
		setProbe(t, &row, steps, name)
		key, ok := activityCollapseKey(row)
		if !ok {
			t.Errorf("%s: probing it made the row unfoldable, which is an unplanned exclusion rule", name)
			return
		}
		if bookkeeping[name] && key != baseKey {
			t.Errorf("%s is the run's own bookkeeping and must not be in the key", name)
		}
		if !bookkeeping[name] && key == baseKey {
			t.Errorf("%s is not in the collapse key: two rows differing only in it would fold", name)
		}
	})

	same := base
	same.at = testNow
	if key, _ := activityCollapseKey(same); key != baseKey {
		t.Error("the unexported at is in the key")
	}
}

func TestActivityCollapseKey_ADeniedRowNeverFolds(t *testing.T) {
	denied := collapseProbeBase()
	denied.Outcome = jobs.OutcomeName(jobs.OutcomeDeniedByPolicy)
	if _, ok := activityCollapseKey(denied); ok {
		t.Error("a denied row may fold")
	}
	dispatch := collapseProbeBase()
	dispatch.Kind = rowDispatch
	if _, ok := activityCollapseKey(dispatch); ok {
		t.Error("a Job row may fold")
	}
	if got := collapseActivityRows([]activityRow{denied, denied}); len(got) != 2 {
		t.Errorf("two identical denied rows folded into %d", len(got))
	}
}

func TestActivityCollapseKey_DifferentCallsDoNotShareAKey(t *testing.T) {
	base := collapseProbeBase()
	baseKey, _ := activityCollapseKey(base)
	for name, mutate := range map[string]func(*activityRow){
		"JobID":     func(r *activityRow) { r.JobID = "job-2" },
		"Outcome":   func(r *activityRow) { r.Outcome = "refused" },
		"Risk":      func(r *activityRow) { r.Risk = "mutate" },
		"AccountID": func(r *activityRow) { r.AccountID = "acct-2" },
		"Args":      func(r *activityRow) { r.Args = "path=/etc" },
		"NodeID":    func(r *activityRow) { r.NodeID = "node-b" },
	} {
		row := base
		mutate(&row)
		if key, _ := activityCollapseKey(row); key == baseKey {
			t.Errorf("rows differing only in %s share a key", name)
		}
	}
}
