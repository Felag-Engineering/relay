package console

// reads_test.go is spec 17's acceptance criteria, plus the two properties that
// are invisible in a rendered page and are the whole reason this screen was
// rebuilt on the capability layer's read lane: the read/mutate split comes
// from the DECLARED risk class, and the audit lane is never queried without an
// Operation filter.
//
// The bias is towards asserting ABSENCE and the SHAPE OF THE QUERIES. "The
// page shows the refusals" is easy and worth little; "the page never asks the
// trail a question that would count mutate traffic as read egress" is the
// property a helpful change six months from now would quietly remove.

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/auditquery"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

// readsDeps wires a Console to nothing but the read lane, which is all Read
// egress reads.
func readsDeps(q *fakeQueries) Deps {
	d := renderableDeps()
	d.Queries = q
	return d
}

func readsBody(t *testing.T, q *fakeQueries, query string) string {
	t.Helper()
	path := "/console/reads"
	if query != "" {
		path += "?" + query
	}
	rec := get(t, newTestHandler(readsDeps(q), accounts.RoleAdmin), path)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", path, rec.Code)
	}
	return rec.Body.String()
}

// readJob is a read-class Job as the Job lane reports it. The RiskClass is the
// DECLARED one (tasks.risk_class), which is the only thing this screen uses to
// decide what a read is.
func readJob(op, accountID string, risk jobs.RiskClass) capability.JobSummary {
	return capability.JobSummary{
		JobID:              "job-" + op,
		CreatedAt:          testNow.Add(-time.Hour),
		State:              jobs.JobStateComplete,
		ActionKind:         jobs.ActionOperation,
		OperationName:      op,
		RiskClass:          risk,
		Requester:          accountID,
		RequesterAccountID: accountID,
		Total:              1,
	}
}

// readDispatchRow is one read-class dispatch record as the read lane returns it.
// Note what capability.AuditRow has no field for: stdout, stderr, truncated.
func readDispatchRow(op, path, node, accountID string, outcome jobs.Outcome) capability.AuditRow {
	row := capability.AuditRow{
		Timestamp:     testNow.Add(-time.Hour),
		Kind:          audit.KindDispatch,
		OperationName: op,
		NodeID:        node,
		Outcome:       outcome,
	}
	if path != "" {
		row.Args = map[string]string{"path": path}
	}
	if accountID != "" {
		row.Verified = capability.VerifiedIdentity{AccountID: accountID, AccountName: accountID + "-bot"}
	}
	return row
}

// enumRow is one control-plane enumeration or trail query.
func enumRow(tool, accountID string) capability.AuditRow {
	row := capability.AuditRow{
		Timestamp:     testNow.Add(-time.Hour),
		Kind:          audit.KindRead,
		OperationName: tool,
	}
	if accountID != "" {
		row.Verified = capability.VerifiedIdentity{AccountID: accountID, AccountName: accountID + "-bot"}
	}
	return row
}

// auditFilters returns every filter this render sent to the audit half of the
// read lane — pages and aggregates alike. The join guard and the drill-down
// are properties of ALL of them, and a filter that skipped one method is
// exactly the bug worth catching.
func (f *fakeQueries) allAuditFilters() []capability.AuditFilter {
	var out []capability.AuditFilter
	out = append(out, f.auditFilters...)
	out = append(out, f.reachFilters...)
	out = append(out, f.countFilters...)
	return out
}

func namesOperation(f capability.AuditFilter, op string) bool {
	return containsString(f.Operations, op)
}

// squashSpace collapses runs of whitespace, so an assertion about a SENTENCE
// survives the template being re-wrapped.
func squashSpace(s string) string { return strings.Join(strings.Fields(s), " ") }

// TestReads_ReadClassComesFromTheDeclaredClassNotANameList is spec 17's fifth
// acceptance criterion: "covers the whole read catalog, not only file.read".
//
// file.checksum is now IN console/vocab.go's readOperations set (issue #461
// added it to shippedReadCatalog, since it is one of the seven templates
// daemon/packaging/templates.d/relay-read/catalog.toml actually ships), so it
// no longer separates a name-list implementation from a declared-class one —
// both would get it right. customer.pack.metrics is the fixture that still
// does the separating: it is a plausible customer-authored Template Operation
// name that the Console's shipped-catalog mirror will never contain (it ships
// with no first-party pack), so a screen that matched on names would silently
// omit it, which on THIS screen is an undercount of exposure. file.checksum
// stays in the fixture too, because it is spec 17's own named criterion.
func TestReads_ReadClassComesFromTheDeclaredClassNotANameList(t *testing.T) {
	// The fixture only means something while this holds.
	if isReadOperation("customer.pack.metrics") {
		t.Fatal("customer.pack.metrics is in the read vocabulary now — pick another Operation the mirror omits")
	}

	q := &fakeQueries{
		jobs: []capability.JobSummary{
			readJob("file.checksum", "acct-1", jobs.RiskClassRead),
			readJob("customer.pack.metrics", "acct-1", jobs.RiskClassRead),
			readJob("service.restart", "acct-1", jobs.RiskClassMutate),
		},
		rows: []capability.AuditRow{
			readDispatchRow("file.checksum", "/etc/shadow", "n1", "acct-1", jobs.OutcomeSuccess),
			readDispatchRow("customer.pack.metrics", "", "n1", "acct-1", jobs.OutcomeSuccess),
			readDispatchRow("service.restart", "", "n1", "acct-1", jobs.OutcomeSuccess),
		},
	}
	readsBody(t, q, "")

	filters := q.allAuditFilters()
	if len(filters) == 0 {
		t.Fatal("the audit lane was never queried — the declared read-class Job produced no vocabulary")
	}
	sawChecksum := false
	sawCustomer := false
	for _, f := range filters {
		if namesOperation(f, "service.restart") {
			t.Errorf("an audit filter names service.restart, a mutate-class Job: %+v", f.Operations)
		}
		if namesOperation(f, "file.checksum") {
			sawChecksum = true
		}
		if namesOperation(f, "customer.pack.metrics") {
			sawCustomer = true
		}
	}
	if !sawChecksum {
		t.Error("no audit filter names file.checksum — spec 17's named criterion")
	}
	if !sawCustomer {
		t.Error("no audit filter names customer.pack.metrics — the read vocabulary came from a name " +
			"list, not from the declared risk class of the Jobs that ran")
	}
}

// TestReads_NeverQueriesTheAuditLaneWithoutAnOperationFilter is the single
// most important correctness invariant on this page.
//
// capability.AuditFilter's zero value matches every Row, and an empty
// Operations list emits no operation_name condition at all — so an AuditReach
// over Kinds:[dispatch] with no Operations counts EVERY MUTATE DISPATCH in the
// window and reports the fleet's mutate traffic as read egress.
func TestReads_NeverQueriesTheAuditLaneWithoutAnOperationFilter(t *testing.T) {
	q := &fakeQueries{
		// A mutate-class Job and its dispatch rows, and nothing read-class.
		jobs: []capability.JobSummary{readJob("service.restart", "acct-1", jobs.RiskClassMutate)},
		rows: []capability.AuditRow{
			readDispatchRow("service.restart", "", "n1", "acct-1", jobs.OutcomeSuccess),
			readDispatchRow("service.restart", "", "n2", "acct-1", jobs.OutcomeSuccess),
		},
	}
	body := readsBody(t, q, "")

	for _, f := range q.allAuditFilters() {
		if containsString(f.Kinds, audit.KindDispatch) && len(f.Operations) == 0 {
			t.Errorf("a dispatch-kind filter carries no Operation filter: %+v — that matches every "+
				"mutate dispatch in the window and reports it as read egress", f)
		}
	}
	if !strings.Contains(body, "The audit lane was not queried for Node reads.") {
		t.Error("the page does not say the audit lane was skipped — a silent zero and a deliberate " +
			"skip are different claims")
	}
	if strings.Contains(body, "service.restart") {
		t.Error("a mutate Operation appears on the read-egress screen")
	}
}

// TestReads_HeadlineDistinguishesTargetsFromExposures is spec 17's second
// acceptance criterion. One file.read across 4,000 Nodes is ONE target and
// FOUR THOUSAND exposures.
func TestReads_HeadlineDistinguishesTargetsFromExposures(t *testing.T) {
	q := &fakeQueries{
		jobs: []capability.JobSummary{readJob("file.read", "acct-1", jobs.RiskClassRead)},
		reachStub: func(f capability.AuditFilter) capability.Reach {
			if f.Outcome != nil || containsString(f.Kinds, audit.KindRead) {
				return capability.Reach{}
			}
			return capability.Reach{Calls: 4000, DistinctTargets: 1, DistinctNodes: 4000}
		},
	}
	body := readsBody(t, q, "")

	for _, want := range []string{
		`<b>4000</b><span>reads from Nodes</span>`,
		`<b>1</b><span>distinct target</span>`,
		`<b>4000</b><span>Nodes touched</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the headline does not carry %s — exposures, distinct targets and Nodes are "+
				"three different questions and the page must label which it answered", want)
		}
	}
}

// TestReads_RefusalsAreExactAndStyledAsADecision is spec 17's third acceptance
// criterion, in both halves: prominent, and informative-neutral.
//
// The count comes from its OWN aggregate, so it cannot shrink because the
// sample below it was short — "do not bury them" made structural rather than
// promised. And a refusal is slate, never the amber that means "needs
// attention now": foundations gives amber one meaning and Policy working is
// not it.
func TestReads_RefusalsAreExactAndStyledAsADecision(t *testing.T) {
	q := &fakeQueries{
		jobs: []capability.JobSummary{readJob("file.read", "acct-1", jobs.RiskClassRead)},
		// Deliberately ONE row where the aggregate says three: the page must
		// print the aggregate.
		rows: []capability.AuditRow{
			readDispatchRow("file.read", "/etc/shadow", "n1", "acct-1", jobs.OutcomeDeniedByPolicy),
		},
		reachStub: func(f capability.AuditFilter) capability.Reach {
			if f.Outcome != nil {
				return capability.Reach{Calls: 3, DistinctTargets: 2, DistinctNodes: 2}
			}
			return capability.Reach{Calls: 10, DistinctTargets: 4, DistinctNodes: 5}
		},
	}
	body := readsBody(t, q, "")

	if !strings.Contains(body, `<b>3</b><span>refused by Policy</span>`) {
		t.Error("the refusal headline is not the exact aggregate — it was counted from the sample, " +
			"which can be short exactly when the number matters")
	}
	if !strings.Contains(body, `class="stat decision"`) {
		t.Error("the refusal statistic is not styled as a Policy decision")
	}
	if strings.Contains(body, `class="stat attn"`) {
		t.Error("a refusal renders in amber — a deny is Policy working, and amber means " +
			"\"needs attention now\"")
	}

	refused := strings.Index(body, `id="refused"`)
	enum := strings.Index(body, "Control-plane enumeration and trail queries")
	if refused < 0 || enum < 0 || refused > enum {
		t.Errorf("the refusal section is at %d and the enumeration panel at %d — refusals must not "+
			"be buried below the lowest-signal panel on the screen", refused, enum)
	}
}

// TestReads_NeverReachesTheTaskLane is spec 17's fourth acceptance criterion
// made structural.
//
// QueryTasks is the ONLY read-lane method that can carry captured bytes
// (capability.TaskRow has Stdout and Stderr; capability.AuditRow has no field
// for either). A screen that called it to recover a deny rule would be the
// exact regression #423 removed, by a quieter route.
func TestReads_NeverReachesTheTaskLane(t *testing.T) {
	const sentinel = "root:$6$SECRET-HASH"
	q := &fakeQueries{
		jobs: []capability.JobSummary{readJob("file.read", "acct-1", jobs.RiskClassRead)},
		rows: []capability.AuditRow{
			readDispatchRow("file.read", "/etc/shadow", "n1", "acct-1", jobs.OutcomeDeniedByPolicy),
		},
		tasks: []capability.TaskRow{{
			TaskID: "t1", NodeID: "n1", Outcome: jobs.OutcomeDeniedByPolicy,
			RiskClass: jobs.RiskClassRead,
			Stdout:    []byte(sentinel), Stderr: []byte("deny read of /etc/shadow: " + sentinel),
		}},
	}
	body := readsBody(t, q, "")

	if len(q.taskLimits) != 0 {
		t.Errorf("the page made %d Task queries — the Task lane is the only one that can carry "+
			"read output, and this screen must never touch it", len(q.taskLimits))
	}
	if strings.Contains(body, sentinel) {
		t.Error("captured output reached the read-egress page")
	}
	if strings.Contains(body, "deny read of") {
		t.Error("a deny explanation reached the page — for a read-class Task the deciding rule is " +
			"the daemon's own stderr, which the trail deliberately never kept (ADR-0025)")
	}
}

// TestReads_SaysWhatTheTrailActuallyRetains.
//
// The precise claim, not the comfortable one. "Read output was never retained"
// is FALSE: the Task row holds what the daemon sent until the Job is
// collected, and GET /api/v1/jobs/{job_id} hands it back. Telling an incident
// responder the bytes are gone when they are one request away is a claim this
// code cannot back — job.go words it correctly and this page matches it.
func TestReads_SaysWhatTheTrailActuallyRetains(t *testing.T) {
	body := readsBody(t, &fakeQueries{}, "")

	if !strings.Contains(body, "GET /api/v1/jobs/{job_id}") {
		t.Error("the page does not say where the bytes DO still live")
	}
	if !strings.Contains(body, "The audit trail keeps outcomes and timings and never read output") {
		t.Error("the page does not attribute the absence to the AUDIT TRAIL specifically")
	}
	for _, untrue := range []string{"was never retained", "does not exist", "never existed"} {
		if strings.Contains(body, untrue) {
			t.Errorf("the page claims read output %q — the Task row holds it until the Job is "+
				"collected, and the Control API returns it", untrue)
		}
	}
}

// TestReads_OperationFilterCannotSmuggleAMutate.
//
// ?op= is INTERSECTED with the read-class vocabulary the window actually
// produced, never passed through to the audit lane. A caller asking for
// service.restart on the read-egress screen gets an empty result and a stated
// refusal, not mutate rows.
//
// Scoped to the AUDIT filters deliberately: the JOB filter legitimately
// carries the name — that is how the Job lane is asked whether any read-class
// Job ran it — and asserting over every recorded filter would fail against a
// correct implementation.
func TestReads_OperationFilterCannotSmuggleAMutate(t *testing.T) {
	q := &fakeQueries{
		jobs: []capability.JobSummary{
			readJob("file.read", "acct-1", jobs.RiskClassRead),
			readJob("service.restart", "acct-1", jobs.RiskClassMutate),
		},
		rows: []capability.AuditRow{
			readDispatchRow("service.restart", "", "n1", "acct-1", jobs.OutcomeSuccess),
		},
	}
	body := readsBody(t, q, "op=service.restart")

	for _, f := range q.allAuditFilters() {
		if namesOperation(f, "service.restart") {
			t.Errorf("an audit filter names service.restart: %+v — ?op= was passed through instead "+
				"of intersected with the declared read-class vocabulary", f.Operations)
		}
	}
	if len(q.jobFilters) == 0 || q.jobFilters[0].Operation != "service.restart" {
		t.Error("the Job lane was not asked about the requested Operation at all")
	}
	if !strings.Contains(body, "No read-class Job ran") {
		t.Error("the page does not say why the Operation produced nothing")
	}
}

// TestReads_QueryCountIsFixedRegardlessOfVolume.
//
// Bounded by construction, not capped after the fact. The tempting N+1 — one
// QueryAudit{JobID} per read Job, to recover its path argument — scales with
// volume AND writes one audit record per Job per page view, on a screen whose
// own reads are already counted by itself.
func TestReads_QueryCountIsFixedRegardlessOfVolume(t *testing.T) {
	small := &fakeQueries{
		jobs: []capability.JobSummary{
			readJob("file.read", "acct-1", jobs.RiskClassRead),
			readJob("log.tail", "acct-1", jobs.RiskClassRead),
			readJob("system.facts", "acct-1", jobs.RiskClassRead),
		},
		rows: []capability.AuditRow{
			readDispatchRow("file.read", "/etc/hosts", "n1", "acct-1", jobs.OutcomeSuccess),
			readDispatchRow("log.tail", "", "n1", "acct-1", jobs.OutcomeSuccess),
			enumRow("list_nodes", "acct-1"),
		},
	}

	large := &fakeQueries{}
	ops := []string{"file.read", "log.tail", "system.facts", "disk.usage", "proc.list"}
	for i := 0; i < 500; i++ {
		j := readJob(ops[i%len(ops)], "acct-1", jobs.RiskClassRead)
		j.JobID = fmt.Sprintf("job-%04d", i)
		large.jobs = append(large.jobs, j)
	}
	for i := 0; i < 5000; i++ {
		large.rows = append(large.rows, readDispatchRow(ops[i%len(ops)],
			fmt.Sprintf("/var/log/%d", i), fmt.Sprintf("n%04d", i), "acct-1", jobs.OutcomeSuccess))
	}

	readsBody(t, small, "")
	readsBody(t, large, "")

	for _, c := range []struct {
		what       string
		got, want  int
		smallCount int
	}{
		{"Job queries", len(large.jobFilters), len(small.jobFilters), len(small.jobFilters)},
		{"audit pages", len(large.auditFilters), len(small.auditFilters), len(small.auditFilters)},
		{"reach aggregates", len(large.reachFilters), len(small.reachFilters), len(small.reachFilters)},
		{"count aggregates", len(large.countFilters), len(small.countFilters), len(small.countFilters)},
	} {
		if c.got != c.want {
			t.Errorf("a 500-Job / 5,000-record window cost %d %s and a 3-Job one cost %d — the page "+
				"fans out with volume", c.got, c.what, c.want)
		}
	}

	for _, q := range []*fakeQueries{small, large} {
		for _, limit := range append(append([]int{}, q.auditLimits...), q.jobLimits...) {
			if limit <= 0 || limit > capability.MaxPageSize {
				t.Errorf("a page was fetched with limit %d, outside (0, %d]", limit, capability.MaxPageSize)
			}
		}
	}
}

// TestReads_PerPrincipalTrendComesFromTheBaselineNotTheTotal.
//
// Spec 17: "a machine Account whose read volume jumped tenfold this week is
// the single most useful row this screen can produce". Against its OWN
// baseline — a busy Account is not interesting and a quiet one that stops
// being quiet is.
func TestReads_PerPrincipalTrendComesFromTheBaselineNotTheTotal(t *testing.T) {
	window := readWindowFor(readWindowDefault).Duration
	width := window / readBuckets
	since := testNow.Add(-window)
	// at(k) is the start of the k-th WHOLE bucket of the window. The extra
	// one an hour later is the bucket that is still filling: it is real, it is
	// small because only part of it has happened, and comparing it against
	// eleven whole buckets is the systematic false negative trendOf drops it
	// to avoid.
	at := func(k int) time.Time { return since.Add(time.Duration(k) * width) }
	partial := at(readBuckets - 1).Add(time.Hour)

	bucket := func(account string, n int, start time.Time) capability.PrincipalBucket {
		return capability.PrincipalBucket{
			AccountID: account, AccountName: account + "-bot", Start: start, Count: n,
		}
	}
	q := &fakeQueries{
		jobs: []capability.JobSummary{readJob("file.read", "acct-spike", jobs.RiskClassRead)},
		countsStub: func(f capability.AuditFilter) []capability.PrincipalBucket {
			if containsString(f.Kinds, audit.KindRead) {
				return nil
			}
			return []capability.PrincipalBucket{
				bucket("acct-spike", 2, at(0)),
				bucket("acct-spike", 2, at(1)),
				bucket("acct-spike", 2, at(2)),
				bucket("acct-spike", 20, at(3)),
				bucket("acct-spike", 1, partial),
				bucket("acct-flat", 2, at(0)),
				bucket("acct-flat", 2, at(1)),
				bucket("acct-flat", 2, at(2)),
				bucket("acct-flat", 2, at(3)),
				bucket("acct-flat", 1, partial),
			}
		},
	}
	body := readsBody(t, q, "")

	// The VOLUME column sums every bucket, partial included — it is a total,
	// and a total that dropped the most recent hour would be wrong.
	if !strings.Contains(body, `<td class="num">27</td>`) {
		t.Error("the spiking Account does not report the 27 reads its buckets sum to")
	}
	if !strings.Contains(body, `<td class="num">9</td>`) {
		t.Error("the flat Account does not report the 9 reads its buckets sum to")
	}
	// The TREND compares whole buckets only. Keeping the partial one makes the
	// spiking Account's most recent bucket a 1 against a baseline of 6.5 and
	// the rise disappears — which is the bias, seen from the inside.
	if n := strings.Count(body, `class="trend rise"`); n != 1 {
		t.Errorf("%d Accounts are marked as rising, want exactly 1 — the trend is being computed "+
			"from the window total, or from a bucket the window clipped, rather than against each "+
			"Account's own baseline of whole buckets", n)
	}
}

// TestReads_TargetTableSaysItIsASample.
//
// job.go's rule: the count above is exact, everything below is computed over
// the N listed. A page that prints a number it did not compute has nothing to
// offer an operator reading it during an incident.
func TestReads_TargetTableSaysItIsASample(t *testing.T) {
	q := &fakeQueries{
		jobs: []capability.JobSummary{readJob("file.read", "acct-1", jobs.RiskClassRead)},
		// The aggregate agrees with the page LENGTH, so the only signal that
		// the table is short is the cursor the lane returned.
		reachStub: func(f capability.AuditFilter) capability.Reach {
			if f.Outcome != nil || containsString(f.Kinds, audit.KindRead) {
				return capability.Reach{}
			}
			return capability.Reach{Calls: readTargetRows, DistinctTargets: readTargetRows, DistinctNodes: 1}
		},
	}
	for i := 0; i <= readTargetRows; i++ {
		q.rows = append(q.rows, readDispatchRow("file.read",
			fmt.Sprintf("/var/log/%d", i), "n1", "acct-1", jobs.OutcomeSuccess))
	}
	body := readsBody(t, q, "")

	if !strings.Contains(squashSpace(body), fmt.Sprintf("computed over the most recent %d records", readTargetRows)) {
		t.Errorf("the by-target table does not say it is computed over the most recent %d records", readTargetRows)
	}
	if !strings.Contains(body, "The counts above are exact") {
		t.Error("the sampled table does not say the counts above it are still exact")
	}
}

// TestReads_TargetKeyFollowsTheTrailsOwnPrecedence.
//
// The store builds AuditReach's distinct-target COALESCE from
// audit.TargetArgKeys (internal/store/auditquery.go's reachTargetExpr). A
// divergent order here makes this page's headline and its table disagree about
// how many distinct things were read.
//
// The second half REORDERS audit.TargetArgKeys and asserts the naming follows.
// That is what distinguishes "reads the shared slice" from "happens to hold a
// byte-identical copy of it" — a copied literal passes every assertion built
// from the slice's current contents.
func TestReads_TargetKeyFollowsTheTrailsOwnPrecedence(t *testing.T) {
	if len(audit.TargetArgKeys) < 2 {
		t.Fatalf("audit.TargetArgKeys = %v — this test proves a PRECEDENCE order and "+
			"needs at least two keys to have one. A shorter list means the trail "+
			"changed shape and this test must be rewritten, not skipped.",
			audit.TargetArgKeys)
	}
	first, second := audit.TargetArgKeys[0], audit.TargetArgKeys[1]

	args := map[string]string{first: "/etc/hosts", second: "nginx"}
	if got := readTargetName("file.read", "", args); got != "file.read /etc/hosts" {
		t.Errorf("readTargetName = %q, want the first key in audit.TargetArgKeys to win", got)
	}
	if got := readTargetName("file.read", "", map[string]string{second: "nginx"}); got != "file.read nginx" {
		t.Errorf("readTargetName = %q, want the second key when the first is absent", got)
	}
	// An explicitly EMPTY value falls through to the next key. This is the one
	// documented divergence from the store's COALESCE, which stops at the
	// first key PRESENT; it is unreachable today because no catalog Operation
	// carries two of these keys.
	if got := readTargetName("file.read", "", map[string]string{first: "", second: "nginx"}); got != "file.read nginx" {
		t.Errorf("readTargetName = %q, want an empty first key to fall through", got)
	}

	// Reordered. A local copy of the key list does not move.
	//
	// Hazard: this mutates a package-level var owned by another package and restores
	// it with t.Cleanup. That is only sound while nothing runs
	// concurrently with it — do not add t.Parallel to this test, or to any
	// test that reads audit.TargetArgKeys, without replacing this seam.
	original := audit.TargetArgKeys
	t.Cleanup(func() { audit.TargetArgKeys = original })
	audit.TargetArgKeys = []string{second, first}
	if got := readTargetName("file.read", "", args); got != "file.read nginx" {
		t.Errorf("readTargetName = %q after reordering audit.TargetArgKeys — this screen holds its "+
			"own copy of the precedence order, which is exactly how it drifts from the store's COALESCE", got)
	}
}

// TestReads_WindowIsAClosedSetAndAlwaysBounded.
//
// The aggregate paths refuse a window wider than
// capability.MaxAggregateWindow AND one that does not end after it starts
// (capability.AuditFilter.validateWindow, .validate). Both refusals arrive as
// a 500 on a URL a caller typed, so the window is a closed set rather than a
// parsed duration — note "-1s", which time.ParseDuration accepts happily.
func TestReads_WindowIsAClosedSetAndAlwaysBounded(t *testing.T) {
	for _, window := range []string{"", "7d", "24h", "30d", "999d", "abc", "-1s", "9999999h"} {
		q := &fakeQueries{
			jobs: []capability.JobSummary{readJob("file.read", "acct-1", jobs.RiskClassRead)},
			rows: []capability.AuditRow{
				readDispatchRow("file.read", "/etc/hosts", "n1", "acct-1", jobs.OutcomeSuccess),
				enumRow("list_nodes", "acct-1"),
			},
		}
		readsBody(t, q, "window="+window)

		check := func(what string, since, until time.Time) {
			switch {
			case since.IsZero() || until.IsZero():
				t.Errorf("?window=%q produced an unbounded %s window — the aggregate paths refuse one", window, what)
			case !until.After(since):
				t.Errorf("?window=%q produced a %s window that ends at or before it starts", window, what)
			case until.Sub(since) > capability.MaxAggregateWindow:
				t.Errorf("?window=%q produced a %s window of %s, past the lane's maximum of %s",
					window, what, until.Sub(since), capability.MaxAggregateWindow)
			}
		}
		for _, f := range q.allAuditFilters() {
			check("audit", f.Since, f.Until)
		}
		for _, f := range q.jobFilters {
			check("Job", f.Since, f.Until)
		}
	}
}

// TestReads_RefusesOversizedFilterValuesBeforeTheReadLane.
//
// job.go's rule: a caller-controlled value is refused BEFORE it reaches the
// read lane, because the lane records its filter in the append-only trail as
// the read's own selector. capability.AuditFilter.validate bounds Kinds,
// Operations and ArgValuePrefix — it does NOT bound AccountID or NodeID, so
// this screen is the only bound on those two.
func TestReads_RefusesOversizedFilterValuesBeforeTheReadLane(t *testing.T) {
	longPath := "/" + strings.Repeat("p", 300)
	longNode := strings.Repeat("n", 200)
	longPrincipal := strings.Repeat("a", 200)

	q := &fakeQueries{jobs: []capability.JobSummary{readJob("file.read", "acct-1", jobs.RiskClassRead)}}
	body := readsBody(t, q, "path="+longPath+"&node="+longNode+"&principal="+longPrincipal)

	for _, f := range q.allAuditFilters() {
		if strings.Contains(f.ArgValuePrefix, "ppppp") {
			t.Error("the over-long path prefix reached the read lane, and the trail recorded it")
		}
		if f.NodeID == longNode {
			t.Error("the over-long Node id reached the read lane, and the trail recorded it")
		}
		if f.AccountID == longPrincipal {
			t.Error("the over-long principal reached the read lane, and the trail recorded it")
		}
	}
	for _, f := range q.jobFilters {
		if f.RequesterAccountID == longPrincipal {
			t.Error("the over-long principal reached the Job lane")
		}
	}
	if n := strings.Count(body, "was refused before it reached the query lane"); n != 3 {
		t.Errorf("the page states %d refused filter values, want 3 — a value dropped silently is a "+
			"page answering a different question than the one asked", n)
	}
}

// TestReads_DecisionColourIsDefinedInTheStylesheet.
//
// The failure this guards is silent: a class applied in HTML with no rule
// behind it renders as ordinary text, and nothing in Go can see it — the same
// failure components.go records for the outcome bar's grow steps.
func TestReads_DecisionColourIsDefinedInTheStylesheet(t *testing.T) {
	css := get(t, newTestHandler(renderableDeps(), accounts.RoleAdmin),
		"/console/assets/console.css").Body.String()

	for _, rule := range []string{
		".stat.decision { border-color: var(--decision-line); background: var(--decision-bg); }",
		"tr.denyrow td { background: var(--decision-bg); }",
	} {
		if !strings.Contains(css, rule) {
			t.Errorf("the stylesheet has no rule %q — a refusal renders as ordinary text, and the "+
				"one place the deny grammar is visible is the one place it is missing", rule)
		}
	}
	if !strings.Contains(css, ".trend.rise") {
		t.Error("the stylesheet has no rule for a rising trend")
	}
	// Slate, not amber. If either rule ever reached for --attention the deny
	// grammar would say "alarm" on the screen that argues a deny is Policy
	// working.
	for _, rule := range []string{".stat.decision", "tr.denyrow td"} {
		i := strings.Index(css, rule)
		if i >= 0 && strings.Contains(css[i:i+120], "--attention") {
			t.Errorf("%s uses the attention colour — a deny is a Policy decision, not an alarm", rule)
		}
	}
}

// TestReads_EnumerationPanelNamesTheConsolesOwnTrailReads.
//
// The read lane records a read of the trail AS A READ, so this screen's own
// queries appear in its own enumeration panel. They are labelled rather than
// filtered out: filtering them would take a second hardcoded name list — the
// exact smell this rebuild removed — and "who queried the audit trail" is
// legitimately part of read egress.
func TestReads_EnumerationPanelNamesTheConsolesOwnTrailReads(t *testing.T) {
	q := &fakeQueries{
		rows: []capability.AuditRow{
			enumRow("query_audit", "acct-1"),
			enumRow("list_nodes", "acct-1"),
		},
	}
	body := readsBody(t, q, "")

	if !strings.Contains(body, "query_audit") || !strings.Contains(body, "list_nodes") {
		t.Error("the enumeration panel does not name the tools that were called")
	}
	if !strings.Contains(body, "this view wrote") {
		t.Error("the page does not admit that reading it writes its own read records — leaving " +
			"query_audit rows unexplained on the screen about who read what")
	}
	if !strings.Contains(body, "it already includes it") {
		t.Error("the page does not say the enumeration figure ALREADY counts this view's own " +
			"queries — the read lane writes its record before the query runs, so the disclosure " +
			"understates by exactly the amount that makes it confusing")
	}

	// The disclosure is about what THIS VIEW cost, so it cannot live inside
	// the enumeration table's own {{if}}: a page with no enumeration rows —
	// every ?op= and ?path= page, and any window with none — still wrote its
	// records, and is where an operator is most likely to wonder where the
	// query_audit rows on the next view came from.
	quiet := &fakeQueries{jobs: []capability.JobSummary{readJob("file.read", "acct-1", jobs.RiskClassRead)}}
	if body := readsBody(t, quiet, "op=file.read"); !strings.Contains(body, "this view wrote") {
		t.Error("a page with no enumeration rows does not say what reading it cost")
	}
}

// TestReads_PrincipalDrilldownScopesEveryQuery is spec 17's first acceptance
// criterion: "answers what has this principal read in this window, and from
// where".
//
// EVERY filter, including the enumeration lane's. A principal threaded into
// some queries and not others is the failure mode that makes a scoped page
// silently show another Account's figures.
func TestReads_PrincipalDrilldownScopesEveryQuery(t *testing.T) {
	q := &fakeQueries{
		jobs: []capability.JobSummary{
			readJob("file.read", "acct-1", jobs.RiskClassRead),
			readJob("log.tail", "acct-2", jobs.RiskClassRead),
		},
		rows: []capability.AuditRow{
			readDispatchRow("file.read", "/etc/hosts", "n1", "acct-1", jobs.OutcomeSuccess),
			readDispatchRow("log.tail", "", "n1", "acct-2", jobs.OutcomeSuccess),
			enumRow("list_nodes", "acct-2"),
		},
	}
	readsBody(t, q, "principal=acct-1")

	if len(q.allAuditFilters()) == 0 {
		t.Fatal("no audit query ran at all")
	}
	for _, f := range q.allAuditFilters() {
		if f.AccountID != "acct-1" {
			t.Errorf("an audit filter is scoped to %q, not to the requested principal: %+v", f.AccountID, f)
		}
	}
	for _, f := range q.jobFilters {
		if f.RequesterAccountID != "acct-1" {
			t.Errorf("the Job filter is scoped to %q, not to the requested principal", f.RequesterAccountID)
		}
	}
}

// TestReads_ReadsNothingButTheQueryLane is spec 17's sixth acceptance
// criterion made structural (invariant 10).
//
// Two ways read output or unretained rule text could re-enter this screen: the
// whole-trail reader, and a deny explanation. Neither may be named here.
func TestReads_ReadsNothingButTheQueryLane(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "reads.go", nil, 0)
	if err != nil {
		t.Fatalf("parse reads.go: %v", err)
	}

	banned := map[string]string{
		"denyText":        "renders a deny explanation — for a read-class Task the deciding rule is the daemon's own stderr, which the trail never kept (ADR-0025)",
		"denyExplanation": "renders a deny explanation — see denyText above",
		"Deny":            "builds a Deny block, which carries rule text this screen must never have",
		"QueryTasks":      "reaches the Task lane, the only read-lane method that can carry captured bytes",
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			if why, bad := banned[node.Name]; bad {
				t.Errorf("reads.go names %s at %s — it %s", node.Name, fset.Position(node.Pos()), why)
			}
		case *ast.SelectorExpr:
			// d.Audit: the whole-trail reader this screen no longer uses.
			if x, ok := node.X.(*ast.Ident); ok && x.Name == "d" && node.Sel.Name == "Audit" {
				t.Errorf("reads.go reads d.Audit at %s — the whole-trail reader materialises every "+
					"record, output included, and this screen reads the query lane only",
					fset.Position(node.Pos()))
			}
		}
		return true
	})
}

// TestReads_UnwiredQueryLaneRefusesRatherThanRenderingEmpty. An empty
// read-egress page is a claim about exposure — "nothing has been read" — made
// because nobody wired a seam.
func TestReads_UnwiredQueryLaneRefusesRatherThanRenderingEmpty(t *testing.T) {
	d := renderableDeps()
	d.Queries = nil
	rec := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/reads")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("read egress with no query lane wired = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not an empty fleet") {
		t.Error("the refusal does not distinguish a wiring problem from an empty trail")
	}
}

// TestReads_RepeatedReadOfOnePathDoesNotInflateItsNodeCount is the regression
// the dev fleet exposed, carried across from the trail-reading build: three
// Nodes read five times must read "3 Nodes", not "15".
func TestReads_RepeatedReadOfOnePathDoesNotInflateItsNodeCount(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{readJob("file.read", "acct-1", jobs.RiskClassRead)}}
	for i := 0; i < 5; i++ {
		for _, node := range []string{"n1", "n2", "n3"} {
			q.rows = append(q.rows, readDispatchRow("file.read", "/etc/shadow", node, "acct-1",
				jobs.OutcomeDeniedByPolicy))
		}
	}
	body := readsBody(t, q, "")

	// One target row: 15 calls across 3 distinct Nodes, all refused.
	want := `<td><code>file.read /etc/shadow</code></td> <td class="num">15</td> <td class="num">3</td>`
	if !strings.Contains(squashSpace(body), want) {
		t.Error("the by-target row does not report 15 calls across 3 distinct Nodes — counting " +
			"records instead of Nodes makes a repeated read report more Nodes than the fleet holds, " +
			"on the screen whose job is to say how far an agent reached")
	}
}

// TestReads_EnumerationsAreCountedApartFromNodeReads.
//
// list_nodes and list_operations touch no Node and can carry no Policy verdict
// — Policy is a Node's, and there is no Node. Both families are exposure and
// both are counted; blending them makes each number mean less on the screen
// whose whole argument is that reading is exfiltration.
func TestReads_EnumerationsAreCountedApartFromNodeReads(t *testing.T) {
	q := &fakeQueries{
		jobs: []capability.JobSummary{readJob("file.read", "acct-1", jobs.RiskClassRead)},
		rows: []capability.AuditRow{
			readDispatchRow("file.read", "/etc/shadow", "n1", "acct-1", jobs.OutcomeDeniedByPolicy),
			enumRow("list_nodes", "acct-1"),
			enumRow("list_nodes", "acct-1"),
			enumRow("list_operations", "acct-1"),
		},
	}
	body := readsBody(t, q, "")

	if !strings.Contains(body, `<b>1</b><span>read from a Node</span>`) {
		t.Error("the Node-read headline is not 1 — an enumeration was folded into it")
	}
	if !strings.Contains(body, `<b>3</b><span>control-plane enumerations</span>`) {
		t.Error("the enumeration headline is not 3")
	}
	// The by-target table is Node reads only: an enumeration in it carries
	// "0 Nodes" beside rows with a real reach.
	targets := body[strings.Index(body, "By target"):strings.Index(body, "Refused by Policy")]
	if strings.Contains(targets, "list_nodes") {
		t.Error("an enumeration appears in the by-target table, where every row is supposed to have " +
			"reached a machine")
	}
	// Per principal, the two families stay in their own columns: one Node read
	// and three enumerations for the one Account.
	if !strings.Contains(squashSpace(body), `<td class="num">1</td> <td class="num">3</td>`) {
		t.Error("the by-principal row does not keep Node reads and enumerations in separate columns")
	}
}

// enumHeadlinePattern extracts the headline enumeration figure —
// `<b>N</b><span>control-plane enumeration(s)</span>` — from a rendered
// Read-egress page.
var enumHeadlinePattern = regexp.MustCompile(`<b>(\d+)</b><span>control-plane enumerations?</span>`)

// principalEnumPattern extracts the By-principal table's Enumerations cell —
// the second `<td class="num">` after the row's trust chip — for the
// Account named by its rendered display text.
func principalEnumPattern(account string) *regexp.Regexp {
	return regexp.MustCompile(`(?s)>` + regexp.QuoteMeta(account) + `</span></td>\s*` +
		`<td class="num">\d+</td>\s*<td class="num">(\d+)</td>`)
}

// TestReads_EnumerationHeadlineAndPrincipalTableAreOneSnapshot (#640, item 6).
//
// The fixtures elsewhere in this file are fakeQueries, which answer instantly
// and cannot reproduce the bug: the read lane records each query's OWN
// KindRead record before that query runs (capability/readlane.go), so the
// headline and the by-principal Enumerations column disagreed by exactly the
// number of the page's own reads that landed between the two aggregates that
// used to compute them. Only a REAL store, sink and query engine reproduce
// that ordering, so this test is store-backed rather than fakeQueries-backed
// — and it must FAIL on the code before this change (a difference of 2).
func TestReads_EnumerationHeadlineAndPrincipalTableAreOneSnapshot(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	sink := auditsink.New(st.Audit(), auditsink.WithClock(func() time.Time { return testNow }))
	q := auditquery.New(st.AuditQueries(), st.JobQueries())
	svc := capability.New(registry.NewInMemory(),
		capability.WithAuditSink(sink),
		capability.WithQueries(q, q),
	)

	// The same verified principal the handler authenticates as (newTestHandler
	// -> roleVerifier{RoleAdmin}), so these seeded records land in the same
	// by-principal row the page's own reads do.
	admin := capability.Principal{
		AccountID: testAccountID(accounts.RoleAdmin),
		Account:   testAccountName(accounts.RoleAdmin),
		Role:      string(accounts.RoleAdmin),
		Kind:      string(accounts.KindHuman),
	}
	ctx := context.Background()
	for _, tool := range []string{"list_nodes", "list_operations", "list_nodes"} {
		if err := sink.RecordRead(ctx, admin, tool, "", "", ""); err != nil {
			t.Fatalf("RecordRead(%q): %v", tool, err)
		}
	}

	d := renderableDeps()
	d.Queries = svc
	d.Now = func() time.Time { return testNow }

	rec := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/reads")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /console/reads = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	headlineMatch := enumHeadlinePattern.FindStringSubmatch(body)
	if headlineMatch == nil {
		t.Fatalf("the enumeration headline did not render at all:\n%s", body)
	}
	principalMatch := principalEnumPattern(testAccountName(accounts.RoleAdmin)).FindStringSubmatch(body)
	if principalMatch == nil {
		t.Fatalf("the by-principal Enumerations cell did not render for %q:\n%s",
			testAccountName(accounts.RoleAdmin), body)
	}
	if headlineMatch[1] != principalMatch[1] {
		t.Errorf("headline enumeration figure = %s, by-principal Enumerations cell = %s — they must "+
			"come from the same aggregate and agree", headlineMatch[1], principalMatch[1])
	}
	// Greater than the 3 seeded records: the page's own reads (this render's
	// QueryJobs/AuditCounts/QueryAudit calls) are counted too, and counted
	// identically in both figures.
	if headlineMatch[1] == "3" {
		t.Error("the headline is exactly the 3 seeded records — the page's own reads are not being " +
			"counted, so this test is not exercising the gap it exists to close")
	}
}

// TestReads_UnattributedEnumerationsAreNotDroppedFromThePrincipalTable (#640
// cycle-2 review, NON-BLOCKING 1b). Q7's headline now sums EVERY bucket
// AuditCounts returns, including one with no AccountID at all — a caller
// whose identity did not verify. principalRows keys its map on AccountID
// too, including "", so that bucket becomes a row of its own ("unattributed")
// rather than being folded into, or dropped from, an attributed Account's
// row. This pins that the headline and the by-principal SUM stay equal by
// construction even when a bucket carries no Account — the case BLOCKING 2's
// review comment asked to be verified rather than assumed.
func TestReads_UnattributedEnumerationsAreNotDroppedFromThePrincipalTable(t *testing.T) {
	q := &fakeQueries{
		jobs: []capability.JobSummary{readJob("file.read", "acct-1", jobs.RiskClassRead)},
		rows: []capability.AuditRow{
			readDispatchRow("file.read", "/etc/shadow", "n1", "acct-1", jobs.OutcomeSuccess),
			enumRow("list_nodes", "acct-1"),
			enumRow("list_operations", ""), // no verified identity: AccountID == ""
		},
	}
	body := readsBody(t, q, "")

	headlineMatch := enumHeadlinePattern.FindStringSubmatch(body)
	if headlineMatch == nil {
		t.Fatalf("the enumeration headline did not render at all:\n%s", body)
	}
	if headlineMatch[1] != "2" {
		t.Fatalf("headline = %s, want 2 (one attributed enumeration, one unattributed)", headlineMatch[1])
	}

	attributed := principalEnumPattern("acct-1-bot").FindStringSubmatch(body)
	if attributed == nil {
		t.Fatalf("no By-principal Enumerations cell for acct-1-bot:\n%s", body)
	}
	unattributed := principalEnumPattern("unattributed").FindStringSubmatch(body)
	if unattributed == nil {
		t.Fatalf("the unattributed enumeration is missing its own By-principal row:\n%s", body)
	}

	got := mustAtoi(t, attributed[1]) + mustAtoi(t, unattributed[1])
	want := mustAtoi(t, headlineMatch[1])
	if got != want {
		t.Errorf("By-principal Enumerations sum = %d (attributed %s + unattributed %s), "+
			"headline = %d — an unattributed bucket must be counted in both, not dropped from either",
			got, attributed[1], unattributed[1], want)
	}
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("Atoi(%q): %v", s, err)
	}
	return n
}

// riskBlindQueries satisfies QueryReader and IGNORES JobFilter.RiskClass —
// a seam that conforms by signature and not by contract.
//
// It is the whole point of the test below: with the declared-class check
// living only in the Job lane's SQL, every assertion this file makes about the
// join guard would be proving a property of fakeQueries, which was written in
// the same change as the screen.
type riskBlindQueries struct{ *fakeQueries }

func (q riskBlindQueries) QueryJobs(ctx context.Context, p capability.Principal, f capability.JobFilter, page capability.PageRequest) (capability.JobPage, error) {
	f.RiskClass = nil
	return q.fakeQueries.QueryJobs(ctx, p, f, page)
}

// TestReads_DeclaredClassIsRecheckedAgainstASeamThatIgnoresTheFilter.
//
// The read/mutate decision is DECLARED (invariant 13), and this screen must
// hold it itself rather than delegate it entirely to store/jobquery.go's
// `t.risk_class = ?`. Without the re-check, a Job lane that returns mutate
// Jobs puts `service.restart` into four AuditFilter.Operations lists and the
// page reports mutate dispatches as read egress, under headings that say read.
func TestReads_DeclaredClassIsRecheckedAgainstASeamThatIgnoresTheFilter(t *testing.T) {
	q := &fakeQueries{
		jobs: []capability.JobSummary{
			readJob("service.restart", "acct-1", jobs.RiskClassMutate),
			readJob("systemctl.daemon-reload", "acct-1", jobs.RiskClassUnspecified),
		},
		rows: []capability.AuditRow{
			readDispatchRow("service.restart", "", "n1", "acct-1", jobs.OutcomeSuccess),
			readDispatchRow("service.restart", "", "n2", "acct-1", jobs.OutcomeSuccess),
		},
	}
	d := readsDeps(q)
	d.Queries = riskBlindQueries{q}

	rec := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/reads")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /console/reads = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	for _, f := range q.allAuditFilters() {
		for _, op := range f.Operations {
			if op == "service.restart" || op == "systemctl.daemon-reload" {
				t.Errorf("an audit filter names %q — the declared-class gate lives only in the Job "+
					"lane, so a seam that ignores JobFilter.RiskClass turns mutate traffic into "+
					"read egress", op)
			}
		}
	}
	if strings.Contains(body, "reads from Nodes</span>") {
		t.Error("the page reports Node reads for a window whose only Jobs are mutate-class")
	}
	if !strings.Contains(body, "The audit lane was not queried for Node reads.") {
		t.Error("the page does not say the Node-read lane was skipped")
	}
}

// TestReads_AFailedAggregateIsAbsentNotZero.
//
// The zero value of an int and an exact count of nothing render as the same
// three pixels and make OPPOSITE claims. "0 refused by Policy", printed
// directly above a listed refusal of /etc/shadow because the aggregate errored,
// is the page contradicting itself in favour of the reassuring half — during
// the incident someone opened it for.
func TestReads_AFailedAggregateIsAbsentNotZero(t *testing.T) {
	q := &fakeQueries{
		jobs: []capability.JobSummary{readJob("file.read", "acct-1", jobs.RiskClassRead)},
		rows: []capability.AuditRow{
			readDispatchRow("file.read", "/etc/shadow", "n1", "acct-1", jobs.OutcomeDeniedByPolicy),
			readDispatchRow("file.read", "/etc/hosts", "n1", "acct-1", jobs.OutcomeSuccess),
		},
		// Only the REFUSAL aggregate fails. Everything else answers.
		reachErrOn: func(f capability.AuditFilter) bool { return f.Outcome != nil },
	}
	body := readsBody(t, q, "")

	if strings.Contains(body, `<span>refused by Policy</span>`) {
		t.Error("the refusal tile rendered although its aggregate failed — an exact zero is the " +
			"strongest claim on this screen and it was manufactured by a failed query")
	}
	if !strings.Contains(body, "The exact refusal count could not be computed") {
		t.Error("the page does not say the refusal count is missing")
	}
	if strings.Contains(body, "These three figures are exact over the") {
		t.Error("the page still claims the refusal figures are exact")
	}
	// And the row that contradicts the zero is still there, which is the whole
	// reason the zero would have been a lie.
	if !strings.Contains(body, "file.read /etc/shadow") {
		t.Error("the refused read is not listed at all — the fixture no longer tests anything")
	}

	// The other half: with NOTHING measured, the page must not say "nothing
	// has been read", which is a positive claim of zero exposure manufactured
	// by two failed queries.
	quiet := &fakeQueries{
		rows:        []capability.AuditRow{enumRow("list_nodes", "acct-1")},
		reachErrOn:  func(capability.AuditFilter) bool { return true },
		countsErrOn: func(capability.AuditFilter) bool { return true },
	}
	body = readsBody(t, quiet, "")
	if strings.Contains(body, "Nothing has been read in this window.") {
		t.Error("two failed queries and a skipped lane rendered as a measurement of zero exposure")
	}
	if !strings.Contains(body, "makes no claim about") {
		t.Error("the page does not distinguish \"nothing was read\" from \"nothing could be measured\"")
	}
}

// TestReads_NoFigureIsShownForALaneThatWasNotQueried.
//
// The suppression reasoning has to reach the STATISTIC, not only the table.
// A headline reading "0 control-plane enumerations" above a panel correctly
// explaining that the enumeration lane was not queried is the page arguing
// with itself, and the headline is the half an operator reads.
func TestReads_NoFigureIsShownForALaneThatWasNotQueried(t *testing.T) {
	// Under ?op=, the enumeration lane is deliberately not queried.
	q := &fakeQueries{
		jobs: []capability.JobSummary{readJob("file.read", "acct-1", jobs.RiskClassRead)},
		rows: []capability.AuditRow{
			readDispatchRow("file.read", "/etc/hosts", "n1", "acct-1", jobs.OutcomeSuccess),
			enumRow("list_nodes", "acct-1"),
		},
	}
	body := readsBody(t, q, "op=file.read")
	if strings.Contains(body, "control-plane enumeration") && strings.Contains(body, "<span>control-plane") {
		t.Error("the headline carries an enumeration figure although the enumeration lane was not queried")
	}
	if !strings.Contains(body, "The headline carries no enumeration figure for the") {
		t.Error("the page does not say why the enumeration figure is absent")
	}

	// And the mirror case: the join guard fired, so the Node-read lane was not
	// queried, but enumerations were.
	guarded := &fakeQueries{rows: []capability.AuditRow{enumRow("list_nodes", "acct-1")}}
	body = readsBody(t, guarded, "")
	if strings.Contains(body, "reads from Nodes</span>") || strings.Contains(body, "distinct target") {
		t.Error("the headline carries Node-read figures although the join guard skipped that lane")
	}
	if !strings.Contains(body, "<span>control-plane enumeration</span>") {
		t.Error("the enumeration figure is missing although its lane WAS queried")
	}
}

// TestReads_PrincipalTableSurvivesTheJoinGuard.
//
// Q9 (AuditCounts over KindRead) sits OUTSIDE the join guard for one reason:
// an Account that has only enumerated must still appear on a page that is
// simultaneously reporting its enumerations. Moving Q9 inside the guard leaves
// "By principal" empty beside a headline of N enumerations, which is spec 17's
// first acceptance criterion answered for one of its two families.
func TestReads_PrincipalTableSurvivesTheJoinGuard(t *testing.T) {
	q := &fakeQueries{
		// No read-class Job at all: the guard WILL fire.
		rows: []capability.AuditRow{
			enumRow("list_nodes", "acct-enum"),
			enumRow("list_operations", "acct-enum"),
		},
	}
	body := readsBody(t, q, "")

	if !strings.Contains(body, "The audit lane was not queried for Node reads.") {
		t.Fatal("the join guard did not fire — the fixture no longer tests anything")
	}
	if !strings.Contains(body, "acct-enum-bot") {
		t.Error("the only Account on this page is missing from \"By principal\", on a page whose " +
			"headline is reporting its enumerations")
	}
	if !strings.Contains(squashSpace(body), `<td class="num">0</td> <td class="num">2</td>`) {
		t.Error("the enumerating Account's two families are not in their own columns")
	}
}

// TestReads_OverlongOperationNameIsDroppedNotSentToTheLane.
//
// capability.AuditFilter.validate refuses ANY entry over 64 bytes, and it
// refuses the whole filter. So one over-long Operation name on one read Job
// would fail every audit query for that window and take the entire screen to a
// 500 — a page destroyed by a row, rather than a row dropped from a page.
func TestReads_OverlongOperationNameIsDroppedNotSentToTheLane(t *testing.T) {
	long := "template." + strings.Repeat("x", maxOperationNameBytes)
	q := &fakeQueries{
		jobs: []capability.JobSummary{
			readJob(long, "acct-1", jobs.RiskClassRead),
			readJob("file.read", "acct-1", jobs.RiskClassRead),
		},
		rows: []capability.AuditRow{
			readDispatchRow("file.read", "/etc/hosts", "n1", "acct-1", jobs.OutcomeSuccess),
		},
	}
	body := readsBody(t, q, "")

	sawShort := false
	for _, f := range q.allAuditFilters() {
		for _, op := range f.Operations {
			if len(op) > maxOperationNameBytes {
				t.Errorf("an Operation of %d bytes reached the read lane, which refuses the whole "+
					"filter over %d — one row would have taken the window's every figure with it",
					len(op), maxOperationNameBytes)
			}
			if op == "file.read" {
				sawShort = true
			}
		}
	}
	if !sawShort {
		t.Error("the well-formed Operation was dropped along with the over-long one")
	}
	if !strings.Contains(body, "longer than 64 bytes") {
		t.Error("the page does not state that an Operation was left out")
	}
}

// TestReads_EachDegradedSectionNamesItsOwnQuery.
//
// Eight queries, four of which may fail without taking the page down. Each has
// to say WHICH figure is missing: a section that renders its rows and stays
// silent about the query that did not answer is indistinguishable from one
// that measured a genuine nothing.
func TestReads_EachDegradedSectionNamesItsOwnQuery(t *testing.T) {
	fixture := func() *fakeQueries {
		return &fakeQueries{
			jobs: []capability.JobSummary{readJob("file.read", "acct-1", jobs.RiskClassRead)},
			rows: []capability.AuditRow{
				readDispatchRow("file.read", "/etc/shadow", "n1", "acct-1", jobs.OutcomeDeniedByPolicy),
				readDispatchRow("file.read", "/etc/hosts", "n2", "acct-1", jobs.OutcomeSuccess),
				enumRow("list_nodes", "acct-1"),
			},
		}
	}
	isDispatch := func(f capability.AuditFilter) bool { return containsString(f.Kinds, audit.KindDispatch) }
	isEnum := func(f capability.AuditFilter) bool { return containsString(f.Kinds, audit.KindRead) }

	for _, c := range []struct {
		name   string
		break_ func(*fakeQueries)
		want   string
	}{
		{"the by-target page (Q6)", func(q *fakeQueries) {
			q.auditErrOn = func(f capability.AuditFilter) bool { return isDispatch(f) && f.Outcome == nil }
		}, "The by-target rows could not be read."},
		{"the refusal page (Q5)", func(q *fakeQueries) {
			q.auditErrOn = func(f capability.AuditFilter) bool { return f.Outcome != nil }
		}, "The refusal rows could not be read"},
		{"the enumeration page (Q8)", func(q *fakeQueries) {
			q.auditErrOn = func(f capability.AuditFilter) bool { return isEnum(f) }
		}, "The enumeration rows could not be read."},
		{"the enumeration count (Q7)", func(q *fakeQueries) {
			q.countsErrOn = func(f capability.AuditFilter) bool { return isEnum(f) }
		}, "The exact enumeration count could not be computed"},
		{"the per-principal counts (Q4/Q7)", func(q *fakeQueries) {
			q.countsErrOn = func(capability.AuditFilter) bool { return true }
		}, "The per-principal figures could not be read."},
	} {
		q := fixture()
		c.break_(q)
		body := readsBody(t, q, "")
		if !strings.Contains(body, c.want) {
			t.Errorf("%s failed and the page does not say so — a silent section is "+
				"indistinguishable from one that measured a genuine nothing", c.name)
		}
		// The page still renders, and the aggregates that DID answer still do.
		if !strings.Contains(body, "reads from Nodes</span>") {
			t.Errorf("%s failing took the whole headline down with it", c.name)
		}
	}
}

// TestReads_StatesTheGapsItCannotClose.
//
// Two caveats that are invisible in the output and change what the numbers
// mean, so they are written down beside them rather than left to be
// rediscovered.
func TestReads_StatesTheGapsItCannotClose(t *testing.T) {
	q := &fakeQueries{
		jobs: []capability.JobSummary{readJob("file.read", "acct-1", jobs.RiskClassRead)},
		rows: []capability.AuditRow{
			readDispatchRow("file.read", "/etc/hosts", "n1", "acct-1", jobs.OutcomeSuccess),
			enumRow("describe_node", "acct-1"),
		},
	}
	body := readsBody(t, q, "")

	// The two lanes read different clocks: Q1 filters a Job's created_at and
	// Q2-Q6 filter a Record's ts, and the dispatch record is written AFTER the
	// Job runs. A read Job created just before the window whose records land
	// inside it contributes no Operation, so its reads are missing from every
	// figure — and if it were the only one, the page would say the lane was
	// not queried while matching records existed.
	if !strings.Contains(body, "different clocks") {
		t.Error("the page does not state the Job-window / audit-window mismatch, which is the same " +
			"class of caveat as the 200-Job page and the 32-Operation cap it DOES state")
	}

	// ?node= is a legitimate filter on the enumeration lane — describe_node
	// and get_job name a Node — but most enumerations name none, so it
	// narrows the panel sharply. That is correct and it must not be silent.
	scoped := readsBody(t, q, "node=n1")
	if !strings.Contains(scoped, "Most enumerations name no") {
		t.Error("a Node filter narrows the enumeration panel without saying why — the Operation " +
			"and path filters both explain themselves and this one does not")
	}
}
