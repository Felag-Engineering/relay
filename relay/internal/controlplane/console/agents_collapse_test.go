package console

// agents_collapse_test.go is #541's acceptance criteria: polling collapses —
// a run of consecutive, identical calls folds into one row carrying a count,
// so an Account making 200 get_job polls does not push a raw_exec that
// happened during the polling off the page.
//
// Its own file for the reason agents_paging_test.go and agents_window_test.go
// already state: screens_test.go is huge and has already silently fused two
// test functions in a three-way merge. New coverage for a change this
// structural goes here instead.

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// agentRowBlocks splits a rendered Agents page into one string per rendered
// row, in rendering order (newest first) — the ordering assertions below
// need the SEQUENCE, which agentRowContaining (screens_test.go) deliberately
// throws away by returning only the one block a needle matches.
func agentRowBlocks(body string) []string {
	return strings.Split(body, `<article class="ev" data-kind="call"`)[1:]
}

// hasRowWithBoth reports whether some rendered row contains both needles —
// used where a single needle (like a Job link shared by two runs) cannot
// pick out one row on its own.
func hasRowWithBoth(body, needleA, needleB string) bool {
	for _, block := range agentRowBlocks(body) {
		if strings.Contains(block, needleA) && strings.Contains(block, needleB) {
			return true
		}
	}
	return false
}

// dataCallsIn returns the integer value of the FIRST data-calls="N" attribute
// in block, or -1 if the block carries none — used by T5 to prove the summed
// verification procedure actually reads the rendered attribute rather than a
// value collapseSummary computed independently of the template.
func dataCallsIn(block string) int {
	const attr = `data-calls="`
	i := strings.Index(block, attr)
	if i < 0 {
		return -1
	}
	rest := block[i+len(attr):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return -1
	}
	n, err := strconv.Atoi(rest[:j])
	if err != nil {
		return -1
	}
	return n
}

// TestAgents_PollingCollapsesAndTheRawExecSurvives is T1, the issue's own
// binding case: one Account polling get_job must not push a raw_exec that
// happened during the polling off the page, and the collapse must not
// silently merge two DIFFERENT Jobs into one row either — the plan-review
// corollary (F1) made the second half of that a fixture requirement rather
// than a claim about the first fixture's incidental shape.
//
// One Account, 200 records total (so fakeQueries neither truncates nor
// reports a next cursor), newest first:
//
//	run A: 100 get_job polls for job-1
//	       1  raw_exec dispatch (systemctl restart nginx, node-a, success)
//	run B: 95  get_job polls for job-1  (same Job as run A, separated by the
//	           raw_exec — must stay its OWN row, not rejoin run A)
//	run C: 4   get_job polls for job-2  (a DIFFERENT Job, IMMEDIATELY ADJACENT
//	           to run B with no raw_exec between)
//
// A fixture keying on Account+tool alone would merge run B and run C into one
// row despite them being different Jobs — this is what proves the JobID
// property T1 always claimed to prove but, before the corollary, did not:
// the raw_exec differs from every read in seven fields at once (Tool, Risk,
// Args, NodeID, Outcome, JobID, ReadClass) and so survives any sufficiently
// weak key, telling this fixture nothing about JobID specifically. Run B vs
// run C differ ONLY in JobID (same Account, same tool, same everything else),
// so they are the one pair in this fixture that can actually discriminate a
// key that dropped JobID from one that kept it.
func TestAgents_PollingCollapsesAndTheRawExecSurvives(t *testing.T) {
	const who = "poller:operator"
	rows := buildPollingFixture(who)
	if len(rows) != 200 {
		t.Fatalf("fixture has %d rows, want exactly 200 so the page neither truncates nor reports "+
			"a next cursor", len(rows))
	}

	rail, calls, _ := buildAgents(rows, "", testNow)
	if len(rail) != 1 {
		t.Fatalf("got %d rail entries, want 1", len(rail))
	}

	// (a) exactly 4 rendered rows: run A, the raw_exec, run B, run C.
	if len(calls) != 4 {
		t.Fatalf("got %d calls, want 4 (run A, raw_exec, run B, run C):\n%+v", len(calls), calls)
	}

	// (c) the raw_exec is the SECOND row — the trail was not reordered.
	if calls[1].Risk != jobs.RiskClassName(jobs.RiskClassMutate) || calls[1].NodeID != "node-a" {
		t.Fatalf("calls[1] is not the raw_exec row: %+v", calls[1])
	}
	for i, c := range calls {
		if i != 1 && c.Risk == jobs.RiskClassName(jobs.RiskClassMutate) {
			t.Errorf("calls[%d] also carries risk mutate — the raw_exec is not alone: %+v", i, c)
		}
	}

	// (b) the raw_exec is its OWN row: it stands for exactly 1 call.
	if calls[1].Calls != 1 {
		t.Errorf("the raw_exec row's Calls = %d, want 1", calls[1].Calls)
	}

	// (d) run A / run B / run C carry the right counts and the right Jobs.
	if calls[0].JobID != "job-1" || calls[0].Calls != 100 {
		t.Errorf("calls[0] (run A) = %+v, want JobID job-1, Calls 100", calls[0])
	}
	if calls[2].JobID != "job-1" || calls[2].Calls != 95 {
		t.Errorf("calls[2] (run B) = %+v, want JobID job-1, Calls 95", calls[2])
	}
	if calls[3].JobID != "job-2" || calls[3].Calls != 4 {
		t.Errorf("calls[3] (run C) = %+v, want JobID job-2, Calls 4", calls[3])
	}

	// (e) the sum of Calls equals every record on the page, and equals the
	// rail's own count for this Account.
	sum := 0
	for _, c := range calls {
		sum += c.Calls
	}
	if sum != 200 {
		t.Errorf("sum(Calls) = %d, want 200", sum)
	}
	if rail[0].Calls != 200 {
		t.Errorf("rail[0].Calls = %d, want 200", rail[0].Calls)
	}

	// (f) the rail's mutate count is 1, and run A's x100 chip renders.
	if rail[0].Mutates != 1 {
		t.Errorf("rail[0].Mutates = %d, want 1", rail[0].Mutates)
	}

	d := renderableDeps()
	d.Queries = &fakeQueries{rows: rows}
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()

	if !strings.Contains(body, "x100</span>") {
		t.Errorf("run A's x100 chip does not render:\n%s", body)
	}
	if n := strings.Count(body, `data-risk="mutate"`); n != 1 {
		t.Errorf("the page renders %d mutate risk chips, want exactly 1", n)
	}
	rawExecRow := agentRowContaining(t, body, `data-risk="mutate"`)
	if !strings.Contains(rawExecRow, `data-calls="1"`) {
		t.Errorf("the raw_exec row does not carry data-calls=\"1\":\n%s", rawExecRow)
	}

	// (g), the corollary's own requirement: run B (job-1) and run C (job-2)
	// are each SEPARATELY reachable, proving the collapse did not fold two
	// different Jobs into one row. Run A is ALSO job-1, so a plain "row
	// containing /console/jobs/job-1" would ambiguously match either job-1
	// row — the count is what tells run A and run B apart.
	if !hasRowWithBoth(body, "/console/jobs/job-1", `data-calls="95"`) {
		t.Errorf("no row carries both job-1's link and data-calls=\"95\" (run B):\n%s", body)
	}
	if !hasRowWithBoth(body, "/console/jobs/job-2", `data-calls="4"`) {
		t.Errorf("no row carries both job-2's link and data-calls=\"4\" (run C):\n%s", body)
	}

	// NOTE what this test does NOT prove: the raw_exec differs from every
	// read in seven fields at once, so its survival alone cannot isolate the
	// risk-class guard specifically — TestAgents_TheCollapseKeyIsTheWholeRenderedRow
	// (T3, below) does that, one field at a time.
}

// buildPollingFixture is T1's fixture, factored out so both the test and
// its mutation notes can refer to its shape by name.
func buildPollingFixture(who string) []capability.AuditRow {
	var rows []capability.AuditRow
	ts := testNow
	next := func() time.Time {
		t := ts
		ts = ts.Add(-time.Second)
		return t
	}
	for i := 0; i < 100; i++ {
		rows = append(rows, capability.AuditRow{
			Kind: audit.KindRead, OperationName: "get_job", JobID: "job-1",
			Principal: who, Timestamp: next(),
		})
	}
	rows = append(rows, capability.AuditRow{
		Kind: audit.KindDispatch, ActionKind: "raw_exec",
		RawExecArgv: []string{"systemctl", "restart", "nginx"},
		NodeID:      "node-a", Principal: who, Outcome: jobs.OutcomeSuccess, Timestamp: next(),
	})
	for i := 0; i < 95; i++ {
		rows = append(rows, capability.AuditRow{
			Kind: audit.KindRead, OperationName: "get_job", JobID: "job-1",
			Principal: who, Timestamp: next(),
		})
	}
	for i := 0; i < 4; i++ {
		rows = append(rows, capability.AuditRow{
			Kind: audit.KindRead, OperationName: "get_job", JobID: "job-2",
			Principal: who, Timestamp: next(),
		})
	}
	return rows
}

// TestAgents_CollapseIsConsecutiveOnly is T2: a read, a raw_exec, then a read
// byte-identical to the first apart from its timestamp. Collapsing across
// the raw_exec would reorder the trail (Q2) and reintroduce this ticket's own
// bug one level down — nothing on screen would then say whether the raw_exec
// happened during the polling or after it.
func TestAgents_CollapseIsConsecutiveOnly(t *testing.T) {
	rows := []capability.AuditRow{
		{Kind: audit.KindRead, OperationName: "get_job", JobID: "job-1",
			Principal: "poller:operator", Timestamp: testNow},
		{Kind: audit.KindDispatch, ActionKind: "raw_exec",
			RawExecArgv: []string{"systemctl", "restart", "nginx"}, NodeID: "node-a",
			Principal: "poller:operator", Outcome: jobs.OutcomeSuccess, Timestamp: testNow.Add(-time.Second)},
		{Kind: audit.KindRead, OperationName: "get_job", JobID: "job-1",
			Principal: "poller:operator", Timestamp: testNow.Add(-2 * time.Second)},
	}

	_, calls, _ := buildAgents(rows, "", testNow)
	if len(calls) != 3 {
		t.Fatalf("got %d calls, want 3 — the two reads are identical apart from timestamp but are "+
			"not ADJACENT and must not collapse across the raw_exec between them", len(calls))
	}
	if calls[1].Risk != jobs.RiskClassName(jobs.RiskClassMutate) {
		t.Fatalf("calls[1] is not the raw_exec row: %+v", calls[1])
	}
}

// TestAgents_TheCollapseKeyIsTheWholeRenderedRow is T3: a reflection sweep
// over every agentCall field NOT excluded from the collapse key (When, Calls,
// FirstWhen — the run's own bookkeeping — and Deny/RepeatDeny, which
// collapsible already handles). For each field, two otherwise-identical rows
// differing ONLY in that field must NOT collapse — naming the field in the
// failure message, so a key that silently dropped one is caught at the
// field, not just at "something is wrong".
//
// This is what makes Q4 (never collapse across a risk class) hold in
// general, since T1's raw_exec differs in seven fields at once and cannot
// isolate any single one of them.
func TestAgents_TheCollapseKeyIsTheWholeRenderedRow(t *testing.T) {
	excluded := map[string]bool{
		"When": true, "Calls": true, "FirstWhen": true, "Deny": true, "RepeatDeny": true,
	}
	base := agentCall{
		When: "2026-08-25 12:00:00Z", Tool: "get_job", Principal: "acct", Verified: true,
		OnBehalfOf: "alice", Risk: "read", Selector: "tag:web", Args: "path=/etc/shadow",
		NodeID: "node-a", NodeHref: "/console/nodes/node-a", Outcome: "audited",
		JobID: "job-1", JobHref: "/console/jobs/job-1", Reason: "because", ReadClass: true,
		Calls: 1,
	}

	typ := reflect.TypeOf(base)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if excluded[field.Name] {
			continue
		}
		t.Run(field.Name, func(t *testing.T) {
			a, b := base, base
			fv := reflect.ValueOf(&b).Elem().Field(i)
			switch fv.Kind() {
			case reflect.String:
				fv.SetString(fv.String() + "-different")
			case reflect.Bool:
				fv.SetBool(!fv.Bool())
			default:
				t.Fatalf("the collapse-key sweep cannot vary field %s (kind %s) — decide whether "+
					"it belongs in sameCall's key and extend this sweep to cover it, rather than "+
					"leaving it silently unswept", field.Name, fv.Kind())
			}
			out := collapseRuns([]agentCall{a, b})
			if len(out) != 2 {
				t.Errorf("varying only %s collapsed the two rows into %d row(s), want 2 — %s is "+
					"missing from the collapse key", field.Name, len(out), field.Name)
			}
		})
	}
}

// TestAgents_ADeniedRowNeverCollapses is T4: three identical consecutive
// denied dispatches on the SAME Node and Operation. After the deny-prose pass
// (buildAgents' seenDeny loop, which runs BEFORE the collapse) rows 2 and 3
// are both {Deny: nil, RepeatDeny: true} and would otherwise compare EQUAL —
// this fixture is what DISCRIMINATES collapsible from sameCall alone. Two
// rows would not discriminate: the first row's non-nil Deny pointer makes it
// unequal to either of the others regardless of collapsible, so the fixture
// needs a THIRD row to prove the guard extends past the first.
func TestAgents_ADeniedRowNeverCollapses(t *testing.T) {
	var rows []capability.AuditRow
	for i := 0; i < 3; i++ {
		rows = append(rows, capability.AuditRow{
			Kind: audit.KindDispatch, OperationName: "file.read",
			Args: map[string]string{"path": "/etc/shadow"}, NodeID: "node-a",
			Outcome: jobs.OutcomeDeniedByPolicy, Principal: "agent:operator",
			Timestamp: testNow.Add(-time.Duration(i) * time.Second),
		})
	}

	_, calls, _ := buildAgents(rows, "", testNow)
	if len(calls) != 3 {
		t.Fatalf("got %d calls, want 3 — a denied row must never collapse, even the RepeatDeny "+
			"rows behind the first", len(calls))
	}
	if calls[0].Deny == nil {
		t.Error("the first denied row lost its explanation")
	}
	if !calls[1].RepeatDeny || !calls[2].RepeatDeny {
		t.Error("the second and third denied rows are not marked RepeatDeny")
	}
}

// TestAgents_TheRailCountsCallsNotCollapsedRows is T5: the fixture that tells
// "count the mutate chips" apart from "add up the call counts on the mutate
// rows" — the property both older rail tests were rewritten to state. Five
// identical raw_exec dispatches plus one read: the five collapse into one
// row, so a naive count of `data-risk="mutate"` chips reports 1 while the
// rail — which counts CALLS, incremented before the collapse ever runs —
// reports 5.
func TestAgents_TheRailCountsCallsNotCollapsedRows(t *testing.T) {
	var rows []capability.AuditRow
	for i := 0; i < 5; i++ {
		rows = append(rows, capability.AuditRow{
			Kind: audit.KindDispatch, ActionKind: "raw_exec",
			RawExecArgv: []string{"systemctl", "restart", "nginx"}, NodeID: "node-a",
			Principal: "poller:operator", Outcome: jobs.OutcomeSuccess,
			Timestamp: testNow.Add(-time.Duration(i) * time.Second),
		})
	}
	rows = append(rows, capability.AuditRow{
		Kind: audit.KindRead, OperationName: "list_nodes", Principal: "poller:operator",
		Timestamp: testNow.Add(-6 * time.Second),
	})

	rail, calls, _ := buildAgents(rows, "", testNow)
	if len(rail) != 1 {
		t.Fatalf("got %d rail entries, want 1", len(rail))
	}
	if rail[0].Calls != 6 {
		t.Errorf("rail[0].Calls = %d, want 6", rail[0].Calls)
	}
	if rail[0].Mutates != 5 {
		t.Errorf("rail[0].Mutates = %d, want 5", rail[0].Mutates)
	}
	if len(calls) != 2 {
		t.Fatalf("got %d rendered rows, want 2 (the collapsed raw_exec run, and the read)", len(calls))
	}

	d := renderableDeps()
	d.Queries = &fakeQueries{rows: rows}
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()

	// The naive count: exactly ONE row is chipped data-risk="mutate", because
	// the five raw_execs collapsed into one row. Counting mutate CHIPS this
	// way would report 1 — which is why the two older rail tests
	// (TestAgents_RailMutateCountAgreesWithTheRowRiskChips,
	// TheRailAgreesPerAccountWhenAnAccountDropsOff) were rewritten to sum
	// Calls rather than count chips; their own fixtures happen to collapse
	// nothing, so they could not have told the two forms apart themselves.
	if n := strings.Count(body, `data-risk="mutate"`); n != 1 {
		t.Fatalf("naive mutate-chip count = %d, want exactly 1 (this is the count the old assertion "+
			"form would have used, and it is not the rail's number)", n)
	}

	// The summed form, read off the RENDERED data-calls attribute — not off
	// calls[i].Calls directly.
	sum := 0
	for _, block := range agentRowBlocks(body) {
		if !strings.Contains(block, `data-risk="mutate"`) {
			continue
		}
		n := dataCallsIn(block)
		if n < 0 {
			t.Fatalf("a mutate row carries no data-calls attribute:\n%s", block)
		}
		sum += n
	}
	if sum != 5 {
		t.Errorf("summed data-calls over mutate rows = %d, want 5 — this is the rail's real "+
			"verification procedure now that a mutate row can stand for more than one call", sum)
	}

	// A template that only emits data-calls when Calls > 1 would NOT be
	// caught by the assertion above — the one mutate row here already stands
	// for 5, which is > 1 regardless. The read row is the fixture's one
	// Calls == 1 row, and it is what the "ALWAYS, including N=1" rule
	// (agents.go item 1(j)) actually needs: verifying the addition an
	// operator does — summing data-calls across several rows, some
	// collapsed and some not — depends on EVERY row exposing the attribute,
	// not only the ones that collapsed.
	readRow := agentRowContaining(t, body, `data-risk="read"`)
	if !strings.Contains(readRow, `data-calls="1"`) {
		t.Errorf("the uncollapsed read row does not carry data-calls=\"1\" — data-calls must "+
			"render on EVERY row, not only the ones a run collapsed into:\n%s", readRow)
	}
}

// TestAgents_ACollapsedRowSaysHowManyCallsAndOverWhatSpan is T6: the xN chip
// renders, the note names both ends of the run, and FirstWhen is the OLDEST
// record's own absolute stamp — never the newest, never a relative "ago".
func TestAgents_ACollapsedRowSaysHowManyCallsAndOverWhatSpan(t *testing.T) {
	newest := testNow
	oldest := testNow.Add(-2 * time.Minute)
	rows := []capability.AuditRow{
		{Kind: audit.KindDispatch, ActionKind: "raw_exec",
			RawExecArgv: []string{"systemctl", "restart", "nginx"}, NodeID: "node-a",
			Principal: "poller:operator", Outcome: jobs.OutcomeSuccess, Timestamp: newest},
		{Kind: audit.KindDispatch, ActionKind: "raw_exec",
			RawExecArgv: []string{"systemctl", "restart", "nginx"}, NodeID: "node-a",
			Principal: "poller:operator", Outcome: jobs.OutcomeSuccess, Timestamp: testNow.Add(-1 * time.Minute)},
		{Kind: audit.KindDispatch, ActionKind: "raw_exec",
			RawExecArgv: []string{"systemctl", "restart", "nginx"}, NodeID: "node-a",
			Principal: "poller:operator", Outcome: jobs.OutcomeSuccess, Timestamp: oldest},
	}

	_, calls, _ := buildAgents(rows, "", testNow)
	if len(calls) != 1 {
		t.Fatalf("got %d calls, want 1 (all three collapse)", len(calls))
	}
	wantWhen := newest.UTC().Format("2006-01-02 15:04:05Z")
	wantFirst := oldest.UTC().Format("2006-01-02 15:04:05Z")
	if calls[0].When != wantWhen {
		t.Errorf("When = %q, want the newest call's stamp %q", calls[0].When, wantWhen)
	}
	if calls[0].FirstWhen != wantFirst {
		t.Errorf("FirstWhen = %q, want the OLDEST call's stamp %q — not the newest, not relative", calls[0].FirstWhen, wantFirst)
	}

	d := renderableDeps()
	d.Queries = &fakeQueries{rows: rows}
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()

	if !strings.Contains(body, "x3</span>") {
		t.Errorf("no x3 chip rendered:\n%s", body)
	}
	if !strings.Contains(body, "3 consecutive identical calls, "+wantFirst+" to "+wantWhen) {
		t.Errorf("the note does not name both ends of the run (%s to %s):\n%s", wantFirst, wantWhen, body)
	}

	css := get(t, newTestHandler(renderableDeps(), accounts.RoleAdmin), "/console/assets/console.css").Body.String()
	i := strings.Index(css, ".chip.calls")
	if i < 0 {
		t.Fatal("the stylesheet has no .chip.calls rule")
	}
	rule := css[i:]
	if j := strings.Index(rule, "}"); j >= 0 {
		rule = rule[:j]
	}
	for _, borrowed := range []string{"var(--failure)", "var(--ok)", "var(--failure-bg)", "var(--ok-bg)"} {
		if strings.Contains(rule, borrowed) {
			t.Errorf(".chip.calls borrows %s — a collapsed run is neither a failure nor a success", borrowed)
		}
	}
}

// twoIdenticalCalls is a fixture that collapses to exactly one row standing
// for two calls — the smallest fixture that makes foldedRows > 0, used by T7
// and T8 to exercise pageNote's collapse clause without entangling it with a
// large fixture's other properties.
func twoIdenticalCalls() []capability.AuditRow {
	row := capability.AuditRow{
		Kind: audit.KindDispatch, ActionKind: "raw_exec",
		RawExecArgv: []string{"systemctl", "restart", "nginx"}, NodeID: "node-a",
		Principal: "poller:operator", Outcome: jobs.OutcomeSuccess,
	}
	a, b := row, row
	a.Timestamp = testNow
	b.Timestamp = testNow.Add(-time.Second)
	return []capability.AuditRow{a, b}
}

// TestAgents_ThePageNoteSaysWhatTheCollapseDid is T7, over the three
// positions Q3 lays out. Each subtest fails independently.
func TestAgents_ThePageNoteSaysWhatTheCollapseDid(t *testing.T) {
	t.Run("unscrolled, no older page — the position #542 left silent", func(t *testing.T) {
		d := renderableDeps()
		d.Queries = &fakeQueries{rows: twoIdenticalCalls()}
		body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()

		if !strings.Contains(body, "are collapsed into") {
			t.Errorf("no collapse clause on the one page position with nothing else to say:\n%s", body)
		}
		if strings.Contains(body, "This page holds the most recent") {
			t.Error("an unscrolled page with no older page still claims a position it does not have")
		}
	})

	t.Run("page one with an older page", func(t *testing.T) {
		d := renderableDeps()
		d.Queries = &fakeQueries{rows: twoIdenticalCalls(), auditNext: "c2"}
		body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents").Body.String()

		if !strings.Contains(body, "are collapsed into") {
			t.Errorf("no collapse clause on a page that also has an older page:\n%s", body)
		}
		if !strings.Contains(body, "This page holds the most recent 200 calls. There are older calls.") {
			t.Errorf("the position clause did not survive #541's PageNote rewrite:\n%s", body)
		}
		if !strings.Contains(body, `href="/console/agents?cursor=c2">Older<`) {
			t.Errorf("no Older link:\n%s", body)
		}
	})

	t.Run("scrolled", func(t *testing.T) {
		d := renderableDeps()
		d.Queries = &fakeQueries{rows: twoIdenticalCalls()}
		body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents?cursor=0").Body.String()

		if !strings.Contains(body, "are collapsed into") {
			t.Errorf("no collapse clause on a scrolled page:\n%s", body)
		}
		if !strings.Contains(body, "not the most recent calls. This page was reached by following Older") {
			t.Errorf("the scrolled position clause did not survive #541's PageNote rewrite:\n%s", body)
		}
		if !strings.Contains(body, ">Newest<") {
			t.Errorf("no Newest link:\n%s", body)
		}
	})
}

// TestAgents_ThePageNoteAlwaysSpeaksWhenThereIsSomethingToSay is T8,
// railNote's contract twin: pageNote is "" iff foldedRows == 0 && !older &&
// !scrolled.
func TestAgents_ThePageNoteAlwaysSpeaksWhenThereIsSomethingToSay(t *testing.T) {
	for _, foldedRows := range []int{0, 1} {
		foldedCalls := 0
		if foldedRows > 0 {
			foldedCalls = 2
		}
		for _, older := range []bool{false, true} {
			for _, scrolled := range []bool{false, true} {
				got := pageNote(foldedCalls, foldedRows, agentsPageSize, older, scrolled)
				wantEmpty := foldedRows == 0 && !older && !scrolled
				if wantEmpty && got != "" {
					t.Errorf("pageNote(%d, %d, _, %v, %v) = %q, want \"\"",
						foldedCalls, foldedRows, older, scrolled, got)
				}
				if !wantEmpty && got == "" {
					t.Errorf("pageNote(%d, %d, _, %v, %v) = \"\", want a non-empty note",
						foldedCalls, foldedRows, older, scrolled)
				}
			}
		}
	}
}

// TestAgents_ScopedCollapseFoldsOnlyWhatItShows is T9: two Accounts
// interleaved in the raw feed, so their calls are NOT adjacent in the
// underlying trail. Scoping to one Account with ?account= filters BEFORE the
// collapse runs (buildAgents' documented ordering), so that Account's calls
// become adjacent IN THE FEED IT SHOWS and still fold — pinning that the
// collapse reasons about the rendered stream, not the raw trail order, and
// that the other Account's rows are simply absent, not merged into anything.
func TestAgents_ScopedCollapseFoldsOnlyWhatItShows(t *testing.T) {
	const a, b = "acct-a:operator", "acct-b:operator"
	rows := []capability.AuditRow{
		{Kind: audit.KindRead, OperationName: "list_nodes", Principal: a, Timestamp: testNow},
		{Kind: audit.KindRead, OperationName: "list_nodes", Principal: b, Timestamp: testNow.Add(-time.Second)},
		{Kind: audit.KindRead, OperationName: "list_nodes", Principal: a, Timestamp: testNow.Add(-2 * time.Second)},
	}

	_, calls, _ := buildAgents(rows, a, testNow)
	if len(calls) != 1 {
		t.Fatalf("got %d calls scoped to %s, want 1 — the two now-adjacent calls should collapse", len(calls), a)
	}
	if calls[0].Calls != 2 {
		t.Errorf("the collapsed row's Calls = %d, want 2", calls[0].Calls)
	}

	d := renderableDeps()
	d.Queries = &fakeQueries{rows: rows}
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/agents?account="+a).Body.String()
	// Scoped to the FEED rows, not the whole body: the rail deliberately
	// keeps listing every Account (it is how an operator navigates to one),
	// so a page-wide check for b's name would fail for a reason unrelated to
	// the collapse under test.
	blocks := agentRowBlocks(body)
	if len(blocks) != 1 {
		t.Fatalf("the scoped feed renders %d rows, want 1", len(blocks))
	}
	if strings.Contains(blocks[0], b) {
		t.Errorf("the scoped feed's one row still names the other Account:\n%s", blocks[0])
	}
}
