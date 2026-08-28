package console

// job_test.go is spec 13's acceptance criteria, asserted against the rendered
// page rather than against the view struct wherever the criterion is about
// what an operator sees.
//
// The bias is towards asserting ABSENCE and BOUNDS: "the page renders the
// denies" is easy and worth little, while "a ten-thousand-Node Job renders no
// list at all, and cost at most one small query per outcome to say so" is the
// property the whole screen exists to have and the one a helpful change six
// months from now would quietly remove.

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

const testJobID = "3f2a91c4d5e6f708192a3b4c5d6e7f80"

// jobDeps builds a Console wired to nothing but the read lane, which is all
// Job detail reads.
func jobDeps(q *fakeQueries) Deps {
	d := renderableDeps()
	d.Queries = q
	return d
}

// oneJob is a JobSummary with counts derived from tasks, so a fixture cannot
// drift into claiming a tally its Tasks do not support.
func oneJob(tasks []capability.TaskRow, risk jobs.RiskClass) capability.JobSummary {
	counts := map[jobs.Outcome]int{}
	for _, t := range tasks {
		counts[t.Outcome]++
	}
	return capability.JobSummary{
		JobID:              testJobID,
		CreatedAt:          testNow,
		State:              jobs.JobStateComplete,
		ActionKind:         jobs.ActionOperation,
		OperationName:      "service.restart",
		RiskClass:          risk,
		Selector:           "node:role=web",
		Requester:          "gleipnir",
		RequesterAccountID: "acct-1",
		Total:              len(tasks),
		Counts:             counts,
	}
}

func mutateTask(node string, outcome jobs.Outcome, out string) capability.TaskRow {
	return capability.TaskRow{
		TaskID: "task-" + node, NodeID: node, State: jobs.DispatchStateResolved,
		Outcome: outcome, RiskClass: jobs.RiskClassMutate, Stdout: []byte(out),
	}
}

func jobBody(t *testing.T, d Deps, path string) string {
	t.Helper()
	rec := get(t, newTestHandler(d, accounts.RoleAdmin), path)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", path, rec.Code)
	}
	return rec.Body.String()
}

func jobPath(query string) string {
	if query == "" {
		return "/console/jobs/" + testJobID
	}
	return "/console/jobs/" + testJobID + "?" + query
}

// TestJob_TenThousandNodesRendersNoList is spec 13's first acceptance
// criterion, and the reason the screen was rebuilt on the query lane: "A Job
// over 10,000 Nodes renders in one screen with no list until explicitly
// requested."
//
// It asserts the COST as well as the output. A page that rendered 8 rows after
// fetching 10,000 would satisfy an eye and none of the reasons this design
// exists — the store would still have been asked for gigabytes, once per
// refresh.
func TestJob_TenThousandNodesRendersNoList(t *testing.T) {
	var tasks []capability.TaskRow
	for i := 0; i < 9986; i++ {
		// Distinct per Node: clustering must not be what saves this page.
		tasks = append(tasks, mutateTask(fmt.Sprintf("node-%05d", i), jobs.OutcomeSuccess, fmt.Sprintf("restarted in %dms", i)))
	}
	for i := 0; i < 8; i++ {
		row := mutateTask(fmt.Sprintf("node-d%d", i), jobs.OutcomeDeniedByPolicy, "")
		row.Stderr = []byte("deny service.restart nginx")
		tasks = append(tasks, row)
	}
	for i := 0; i < 4; i++ {
		tasks = append(tasks, mutateTask(fmt.Sprintf("node-f%d", i), jobs.OutcomeFailure, fmt.Sprintf("unit failed: %d", i)))
	}
	for i := 0; i < 2; i++ {
		tasks = append(tasks, mutateTask(fmt.Sprintf("node-u%d", i), jobs.OutcomeUnreachable, ""))
	}

	q := &fakeQueries{jobs: []capability.JobSummary{oneJob(tasks, jobs.RiskClassMutate)}, tasks: tasks}
	body := jobBody(t, jobDeps(q), jobPath(""))

	// The counts are EXACT — they came from the aggregate, not from counting
	// rows the page fetched.
	for _, want := range []string{"9986", "denied_by_policy", "unreachable"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not report %q", want)
		}
	}
	if n := strings.Count(body, `class="trow"`); n > 8*jobGroupRows {
		t.Errorf("the page rendered %d Node rows, want at most %d", n, 8*jobGroupRows)
	}
	// The success group — the mode — lists nothing at all.
	if strings.Contains(successGroupOf(t, body), `class="trow"`) {
		t.Error("the success group listed Nodes on a 10,000-Node Job; a list is the thing this screen exists not to be")
	}
	if len(body) > 200_000 {
		t.Errorf("the rendered page is %d bytes; a Job detail that grows with the fleet has not solved the problem", len(body))
	}

	// One aggregate, one trail row, and at most one bounded page per outcome.
	if q.jobCalls != 1 || q.auditCalls != 1 {
		t.Errorf("the page cost %d Job queries and %d trail queries, want 1 and 1", q.jobCalls, q.auditCalls)
	}
	if len(q.taskLimits) > 8 {
		t.Errorf("the page made %d Task queries, want at most one per outcome", len(q.taskLimits))
	}
	for _, limit := range q.taskLimits {
		if limit <= 0 || limit > jobGroupExpanded {
			t.Errorf("a Task query asked for %d rows, which is not a bounded page", limit)
		}
	}
	if len(q.taskLimits) != 3 {
		t.Errorf("the page made %d Task queries for 3 non-success outcomes — the success group must fetch nothing", len(q.taskLimits))
	}
}

// successGroupOf returns the success <details> block — not the success SEGMENT
// of the outcome bar, which carries the same data-outcome and comes first.
func successGroupOf(t *testing.T, body string) string {
	t.Helper()
	for _, block := range strings.Split(body, `<details class="ogroup"`)[1:] {
		if j := strings.Index(block, "</details>"); j >= 0 {
			block = block[:j]
		}
		if strings.Contains(block, `<span class="chip outcome" data-outcome="success"`) {
			return block
		}
	}
	t.Fatal("the page has no success group at all")
	return ""
}

// TestJob_ThreeNodeJobListsEveryNode is the other half of the same problem —
// "A three-Node Job is as legible as a ten-thousand-Node one" — and the bug
// the fleet view already shipped once: a screen that computes what is
// interesting still has to show you the Job when the Job fits.
func TestJob_ThreeNodeJobListsEveryNode(t *testing.T) {
	tasks := []capability.TaskRow{
		mutateTask("node-a", jobs.OutcomeSuccess, "restarted"),
		mutateTask("node-b", jobs.OutcomeSuccess, "already running"),
		mutateTask("node-c", jobs.OutcomeSuccess, "restarted after 2s"),
	}
	q := &fakeQueries{jobs: []capability.JobSummary{oneJob(tasks, jobs.RiskClassMutate)}, tasks: tasks}
	body := jobBody(t, jobDeps(q), jobPath(""))

	for _, node := range []string{"node-a", "node-b", "node-c"} {
		if !strings.Contains(body, node) {
			t.Errorf("a three-Node Job does not list %s", node)
		}
	}
	if n := strings.Count(body, `class="trow"`); n != 3 {
		t.Errorf("a three-Node Job rendered %d rows, want 3", n)
	}
}

// TestJob_ALegibleJobListsEverySuccessToo pins the legibleJob boundary rather
// than only its far side. At 40 Tasks every group lists everything, success
// included; the constant says so and a three-Node test cannot tell the
// difference between listing everything and listing the first 25.
func TestJob_ALegibleJobListsEverySuccessToo(t *testing.T) {
	var tasks []capability.TaskRow
	for i := 0; i < 40; i++ {
		tasks = append(tasks, mutateTask(fmt.Sprintf("node-%02d", i), jobs.OutcomeSuccess, fmt.Sprintf("restarted %d", i)))
	}
	q := &fakeQueries{jobs: []capability.JobSummary{oneJob(tasks, jobs.RiskClassMutate)}, tasks: tasks}
	body := jobBody(t, jobDeps(q), jobPath(""))

	if n := strings.Count(body, `class="trow"`); n != 40 {
		t.Errorf("a 40-Task Job rendered %d rows, want all 40 — legibleJob is %d", n, legibleJob)
	}
	if strings.Contains(successGroupOf(t, body), "listed") {
		t.Error("a Job that listed every success still claimed it elided some")
	}
}

// TestJob_AllEightOutcomesRender is spec 13's second criterion. The three
// "did not run" kinds are the ones a careless implementation drops, because
// they are Relay-synthesized and carry no process result at all.
func TestJob_AllEightOutcomesRender(t *testing.T) {
	all := []jobs.Outcome{
		jobs.OutcomeSuccess, jobs.OutcomeFailure, jobs.OutcomeTimeout,
		jobs.OutcomeDeniedByPolicy, jobs.OutcomeCancelled, jobs.OutcomeUnreachable,
		jobs.OutcomeVersionRefused, jobs.OutcomeUnsupported,
	}
	var tasks []capability.TaskRow
	for _, o := range all {
		tasks = append(tasks, mutateTask("node-"+OutcomeLabel(o), o, ""))
	}
	q := &fakeQueries{jobs: []capability.JobSummary{oneJob(tasks, jobs.RiskClassMutate)}, tasks: tasks}
	body := jobBody(t, jobDeps(q), jobPath(""))

	if n := strings.Count(body, `<details class="ogroup"`); n != 8 {
		t.Errorf("the page rendered %d outcome groups, want 8", n)
	}
	for _, o := range all {
		if !strings.Contains(body, fmt.Sprintf(`data-outcome="%s"`, OutcomeLabel(o))) {
			t.Errorf("outcome %s has no group of its own", OutcomeLabel(o))
		}
	}
	// Ordering is by interest, not alphabetical: a page that opens with nine
	// thousand successes has buried the deny that was the reason anyone looked.
	first := strings.Index(body, `<details class="ogroup"`)
	if !strings.Contains(body[first:first+200], "denied_by_policy") {
		t.Error("the first group is not the denied one")
	}
	if strings.LastIndex(body, `data-outcome="success"`) < strings.LastIndex(body, `data-outcome="denied_by_policy"`) {
		t.Error("success does not sort last")
	}
	// Success is the mode and renders collapsed; everything else opens.
	if strings.HasPrefix(successGroupOf(t, body), " open>") {
		t.Error("the success group renders expanded")
	}
}

// TestJob_DenyGroupIsGroupedByRuleAndLinksToPolicy is spec 13's third
// criterion and the screen's showpiece: the rule VERBATIM, in mono, slate
// rather than red, with a link to the Node's effective Policy — which the
// Relay may only read and can never write (ADR-0002, invariant 2).
func TestJob_DenyGroupIsGroupedByRuleAndLinksToPolicy(t *testing.T) {
	shared := "deny raw_exec /usr/bin/rm  # rule 14, /etc/relay/policy.d/20-fs.toml"
	other := "deny service.restart nginx  # rule 3"
	deny := func(node, rule string) capability.TaskRow {
		row := mutateTask(node, jobs.OutcomeDeniedByPolicy, "")
		row.Stderr = []byte(rule)
		return row
	}
	tasks := []capability.TaskRow{
		deny("node-x", shared), deny("node-y", shared), deny("node-z", other),
	}
	q := &fakeQueries{jobs: []capability.JobSummary{oneJob(tasks, jobs.RiskClassMutate)}, tasks: tasks}
	body := jobBody(t, jobDeps(q), jobPath(""))

	// Two rules, two deny blocks — "when they differ, group by rule".
	if n := strings.Count(body, `class="deny"`); n != 2 {
		t.Errorf("the page rendered %d deny blocks for 3 denies under 2 rules, want 2", n)
	}
	for _, rule := range []string{"rule 14", "rule 3"} {
		if !strings.Contains(body, rule) {
			t.Errorf("the deciding rule %q is not rendered verbatim", rule)
		}
	}
	if !strings.Contains(body, `href="/console/nodes/node-x"`) {
		t.Error("the deny does not link to the Node's effective Policy")
	}
	if !strings.Contains(body, `data-outcome="denied_by_policy"`) {
		t.Error("the deny is not chipped as a deny")
	}
	// A deny is the product working. It is never painted as a failure.
	if strings.Contains(contentOf(body), `class="fail"`) {
		t.Error("a deny rendered in the failure treatment")
	}
	// The Relay cannot fix this, and the page says so rather than offering a
	// control that would imply it could.
	if !strings.Contains(body, "Relay cannot change this") {
		t.Error("the deny block does not say Policy is rooted on the Node")
	}
}

// TestJob_SharedDenyRuleIsShownOnce — the same rule refusing the same
// Operation on 300 Nodes is one fact, not 300, and 300 identical blocks bury
// the one thing the operator came for.
func TestJob_SharedDenyRuleIsShownOnce(t *testing.T) {
	var tasks []capability.TaskRow
	for i := 0; i < 6; i++ {
		row := mutateTask(fmt.Sprintf("node-%d", i), jobs.OutcomeDeniedByPolicy, "")
		row.Stderr = []byte("deny service.restart nginx")
		tasks = append(tasks, row)
	}
	q := &fakeQueries{jobs: []capability.JobSummary{oneJob(tasks, jobs.RiskClassMutate)}, tasks: tasks}
	body := jobBody(t, jobDeps(q), jobPath(""))

	if n := strings.Count(body, `class="deny"`); n != 1 {
		t.Errorf("6 identical denials rendered %d blocks, want 1", n)
	}
	if !strings.Contains(body, "fired the same rule") {
		t.Error("the page shows one rule for 6 denials without saying that is what it did")
	}
}

// TestJob_ReadClassCarriesNoOutputAtAnyAge is ADR-0025 rendered, and it is
// asserted against a seam that HANDS THE BYTES OVER: the Console gates on the
// declared risk class itself rather than trusting the read lane to have
// stripped. Two independent gates on one rule is what makes "read output never
// renders here" a property of the code and not of one package remembering.
func TestJob_ReadClassCarriesNoOutputAtAnyAge(t *testing.T) {
	secret := "root:x:0:0:SECRET"
	task := capability.TaskRow{
		TaskID: "task-1", NodeID: "node-web-1", State: jobs.DispatchStateResolved,
		Outcome: jobs.OutcomeSuccess, RiskClass: jobs.RiskClassRead, Stdout: []byte(secret),
	}
	tasks := []capability.TaskRow{task}
	q := &fakeQueries{jobs: []capability.JobSummary{oneJob(tasks, jobs.RiskClassRead)}, tasks: tasks}
	body := jobBody(t, jobDeps(q), jobPath(""))

	if strings.Contains(body, secret) {
		t.Fatal("a read-class Task's captured output rendered — read output is never retained, at any age")
	}
	if !strings.Contains(body, "This was a read.") {
		t.Error("the page does not say the output was never kept")
	}

	// The same bytes on a mutate-class Task DO render, which is what makes the
	// assertion above about the risk class rather than about empty output.
	task.RiskClass = jobs.RiskClassMutate
	mutate := []capability.TaskRow{task}
	q = &fakeQueries{jobs: []capability.JobSummary{oneJob(mutate, jobs.RiskClassMutate)}, tasks: mutate}
	if !strings.Contains(jobBody(t, jobDeps(q), jobPath("")), secret) {
		t.Error("a mutate-class Task rendered no output — the read rule was applied to the wrong class")
	}

	// The DENY RULE is read output as well: the daemon explains a refusal in
	// the Task's own stderr, so a read-class deny must not print it either.
	denied := capability.TaskRow{
		TaskID: "task-2", NodeID: "node-web-2", State: jobs.DispatchStateResolved,
		Outcome: jobs.OutcomeDeniedByPolicy, RiskClass: jobs.RiskClassRead,
		Stderr: []byte("deny file.read /etc/shadow  # " + secret),
	}
	deniedTasks := []capability.TaskRow{denied}
	q = &fakeQueries{jobs: []capability.JobSummary{oneJob(deniedTasks, jobs.RiskClassRead)}, tasks: deniedTasks}
	deniedBody := jobBody(t, jobDeps(q), jobPath(""))
	if strings.Contains(deniedBody, secret) {
		t.Error("a read-class deny rendered the daemon's stderr, which IS the read output ADR-0025 says was never kept")
	}
	if !strings.Contains(deniedBody, "not recorded in the trail for a read-class Task") {
		t.Error("a read-class deny does not explain why there is no rule to show")
	}

	// An UNSPECIFIED class withholds too. Everywhere else in this codebase
	// unspecified means mutate; for output retention that direction inverts.
	task.RiskClass = jobs.RiskClassUnspecified
	unspecified := []capability.TaskRow{task}
	q = &fakeQueries{jobs: []capability.JobSummary{oneJob(unspecified, jobs.RiskClassMutate)}, tasks: unspecified}
	if strings.Contains(jobBody(t, jobDeps(q), jobPath("")), secret) {
		t.Error("a Task with an unspecified risk class rendered its output; retention must fail safe toward withholding")
	}
}

// TestJob_ReadClassDoesNotClaimIdenticalOutput — on a read Job there is no
// retained output, so every row's is empty. "4 Nodes reported identical
// output" describes the Relay's retention policy as if it were a fact about
// the fleet.
func TestJob_ReadClassDoesNotClaimIdenticalOutput(t *testing.T) {
	var tasks []capability.TaskRow
	for _, n := range []string{"n1", "n2", "n3", "n4"} {
		tasks = append(tasks, capability.TaskRow{
			TaskID: "task-" + n, NodeID: n, State: jobs.DispatchStateResolved,
			Outcome: jobs.OutcomeSuccess, RiskClass: jobs.RiskClassRead,
		})
	}
	q := &fakeQueries{jobs: []capability.JobSummary{oneJob(tasks, jobs.RiskClassRead)}, tasks: tasks}
	body := jobBody(t, jobDeps(q), jobPath(""))

	if strings.Contains(body, "reported identical output") {
		t.Error("a read-class Job claimed Nodes reported identical output — none was retained")
	}
	if n := strings.Count(body, `class="trow"`); n != 4 {
		t.Errorf("read-class rows were collapsed: got %d, want all 4 listed", n)
	}
}

// TestJob_IdenticalOutputClusters is the disclosure ladder: 20 identical
// results are one fact, not 20, and rendering them as 20 rows is the
// behaviour clustering exists to prevent.
func TestJob_IdenticalOutputClusters(t *testing.T) {
	var tasks []capability.TaskRow
	for i := 0; i < 20; i++ {
		tasks = append(tasks, mutateTask(fmt.Sprintf("n%02d", i), jobs.OutcomeSuccess, "ok"))
	}
	tasks = append(tasks, mutateTask("odd", jobs.OutcomeSuccess, "different"))

	q := &fakeQueries{jobs: []capability.JobSummary{oneJob(tasks, jobs.RiskClassMutate)}, tasks: tasks}
	groups := jobGroups(t.Context(), jobDeps(q), capability.Principal{}, oneJob(tasks, jobs.RiskClassMutate), "", "service.restart")

	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(groups))
	}
	g := groups[0]
	if g.Sampled {
		t.Error("a 21-Task Job reported its clusters as sampled; it listed everything")
	}
	cs := g.Clusters
	if len(cs) != 2 {
		t.Fatalf("got %d clusters, want 2", len(cs))
	}
	if cs[0].Count != 20 || !cs[0].Representative || len(cs[0].Rows) != 1 {
		t.Errorf("the 20 identical results did not collapse to one representative: %+v", cs[0])
	}
	if cs[1].Count != 1 || cs[1].Representative {
		t.Errorf("the single differing result was collapsed: %+v", cs[1])
	}
}

// TestJob_SentinelExitCodesAreNotRenderedAsProcessResults.
//
// The daemon uses -1 exclusively as "no exit status": denied before spawn,
// killed, never sent. Relay-synthesized outcomes carry a zero that means
// nothing. Rendering either as an exit code invites an operator to read "did
// not run" as a real result — and "exit 0" beside `unreachable` says it
// succeeded.
func TestJob_SentinelExitCodesAreNotRenderedAsProcessResults(t *testing.T) {
	cases := []struct {
		outcome jobs.Outcome
		code    int32
		want    bool
	}{
		{jobs.OutcomeSuccess, 0, true},
		{jobs.OutcomeFailure, 2, true},
		{jobs.OutcomeDeniedByPolicy, -1, false},
		{jobs.OutcomeTimeout, -1, false},
		{jobs.OutcomeCancelled, -1, false},
		{jobs.OutcomeUnreachable, 0, false},
		{jobs.OutcomeVersionRefused, 0, false},
		{jobs.OutcomeUnsupported, 0, false},
	}
	for _, c := range cases {
		if got := hasRealExitStatus(c.outcome, c.code); got != c.want {
			t.Errorf("%s with code %d: has real exit status = %v, want %v",
				OutcomeLabel(c.outcome), c.code, got, c.want)
		}
	}

	// Having one and being worth screen are different questions. A success
	// exits zero by definition, so printing it says nothing and prints it in
	// the failure colour while doing so.
	shown := func(o jobs.Outcome, code int32) bool {
		row := mutateTask("n", o, "")
		row.ExitCode = code
		return newTaskRow(row, false, "service.restart").ShowExit
	}
	if shown(jobs.OutcomeSuccess, 0) {
		t.Error("a successful Task renders \"exit 0\" — the outcome already said so, in the failure colour")
	}
	if !shown(jobs.OutcomeFailure, 3) {
		t.Error("a failing Task hides the exit code that explains it")
	}
	if shown(jobs.OutcomeDeniedByPolicy, -1) {
		t.Error("a deny renders the daemon's no-exit-status sentinel")
	}
}

// TestJob_ReadsPerNodeResultsThroughTheQueryLane covers what the aggregate
// alone cannot say: per-Node exit codes, captured output, and the Tasks still
// in flight. It replaces the JobReader-seam test the query-lane migration
// deleted (#423).
func TestJob_ReadsPerNodeResultsThroughTheQueryLane(t *testing.T) {
	tasks := []capability.TaskRow{
		mutateTask("node-web-1", jobs.OutcomeSuccess, "restarted"),
		func() capability.TaskRow {
			row := mutateTask("node-web-2", jobs.OutcomeFailure, "")
			row.ExitCode = 3
			row.Stderr = []byte("unit not found")
			return row
		}(),
	}
	sum := oneJob(tasks, jobs.RiskClassMutate)
	// One more Task exists and has not resolved: it is in the Job's Total but
	// in no outcome tally, which is exactly how the aggregate reports it.
	sum.Total = 3
	sum.Unresolved = 1
	sum.State = jobs.JobStateRunning

	q := &fakeQueries{jobs: []capability.JobSummary{sum}, tasks: tasks}
	body := jobBody(t, jobDeps(q), jobPath(""))

	if !strings.Contains(body, "1 still in flight") {
		t.Error("an unresolved Task is not reported as in flight")
	}
	if !strings.Contains(body, "exit 3") {
		t.Error("a genuine non-zero exit code was not rendered")
	}
	// Neither a sentinel nor a redundant zero. `success` already implies exit
	// 0, and .exit is painted in the failure colour — a green row carrying a
	// red "exit 0" spends the product's one alarming colour on its calmest
	// event.
	if strings.Contains(body, "exit -1") || strings.Contains(body, "exit 0") {
		t.Error("an exit code rendered that the outcome already implied, or a sentinel rendered as a result")
	}
	if !strings.Contains(body, "unit not found") {
		t.Error("captured stderr from a mutate Task was not rendered")
	}
	if strings.Index(body, "failure") > strings.Index(body, ">success<") {
		t.Error("success sorted before failure — ordering is by interest, not alphabetical")
	}
	if !strings.Contains(body, "running") {
		t.Error("a Job with an unresolved Task does not render as running")
	}
}

// planBlockOf returns the Plan section, and its STRUCTURE with every text node
// removed — which is what "does not reflow" is a claim about.
func planBlockOf(t *testing.T, body string) (block, skeleton string) {
	t.Helper()
	i := strings.Index(body, `<section class="plan"`)
	if i < 0 {
		t.Fatal("the page renders no Plan block")
	}
	rest := body[i:]
	j := strings.Index(rest, "</section>")
	if j < 0 {
		t.Fatal("the Plan block is unterminated")
	}
	block = rest[:j]
	return block, regexp.MustCompile(`>[^<]*<`).ReplaceAllString(block, "><")
}

// TestJob_PlanBlockDoesNotReflowWhileTheJobRuns is spec 13's fifth criterion
// and foundations rule 6: a Plan is what was agreed, and a block that moves
// under a human is a decision made about something else.
//
// The fake models the real gap it depends on: a Job's Selector lives in the
// dispatch audit record, which the Job engine writes only AFTER the dispatch
// returns, so an in-flight Job genuinely has no Selector to render. The
// STRUCTURE is asserted identical across that transition; the Selector's own
// slot is allowed to resolve from its pending note to the Selector, and
// nothing else may move.
func TestJob_PlanBlockDoesNotReflowWhileTheJobRuns(t *testing.T) {
	tasks := []capability.TaskRow{mutateTask("node-a", jobs.OutcomeSuccess, "restarted")}

	running := oneJob(tasks, jobs.RiskClassMutate)
	running.State = jobs.JobStateRunning
	running.Total = 412
	running.Unresolved = 411
	// In flight: no dispatch audit row exists yet, so nothing has filled these.
	running.Selector = ""
	running.Requester = ""
	running.RequesterAccountID = ""

	complete := running
	complete.State = jobs.JobStateComplete
	complete.Unresolved = 0
	complete.Selector = "node:role=web"
	complete.Requester = "gleipnir"
	complete.RequesterAccountID = "acct-1"

	inflightQ := &fakeQueries{jobs: []capability.JobSummary{running}, tasks: tasks}
	doneQ := &fakeQueries{
		jobs:  []capability.JobSummary{complete},
		tasks: tasks,
		rows:  []capability.AuditRow{{Kind: audit.KindDispatch, JobID: testJobID, Selector: "node:role=web", Principal: "gleipnir:operator"}},
	}

	inflight, inflightSkeleton := planBlockOf(t, jobBody(t, jobDeps(inflightQ), jobPath("")))
	done, doneSkeleton := planBlockOf(t, jobBody(t, jobDeps(doneQ), jobPath("")))

	if inflightSkeleton != doneSkeleton {
		t.Errorf("the Plan block reflowed when the Job completed:\nrunning:  %s\ncomplete: %s", inflightSkeleton, doneSkeleton)
	}
	// The fan-out is fixed at dispatch: every Task is created before the first
	// one runs, so it must not grow as results arrive.
	for _, block := range []string{inflight, done} {
		if !strings.Contains(block, "412 Nodes matched") {
			t.Errorf("the Plan block does not carry the fan-out it was dispatched against: %s", block)
		}
		if strings.Contains(block, "cap ") {
			t.Errorf("the Plan block rendered a blast cap; the Console is never told one (invariant 11): %s", block)
		}
	}
	// The one slot that resolves, and it says which it is rather than
	// pretending the Selector is empty.
	if !strings.Contains(inflight, "recorded in the audit trail") {
		t.Errorf("a running Job's Selector slot is blank rather than pending: %s", inflight)
	}
	if !strings.Contains(done, "node:role=web") {
		t.Errorf("a completed Job does not render the Selector it ran against: %s", done)
	}
}

// TestJob_JobIdIsNotPresentedAsAPlanHash. The plan hash is what an approval
// commits to; a Job ID rendered in its place is a different identifier with
// different meaning, presented as the one an operator is trained to compare.
func TestJob_JobIdIsNotPresentedAsAPlanHash(t *testing.T) {
	tasks := []capability.TaskRow{mutateTask("node-a", jobs.OutcomeSuccess, "ok")}
	q := &fakeQueries{jobs: []capability.JobSummary{oneJob(tasks, jobs.RiskClassMutate)}, tasks: tasks}
	body := jobBody(t, jobDeps(q), jobPath(""))

	if strings.Contains(body, "planhash") {
		t.Error("an ungated dispatch rendered something in the plan-hash slot; nothing retained one")
	}
	if !strings.Contains(body, "no plan hash was retained") {
		t.Error("the page does not say why there is no plan hash")
	}
	// With an approval bound, the REAL hash appears — the approval is the only
	// thing in the Relay that retains one.
	d := jobDeps(&fakeQueries{
		jobs:  []capability.JobSummary{oneJob(tasks, jobs.RiskClassMutate)},
		tasks: tasks,
		rows:  []capability.AuditRow{{Kind: audit.KindDispatch, JobID: testJobID, ApprovalID: "ap-1"}},
	})
	d.Approvals = &fakeApprovals{pending: []approval.Request{{ID: "ap-1", PlanHash: "sha256:4b18c02f9911"}}}
	gated := jobBody(t, d, jobPath(""))

	if !strings.Contains(gated, "sha256:4b18c02f9911") && !strings.Contains(gated, "4b18c02f9911") {
		t.Error("a gated dispatch does not render the plan hash its approval committed to")
	}
	if strings.Contains(gated, `class="planhash" title="This is what an approval commits to.">`+shortHash(testJobID)) {
		t.Error("the Job ID is rendered as the plan hash")
	}
}

// TestJob_OffersNoControlAtAll is v0.6.0's rule, restated per-screen: no route
// on this page reaches the capability layer's write or dispatch path. Cancel
// is v0.7.0, and a Cancel that shipped early would be the first Console
// control that changes the fleet.
func TestJob_OffersNoControlAtAll(t *testing.T) {
	tasks := []capability.TaskRow{mutateTask("node-a", jobs.OutcomeSuccess, "ok")}
	q := &fakeQueries{jobs: []capability.JobSummary{oneJob(tasks, jobs.RiskClassMutate)}, tasks: tasks}
	content := contentOf(jobBody(t, jobDeps(q), jobPath("")))

	for _, banned := range []string{"<form", "<button", `method="post"`, "hx-post", "<script"} {
		if strings.Contains(content, banned) {
			t.Errorf("the Job screen renders %q — no control on this page may reach the capability layer in v0.6.0", banned)
		}
	}
}

// TestJob_ExpandedGroupIsBoundedToo — "show all" is one more click away and is
// still not a list of 9,797. The explicit request is honoured up to a bound
// the page states, which is the difference between a disclosure ladder and a
// denial of service an operator inflicts on themselves.
func TestJob_ExpandedGroupIsBoundedToo(t *testing.T) {
	var tasks []capability.TaskRow
	for i := 0; i < 1000; i++ {
		tasks = append(tasks, mutateTask(fmt.Sprintf("node-%04d", i), jobs.OutcomeSuccess, fmt.Sprintf("restarted %d", i)))
	}
	q := &fakeQueries{jobs: []capability.JobSummary{oneJob(tasks, jobs.RiskClassMutate)}, tasks: tasks}
	body := jobBody(t, jobDeps(q), jobPath("show=success"))

	if n := strings.Count(body, `class="trow"`); n != jobGroupExpanded {
		t.Errorf("an expanded group rendered %d rows, want exactly %d", n, jobGroupExpanded)
	}
	if !strings.Contains(body, "of 1000 listed") {
		t.Error("an expanded group does not say how many of the group it listed")
	}
	if !strings.Contains(body, "computed over the") {
		t.Error("a sampled group does not say its clustering is over the listed rows only")
	}
	for _, limit := range q.taskLimits {
		if limit > jobGroupExpanded {
			t.Errorf("?show= asked the store for %d rows, past the page's own bound", limit)
		}
	}
}

// TestJob_UnwiredQueryLaneRefusesRatherThanRenderingEmpty. An empty Job detail
// is a claim about the Job — "nothing ran, nothing was denied" — made because
// nobody wired a seam.
func TestJob_UnwiredQueryLaneRefusesRatherThanRenderingEmpty(t *testing.T) {
	d := renderableDeps()
	// Explicitly unwired: renderableDeps wires the read lane, because every
	// screen that migrated onto it 500s without one.
	d.Queries = nil
	rec := get(t, newTestHandler(d, accounts.RoleAdmin), jobPath(""))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("Job detail with no query lane wired = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not an empty fleet") {
		t.Error("the refusal does not distinguish a wiring problem from an empty Job")
	}
}

// TestJob_InFlightJobWithNoAuditRowYetStillRenders. The Job engine writes the
// dispatch record only after the dispatch returns, so the trail is EMPTY for a
// Job that is still running. That is normal, and a 404 for it would make the
// screen unreachable during exactly the window an operator most wants it.
func TestJob_InFlightJobWithNoAuditRowYetStillRenders(t *testing.T) {
	sum := oneJob(nil, jobs.RiskClassMutate)
	sum.State = jobs.JobStateRunning
	sum.Total = 412
	sum.Unresolved = 412
	sum.Selector = ""
	sum.Requester = ""
	sum.RequesterAccountID = ""

	q := &fakeQueries{jobs: []capability.JobSummary{sum}}
	body := jobBody(t, jobDeps(q), jobPath(""))

	if !strings.Contains(body, "412 still in flight") {
		t.Error("an in-flight Job does not report its unresolved Tasks")
	}
	if !strings.Contains(body, "unattributed") {
		t.Error("a Job with no attribution yet renders a blank requester rather than saying so")
	}
	if strings.Contains(body, "could not be read") {
		t.Error("a missing dispatch record was reported as a failure; it is the normal in-flight state")
	}
}

// TestJob_UnknownJobIs404 — an id that was never dispatched has no Job, and
// the page says so rather than rendering an empty one.
func TestJob_UnknownJobIs404(t *testing.T) {
	q := &fakeQueries{}
	rec := get(t, newTestHandler(jobDeps(q), accounts.RoleAdmin), jobPath(""))
	if rec.Code != http.StatusNotFound {
		t.Errorf("an unknown Job = %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "No Job with the id") {
		t.Error("the 404 does not name what was not found")
	}

	// An over-long id never reaches the read lane at all: it is
	// caller-controlled and the lane records it in the append-only trail.
	long := strings.Repeat("f", maxJobIDBytes+1)
	rec = get(t, newTestHandler(jobDeps(q), accounts.RoleAdmin), "/console/jobs/"+long)
	if rec.Code != http.StatusNotFound {
		t.Errorf("an over-long Job id = %d, want 404", rec.Code)
	}
	if q.jobCalls != 1 {
		t.Errorf("the read lane was called %d times; the over-long id must be refused before it", q.jobCalls)
	}
}

// TestJob_LongOutputIsClippedAndSaysSo. The daemon's own cap is 1 MiB, which
// is a reasonable thing to store and an unreasonable thing to put on a screen
// once per Node. The note claims only what the page can stand behind: how much
// of what the Relay stored is shown.
func TestJob_LongOutputIsClippedAndSaysSo(t *testing.T) {
	long := strings.Repeat("x", maxOutputBytes*3)
	tasks := []capability.TaskRow{mutateTask("node-a", jobs.OutcomeSuccess, long)}
	q := &fakeQueries{jobs: []capability.JobSummary{oneJob(tasks, jobs.RiskClassMutate)}, tasks: tasks}
	body := jobBody(t, jobDeps(q), jobPath(""))

	if strings.Contains(body, long) {
		t.Error("a Task's whole output was rendered; the page is bounded per row as well as per group")
	}
	if !strings.Contains(body, "Shown to the first 2 KB") {
		t.Error("output was clipped without the page saying so")
	}
	// The page must not claim the DAEMON truncated anything: the Task lane
	// cannot know, and telling an operator nothing was lost when 1 MiB was is
	// worse than saying nothing.
	if strings.Contains(body, "truncated by the daemon") {
		t.Error("the page claims a daemon-side truncation it cannot observe")
	}
}

// TestJob_AFailedRowFetchKeepsTheCounts. The counts came from the aggregate,
// so a failed row query costs the operator the detail and never the page —
// and it says which.
func TestJob_AFailedRowFetchKeepsTheCounts(t *testing.T) {
	tasks := []capability.TaskRow{
		mutateTask("node-a", jobs.OutcomeFailure, "boom"),
		mutateTask("node-b", jobs.OutcomeFailure, "boom"),
	}
	q := &fakeQueries{
		jobs:     []capability.JobSummary{oneJob(tasks, jobs.RiskClassMutate)},
		tasks:    tasks,
		tasksErr: errNotFound,
	}
	body := jobBody(t, jobDeps(q), jobPath(""))

	if !strings.Contains(body, "<b>2</b>") {
		t.Error("a failed row fetch lost the exact count, which did not come from the rows")
	}
	if !strings.Contains(body, "could not be read") {
		t.Error("a failed row fetch renders silently, as if the group were empty")
	}
	// And it renders ONLY that. The elision note is an explanation of a
	// deliberate choice — "at this size the count is the answer" — which is
	// false beside a store error, at a size of two, and it carries a link that
	// re-runs the query that just failed, during the outage that failed it.
	if strings.Contains(body, "at this size the count is") {
		t.Error("a failed row fetch printed the size-based elision explanation beside the true one")
	}
	if strings.Contains(body, "?show=failure") {
		t.Error("a failed row fetch offered a link that re-runs the query that just failed")
	}
	if strings.Contains(body, "none listed") {
		t.Error("a failed row fetch reported the group as deliberately unlisted")
	}
}

// TestJob_DenyRuleIsBoundedLikeEveryOtherByteOnThePage is the boundedness
// claim applied to the one string this page renders that a NODE writes.
//
// A deny rule is the daemon's stderr, the daemon's own cap is 1 MiB, and the
// denied group lists up to jobGroupExpanded of them under the ?show= link the
// page itself offers. Rendered whole that is ~100 MiB of HTML from one GET,
// repeatable by holding down refresh, and reachable by a single compromised
// Node padding its refusal message — on the screen whose entire claim is that
// it is bounded by construction.
func TestJob_DenyRuleIsBoundedLikeEveryOtherByteOnThePage(t *testing.T) {
	const daemonOutputCap = 1 << 20 // daemon/src/config.rs MAX_OUTPUT_BYTES

	var tasks []capability.TaskRow
	for i := 0; i < jobGroupExpanded; i++ {
		row := mutateTask(fmt.Sprintf("node-d%03d", i), jobs.OutcomeDeniedByPolicy, "")
		// Distinct per Node, so clustering cannot be what saves the page.
		row.Stderr = []byte(fmt.Sprintf("deny %d ", i) + strings.Repeat("x", daemonOutputCap))
		tasks = append(tasks, row)
	}
	q := &fakeQueries{jobs: []capability.JobSummary{oneJob(tasks, jobs.RiskClassMutate)}, tasks: tasks}
	body := jobBody(t, jobDeps(q), jobPath("show=denied_by_policy"))

	// 100 rules x 1 MiB is ~104 MB unclipped; clipped it is ~100 x 2 KB.
	if len(body) > 1_000_000 {
		t.Errorf("one page view rendered %d bytes of HTML from %d denies at the daemon's %d-byte cap — "+
			"the deny rule is not bounded", len(body), len(tasks), daemonOutputCap)
	}
	if strings.Contains(body, strings.Repeat("x", maxOutputBytes+1)) {
		t.Errorf("a deny rule longer than maxOutputBytes (%d) rendered whole", maxOutputBytes)
	}
	if !strings.Contains(body, "Shown to the first 2 KB of the refusal") {
		t.Error("a clipped deny rule does not say it was clipped")
	}
	// Clipping is a bound, not a summary: what is shown is still the daemon's
	// own bytes, from the start.
	if !strings.Contains(body, "deny 0 xxx") {
		t.Error("the clipped rule does not begin with what the daemon actually said")
	}
}

// TestJob_ReadClassDenyClaimsNoSharedRuleAndListsEveryNode is F1 of the #423
// security review.
//
// On a read-class Job the trail retained no rule, so every row carries
// denyText's identical explanation of that fact. Clustering on it reported
// that N Nodes fired ONE Policy rule — a fact about Policy this Relay
// deliberately does not have — and then hid every Node ID but the first behind
// the claim, with no elision note, because nothing had been elided.
func TestJob_ReadClassDenyClaimsNoSharedRuleAndListsEveryNode(t *testing.T) {
	var tasks []capability.TaskRow
	for i, node := range []string{"n1", "n2", "n3", "n4"} {
		row := capability.TaskRow{
			TaskID: "task-" + node, NodeID: node, State: jobs.DispatchStateResolved,
			Outcome: jobs.OutcomeDeniedByPolicy, RiskClass: jobs.RiskClassRead,
			// Four DIFFERENT rules, which the read lane strips in production
			// and this fake deliberately does not: the page must not report
			// agreement it cannot see either way.
			Stderr: []byte(fmt.Sprintf("deny file.read /etc/secret-%d", i)),
		}
		tasks = append(tasks, row)
	}
	q := &fakeQueries{jobs: []capability.JobSummary{oneJob(tasks, jobs.RiskClassRead)}, tasks: tasks}
	body := jobBody(t, jobDeps(q), jobPath(""))

	if strings.Contains(body, "fired the same rule") {
		t.Error("a read-class deny group claimed every Node fired one rule; the trail kept no rule to compare")
	}
	if strings.Contains(body, "fired this rule") {
		t.Error("a read-class deny cluster is labelled as a shared rule")
	}
	for _, node := range []string{"n1", "n2", "n3", "n4"} {
		if !strings.Contains(body, ">"+node+"<") {
			t.Errorf("Node %s was dropped from a read-class deny group that elided nothing", node)
		}
	}
	if n := strings.Count(body, `class="trow"`); n != 4 {
		t.Errorf("the read-class deny group listed %d of 4 Nodes", n)
	}
	// And the substitute explanation is still shown once, not four times.
	if n := strings.Count(body, `class="deny"`); n != 1 {
		t.Errorf("the identical not-recorded explanation rendered %d times, want 1", n)
	}
	if !strings.Contains(body, "the deciding rule is recorded for none of them") {
		t.Error("the group does not say why there is no rule for any of these Nodes")
	}
}

// TestJob_MutateDenyWithNoStderrIsNotAssertedAsAgreement is the same defect on
// the other lane: a mutate-class deny the daemon sent no rule for also falls
// back to one identical sentence, and clustering on it would report agreement
// between Nodes that nothing observed.
func TestJob_MutateDenyWithNoStderrIsNotAssertedAsAgreement(t *testing.T) {
	var tasks []capability.TaskRow
	for _, node := range []string{"m1", "m2", "m3", "m4"} {
		tasks = append(tasks, mutateTask(node, jobs.OutcomeDeniedByPolicy, ""))
	}
	q := &fakeQueries{jobs: []capability.JobSummary{oneJob(tasks, jobs.RiskClassMutate)}, tasks: tasks}
	body := jobBody(t, jobDeps(q), jobPath(""))

	if strings.Contains(body, "fired the same rule") || strings.Contains(body, "fired this rule") {
		t.Error("denies with no reported rule were reported as having fired one")
	}
	if n := strings.Count(body, `class="trow"`); n != 4 {
		t.Errorf("listed %d of 4 Nodes whose denials were never explained", n)
	}
}
