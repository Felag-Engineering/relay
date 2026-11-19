package console

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/policyview"
)

// The tests in this file prove the rule in audit-and-read-lane.md: a control,
// invisible or bidirectional character in an argument, an Operation name, Node
// output or a Node-reported Policy is drawn as a visible escape on every Console
// surface that shows it, never raw.

const lookalikePath = "/var/log/app.log"

// hostile is a path-shaped value that reads as lookalikePath and is not,
// with the escape text a reader must see in its place.
type hostile struct {
	name, value, escape string
}

func hostileVectors() []hostile {
	r := func(c rune) string { return string(rune(c)) }
	return []hostile{
		{"C1 control", "/var/log/app" + r(0x85) + ".log", `app\u0085.log`},
		{"zero-width", "/var/log/app" + r(0x200b) + ".log", `app\u200b.log`},
		{"RLO", "/var/log/" + r(0x202e) + "gol.ppa", `\u202egol.ppa`},
		{"LRI", "/var/log/" + r(0x2066) + "app.log" + r(0x2069), `\u2066app.log\u2069`},
		{"no-break space", "/var/log/app" + r(0xa0) + ".log", `app\u00a0.log`},
	}
}

// requireVisible asserts the three properties of the rule on one rendered text:
// the escape is there, no raw hidden rune is, and it does not read as the plain
// lookalike.
func requireVisible(t *testing.T, where, text string, v hostile) {
	t.Helper()
	if !strings.Contains(text, v.escape) {
		t.Errorf("%s lacks the visible escape %q", where, v.escape)
	}
	for _, r := range v.value {
		if (r > 0x7e || r < 0x20) && strings.ContainsRune(text, r) {
			t.Errorf("%s holds the raw character %U", where, r)
		}
	}
	if strings.Contains(text, lookalikePath) {
		t.Errorf("%s reads as the plain lookalike %q", where, lookalikePath)
	}
}

// TestActivity_ArgumentsShowInvisibleCharactersAsEscapes: a Job row (named
// arguments and Raw Exec argv) and a refusal row each draw their argument and
// Operation name with visible escapes, on the screen and in the CSV export.
func TestActivity_ArgumentsShowInvisibleCharactersAsEscapes(t *testing.T) {
	for _, v := range hostileVectors() {
		t.Run(v.name, func(t *testing.T) {
			q := &fakeQueries{
				jobs: []capability.JobSummary{{
					JobID: "job-1", CreatedAt: testNow, OperationName: "file.read",
					ActionKind: jobs.ActionOperation, RiskClass: jobs.RiskClassRead,
					Args:      map[string]string{"path": v.value},
					Requester: "gleipnir", RequesterAccountID: "acct-1",
					Total: 1, Counts: map[jobs.Outcome]int{jobs.OutcomeSuccess: 1},
				}, {
					JobID: "job-2", CreatedAt: testNow, OperationName: "tail" + string(rune(0x202e)) + "x",
					ActionKind: jobs.ActionOperation, RiskClass: jobs.RiskClassMutate,
					Requester: "gleipnir", RequesterAccountID: "acct-1",
					Total: 1, Counts: map[jobs.Outcome]int{jobs.OutcomeSuccess: 1},
				}, {
					JobID: "job-3", CreatedAt: testNow, OperationName: "raw_exec",
					ActionKind: jobs.ActionRawExec, RiskClass: jobs.RiskClassMutate,
					RawExecArgv: []string{"/usr/bin/tail", v.value},
					Requester:   "gleipnir", RequesterAccountID: "acct-1",
					Total: 1, Counts: map[jobs.Outcome]int{jobs.OutcomeSuccess: 1},
				}},
				// Dispatch rows are not read from the trail lane: the Job lane above
				// draws them. A refusal is the trail row that names an Operation.
				rows: []capability.AuditRow{{
					Kind: audit.KindRefusal, Timestamp: testNow,
					OperationName: "file.read" + string(rune(0x202e)),
				}},
			}
			h := newTestHandler(activityDeps(q), accounts.RoleAdmin)
			for name, path := range map[string]string{
				"HTML": "/console/activity",
				"CSV":  "/console/activity?format=csv",
			} {
				body := get(t, h, path).Body.String()
				requireVisible(t, name, body, v)
				if !strings.Contains(body, "file.read"+`\u202e`) {
					t.Errorf("%s: the refusal's Operation name is not drawn with a visible escape", name)
				}
				if !strings.Contains(body, "tail"+`\u202e`+"x") {
					t.Errorf("%s: the Job's Operation name is not drawn with a visible escape", name)
				}
				if strings.ContainsRune(body, rune(0x202e)) && v.name != "RLO" {
					t.Errorf("%s holds a raw right-to-left override", name)
				}
			}
		})
	}
}

// TestActivity_ReasonShowsInvisibleCharactersAsEscapes: a refusal Reason that
// quotes a caller value is drawn with its invisible characters as escapes, and
// the escapes strconv.Quote already wrote are not doubled.
func TestActivity_ReasonShowsInvisibleCharactersAsEscapes(t *testing.T) {
	hangulFiller := string(rune(0x3164))
	for _, v := range hostileVectors() {
		t.Run(v.name, func(t *testing.T) {
			q := &fakeQueries{rows: []capability.AuditRow{
				{Kind: audit.KindRefusal, Timestamp: testNow, Reason: "refused: " + v.value},
				{Kind: audit.KindRefusal, Timestamp: testNow, Reason: "refused " + strconv.Quote("a"+hangulFiller+"b")},
			}}
			h := newTestHandler(activityDeps(q), accounts.RoleAdmin)
			for name, path := range map[string]string{
				"HTML": "/console/activity",
				"CSV":  "/console/activity?format=csv",
			} {
				body := get(t, h, path).Body.String()
				requireVisible(t, name, body, v)
				if strings.Contains(body, hangulFiller) {
					t.Errorf("%s holds the raw Hangul filler", name)
				}
				if !strings.Contains(body, `a\u3164b`) || strings.Contains(body, `\\u3164`) {
					t.Errorf("%s does not show the quoted value with a visible escape and no doubling", name)
				}
			}
		})
	}
}

// TestJob_ArgumentsOutputAndDenyRuleShowInvisibleCharactersAsEscapes: the Job
// page draws arguments, captured output and a denied Task's rule with visible
// escapes, keeps the output's line breaks, and does not merge two outputs that
// differ by one invalid byte.
func TestJob_ArgumentsOutputAndDenyRuleShowInvisibleCharactersAsEscapes(t *testing.T) {
	for _, v := range hostileVectors() {
		t.Run(v.name, func(t *testing.T) {
			out := mutateTask("node-a", jobs.OutcomeSuccess, "line1\n"+v.value)
			deny := mutateTask("node-d", jobs.OutcomeDeniedByPolicy, "")
			deny.Stderr = []byte("deny " + v.value)
			tasks := []capability.TaskRow{out, deny}
			sum := oneJob(tasks, jobs.RiskClassMutate)
			q := &fakeQueries{jobs: []capability.JobSummary{sum}, tasks: tasks,
				rows: []capability.AuditRow{{
					Kind: audit.KindDispatch, JobID: testJobID, OperationName: "service.restart",
					Args: map[string]string{"path": v.value},
				}}}

			body := jobBody(t, jobDeps(q), jobPath(""))

			requireVisible(t, "Job page", body, v)
			if n := strings.Count(body, v.escape); n < 3 {
				t.Errorf("the escape appears %d times, want it in the arguments, the output and the deny rule", n)
			}
			if !strings.Contains(body, "line1\n") {
				t.Error("the output's line break was not kept")
			}
		})
	}

	a := mutateTask("node-a", jobs.OutcomeSuccess, "out"+string([]byte{0xff}))
	b := mutateTask("node-b", jobs.OutcomeSuccess, "out"+string([]byte{0xfe}))
	tasks := []capability.TaskRow{a, b}
	q := &fakeQueries{jobs: []capability.JobSummary{oneJob(tasks, jobs.RiskClassMutate)}, tasks: tasks}
	groups := jobGroups(t.Context(), jobDeps(q), capability.Principal{}, oneJob(tasks, jobs.RiskClassMutate), "", "service.restart")
	if len(groups) != 1 || len(groups[0].Clusters) != 2 {
		t.Fatalf("outputs differing by one invalid byte clustered together: %+v", groups)
	}
}

// TestNode_ReportedPolicyAndRecentTasksShowInvisibleCharactersAsEscapes: the
// Node-reported Policy and the Recent Tasks list draw hidden characters as
// visible escapes, and a Policy regex with an ordinary backslash is unchanged.
func TestNode_ReportedPolicyAndRecentTasksShowInvisibleCharactersAsEscapes(t *testing.T) {
	const regex = `^/usr/bin/systemctl\sstatus$`
	for _, v := range hostileVectors() {
		t.Run(v.name, func(t *testing.T) {
			d := fleetFixture()
			d = withPolicy(d, map[string]policyview.Snapshot{"node-web-1": reportedSnapshot(policyview.Snapshot{
				RawExecEnabled:   true,
				RawAllowPatterns: []string{v.value, regex},
				OperationRules: []policyview.OperationRule{{
					Name: "file.read", AllowedArgs: [][]string{{v.value}},
				}},
			}, testNow.Add(-time.Minute))})
			d.Audit = fakeAudit{records: []audit.Record{{
				Kind: audit.KindDispatch, NodeID: "node-web-1", OperationName: "file.read",
				Args: map[string]string{"path": v.value}, Outcome: jobs.OutcomeSuccess,
				JobID: "job-1", Timestamp: testNow,
			}, {
				Kind: audit.KindDispatch, NodeID: "node-web-1", OperationName: "service.restart",
				Outcome: jobs.OutcomeDeniedByPolicy, Reason: "deny " + v.value, Timestamp: testNow.Add(time.Second),
			}}}

			body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/node-web-1").Body.String()

			policy := policyPanelOf(body)
			if policy == "" {
				t.Fatal("no effective-Policy panel rendered")
			}
			requireVisible(t, "Policy panel", policy, v)
			if !strings.Contains(policy, regex) {
				t.Errorf("the Policy regex was changed: want %q in\n%s", regex, policy)
			}
			tasks := tasksPanelOf(body)
			if tasks == "" {
				t.Fatal("no Recent Tasks panel rendered")
			}
			requireVisible(t, "Recent Tasks panel", tasks, v)
			if n := strings.Count(tasks, v.escape); n < 2 {
				t.Errorf("Recent Tasks shows the escape %d times, want the argument and the deny text", n)
			}
		})
	}
}

// TestCompare_ReportedPolicyShowsInvisibleCharactersAsEscapes: Compare draws a
// Node-reported pattern with visible escapes and still marks the row as
// differing, because escaping is exact.
func TestCompare_ReportedPolicyShowsInvisibleCharactersAsEscapes(t *testing.T) {
	for _, v := range hostileVectors() {
		t.Run(v.name, func(t *testing.T) {
			d := fleetFixture()
			d = withPolicy(d, map[string]policyview.Snapshot{
				"node-web-1": reportedSnapshot(policyview.Snapshot{
					RawDenyPatterns: []string{v.value},
				}, testNow.Add(-time.Minute)),
				"node-web-2": reportedSnapshot(policyview.Snapshot{
					RawDenyPatterns: []string{lookalikePath},
				}, testNow.Add(-time.Minute)),
			})

			body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/compare?nodes=node-web-1,node-web-2").Body.String()

			if !strings.Contains(body, v.escape) {
				t.Fatalf("Compare lacks the visible escape %q", v.escape)
			}
			for _, r := range v.value {
				if (r > 0x7e || r < 0x20) && strings.ContainsRune(body, r) {
					t.Errorf("Compare holds the raw character %U", r)
				}
			}
			// The lookalike is Node two's own value, so it is legitimately on the
			// page once. A second occurrence would be the hostile value reading as it.
			if n := strings.Count(body, lookalikePath); n != 1 {
				t.Errorf("the plain lookalike appears %d times, want exactly once (Node two's value)", n)
			}
			if !strings.Contains(strings.ToLower(body), "differ") {
				t.Error("the differing patterns are not marked as differing")
			}
		})
	}
}

// TestVisiblePolicy_EscapesEveryNodeChosenStringAndKeepsTheRest sets every
// Snapshot field: each string a Node chose is escaped, a plain value reads as
// itself, and the fields that are not text pass through unchanged.
func TestVisiblePolicy_EscapesEveryNodeChosenStringAndKeepsTheRest(t *testing.T) {
	hidden := "app" + string(rune(0x202e)) + ".log"
	const shown = `app\u202e.log`
	in := policyview.Snapshot{
		RawExecEnabled:    true,
		RawAllowPatterns:  []string{hidden, lookalikePath},
		RawDenyPatterns:   []string{hidden, lookalikePath},
		AllowedOperations: []string{hidden, "file.read"},
		PolicyFingerprint: "fp-1",
		ReportedAt:        testNow,
		OperationRules: []policyview.OperationRule{
			{Name: hidden, AllowedArgs: [][]string{{hidden, lookalikePath}}},
		},
		DenyRules: []policyview.DenyRule{
			{Name: hidden, Args: [][]string{{hidden, lookalikePath}}},
		},
	}
	want := policyview.Snapshot{
		RawExecEnabled:    true,
		RawAllowPatterns:  []string{shown, lookalikePath},
		RawDenyPatterns:   []string{shown, lookalikePath},
		AllowedOperations: []string{shown, "file.read"},
		PolicyFingerprint: "fp-1",
		ReportedAt:        testNow,
		OperationRules: []policyview.OperationRule{
			{Name: shown, AllowedArgs: [][]string{{shown, lookalikePath}}},
		},
		DenyRules: []policyview.DenyRule{
			{Name: shown, Args: [][]string{{shown, lookalikePath}}},
		},
	}

	got := visiblePolicy(in)

	if !reflect.DeepEqual(got, want) {
		t.Errorf("visiblePolicy =\n%+v\nwant\n%+v", got, want)
	}
	if in.OperationRules[0].Name != hidden || in.DenyRules[0].Args[0][0] != hidden || in.AllowedOperations[0] != hidden {
		t.Error("visiblePolicy modified its input")
	}
}

// TestJob_StoredApprovalSummaryShowsInvisibleCharactersAsEscapes: the Console
// rule from the issue (the approval question and notice have their own claim in
// approval.md, not this page). A Summary stored by the earlier formatter left
// Template Operation names and slot keys raw; the Job page draws them as escapes, and a Summary
// that already holds an escape as text is not escaped a second time.
func TestJob_StoredApprovalSummaryShowsInvisibleCharactersAsEscapes(t *testing.T) {
	r := func(c rune) string { return string(c) }
	legacy := "run tpl" + r(0x202e) + r(0x200b) + r(0xa0) + "x on 2 Nodes with slot" + r(0x2066) + r(0x85) + "=v"
	already := `run tpl\u202ex on 1 Node`

	jobPage := func(stored string) string {
		tasks := gatedTasks()
		q := &fakeQueries{jobs: []capability.JobSummary{oneJob(tasks, jobs.RiskClassMutate)}, tasks: tasks,
			rows: []capability.AuditRow{{Kind: audit.KindDispatch, JobID: testJobID, ApprovalID: "ap-1"}}}
		d := jobDeps(q)
		d.Approvals = &fakeApprovals{pending: []approval.Request{{
			ID: "ap-1", State: approval.StateApproved, RequestedBy: "gleipnir",
			MatchedRules: []string{"prod-mutate"}, Summary: stored, PlanHash: "sha256:4b18c02f9911",
		}}}
		return jobBody(t, d, jobPath(""))
	}

	body := jobPage(legacy)
	for _, c := range []rune{0x202e, 0x200b, 0xa0, 0x2066, 0x85} {
		if strings.ContainsRune(body, c) {
			t.Errorf("legacy summary: Job page holds the raw character %U", c)
		}
	}
	for _, w := range []string{`tpl\u202e\u200b\u00a0x`, `slot\u2066\u0085=v`} {
		if !strings.Contains(body, w) {
			t.Errorf("legacy summary: Job page lacks the visible escape %q", w)
		}
	}

	body = jobPage(already)
	if !strings.Contains(body, already) {
		t.Errorf("Job page does not show %q unchanged", already)
	}
	if strings.Contains(body, `\u005c`) {
		t.Error("an existing escape was escaped a second time")
	}
}
