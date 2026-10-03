package console

import (
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

func jobHeadOf(t *testing.T, body string) string {
	t.Helper()
	i := strings.Index(body, `<section class="jobhead"`)
	if i < 0 {
		t.Fatal("the page renders no Job header")
	}
	rest := body[i:]
	j := strings.Index(rest, "</section>")
	if j < 0 {
		t.Fatal("the Job header is unterminated")
	}
	return rest[:j]
}

func TestJob_TheRawExecTierIsNeverImpersonated(t *testing.T) {
	const tierMark = `data-tier`
	for _, c := range []struct {
		name      string
		kind      jobs.ActionKind
		opName    string
		rows      []capability.AuditRow
		want      []string
		wantNot   []string
		denyBlock string
	}{
		{
			name: "real Raw Exec", kind: jobs.ActionRawExec,
			want: []string{`data-tier="raw_exec"`, ">Raw Exec<", `<code class="jobop">raw_exec</code>`},
		},
		{
			name: "Operation named raw_exec", kind: jobs.ActionOperation, opName: "raw_exec",
			want:      []string{`<code class="jobop">run_operation · raw_exec</code>`},
			wantNot:   []string{tierMark},
			denyBlock: "run_operation · raw_exec",
		},
		{
			name: "neither name nor tier", kind: jobs.ActionUnspecified,
			want:    []string{`<span class="dim">dispatch</span>`},
			wantNot: []string{tierMark, `<code class="jobop"></code>`},
		},
		{
			name: "collision only on the dispatch record", kind: jobs.ActionUnspecified,
			rows:    []capability.AuditRow{{Kind: audit.KindDispatch, JobID: testJobID, OperationName: "raw_exec"}},
			want:    []string{`<code class="jobop">run_operation · raw_exec</code>`},
			wantNot: []string{tierMark},
		},
		{
			name: "ordinary Operation", kind: jobs.ActionOperation, opName: "service.restart",
			want:    []string{`<code class="jobop">service.restart</code>`},
			wantNot: []string{tierMark},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			task := mutateTask("node-1", jobs.OutcomeSuccess, "ok")
			if c.denyBlock != "" {
				task = mutateTask("node-1", jobs.OutcomeDeniedByPolicy, "")
				task.Stderr = []byte("denied by policy")
			}
			sum := oneJob([]capability.TaskRow{task}, jobs.RiskClassMutate)
			sum.ActionKind, sum.OperationName = c.kind, c.opName
			q := &fakeQueries{jobs: []capability.JobSummary{sum}, tasks: []capability.TaskRow{task}, rows: c.rows}
			body := jobBody(t, jobDeps(q), jobPath(""))

			head := jobHeadOf(t, body)
			for _, w := range c.want {
				if !strings.Contains(head, w) {
					t.Errorf("header lacks %q:\n%s", w, head)
				}
			}
			for _, w := range c.wantNot {
				if strings.Contains(head, w) {
					t.Errorf("header contains %q:\n%s", w, head)
				}
			}
			if c.denyBlock != "" && !strings.Contains(body, `<span class="denyop">`+c.denyBlock+`</span>`) {
				t.Errorf("the deny block does not read %q", c.denyBlock)
			}
		})
	}
}

// The chip is written once per screen. Until it is shared, this keeps Job
// detail's from drifting from Activity's (node_tier_test.go does Node detail's).
func TestJob_TheRawExecChipMatchesActivitys(t *testing.T) {
	chipOf := func(body string) string {
		i := strings.Index(body, `<span class="chip" data-tier="raw_exec">`)
		if i < 0 {
			t.Fatalf("no Raw Exec chip on the page:\n%s", body)
		}
		j := strings.Index(body[i:], "</span>")
		return body[i : i+j+len("</span>")]
	}

	rawExec := runningJob("job-1", "p", "a")
	rawExec.ActionKind, rawExec.OperationName = jobs.ActionRawExec, ""
	activity := activityRunning(t, &fakeQueries{jobs: []capability.JobSummary{rawExec}}, accounts.RoleAdmin, "/console/activity")

	task := mutateTask("node-1", jobs.OutcomeSuccess, "ok")
	sum := oneJob([]capability.TaskRow{task}, jobs.RiskClassMutate)
	sum.ActionKind, sum.OperationName = jobs.ActionRawExec, ""
	detail := jobBody(t, jobDeps(&fakeQueries{jobs: []capability.JobSummary{sum}, tasks: []capability.TaskRow{task}}), jobPath(""))

	if a, d := chipOf(activity), chipOf(jobHeadOf(t, detail)); a != d {
		t.Errorf("the Raw Exec chip differs: Activity %q, Job detail %q", a, d)
	}
}
