package console

import (
	"context"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

const rawExecChip = `<span class="chip" data-tier="raw_exec">Raw Exec</span>`

// nodeTasksPanel renders node-web-1's Recent Tasks over one dispatch record.
func nodeTasksPanel(t *testing.T, rec audit.Record) string {
	t.Helper()
	rec.Kind, rec.NodeID, rec.Timestamp = audit.KindDispatch, "node-web-1", testNow
	repo := &captureRepo{}
	if err := repo.Append(context.Background(), rec); err != nil {
		t.Fatalf("Append: %v", err)
	}
	d := fleetFixture()
	d.Audit = repo
	panel := tasksPanelOf(get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/node-web-1").Body.String())
	if panel == "" {
		t.Fatal("the Node page has no Recent Tasks panel")
	}
	return panel
}

// D18 point 5: Raw Exec's tier is conspicuous everywhere it is drawn, and is
// read from the record's structured fields, never from an Operation's name.
func TestNode_TheRawExecTierIsNeverImpersonated(t *testing.T) {
	const tierMark = `data-tier`
	for _, c := range []struct {
		name      string
		rec       audit.Record
		want      []string
		wantNot   []string
		denyBlock string
	}{
		{
			name: "real Raw Exec",
			rec: audit.Record{ActionKind: "raw_exec", RawExecArgv: []string{"/usr/bin/uptime"},
				Outcome: jobs.OutcomeSuccess, JobID: "job-1"},
			want: []string{rawExecChip + `<code>raw_exec</code>`},
		},
		{
			name: "Operation named raw_exec",
			rec: audit.Record{ActionKind: "operation", OperationName: "raw_exec",
				Outcome: jobs.OutcomeDeniedByPolicy, Reason: "denied by policy"},
			want:      []string{`<code>run_operation · raw_exec</code>`},
			wantNot:   []string{tierMark, `<code>raw_exec</code>`},
			denyBlock: "run_operation · raw_exec",
		},
		{
			name: "ordinary Operation",
			rec: audit.Record{ActionKind: "operation", OperationName: "service.restart",
				Outcome: jobs.OutcomeSuccess, JobID: "job-1"},
			want:    []string{`<code>service.restart</code>`},
			wantNot: []string{tierMark},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			panel := nodeTasksPanel(t, c.rec)
			for _, w := range c.want {
				if !strings.Contains(panel, w) {
					t.Errorf("Recent Tasks lacks %q:\n%s", w, panel)
				}
			}
			for _, w := range c.wantNot {
				if strings.Contains(panel, w) {
					t.Errorf("Recent Tasks contains %q:\n%s", w, panel)
				}
			}
			if c.denyBlock != "" && !strings.Contains(panel, `<span class="denyop">`+c.denyBlock+`</span>`) {
				t.Errorf("the deny block does not read %q:\n%s", c.denyBlock, panel)
			}
		})
	}
}

// The chip is written per screen; this keeps Node detail's from drifting from
// Activity's, as TestJob_TheRawExecChipMatchesActivitys does for Job detail.
func TestNode_TheRawExecChipMatchesActivitys(t *testing.T) {
	rawExec := runningJob("job-1", "p", "a")
	rawExec.ActionKind, rawExec.OperationName = jobs.ActionRawExec, ""
	activity := activityRunning(t, &fakeQueries{jobs: []capability.JobSummary{rawExec}}, accounts.RoleAdmin, "/console/activity")
	if !strings.Contains(activity, rawExecChip) {
		t.Fatalf("Activity's Raw Exec chip is no longer %q; update Node detail's to match", rawExecChip)
	}
	panel := nodeTasksPanel(t, audit.Record{ActionKind: "raw_exec", RawExecArgv: []string{"/usr/bin/uptime"},
		Outcome: jobs.OutcomeSuccess})
	if !strings.Contains(panel, rawExecChip) {
		t.Errorf("Node detail draws no chip matching Activity's %q:\n%s", rawExecChip, panel)
	}
}
