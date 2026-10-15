package store

import (
	"context"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

func TestJobRecording_FromCounts(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		total, intents, outcomes int
		want                     jobs.JobRecording
	}{
		{"nothing recorded", 2, 0, 0, jobs.JobRecordingNone},
		{"a zero-Task Job with nothing", 0, 0, 0, jobs.JobRecordingNone},
		{"intent only", 2, 1, 0, jobs.JobRecordingIntentOnly},
		{"some outcomes", 2, 1, 1, jobs.JobRecordingOutcomePartial},
		{"every outcome", 2, 1, 2, jobs.JobRecordingOutcome},
		{"legacy: outcomes, no intent", 2, 0, 2, jobs.JobRecordingOutcome},
		{"legacy: some outcomes, no intent", 3, 0, 1, jobs.JobRecordingOutcomePartial},
		{"pruned Tasks: outcomes remain", 0, 1, 2, jobs.JobRecordingOutcome},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := jobRecording(tc.total, tc.intents, tc.outcomes); got != tc.want {
				t.Errorf("jobRecording(%d, %d, %d) = %v, want %v", tc.total, tc.intents, tc.outcomes, got, tc.want)
			}
		})
	}
}

// TestJobQuery_RecordingDistinguishesIntentFromOutcome is the read lane's side
// of #887, end to end over a real store: the trail holds an intent row with
// none, some or all of a Job's outcome rows, and QueryJobs says which.
func TestJobQuery_RecordingDistinguishesIntentFromOutcome(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	resolved := func(id, node string) jobs.Task {
		return jobs.Task{ID: id, NodeID: node, Action: jobs.Action{Kind: jobs.ActionRawExec, RiskClass: jobs.RiskClassMutate}, State: jobs.DispatchStateResolved, Outcome: jobs.OutcomeSuccess}
	}
	twoTasks := func(job string) []jobs.Task {
		return []jobs.Task{resolved(job+"-t1", "node-1"), resolved(job+"-t2", "node-2")}
	}
	intent := func(job string) {
		t.Helper()
		if err := st.Audit().Append(ctx, intentRecord("aud-"+job+"-intent", job)); err != nil {
			t.Fatalf("append intent: %v", err)
		}
	}

	createJobFixture(t, ctx, st, "job-none", base, twoTasks("job-none"))

	createJobFixture(t, ctx, st, "job-intent", base, twoTasks("job-intent"))
	intent("job-intent")

	createJobFixture(t, ctx, st, "job-partial", base, twoTasks("job-partial"))
	intent("job-partial")
	dispatchAuditRecordFull(t, ctx, st, "aud-partial-1", "job-partial", "node-1", jobs.OutcomeSuccess, base)

	createJobFixture(t, ctx, st, "job-full", base, twoTasks("job-full"))
	intent("job-full")
	dispatchAuditRecordFull(t, ctx, st, "aud-full-1", "job-full", "node-1", jobs.OutcomeSuccess, base)
	dispatchAuditRecordFull(t, ctx, st, "aud-full-2", "job-full", "node-2", jobs.OutcomeSuccess, base)

	createJobFixture(t, ctx, st, "job-legacy", base, twoTasks("job-legacy"))
	dispatchAuditRecordFull(t, ctx, st, "aud-legacy-1", "job-legacy", "node-1", jobs.OutcomeSuccess, base)
	dispatchAuditRecordFull(t, ctx, st, "aud-legacy-2", "job-legacy", "node-2", jobs.OutcomeSuccess, base)

	for job, want := range map[string]jobs.JobRecording{
		"job-none":    jobs.JobRecordingNone,
		"job-intent":  jobs.JobRecordingIntentOnly,
		"job-partial": jobs.JobRecordingOutcomePartial,
		"job-full":    jobs.JobRecordingOutcome,
		"job-legacy":  jobs.JobRecordingOutcome,
	} {
		page, err := st.JobQueries().QueryJobs(ctx, jobs.JobQuery{JobID: job}, 0, "")
		if err != nil || len(page.Jobs) != 1 {
			t.Fatalf("QueryJobs(%s): %v (%d jobs)", job, err, len(page.Jobs))
		}
		if got := page.Jobs[0].Recording; got != want {
			t.Errorf("%s: Recording = %v, want %v", job, got, want)
		}
	}
}
