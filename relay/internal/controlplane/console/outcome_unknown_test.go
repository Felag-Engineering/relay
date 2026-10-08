package console

import (
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// "Intent recorded, outcome unknown" (#887). The predicate is the capability
// layer's (JobSummary.OutcomeUnrecorded); these tests only prove the screens
// render it, and render it nowhere else.

const (
	chipIntentOnly = "intent recorded · outcome unknown"
	chipPartial    = "outcome partly unknown"
)

func unknownOutcomeJob(rec jobs.JobRecording) capability.JobSummary {
	sum := runningJob("job-1", "gleipnir-prod", "acct-1")
	sum.Unresolved, sum.State, sum.Recording = 0, jobs.JobStateComplete, rec
	return sum
}

func TestActivity_CompleteJobWithOnlyAnIntentSaysOutcomeUnknown(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{unknownOutcomeJob(jobs.JobRecordingIntentOnly)}}
	body := activityRunning(t, q, accounts.RoleAdmin, "/console/activity")

	if !strings.Contains(body, chipIntentOnly) || !strings.Contains(body, `data-state="outcome-unknown"`) {
		t.Errorf("a finished Job with only its intent shows no outcome-unknown chip:\n%s", body)
	}
	if strings.Contains(body, chipPartial) {
		t.Error("an intent-only Job is described as partly recorded")
	}
}

func TestActivity_PartialOutcomeSaysOutcomePartlyUnknown(t *testing.T) {
	q := &fakeQueries{jobs: []capability.JobSummary{unknownOutcomeJob(jobs.JobRecordingOutcomePartial)}}
	body := activityRunning(t, q, accounts.RoleAdmin, "/console/activity")

	if !strings.Contains(body, chipPartial) {
		t.Errorf("a partly recorded Job shows no %q chip:\n%s", chipPartial, body)
	}
	if strings.Contains(body, chipIntentOnly) {
		t.Error("a partly recorded Job is described as having no outcome at all")
	}
}

func TestActivity_FullyRecordedAndRunningJobsHaveNoOutcomeUnknownChip(t *testing.T) {
	running := runningJob("job-1", "gleipnir-prod", "acct-1")
	running.Recording = jobs.JobRecordingIntentOnly
	for name, sum := range map[string]capability.JobSummary{
		"fully recorded": unknownOutcomeJob(jobs.JobRecordingOutcome),
		"legacy, none":   unknownOutcomeJob(jobs.JobRecordingNone),
		// Running already says the outcome is pending.
		"running with only an intent": running,
	} {
		q := &fakeQueries{jobs: []capability.JobSummary{sum}}
		body := activityRunning(t, q, accounts.RoleAdmin, "/console/activity")
		for _, banned := range []string{chipIntentOnly, chipPartial, `data-state="outcome-unknown"`} {
			if strings.Contains(body, banned) {
				t.Errorf("%s: renders %q", name, banned)
			}
		}
	}
}

func TestJob_IntentOnlyJobSaysOutcomeUnknown(t *testing.T) {
	sum := oneJob(nil, jobs.RiskClassMutate)
	sum.Total, sum.Selector, sum.Recording = 2, "", jobs.JobRecordingIntentOnly
	body := jobBody(t, jobDeps(&fakeQueries{jobs: []capability.JobSummary{sum}}), jobPath(""))

	if !strings.Contains(body, chipIntentOnly) {
		t.Errorf("the Job page shows no outcome-unknown chip:\n%s", body)
	}
	if !strings.Contains(body, "no dispatch outcome was recorded") {
		t.Error("the Selector slot still promises a record that is not coming")
	}
	if strings.Contains(body, "recorded in the audit trail when the dispatch completes") {
		t.Error("the Selector note promises an audit record for a finished Job that has none")
	}
}

func TestJob_FullyRecordedJobHasNoOutcomeUnknownChip(t *testing.T) {
	sum := oneJob(nil, jobs.RiskClassMutate)
	sum.Recording = jobs.JobRecordingOutcome
	body := jobBody(t, jobDeps(&fakeQueries{jobs: []capability.JobSummary{sum}}), jobPath(""))

	if strings.Contains(body, chipIntentOnly) || strings.Contains(body, chipPartial) {
		t.Error("a fully recorded Job shows an outcome-unknown chip")
	}
}
