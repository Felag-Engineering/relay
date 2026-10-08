package capability

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// TestOutcomeUnrecorded_CoversIntentOnlyAndPartialOnlyWhenComplete: the single
// definition of "intent recorded, outcome unknown" (#887). Running + IntentOnly
// is false by design: it documents the Running-forever case after a crash.
func TestOutcomeUnrecorded_CoversIntentOnlyAndPartialOnlyWhenComplete(t *testing.T) {
	for _, tc := range []struct {
		name      string
		state     jobs.JobState
		recording jobs.JobRecording
		want      bool
	}{
		{"complete, none", jobs.JobStateComplete, jobs.JobRecordingNone, false},
		{"complete, intent only", jobs.JobStateComplete, jobs.JobRecordingIntentOnly, true},
		{"complete, partial", jobs.JobStateComplete, jobs.JobRecordingOutcomePartial, true},
		{"complete, outcome", jobs.JobStateComplete, jobs.JobRecordingOutcome, false},
		{"running, intent only", jobs.JobStateRunning, jobs.JobRecordingIntentOnly, false},
		{"running, partial", jobs.JobStateRunning, jobs.JobRecordingOutcomePartial, false},
		{"running, outcome", jobs.JobStateRunning, jobs.JobRecordingOutcome, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := JobSummary{State: tc.state, Recording: tc.recording}.OutcomeUnrecorded()
			if got != tc.want {
				t.Errorf("OutcomeUnrecorded() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAuditFilter_Validate_OperationsCap is F2 (#441 cycle-2 security
// review): Operations is capped exactly as Kinds is (32 entries x 64 bytes),
// so buildAuditWhere can never be handed enough caller-controlled entries to
// build a multi-hundred-KB statement that blows SQLite's bound-parameter
// limit.
func TestAuditFilter_Validate_OperationsCap(t *testing.T) {
	tooMany := make([]string, 33)
	for i := range tooMany {
		tooMany[i] = "op"
	}
	if err := (AuditFilter{Operations: tooMany}).validate(); !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("33 operations: err = %v, want ErrInvalidFilter", err)
	}

	exactlyMax := make([]string, 32)
	for i := range exactlyMax {
		exactlyMax[i] = "op"
	}
	if err := (AuditFilter{Operations: exactlyMax}).validate(); err != nil {
		t.Errorf("32 operations (at the cap): err = %v, want nil", err)
	}

	tooLong := AuditFilter{Operations: []string{
		"system.facts.this-operation-name-is-far-longer-than-sixty-four-bytes-long",
	}}
	if err := tooLong.validate(); !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("65-byte operation name: err = %v, want ErrInvalidFilter", err)
	}

	// A hostile 60,000-entry list — the reviewer's empirically-confirmed
	// "too many SQL variables" case — is refused long before it reaches SQL.
	hostile := make([]string, 60_000)
	for i := range hostile {
		hostile[i] = "op"
	}
	if err := (AuditFilter{Operations: hostile}).validate(); !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("60,000 operations: err = %v, want ErrInvalidFilter", err)
	}
}

// TestAuditFilter_ValidateWindow is F1 (#441 cycle-2 security review):
// AuditCounts/AuditReach require a bounded Since/Until window.
func TestAuditFilter_ValidateWindow(t *testing.T) {
	since := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name    string
		f       AuditFilter
		wantErr bool
	}{
		{"empty filter (the hostile match-everything case)", AuditFilter{}, true},
		{"since only", AuditFilter{Since: since}, true},
		{"until only", AuditFilter{Until: since.Add(time.Hour)}, true},
		{"span exceeds MaxAggregateWindow", AuditFilter{Since: since, Until: since.Add(MaxAggregateWindow + time.Hour)}, true},
		{"span at MaxAggregateWindow", AuditFilter{Since: since, Until: since.Add(MaxAggregateWindow)}, false},
		{"small bounded window", AuditFilter{Since: since, Until: since.Add(time.Hour)}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.f.validateWindow()
			if c.wantErr && !errors.Is(err, ErrInvalidFilter) {
				t.Errorf("validateWindow() = %v, want ErrInvalidFilter", err)
			}
			if !c.wantErr && err != nil {
				t.Errorf("validateWindow() = %v, want nil", err)
			}
		})
	}
}

// TestClampBucket is F1: a caller-chosen bucket below MinAuditBucket is
// floored, never refused; a bucket at or above the floor passes through
// unchanged.
func TestClampBucket(t *testing.T) {
	cases := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"zero", 0, MinAuditBucket},
		{"one second (the hostile per-second-bucket case)", time.Second, MinAuditBucket},
		{"just under the floor", MinAuditBucket - time.Millisecond, MinAuditBucket},
		{"exactly the floor", MinAuditBucket, MinAuditBucket},
		{"above the floor", time.Hour, time.Hour},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := clampBucket(c.in); got != c.want {
				t.Errorf("clampBucket(%s) = %s, want %s", c.in, got, c.want)
			}
		})
	}
}

// TestJobFilter_SummaryRecordsOnBehalfOf: every filter field this lane can be
// asked for must reach the read record's selector, or the trail cannot answer
// "who searched for whose work". A filter the caller can set and the trail
// does not record is a search that leaves no evidence.
func TestJobFilter_SummaryRecordsOnBehalfOf(t *testing.T) {
	got := JobFilter{OnBehalfOf: "agent-7"}.summary()
	if got != "on_behalf_of=agent-7" {
		t.Errorf("summary() = %q, want on_behalf_of=agent-7", got)
	}

	// The asserted lane is caller-claimed, so it is exactly the field a
	// principal would use to forge the summary's own structure.
	forged := JobFilter{OnBehalfOf: `x;requester=admin;op=raw_exec`}.summary()
	if forged != `on_behalf_of=x\;requester\=admin\;op\=raw_exec` {
		t.Errorf("summary() = %q — a caller-controlled value wrote the summary's own structure", forged)
	}
}

// TestFilters_BoundOnBehalfOf. The asserted lane is caller-controlled and
// crosses this boundary INTACT on its way to the store — the recorded read
// record is truncated by filterSummary, but the value the seam is handed is
// not. Without a bound here the only one is net/http's header limit, which is
// the transport's business and not this layer's, and only one surface has it.
func TestFilters_BoundOnBehalfOf(t *testing.T) {
	long := strings.Repeat("a", maxOnBehalfOfBytes+1)

	if err := (JobFilter{OnBehalfOf: long}).validate(); !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("JobFilter with an over-long on_behalf_of: err = %v, want ErrInvalidFilter", err)
	}
	if err := (AuditFilter{OnBehalfOf: long}).validate(); !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("AuditFilter with an over-long on_behalf_of: err = %v, want ErrInvalidFilter", err)
	}

	// At the bound, not one past it, both are accepted: the bound is a bound
	// and not an off-by-one refusal of a legitimate identity.
	atMax := strings.Repeat("a", maxOnBehalfOfBytes)
	if err := (JobFilter{OnBehalfOf: atMax}).validate(); err != nil {
		t.Errorf("JobFilter at the bound: err = %v, want nil", err)
	}
	if err := (AuditFilter{OnBehalfOf: atMax}).validate(); err != nil {
		t.Errorf("AuditFilter at the bound: err = %v, want nil", err)
	}
}
