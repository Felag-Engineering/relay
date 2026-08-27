package capability

import (
	"errors"
	"testing"
	"time"
)

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
