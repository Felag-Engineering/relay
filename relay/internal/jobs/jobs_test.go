package jobs

import (
	"strings"
	"testing"
)

// TestProtocolViolationExplanation_Legibility pins ProtocolViolation's TEXT
// against the exact lie #632 is about, mirroring
// capability/refusal_legibility_test.go's positive+negative style. It is
// the assertion that stops a later editor softening this text back into
// "the Task was never sent" — the sentence a forged version_refused row
// would otherwise render.
func TestProtocolViolationExplanation_Legibility(t *testing.T) {
	required := []string{
		"WAS dispatched",
		"may have executed",
		"/proto",
	}
	forbidden := []string{
		"never sent",
		"was not sent",
		"nothing executed",
		"denied_by_policy",
		"Policy",
	}

	cases := []struct {
		name       string
		v          ProtocolViolation
		wantsNamed bool // ViolationRelayOnlyOutcome names the value it refused; ViolationUnresolvedOutcome has no value to name.
	}{
		{"relay_only_outcome", ProtocolViolation{Rule: ViolationRelayOnlyOutcome, ReportedOutcome: "OUTCOME_VERSION_REFUSED"}, true},
		{"unresolved_outcome", ProtocolViolation{Rule: ViolationUnresolvedOutcome, ReportedOutcome: "OUTCOME_UNSPECIFIED"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.v.Explanation()
			for _, want := range required {
				if !strings.Contains(got, want) {
					t.Errorf("Explanation() missing %q: %s", want, got)
				}
			}
			if c.wantsNamed && !strings.Contains(got, c.v.ReportedOutcome) {
				t.Errorf("Explanation() does not name the reported outcome %q: %s", c.v.ReportedOutcome, got)
			}
			// Lower-cased on both sides: a forbidden phrase capitalized at the
			// start of a sentence ("Never sent.") must still trip this check
			// (code review, cycle 2) — the whole point is to catch the #632 lie
			// in any casing an editor might reach for.
			lowerGot := strings.ToLower(got)
			for _, bad := range forbidden {
				if strings.Contains(lowerGot, strings.ToLower(bad)) {
					t.Errorf("Explanation() must never contain %q — that is the #632 lie or a Policy claim it must not make: %s", bad, got)
				}
			}
		})
	}
}

// TestProtocolViolationExplanation_EmptyForNoViolation asserts the zero
// value (no violation) explains nothing — a routine, unviolated Result must
// never carry Relay-authored protocol-violation prose.
func TestProtocolViolationExplanation_EmptyForNoViolation(t *testing.T) {
	if got := (ProtocolViolation{}).Explanation(); got != "" {
		t.Errorf("Explanation() for the zero ProtocolViolation = %q, want empty", got)
	}
}

// TestProtocolViolationExplanation_UnnamedOutcome asserts an empty
// ReportedOutcome renders as prose rather than a dangling %s.
func TestProtocolViolationExplanation_UnnamedOutcome(t *testing.T) {
	got := ProtocolViolation{Rule: ViolationRelayOnlyOutcome}.Explanation()
	if !strings.Contains(got, "an unnamed value") {
		t.Errorf("Explanation() with no ReportedOutcome = %q, want it to say \"an unnamed value\"", got)
	}
}

// TestProtocolViolation_Violated asserts Violated() is false only for the
// zero value.
func TestProtocolViolation_Violated(t *testing.T) {
	if (ProtocolViolation{}).Violated() {
		t.Error("Violated() = true for the zero ProtocolViolation")
	}
	if !(ProtocolViolation{Rule: ViolationRelayOnlyOutcome}).Violated() {
		t.Error("Violated() = false for ViolationRelayOnlyOutcome")
	}
	if !(ProtocolViolation{Rule: ViolationUnresolvedOutcome}).Violated() {
		t.Error("Violated() = false for ViolationUnresolvedOutcome")
	}
}
