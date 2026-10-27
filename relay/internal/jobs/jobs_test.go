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

// TestOutcomeName_CoversAllEight pins the vocabulary at eight distinct names.
// Three of them are different kinds of "it did not run" that must not be
// collapsed: an operator who cannot tell them apart cannot tell a Policy problem
// from a fleet problem. In particular version_refused (ADR-0014's dispatch-level
// gate) must never render as denied_by_policy or unreachable.
func TestOutcomeName_CoversAllEight(t *testing.T) {
	want := map[Outcome]string{
		OutcomeSuccess:        "success",
		OutcomeFailure:        "failure",
		OutcomeTimeout:        "timeout",
		OutcomeDeniedByPolicy: "denied_by_policy",
		OutcomeCancelled:      "cancelled",
		OutcomeUnreachable:    "unreachable",
		OutcomeVersionRefused: "version_refused",
		OutcomeUnsupported:    "unsupported",
	}
	if len(want) != 8 {
		t.Fatalf("the vocabulary under test has %d entries, want 8", len(want))
	}
	seen := map[string]bool{}
	for outcome, label := range want {
		got := OutcomeName(outcome)
		if got != label {
			t.Errorf("OutcomeName(%d) = %q, want %q", outcome, got, label)
		}
		if seen[got] {
			t.Errorf("%q is produced by more than one outcome: two states have been collapsed", got)
		}
		seen[got] = true
	}
	if got := OutcomeName(OutcomeUnspecified); got != "unspecified" {
		t.Errorf("the zero value renders as %q", got)
	}
}

// TestRiskClassName pins the risk-class wire names. They are persisted and
// hashed into approval shapes, so changing one silently orphans stored rows.
func TestRiskClassName(t *testing.T) {
	for class, want := range map[RiskClass]string{
		RiskClassRead:        "read",
		RiskClassMutate:      "mutate",
		RiskClassUnspecified: "unspecified",
		RiskClass(99):        "unspecified",
	} {
		if got := RiskClassName(class); got != want {
			t.Errorf("RiskClassName(%d) = %q, want %q", class, got, want)
		}
	}
}

// TestParseRiskClass pins ParseRiskClass as RiskClassName's exact inverse: it
// round-trips both classes and refuses everything else, including the empty
// string, case variants and "unspecified".
func TestParseRiskClass(t *testing.T) {
	for _, class := range []RiskClass{RiskClassRead, RiskClassMutate} {
		got, ok := ParseRiskClass(RiskClassName(class))
		if !ok || got != class {
			t.Errorf("ParseRiskClass(%q) = %d, %v; want %d, true", RiskClassName(class), got, ok, class)
		}
	}
	for _, in := range []string{"", "unspecified", "Read", "MUTATE", " read", "any"} {
		if got, ok := ParseRiskClass(in); ok || got != RiskClassUnspecified {
			t.Errorf("ParseRiskClass(%q) = %d, %v; want RiskClassUnspecified, false", in, got, ok)
		}
	}
}

func TestHalt_ZeroValueHasNotHalted(t *testing.T) {
	if (Halt{}).Halted() {
		t.Error("the zero Halt reports a halt")
	}
	if !(Halt{TaskID: "task-1"}).Halted() {
		t.Error("a Halt naming a Task reports no halt")
	}
}

func TestHalt_ReasonNamesTheNodeAndOutcome(t *testing.T) {
	for _, o := range []Outcome{OutcomeFailure, OutcomeTimeout} {
		h := Halt{TaskID: "task-1", NodeID: "node-7", Outcome: o, Resolved: true}
		reason := h.Reason()
		for _, want := range []string{`"node-7"`, OutcomeName(o), "never sent", "in flight"} {
			if !strings.Contains(reason, want) {
				t.Errorf("Reason() = %q, want it to contain %q", reason, want)
			}
		}
		if reason != h.Reason() {
			t.Error("Reason() is not deterministic")
		}
	}
}

// TestHalt_ReasonNeverSaysResolvedOfAnUnresolvedTask: the text claims a
// recorded resolution only when the Halt says the Task holds one.
func TestHalt_ReasonNeverSaysResolvedOfAnUnresolvedTask(t *testing.T) {
	unresolved := Halt{TaskID: "task-1", NodeID: "node-1", Outcome: OutcomeFailure}.Reason()
	if strings.Contains(unresolved, "resolved") || !strings.Contains(unresolved, "no recorded result") {
		t.Errorf("unresolved Reason() = %q, want no 'resolved' and 'no recorded result'", unresolved)
	}
	resolved := Halt{TaskID: "task-1", NodeID: "node-1", Outcome: OutcomeFailure, Resolved: true}.Reason()
	if !strings.Contains(resolved, "resolved failure") || strings.Contains(resolved, "no recorded result") {
		t.Errorf("resolved Reason() = %q, want 'resolved failure' only", resolved)
	}
}

// TestHalt_RestartReasonNamesTheHaltAndClaimsNoLess: a Task marked dispatched
// at a restart may have been sent, so its text never says it was not.
func TestHalt_RestartReasonNamesTheHaltAndClaimsNoLess(t *testing.T) {
	for _, resolved := range []bool{true, false} {
		h := Halt{TaskID: "task-1", NodeID: "node-7", Outcome: OutcomeTimeout, Resolved: resolved}
		reason := h.RestartReason()
		for _, want := range []string{`"node-7"`, OutcomeName(OutcomeTimeout), "restarted", "may have run"} {
			if !strings.Contains(reason, want) {
				t.Errorf("RestartReason() = %q, want it to contain %q", reason, want)
			}
		}
		for _, banned := range []string{"never sent", "nothing ran"} {
			if strings.Contains(reason, banned) {
				t.Errorf("RestartReason() = %q, must not claim %q", reason, banned)
			}
		}
		if !strings.HasPrefix(reason, h.lead()) || !strings.HasPrefix(h.Reason(), h.lead()) {
			t.Errorf("RestartReason() and Reason() must open with the same halt sentence for resolved=%v", resolved)
		}
	}
}

func TestHalt_RestartResultIsAFailureWithNoExitStatus(t *testing.T) {
	h := Halt{TaskID: "task-1", NodeID: "node-7", Outcome: OutcomeFailure, Resolved: true}
	got := h.RestartResult()
	if got.Outcome != OutcomeFailure || got.ExitCode != -1 || string(got.Stderr) != h.RestartReason() ||
		len(got.Stdout) != 0 || got.Truncated {
		t.Errorf("RestartResult() = %+v, want failure, exit -1, RestartReason as stderr and nothing else", got)
	}
}

func TestResolvedOutcomes(t *testing.T) {
	got := ResolvedOutcomes()
	if len(got) != 8 {
		t.Fatalf("ResolvedOutcomes() has %d entries, want 8", len(got))
	}
	seen := map[string]bool{}
	for _, o := range got {
		name := OutcomeName(o)
		if o == OutcomeUnspecified || name == "unspecified" {
			t.Errorf("ResolvedOutcomes() holds %v, which is not a resolved outcome", o)
		}
		if seen[name] {
			t.Errorf("ResolvedOutcomes() repeats %q", name)
		}
		seen[name] = true
	}
	if got[0] != OutcomeSuccess || got[len(got)-1] != OutcomeUnsupported {
		t.Errorf("ResolvedOutcomes() order = %v, want success first and unsupported last", got)
	}
	got[0] = OutcomeFailure
	if ResolvedOutcomes()[0] != OutcomeSuccess {
		t.Error("ResolvedOutcomes() shares its backing array between calls")
	}
}
