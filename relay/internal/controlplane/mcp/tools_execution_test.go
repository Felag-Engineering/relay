package mcp

import (
	"context"
	"encoding/json"
	"testing"
)

// TestRequirePrincipal_NoPrincipalInContextIsALegibleError is RB4's
// hardening (plan review): the execution tools must never fall through with
// a zero-value capability.Principal when PrincipalFromContext reports !ok.
func TestRequirePrincipal_NoPrincipalInContextIsALegibleError(t *testing.T) {
	if _, err := requirePrincipal(context.Background()); err == nil {
		t.Fatal("requirePrincipal(no principal in context) = nil error, want a legible error (RB4: never dispatch/cancel unattributed)")
	}
}

// TestResolveTimeoutSeconds_RejectsOutOfRange is RB6's concrete bound
// (plan review): timeout_seconds outside [0, maxTimeoutSeconds] is a
// legible rejection, never a silent clamp/overflow on an RCE surface.
func TestResolveTimeoutSeconds_RejectsOutOfRange(t *testing.T) {
	if _, err := resolveTimeoutSeconds(-1); err == nil {
		t.Error("resolveTimeoutSeconds(-1) = nil error, want a rejection")
	}
	if _, err := resolveTimeoutSeconds(maxTimeoutSeconds + 1); err == nil {
		t.Error("resolveTimeoutSeconds(max+1) = nil error, want a rejection")
	}
	if got, err := resolveTimeoutSeconds(0); err != nil || got != 0 {
		t.Errorf("resolveTimeoutSeconds(0) = (%d, %v), want (0, nil)", got, err)
	}
	if got, err := resolveTimeoutSeconds(maxTimeoutSeconds); err != nil || got != maxTimeoutSeconds {
		t.Errorf("resolveTimeoutSeconds(max) = (%d, %v), want (%d, nil)", got, err, maxTimeoutSeconds)
	}
}

// TestRunOrPlanOutput_ZeroMatchMatchesIssue118Shape is the PLAN-REVIEWER
// ADDENDUM A2 regression guard: job_id/results carry NO omitempty on
// RunOrPlanOutput (mirroring ExecutionOutput's own tags exactly), so a
// zero-match plan=false run still renders {"job_id":"","results":[]} —
// byte-identical to #118 — never a bare {}. plan, the only new field, is
// omitempty and absent entirely when nil.
func TestRunOrPlanOutput_ZeroMatchMatchesIssue118Shape(t *testing.T) {
	out := RunOrPlanOutput{Results: []PerNodeResult{}}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	want := `{"job_id":"","results":[]}`
	if string(b) != want {
		t.Errorf("json.Marshal(zero-match RunOrPlanOutput) = %s, want %s", b, want)
	}
}

// TestRunOrPlanOutput_PlanFieldOmittedWhenNil asserts the plan field itself
// carries omitempty — a real (non-plan) response never renders a "plan" key
// at all.
func TestRunOrPlanOutput_PlanFieldOmittedWhenNil(t *testing.T) {
	out := RunOrPlanOutput{JobID: "job-1", Results: []PerNodeResult{{NodeID: "node-1", Outcome: "success"}}}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if _, ok := raw["plan"]; ok {
		t.Errorf("marshaled output %s contains a \"plan\" key, want it omitted when Plan is nil", b)
	}
}
