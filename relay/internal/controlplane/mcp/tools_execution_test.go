package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/opvocab"
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

// TestRunOrPlanOutput_ZeroMatchOmitsJobID is #207/#253's job_id contract
// (deliberately superseding #119's byte-identical-to-#118 freeze, which
// pinned {"job_id":"","results":[]} here): a zero-match plan=false run
// created no Job, so it renders NO job_id key at all — an empty-string id
// read as a missing/failed id. results stays an explicit empty array, never
// null and never a bare {}.
func TestRunOrPlanOutput_ZeroMatchOmitsJobID(t *testing.T) {
	out := RunOrPlanOutput{Results: []PerNodeResult{}}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	want := `{"results":[]}`
	if string(b) != want {
		t.Errorf("json.Marshal(zero-match RunOrPlanOutput) = %s, want %s (no Job was created, so no job_id key)", b, want)
	}
}

// TestRunOrPlanOutput_PlanResponseOmitsJobID is #207/#253 item 2's emitted-
// JSON assertion: a plan=true response (the exact shape both execution
// tools' plan branches construct) carries NO job_id key — a Plan creates no
// Job — while results stays an explicit empty array, never null.
func TestRunOrPlanOutput_PlanResponseOmitsJobID(t *testing.T) {
	plan := renderPlan(capability.PlanResult{Matched: 0})
	out := RunOrPlanOutput{Results: []PerNodeResult{}, Plan: &plan}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if _, ok := raw["job_id"]; ok {
		t.Errorf("plan response %s contains a \"job_id\" key, want it omitted (a Plan creates no Job)", b)
	}
	if string(raw["results"]) != "[]" {
		t.Errorf("plan response results = %s, want [] (an explicit empty array, never null)", raw["results"])
	}
	if _, ok := raw["plan"]; !ok {
		t.Errorf("plan response %s has no \"plan\" key, want one", b)
	}
}

// TestPerNodeResult_ExitCodePresence is #207/#253 item 1's shape decision:
// exit_code is present in the emitted JSON iff a real process exit status
// exists — outcome success/failure with a daemon-reported code >= 0. The
// daemon's -1 "no exit status" sentinel (denied-before-spawn, spawn failure,
// signal-kill, timeout/cancel kill) and the Relay's synthesized zero value
// (unreachable, version_refused) must never surface as a plausible real
// exit code; outcome is the authoritative did-it-run state.
func TestPerNodeResult_ExitCodePresence(t *testing.T) {
	tests := []struct {
		name     string
		outcome  jobs.Outcome
		exitCode int32
		want     string // exact rendered value, "" = key must be absent
	}{
		{"success exits 0", jobs.OutcomeSuccess, 0, "0"},
		{"failure with a real non-zero exit", jobs.OutcomeFailure, 2, "2"},
		{"spawn failure (daemon -1 sentinel)", jobs.OutcomeFailure, -1, ""},
		{"denied_by_policy never ran (daemon -1 sentinel)", jobs.OutcomeDeniedByPolicy, -1, ""},
		{"timeout killed without an exit status", jobs.OutcomeTimeout, -1, ""},
		{"cancelled killed without an exit status", jobs.OutcomeCancelled, -1, ""},
		{"unreachable never dispatched (Relay zero value)", jobs.OutcomeUnreachable, 0, ""},
		{"version_refused never dispatched (Relay zero value)", jobs.OutcomeVersionRefused, 0, ""},
		{"pending/unspecified has not run", jobs.OutcomeUnspecified, 0, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := perNodeResultFromTask(jobs.Task{NodeID: "node-a", Outcome: tt.outcome, ExitCode: tt.exitCode})
			b, err := json.Marshal(res)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(b, &raw); err != nil {
				t.Fatalf("json.Unmarshal: %v", err)
			}
			got, present := raw["exit_code"]
			if tt.want == "" {
				if present {
					t.Errorf("%s: emitted %s, want NO exit_code key (no real process exit status exists)", tt.name, b)
				}
				return
			}
			if !present {
				t.Errorf("%s: emitted %s, want exit_code %s present", tt.name, b, tt.want)
			} else if string(got) != tt.want {
				t.Errorf("%s: exit_code = %s, want %s", tt.name, got, tt.want)
			}
		})
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

// TestOutcomeString_VersionRefused is ADR-0014's dispatch-level gate render:
// jobs.OutcomeVersionRefused must render as the distinct "version_refused"
// string, never "denied_by_policy" (a Policy verdict, not a Relay-side gate)
// or "unreachable" (a connectivity conclusion).
func TestOutcomeString_VersionRefused(t *testing.T) {
	if got := outcomeString(jobs.OutcomeVersionRefused); got != "version_refused" {
		t.Errorf("outcomeString(OutcomeVersionRefused) = %q, want %q", got, "version_refused")
	}
}

// TestRenderPlan_CarriesOutdatedIntoPerNodeVerdict is ADR-0014's plan-mode
// wire contract: renderPlan copies capability.NodeVerdict.Outdated onto
// PerNodeVerdict.Outdated verbatim, for both an outdated and a current Node.
func TestRenderPlan_CarriesOutdatedIntoPerNodeVerdict(t *testing.T) {
	pr := capability.PlanResult{
		Matched: 2,
		Verdicts: []capability.NodeVerdict{
			{NodeID: "node-old", Status: capability.VerdictAllow, Outdated: true},
			{NodeID: "node-current", Status: capability.VerdictAllow, Outdated: false},
		},
	}
	out := renderPlan(pr)

	byNode := map[string]PerNodeVerdict{}
	for _, v := range out.Verdicts {
		byNode[v.NodeID] = v
	}
	if !byNode["node-old"].Outdated {
		t.Error(`renderPlan: node-old PerNodeVerdict.Outdated = false, want true`)
	}
	if byNode["node-current"].Outdated {
		t.Error(`renderPlan: node-current PerNodeVerdict.Outdated = true, want false`)
	}
}

// stubOpsLister adapts the real opvocab vocabulary to OperationLister for the
// internal (package mcp) tests below, which reach unexported buildOperationAction
// directly. mcp_test.go's opsLister lives in package mcp_test and is not visible
// here.
type stubOpsLister struct{}

func (stubOpsLister) Operations() []opvocab.Descriptor { return opvocab.Operations() }

// --- #345: argument-name validation in buildOperationAction --------------
//
// The defect these guard: an unknown or misspelled arg name was passed
// straight through as an opaque map. A misspelled REQUIRED arg then defaulted
// to empty and the daemon's rejection surfaced as outcome=denied_by_policy —
// which the tool description tells the agent to answer with describe_node +
// narrow + retry, a loop a malformed call can never exit. These prove the
// malformed call now fails fast, before dispatch, with a legible error.

// TestBuildOperationAction_MisspelledRequiredArgIsRejected is the exact trap
// from #345: `service.restart {"unitt":"nginx"}`. The misspelled name must be
// rejected here — NOT dropped, dispatched, and returned as denied_by_policy.
func TestBuildOperationAction_MisspelledRequiredArgIsRejected(t *testing.T) {
	_, err := buildOperationAction(stubOpsLister{}, "service.restart", map[string]string{"unitt": "nginx"}, 0)
	if err == nil {
		t.Fatal("buildOperationAction(service.restart, {unitt}) = nil error, want an unknown-argument rejection")
	}
	msg := err.Error()
	for _, want := range []string{"unitt", "unit", "list_operations"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q must mention %q so the agent can correct the misspelling", msg, want)
		}
	}
}

// TestBuildOperationAction_UnknownArgOnAValidCallIsRejected covers the
// silent-drop half: an otherwise-valid call carrying an extra unknown name
// used to succeed with the extra arg dropped. It must now be rejected.
func TestBuildOperationAction_UnknownArgOnAValidCallIsRejected(t *testing.T) {
	_, err := buildOperationAction(stubOpsLister{}, "file.read", map[string]string{"path": "/etc/os-release", "bogus": "x"}, 0)
	if err == nil {
		t.Fatal("buildOperationAction(file.read, {path, bogus}) = nil error, want the unknown 'bogus' rejected, not silently dropped")
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Errorf("error %q must name the unknown argument 'bogus'", err.Error())
	}
}

// TestBuildOperationAction_ZeroArgOperationRejectsAnyArg: system.facts takes
// no arguments, so any provided name is unknown.
func TestBuildOperationAction_ZeroArgOperationRejectsAnyArg(t *testing.T) {
	if _, err := buildOperationAction(stubOpsLister{}, "system.facts", map[string]string{"x": "y"}, 0); err == nil {
		t.Fatal("buildOperationAction(system.facts, {x}) = nil error, want any argument rejected for a zero-arg Operation")
	}
}

// TestBuildOperationAction_MissingRequiredArgIsRejected: an omitted required
// arg (as opposed to a misspelled one) must also fail fast with the required
// name, rather than defaulting empty into a denied_by_policy.
func TestBuildOperationAction_MissingRequiredArgIsRejected(t *testing.T) {
	_, err := buildOperationAction(stubOpsLister{}, "service.restart", map[string]string{}, 0)
	if err == nil {
		t.Fatal("buildOperationAction(service.restart, {}) = nil error, want a missing-required-argument rejection")
	}
	if !strings.Contains(err.Error(), "unit") {
		t.Errorf("error %q must name the missing required argument 'unit'", err.Error())
	}
}

// TestBuildOperationAction_ValidArgsSucceed proves the pre-check is a narrow
// name gate, not a blanket refusal: correct names (including an omitted
// OPTIONAL arg) still build the Action, with args and risk class preserved.
func TestBuildOperationAction_ValidArgsSucceed(t *testing.T) {
	cases := []struct {
		name string
		args map[string]string
		risk jobs.RiskClass
	}{
		{"system.facts", map[string]string{}, jobs.RiskClassRead},
		{"file.read", map[string]string{"path": "/etc/os-release"}, jobs.RiskClassRead},
		{"service.restart", map[string]string{"unit": "nginx"}, jobs.RiskClassMutate},
		// version is optional — omitting it must NOT trip the required check.
		{"pkg.install", map[string]string{"name": "nginx"}, jobs.RiskClassMutate},
		{"pkg.install", map[string]string{"name": "nginx", "version": "1.24.0"}, jobs.RiskClassMutate},
	}
	for _, c := range cases {
		act, err := buildOperationAction(stubOpsLister{}, c.name, c.args, 0)
		if err != nil {
			t.Errorf("buildOperationAction(%s, %v) = error %v, want success", c.name, c.args, err)
			continue
		}
		if act.OperationName != c.name || act.RiskClass != c.risk {
			t.Errorf("buildOperationAction(%s) = {name:%q risk:%v}, want {name:%q risk:%v}", c.name, act.OperationName, act.RiskClass, c.name, c.risk)
		}
		if len(act.OperationArgs) != len(c.args) {
			t.Errorf("buildOperationAction(%s) args = %v, want %v (passed through unchanged)", c.name, act.OperationArgs, c.args)
		}
	}
}

// The ", required"/", optional" marker convention these depend on is guarded
// mechanically in opvocab (TestArgConstraintsAreClassifiable), beside the
// ArgConstraints prose it reads.

// --- #270/#271: a parked dispatch on the AI's own channel ---

// parkingExecutor is an Executor whose Run always parks, so the rendering of
// a park can be tested without standing up a gate, a store, and a fleet.
type parkingExecutor struct{ parked *capability.ParkedError }

func (e parkingExecutor) Run(context.Context, capability.Principal, capability.Selector, jobs.Action) ([]capability.NodeResult, error) {
	return nil, e.parked
}

func (parkingExecutor) CancelJob(context.Context, capability.Principal, string) error { return nil }

func (parkingExecutor) Plan(context.Context, capability.Principal, capability.Selector, jobs.Action) (capability.PlanResult, error) {
	return capability.PlanResult{}, nil
}

func testParkedError() *capability.ParkedError {
	return &capability.ParkedError{
		RequestID: "apr-123",
		PlanHash:  "hash-abc",
		Summary:   `service.restart(unit="nginx") [mutate] on 12 node(s): node-a, node-b`,
		Progress:  "0 of 2",
		Rules:     []string{"prod-mutates-need-two-people"},
		ExpiresAt: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC),
	}
}

// TestDispatchAndRender_ParkIsAResultNotAnError is the behaviour that matters
// most here, and it is a legibility guarantee rather than a cosmetic one
// (ADR-0001/0003): a park is neither a failure nor a completion, and an
// AI-agent told "dispatch failed" learns the wrong lesson twice — it may retry
// against a gate that will park it every time, and it may report a fleet
// action as broken when a human is merely being asked.
func TestDispatchAndRender_ParkIsAResultNotAnError(t *testing.T) {
	out, err := dispatchAndRender(context.Background(),
		parkingExecutor{parked: testParkedError()}, nil,
		capability.Principal{Account: "gleipnir-prod"}, capability.Selector{}, jobs.Action{Kind: jobs.ActionOperation})
	if err != nil {
		t.Fatalf("dispatchAndRender returned an error for a park: %v — a park must render as a RESULT", err)
	}

	if out.PendingApproval == nil {
		t.Fatal("no pending_approval in the result; the caller cannot tell a park from a zero-match dispatch")
	}
	pa := out.PendingApproval

	if pa.Status != statusPendingApproval {
		t.Errorf("status = %q, want %q", pa.Status, statusPendingApproval)
	}
	if pa.RequestID != "apr-123" || pa.PlanHash != "hash-abc" {
		t.Errorf("pending_approval = %+v, want the request and plan it names", pa)
	}
	if pa.Summary != testParkedError().Summary {
		t.Errorf("summary = %q, want the Relay-authored text verbatim", pa.Summary)
	}
	if pa.Progress != "0 of 2" || len(pa.MatchedRules) != 1 {
		t.Errorf("pending_approval = %+v, want the quorum state and the rule that fired", pa)
	}
	if pa.ExpiresAt != "2026-08-15T12:00:00Z" {
		t.Errorf("expires_at = %q, want RFC 3339 UTC", pa.ExpiresAt)
	}
	if pa.NextStep == "" {
		t.Error("next_step is empty; an agent with no guidance retries in a loop")
	}

	// Nothing ran, so nothing may look like it did.
	if out.JobID != "" {
		t.Errorf("job_id = %q, want absent — a parked dispatch creates no Job", out.JobID)
	}
	if len(out.Results) != 0 {
		t.Errorf("results = %v, want empty", out.Results)
	}
}

// TestPendingApproval_IsOmittedOnANormalDispatch: the field must be absent
// unless it applies, or every caller has to branch on an always-present key.
func TestPendingApproval_IsOmittedOnANormalDispatch(t *testing.T) {
	b, err := json.Marshal(RunOrPlanOutput{JobID: "job-1", Results: []PerNodeResult{}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "pending_approval") {
		t.Errorf("pending_approval present on a normal dispatch: %s", b)
	}
}

// TestPendingApproval_CarriesNoWayToApprove is the structural half of
// ADR-0027 restated at the wire: the parked result points a HUMAN at the
// authenticated Control API endpoint and gives the agent nothing it could use
// to answer for itself. The complementary guard is no_decision_test.go, which
// stops this package from ever gaining a decision path at all.
func TestPendingApproval_CarriesNoWayToApprove(t *testing.T) {
	pa := renderParked(testParkedError())

	if pa.DecisionPath != "/api/v1/approvals/apr-123/decision" {
		t.Errorf("decision_path = %q, want the Control API route", pa.DecisionPath)
	}
	b, err := json.Marshal(pa)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// A token, credential, or approve-flag reaching the agent's channel would
	// hand the requester the answer to its own request.
	for _, forbidden := range []string{"token", "credential", "secret", "\"approve\""} {
		if strings.Contains(strings.ToLower(string(b)), forbidden) {
			t.Errorf("parked result carries %q: %s", forbidden, b)
		}
	}
}
