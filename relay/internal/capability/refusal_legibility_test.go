package capability

import (
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	relayv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"
)

// TestRefusalLegibility pins the TEXT of all four refusal walls the demo
// walks into (#454), each against the what/where/what-would-change bar. It
// exists because today's e2e suite would pass a refactor that collapsed
// FrozenError.Error() down to "frozen" — this file makes that a build
// failure instead.
// sharedBoundarySubstrings must appear in BOTH PolicyDenyExplanation and
// PolicyDenyVerdictExplanation, since both share policyBoundaryExplanation
// verbatim and differ only in their lead clause.
var sharedBoundarySubstrings = []string{
	"loads it from that Node's own disk",
	"no code path to add, change or relax a rule",
	"ADR-0002",
	"carries no caller identity",
	"reaching the Node",
	"the same answer whoever asks",
	"no credential this control plane can issue",
	"Where the answer is a Policy rule",
	"config management",
}

func TestRefusalLegibility(t *testing.T) {
	t.Run("wall1a_applied_policy_deny", func(t *testing.T) {
		want := append([]string{
			"Refused by the Node",
			"a refusal, not a failure",
			"nothing executed",
		}, sharedBoundarySubstrings...)
		for _, w := range want {
			if !strings.Contains(PolicyDenyExplanation, w) {
				t.Errorf("PolicyDenyExplanation missing %q: %s", w, PolicyDenyExplanation)
			}
		}
		// Negative assertions pinning the review's blocking finding: the
		// blanket "no retry changes this answer" claim is FALSE on an
		// args-mismatch deny (the daemon's own stderr on that same row says
		// a different argument would be allowed), on ADR-0018 argument-form
		// preconditions, on file_read.rs's post-open IO-error path, and on
		// the deny-all fallback. The claim is scoped to the credential,
		// which is what the Relay can guarantee — never scoped to "no
		// retry".
		for _, forbidden := range []string{"retry", "retries"} {
			if strings.Contains(strings.ToLower(PolicyDenyExplanation), forbidden) {
				t.Errorf("PolicyDenyExplanation must never contain %q: %s", forbidden, PolicyDenyExplanation)
			}
		}
	})

	t.Run("wall1b_plan_verdict", func(t *testing.T) {
		want := append([]string{
			"would refuse this",
			"nothing was dispatched",
		}, sharedBoundarySubstrings...)
		for _, w := range want {
			if !strings.Contains(PolicyDenyVerdictExplanation, w) {
				t.Errorf("PolicyDenyVerdictExplanation missing %q: %s", w, PolicyDenyVerdictExplanation)
			}
		}
		for _, forbidden := range []string{"retry", "retries"} {
			if strings.Contains(strings.ToLower(PolicyDenyVerdictExplanation), forbidden) {
				t.Errorf("PolicyDenyVerdictExplanation must never contain %q: %s", forbidden, PolicyDenyVerdictExplanation)
			}
		}
	})

	t.Run("boundary_core_is_byte_identical_across_plan_and_apply", func(t *testing.T) {
		if !strings.Contains(PolicyDenyExplanation, policyBoundaryExplanation) {
			t.Errorf("PolicyDenyExplanation does not contain policyBoundaryExplanation verbatim")
		}
		if !strings.Contains(PolicyDenyVerdictExplanation, policyBoundaryExplanation) {
			t.Errorf("PolicyDenyVerdictExplanation does not contain policyBoundaryExplanation verbatim")
		}
	})

	t.Run("wall2_blast_cap", func(t *testing.T) {
		err := &CapExceededError{Class: jobs.RiskClassMutate, Matched: 5, Cap: 2}
		got := err.Error()
		for _, want := range []string{
			"blast-radius cap exceeded",
			"mutate-cap",
			"narrow the Selector to at most",
			"5",
			"2",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("CapExceededError.Error() missing %q: %s", want, got)
			}
		}
	})

	t.Run("wall3_freeze", func(t *testing.T) {
		got := (&FrozenError{}).Error()
		for _, want := range []string{
			"Relay-wide Freeze",
			"ADR-0013",
			"until an admin releases the Freeze",
			"Policy preflight",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("FrozenError.Error() missing %q: %s", want, got)
			}
		}
	})

	t.Run("wall4_version_gate", func(t *testing.T) {
		got := jobs.VersionRefusedMessage
		for _, want := range []string{
			"below the Relay's configured minimum",
			"ADR-0014",
			"the Task was never sent",
			"config-management",
			"never pushes binaries",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("jobs.VersionRefusedMessage missing %q: %s", want, got)
			}
		}
	})
}

// TestRefusalExplanation_MappingIsExhaustive asserts RefusalExplanation over
// EVERY jobs.Outcome value, so a new enum member that silently falls through
// to "" is a deliberate, reviewed act rather than an accident. Update this
// list — and RefusalExplanation's switch — together whenever jobs.Outcome
// gains a member.
func TestRefusalExplanation_MappingIsExhaustive(t *testing.T) {
	cases := []struct {
		outcome jobs.Outcome
		want    string
	}{
		{jobs.OutcomeUnspecified, ""},
		{jobs.OutcomeSuccess, ""},
		{jobs.OutcomeFailure, ""},
		{jobs.OutcomeTimeout, ""},
		{jobs.OutcomeDeniedByPolicy, PolicyDenyExplanation},
		{jobs.OutcomeCancelled, ""},
		{jobs.OutcomeUnreachable, ""},
		{jobs.OutcomeVersionRefused, jobs.VersionRefusedMessage},
		{jobs.OutcomeUnsupported, ""},
	}
	// Anchored to relayv1.Outcome_name — a real source of truth, not a second
	// literal in this file — because a `const wantOutcomeCount = 9` compared
	// only against len(cases) never moves when jobs.Outcome gains a member:
	// both numbers live in this file, so the check degenerates to "9 != 9",
	// permanently false, and a silently-defaulting new Outcome would sail
	// through undetected. jobs.Outcome mirrors relayv1.Outcome 1:1, and
	// invariant 8 makes /proto the origin of any new Outcome value, so
	// asserting against the generated enum map is sound: it changes the
	// moment `make proto` regenerates it from a real proto edit.
	const wantOutcomeCount = 9
	if got := len(relayv1.Outcome_name); got != wantOutcomeCount {
		t.Fatalf("relayv1.Outcome_name has %d entries, want %d — a new Outcome was added to /proto; "+
			"add its case to RefusalExplanation's switch, a row above, and bump wantOutcomeCount here", got, wantOutcomeCount)
	}
	if len(cases) != wantOutcomeCount {
		t.Fatalf("test itself is stale: %d cases, want %d — a jobs.Outcome value was added or removed", len(cases), wantOutcomeCount)
	}
	for _, c := range cases {
		if got := RefusalExplanation(c.outcome); got != c.want {
			t.Errorf("RefusalExplanation(%v) = %q, want %q", c.outcome, got, c.want)
		}
	}
}

// TestVerdictExplanation_MappingIsExhaustive is TestRefusalExplanation_MappingIsExhaustive's
// plan-mode counterpart, over every VerdictStatus value.
func TestVerdictExplanation_MappingIsExhaustive(t *testing.T) {
	cases := []struct {
		status VerdictStatus
		want   string
	}{
		{VerdictUnknown, ""},
		{VerdictAllow, ""},
		{VerdictDeny, PolicyDenyVerdictExplanation},
		{VerdictUnsupported, ""},
	}
	// VerdictStatus has no proto mirror to anchor against (unlike jobs.Outcome
	// above), so this anchors to the last known member's own ordinal instead
	// of a second independent literal: if a member is inserted before
	// VerdictUnsupported, its iota value shifts and this fails. Residual gap,
	// stated rather than hidden: a member appended AFTER VerdictUnsupported
	// leaves int(VerdictUnsupported) unchanged, so this guard would not catch
	// it — only a hand-added case row (reviewed at code-review time) does.
	const wantStatusCount = 4
	if got := int(VerdictUnsupported); got != wantStatusCount-1 {
		t.Fatalf("VerdictUnsupported = %d, want %d — a VerdictStatus member was inserted or removed; "+
			"add its case to VerdictExplanation's switch, a row above, and bump wantStatusCount here", got, wantStatusCount-1)
	}
	if len(cases) != wantStatusCount {
		t.Fatalf("test itself is stale: %d cases, want %d — a VerdictStatus value was added or removed", len(cases), wantStatusCount)
	}
	for _, c := range cases {
		if got := VerdictExplanation(c.status); got != c.want {
			t.Errorf("VerdictExplanation(%v) = %q, want %q", c.status, got, c.want)
		}
	}
}
