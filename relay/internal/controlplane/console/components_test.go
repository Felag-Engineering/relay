package console

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

func render(t *testing.T, name string, data any) string {
	t.Helper()
	var buf bytes.Buffer
	if err := componentsTmpl.ExecuteTemplate(&buf, name, data); err != nil {
		t.Fatalf("render %s: %v", name, err)
	}
	return buf.String()
}

// --- The outcome bar's floor ------------------------------------------------

// TestOutcomeBar_MinoritySegmentsSurviveAtFleetScale is the reason this
// component exists at all, stated as the spec states it: at 10,000 Nodes, 14
// denies are 0.14% and would vanish — and they are the entire reason anyone is
// looking at the bar.
func TestOutcomeBar_MinoritySegmentsSurviveAtFleetScale(t *testing.T) {
	bar := NewOutcomeBar([]OutcomeCount{
		{jobs.OutcomeSuccess, 9986},
		{jobs.OutcomeDeniedByPolicy, 14},
	})

	var denied Segment
	for _, s := range bar.Segments {
		if s.Outcome == jobs.OutcomeDeniedByPolicy {
			denied = s
		}
	}
	if denied.Count != 14 {
		t.Fatalf("the denied segment is missing from the bar: %+v", bar.Segments)
	}
	if denied.Percent > 0.2 {
		t.Errorf("Percent = %f, want the TRUE share (~0.14%%)", denied.Percent)
	}
	if denied.Width < minSegmentPercent {
		t.Errorf("Width = %f%%, want at least the %g%% floor — at this share the segment is a sub-pixel sliver",
			denied.Width, minSegmentPercent)
	}
}

func TestOutcomeBar_WidthsAlwaysSumToTheWholeBar(t *testing.T) {
	cases := map[string][]OutcomeCount{
		"one outcome": {{jobs.OutcomeSuccess, 40}},
		"two, lopsided": {
			{jobs.OutcomeSuccess, 9999},
			{jobs.OutcomeFailure, 1},
		},
		"an even spread": {
			{jobs.OutcomeSuccess, 10},
			{jobs.OutcomeFailure, 10},
			{jobs.OutcomeDeniedByPolicy, 10},
		},
		// The pathological case: the nominal floor cannot be honoured for all
		// eight at once, so it must SHRINK rather than overflow the bar.
		"all eight, one Node each": {
			{jobs.OutcomeSuccess, 1}, {jobs.OutcomeFailure, 1},
			{jobs.OutcomeTimeout, 1}, {jobs.OutcomeDeniedByPolicy, 1},
			{jobs.OutcomeCancelled, 1}, {jobs.OutcomeUnreachable, 1},
			{jobs.OutcomeVersionRefused, 1}, {jobs.OutcomeUnsupported, 1},
		},
	}
	for name, counts := range cases {
		t.Run(name, func(t *testing.T) {
			bar := NewOutcomeBar(counts)
			total := 0.0
			for _, s := range bar.Segments {
				if s.Width <= 0 {
					t.Errorf("segment %s has width %f", s.Label, s.Width)
				}
				total += s.Width
			}
			if total < 99.9 || total > 100.1 {
				t.Errorf("widths sum to %f%%, want 100%%", total)
			}
		})
	}
}

func TestOutcomeBar_DropsOutcomesNobodyReported(t *testing.T) {
	bar := NewOutcomeBar([]OutcomeCount{
		{jobs.OutcomeSuccess, 5},
		{jobs.OutcomeFailure, 0},
		{jobs.OutcomeTimeout, 0},
	})
	// An outcome nobody reported is not a fact about this Job, and a bar full
	// of hairlines teaches an operator to ignore hairlines.
	if len(bar.Segments) != 1 {
		t.Fatalf("bar has %d segments, want only the non-zero one", len(bar.Segments))
	}
	if bar.Total != 5 {
		t.Errorf("Total = %d, want 5", bar.Total)
	}
}

func TestOutcomeBar_EmptyRendersNothingRatherThanAZeroedBar(t *testing.T) {
	bar := NewOutcomeBar(nil)
	if len(bar.Segments) != 0 || bar.Total != 0 {
		t.Errorf("an empty bar is %+v, want nothing", bar)
	}
	if !strings.Contains(render(t, "outcome-bar", bar), "0 Nodes") {
		t.Error("an empty bar should still render an honest label")
	}
}

func TestOutcomeBar_SegmentOrderIsStable(t *testing.T) {
	// Foundations rule 6, live but stable: a live bar that reshuffles under
	// someone reading it is worse than one that updates a beat late.
	counts := []OutcomeCount{
		{jobs.OutcomeUnsupported, 3},
		{jobs.OutcomeSuccess, 100},
		{jobs.OutcomeDeniedByPolicy, 7},
	}
	first := NewOutcomeBar(counts)
	// Same data, different input order: the rendered order must not change.
	shuffled := []OutcomeCount{counts[1], counts[2], counts[0]}
	second := NewOutcomeBar(shuffled)

	if len(first.Segments) != len(second.Segments) {
		t.Fatal("segment counts differ")
	}
	for i := range first.Segments {
		if first.Segments[i].Outcome != second.Segments[i].Outcome {
			t.Errorf("segment %d is %s then %s: the order depends on input order",
				i, first.Segments[i].Label, second.Segments[i].Label)
		}
	}
}

// TestOutcomeLabel_CoversAllEight pins the vocabulary at eight. The brief named
// six, and three of the eight are different kinds of "it did not run" that must
// not be collapsed: an operator who cannot tell them apart cannot tell a Policy
// problem from a fleet problem.
func TestOutcomeLabel_CoversAllEight(t *testing.T) {
	want := map[jobs.Outcome]string{
		jobs.OutcomeSuccess:        "success",
		jobs.OutcomeFailure:        "failure",
		jobs.OutcomeTimeout:        "timeout",
		jobs.OutcomeDeniedByPolicy: "denied_by_policy",
		jobs.OutcomeCancelled:      "cancelled",
		jobs.OutcomeUnreachable:    "unreachable",
		jobs.OutcomeVersionRefused: "version_refused",
		jobs.OutcomeUnsupported:    "unsupported",
	}
	if len(want) != 8 {
		t.Fatalf("the vocabulary under test has %d entries, want 8", len(want))
	}
	seen := map[string]bool{}
	for outcome, label := range want {
		got := OutcomeLabel(outcome)
		if got != label {
			t.Errorf("OutcomeLabel(%d) = %q, want %q", outcome, got, label)
		}
		if seen[got] {
			t.Errorf("%q is produced by more than one outcome: two states have been collapsed", got)
		}
		seen[got] = true
	}
	if got := OutcomeLabel(jobs.OutcomeUnspecified); got != "unspecified" {
		t.Errorf("the zero value renders as %q", got)
	}
}

// --- The two chip grammars --------------------------------------------------

// TestChipGrammars_OccupyDifferentVisualChannels is the property the spec is
// most insistent about: the trust lane owns fill-versus-outline and the
// namespace lane owns hue, glyph and the mono prefix. They sit within 200px of
// each other on the approval card, and if they shared a channel a caller's
// CLAIM would read as something the Relay verified.
//
// Asserted structurally — each grammar carries its own data attribute and
// neither carries the other's — because the stylesheet keys off exactly those.
func TestChipGrammars_OccupyDifferentVisualChannels(t *testing.T) {
	label := render(t, "label-chip", Label{Namespace: NamespaceRelay, Key: "quarantine"})
	trust := render(t, "trust-chip", Trust{Text: "gleipnir:operator", Verified: true})

	if !strings.Contains(label, `data-ns="relay"`) {
		t.Errorf("a label chip does not carry its namespace: %s", label)
	}
	if strings.Contains(label, "data-trust") {
		t.Errorf("a label chip carries a TRUST attribute: the two grammars have collided: %s", label)
	}
	if !strings.Contains(trust, `data-trust="verified"`) {
		t.Errorf("a trust chip does not carry its lane: %s", trust)
	}
	if strings.Contains(trust, "data-ns") {
		t.Errorf("a trust chip carries a NAMESPACE attribute: the two grammars have collided: %s", trust)
	}
}

func TestTrustChip_AssertedAndVerifiedAreNeverInterchangeable(t *testing.T) {
	verified := render(t, "trust-chip", Trust{Text: "mike", Verified: true})
	asserted := render(t, "trust-chip", Trust{Text: "mike", Verified: false})

	if verified == asserted {
		t.Fatal("a verified identity and a caller's claim render identically")
	}
	if !strings.Contains(asserted, "Nothing checked it") {
		t.Errorf("an asserted chip does not say it is unchecked: %s", asserted)
	}
	if !strings.Contains(verified, "authenticated") {
		t.Errorf("a verified chip does not say it was authenticated: %s", verified)
	}
}

func TestLabelChip_OnlyTheSecurityLaneIsMarked(t *testing.T) {
	// Invariant 7: quarantine, remediation and secret distribution target
	// `relay:` and ONLY `relay:`. The lock is how that is legible at a glance
	// in a wall of quiet chips.
	marked := map[Namespace]bool{
		NamespaceRelay: true,
		NamespaceNode:  false,
		NamespaceTag:   false,
		NamespaceState: false,
	}
	for ns, want := range marked {
		l := Label{Namespace: ns, Key: "k", Value: "v"}
		if got := l.SecurityLane(); got != want {
			t.Errorf("%s: SecurityLane() = %v, want %v", ns, got, want)
		}
		out := render(t, "label-chip", l)
		if got := strings.Contains(out, `data-lane="security"`); got != want {
			t.Errorf("%s renders lane=%v, want %v: %s", ns, got, want, out)
		}
	}
}

func TestParseLabel_RefusesAnUnknownNamespace(t *testing.T) {
	// Named fields, not positional: Label gained a severity channel and every
	// one of these literals broke at once. A parser test should not have to be
	// edited because a rendering concern was added to the type it parses into.
	good := map[string]Label{
		"node:env=prod":                    {Namespace: NamespaceNode, Key: "env", Value: "prod"},
		"tag:migration-a":                  {Namespace: NamespaceTag, Key: "migration-a"},
		"relay:quarantine":                 {Namespace: NamespaceRelay, Key: "quarantine"},
		"state:policy-fingerprint=4b18c02": {Namespace: NamespaceState, Key: "policy-fingerprint", Value: "4b18c02"},
	}
	for term, want := range good {
		got, ok := ParseLabel(term)
		if !ok || got != want {
			t.Errorf("ParseLabel(%q) = %+v, %v; want %+v", term, got, ok, want)
		}
		if got.String() != term {
			t.Errorf("round trip: %q -> %q", term, got.String())
		}
	}
	// A chip whose namespace the Console does not understand would be
	// rendered with authority it has not earned.
	for _, bad := range []string{"", "env=prod", "custom:thing", "NODE:env=prod", "node:", ":x"} {
		if _, ok := ParseLabel(bad); ok {
			t.Errorf("ParseLabel(%q) accepted an unrecognised label", bad)
		}
	}
}

// --- The deny block ---------------------------------------------------------

// TestDenyBlock_IsNotAnError is foundations rule 1: a deny is the product
// working correctly. It renders calm and informative, in slate, never as a red
// failure — if a deny ever renders red, the product is arguing against itself.
func TestDenyBlock_IsNotAnError(t *testing.T) {
	out := render(t, "deny-block", Deny{
		NodeID:        "node-7f2a",
		OperationName: "service.restart",
		Rule:          `deny service.restart where args.unit != "nginx"`,
		File:          "/etc/relay/policy.toml",
		Line:          42,
		PolicyHref:    "/console/nodes/node-7f2a#policy",
		DraftRuleHref: "/console/policy/fix?deny=abc",
	})

	if !strings.Contains(out, `data-outcome="denied_by_policy"`) {
		t.Error("the deny block does not carry the denied-by-policy treatment")
	}
	for _, wrong := range []string{"error", "Error", "failed", "Failure"} {
		if strings.Contains(out, wrong) {
			t.Errorf("the deny block calls a Policy decision %q: %s", wrong, out)
		}
	}
	// The rule VERBATIM, with its location. A paraphrased rule is a rule an
	// operator has to go and check.
	if !strings.Contains(out, `deny service.restart where args.unit != &#34;nginx&#34;`) {
		t.Errorf("the rule is not rendered verbatim: %s", out)
	}
	if !strings.Contains(out, "/etc/relay/policy.toml:42") {
		t.Errorf("the deny block does not locate the rule: %s", out)
	}
	// Both links: from "denied" to "I know which file to change", without
	// leaving the Console.
	if !strings.Contains(out, "effective Policy") || !strings.Contains(out, "Draft the rule") {
		t.Errorf("the deny block is missing one of its two links: %s", out)
	}
	// And the Console must be VISIBLY unable to make the change (ADR-0002,
	// invariant 2). This sentence is the visible part.
	if !strings.Contains(out, "Relay cannot change this") {
		t.Errorf("the deny block does not say the Relay cannot write Policy: %s", out)
	}
}

func TestDenyBlock_EscapesARuleItDidNotWrite(t *testing.T) {
	// Policy text comes from a Node's own file. A compromised Node reports
	// whatever it likes, and this block renders it verbatim by design — so
	// "verbatim" must mean escaped, not injected.
	out := render(t, "deny-block", Deny{
		Rule: `deny <script>alert('pwned')</script>`,
	})
	if strings.Contains(out, "<script>") {
		t.Fatalf("a Policy rule was rendered as live markup: %s", out)
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("the rule was not escaped: %s", out)
	}
}

// --- The Plan renderer ------------------------------------------------------

func TestPlan_ShowsTheCapArithmetic(t *testing.T) {
	// A cap that silently trims a fan-out is a surprise at the worst possible
	// moment; a cap you can see coming is a control.
	p := Plan{
		Selector:  "node:env=prod",
		Matched:   412,
		Cap:       50,
		RiskClass: jobs.RiskClassMutate,
		Hash:      "sha256:4b18c02",
	}
	if !p.OverCap() {
		t.Fatal("412 matched against a cap of 50 does not report OverCap")
	}
	out := render(t, "plan", p)
	for _, want := range []string{"412 Nodes matched", "cap 50", "over the mutate cap", "sha256:4b18c02", "node:env=prod"} {
		if !strings.Contains(out, want) {
			t.Errorf("the Plan does not show %q: %s", want, out)
		}
	}
}

func TestPlan_CountsVerdictsAndRendersEveryDeny(t *testing.T) {
	p := Plan{
		Selector:  "node:role=web",
		Matched:   3,
		Cap:       50,
		RiskClass: jobs.RiskClassRead,
		Hash:      "sha256:aaa",
		Verdicts: []PlanVerdict{
			{NodeID: "node-1", Allowed: true},
			{NodeID: "node-2", Allowed: false, Deny: &Deny{NodeID: "node-2", Rule: "deny proc.list"}},
			{NodeID: "node-3", Allowed: false, Deny: &Deny{NodeID: "node-3", Rule: "deny everything"}},
		},
	}
	if p.AllowedCount() != 1 || p.DeniedCount() != 2 {
		t.Fatalf("counts are %d allowed / %d denied, want 1 / 2", p.AllowedCount(), p.DeniedCount())
	}
	out := render(t, "plan", p)
	// Every deny is rendered, not a summary of them: the whole point of plan
	// mode is seeing which Nodes will refuse and why.
	if !strings.Contains(out, "deny proc.list") || !strings.Contains(out, "deny everything") {
		t.Errorf("the Plan does not render every deny: %s", out)
	}
	if !p.OverCap() {
		// 3 under a cap of 50 is fine.
	} else {
		t.Error("3 matched under a cap of 50 reports OverCap")
	}
}

func TestPlan_HashIsRenderedAsTheThingAnApprovalCommitsTo(t *testing.T) {
	out := render(t, "plan", Plan{Hash: "sha256:4b18c02", RiskClass: jobs.RiskClassMutate})
	if !strings.Contains(out, "This is what an approval commits to") {
		t.Errorf("the plan hash is rendered without saying what it is for: %s", out)
	}
}

// TestPlan_ADispatchedPlanPredictsNothing is the Job-detail case (#423): the
// same renderer, invoked for a Plan that has already run.
//
// "0 would run, 0 would be denied" on a finished Job is a lie about a
// prediction nobody made, and an empty plan hash presented as one is the
// mislabel #465 named. Both slots are omitted rather than filled with
// something false; the fan-out and the risk class — the facts that ARE known
// — still render.
func TestPlan_ADispatchedPlanPredictsNothing(t *testing.T) {
	out := render(t, "plan", Plan{
		Matched:      10000,
		RiskClass:    jobs.RiskClassMutate,
		SelectorNote: "recorded when the dispatch completes",
	})
	if strings.Contains(out, "would run") {
		t.Errorf("a Plan with no verdicts predicts an outcome anyway: %s", out)
	}
	if strings.Contains(out, "planhash") {
		t.Errorf("a Plan with no hash renders an empty one as if it were the identity of the plan: %s", out)
	}
	// The Selector's SLOT is still there, holding the note. A block that grows
	// a line when the Selector arrives has reflowed, which is exactly what
	// foundations rule 6 forbids.
	if !strings.Contains(out, "recorded when the dispatch completes") {
		t.Errorf("the Selector slot is missing entirely rather than pending: %s", out)
	}
	if !strings.Contains(out, "10000 Nodes matched") || !strings.Contains(out, `data-risk="mutate"`) {
		t.Errorf("a dispatched Plan dropped the facts it does know: %s", out)
	}
}

// --- The step-up modal ------------------------------------------------------

// TestStepUp_NamesWhatItAuthorises is the shell spec's acceptance criterion.
// "Confirm it is you" with no object is how people are trained to type their
// password into anything.
func TestStepUp_NamesWhatItAuthorises(t *testing.T) {
	out := render(t, "step-up", StepUp{
		Action:     "Restart nginx on 412 Nodes",
		Detail:     "sha256:4b18c02",
		FormAction: "/console/run/apply",
		CSRFToken:  "token-value",
		WindowText: "This confirmation lasts 5 minutes.",
	})

	if !strings.Contains(out, "Restart nginx on 412 Nodes") {
		t.Errorf("the step-up prompt does not name the action: %s", out)
	}
	if !strings.Contains(out, `type="password"`) {
		t.Error("the step-up prompt does not ask for a credential")
	}
	// A step-up is a mutating request like any other.
	if !strings.Contains(out, `method="post"`) || !strings.Contains(out, "csrf_token") {
		t.Errorf("the step-up prompt is not a CSRF-protected POST: %s", out)
	}
	if !strings.Contains(out, "lasts 5 minutes") {
		t.Errorf("the step-up prompt does not say how long the confirmation lasts: %s", out)
	}
}

// --- Whole-package template hygiene -----------------------------------------

// TestComponents_ContainNoInlineScript is the shell spec's acceptance
// criterion, extended to the shared components: the CSP admits no inline
// script, and `hx-on:` IS script even though the other hx-* attributes are not.
func TestComponents_ContainNoInlineScript(t *testing.T) {
	samples := map[string]any{
		"label-chip":  Label{Namespace: NamespaceRelay, Key: "quarantine"},
		"trust-chip":  Trust{Text: "mike", Verified: true},
		"outcome-bar": NewOutcomeBar([]OutcomeCount{{jobs.OutcomeSuccess, 3}, {jobs.OutcomeDeniedByPolicy, 1}}),
		"deny-block":  Deny{Rule: "deny x", File: "p.toml", Line: 1},
		"plan":        Plan{Selector: "s", Matched: 1, Cap: 5, Hash: "h"},
		"step-up":     StepUp{Action: "a", FormAction: "/x", CSRFToken: "t"},
		"pin-bar": pinState{
			Pins:        []nodePin{{ID: "n1", Known: true, Href: "/console/nodes/n1", UnpinHref: "/console/"}},
			CompareHref: "/console/compare?nodes=n1", FleetHref: "/console/?pin=n1",
		},
	}
	for name, data := range samples {
		out := render(t, name, data)
		for _, banned := range []string{"<script", "hx-on:", "onclick=", "onload=", "javascript:"} {
			if strings.Contains(strings.ToLower(out), banned) {
				t.Errorf("%s renders %q, which the content security policy blocks", name, banned)
			}
		}
	}
}
