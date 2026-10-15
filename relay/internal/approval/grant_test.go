package approval

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

var grantNow = time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

func validScope() Scope {
	return Scope{
		Account:    "gleipnir-prod",
		RiskClass:  jobs.RiskClassMutate,
		MaxFanOut:  10,
		Operations: []string{"service.restart"},
	}
}

func validGrant() Grant {
	s := validScope()
	return Grant{
		ID:        "grant-1",
		RequestID: "req-1",
		Scope:     s,
		StartsAt:  grantNow,
		ExpiresAt: grantNow.Add(2 * time.Hour),
		MaxUses:   20,
		Summary:   SummarizeScope(s, grantNow, grantNow.Add(2*time.Hour), 20),
		CreatedAt: grantNow,
	}
}

func coveredDispatch() Dispatch {
	return Dispatch{
		RiskClass: jobs.RiskClassMutate,
		FanOut:    5,
		Account:   "gleipnir-prod",
		Operation: "service.restart",
	}
}

// --- the inversion: Scope is explicit-by-default, Match is not ---

// TestZeroScopeIsRefused is the single most important test in this file.
//
// An omitted field in a gate Match means "match anything", which gates MORE and
// is safe. The same omission in a Scope would cover anything, which
// pre-approves more and is not. A zero Scope must therefore be impossible to
// store, not merely ineffective.
func TestZeroScopeIsRefused(t *testing.T) {
	if err := (Scope{}).Validate(); err == nil {
		t.Fatal("the zero Scope validated; an unbounded grant is a standing authorization")
	}
}

// TestEveryScopeBoundIsRequired walks each dimension: dropping any one of them
// must fail, so no single forgotten field silently widens a grant.
func TestEveryScopeBoundIsRequired(t *testing.T) {
	cases := map[string]func(*Scope){
		"no account":         func(s *Scope) { s.Account = "" },
		"no risk class":      func(s *Scope) { s.RiskClass = jobs.RiskClassUnspecified },
		"no fan-out ceiling": func(s *Scope) { s.MaxFanOut = 0 },
		"no operations":      func(s *Scope) { s.Operations = nil; s.RawExec = false },
	}
	for name, break_ := range cases {
		t.Run(name, func(t *testing.T) {
			s := validScope()
			break_(&s)
			if err := s.Validate(); err == nil {
				t.Fatalf("Scope with %s validated, want a refusal", name)
			} else if !errors.Is(err, ErrGrantUnbounded) {
				t.Errorf("err = %v, want ErrGrantUnbounded", err)
			}
		})
	}
}

// TestEmptyOperationListCoversNothing: the list is an allow-list, and an empty
// allow-list is empty — never a wildcard.
func TestEmptyOperationListCoversNothing(t *testing.T) {
	g := validGrant()
	g.Scope.Operations = nil
	g.Scope.RawExec = false

	if g.Covers(coveredDispatch(), grantNow) {
		t.Fatal("a grant with no operations covered a dispatch")
	}
}

// TestRawExecIsASeparateOptIn: Raw Exec is never reachable by naming it in
// Operations, because it has no Operation name — a grant covering it must say
// so in the field whose name an auditor will read.
func TestRawExecIsASeparateOptIn(t *testing.T) {
	g := validGrant()
	g.Scope.Operations = []string{"raw_exec", "raw exec", ""}
	g.Scope.RawExec = false

	rawDispatch := coveredDispatch()
	rawDispatch.Operation = ""
	rawDispatch.RawExec = true

	if g.Covers(rawDispatch, grantNow) {
		t.Fatal("Raw Exec was covered by an Operations entry; it must require the explicit RawExec opt-in")
	}

	g.Scope.Operations = []string{"service.restart"}
	g.Scope.RawExec = true
	if !g.Covers(rawDispatch, grantNow) {
		t.Fatal("explicit RawExec opt-in did not cover a Raw Exec dispatch")
	}
}

// --- the ceiling ---

// TestFanOutIsACeilingNotAFloor is the dual of Match.MinFanOut, and the bug it
// guards against is a grant described to a human as covering a handful of Nodes
// covering the fleet once the registry grows.
func TestFanOutIsACeilingNotAFloor(t *testing.T) {
	g := validGrant() // MaxFanOut 10

	small := coveredDispatch()
	small.FanOut = 1
	if !g.Covers(small, grantNow) {
		t.Error("a dispatch below the ceiling was not covered; MaxFanOut is a ceiling, not a floor")
	}

	atLimit := coveredDispatch()
	atLimit.FanOut = 10
	if !g.Covers(atLimit, grantNow) {
		t.Error("a dispatch exactly at the ceiling was not covered")
	}

	tooWide := coveredDispatch()
	tooWide.FanOut = 11
	if g.Covers(tooWide, grantNow) {
		t.Fatal("a dispatch above the ceiling was covered — the approver bounded what they agreed to")
	}
}

// --- scope discrimination ---

func TestGrantDoesNotCoverOutsideItsScope(t *testing.T) {
	g := validGrant()

	cases := map[string]func(*Dispatch){
		"another account":    func(d *Dispatch) { d.Account = "someone-else" },
		"another operation":  func(d *Dispatch) { d.Operation = "pkg.install" },
		"another risk class": func(d *Dispatch) { d.RiskClass = jobs.RiskClassRead },
		"raw exec":           func(d *Dispatch) { d.RawExec = true; d.Operation = "" },
	}
	for name, break_ := range cases {
		t.Run(name, func(t *testing.T) {
			d := coveredDispatch()
			break_(&d)
			if g.Covers(d, grantNow) {
				t.Fatalf("grant covered a dispatch with %s", name)
			}
		})
	}
}

// TestReadGrantNeverCoversMutate: the classes are not interchangeable, and this
// is the direction that matters — a grant written for a read sweep must not
// release a mutate.
func TestReadGrantNeverCoversMutate(t *testing.T) {
	g := validGrant()
	g.Scope.RiskClass = jobs.RiskClassRead

	if g.Covers(coveredDispatch(), grantNow) { // coveredDispatch is mutate
		t.Fatal("a read-class grant covered a mutate dispatch")
	}
}

// TestSelectorNamespaceNarrows is now a GATE-RULE test, not a Grant/Scope one:
// #482 removed namespace pinning from a Scope entirely, so the only namespace
// narrowing left in this package is Match.SelectorNamespace on a gate Rule.
// The name is kept (docs/specs/selectors-and-labels.md:255 cites it as proof
// that "a relay:-namespace Selector narrows as expected" at the approval
// seam) so that citation stays true without an edit to the spec.
func TestSelectorNamespaceNarrows(t *testing.T) {
	gate, err := NewGate([]Rule{{
		Name:    "relay-lane",
		Match:   Match{SelectorNamespace: "relay"},
		Require: Requirement{Count: 1},
	}})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}

	wrong := coveredDispatch()
	wrong.Namespaces = []string{"tag"}
	if _, _, gated := gate.Evaluate(wrong); gated {
		t.Error("a rule matching relay: gated a tag: Selector")
	}

	right := coveredDispatch()
	right.Namespaces = []string{"relay"}
	if _, _, gated := gate.Evaluate(right); !gated {
		t.Error("a rule matching relay: did not gate a relay: Selector")
	}

	both := coveredDispatch()
	both.Namespaces = []string{"relay", "node"}
	if _, _, gated := gate.Evaluate(both); !gated {
		t.Error("a rule matching relay: did not gate a dispatch whose Selector also used node:")
	}
}

// TestSelectorNamespaceState is TestSelectorNamespaceNarrows' sibling for
// ADR-0034's fourth namespace: a gate Rule must be able to match "state", and
// it narrows the same way "relay" and "tag" do. Kept as a gate-rule test for
// the same reason (docs/specs/selectors-and-labels.md:255).
func TestSelectorNamespaceState(t *testing.T) {
	if err := (Rule{Name: "r", Match: Match{SelectorNamespace: "state"}, Require: Requirement{Count: 1}}).Validate(); err != nil {
		t.Fatalf("a rule matching selector_namespace \"state\" did not validate: %v", err)
	}

	gate, err := NewGate([]Rule{{
		Name:    "state-lane",
		Match:   Match{SelectorNamespace: "state"},
		Require: Requirement{Count: 1},
	}})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}

	wrong := coveredDispatch()
	wrong.Namespaces = []string{"node"}
	if _, _, gated := gate.Evaluate(wrong); gated {
		t.Error("a rule matching state: gated a node: Selector")
	}

	right := coveredDispatch()
	right.Namespaces = []string{"state"}
	if _, _, gated := gate.Evaluate(right); !gated {
		t.Error("a rule matching state: did not gate a state: Selector")
	}
}

// TestCoversIgnoresSelectorNamespaces is #482's central property: a Scope has
// no namespace term, so Covers's decision does not vary with the dispatch's
// namespace list at all.
func TestCoversIgnoresSelectorNamespaces(t *testing.T) {
	g := validGrant()

	for _, namespaces := range [][]string{nil, {"node"}, {"relay", "node"}, {"state"}, {"tag"}} {
		d := coveredDispatch()
		d.Namespaces = namespaces
		if !g.Covers(d, grantNow) {
			t.Errorf("Covers(namespaces=%v) = false, want true — a Scope has no namespace term", namespaces)
		}
	}
}

// --- the window and the counter ---

func TestGrantWindowIsEnforced(t *testing.T) {
	g := validGrant() // grantNow .. +2h
	d := coveredDispatch()

	if g.Covers(d, grantNow.Add(-time.Second)) {
		t.Error("covered before the window opened")
	}
	if !g.Covers(d, grantNow.Add(time.Hour)) {
		t.Error("did not cover inside the window")
	}
	if g.Covers(d, g.ExpiresAt) {
		t.Error("covered at the expiry instant; the window is half-open")
	}
	if g.Covers(d, g.ExpiresAt.Add(time.Hour)) {
		t.Error("covered after the window closed")
	}
}

func TestExhaustedGrantCoversNothing(t *testing.T) {
	g := validGrant()
	g.Uses = g.MaxUses

	if g.Covers(coveredDispatch(), grantNow) {
		t.Fatal("an exhausted grant still covered a dispatch")
	}
	if g.Remaining() != 0 {
		t.Errorf("Remaining = %d, want 0", g.Remaining())
	}
}

func TestRevokedGrantCoversNothing(t *testing.T) {
	g := validGrant()
	g.RevokedAt = grantNow.Add(time.Minute)
	g.RevokedBy = "ana"

	if g.Covers(coveredDispatch(), grantNow.Add(2*time.Minute)) {
		t.Fatal("a revoked grant still covered a dispatch")
	}
	if !g.Revoked() {
		t.Error("Revoked() = false after revocation")
	}
}

// --- bounds that cannot be configured away ---

func TestGrantWindowCannotExceedTheHardMaximum(t *testing.T) {
	g := validGrant()
	g.ExpiresAt = g.StartsAt.Add(MaxGrantWindow + time.Minute)

	err := g.Validate()
	if err == nil {
		t.Fatal("a window longer than MaxGrantWindow validated")
	}
	if !errors.Is(err, ErrGrantUnbounded) {
		t.Errorf("err = %v, want ErrGrantUnbounded", err)
	}
}

func TestGrantUsesCannotExceedTheHardMaximum(t *testing.T) {
	g := validGrant()
	g.MaxUses = MaxGrantUses + 1

	if err := g.Validate(); !errors.Is(err, ErrGrantUnbounded) {
		t.Fatalf("err = %v, want ErrGrantUnbounded for a use limit above the maximum", err)
	}
}

func TestGrantWithoutAnApprovalRequestIsRefused(t *testing.T) {
	g := validGrant()
	g.RequestID = ""

	if err := g.Validate(); err == nil {
		t.Fatal("a grant with no approval request validated; a grant is never self-authorizing")
	}
}

func TestValidGrantValidates(t *testing.T) {
	if err := validGrant().Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// --- fail closed: a pre-#482 pinned Grant covers nothing ---

// TestLegacyNamespacePinnedGrantCoversNothing is #482's fail-closed guarantee
// at the domain level: a Grant read back with a legacy namespace pin is never
// Active and never covers anything, whatever namespaces the dispatch carries.
// Ignoring the pin would widen the Grant beyond what it was priced for, which
// is the exact defect #482 removes.
func TestLegacyNamespacePinnedGrantCoversNothing(t *testing.T) {
	g := validGrant()
	g.LegacyNamespacePin = "node"

	if g.Active(grantNow) {
		t.Error("a legacy-pinned grant is Active; it must fail closed")
	}
	for _, namespaces := range [][]string{{"node"}, {"relay", "node"}, nil} {
		d := coveredDispatch()
		d.Namespaces = namespaces
		if g.Covers(d, grantNow) {
			t.Errorf("Covers(namespaces=%v) = true for a legacy-pinned grant, want false", namespaces)
		}
	}
	if err := g.Validate(); !errors.Is(err, ErrGrantInvalid) {
		t.Errorf("Validate() = %v, want ErrGrantInvalid for a grant carrying a legacy namespace pin", err)
	}
}

// --- the approver-facing text ---

// TestSummarizeScopeStatesEveryBound: the approver must be able to read what
// they are agreeing to, and every wall must appear in it — a summary that
// omitted the fan-out ceiling or the expiry would be the approval-view fidelity
// gap at fleet scale.
func TestSummarizeScopeStatesEveryBound(t *testing.T) {
	s := validScope()
	got := SummarizeScope(s, grantNow, grantNow.Add(2*time.Hour), 20)

	for _, want := range []string{
		"service.restart",      // what
		"mutate",               // class
		"gleipnir-prod",        // whose
		"10 node(s)",           // fan-out ceiling
		"20 dispatch(es)",      // use ceiling
		"2026-08-16T12:00:00Z", // window open
		"2026-08-16T14:00:00Z", // window close
	} {
		if !strings.Contains(got, want) {
			t.Errorf("summary is missing %q:\n%s", want, got)
		}
	}
}

func TestSummarizeScopeNamesRawExecExplicitly(t *testing.T) {
	s := validScope()
	s.RawExec = true

	got := SummarizeScope(s, grantNow, grantNow.Add(time.Hour), 5)
	if !strings.Contains(got, "raw exec") {
		t.Errorf("a scope covering Raw Exec must say so in the text a human reads:\n%s", got)
	}
}

// TestOperationNameWithACommaIsRefused: the store encodes Operations
// comma-separated, so a comma inside a name would split one Operation into two
// on read-back — and on an ALLOW-LIST that means covering something nobody
// approved. The encoding must never be the thing that decides coverage.
func TestOperationNameWithACommaIsRefused(t *testing.T) {
	s := validScope()
	s.Operations = []string{"service.restart,pkg.install"}

	if err := s.Validate(); err == nil {
		t.Fatal("an operation name containing the encoding's separator validated")
	}
}

// --- pricing a Grant over every namespace (#482) ---

// TestRequirementForScopeProbesEveryKnownNamespace: RequirementForScope must
// walk every known namespace unconditionally, because a Scope has no
// namespace term to narrow the walk with. RequirementForScope had zero direct
// unit tests before #482; this fails if the walk is ever narrowed back to a
// pinned namespace.
func TestRequirementForScopeProbesEveryKnownNamespace(t *testing.T) {
	var probed []string
	recorder := func(d Dispatch) (Requirement, []string, bool) {
		if len(d.Namespaces) != 1 {
			t.Fatalf("probe carried %d namespaces, want exactly 1: %v", len(d.Namespaces), d.Namespaces)
		}
		probed = append(probed, d.Namespaces[0])
		return Requirement{Count: 1}, []string{"r"}, true
	}

	if _, _, gated := RequirementForScope(validScope(), recorder); !gated {
		t.Fatal("RequirementForScope reported ungated with an evaluate func that always gates")
	}

	seen := map[string]bool{}
	for _, ns := range probed {
		seen[ns] = true
	}
	want := []string{"node", "relay", "tag", "state"}
	if len(seen) != len(want) {
		t.Fatalf("probed namespaces = %v, want exactly %v", probed, want)
	}
	for _, ns := range want {
		if !seen[ns] {
			t.Errorf("RequirementForScope never probed namespace %q", ns)
		}
	}
}

// TestKnownNamespacesMatchGateRuleNamespaces pins that Rule.Validate accepts
// exactly knownNamespaces (what RequirementForScope prices a Grant over) and
// nothing else. Rule.Validate consults knownNamespaces directly rather than a
// second hardcoded set (gate.go), so there is only one vocabulary to drift —
// this is a regression test for that single source, not a comparison between
// two independently-maintained lists.
func TestKnownNamespacesMatchGateRuleNamespaces(t *testing.T) {
	for _, ns := range knownNamespaces {
		r := Rule{Name: "r", Match: Match{SelectorNamespace: ns}, Require: Requirement{Count: 1}}
		if err := r.Validate(); err != nil {
			t.Errorf("a gate rule matching selector_namespace %q did not validate: %v", ns, err)
		}
	}
	bad := Rule{Name: "r", Match: Match{SelectorNamespace: "tenant"}, Require: Requirement{Count: 1}}
	if err := bad.Validate(); err == nil {
		t.Error("a gate rule matching an unknown namespace validated; knownNamespaces has drifted from Rule.Validate's vocabulary")
	}
}

// TestRequirementForScopeTakesTheStrictestNamespaceRule is #482's worked
// example, straight through the derivation: a Scope covering "relay:node"
// dispatches must be priced at the STRICTER of a namespace-specific rule and
// a namespace-agnostic one, because the derivation cannot know in advance
// which namespaces a covered dispatch's Selector will use.
func TestRequirementForScopeTakesTheStrictestNamespaceRule(t *testing.T) {
	gate, err := NewGate([]Rule{
		{Name: "relay-two", Match: Match{SelectorNamespace: "relay"}, Require: Requirement{Count: 2}},
		{Name: "any", Match: Match{}, Require: Requirement{Count: 1}},
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}

	requirement, names, gated := RequirementForScope(validScope(), gate.Evaluate)
	if !gated {
		t.Fatal("RequirementForScope reported ungated with a gate that matches everything")
	}
	if requirement.Count != 2 {
		t.Errorf("Count = %d, want 2 (the strictest rule the relay: probe hits)", requirement.Count)
	}
	if want := "any,relay-two"; strings.Join(names, ",") != want {
		t.Errorf("MatchedRules = %v, want %s", names, want)
	}
}

// TestGrantShapeKey_IgnoresWindowUsesAndCeiling is acceptance 4: a Grant's
// shape key covers WHAT it authorizes, not how much or for how long — while
// HashScope, which is the Grant's actual approval binding, still covers all
// three. "Same scope, ceiling grew 10 -> 500" is the single most valuable diff
// the callout can render, and it only renders if the two records share a key.
func TestGrantShapeKey_IgnoresWindowUsesAndCeiling(t *testing.T) {
	base := validGrant()

	widerCeiling := validGrant()
	widerCeiling.Scope.MaxFanOut = 500

	moreUses := validGrant()
	moreUses.MaxUses = 200

	laterWindow := validGrant()
	laterWindow.StartsAt = grantNow.Add(24 * time.Hour)
	laterWindow.ExpiresAt = grantNow.Add(48 * time.Hour)

	for _, other := range []Grant{widerCeiling, moreUses, laterWindow} {
		if base.ShapeKey() != other.ShapeKey() {
			t.Errorf("a scale-only change moved the shape key (%+v)", other.Scope)
		}
		if HashScope(base.Scope, base.StartsAt, base.ExpiresAt, base.MaxUses) ==
			HashScope(other.Scope, other.StartsAt, other.ExpiresAt, other.MaxUses) {
			t.Errorf("HashScope did NOT change — the Grant's approval binding stopped covering its bounds (%+v)", other)
		}
	}
}

// TestGrantShapeKey_DistinguishesScopeWalls: every wall is in the key, and the
// only folding is the folding Covers itself does (strings.EqualFold on the
// account and on Operation names).
func TestGrantShapeKey_DistinguishesScopeWalls(t *testing.T) {
	base := validScope()

	otherAccount := validScope()
	otherAccount.Account = "someone-else"

	otherRisk := validScope()
	otherRisk.RiskClass = jobs.RiskClassRead

	otherOps := validScope()
	otherOps.Operations = []string{"pkg.install"}

	moreOps := validScope()
	moreOps.Operations = []string{"service.restart", "pkg.install"}

	rawExec := validScope()
	rawExec.RawExec = true

	distinct := map[string]Scope{
		"base": base, "account": otherAccount, "risk": otherRisk,
		"ops": otherOps, "more ops": moreOps, "raw exec": rawExec,
	}
	seen := make(map[string]string, len(distinct))
	for name, s := range distinct {
		key := HashGrantShape(s)
		if other, dup := seen[key]; dup {
			t.Errorf("scopes %q and %q share a shape key", name, other)
		}
		seen[key] = name
	}

	// Case-only differences where Covers folds: the same Grant, not two.
	folded := validScope()
	folded.Account = "GLEIPNIR-PROD"
	folded.Operations = []string{"Service.Restart"}
	if HashGrantShape(base) != HashGrantShape(folded) {
		t.Error("a case-only difference in the account or an Operation name changed the shape key, but Grant.Covers folds both")
	}

	// A legacy-pinned Grant's ShapeKey differs from an unpinned Grant of the
	// same Scope: the pin is a Grant-level fact (#482), carried only through
	// Grant.ShapeKey, and it must not collapse a dead pinned Grant onto a live
	// unpinned one.
	pinned := validGrant()
	pinned.LegacyNamespacePin = "node"
	if pinned.ShapeKey() == validGrant().ShapeKey() {
		t.Error("a legacy-pinned Grant shares a shape key with an unpinned Grant of the same Scope")
	}
}

// TestGrantRequestCarriesTheGrantsShapeKey: the queue card and the Grant it
// authorizes group on one key, so they cannot drift apart.
func TestGrantRequestCarriesTheGrantsShapeKey(t *testing.T) {
	g := validGrant()
	r := NewGrantRequest(g, "acct-g", "gleipnir-prod", []string{"batch-rule"}, req(1, false), grantNow)
	if r.ShapeKey != g.ShapeKey() {
		t.Errorf("grant Request shape key = %q, grant's own = %q", r.ShapeKey, g.ShapeKey())
	}
	if IsLegacyShapeKey(r.ShapeKey) || r.ShapeKey == "" {
		t.Errorf("grant Request shape key %q is not a computed key", r.ShapeKey)
	}
}

// TestHashScopeDigestIsPinned pins one literal HashScope digest, unlike
// plan_test.go which deliberately pins none (see TestHashPlanIsInjectiveOverDistinctPlans).
// The difference is not an inconsistency: HashPlan's bytes are the thing #494
// is changing on purpose, so pinning its old digest would only assert the bug.
// HashScope is NOT moving — it is a live binding on approval_requests.plan_hash
// for grant requests (grant.go:541, NewGrantRequest), and #494 only reuses its
// two writer primitives (encoding.go) inside the same field sequence. A golden
// digest here is what turns "the refactor moved a byte" into a red test
// instead of a silently re-pointed stored hash: this test must be written and
// observed green against unmodified HEAD, BEFORE grant.go is touched, so that
// green-after actually proves byte-identical rather than merely asserting it.
//
// The golden below was recaptured UNPINNED, at unmodified HEAD, for #482: a
// Scope no longer has a SelectorNamespace field, and HashScope's "namespace"
// field is now always written empty (grant.go), so the digest of an unpinned
// Scope must stay byte-identical to what it always was.
func TestHashScopeDigestIsPinned(t *testing.T) {
	startsAt := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	expiresAt := time.Date(2026, 8, 16, 14, 0, 0, 0, time.UTC)

	s := Scope{
		Account:    "gleipnir-prod",
		RiskClass:  jobs.RiskClassMutate,
		MaxFanOut:  10,
		Operations: []string{"service.restart", "pkg.install"},
		RawExec:    true,
	}

	const want = "07b601d832fc522f3719d39cf09a1c595b3362d70a9d799a3ad66efd2a592d30"
	if got := HashScope(s, startsAt, expiresAt, 20); got != want {
		t.Errorf("HashScope digest moved:\n got  %s\n want %s\nHashScope is a live binding on stored grant plan_hash values and must not change", got, want)
	}
}

// TestGrantShapeKeyDigestIsPinned is TestHashScopeDigestIsPinned's sibling for
// HashGrantShape: stored approval_requests.shape_key depends on it staying
// byte-identical for an unpinned Scope. Golden captured at the same unmodified
// HEAD, for the same Scope.
func TestGrantShapeKeyDigestIsPinned(t *testing.T) {
	s := Scope{
		Account:    "gleipnir-prod",
		RiskClass:  jobs.RiskClassMutate,
		MaxFanOut:  10,
		Operations: []string{"service.restart", "pkg.install"},
		RawExec:    true,
	}

	const want = "c6ed815e37c974fb7843d3de43ab093bc40d42afc4fd37adb2035bfc0f5748b2"
	if got := HashGrantShape(s); got != want {
		t.Errorf("HashGrantShape digest moved:\n got  %s\n want %s\nshape_key is a stored binding and must not change for an unpinned Scope", got, want)
	}
}

// TestLegacyPinnedGrantShapeMatchesItsHeadDigest is the pinned counterpart:
// before #482, HashGrantShape hashed Scope.SelectorNamespace directly. After
// #482, a legacy pin reaches the same bytes only through Grant.ShapeKey (via
// hashGrantShape's separate legacyNamespacePin parameter), so a Grant stored
// pinned to "relay" before this change must still resolve to the digest it
// always had.
func TestLegacyPinnedGrantShapeMatchesItsHeadDigest(t *testing.T) {
	g := Grant{
		Scope: Scope{
			Account:    "gleipnir-prod",
			RiskClass:  jobs.RiskClassMutate,
			MaxFanOut:  10,
			Operations: []string{"service.restart", "pkg.install"},
			RawExec:    true,
		},
		LegacyNamespacePin: "relay",
	}

	const want = "2545f3134b32c07ae7551e4938cc0d9c4c00b4f758a467c4f031570623bfb32c"
	if got := g.ShapeKey(); got != want {
		t.Errorf("legacy-pinned Grant.ShapeKey() moved:\n got  %s\n want %s\na stored shape_key for a pre-#482 pinned Grant must still recompute exactly", got, want)
	}
}
