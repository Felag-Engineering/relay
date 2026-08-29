package approval

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
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

func TestSelectorNamespaceNarrows(t *testing.T) {
	g := validGrant()
	g.Scope.SelectorNamespace = "relay"

	wrong := coveredDispatch()
	wrong.Namespaces = []string{"tag"}
	if g.Covers(wrong, grantNow) {
		t.Error("grant scoped to relay: covered a tag: Selector")
	}

	right := coveredDispatch()
	right.Namespaces = []string{"relay"}
	if !g.Covers(right, grantNow) {
		t.Error("grant scoped to relay: did not cover a relay: Selector")
	}
}

// TestSelectorNamespaceState is TestSelectorNamespaceNarrows' sibling for
// ADR-0034's fourth namespace: a Scope must be able to pin "state", and it
// narrows the same way "relay" and "tag" do.
func TestSelectorNamespaceState(t *testing.T) {
	s := validScope()
	s.SelectorNamespace = "state"
	if err := s.Validate(); err != nil {
		t.Fatalf("Scope with selector_namespace \"state\" did not validate: %v", err)
	}

	g := validGrant()
	g.Scope.SelectorNamespace = "state"

	wrong := coveredDispatch()
	wrong.Namespaces = []string{"node"}
	if g.Covers(wrong, grantNow) {
		t.Error("grant scoped to state: covered a node: Selector")
	}

	right := coveredDispatch()
	right.Namespaces = []string{"state"}
	if !g.Covers(right, grantNow) {
		t.Error("grant scoped to state: did not cover a state: Selector")
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

	otherNamespace := validScope()
	otherNamespace.SelectorNamespace = "relay"

	distinct := map[string]Scope{
		"base": base, "account": otherAccount, "risk": otherRisk,
		"ops": otherOps, "more ops": moreOps, "raw exec": rawExec, "namespace": otherNamespace,
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

	// And NOT where it does not fold: Scope.Validate accepts SelectorNamespace
	// case-sensitively, so "Node" is not a namespace at all.
	unfolded := validScope()
	unfolded.SelectorNamespace = "node"
	upper := validScope()
	upper.SelectorNamespace = "Node"
	if HashGrantShape(unfolded) == HashGrantShape(upper) {
		t.Error("the selector namespace was case-folded, but nothing that matches it folds")
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
func TestHashScopeDigestIsPinned(t *testing.T) {
	startsAt := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	expiresAt := time.Date(2026, 8, 16, 14, 0, 0, 0, time.UTC)

	s := Scope{
		Account:           "gleipnir-prod",
		RiskClass:         jobs.RiskClassMutate,
		MaxFanOut:         10,
		Operations:        []string{"service.restart", "pkg.install"},
		RawExec:           true,
		SelectorNamespace: "relay",
	}

	const want = "df94e374dad73de3588ba88c560909becc982393e1fd7a78282dd6ccd251d3fc"
	if got := HashScope(s, startsAt, expiresAt, 20); got != want {
		t.Errorf("HashScope digest moved:\n got  %s\n want %s\nHashScope is a live binding on stored grant plan_hash values and must not change", got, want)
	}
}
