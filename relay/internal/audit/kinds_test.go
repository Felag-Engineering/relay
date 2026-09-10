package audit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// TestKinds_ListsEveryDeclaredKind reads this package's own source rather than
// its exported symbols, because a Kind is an untyped string constant and no
// amount of reflection over the compiled package can enumerate them.
//
// Without it, Kinds() is a hand-maintained second list of a hand-maintained
// first one, and the failure mode is silent in exactly the place it matters:
// a new Kind lands, the Console's trail lane never requests it, and the
// surface billed as the audit trail simply does not show that kind of event.
func TestKinds_ListsEveryDeclaredKind(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "audit.go", nil, 0)
	if err != nil {
		t.Fatalf("parse audit.go: %v", err)
	}

	declared := map[string]string{} // constant name -> value
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || len(spec.Values) != 1 {
			return true
		}
		name := spec.Names[0].Name
		if !strings.HasPrefix(name, "Kind") {
			return true
		}
		lit, ok := spec.Values[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		declared[name] = value
		return true
	})

	if len(declared) == 0 {
		t.Fatal("the guard found no Kind constants in audit.go — it is not reading the source it thinks it is")
	}

	listed := map[string]bool{}
	for _, k := range Kinds() {
		if listed[k] {
			t.Errorf("Kinds() lists %q twice", k)
		}
		listed[k] = true
	}

	for name, value := range declared {
		if !listed[value] {
			t.Errorf("audit.%s (%q) is declared but absent from Kinds(). Add it, and classify it "+
				"on every consumer that partitions the vocabulary — an unclassified kind vanishes "+
				"from the Console's trail without anything saying so.", name, value)
		}
		delete(listed, value)
	}
	for extra := range listed {
		t.Errorf("Kinds() lists %q, which no Kind constant declares", extra)
	}
}

// TestKinds_ReturnsACopy: the package's list is not a caller's to reorder.
func TestKinds_ReturnsACopy(t *testing.T) {
	first := Kinds()
	if len(first) == 0 {
		t.Fatal("Kinds() is empty")
	}
	first[0] = "clobbered"
	if Kinds()[0] == "clobbered" {
		t.Error("a caller mutated the package's Kind list through the slice Kinds() returned")
	}
}

// TestAuthFailureKinds_PartitionsTheWholeVocabulary is the guard the group
// actually needs: every Kind in Kinds() must appear in EXACTLY ONE of
// authFailureKinds or notAnAuthFailureKinds. A kind nobody classified fails
// here, which is the mistake that actually happens — somebody adds a kind and
// does not think about whether it belongs to the credential-grinding query.
//
// This replaced a suffix heuristic (membership derived from a "_failed" /
// "_throttled" ending). A security review defeated that version with one
// input: a kind named step_up_denied, added to Kinds() and NOT to the group,
// passed — no suffix, so the rule had nothing to say about it. The heuristic
// only ever fired when a kind was wrongly ADDED to the group, which nobody
// does by accident, and it would have force-marched a future enrollment_failed
// into the group, counting Node enrollment failures as password attacks.
//
// A closed partition has no such blind spot, because the obligation is on
// Kinds() rather than on how a name is spelled.
func TestAuthFailureKinds_PartitionsTheWholeVocabulary(t *testing.T) {
	inFailure := map[string]bool{}
	for _, k := range authFailureKinds {
		inFailure[k] = true
	}
	inOther := map[string]bool{}
	for _, k := range notAnAuthFailureKinds {
		inOther[k] = true
	}

	for _, k := range Kinds() {
		switch {
		case inFailure[k] && inOther[k]:
			t.Errorf("%q is in BOTH authFailureKinds and notAnAuthFailureKinds", k)
		case !inFailure[k] && !inOther[k]:
			t.Errorf("%q is in neither authFailureKinds nor notAnAuthFailureKinds. "+
				"Decide: does a query for %q mean a credential was submitted and refused? "+
				"Add it to one list or the other.", k, k)
		}
	}

	// And nothing may be classified that is not a declared Kind, or the
	// partition could be "complete" while naming something that does not exist.
	declared := map[string]bool{}
	for _, k := range Kinds() {
		declared[k] = true
	}
	for _, k := range append(append([]string(nil), authFailureKinds...), notAnAuthFailureKinds...) {
		if !declared[k] {
			t.Errorf("%q is classified but is not in Kinds()", k)
		}
	}
}

// TestAuthFailureKinds_NeverASuccessKind is the failure mode the suffix guard
// above cannot see for itself: KindStepUp and KindLoginSucceeded name no
// suffix at all, so the loop above never visits them. A grinding query that
// counted a successful sign-in or step-up as an attack would be worse than no
// query.
func TestAuthFailureKinds_NeverASuccessKind(t *testing.T) {
	for _, k := range AuthFailureKinds() {
		if k == KindStepUp || k == KindLoginSucceeded {
			t.Errorf("AuthFailureKinds() contains the success kind %q", k)
		}
	}
}

// TestAuthFailureKinds_ContainsExactlyTheFour pins the concrete membership
// the suffix guard only checks abstractly, so a typo in one of the four
// literal strings (e.g. a stray KindStepUpFailed vs KindLoginFailed swap)
// fails here even though both still end in "_failed".
func TestAuthFailureKinds_ContainsExactlyTheFour(t *testing.T) {
	want := map[string]bool{
		KindLoginFailed:     true,
		KindLoginThrottled:  true,
		KindStepUpFailed:    true,
		KindStepUpThrottled: true,
	}
	got := AuthFailureKinds()
	if len(got) != len(want) {
		t.Fatalf("AuthFailureKinds() = %v, want exactly the four not-accepted kinds", got)
	}
	for _, k := range got {
		if !want[k] {
			t.Errorf("AuthFailureKinds() contains unexpected kind %q", k)
		}
	}
}

// TestAuthFailureKinds_ReturnsACopy: it must hold the same property Kinds()
// documents for itself, or a caller mutating one slice corrupts the other's
// backing array.
func TestAuthFailureKinds_ReturnsACopy(t *testing.T) {
	first := AuthFailureKinds()
	if len(first) == 0 {
		t.Fatal("AuthFailureKinds() is empty")
	}
	first[0] = "clobbered"
	if AuthFailureKinds()[0] == "clobbered" {
		t.Error("a caller mutated the package's list through the slice AuthFailureKinds() returned")
	}
}
