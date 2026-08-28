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
