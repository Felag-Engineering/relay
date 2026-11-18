package capability

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// authorizationMethods are the Authorizer methods whose every use in shipped
// code must be handed a context with caller-asserted attribution stripped.
var authorizationMethods = map[string]bool{
	"Authorize":                 true,
	"AuthorizeControl":          true,
	"AuthorizeApprovalDecision": true,
}

// authorizationCallsWithoutMask returns a message for every reference to an
// authorization method in f that is not a call taking withoutAssertions(...)
// as its first argument, and counts the compliant calls per method. A method
// value (`f := a.AuthorizeControl`) is a violation: it hides the argument.
func authorizationCallsWithoutMask(fset *token.FileSet, f *ast.File) (violations []string, seen map[string]int) {
	seen = map[string]int{}
	masked := map[*ast.SelectorExpr]bool{}

	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !authorizationMethods[sel.Sel.Name] || len(call.Args) == 0 {
			return true
		}
		first, ok := call.Args[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := first.Fun.(*ast.Ident); ok && id.Name == "withoutAssertions" {
			masked[sel] = true
			seen[sel.Sel.Name]++
		}
		return true
	})

	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || !authorizationMethods[sel.Sel.Name] || masked[sel] {
			return true
		}
		violations = append(violations, fset.Position(sel.Pos()).String()+": "+sel.Sel.Name+
			" is reached without withoutAssertions(ctx) as its first argument; an authorization decision must never read caller-asserted attribution."+
			" If this is a method that is not an Authorizer, rename it; if the name must stay, add an explicit allowlist entry in this test")
		return true
	})
	return violations, seen
}

// TestAuthorizationMethodsMatchTheAuthorizerInterfaces fails when an interface
// named *Authorizer gains a method the guard does not know, so a new
// authorization method cannot slip past the guard unnoticed.
func TestAuthorizationMethodsMatchTheAuthorizerInterfaces(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	derived := map[string]bool{}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			spec, ok := n.(*ast.TypeSpec)
			if !ok || !strings.HasSuffix(spec.Name.Name, "Authorizer") {
				return true
			}
			iface, ok := spec.Type.(*ast.InterfaceType)
			if !ok {
				return true
			}
			for _, m := range iface.Methods.List {
				for _, id := range m.Names {
					derived[id.Name] = true
				}
			}
			return true
		})
	}
	for m := range derived {
		if !authorizationMethods[m] {
			t.Errorf("%s is an Authorizer method the guard does not know: add it to authorizationMethods", m)
		}
	}
	for m := range authorizationMethods {
		if !derived[m] {
			t.Errorf("authorizationMethods lists %s, which no Authorizer interface declares", m)
		}
	}
}

// TestCapabilityLayer_EveryAuthorizationCallMasksAssertions pins, at every
// call site, that an Authorizer is handed a context without caller-asserted
// attribution. It scans every shipped file instead of trusting a shared
// helper: a helper can be bypassed by calling the Authorizer directly, so the
// property is pinned where it would break.
//
// Proves EX-7.
func TestCapabilityLayer_EveryAuthorizationCallMasksAssertions(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	total := map[string]int{}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		violations, seen := authorizationCallsWithoutMask(fset, f)
		for _, v := range violations {
			t.Error(v)
		}
		for m, n := range seen {
			total[m] += n
		}
	}
	for m := range authorizationMethods {
		if total[m] == 0 {
			t.Errorf("guard proves nothing about %s: no compliant call site found", m)
		}
	}
}

// TestAuthorizationMaskGuard_FiresOnAnUnmaskedCallAndAMethodValue is the
// guard's planted-fixture self-test: it proves the guard can fail.
func TestAuthorizationMaskGuard_FiresOnAnUnmaskedCallAndAMethodValue(t *testing.T) {
	const src = `package capability

func planted(x *thing, ctx ctxT, p, a, s any) {
	_ = x.authz.AuthorizeControl(withoutAssertions(ctx), p, a)
	_ = x.authz.AuthorizeControl(ctx, p, a)
	_ = x.authz.Authorize(ctx, p, a, s)
	f := x.authz.AuthorizeApprovalDecision
	_ = f
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "planted.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	violations, seen := authorizationCallsWithoutMask(fset, f)
	if len(violations) != 3 {
		t.Errorf("violations = %d (%v), want 3: a bare call, a second method name and a method value", len(violations), violations)
	}
	if len(seen) != 1 || seen["AuthorizeControl"] != 1 {
		t.Errorf("compliant calls seen = %v, want only AuthorizeControl: 1", seen)
	}
}

// The mask is on the authorization decision only; the audit record keeps what
// was asserted.
//
// Proves EX-7.
func TestEngageFreeze_AuthorizesWithoutAssertions(t *testing.T) {
	spy := &assertionSpyAuthorizer{}
	svc, _, audit := newFreezeService(t, spy)

	want := Assertions{OnBehalfOf: "ops-team", Traceparent: "00-abc-def-01", SessionRef: "conv_1", ChangeRef: "CHG-1"}
	ctx := WithAssertions(context.Background(), want)

	if err := svc.EngageFreeze(ctx, Principal{Account: "alice", Role: "operator", Kind: PrincipalKindHuman}); err != nil {
		t.Fatalf("EngageFreeze: %v", err)
	}

	if !spy.called {
		t.Fatal("the Authorizer was never called; this test proves nothing")
	}
	if !spy.sawAssertions.IsZero() {
		t.Errorf("the Authorizer could see caller-asserted attribution %+v", spy.sawAssertions)
	}
	if spy.sawPrincipal.Account != "alice" {
		t.Errorf("the Authorizer saw principal %+v, want the acting Account alice", spy.sawPrincipal)
	}
	if len(audit.freezeCalls) != 1 || audit.freezeCalls[0].Asserted != want || !audit.freezeCalls[0].Engage {
		t.Errorf("freeze record = %+v, want one engage record still carrying %+v", audit.freezeCalls, want)
	}
}

// The mask is on the authorization decision only; the audit record keeps what
// was asserted.
//
// Proves EX-7.
func TestReleaseFreeze_AuthorizesWithoutAssertions(t *testing.T) {
	spy := &assertionSpyAuthorizer{}
	svc, _, audit := newFreezeService(t, spy)

	want := Assertions{OnBehalfOf: "ops-team", Traceparent: "00-abc-def-01", SessionRef: "conv_1", ChangeRef: "CHG-1"}
	ctx := WithAssertions(context.Background(), want)

	if err := svc.ReleaseFreeze(ctx, Principal{Account: "root-admin", Role: "admin", Kind: PrincipalKindHuman}, "incident resolved"); err != nil {
		t.Fatalf("ReleaseFreeze: %v", err)
	}

	if !spy.called {
		t.Fatal("the Authorizer was never called; this test proves nothing")
	}
	if !spy.sawAssertions.IsZero() {
		t.Errorf("the Authorizer could see caller-asserted attribution %+v", spy.sawAssertions)
	}
	if spy.sawPrincipal.Account != "root-admin" {
		t.Errorf("the Authorizer saw principal %+v, want the acting Account root-admin", spy.sawPrincipal)
	}
	if len(audit.freezeCalls) != 1 || audit.freezeCalls[0].Asserted != want || audit.freezeCalls[0].Engage {
		t.Errorf("freeze record = %+v, want one release record still carrying %+v", audit.freezeCalls, want)
	}
}
