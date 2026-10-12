package main

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/events"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
)

// TestDefaultControlSurfaces_MountWithoutCollision mounts every surface
// defaultControlSurfaces() returns onto a bare *http.ServeMux — no
// controlplane.Server, no Authenticator, no listener — and verifies:
//  1. Mount never panics (mux.Handle itself panics on a duplicate pattern,
//     so a clean run already proves no two surfaces collide), and
//  2. every route callers depend on ("/mcp" and the five /api/v1/* routes)
//     actually resolves to a registered handler afterward.
func TestDefaultControlSurfaces_MountWithoutCollision(t *testing.T) {
	mux := http.NewServeMux()
	sd := surfaceDeps{
		ops: opvocabLister{},
		now: func() time.Time { return time.Time{} },
	}

	for _, s := range defaultControlSurfaces() {
		s.Mount(mux, sd)
	}

	wantRoutes := []struct {
		method, path string
	}{
		{http.MethodPost, "/mcp"},
		{http.MethodPost, "/api/v1/enrollment-tokens"},
		{http.MethodDelete, "/api/v1/enrollment-tokens/some-id"},
		{http.MethodPost, "/api/v1/nodes/some-node/revoke"},
		{http.MethodPost, "/api/v1/freeze/engage"},
		{http.MethodPost, "/api/v1/freeze/release"},
		{http.MethodGet, "/metrics"},
	}
	for _, want := range wantRoutes {
		req := httptest.NewRequest(want.method, want.path, nil)
		if h, pattern := mux.Handler(req); h == nil || pattern == "" {
			t.Errorf("mux.Handler(%s %s): no handler registered (pattern=%q)", want.method, want.path, pattern)
		}
	}
}

// TestDefaultControlSurfaces_Order pins defaultControlSurfaces() to exactly
// mcpSurface, apiSurface, and metricsSurface: a change here should be a
// deliberate one-line edit to the explicit slice, not an accidental drop.
func TestDefaultControlSurfaces_Order(t *testing.T) {
	surfaces := defaultControlSurfaces()
	if len(surfaces) != 3 {
		t.Fatalf("len(defaultControlSurfaces()) = %d, want 3", len(surfaces))
	}
	if _, ok := surfaces[0].(mcpSurface); !ok {
		t.Errorf("surfaces[0] = %T, want mcpSurface", surfaces[0])
	}
	if _, ok := surfaces[1].(apiSurface); !ok {
		t.Errorf("surfaces[1] = %T, want apiSurface", surfaces[1])
	}
	if _, ok := surfaces[2].(metricsSurface); !ok {
		t.Errorf("surfaces[2] = %T, want metricsSurface", surfaces[2])
	}
}

// TestSurfaceDeps_AuditSinkIsWired is a regression guard for a defect found
// while building #357: newServer assembled surfaceDeps WITHOUT setting
// auditSink, so it was nil, and mcp's readAuditor answered its defensive
// `sink == nil` check by skipping silently. Read-access auditing (#288,
// ADR-0025) was therefore dead in production from the day it shipped — the
// trail was empty and nothing anywhere said so.
//
// A nil sink fails silently by design (that skip is deliberate, so an unwired
// surface still works), which is exactly why it needs a test rather than a
// runtime check: the only way to notice is to assert the wiring.
func TestSurfaceDeps_AuditSinkIsWired(t *testing.T) {
	f := startRelay(t, WithControlPlane())

	// Drive a read through the surface and assert the trail actually grew.
	jobID := seedJob(t, f.Deps)
	resp := controlAPIRequest(t, f.ClientFor(""), http.MethodGet,
		f.ControlBase+"/api/v1/jobs/"+jobID, f.Credential, nil)
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read status = %d, want 200", resp.StatusCode)
	}

	records, err := f.Deps.audit.ByJob(context.Background(), jobID)
	if err != nil {
		t.Fatalf("audit.ByJob: %v", err)
	}
	for _, rec := range records {
		if rec.Kind == audit.KindRead {
			return // the sink is wired and writing
		}
	}
	t.Fatal("no KindRead record after a Job read — surfaceDeps.auditSink is not wired, so read auditing is silently disabled (ADR-0025)")
}

// TestConsoleSurface_MountsTheLiveReadRouteAndTheFingerprints is the wiring
// half of #427, in the shape TestSurfaceDeps_AuditSinkIsWired established: a
// seam the Console degrades gracefully without is a seam whose absence is
// invisible, so the only way to notice it was never wired is to assert it.
//
// Day one renders "not wired" for missing fingerprints and drops its live watch
// for a missing event seam. Both are correct behaviour and both look exactly
// like a composition-root bug.
func TestConsoleSurface_MountsTheLiveReadRouteAndTheFingerprints(t *testing.T) {
	mux := http.NewServeMux()
	consoleSurface{}.Mount(mux, surfaceDeps{
		now:    func() time.Time { return time.Time{} },
		events: events.NewBus(),
		trust:  consoleTrustReader{caFingerprint: "abc123"},
	})

	req := httptest.NewRequest(http.MethodGet, "/console/events?kinds=enrollment", nil)
	if h, pattern := mux.Handler(req); h == nil || pattern == "" {
		t.Errorf("GET /console/events is not mounted (pattern=%q) — the Console has no live path", pattern)
	}
}

// TestConsoleSurface_UnwiredSeamsCrossTheBoundaryAsNil is Go's typed-nil trap,
// which this file already names for the audit sink: assigning a nil
// *events.Bus straight into an interface field produces a NON-nil interface
// holding a nil pointer, so every `d.Events == nil` guard in package console
// passes it through and the first call panics.
//
// The Console's contract is that an unwired seam makes the screens that need
// it degrade — day one drops its live watch, the stream answers 503. That is
// three written promises, and all three are false if the interface is never
// nil. Not reachable in production (newServer always builds a bus), which is
// exactly why it needs a test rather than a runtime check.
func TestConsoleSurface_UnwiredSeamsCrossTheBoundaryAsNil(t *testing.T) {
	if got := consoleEventsOrNil(nil); got != nil {
		t.Errorf("consoleEventsOrNil(nil) = %#v, want an untyped nil — a typed nil makes every "+
			"`d.Events == nil` guard in the Console false and the first call a panic", got)
	}

	// The whole surface, mounted with nothing wired, behind a real
	// authenticator — because the route's nil check comes BEFORE it resolves
	// a principal, and a request without one is refused earlier and never
	// reaches the seam at all. With the typed nil, this panics inside
	// Subscribe on a nil *events.Bus.
	mux := http.NewServeMux()
	consoleSurface{}.Mount(mux, surfaceDeps{now: func() time.Time { return time.Time{} }})
	authn := controlplane.NewAuthenticator(stubVerifier{})
	handler := authn.Middleware(mux)

	req := httptest.NewRequest(http.MethodGet, "/console/events?kinds=enrollment", nil)
	req.Header.Set("Authorization", "Bearer "+stubCredential)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req) // a panic here fails the test, which is the point

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /console/events with no event seam wired = %d, want 503 — an unwired seam "+
			"must reach the Console as an untyped nil so the route can say so", rec.Code)
	}
}

// stubVerifier authenticates one credential, so a test can drive a mounted
// surface through the REAL authentication boundary without standing up an
// Account store.
type stubVerifier struct{}

const stubCredential = accounts.TokenPrefix + "0123456789abcdef.stub" //nolint:gosec // test fixture

func (stubVerifier) Verify(_ context.Context, credential string) (accounts.Account, accounts.APIToken, error) {
	if credential != stubCredential {
		return accounts.Account{}, accounts.APIToken{}, accounts.ErrTokenInvalid
	}
	return accounts.Account{
		Name: "stub-admin", Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true,
	}, accounts.APIToken{ID: "tok-stub"}, nil
}

// TestSurfaceDeps_NoSurfaceIsHandedTheRegistryOrACache is the composition-root
// half of the structural guard (#680): the three adapter packages'
// no_dispatch_test.go guards (mcp, api, console) stop a SURFACE from
// DECLARING a seam that hands back a registry.Node or a display-only
// snapshot without a context; this test stops the ROOT from WIRING one.
// After this issue no surface is handed the registry or a display-only
// cache directly — every registry, Policy-view and Template-vocabulary
// read goes through d.readLane, the capability read lane.
func TestSurfaceDeps_NoSurfaceIsHandedTheRegistryOrACache(t *testing.T) {
	// Keyed by PkgPath, not a type-name substring: a substring match would
	// pass a field concretely typed *registry.InMemory (it never spells
	// "registry.Repository"), which is exactly the regression this guard
	// exists to catch. Any type from these three packages is banned, not
	// just their headline Repository/Cache types.
	bannedPkgs := map[string]bool{
		reflect.TypeOf((*registry.Repository)(nil)).Elem().PkgPath(): true,
		reflect.TypeOf(policyview.Cache{}).PkgPath():                 true,
		reflect.TypeOf(nodevocab.Cache{}).PkgPath():                  true,
	}

	typ := reflect.TypeOf(surfaceDeps{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		elem := f.Type
		for elem.Kind() == reflect.Pointer || elem.Kind() == reflect.Slice {
			elem = elem.Elem()
		}
		if bannedPkgs[elem.PkgPath()] {
			t.Errorf("surfaceDeps.%s has type %s, whose element %s is from a banned package — no "+
				"surface may be handed the registry or a display-only cache directly; read through "+
				"d.readLane (invariant 10, QRY-28)",
				f.Name, f.Type, elem)
		}
	}
}

// TestConsoleTrustReader_ReportsNothingRatherThanGuessing: the server leaf is
// held live because it rotates, and a Relay assembled without one must produce
// an empty string — which day one renders as "not wired" rather than as a
// fingerprint an operator might compare against.
func TestConsoleTrustReader_ReportsNothingRatherThanGuessing(t *testing.T) {
	r := consoleTrustReader{caFingerprint: "ca-digest"}

	if got := r.CAFingerprint(); got != "ca-digest" {
		t.Errorf("CAFingerprint() = %q, want the CA's digest", got)
	}
	if got := r.ServerFingerprint(); got != "" {
		t.Errorf("ServerFingerprint() with no certificate = %q, want empty", got)
	}
}

// recordingToolCallObserver is a test-only mcp.ToolCallObserver (#721) used
// as the positive control below: passing one through WithMCPServerOptions and
// then observing it fire on a real tool call proves the option reached the
// real mcp.New call, not merely surfaceDeps or appDeps. It is appended AFTER
// mcpSurface.Mount's own toolCallObserver, so it also overrides it for that
// request (mcp.New applies options in order — see mcpSurface.Mount).
type recordingToolCallObserver struct {
	mu    sync.Mutex
	calls int
}

func (o *recordingToolCallObserver) ToolCall(_ context.Context, _ mcp.ToolCallEvent) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls++
}

func (o *recordingToolCallObserver) callCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.calls
}

// TestControlSurfaces_TestOnlyMCPOptionHookIsEmptyInProduction is #721's
// acceptance criterion: serverHooks.testMCPOptions is a seam that reaches the
// real mcpSurface.Mount, and only a test may ever populate it.
//
// Three parts, each closing a different gap the others leave open:
//   - runtime proves the actual production entry point (newServer) leaves it
//     empty, which would otherwise be an assumption about a code path this
//     test never runs;
//   - the positive control proves that assertion is not vacuous — a
//     non-empty serverHooks really does reach mcp.New, so an accidental no-op
//     wiring bug could not make "empty" trivially true;
//   - the static scan proves the property for every production file in this
//     package, not just today's one call site, so a second, unaudited call to
//     newServerWithHooks would fail the build rather than waiting to be
//     found by hand.
//
// S2b (#646) adds the sibling test that the production composition root does
// not pass the MRTR answer-path option itself; S4b inverts THAT one, not
// this one — this test is about the hook's shape, not about any particular
// option.
func TestControlSurfaces_TestOnlyMCPOptionHookIsEmptyInProduction(t *testing.T) {
	t.Run("runtime: empty on the production entry point", func(t *testing.T) {
		cfg := baseTestConfig(t)
		cfg.ControlEnabled = true
		cfg.ControlAddr = "127.0.0.1:0"

		_, deps, err := newServer(cfg)
		if err != nil {
			t.Fatalf("newServer: %v", err)
		}
		t.Cleanup(func() { deps.store.Close() }) //nolint:errcheck

		if got := len(deps.hooks.testMCPOptions); got != 0 {
			t.Errorf("newServer's appDeps.hooks.testMCPOptions has length %d, want 0 — the production "+
				"entry point must never populate a test-only hook (#721)", got)
		}
	})

	t.Run("positive control: WithMCPServerOptions reaches mcp.New", func(t *testing.T) {
		observer := &recordingToolCallObserver{}
		f := startRelay(t, WithControlPlane(), WithMCPServerOptions(mcp.WithToolCallObserver(observer)))

		if got := len(f.Deps.hooks.testMCPOptions); got != 1 {
			t.Fatalf("f.Deps.hooks.testMCPOptions has length %d, want 1 — startRelay's "+
				"WithMCPServerOptions did not reach appDeps.hooks", got)
		}

		session := relaytest.Connect(t, f.ControlBase, f.Client())
		relaytest.CallTool(t, session, "list_operations", nil)

		if got := observer.callCount(); got != 1 {
			t.Errorf("recording observer saw %d tool calls, want 1 — the test-only mcp.Option never "+
				"reached the real mcp.New call", got)
		}
	})

	t.Run("static: no production file ever populates the hook", func(t *testing.T) {
		_, thisFile, _, ok := runtime.Caller(0)
		if !ok {
			t.Fatal("runtime.Caller failed")
		}
		dir := filepath.Dir(thisFile)

		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("os.ReadDir(%s): %v", dir, err)
		}

		fset := token.NewFileSet()
		newServerWithHooksCalls := 0
		for _, e := range entries {
			name := e.Name()
			// The parser ignores build tags, so build-tag-excluded files
			// (devharness.go vs devharness_stub.go) are scanned regardless of
			// which one this build would actually compile — the point is
			// that NEITHER may ever fill in serverHooks.
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}

			path := filepath.Join(dir, name)
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parser.ParseFile(%s): %v", path, err)
			}

			ast.Inspect(file, func(n ast.Node) bool {
				switch v := n.(type) {
				case *ast.CompositeLit:
					if ident, ok := v.Type.(*ast.Ident); ok && ident.Name == "serverHooks" && len(v.Elts) != 0 {
						t.Errorf("%s: a serverHooks{...} literal sets %d field(s) — serverHooks must "+
							"stay the zero value everywhere but a test (#721)", name, len(v.Elts))
					}
				case *ast.CallExpr:
					if ident, ok := v.Fun.(*ast.Ident); ok && ident.Name == "newServerWithHooks" {
						newServerWithHooksCalls++
					}
				}
				return true
			})

			// The two checks above catch a serverHooks{...} literal and a
			// second newServerWithHooks call site, but neither would catch a
			// production file that skips both and reaches into the field
			// directly (an assignment or an append on
			// sd.testMCPOptions/d.testMCPOptions, or a surfaceDeps{
			// testMCPOptions: ...} literal whose value is not
			// hooks.testMCPOptions) — security review and coordinator
			// follow-up, cycle 2 of #721. testMCPOptionsViolations closes
			// that gap, per top-level function AND per package-level
			// declaration, so the allowlist is pinned by (file, enclosing
			// function) rather than by a line number that would silently
			// stop matching after an unrelated edit, and a `var` outside any
			// function is scanned too rather than skipped entirely.
			for _, decl := range file.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok {
					if fn.Body == nil {
						continue
					}
					for _, msg := range testMCPOptionsViolations(name, fn.Name.Name, funcReceiverType(fn), fn.Body) {
						t.Error(msg)
					}
					continue
				}
				// A package-level declaration (var/const/type) has no
				// enclosing function, so neither allowlisted read (both
				// defined inside a specific function) can ever match here —
				// any testMCPOptions reference at this level is a violation.
				for _, msg := range testMCPOptionsViolations(name, "", "", decl) {
					t.Error(msg)
				}
			}
		}

		if newServerWithHooksCalls != 1 {
			t.Errorf("found %d call(s) to newServerWithHooks across this package's production files, "+
				"want exactly 1 (the one inside newServer) — a second call site could hand it a "+
				"non-empty serverHooks outside a test", newServerWithHooksCalls)
		}
	})

	// These subtests are the negative control for the static scan above:
	// they prove testMCPOptionsViolations actually fails closed on a
	// production write, rather than merely never having found one in
	// today's two files. Each exercises the scan function directly on a
	// fabricated snippet instead of editing a real production file, so the
	// guard it proves stays in the suite permanently (security review,
	// cycle 2 of #721; coordinator follow-up, same cycle).
	t.Run("negative control: the scan flags a production write to testMCPOptions", func(t *testing.T) {
		// Same shape as the real leak this guard exists to catch: a
		// surfaceDeps.testMCPOptions write from inside mcpSurface.Mount,
		// using a differently-named local variable rather than the
		// allowlisted parameter `d`. Reported twice over — once as the
		// assignment's LHS, once as append's argument under the wrong
		// variable name — either finding alone is enough to fail the build.
		const badSnippet = `package main

func (mcpSurface) Mount(mux *http.ServeMux, sd surfaceDeps) {
	sd.testMCPOptions = append(sd.testMCPOptions, mcp.WithClock(nil))
}
`
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "control_surfaces.go", badSnippet, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile(negative-control snippet): %v", err)
		}

		var violations []string
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			violations = append(violations,
				testMCPOptionsViolations("control_surfaces.go", fn.Name.Name, funcReceiverType(fn), fn.Body)...)
		}

		if len(violations) == 0 {
			t.Fatal("testMCPOptionsViolations found no violation in " +
				"`sd.testMCPOptions = append(sd.testMCPOptions, ...)` — the static scan would let this " +
				"production write through silently; it exists to catch exactly this (#721)")
		}
	})

	// A KeyValueExpr whose value is not a selector at all (a slice literal,
	// here) never satisfies `sel.Sel.Name == "testMCPOptions"`, so a scan
	// that only ever visited SelectorExpr nodes would let it through
	// silently — the gap the coordinator's cycle-2 follow-up found in the
	// prior version of this guard.
	t.Run("negative control: the scan flags a testMCPOptions field literal", func(t *testing.T) {
		const badSnippet = `package main

func buildFallbackDeps() surfaceDeps {
	return surfaceDeps{testMCPOptions: []mcp.Option{mcp.WithClock(nil)}}
}
`
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "control_surfaces.go", badSnippet, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile(negative-control snippet): %v", err)
		}

		fn, ok := file.Decls[0].(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			t.Fatal("negative-control snippet has no function body")
		}
		violations := testMCPOptionsViolations("control_surfaces.go", fn.Name.Name, funcReceiverType(fn), fn.Body)

		if len(violations) == 0 {
			t.Fatal("testMCPOptionsViolations found no violation in " +
				"`surfaceDeps{testMCPOptions: []mcp.Option{...}}` — a literal value is not a selector, so " +
				"a scan that only watches SelectorExpr nodes would let this production write through " +
				"silently (#721)")
		}
	})

	// Same literal, but as a package-level var initializer rather than
	// inside a function body. The static scan's outer loop originally
	// walked only FuncDecl bodies, so a top-level `var` never reached
	// testMCPOptionsViolations at all — also found in the coordinator's
	// cycle-2 follow-up.
	t.Run("negative control: the scan flags a package-level testMCPOptions literal", func(t *testing.T) {
		const badSnippet = `package main

var fallbackDeps = surfaceDeps{testMCPOptions: []mcp.Option{mcp.WithClock(nil)}}
`
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "control_surfaces.go", badSnippet, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile(negative-control snippet): %v", err)
		}
		if len(file.Decls) != 1 {
			t.Fatalf("negative-control snippet has %d declaration(s), want 1", len(file.Decls))
		}
		if _, ok := file.Decls[0].(*ast.FuncDecl); ok {
			t.Fatal("negative-control snippet's declaration parsed as a FuncDecl, want a package-level var")
		}

		violations := testMCPOptionsViolations("control_surfaces.go", "", "", file.Decls[0])

		if len(violations) == 0 {
			t.Fatal("testMCPOptionsViolations found no violation in a package-level " +
				"`var ... = surfaceDeps{testMCPOptions: ...}` — the static scan's outer loop must walk " +
				"package-level declarations too, not just function bodies (#721)")
		}
	})
}

// funcReceiverType returns the unqualified name of fn's receiver type ("" for
// a function with no receiver, or one whose receiver type is not a plain
// identifier). Used to distinguish mcpSurface's Mount from every other
// type's Mount method of the same name.
func funcReceiverType(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	t := fn.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	ident, ok := t.(*ast.Ident)
	if !ok {
		return ""
	}
	return ident.Name
}

// testMCPOptionsViolations reports every reference to testMCPOptions inside
// node — a FuncDecl's body when funcName/recv name the enclosing function, or
// a package-level declaration when funcName and recv are both "" — that is
// not one of the two allowlisted reads:
//   - control_surfaces.go, func (mcpSurface) Mount: `d.testMCPOptions`
//     spread into append() when building the MCP option list.
//   - main.go, func newServerWithHooks: `hooks.testMCPOptions` as the value
//     of the `testMCPOptions:` key in the surfaceDeps composite literal.
//
// Two independent checks close two different gaps (coordinator follow-up,
// cycle 2 of #721):
//   - a *ast.KeyValueExpr keyed testMCPOptions is flagged unless its value is
//     EXACTLY the selector hooks.testMCPOptions inside newServerWithHooks —
//     this is what catches a literal value (e.g.
//     `surfaceDeps{testMCPOptions: []mcp.Option{...}}`), which a scan that
//     only visits *ast.SelectorExpr nodes named testMCPOptions would miss
//     entirely, since the key itself is a plain *ast.Ident;
//   - a *ast.SelectorExpr named testMCPOptions anywhere else (e.g.
//     `d.testMCPOptions` spread into append, or an assignment's LHS) is
//     flagged unless it is the one allowlisted append-argument read inside
//     mcpSurface.Mount.
//
// Because the caller passes funcName == "" and recv == "" for a package-level
// declaration, neither allowlisted case can ever match there — a `var`
// outside any function is never a legal place for this field to appear.
//
// The allowlist is pinned by (fileName, enclosing function name, receiver
// type, and the exact base identifier the known code reads from) rather than
// by line number, so it survives an unrelated edit elsewhere in either
// function. A selector used as the LHS of an assignment, appended from a
// differently-named variable, or read from any other function, file, or
// package-level declaration is never allowlisted regardless of where it
// sits — this is what the negative controls above exercise (security review
// and coordinator follow-up, cycle 2 of #721: the previous version of this
// guard watched only the recorded appDeps.hooks copy and the serverHooks{...}
// literal, not the field itself, so a direct
// `sd.testMCPOptions = append(...)` in a production file would have passed
// every existing subtest, and a non-selector KeyValueExpr value or a
// package-level `var` would still pass today's SelectorExpr-only,
// FuncDecl-only scan).
func testMCPOptionsViolations(fileName, funcName, recv string, node ast.Node) []string {
	var violations []string
	funcDesc := funcName
	if funcDesc == "" {
		funcDesc = "<package-level declaration>"
	}

	var stack []ast.Node
	ast.Inspect(node, func(n ast.Node) bool {
		if n == nil {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			return false
		}

		if kv, ok := n.(*ast.KeyValueExpr); ok {
			if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "testMCPOptions" {
				if fileName == "main.go" && funcName == "newServerWithHooks" && isHooksTestMCPOptionsSelector(kv.Value) {
					return false // allowed: testMCPOptions: hooks.testMCPOptions
				}
				violations = append(violations, fmt.Sprintf(
					"%s: %s sets testMCPOptions to a value other than hooks.testMCPOptions — only "+
						"main.go's newServerWithHooks may populate this field, and only from its own "+
						"hooks parameter (#721)", fileName, funcDesc))
				return false // reported once; the value is not independently re-scanned below
			}
		}

		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "testMCPOptions" {
			base, _ := sel.X.(*ast.Ident)
			baseName := ""
			if base != nil {
				baseName = base.Name
			}

			allowed := false
			if len(stack) > 0 {
				// append(d.testMCPOptions, ...) inside mcpSurface.Mount — a
				// read, spread into a new slice, never a write to the field
				// itself. The KeyValueExpr form (testMCPOptions:
				// hooks.testMCPOptions) is handled entirely above, before
				// this node is ever reached.
				if call, ok := stack[len(stack)-1].(*ast.CallExpr); ok {
					if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "append" {
						allowed = fileName == "control_surfaces.go" && funcName == "Mount" &&
							recv == "mcpSurface" && baseName == "d"
					}
				}
			}

			if !allowed {
				violations = append(violations, fmt.Sprintf(
					"%s: %s has an unallowlisted reference to testMCPOptions (%s.testMCPOptions) — only "+
						"control_surfaces.go's mcpSurface.Mount (reading d.testMCPOptions into append) and "+
						"main.go's newServerWithHooks (reading hooks.testMCPOptions into the surfaceDeps "+
						"literal) may ever touch this test-only hook (#721)", fileName, funcDesc, baseName))
			}
		}

		stack = append(stack, n)
		return true
	})
	return violations
}

// isHooksTestMCPOptionsSelector reports whether e is exactly the selector
// expression hooks.testMCPOptions — the one value testMCPOptionsViolations
// allows as a testMCPOptions field's value, and only inside main.go's
// newServerWithHooks.
func isHooksTestMCPOptionsSelector(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "testMCPOptions" {
		return false
	}
	base, ok := sel.X.(*ast.Ident)
	return ok && base.Name == "hooks"
}
