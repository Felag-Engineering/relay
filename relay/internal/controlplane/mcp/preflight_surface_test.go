package mcp

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// preflightDetectorRegex is deliberately narrower than the obvious guess.
// After ADR-0038, "plan" names the Plan capability
// (docs/specs/plan.md, Status "designed, not built") — its own MCP tools
// (propose_plan, get_plan, advance_plan, abandon_plan) all carry the bare
// token "plan" and none of them is a preflight, so a preflight-detector
// regex carrying that token would false-match every one of them the moment
// plan.md is built. The detection that would give up is recovered, more
// strongly, by TestNoPreflightToolOrMethodIsRegistered's own exact-set
// assertion: a tool literally named "plan" (or "policy_check", or anything
// else) is caught there, reviewed, and named — never silently exempted by a
// regex allowlist.
var preflightDetectorRegex = regexp.MustCompile(`(?i)preflight|preview|dry.?run|simulate|what.?if`)

// registeredEntryPoint is one MCP tool or custom-method registration this
// package's own non-test sources declare, plus where it was found — so a
// failure names the offending file and line rather than reporting an
// unattributed set mismatch.
type registeredEntryPoint struct {
	name string
	file string
	line int
}

// toolNameFromAddToolArg extracts the Name field from an
// &sdkmcp.Tool{Name: "...", ...} composite literal argument, as passed to
// sdkmcp.AddTool's second parameter.
func toolNameFromAddToolArg(arg ast.Expr) (string, bool) {
	unary, ok := arg.(*ast.UnaryExpr)
	if !ok || unary.Op != token.AND {
		return "", false
	}
	lit, ok := unary.X.(*ast.CompositeLit)
	if !ok {
		return "", false
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "Name" {
			continue
		}
		bl, ok := kv.Value.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			continue
		}
		s, err := strconv.Unquote(bl.Value)
		if err != nil {
			return "", false
		}
		return s, true
	}
	return "", false
}

// collectMCPEntryPoints AST-walks every non-test .go file in this package's
// own directory for a CallExpr registering a tool (sdkmcp.AddTool) or a
// custom method (sdkmcp.AddReceivingCustomMethod), regardless of whether
// mcp.New's own wiring would register it conditionally at runtime — the
// reason this is an AST walk rather than a live ListTools call against
// newTestServer: mcp.New registers approve_request only when
// WithApprovalDecider is passed, so a live-server check sees only a subset of
// the package's real registration sites. The AST walk sees every one,
// regardless of how it is wired at runtime.
//
// FAIL CLOSED (security review, cycle 2, SR1): a registration whose name
// cannot be resolved to a string literal is a t.Errorf naming the file and
// line, never a silent skip. A skip is how a tool registered as
// `&sdkmcp.Tool{Name: toolPreflight, ...}` — a package-level name constant,
// the shape readlane_registry.go already uses for its own strings — would
// ship a second preflight tool under a walk that still reports a clean
// exact set.
func collectMCPEntryPoints(t *testing.T) []registeredEntryPoint {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%s): %v", dir, err)
	}

	var found []registeredEntryPoint
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", path, err)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pos := fset.Position(call.Pos())
			switch sel.Sel.Name {
			case "AddTool":
				// FAIL CLOSED (security review, cycle 2, SR1): a tool whose
				// Name cannot be resolved to a string literal must not be
				// silently invisible to this guard. A skip here is exactly
				// how `const toolPreflight = "preflight"` used as a Name
				// value would ship a separate preflight tool under a green
				// PF-1 guard — this repo already uses name constants for
				// tool names elsewhere (readlane_registry.go).
				if len(call.Args) < 2 {
					t.Errorf("%s:%d calls AddTool with fewer than 2 arguments — this walk cannot resolve its tool name and fails closed rather than silently skipping the registration (PF-1)", name, pos.Line)
					return true
				}
				toolName, ok := toolNameFromAddToolArg(call.Args[1])
				if !ok {
					t.Errorf("%s:%d registers a tool whose Name is not a string literal — this walk cannot verify it is not a preflight tool and fails closed rather than silently skipping it (PF-1)", name, pos.Line)
					return true
				}
				found = append(found, registeredEntryPoint{name: toolName, file: name, line: pos.Line})
			case "AddReceivingCustomMethod":
				if len(call.Args) < 2 {
					t.Errorf("%s:%d calls AddReceivingCustomMethod with fewer than 2 arguments — this walk cannot resolve its method name and fails closed rather than silently skipping the registration (PF-1)", name, pos.Line)
					return true
				}
				lit, ok := call.Args[1].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Errorf("%s:%d registers a custom method whose name is not a string literal — this walk cannot verify it is not a preflight method and fails closed rather than silently skipping it (PF-1)", name, pos.Line)
					return true
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Errorf("%s:%d registers a custom method with an unparsable string literal name (%v) — this walk fails closed rather than silently skipping it (PF-1)", name, pos.Line, err)
					return true
				}
				found = append(found, registeredEntryPoint{name: s, file: name, line: pos.Line})
			}
			return true
		})
	}
	return found
}

// TestNoPreflightToolOrMethodIsRegistered proves PF-1's MCP half
// (docs/specs/policy-preflight.md): "no surface exposes a separate preflight
// tool or route" — the only way in is the plan option on run_operation and
// raw_exec.
//
// The positive half (the "only way in" via plan:true) is already in the
// tree and cited rather than rebuilt: mcp_plan_test.go's plan-mode tests
// call run_operation/raw_exec with the plan option and get verdicts back.
func TestNoPreflightToolOrMethodIsRegistered(t *testing.T) {
	found := collectMCPEntryPoints(t)
	if len(found) == 0 {
		t.Fatal("collectMCPEntryPoints found zero registration sites — the AST walk matched nothing; the SDK's registration shape likely changed and this guard cannot prove anything until it is updated")
	}

	names := make(map[string]bool, len(found))
	for _, f := range found {
		names[f.name] = true
	}

	// The eight entry points registered today. Any addition must be named
	// here and reviewed against PF-1 before it passes.
	want := []string{
		"list_nodes", "describe_node", "list_operations",
		"run_operation", "raw_exec",
		"cancel_job", "get_job",
		"approve_request",
	}
	wantSet := make(map[string]bool, len(want))
	for _, w := range want {
		wantSet[w] = true
	}

	for n := range names {
		if !wantSet[n] {
			t.Errorf("an unexpected entry point %q is registered — any addition must be named in this test's exact set and reviewed against PF-1 before it passes", n)
		}
	}
	for _, w := range want {
		if !names[w] {
			t.Errorf("expected entry point %q is not registered — the exact set changed", w)
		}
	}

	// The guard against the walk silently matching nothing useful even
	// though it found something: run_operation and raw_exec must both be
	// among the entry points found, since they are the two the plan option
	// actually lives on.
	if !names["run_operation"] || !names["raw_exec"] {
		t.Fatal("run_operation/raw_exec were not found among the registered entry points — the walk is not seeing this package's real registration sites")
	}

	for _, f := range found {
		if preflightDetectorRegex.MatchString(f.name) {
			t.Errorf("%s:%d registers %q, which matches the preflight-detector regex — PF-1 says no surface exposes a separate preflight tool or method", f.file, f.line, f.name)
		}
	}

	// Cross-check the other direction (code review, cycle 2, CR3): the exact
	// set above is only as good as what collectMCPEntryPoints's AST walk
	// recognises. A tool registered in a shape the walk does not recognise
	// (a future SDK registration helper, say) would be invisible to both the
	// exact set and the regex above. Every tool a REAL, fully-wired server's
	// live ListTools returns must be a name this walk already found.
	for live := range liveRegisteredToolNames(t) {
		if !names[live] {
			t.Errorf("live ListTools() returns tool %q, which collectMCPEntryPoints's AST walk did not find at all — the walk's recognised registration shape has drifted from what mcp.New actually registers", live)
		}
	}
}

// noopExecutor and noopApprovalDecider satisfy Executor/ApprovalDecider well
// enough to be wired into a real server for liveRegisteredToolNames below —
// every conditionally-registered tool needs a non-nil collaborator to be
// MOUNTED, but none of them is ever CALLED (this test only lists tools, it
// never calls one), so every method here is an unreached stub.
type noopExecutor struct{}

func (noopExecutor) Start(ctx context.Context, p capability.Principal, sel capability.Selector, act jobs.Action, o capability.StartOptions) (capability.StartedJob, error) {
	return capability.StartedJob{}, nil
}
func (noopExecutor) CancelJob(ctx context.Context, p capability.Principal, jobID string) error {
	return nil
}
func (noopExecutor) Plan(ctx context.Context, p capability.Principal, sel capability.Selector, act jobs.Action) (capability.PlanResult, error) {
	return capability.PlanResult{}, nil
}

type noopApprovalDecider struct{}

func (noopApprovalDecider) DecideApproval(ctx context.Context, p capability.Principal, in capability.ApprovalDecision) (approval.Request, error) {
	return approval.Request{}, nil
}

// liveRegisteredToolNames builds a real mcp.New server with every
// conditionally-registered tool switched on (an ApprovalDecider, alongside the
// always-registered ones), serves it over a
// plain httptest server (New returns a bare http.Handler; the
// Authenticator.Middleware that wraps it in production is orthogonal to
// tool registration), and returns the set of tool names a real MCP client's
// ListTools call reports. This is the live half of
// TestNoPreflightToolOrMethodIsRegistered's cross-check — deliberately not
// the test's ONLY seam (see collectMCPEntryPoints's doc comment for why an
// AST walk is still required: conditional registration means a live check
// alone would miss any tool the fixture below fails to switch on).
func liveRegisteredToolNames(t *testing.T) map[string]bool {
	t.Helper()
	handler := New(nil, stubOpsLister{}, noopExecutor{}, nil, nil, WithApprovalDecider(noopApprovalDecider{}))
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "preflight-surface-test", Version: "0.0.1"}, nil)
	transport := &sdkmcp.StreamableClientTransport{Endpoint: srv.URL, HTTPClient: srv.Client()}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(res.Tools) == 0 {
		t.Fatal("ListTools() returned zero tools — the fixture is not really wired, so this cross-check would pass vacuously")
	}
	names := make(map[string]bool, len(res.Tools))
	for _, tool := range res.Tools {
		names[tool.Name] = true
	}
	return names
}

// TestBuildOperationAction_IllFormedArgValueIsNotRefused is the surface-side
// link of PF-13's value half: "an ill-formed argument value is NOT refused
// by the Relay" — the mirror of TestBuildOperationAction_UnknownArgOnAValidCallIsRejected,
// which proves the name half. opvocab.ValidateArgNames (the only Relay-side
// argument check both surfaces call) checks unknown/missing NAMES and
// inspects no value at all, so a well-named, ill-formed value must sail
// through unchanged — it is the daemon's business, never the Relay's
// (invariant 12, ADR-0011).
func TestBuildOperationAction_IllFormedArgValueIsNotRefused(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		args      map[string]string
	}{
		{
			name:      "file.read: a non-canonical path — the daemon denies it (ADR-0018)",
			operation: "file.read",
			args:      map[string]string{"path": "/etc/../etc/shadow"},
		},
		{
			name:      "service.restart: a unit name carrying a semicolon and a shell fragment — fails the daemon's validate_unit_name",
			operation: "service.restart",
			args:      map[string]string{"unit": "nginx; rm -rf /"},
		},
		{
			name:      "pkg.install: a traversal-shaped package name — fails the daemon's validate_pkg_name",
			operation: "pkg.install",
			args:      map[string]string{"name": "../../etc/passwd"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			act, err := buildOperationAction(stubOpsLister{}, tc.operation, tc.args, 0)
			if err != nil {
				t.Fatalf("buildOperationAction(%s, %v) = %v, want no error — an ill-formed VALUE is the daemon's business, not the Relay's (PF-13, invariant 12)", tc.operation, tc.args, err)
			}
			for k, want := range tc.args {
				if got := act.OperationArgs[k]; got != want {
					t.Errorf("OperationArgs[%q] = %q, want %q byte-for-byte (no trimming, no normalisation)", k, got, want)
				}
			}
			if act.RiskClass != jobs.RiskClassUnspecified {
				t.Errorf("RiskClass = %v, want unspecified: the adapter sets no class; the capability layer derives it (invariant 13)", act.RiskClass)
			}
		})
	}
}
