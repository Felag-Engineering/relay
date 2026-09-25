package mcp_test

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// elicit_test.go is S2b of #646's mcp-handler-seam proof (elicit.go): fixture
// request -> asserted response, over the SDK's real HTTP transport, mirroring
// taskgolden_test.go's fixtures rather than re-inventing them. This step
// merges dark (the option is never passed from cmd/relay/control_surfaces.go)
// — every test here reaches the option through mcp.WithApprovalElicitation
// directly, package mcp_test's own seam onto mcp.New.

// askableElicitRequestID/askableElicitPlanHash/askableElicitTaskID are the
// fixed fields askableParker's park carries, mirroring goldenParker's shape
// (taskgolden_test.go) so the two fixture families stay visually comparable.
const (
	askableElicitRequestID = "req-elicit-1"
	askableElicitPlanHash  = "hash-elicit-1"
	askableElicitTaskID    = "task-elicit-1"
)

// askableParker is an Executor whose every dispatch parks with a fixed
// *capability.ParkedError, Askable set from the field — so the rendering
// tests below are a function of the RENDERING alone, mirroring
// taskgolden_test.go's goldenParker.
type askableParker struct{ askable bool }

func (p askableParker) Run(context.Context, capability.Principal, capability.Selector, jobs.Action) ([]capability.NodeResult, error) {
	return nil, &capability.ParkedError{
		RequestID:     askableElicitRequestID,
		PlanHash:      askableElicitPlanHash,
		Summary:       `service.restart(unit="nginx") [mutate] on 1 node(s): node-a`,
		Progress:      "0 of 1",
		Rules:         []string{"all-mutates-need-a-human"},
		ExpiresAt:     goldenNow.Add(4 * time.Hour),
		TaskID:        askableElicitTaskID,
		TaskExpiresAt: goldenNow.Add(time.Hour),
		Askable:       p.askable,
	}
}

func (askableParker) CancelJob(context.Context, capability.Principal, string) error { return nil }

func (askableParker) Plan(context.Context, capability.Principal, capability.Selector, jobs.Action) (capability.PlanResult, error) {
	return capability.PlanResult{}, nil
}

// stubDecider implements mcp.ApprovalDecider and fails the test if ever
// called: this step renders a question, it never decides one (ADR-0029
// decision 5 is tools_approval.go's alone). It reports the failure with
// t.Error rather than t.Fatal: the SDK invokes DecideApproval from its own
// handler goroutine, and t.Fatal there would only stop that goroutine —
// silently, since t.Fatal is documented to require running on the test's own
// goroutine — rather than the test itself.
type stubDecider struct{ t *testing.T }

func (d stubDecider) DecideApproval(context.Context, capability.Principal, capability.ApprovalDecision) (approval.Request, error) {
	d.t.Helper()
	d.t.Error("stubDecider.DecideApproval was called — S2b never decides, it only renders a question")
	return approval.Request{}, nil
}

// elicitServer mounts the real handler behind the real authenticator, exactly
// like taskgolden_test.go's goldenServerWithExec, with opts appended after
// the fixed clock so a test can turn the option (and a decider) on.
func elicitServer(t *testing.T, exec mcp.Executor, tasks mcp.TaskResolver, opts ...mcp.Option) *httptest.Server {
	t.Helper()
	allOpts := append([]mcp.Option{mcp.WithClock(func() time.Time { return goldenNow })}, opts...)
	handler := mcp.New(nil, opsLister{}, exec, goldenJobs{}, nil, tasks, allOpts...)

	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	srv := httptest.NewServer(controlplane.NewAuthenticator(goldenVerifier{}).Middleware(mux))
	t.Cleanup(srv.Close)
	return srv
}

// elicitRunOperationRequest is runOperationRequest (taskgolden_test.go)
// generalized to an arbitrary clientCapabilities JSON value, so a test can
// drive every combination the emission predicate cares about.
func elicitRunOperationRequest(caps string) string {
	return `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"_meta":{` +
		`"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
		`"io.modelcontextprotocol/clientInfo":{"name":"elicit-client","version":"0.0.1"},` +
		`"io.modelcontextprotocol/clientCapabilities":` + caps + `},` +
		`"name":"run_operation","arguments":{"operation":"service.restart","args":{"unit":"nginx"}}}}`
}

// elicitCaps and tasksAndElicitCaps are the clientCapabilities bodies the
// tests below need repeatedly.
const (
	elicitCaps         = `{"elicitation":{"form":{}}}`
	noElicitCaps       = `{}`
	tasksOnlyCaps      = `{"extensions":{"io.modelcontextprotocol/tasks":{}}}`
	tasksAndElicitCaps = `{"elicitation":{"form":{}},"extensions":{"io.modelcontextprotocol/tasks":{}}}`
)

// decodedResult is the subset of a tools/call JSON-RPC response elicit_test.go
// asserts against.
type decodedResult struct {
	ResultType        string          `json:"resultType"`
	Meta              map[string]any  `json:"_meta"`
	Content           json.RawMessage `json:"content"`
	StructuredContent json.RawMessage `json:"structuredContent"`
	InputRequests     json.RawMessage `json:"inputRequests"`
	RequestState      string          `json:"requestState"`
	IsError           bool            `json:"isError"`
}

// decodeElicitResult unmarshals body's JSON-RPC result.
func decodeElicitResult(t *testing.T, body string) decodedResult {
	t.Helper()
	var resp struct {
		Result decodedResult `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode: %v; body = %s", err, body)
	}
	return resp.Result
}

func isEmptyJSON(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s == "" || s == "null" || s == "[]"
}

// TestElicit_QuestionCarriesNoContent is the headline shape proof (AP-60):
// an askable park, from an MRTR-capable, elicitation-advertising client,
// with the option on and a decider wired, renders an input-required result
// carrying exactly one input request keyed by the request ID, a sealed
// requestState, and the request ID/plan hash in `_meta` — never Content,
// never structuredContent, never the pending_approval string anywhere.
func TestElicit_QuestionCarriesNoContent(t *testing.T) {
	srv := elicitServer(t, askableParker{askable: true}, goldenTasks{},
		mcp.WithApprovalElicitation(), mcp.WithApprovalDecider(stubDecider{t: t}))

	status, body, _ := postJSONRPC(t, srv, "tools/call", "run_operation", elicitRunOperationRequest(elicitCaps))
	if status != 200 {
		t.Fatalf("status = %d; body = %s", status, body)
	}
	if strings.Contains(body, "pending_approval") {
		t.Fatalf("body contains \"pending_approval\": %s", body)
	}

	res := decodeElicitResult(t, body)
	if res.IsError {
		t.Fatalf("isError = true, want false: %s", body)
	}
	if res.ResultType != "input_required" {
		t.Errorf("resultType = %q, want input_required", res.ResultType)
	}
	if !isEmptyJSON(res.Content) {
		t.Errorf("content = %s, want absent/null/empty", res.Content)
	}
	if !isEmptyJSON(res.StructuredContent) {
		t.Errorf("structuredContent = %s, want absent", res.StructuredContent)
	}
	if res.RequestState == "" {
		t.Error("requestState is empty, want the sealed state")
	}

	// Every InputRequestMap entry wraps its params under a "method" wire
	// discriminator (go-sdk mcp/protocol.go's InputRequestMap.MarshalJSON) —
	// methodElicit ("elicitation/create") for an *sdkmcp.ElicitParams — so the
	// message/schema live one level down, under "params".
	var reqs map[string]struct {
		Method string `json:"method"`
		Params struct {
			Mode            string         `json:"mode"`
			Message         string         `json:"message"`
			RequestedSchema map[string]any `json:"requestedSchema"`
			Meta            map[string]any `json:"_meta"`
		} `json:"params"`
	}
	if err := json.Unmarshal(res.InputRequests, &reqs); err != nil {
		t.Fatalf("decode inputRequests: %v; %s", err, res.InputRequests)
	}
	if len(reqs) != 1 {
		t.Fatalf("inputRequests has %d entries, want exactly 1: %+v", len(reqs), reqs)
	}
	entry, ok := reqs[askableElicitRequestID]
	if !ok {
		t.Fatalf("inputRequests is not keyed by the request ID %q: %+v", askableElicitRequestID, reqs)
	}
	if entry.Method != "elicitation/create" {
		t.Errorf("method = %q, want elicitation/create", entry.Method)
	}
	if entry.Params.Mode != "form" {
		t.Errorf("mode = %q, want form", entry.Params.Mode)
	}
	if entry.Params.Message != `service.restart(unit="nginx") [mutate] on 1 node(s): node-a` {
		t.Errorf("message = %q, want the Relay-authored summary verbatim", entry.Params.Message)
	}
	if entry.Params.Meta != nil {
		t.Errorf("input request _meta = %+v, want nil — no vendor elicitation-kind hint", entry.Params.Meta)
	}
	wantSchema := map[string]any{"type": "object", "properties": map[string]any{}}
	gotSchema, err := json.Marshal(entry.Params.RequestedSchema)
	if err != nil {
		t.Fatalf("marshal requestedSchema: %v", err)
	}
	wantSchemaJSON, _ := json.Marshal(wantSchema)
	if string(gotSchema) != string(wantSchemaJSON) {
		t.Errorf("requestedSchema = %s, want %s", gotSchema, wantSchemaJSON)
	}

	if got := res.Meta[mcpMetaKeyRequestID]; got != askableElicitRequestID {
		t.Errorf("_meta[%q] = %v, want %q", mcpMetaKeyRequestID, got, askableElicitRequestID)
	}
	if got := res.Meta[mcpMetaKeyPlanHash]; got != askableElicitPlanHash {
		t.Errorf("_meta[%q] = %v, want %q", mcpMetaKeyPlanHash, got, askableElicitPlanHash)
	}
}

// mcpMetaKeyRequestID/mcpMetaKeyPlanHash mirror elicit.go's own unexported
// constants — duplicated here because this test file is package mcp_test and
// cannot reach the unexported originals; a drift between the two literals
// would fail TestElicit_QuestionCarriesNoContent immediately.
const (
	mcpMetaKeyRequestID = "relay/request_id"
	mcpMetaKeyPlanHash  = "relay/plan_hash"
)

// TestElicit_NonAskableParkRendersPendingApproval is AP-61/AP-62: a park the
// capability layer marked NOT askable renders byte-for-byte the same
// pending_approval result as a server with no elicitation option at all,
// even with the option on, a decider wired, and an MRTR/elicitation-capable
// client — Askable is read, never recomputed (invariant 10).
func TestElicit_NonAskableParkRendersPendingApproval(t *testing.T) {
	req := elicitRunOperationRequest(elicitCaps)

	baseline := elicitServer(t, askableParker{askable: false}, goldenTasks{})
	_, wantBody, _ := postJSONRPC(t, baseline, "tools/call", "run_operation", req)
	if !strings.Contains(wantBody, "pending_approval") {
		t.Fatalf("baseline body has no pending_approval, the golden itself is broken: %s", wantBody)
	}

	withElicit := elicitServer(t, askableParker{askable: false}, goldenTasks{},
		mcp.WithApprovalElicitation(), mcp.WithApprovalDecider(stubDecider{t: t}))
	_, gotBody, _ := postJSONRPC(t, withElicit, "tools/call", "run_operation", req)

	assertGoldenJSON(t, gotBody, wantBody)
}

// TestElicit_OutOfBandParkNeverAsks_HandlerSeam is AP-69's weaker,
// mcp-handler-seam companion to cmd/relay/elicit_e2e_test.go's
// TestElicit_OutOfBandParkNeverAsks, which drives the real gate (the real
// source of Askable=false for an out-of-band rule); here the fixture stands
// in for that gate by setting askableParker{askable: false} directly (an
// out-of-band park is exactly a non-askable one; askableBy's channel term,
// capability/approval.go), so what this test actually proves is the same
// claim TestElicit_NonAskableParkRendersPendingApproval does — that an
// elicitation-advertising client still gets pending_approval when Askable is
// false — kept as a separate, differently-shaped assertion (substring rather
// than golden-JSON-equal) rather than folded into it, so a regression in
// either style of check is still caught.
func TestElicit_OutOfBandParkNeverAsks_HandlerSeam(t *testing.T) {
	srv := elicitServer(t, askableParker{askable: false}, goldenTasks{},
		mcp.WithApprovalElicitation(), mcp.WithApprovalDecider(stubDecider{t: t}))

	_, body, _ := postJSONRPC(t, srv, "tools/call", "run_operation", elicitRunOperationRequest(elicitCaps))
	res := decodeElicitResult(t, body)
	if res.ResultType == "input_required" {
		t.Fatalf("resultType = input_required, want pending_approval rendering (out-of-band park): %s", body)
	}
	if !strings.Contains(body, "pending_approval") {
		t.Fatalf("body has no pending_approval: %s", body)
	}
}

// TestElicit_OptionOffChangesNothing is the AP-70 dark guard at the mcp
// handler seam: an askable park from an MRTR/elicitation-capable client
// renders identically to today whenever the option is off, or a decider is
// unwired — three servers, one canonical body.
func TestElicit_OptionOffChangesNothing(t *testing.T) {
	req := elicitRunOperationRequest(elicitCaps)

	noOptions := elicitServer(t, askableParker{askable: true}, goldenTasks{})
	_, wantBody, _ := postJSONRPC(t, noOptions, "tools/call", "run_operation", req)
	if !strings.Contains(wantBody, "pending_approval") {
		t.Fatalf("baseline body has no pending_approval, the golden itself is broken: %s", wantBody)
	}

	optionOnlyNoDecider := elicitServer(t, askableParker{askable: true}, goldenTasks{}, mcp.WithApprovalElicitation())
	_, body2, _ := postJSONRPC(t, optionOnlyNoDecider, "tools/call", "run_operation", req)
	assertGoldenJSON(t, body2, wantBody)

	deciderOnlyNoOption := elicitServer(t, askableParker{askable: true}, goldenTasks{}, mcp.WithApprovalDecider(stubDecider{t: t}))
	_, body3, _ := postJSONRPC(t, deciderOnlyNoOption, "tools/call", "run_operation", req)
	assertGoldenJSON(t, body3, wantBody)
}

// TestElicit_NoElicitationCapabilityDoesNotAsk: `_meta` is 2026-07-28 (MRTR
// capable) but clientCapabilities carries no elicitation object at all —
// predicate condition 3 refuses, so the park renders pending_approval and no
// inputRequests.
func TestElicit_NoElicitationCapabilityDoesNotAsk(t *testing.T) {
	srv := elicitServer(t, askableParker{askable: true}, goldenTasks{},
		mcp.WithApprovalElicitation(), mcp.WithApprovalDecider(stubDecider{t: t}))

	_, body, _ := postJSONRPC(t, srv, "tools/call", "run_operation", elicitRunOperationRequest(noElicitCaps))
	res := decodeElicitResult(t, body)
	if len(res.InputRequests) != 0 {
		t.Fatalf("inputRequests present with no elicitation capability advertised: %s", body)
	}
	if !strings.Contains(body, "pending_approval") {
		t.Fatalf("body has no pending_approval: %s", body)
	}
}

// TestElicit_ElicitedParkEmitsNoTaskEnvelope is AP-71: with the real task
// shim wired (goldenTasks), a client capable of BOTH elicitation and Tasks
// gets the question and no task envelope at all (no taskId/status/ttlMs), while
// a client capable of Tasks alone (cannot be asked) still gets today's task
// envelope unchanged.
func TestElicit_ElicitedParkEmitsNoTaskEnvelope(t *testing.T) {
	srv := elicitServer(t, askableParker{askable: true}, goldenTasks{},
		mcp.WithApprovalElicitation(), mcp.WithApprovalDecider(stubDecider{t: t}))

	_, bothBody, _ := postJSONRPC(t, srv, "tools/call", "run_operation", elicitRunOperationRequest(tasksAndElicitCaps))
	res := decodeElicitResult(t, bothBody)
	if res.ResultType != "input_required" {
		t.Errorf("resultType = %q, want input_required", res.ResultType)
	}
	if len(res.InputRequests) == 0 {
		t.Errorf("inputRequests missing: %s", bothBody)
	}
	if !isEmptyJSON(res.StructuredContent) {
		t.Errorf("structuredContent present, want none: %s", bothBody)
	}
	for _, forbidden := range []string{`"taskId"`, `"pollIntervalMs"`, `"ttlMs"`} {
		if strings.Contains(bothBody, forbidden) {
			t.Errorf("body contains %s, want no task envelope: %s", forbidden, bothBody)
		}
	}

	_, taskOnlyBody, _ := postJSONRPC(t, srv, "tools/call", "run_operation", elicitRunOperationRequest(tasksOnlyCaps))
	var taskResp struct {
		Result struct {
			ResultType string `json:"resultType"`
			TaskID     string `json:"taskId"`
			Status     string `json:"status"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(taskOnlyBody), &taskResp); err != nil {
		t.Fatalf("decode: %v; body = %s", err, taskOnlyBody)
	}
	if taskResp.Result.ResultType != "task" {
		t.Errorf("resultType = %q, want task (Tasks-capable client that cannot be asked keeps today's envelope)", taskResp.Result.ResultType)
	}
	if taskResp.Result.TaskID != askableElicitTaskID {
		t.Errorf("taskId = %q, want %q", taskResp.Result.TaskID, askableElicitTaskID)
	}
	if taskResp.Result.Status != "working" {
		t.Errorf("status = %q, want working", taskResp.Result.Status)
	}
}

// TestElicit_SealKeyIsPerProcessAndNotConfiguration proves the key is
// process-lifetime (two mcp.New instances seal the SAME fields to DIFFERENT
// states — Seal is deterministic, so a difference in output can only come
// from a difference in key) and, structurally, that the key can never be
// reached from configuration.
func TestElicit_SealKeyIsPerProcessAndNotConfiguration(t *testing.T) {
	req := elicitRunOperationRequest(elicitCaps)

	srv1 := elicitServer(t, askableParker{askable: true}, goldenTasks{},
		mcp.WithApprovalElicitation(), mcp.WithApprovalDecider(stubDecider{t: t}))
	srv2 := elicitServer(t, askableParker{askable: true}, goldenTasks{},
		mcp.WithApprovalElicitation(), mcp.WithApprovalDecider(stubDecider{t: t}))

	_, body1, _ := postJSONRPC(t, srv1, "tools/call", "run_operation", req)
	_, body2, _ := postJSONRPC(t, srv2, "tools/call", "run_operation", req)

	state1 := decodeElicitResult(t, body1).RequestState
	state2 := decodeElicitResult(t, body2).RequestState
	if state1 == "" || state2 == "" {
		t.Fatalf("empty requestState: body1=%s body2=%s", body1, body2)
	}
	if state1 == state2 {
		t.Errorf("requestState is IDENTICAL across two mcp.New instances given the same inputs — "+
			"the seal key must be minted fresh per process (invariant 11): %q", state1)
	}

	for _, finding := range scanElicitKeySurface(t) {
		t.Error(finding)
	}
}

// TestElicit_ServerNeverSendsElicitation is the structural half of "the
// server never sends elicitation/create itself": no non-test file in package
// mcp calls a selector named Elicit or CreateMessage, or spells the literal
// "elicitation/create" — the question travels as an ordinary CallToolResult,
// and it is the CLIENT's own multi-round-trip middleware that ever turns it
// into a real elicitation/create round trip.
func TestElicit_ServerNeverSendsElicitation(t *testing.T) {
	dir := mcpPackageDir(t)
	fset := token.NewFileSet()

	forEachNonTestGoFile(t, dir, func(name string, file *ast.File) {
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.SelectorExpr:
				if node.Sel.Name == "Elicit" || node.Sel.Name == "CreateMessage" {
					t.Errorf("%s calls a selector named %q — the server must never initiate elicitation/create or CreateMessage itself (ADR-0029)", name, node.Sel.Name)
				}
			case *ast.BasicLit:
				if node.Kind != token.STRING {
					return true
				}
				lit, err := strconv.Unquote(node.Value)
				if err == nil && lit == "elicitation/create" {
					t.Errorf("%s spells the literal %q — the server must never send it itself (ADR-0029)", name, lit)
				}
			}
			return true
		})
	}, fset)
}

// -----------------------------------------------------------------------
// Structural scanning helpers
// -----------------------------------------------------------------------

// requeststateImportPath is the seal-key package's import path.
const requeststateImportPath = "github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp/requeststate"

// mcpPackageDir locates package mcp's own directory (this test file's
// directory) via runtime.Caller, mirroring no_dispatch_test.go/
// no_decision_test.go's own pattern.
func mcpPackageDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(thisFile)
}

// forEachNonTestGoFile parses every non-test .go file directly inside dir and
// calls fn with its base name and parsed *ast.File.
func forEachNonTestGoFile(t *testing.T, dir string, fn func(name string, file *ast.File), fset *token.FileSet) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%s): %v", dir, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", path, err)
		}
		fn(name, file)
	}
}

// isByteSliceType reports whether expr is exactly []byte.
func isByteSliceType(expr ast.Expr) bool {
	arr, ok := expr.(*ast.ArrayType)
	if !ok || arr.Len != nil {
		return false
	}
	ident, ok := arr.Elt.(*ast.Ident)
	return ok && ident.Name == "byte"
}

// isRequestStateSealerPointer reports whether expr is exactly
// *requeststate.Sealer.
func isRequestStateSealerPointer(expr ast.Expr) bool {
	star, ok := expr.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	return ok && ident.Name == "requeststate" && sel.Sel.Name == "Sealer"
}

// returnsOption reports whether fn's sole return value is exactly Option —
// i.e. fn is one of the package's Option constructors (WithClock,
// WithApprovalDecider, WithApprovalElicitation, WithToolCallObserver, and any
// future WithXxx). These are THE configuration surface a caller passes into
// mcp.New, which is why the []byte/*requeststate.Sealer parameter rule below
// is scoped to them rather than to every top-level function: a plain helper
// like taskshim.go's writeShimResponse(w io.Writer, ...) or
// tools_execution.go's truncateOutput(b []byte) takes a []byte for reasons
// that have nothing to do with the seal key, and flagging it would be a false
// positive against real, benign code.
func returnsOption(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
		return false
	}
	ident, ok := fn.Type.Results.List[0].Type.(*ast.Ident)
	return ok && ident.Name == "Option"
}

// scanElicitKeySurface is the structural half of
// TestElicit_SealKeyIsPerProcessAndNotConfiguration: it returns one finding
// per way the requeststate seal key could become reachable from outside
// mcp.New's own crypto/rand mint, narrowed to top-level Option constructors
// (see returnsOption above) so it does not flag ordinary []byte-typed
// helpers with nothing to do with the seal key.
//
//   - No file in package mcp may reference requeststate.New or
//     requeststate.NewKey — only requeststate.Mint (elicit.go's
//     newQuestioner) ever constructs a Sealer.
//   - No top-level (no receiver) function in package mcp may take a
//     parameter of type *requeststate.Sealer — nothing outside elicit.go's
//     own newQuestioner should ever hold or pass one.
//   - No Option CONSTRUCTOR (a top-level function returning exactly Option
//     — see returnsOption) may take a parameter of type []byte or
//     *requeststate.Sealer: an Option is precisely the configuration
//     surface a caller passes into mcp.New, so this is where a
//     configurable key would first appear. Scoped to Option constructors
//     rather than every top-level function so it does not flag ordinary
//     []byte-typed helpers with nothing to do with the seal key (plan
//     review item 1).
//   - WithApprovalElicitation takes no parameters at all: an Option that
//     accepted an argument would be one step from a configurable key.
//   - No non-test file in cmd/relay imports the requeststate package: the
//     composition root has no business reaching the key package directly.
func scanElicitKeySurface(t *testing.T) []string {
	t.Helper()
	var findings []string

	mcpDir := mcpPackageDir(t)
	cmdRelayDir := filepath.Join(mcpDir, "..", "..", "..", "cmd", "relay")
	fset := token.NewFileSet()

	forEachNonTestGoFile(t, mcpDir, func(name string, file *ast.File) {
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkgIdent, ok := sel.X.(*ast.Ident)
			if !ok || pkgIdent.Name != "requeststate" {
				return true
			}
			if sel.Sel.Name == "New" || sel.Sel.Name == "NewKey" {
				findings = append(findings, name+" references requeststate."+sel.Sel.Name+
					" — the seal key must be minted only via requeststate.Mint (invariant 11)")
			}
			return true
		})

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				// Methods are out of scope (e.g. an io.Writer's
				// Write([]byte)) — see the doc comment above.
				continue
			}
			if fn.Name.Name == "WithApprovalElicitation" && fn.Type.Params != nil && len(fn.Type.Params.List) != 0 {
				findings = append(findings, name+": WithApprovalElicitation takes parameters, want none")
			}
			if fn.Type.Params == nil {
				continue
			}
			isOption := returnsOption(fn)
			for _, field := range fn.Type.Params.List {
				if isRequestStateSealerPointer(field.Type) {
					findings = append(findings, name+": top-level func "+fn.Name.Name+
						" takes a *requeststate.Sealer parameter — nothing outside elicit.go's "+
						"newQuestioner should ever hold or pass one")
					continue
				}
				if isOption && isByteSliceType(field.Type) {
					findings = append(findings, name+": Option constructor "+fn.Name.Name+
						" takes a []byte parameter — the seal key must never be configurable "+
						"through the surface a caller passes into mcp.New")
				}
			}
		}
	}, fset)

	forEachNonTestGoFile(t, cmdRelayDir, func(name string, file *ast.File) {
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err == nil && path == requeststateImportPath {
				findings = append(findings, name+" imports "+requeststateImportPath+
					" — the composition root must never reach the seal key package directly")
			}
		}
	}, fset)

	return findings
}
