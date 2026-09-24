package mcp_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

// capturingObserver is a mcp.ToolCallObserver test double: it appends every
// ToolCall under a mutex (calls arrive on the server's own goroutines) and
// nothing else — no filtering, no dropping — so tests can assert on exactly
// what the middleware published.
type capturingObserver struct {
	mu     sync.Mutex
	events []mcp.ToolCallEvent
}

func (o *capturingObserver) ToolCall(_ context.Context, e mcp.ToolCallEvent) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, e)
}

func (o *capturingObserver) snapshot() []mcp.ToolCallEvent {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]mcp.ToolCallEvent(nil), o.events...)
}

// newObservedServer is toolevents_test.go's own fixture: newTestServer's
// shape (one Node, a real execution-wired capability.Service over a
// fakeConduit), minus the Policy/Template caches this file's tests don't
// need, plus observer wired via mcp.WithToolCallObserver and capSvc wired
// as the Tasks resolver too — tasks/get must never publish a tool-call
// event, and exercising that needs the extension actually registered.
func newObservedServer(t *testing.T, nodeID, hostname string, observer mcp.ToolCallObserver) (testServer, *fakeConduit) {
	t.Helper()

	if hostname == "" {
		hostname = "host-observed"
	}
	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{
		NodeID: nodeID,
		Facts:  registry.Facts{Hostname: hostname, OS: "linux"},
	}.WithNodeLabels(map[string]string{"role": "web"})); err != nil {
		t.Fatalf("seed node: %v", err)
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() }) //nolint:errcheck

	conduit := newFakeConduit()
	capSvc := capability.New(reg,
		capability.WithExecution(st.Jobs(), st.Tasks(), conduit, capability.WithExecNewID(deterministicIDs())),
		capability.WithAuthorizer(testAuthorizer{}),
		capability.WithCapChecker(capability.NewBlastCap(0, 0)),
		capability.WithAuditSink(auditsink.New(st.Audit())),
		capability.WithFreeze(st.Freeze()),
	)
	results := testJobResultReader{jobsRepo: st.Jobs(), tasksRepo: st.Tasks()}

	var opts []mcp.Option
	if observer != nil {
		opts = append(opts, mcp.WithToolCallObserver(observer))
	}
	// capSvc doubles as the Tasks resolver (last arg), exactly like
	// cmd/relay/control_surfaces.go's mcpSurface.Mount — needed so tasks/get
	// is actually registered for TestToolCallMiddleware_DoesNotFireFor.
	handler := mcp.New(testReadLane{svc: capSvc}, opsLister{}, capSvc, results, nil, capSvc, opts...)

	cert := selfSignedCert(t)
	controlSrv := controlplane.New(
		controlplane.Config{
			Addr:           "127.0.0.1:0",
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
		},
		controlplane.NewAuthenticator(staticVerifier{credential: testToken}),
	)
	controlSrv.Mux().Handle("/mcp", handler)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() {
		_ = controlSrv.Serve(lis)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = controlSrv.Shutdown(ctx)
	})

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}

	plain := &http.Client{Transport: transport}
	authed := &http.Client{Transport: relaytest.BearerRoundTripper{Base: transport, Token: testToken}}

	return testServer{
		base:    "https://" + lis.Addr().String(),
		plain:   plain,
		authed:  authed,
		nodeA:   nodeID,
		store:   st,
		conduit: conduit,
		reg:     reg,
	}, conduit
}

// TestToolCallMiddleware_FiresOncePerCall_WithArguments proves the
// middleware publishes exactly one event per tools/call, carrying the
// decoded arguments.
func TestToolCallMiddleware_FiresOncePerCall_WithArguments(t *testing.T) {
	obs := &capturingObserver{}
	ts, _ := newObservedServer(t, "node-1", "", obs)
	session := ts.connect(t)

	callTool(t, session, "list_nodes", map[string]any{"selector": "node:role=web"})

	events := obs.snapshot()
	if len(events) != 1 {
		t.Fatalf("got %d events, want exactly 1: %+v", len(events), events)
	}
	if events[0].Tool != "list_nodes" {
		t.Errorf("Tool = %q, want list_nodes", events[0].Tool)
	}
	if got := events[0].Arguments["selector"]; got != "node:role=web" {
		t.Errorf("Arguments[selector] = %q, want %q", got, "node:role=web")
	}
}

// TestToolCallMiddleware_RawExec_CarriesFullArgv is the publisher's whole
// point: raw_exec's full argv must reach the event.
func TestToolCallMiddleware_RawExec_CarriesFullArgv(t *testing.T) {
	obs := &capturingObserver{}
	ts, conduit := newObservedServer(t, "node-1", "", obs)
	conduit.connect("node-1")
	conduit.results["node-1"] = jobs.Result{Outcome: jobs.OutcomeSuccess}
	session := ts.connect(t)

	callTool(t, session, "raw_exec", map[string]any{
		"selector": "node:role=web",
		"argv":     []any{"/usr/bin/systemctl", "restart", "nginx"},
	})

	events := obs.snapshot()
	if len(events) != 1 {
		t.Fatalf("got %d events, want exactly 1: %+v", len(events), events)
	}
	argv := events[0].Arguments["argv"]
	for _, want := range []string{"/usr/bin/systemctl", "restart", "nginx"} {
		if !strings.Contains(argv, want) {
			t.Errorf("Arguments[argv] = %q, want it to contain %q", argv, want)
		}
	}
}

// TestToolCallMiddleware_DoesNotFireFor proves the middleware fires ONLY for
// tools/call: initialize (done implicitly by connect), tools/list, and
// tasks/get must all leave the observer untouched.
func TestToolCallMiddleware_DoesNotFireFor(t *testing.T) {
	obs := &capturingObserver{}
	ts, _ := newObservedServer(t, "node-1", "", obs)
	session := ts.connect(t) // initialize

	if _, err := session.ListTools(context.Background(), nil); err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	postTasksGet(t, ts)

	if events := obs.snapshot(); len(events) != 0 {
		t.Fatalf("got %d events after initialize/tools-list/tasks-get, want 0: %+v", len(events), events)
	}
}

// postTasksGet sends a raw tasks/get JSON-RPC request against ts, proving
// (alongside TestToolCallMiddleware_DoesNotFireFor's assertion) that the
// middleware's `method == "tools/call"` guard actually excludes it. The
// request targets an unknown task id — a 4xx/error response is fine; only
// whether the observer fired matters here.
func postTasksGet(t *testing.T, ts testServer) {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{"taskId":"no-such-task"}}`
	req, err := http.NewRequest(http.MethodPost, ts.base+"/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	resp, err := ts.authed.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
}

// TestToolCallMiddleware_LeakTest_ListNodes is the behavioural complement to
// the structural walls (internal/events' stdlib-only import,
// ToolCallEvent's closed field set, publish-before-handler): a Node's
// hostname is a unique marker never present anywhere in a list_nodes
// CALL's own arguments, so it can never appear in the published event no
// matter what list_nodes' response contains.
func TestToolCallMiddleware_LeakTest_ListNodes(t *testing.T) {
	const marker = "leak-marker-hostname-4f8c9e"
	obs := &capturingObserver{}
	ts, _ := newObservedServer(t, "node-1", marker, obs)

	session := ts.connect(t)
	res := callTool(t, session, "list_nodes", map[string]any{})
	if !strings.Contains(resultText(t, res), marker) {
		t.Fatal("test setup broken: list_nodes response does not even contain the marker")
	}

	for _, ev := range obs.snapshot() {
		for k, v := range ev.Arguments {
			if strings.Contains(v, marker) {
				t.Fatalf("published event leaked the marker via Arguments[%q] = %q", k, v)
			}
		}
		if strings.Contains(ev.Tool, marker) {
			t.Fatalf("published event leaked the marker via Tool = %q", ev.Tool)
		}
	}
}

// TestToolCallMiddleware_LeakTest_GetJobStdout dispatches a Job whose
// captured Stdout is a unique marker, then calls get_job over it: the
// published events (one for raw_exec, one for get_job) must never contain
// the marker — get_job's only argument is job_id, and raw_exec's own
// argument never mentions daemon-produced output because it does not exist
// yet when raw_exec's event was published.
func TestToolCallMiddleware_LeakTest_GetJobStdout(t *testing.T) {
	const marker = "leak-marker-stdout-9a21bd"
	obs := &capturingObserver{}
	ts, conduit := newObservedServer(t, "node-1", "", obs)
	conduit.connect("node-1")
	conduit.results["node-1"] = jobs.Result{Outcome: jobs.OutcomeSuccess, Stdout: []byte(marker)}

	session := ts.connect(t)
	runRes := callTool(t, session, "raw_exec", map[string]any{
		"selector": "node:role=web",
		"argv":     []any{"/usr/bin/true"},
	})
	var run struct {
		JobID string `json:"job_id"`
	}
	decodeResult(t, runRes, &run)
	if run.JobID == "" {
		t.Fatal("raw_exec did not return a job_id")
	}

	getRes := callTool(t, session, "get_job", map[string]any{"job_id": run.JobID})
	if !strings.Contains(resultText(t, getRes), marker) {
		t.Fatal("test setup broken: get_job response does not even contain the marker")
	}

	for _, ev := range obs.snapshot() {
		for k, v := range ev.Arguments {
			if strings.Contains(v, marker) {
				t.Fatalf("published event leaked the marker via Arguments[%q] = %q", k, v)
			}
		}
	}
}

// TestToolCallMiddleware_ArgumentBudget proves a large argv is truncated
// (dropped whole, per argumentsFromRaw's doc comment) rather than
// unboundedly published — the ring behind this seam holds 1,000 of these,
// and raw_exec's argv is caller-controlled.
func TestToolCallMiddleware_ArgumentBudget(t *testing.T) {
	obs := &capturingObserver{}
	ts, conduit := newObservedServer(t, "node-1", "", obs)
	conduit.connect("node-1")
	conduit.results["node-1"] = jobs.Result{Outcome: jobs.OutcomeSuccess}
	session := ts.connect(t)

	huge := make([]any, 0, 2000)
	for i := 0; i < 2000; i++ {
		huge = append(huge, fmt.Sprintf("argument-number-%d-padded-out-to-make-this-big", i))
	}

	callTool(t, session, "raw_exec", map[string]any{
		"selector": "node:role=web",
		"argv":     huge,
	})

	events := obs.snapshot()
	if len(events) != 1 {
		t.Fatalf("got %d events, want exactly 1", len(events))
	}
	if !events[0].ArgumentsTruncated {
		t.Error("ArgumentsTruncated = false, want true for a >100KB argv")
	}
	var total int
	for _, v := range events[0].Arguments {
		total += len(v)
	}
	if total > 4096 {
		t.Errorf("rendered Arguments total %d bytes, want <= 4096 (the budget)", total)
	}
}

// TestToolCallMiddleware_HugeKeysEmptyValues_TruncatedAndBounded is the S2
// security-review regression guard (cycle 2, review-feedback.md): a budget
// that charges only rendered VALUES never advances when values are empty,
// so `{"kkkk...(huge)": "" x N}` used to slip past the 4096-byte budget
// entirely with truncated=false. The extra unknown properties make
// list_nodes itself fail input validation (IsError), but the middleware
// publishes before that handler ever runs, so this proves what actually
// reached the bus regardless of the call's own outcome.
func TestToolCallMiddleware_HugeKeysEmptyValues_TruncatedAndBounded(t *testing.T) {
	obs := &capturingObserver{}
	ts, _ := newObservedServer(t, "node-1", "", obs)
	session := ts.connect(t)

	args := make(map[string]any, 200)
	for i := 0; i < 200; i++ {
		args[fmt.Sprintf("k%04d-%s", i, strings.Repeat("k", 5000))] = ""
	}
	callTool(t, session, "list_nodes", args)

	events := obs.snapshot()
	if len(events) != 1 {
		t.Fatalf("got %d events, want exactly 1: %+v", len(events), events)
	}
	if !events[0].ArgumentsTruncated {
		t.Error("ArgumentsTruncated = false, want true for 200 huge-key/empty-value arguments")
	}
	var total int
	for k, v := range events[0].Arguments {
		total += len(k) + len(v)
	}
	if total > 4096 {
		t.Errorf("rendered Arguments total (keys+values) %d bytes, want <= 4096 (the budget)", total)
	}
	if len(events[0].Arguments) > 64 {
		t.Errorf("got %d Arguments entries, want <= maxArgumentEntries (64)", len(events[0].Arguments))
	}
}

// TestToolCallMiddleware_OversizedToolName_Capped is the S2 regression guard
// for params.Name (review-feedback.md cycle 2): the middleware publishes
// the tool name BEFORE the SDK has validated that it names a real,
// registered tool, so an unbounded name must still be capped. Calls
// session.CallTool directly (not the callTool helper, which fails the test
// on a protocol-level error) since an oversized name is expected to be
// rejected by the transport — only what the observer captured matters here.
func TestToolCallMiddleware_OversizedToolName_Capped(t *testing.T) {
	obs := &capturingObserver{}
	ts, _ := newObservedServer(t, "node-1", "", obs)
	session := ts.connect(t)

	hugeName := strings.Repeat("n", 5000)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = session.CallTool(ctx, &sdkmcp.CallToolParams{Name: hugeName, Arguments: map[string]any{}})

	events := obs.snapshot()
	if len(events) != 1 {
		t.Fatalf("got %d events, want exactly 1", len(events))
	}
	if len(events[0].Tool) > 128 {
		t.Errorf("Tool name length = %d, want <= 128 (maxToolNameBytes)", len(events[0].Tool))
	}
}

// TestToolCallMiddleware_HandlerError_StillPublishesOneEvent proves
// publishing happens before the handler runs: a tool call that itself
// fails must still be observed exactly once.
func TestToolCallMiddleware_HandlerError_StillPublishesOneEvent(t *testing.T) {
	obs := &capturingObserver{}
	ts, _ := newObservedServer(t, "node-1", "", obs)
	session := ts.connect(t)

	// Empty argv is raw_exec's own input-validation failure
	// ("argv must not be empty") — a tool-level error, not a transport one.
	res := callTool(t, session, "raw_exec", map[string]any{
		"selector": "node:role=web",
		"argv":     []any{},
	})
	if !res.IsError {
		t.Fatal("expected raw_exec with empty argv to fail")
	}

	events := obs.snapshot()
	if len(events) != 1 {
		t.Fatalf("got %d events for a failed tool call, want exactly 1: %+v", len(events), events)
	}
	if events[0].Tool != "raw_exec" {
		t.Errorf("Tool = %q, want raw_exec", events[0].Tool)
	}
}

// TestToolCallMiddleware_NilObserver_InstallsNoMiddleware proves a nil
// observer (mcp.New's default) installs no middleware at all: a tool call
// still succeeds normally.
func TestToolCallMiddleware_NilObserver_InstallsNoMiddleware(t *testing.T) {
	ts, _ := newObservedServer(t, "node-1", "", nil)
	session := ts.connect(t)

	res := callTool(t, session, "list_nodes", map[string]any{})
	if res.IsError {
		t.Fatalf("list_nodes failed with a nil observer: %+v", res.Content)
	}
}
