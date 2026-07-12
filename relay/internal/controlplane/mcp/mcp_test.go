package mcp_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/opvocab"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

const testToken = "mcp-integration-test-token"

// opsLister adapts opvocab.Operations (a package-level func) to
// mcp.OperationLister, exactly like relay/cmd/relay/main.go's opvocabLister.
type opsLister struct{}

func (opsLister) Operations() []opvocab.Descriptor { return opvocab.Operations() }

// selfSignedCert mints a throwaway, self-signed TLS certificate for tests
// (mirrors controlplane's own selfSignedCert test helper — unexported there,
// so duplicated here rather than exported solely for tests).
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mcp-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return cert
}

// testJobResultReader adapts a *store.Store's Jobs()/Tasks() to
// mcp.JobResultReader, mirroring cmd/relay/main.go's own (unexported)
// jobResultReader — duplicated here rather than exported solely for tests.
type testJobResultReader struct {
	jobsRepo  jobs.JobRepository
	tasksRepo jobs.TaskRepository
}

func (r testJobResultReader) GetJob(ctx context.Context, id string) (jobs.Job, error) {
	return r.jobsRepo.GetJob(ctx, id)
}

func (r testJobResultReader) TasksByJob(ctx context.Context, jobID string) ([]jobs.Task, error) {
	return r.tasksRepo.ByJob(ctx, jobID)
}

// testServer is the fixture for every test in this file: a control-plane
// Server with the real MCP handler mounted at /mcp behind
// Authenticator.Middleware, seeded with two Nodes and one Policy snapshot,
// and (#118) a REAL execution-wired capability.Service — store, conduit,
// authz, blast-cap, audit sink, and Freeze store are all real, so
// run_operation/raw_exec/cancel_job/get_job exercise the exact same
// pipeline (Freeze -> Selector -> authz -> blast-cap -> dispatch -> audit)
// every production surface does. store/conduit are exposed so
// mcp_exec_test.go's cases can configure per-Node connectivity/results and
// inspect audit rows.
type testServer struct {
	base    string
	plain   *http.Client // TLS-trusting, no credential
	authed  *http.Client // TLS-trusting, valid bearer credential
	nodeA   string       // node:role=web, relay:quarantine=on; has a captured Policy snapshot
	nodeB   string       // node:env=prod; no Policy snapshot captured
	store   *store.Store
	conduit *fakeConduit
}

// newTestServer builds the fixture described on testServer with generous
// (package-default) blast-radius caps — see newTestServerWithBlastCap for
// the over-cap test's smaller mutateCap.
func newTestServer(t *testing.T) testServer {
	return newTestServerWithBlastCap(t, 0, 0)
}

// newTestServerWithBlastCap is newTestServer, parameterized on the
// read/mutate blast-radius caps (capability.NewBlastCap: a non-positive
// value clamps to the package default). Node A carries both a node: and a
// relay: label so the "labels are never merged" assertions have something
// to distinguish; Node B has no policyview.Cache entry so describe_node's
// reported=false path is exercised.
func newTestServerWithBlastCap(t *testing.T, readCap, mutateCap int) testServer {
	t.Helper()

	const nodeA = "node-a"
	const nodeB = "node-b"

	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{
		NodeID: nodeA,
		Facts: registry.Facts{
			Hostname:    "web-1",
			OS:          "linux",
			Kernel:      "6.1.0",
			Arch:        "amd64",
			IPAddresses: []string{"10.0.0.1"},
		},
		NodeLabels:        map[string]string{"role": "web"},
		PolicyFingerprint: "sha256:node-a-fingerprint",
	}); err != nil {
		t.Fatalf("seed node A: %v", err)
	}
	if err := reg.SetRelayLabels(nodeA, map[string]string{"quarantine": "on"}); err != nil {
		t.Fatalf("set node A relay labels: %v", err)
	}
	if _, err := reg.Upsert(registry.Report{
		NodeID:            nodeB,
		Facts:             registry.Facts{Hostname: "db-1", OS: "linux"},
		NodeLabels:        map[string]string{"env": "prod"},
		PolicyFingerprint: "sha256:node-b-fingerprint",
	}); err != nil {
		t.Fatalf("seed node B: %v", err)
	}

	policyCache := policyview.New()
	policyCache.Set(nodeA, policyview.Snapshot{
		RawExecEnabled:    true,
		RawAllowPatterns:  []string{`^/usr/bin/systemctl restart .+$`},
		RawDenyPatterns:   []string{`.*rm -rf.*`},
		AllowedOperations: []string{"system.facts", "file.read"},
		PolicyFingerprint: "sha256:node-a-fingerprint",
	})
	// nodeB intentionally has no captured snapshot: describe_node(nodeB) must
	// show reported=false, proving absence isn't confused with "unrestricted".

	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() }) //nolint:errcheck

	conduit := newFakeConduit()
	capSvc := capability.New(reg,
		capability.WithExecution(st.Jobs(), st.Tasks(), conduit, capability.WithExecNewID(deterministicIDs())),
		capability.WithAuthorizer(testAuthorizer{}),
		capability.WithCapChecker(capability.NewBlastCap(readCap, mutateCap)),
		capability.WithAuditSink(auditsink.New(st.Audit())),
		capability.WithFreeze(st.Freeze()),
	)
	results := testJobResultReader{jobsRepo: st.Jobs(), tasksRepo: st.Tasks()}

	handler := mcp.New(reg, policyCache, opsLister{}, capSvc, results)

	cert := selfSignedCert(t)
	sum := sha256.Sum256([]byte(testToken))
	controlSrv := controlplane.New(
		controlplane.Config{Addr: "127.0.0.1:0", TLSCert: cert},
		controlplane.NewAuthenticator(sum[:]),
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
		nodeA:   nodeA,
		nodeB:   nodeB,
		store:   st,
		conduit: conduit,
	}
}

// connect opens an authenticated MCP client session against ts.
func (ts testServer) connect(t *testing.T) *sdkmcp.ClientSession {
	t.Helper()

	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "mcp-test-client", Version: "0.0.1"}, nil)
	transport := &sdkmcp.StreamableClientTransport{Endpoint: ts.base + "/mcp", HTTPClient: ts.authed}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// callTool calls name with args and fails the test on a protocol-level
// error (transport/JSON-RPC failure) — but NOT on a tool error (IsError),
// which callers assert on explicitly.
func callTool(t *testing.T, session *sdkmcp.ClientSession, name string, args map[string]any) *sdkmcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := session.CallTool(ctx, &sdkmcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s): protocol error: %v", name, err)
	}
	return res
}

// decodeResult unmarshals a successful CallToolResult's text content into out.
func decodeResult(t *testing.T, res *sdkmcp.CallToolResult, out any) {
	t.Helper()
	if res.IsError {
		t.Fatalf("tool call returned IsError=true unexpectedly; content = %+v", res.Content)
	}
	if len(res.Content) == 0 {
		t.Fatal("CallToolResult.Content is empty")
	}
	tc, ok := res.Content[0].(*sdkmcp.TextContent)
	if !ok {
		t.Fatalf("CallToolResult.Content[0] = %T, want *sdkmcp.TextContent", res.Content[0])
	}
	if err := json.Unmarshal([]byte(tc.Text), out); err != nil {
		t.Fatalf("json.Unmarshal(%q): %v", tc.Text, err)
	}
}

func TestMCP_ListNodes_All(t *testing.T) {
	ts := newTestServer(t)
	session := ts.connect(t)

	res := callTool(t, session, "list_nodes", nil)
	var out mcp.ListNodesOutput
	decodeResult(t, res, &out)

	if len(out.Nodes) != 2 {
		t.Fatalf("list_nodes(): got %d Nodes, want 2: %+v", len(out.Nodes), out.Nodes)
	}

	var a, b *mcp.NodeItem
	for i := range out.Nodes {
		switch out.Nodes[i].NodeID {
		case ts.nodeA:
			a = &out.Nodes[i]
		case ts.nodeB:
			b = &out.Nodes[i]
		}
	}
	if a == nil || b == nil {
		t.Fatalf("list_nodes(): missing expected NodeIDs; got %+v", out.Nodes)
	}

	// node: and relay: labels must be visibly distinct — separate maps,
	// never merged (ADR-0006, invariant 7).
	if a.NodeLabels["role"] != "web" {
		t.Errorf("node A NodeLabels[role] = %q, want %q", a.NodeLabels["role"], "web")
	}
	if a.RelayLabels["quarantine"] != "on" {
		t.Errorf("node A RelayLabels[quarantine] = %q, want %q", a.RelayLabels["quarantine"], "on")
	}
	if _, ok := a.NodeLabels["quarantine"]; ok {
		t.Error("node A NodeLabels contains quarantine — relay: label leaked into node: map")
	}
	if _, ok := b.RelayLabels["env"]; ok {
		t.Error("node B RelayLabels contains env — node: label leaked into relay: map")
	}
	if len(b.RelayLabels) != 0 {
		t.Errorf("node B RelayLabels = %v, want empty", b.RelayLabels)
	}

	if a.Facts.Hostname != "web-1" {
		t.Errorf("node A Facts.Hostname = %q, want %q", a.Facts.Hostname, "web-1")
	}
}

func TestMCP_ListNodes_SelectorFilter(t *testing.T) {
	ts := newTestServer(t)
	session := ts.connect(t)

	t.Run("node: filter matches only node A", func(t *testing.T) {
		res := callTool(t, session, "list_nodes", map[string]any{"selector": "node:role=web"})
		var out mcp.ListNodesOutput
		decodeResult(t, res, &out)
		if len(out.Nodes) != 1 || out.Nodes[0].NodeID != ts.nodeA {
			t.Fatalf("list_nodes(node:role=web) = %+v, want only %q", out.Nodes, ts.nodeA)
		}
	})

	t.Run("relay: filter matches only node A", func(t *testing.T) {
		res := callTool(t, session, "list_nodes", map[string]any{"selector": "relay:quarantine=on"})
		var out mcp.ListNodesOutput
		decodeResult(t, res, &out)
		if len(out.Nodes) != 1 || out.Nodes[0].NodeID != ts.nodeA {
			t.Fatalf("list_nodes(relay:quarantine=on) = %+v, want only %q", out.Nodes, ts.nodeA)
		}
	})

	t.Run("bare key with no namespace prefix is a tool error", func(t *testing.T) {
		res := callTool(t, session, "list_nodes", map[string]any{"selector": "bare=key"})
		if !res.IsError {
			t.Fatalf("list_nodes(bare=key): IsError = false, want true (fail-closed on missing namespace prefix)")
		}
	})
}

func TestMCP_DescribeNode(t *testing.T) {
	ts := newTestServer(t)
	session := ts.connect(t)

	t.Run("node with a captured Policy snapshot", func(t *testing.T) {
		res := callTool(t, session, "describe_node", map[string]any{"node_id": ts.nodeA})
		var out mcp.DescribeNodeOutput
		decodeResult(t, res, &out)

		if out.NodeID != ts.nodeA {
			t.Errorf("NodeID = %q, want %q", out.NodeID, ts.nodeA)
		}
		if !out.EffectivePolicy.Reported {
			t.Error("EffectivePolicy.Reported = false, want true (a snapshot was captured for node A)")
		}
		if !out.EffectivePolicy.RawExecEnabled {
			t.Error("EffectivePolicy.RawExecEnabled = false, want true")
		}
		if len(out.EffectivePolicy.AllowedOperations) != 2 {
			t.Errorf("EffectivePolicy.AllowedOperations = %v, want 2 entries", out.EffectivePolicy.AllowedOperations)
		}
		if out.EffectivePolicy.PolicyFingerprint == "" {
			t.Error("EffectivePolicy.PolicyFingerprint is empty, want set")
		}
	})

	t.Run("node with no captured Policy snapshot", func(t *testing.T) {
		res := callTool(t, session, "describe_node", map[string]any{"node_id": ts.nodeB})
		var out mcp.DescribeNodeOutput
		decodeResult(t, res, &out)

		if out.NodeID != ts.nodeB {
			t.Errorf("NodeID = %q, want %q", out.NodeID, ts.nodeB)
		}
		if out.EffectivePolicy.Reported {
			t.Error("EffectivePolicy.Reported = true, want false (no snapshot captured for node B)")
		}
		// The top-level (registry) Policy fingerprint must still show even
		// when no snapshot has been captured.
		if out.PolicyFingerprint == "" {
			t.Error("top-level PolicyFingerprint is empty, want the registry's Hello-reported fingerprint")
		}
	})

	t.Run("unknown node is a tool error", func(t *testing.T) {
		res := callTool(t, session, "describe_node", map[string]any{"node_id": "no-such-node"})
		if !res.IsError {
			t.Fatal("describe_node(no-such-node): IsError = false, want true")
		}
	})
}

func TestMCP_ListOperations(t *testing.T) {
	ts := newTestServer(t)
	session := ts.connect(t)

	res := callTool(t, session, "list_operations", nil)
	var out mcp.ListOperationsOutput
	decodeResult(t, res, &out)

	// want/wantArgKeys are derived directly from opvocab.Operations() (the
	// exact registry list_operations itself renders) rather than a
	// hand-copied literal (#163 S3) — this test can never drift from
	// opvocab's own golden-backed vocabulary (opvocab_test.go's
	// TestOperations_MatchesGoldenSchema, ADR-0015); it instead proves the
	// vocabulary survives JSON rendering through list_operations.
	want := make(map[string]string, len(opvocab.Operations()))
	wantArgKeys := make(map[string][]string, len(opvocab.Operations()))
	for _, d := range opvocab.Operations() {
		switch d.Risk {
		case jobs.RiskClassRead:
			want[d.Name] = "read"
		case jobs.RiskClassMutate:
			want[d.Name] = "mutate"
		default:
			t.Fatalf("opvocab.Operations()[%q].Risk = %v, want RiskClassRead or RiskClassMutate", d.Name, d.Risk)
		}
		keys := make([]string, 0, len(d.ArgConstraints))
		for k := range d.ArgConstraints {
			keys = append(keys, k)
		}
		wantArgKeys[d.Name] = keys
	}
	if len(out.Operations) != len(want) {
		t.Fatalf("list_operations(): got %d entries, want %d: %+v", len(out.Operations), len(want), out.Operations)
	}
	for _, op := range out.Operations {
		wantRisk, ok := want[op.Name]
		if !ok {
			t.Errorf("list_operations(): unexpected entry %q", op.Name)
			continue
		}
		if op.RiskClass != wantRisk {
			t.Errorf("list_operations()[%q].RiskClass = %q, want %q", op.Name, op.RiskClass, wantRisk)
		}
		if op.Name == "raw_exec" {
			t.Error("list_operations(): Raw Exec must never appear (it is not an Operation)")
		}

		// #120: every Operation must be legible — a non-empty purpose and
		// example, so a model reader never has to trial-and-error its way
		// to a working call.
		if strings.TrimSpace(op.Purpose) == "" {
			t.Errorf("list_operations()[%q].Purpose is empty, want a non-empty description", op.Name)
		}
		if op.Example == "" {
			t.Errorf("list_operations()[%q].Example is empty, want a concrete usage example", op.Name)
		}
		if op.ArgConstraints == nil {
			t.Errorf("list_operations()[%q].ArgConstraints is nil, want non-nil", op.Name)
		}

		wantKeys, ok := wantArgKeys[op.Name]
		if !ok {
			continue
		}
		if len(op.ArgConstraints) != len(wantKeys) {
			t.Errorf("list_operations()[%q].ArgConstraints = %v, want keys %v", op.Name, op.ArgConstraints, wantKeys)
			continue
		}
		for _, k := range wantKeys {
			if strings.TrimSpace(op.ArgConstraints[k]) == "" {
				t.Errorf("list_operations()[%q].ArgConstraints[%q] is empty, want documented constraint prose", op.Name, k)
			}
		}
	}
}

// TestMCP_RequiresCredential proves that #117's real MCP handler is still
// reached only through the same Authenticator.Middleware #115 proved with
// the now-removed /mcp placeholder: no credential and a wrong credential
// both fail with 401.
func TestMCP_RequiresCredential(t *testing.T) {
	ts := newTestServer(t)

	initializeBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`

	post := func(client *http.Client, token string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, ts.base+"/mcp", strings.NewReader(initializeBody))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		return resp
	}

	resp := post(ts.plain, "")
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no credential: status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	respWrong := post(ts.plain, "wrong-"+testToken)
	defer respWrong.Body.Close() //nolint:errcheck
	if respWrong.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong credential: status = %d, want %d", respWrong.StatusCode, http.StatusUnauthorized)
	}

	respOK := post(ts.plain, testToken)
	defer respOK.Body.Close() //nolint:errcheck
	if respOK.StatusCode != http.StatusOK {
		t.Errorf("valid credential: status = %d, want %d", respOK.StatusCode, http.StatusOK)
	}
}
