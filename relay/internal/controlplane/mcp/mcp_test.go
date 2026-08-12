package mcp_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/nodevocab"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/opvocab"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

const testToken = accounts.TokenPrefix + "abcdef0123456789.mcp-integration-test" //nolint:gosec // test fixture, not a real credential

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
	return newTestServerWithConfig(t, readCap, mutateCap, "")
}

// newTestServerWithConfig is newTestServerWithBlastCap, additionally
// parameterized on the registry's min_daemon_version gate (ADR-0014); ""
// leaves the gate off, exactly like newTestServerWithBlastCap.
func newTestServerWithConfig(t *testing.T, readCap, mutateCap int, minDaemonVersion string) testServer {
	t.Helper()

	const nodeA = "node-a"
	const nodeB = "node-b"

	reg := registry.NewInMemory(registry.WithMinDaemonVersion(minDaemonVersion))
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
		DaemonVersion:     "1.1.0",
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
		DaemonVersion:     "1.3.0",
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
		OperationRules: []policyview.OperationRule{
			{Name: "service.restart", AllowedArgs: [][]string{{"nginx", "php-fpm"}}},
			// A zero-arg Operation's rule arrives with nil AllowedArgs (proto
			// empty repeated field) — describe_node must render it as [] and
			// never null (#207/#253).
			{Name: "system.facts", AllowedArgs: nil},
		},
		DenyRules: []policyview.DenyRule{
			{Name: "file.read", Args: [][]string{{"/etc/shadow"}}},
		},
	})
	// nodeB intentionally has no captured snapshot: describe_node(nodeB) must
	// show reported=false, proving absence isn't confused with "unrestricted".

	// nodeA has a reported Template Operation vocabulary (#291, ADR-0021);
	// nodeB deliberately has none captured, so describe_node(nodeB) shows
	// template_vocabulary.reported=false — "not reported yet", never "this
	// Node has no templates".
	vocabCache := nodevocab.New()
	vocabCache.Set(nodeA, nodevocab.Snapshot{
		Fingerprint: "sha256:node-a-template-set",
		Templates: []nodevocab.Template{
			{Name: "disk.usage", RiskClass: int32(jobs.RiskClassRead)},
			{
				Name:      "log.tail",
				RiskClass: int32(jobs.RiskClassRead),
				Slots: []nodevocab.Slot{
					{Name: "lines", Type: "integer"},
					{Name: "path", Type: "path"},
				},
			},
		},
	})

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

	handler := mcp.New(reg, policyCache, vocabCache, opsLister{}, capSvc, results)

	cert := selfSignedCert(t)
	controlSrv := controlplane.New(
		controlplane.Config{Addr: "127.0.0.1:0", TLSCert: cert},
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

// resultText returns a successful CallToolResult's raw JSON text — for
// asserting the EMITTED wire shape (key presence/absence, null vs []) that
// a struct round-trip would mask (#207/#253).
func resultText(t *testing.T, res *sdkmcp.CallToolResult) string {
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
	return tc.Text
}

// decodeResult unmarshals a successful CallToolResult's text content into out.
func decodeResult(t *testing.T, res *sdkmcp.CallToolResult, out any) {
	t.Helper()
	text := resultText(t, res)
	if err := json.Unmarshal([]byte(text), out); err != nil {
		t.Fatalf("json.Unmarshal(%q): %v", text, err)
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

// TestMCP_Outdated exercises the ADR-0014 outdated gate end-to-end through
// both list_nodes and describe_node: a below-minimum Node's daemon version
// must show outdated:true, an at/above-minimum Node's must show false, and
// with the gate off (newTestServer's default) no Node is ever outdated.
func TestMCP_Outdated(t *testing.T) {
	t.Run("gate off: no Node is ever outdated", func(t *testing.T) {
		ts := newTestServer(t)
		session := ts.connect(t)

		listRes := callTool(t, session, "list_nodes", nil)
		var listOut mcp.ListNodesOutput
		decodeResult(t, listRes, &listOut)
		for _, n := range listOut.Nodes {
			if n.Outdated {
				t.Errorf("list_nodes: node %q Outdated = true, want false (gate off)", n.NodeID)
			}
		}

		describeRes := callTool(t, session, "describe_node", map[string]any{"node_id": ts.nodeA})
		var describeOut mcp.DescribeNodeOutput
		decodeResult(t, describeRes, &describeOut)
		if describeOut.Outdated {
			t.Error("describe_node: Outdated = true, want false (gate off)")
		}
	})

	t.Run("gate on: below-minimum Node is outdated, above-minimum is not", func(t *testing.T) {
		// Node A reports 1.1.0, Node B reports 1.3.0 (see newTestServerWithConfig).
		ts := newTestServerWithConfig(t, 0, 0, "1.2.0")
		session := ts.connect(t)

		listRes := callTool(t, session, "list_nodes", nil)
		var listOut mcp.ListNodesOutput
		decodeResult(t, listRes, &listOut)

		var a, b *mcp.NodeItem
		for i := range listOut.Nodes {
			switch listOut.Nodes[i].NodeID {
			case ts.nodeA:
				a = &listOut.Nodes[i]
			case ts.nodeB:
				b = &listOut.Nodes[i]
			}
		}
		if a == nil || b == nil {
			t.Fatalf("list_nodes(): missing expected NodeIDs; got %+v", listOut.Nodes)
		}
		if !a.Outdated {
			t.Error("list_nodes: node A (1.1.0) Outdated = false, want true (below 1.2.0 minimum)")
		}
		if b.Outdated {
			t.Error("list_nodes: node B (1.3.0) Outdated = true, want false (above 1.2.0 minimum)")
		}

		describeRes := callTool(t, session, "describe_node", map[string]any{"node_id": ts.nodeA})
		var describeOut mcp.DescribeNodeOutput
		decodeResult(t, describeRes, &describeOut)
		if !describeOut.Outdated {
			t.Error("describe_node(node A): Outdated = false, want true (below 1.2.0 minimum)")
		}
	})
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
		// DoD (#187): describe_node must show the per-Operation allowed-arg
		// rule and the explicit deny rule, verbatim from the daemon's Policy.
		// The zero-arg system.facts rule decodes as a non-nil empty slice —
		// its allowed_args were emitted as [], never null (#207/#253).
		wantOperationRules := []mcp.OperationRuleOutput{
			{Name: "service.restart", AllowedArgs: [][]string{{"nginx", "php-fpm"}}},
			{Name: "system.facts", AllowedArgs: [][]string{}},
		}
		if !reflect.DeepEqual(out.EffectivePolicy.OperationRules, wantOperationRules) {
			t.Errorf("EffectivePolicy.OperationRules = %+v, want %+v",
				out.EffectivePolicy.OperationRules, wantOperationRules)
		}
		// Assert the emitted JSON, not just the decoded struct: a zero-arg
		// rule renders "allowed_args":[] and no "allowed_args":null appears
		// anywhere in the response (#207/#253).
		text := resultText(t, res)
		if !strings.Contains(text, `"allowed_args":[]`) {
			t.Errorf("describe_node JSON = %s, want it to contain %q (the zero-arg system.facts rule)", text, `"allowed_args":[]`)
		}
		if strings.Contains(text, `"allowed_args":null`) {
			t.Errorf("describe_node JSON = %s, must never contain %q", text, `"allowed_args":null`)
		}
		wantDenyRules := []mcp.DenyRuleOutput{
			{Name: "file.read", Args: [][]string{{"/etc/shadow"}}},
		}
		if !reflect.DeepEqual(out.EffectivePolicy.DenyRules, wantDenyRules) {
			t.Errorf("EffectivePolicy.DenyRules = %+v, want %+v",
				out.EffectivePolicy.DenyRules, wantDenyRules)
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
		if len(out.EffectivePolicy.OperationRules) != 0 || len(out.EffectivePolicy.DenyRules) != 0 {
			t.Errorf("EffectivePolicy.OperationRules/DenyRules = %+v/%+v, want both empty (Reported=false)",
				out.EffectivePolicy.OperationRules, out.EffectivePolicy.DenyRules)
		}
		// The emitted JSON must carry empty ARRAYS, never null (#207/#253):
		// reported=false is the only "no Policy data yet" signal.
		text := resultText(t, res)
		if !strings.Contains(text, `"operation_rules":[]`) || !strings.Contains(text, `"deny_rules":[]`) {
			t.Errorf("describe_node (reported=false) JSON = %s, want it to contain %q and %q — arrays, never null",
				text, `"operation_rules":[]`, `"deny_rules":[]`)
		}
	})

	// #291 (ADR-0021): describe_node reports the Node's Template Operation
	// vocabulary beside its effective Policy, with the same "reported is the
	// only no-data-yet signal" discipline.
	t.Run("node with a captured template vocabulary", func(t *testing.T) {
		res := callTool(t, session, "describe_node", map[string]any{"node_id": ts.nodeA})
		var out mcp.DescribeNodeOutput
		decodeResult(t, res, &out)

		if !out.TemplateVocabulary.Reported {
			t.Fatal("TemplateVocabulary.Reported = false, want true (a snapshot was captured for node A)")
		}
		if out.TemplateVocabulary.Fingerprint != "sha256:node-a-template-set" {
			t.Errorf("TemplateVocabulary.Fingerprint = %q, want the reported template-set fingerprint",
				out.TemplateVocabulary.Fingerprint)
		}
		want := []mcp.TemplateOperationOutput{
			{Name: "disk.usage", RiskClass: "read", Slots: []mcp.TemplateSlotOutput{}},
			{
				Name:      "log.tail",
				RiskClass: "read",
				Slots: []mcp.TemplateSlotOutput{
					{Name: "lines", Type: "integer", EnumValues: []string{}},
					{Name: "path", Type: "path", EnumValues: []string{}},
				},
			},
		}
		if !reflect.DeepEqual(out.TemplateVocabulary.Templates, want) {
			t.Errorf("TemplateVocabulary.Templates = %+v, want %+v", out.TemplateVocabulary.Templates, want)
		}
		// The template BODY never crosses the wire (ADR-0021): only the
		// daemon renders it, so no response may carry one.
		text := resultText(t, res)
		if strings.Contains(text, `"body"`) {
			t.Errorf("describe_node JSON = %s, must never carry a template body", text)
		}
		if strings.Contains(text, `"slots":null`) || strings.Contains(text, `"templates":null`) {
			t.Errorf("describe_node JSON = %s, must use empty arrays, never null", text)
		}
	})

	t.Run("node with no captured template vocabulary", func(t *testing.T) {
		res := callTool(t, session, "describe_node", map[string]any{"node_id": ts.nodeB})
		var out mcp.DescribeNodeOutput
		decodeResult(t, res, &out)

		if out.TemplateVocabulary.Reported {
			t.Error("TemplateVocabulary.Reported = true, want false (nothing captured for node B)")
		}
		if len(out.TemplateVocabulary.Templates) != 0 {
			t.Errorf("TemplateVocabulary.Templates = %+v, want empty", out.TemplateVocabulary.Templates)
		}
		text := resultText(t, res)
		if !strings.Contains(text, `"templates":[]`) {
			t.Errorf("describe_node (reported=false) JSON = %s, want %q — an array, never null",
				text, `"templates":[]`)
		}
	})

	t.Run("unknown node is a tool error", func(t *testing.T) {
		res := callTool(t, session, "describe_node", map[string]any{"node_id": "no-such-node"})
		if !res.IsError {
			t.Fatal("describe_node(no-such-node): IsError = false, want true")
		}
	})
}

// TestMCP_ListOperations_PerNode is #291's discovery half (ADR-0021): the
// vocabulary is per-Node, so list_operations(node_id) returns that Node's
// Template Operations alongside the frozen native four, each tagged with its
// source, and a Node with nothing reported says so rather than implying it has
// no templates.
func TestMCP_ListOperations_PerNode(t *testing.T) {
	ts := newTestServer(t)
	session := ts.connect(t)

	t.Run("without node_id: natives only", func(t *testing.T) {
		res := callTool(t, session, "list_operations", nil)
		var out mcp.ListOperationsOutput
		decodeResult(t, res, &out)

		if out.NodeID != "" {
			t.Errorf("NodeID = %q, want empty when no Node was named", out.NodeID)
		}
		for _, op := range out.Operations {
			if op.Source != "native" {
				t.Errorf("list_operations()[%q].Source = %q, want \"native\" (no Node was named)", op.Name, op.Source)
			}
		}
		if len(out.Operations) != len(opvocab.Operations()) {
			t.Errorf("list_operations(): got %d entries, want the %d native Operations",
				len(out.Operations), len(opvocab.Operations()))
		}
	})

	t.Run("with node_id: natives plus that Node's templates", func(t *testing.T) {
		res := callTool(t, session, "list_operations", map[string]any{"node_id": ts.nodeA})
		var out mcp.ListOperationsOutput
		decodeResult(t, res, &out)

		if out.NodeID != ts.nodeA {
			t.Errorf("NodeID = %q, want %q", out.NodeID, ts.nodeA)
		}
		if !out.TemplatesReported {
			t.Error("TemplatesReported = false, want true (node A reported a template set)")
		}
		if out.TemplateSetFingerprint != "sha256:node-a-template-set" {
			t.Errorf("TemplateSetFingerprint = %q, want the reported fingerprint", out.TemplateSetFingerprint)
		}

		bySource := map[string][]mcp.OperationItem{}
		for _, op := range out.Operations {
			bySource[op.Source] = append(bySource[op.Source], op)
		}
		if got := len(bySource["native"]); got != len(opvocab.Operations()) {
			t.Errorf("native entries = %d, want %d", got, len(opvocab.Operations()))
		}
		if got := len(bySource["template"]); got != 2 {
			t.Fatalf("template entries = %d, want 2: %+v", got, bySource["template"])
		}
		for _, op := range bySource["template"] {
			if op.RiskClass != "read" {
				t.Errorf("template %q RiskClass = %q, want \"read\"", op.Name, op.RiskClass)
			}
			// Legibility bar (ADR-0001): a template entry must be as usable as
			// a native one — purpose, example, and per-slot constraint prose.
			if strings.TrimSpace(op.Purpose) == "" || op.Example == "" || op.ArgConstraints == nil {
				t.Errorf("template %q is not legible: %+v", op.Name, op)
			}
			if op.Name == "log.tail" {
				for _, slot := range []string{"lines", "path"} {
					if strings.TrimSpace(op.ArgConstraints[slot]) == "" {
						t.Errorf("template log.tail ArgConstraints[%q] is empty, want constraint prose", slot)
					}
				}
			}
		}
	})

	t.Run("with a node that has reported nothing", func(t *testing.T) {
		res := callTool(t, session, "list_operations", map[string]any{"node_id": ts.nodeB})
		var out mcp.ListOperationsOutput
		decodeResult(t, res, &out)

		if out.TemplatesReported {
			t.Error("TemplatesReported = true, want false (node B reported no template set)")
		}
		for _, op := range out.Operations {
			if op.Source == "template" {
				t.Errorf("list_operations(node B) returned template %q; nothing was reported for that Node", op.Name)
			}
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

// staticVerifier is a controlplane.TokenVerifier accepting exactly one
// credential, as the founding admin Account — enough for the MCP surface
// tests, whose subject is the tool surface rather than the credential path
// (that is internal/controlplane's and the cmd/relay e2e's job).
type staticVerifier struct{ credential string }

func (v staticVerifier) Verify(_ context.Context, credential string) (accounts.Account, accounts.APIToken, error) {
	if credential != v.credential {
		return accounts.Account{}, accounts.APIToken{}, accounts.ErrTokenInvalid
	}
	return accounts.Account{
		Name:    accounts.FoundingAdminName,
		Kind:    accounts.KindHuman,
		Role:    accounts.RoleAdmin,
		Enabled: true,
	}, accounts.APIToken{ID: "tok-test"}, nil
}
