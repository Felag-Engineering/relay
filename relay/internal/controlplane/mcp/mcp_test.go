package mcp_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/auditquery"
	"github.com/Felag-Engineering/relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/nodevocab"
	"github.com/Felag-Engineering/relay/relay/internal/opvocab"
	"github.com/Felag-Engineering/relay/relay/internal/policyalias"
	"github.com/Felag-Engineering/relay/relay/internal/policyview"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

const testToken = accounts.TokenPrefix + "abcdef0123456789.mcp-integration-test" // test fixture, not a real credential

// opsLister adapts opvocab.Operations (a package-level func) to
// mcp.OperationLister, exactly like relay/cmd/relay/main.go's opvocabLister.
type opsLister struct{}

func (opsLister) Operations() []opvocab.Descriptor { return opvocab.Operations() }

// testReadLane adapts a *capability.ReadLane to mcp.ReadLane, mirroring
// cmd/relay/main.go's composition-root adapter (mcpReadLane,
// control_surfaces.go, #680): mcp.ReadLane is deliberately Principal-free,
// so the Principal is resolved from ctx here, on this side of the seam,
// exactly like the production adapter — and the real audit sink underneath
// ts.store means every read this fixture makes is genuinely recorded.
type testReadLane struct {
	svc *capability.ReadLane
}

var errNoPrincipalInContext = errors.New("mcp_test: no authenticated principal in context")

func (l testReadLane) principal(ctx context.Context) (capability.Principal, error) {
	p, ok := controlplane.PrincipalFromContext(ctx)
	if !ok {
		return capability.Principal{}, errNoPrincipalInContext
	}
	return p, nil
}

func (l testReadLane) ListNodes(ctx context.Context, selector string) (mcp.NodeListing, error) {
	p, err := l.principal(ctx)
	if err != nil {
		return mcp.NodeListing{}, err
	}
	listing, err := l.svc.ListNodes(ctx, p, selector)
	if err != nil {
		return mcp.NodeListing{}, err
	}
	return mcp.NodeListing{Nodes: listing.Nodes, Eval: listing.Eval}, nil
}

func (l testReadLane) DescribeNode(ctx context.Context, nodeID string) (mcp.NodeDescription, error) {
	p, err := l.principal(ctx)
	if err != nil {
		return mcp.NodeDescription{}, err
	}
	detail, err := l.svc.DescribeNode(ctx, p, nodeID)
	if err != nil {
		return mcp.NodeDescription{}, err
	}
	return mcp.NodeDescription{
		Node:              detail.Node,
		Eval:              detail.Eval,
		Policy:            detail.Policy,
		PolicyReported:    detail.PolicyReported,
		Templates:         detail.Templates,
		TemplatesReported: detail.TemplatesReported,
	}, nil
}

func (l testReadLane) ListOperations(ctx context.Context, nodeID string) (mcp.NodeVocabulary, error) {
	p, err := l.principal(ctx)
	if err != nil {
		return mcp.NodeVocabulary{}, err
	}
	vocab, err := l.svc.ListOperations(ctx, p, nodeID)
	if err != nil {
		return mcp.NodeVocabulary{}, err
	}
	return mcp.NodeVocabulary{Templates: vocab.Templates, Reported: vocab.Reported}, nil
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
// and (#118) a REAL capability.Execution — store, conduit,
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
	// reg is the same registry the capability lane reads, exposed so a test
	// can seed further Nodes after the fixture is built — the fleet-ordering
	// test needs an insertion order that differs from Node-ID order.
	reg *registry.InMemory
	// aliases is the counted Policy alias source the capability layer was
	// built over, with an alias seeded for node A's fingerprint.
	aliases *countingAliases
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

// drainOnCleanup waits for the Execution's background Jobs (Start, #895) when the
// test ends. Registered right after capability.NewExecution, so (cleanups run
// last-in-first-out) it runs after the test's own cleanups and the server's
// Shutdown and before the store closes: a Job still fanning out never writes
// to a closed store.
func drainOnCleanup(t *testing.T, svc *capability.Execution) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := svc.Drain(ctx); err != nil {
			t.Errorf("background Jobs did not drain before the store closed: %v", err)
		}
	})
}

// newTestServerWithConfig is newTestServerWithBlastCap, additionally
// parameterized on the registry's min_daemon_version gate (ADR-0014); ""
// leaves the gate off, exactly like newTestServerWithBlastCap.
func newTestServerWithConfig(t *testing.T, readCap, mutateCap int, minDaemonVersion string) testServer {
	t.Helper()
	return newTestServerWithAccount(t, "", readCap, mutateCap, minDaemonVersion)
}

// newTestServerWithAccount is newTestServerWithConfig for a credential that
// authenticates as the Account with the given ID. The default ID is "": an
// Account with no ID can use no idempotency key (#895).
func newTestServerWithAccount(t *testing.T, accountID string, readCap, mutateCap int, minDaemonVersion string) testServer {
	t.Helper()
	return newTestServerWithConcurrency(t, accountID, readCap, mutateCap, minDaemonVersion, 0)
}

// newTestServerWithConcurrency is newTestServerWithAccount with the Job
// engine's dispatch concurrency pinned; 0 keeps the engine's default.
func newTestServerWithConcurrency(t *testing.T, accountID string, readCap, mutateCap int, minDaemonVersion string, concurrency int) testServer {
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
		PolicyFingerprint: nodeAFingerprint,
		DaemonVersion:     "1.1.0",
	}.WithNodeLabels(map[string]string{"role": "web"})); err != nil {
		t.Fatalf("seed node A: %v", err)
	}
	if err := reg.SetRelayLabels(nodeA, map[string]string{"quarantine": "on"}); err != nil {
		t.Fatalf("set node A relay labels: %v", err)
	}
	if _, err := reg.Upsert(registry.Report{
		NodeID:            nodeB,
		Facts:             registry.Facts{Hostname: "db-1", OS: "linux"},
		PolicyFingerprint: "sha256:node-b-fingerprint",
		DaemonVersion:     "1.3.0",
	}.WithNodeLabels(map[string]string{"env": "prod"})); err != nil {
		t.Fatalf("seed node B: %v", err)
	}
	// Node B carries a tag. Tags are written only by a human Account through
	// the Control API, so the fixture seeds one the way no MCP session can.
	if err := reg.ApplyTagChanges([]registry.TagChange{
		{NodeID: nodeB, Key: "team", After: registry.TagValue{Set: true, Value: "payments"}},
	}); err != nil {
		t.Fatalf("seed node B tag: %v", err)
	}

	policyCache := policyview.New()
	policyCache.Set(nodeA, policyview.Snapshot{
		RawExecEnabled:    true,
		RawAllowPatterns:  []string{`^/usr/bin/systemctl restart .+$`},
		RawDenyPatterns:   []string{`.*rm -rf.*`},
		AllowedOperations: []string{"system.facts", "file.read"},
		PolicyFingerprint: nodeAFingerprint,
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
	t.Cleanup(func() { st.Close() })

	// Node A's fingerprint carries an alias, and the alias source is counted:
	// QRY-36 says no tool of this surface reads or renders one.
	if err := st.Audit().(audit.PolicyAliasAppender).AppendWithPolicyAlias(context.Background(),
		audit.Record{ID: "alias-seed", Timestamp: time.Now().UTC(), Kind: audit.KindPolicyAlias, Principal: "seed"},
		policyalias.Change{Fingerprint: nodeAFingerprint, To: aliasSeedName}); err != nil {
		t.Fatalf("seed Policy alias: %v", err)
	}
	aliases := &countingAliases{inner: st.PolicyAliases()}

	conduit := newFakeConduit()
	q := auditquery.New(st.AuditQueries(), st.JobQueries())
	capSvc := newCapService(t, capSeams{
		reg:         reg,
		authz:       testAuthorizer{},
		settings:    blastCaps(readCap, mutateCap),
		audit:       auditsink.New(st.Audit()),
		freeze:      st.Freeze(),
		auditQ:      q,
		jobQ:        q,
		policyView:  policyCache,
		nodeVocab:   vocabCache,
		aliases:     aliases,
		idem:        st.IdempotencyKeys(),
		jobsRepo:    st.Jobs(),
		tasksRepo:   st.Tasks(),
		conduit:     conduit,
		newID:       deterministicIDs(),
		concurrency: concurrency,
	})
	drainOnCleanup(t, capSvc.Execution)
	results := testJobResultReader{jobsRepo: st.Jobs(), tasksRepo: st.Tasks()}

	handler := mcp.New(testReadLane{svc: capSvc.ReadLane}, opsLister{}, capSvc.Execution, results, nil, nil)

	cert := relaytest.SelfSignedServerCert(t, "mcp-test")
	controlSrv := controlplane.New(
		controlplane.Config{
			Addr: "127.0.0.1:0",
			// Production hands this *ca.ServerCertificate's method, which
			// re-issues the leaf before it expires (#403); a fixed
			// certificate is all this test needs.
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
		},
		controlplane.NewAuthenticator(staticVerifier{credential: testToken, accountID: accountID}),
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
		reg:     reg,
		aliases: aliases,
	}
}

// aliasSeedName is the Policy alias the fixture gives node A's fingerprint.
const aliasSeedName = "zz-seeded-policy-alias"

// nodeAFingerprint is a well-formed Policy fingerprint (64 lowercase hex), the
// only shape the store attaches an alias to.
const nodeAFingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// countingAliases counts how often the alias source is read.
type countingAliases struct {
	inner policyalias.Reader
	lists atomic.Int32
}

func (c *countingAliases) List(ctx context.Context) (map[string]string, error) {
	c.lists.Add(1)
	return c.inner.List(ctx)
}

// failingReadSink wraps a real *auditsink.Sink but refuses every RecordRead
// call — the fixture for proving the read lane's fail-closed contract
// (ADR-0025, #680): an unauditable read must not silently happen. Every
// other AuditSink method is inherited unchanged.
type failingReadSink struct {
	*auditsink.Sink
}

func (failingReadSink) RecordRead(context.Context, capability.Principal, string, string, string, string) error {
	return errors.New("mcp_test: audit trail unavailable")
}

// newTestServerWithFailingReadSink mirrors newTestServer, seeding one Node,
// but wires failingReadSink in place of the real one — used to prove every
// read tool fails closed, and records nothing, when its access record
// cannot be written.
func newTestServerWithFailingReadSink(t *testing.T) testServer {
	t.Helper()

	const nodeA = "node-a"

	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{
		NodeID: nodeA,
		Facts:  registry.Facts{Hostname: "web-1", OS: "linux"},
	}); err != nil {
		t.Fatalf("seed node A: %v", err)
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	conduit := newFakeConduit()
	q := auditquery.New(st.AuditQueries(), st.JobQueries())
	capSvc := newCapService(t, capSeams{
		reg:       reg,
		authz:     testAuthorizer{},
		audit:     failingReadSink{Sink: auditsink.New(st.Audit())},
		freeze:    st.Freeze(),
		auditQ:    q,
		jobQ:      q,
		jobsRepo:  st.Jobs(),
		tasksRepo: st.Tasks(),
		conduit:   conduit,
		newID:     deterministicIDs(),
	})
	drainOnCleanup(t, capSvc.Execution)
	results := testJobResultReader{jobsRepo: st.Jobs(), tasksRepo: st.Tasks()}
	handler := mcp.New(testReadLane{svc: capSvc.ReadLane}, opsLister{}, capSvc.Execution, results, nil, nil)

	cert := relaytest.SelfSignedServerCert(t, "mcp-test")
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

	return testServer{
		base:    "https://" + lis.Addr().String(),
		plain:   &http.Client{Transport: transport},
		authed:  &http.Client{Transport: relaytest.BearerRoundTripper{Base: transport, Token: testToken}},
		nodeA:   nodeA,
		store:   st,
		conduit: conduit,
		reg:     reg,
	}
}

// auditReadRecords returns every KindRead Record on ts's trail — the
// capability read lane's own access log, queried directly rather than
// through the lane itself, so these tests prove what actually landed on
// the trail rather than re-asking the thing under test.
func auditReadRecords(t *testing.T, ts testServer) []audit.Record {
	t.Helper()
	all, err := ts.store.Audit().List(context.Background())
	if err != nil {
		t.Fatalf("Audit().List: %v", err)
	}
	var reads []audit.Record
	for _, r := range all {
		if r.Kind == audit.KindRead {
			reads = append(reads, r)
		}
	}
	return reads
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

// TestMCP_ListNodes_TagSelectorResolves is QRY-41's tag half on MCP: a tag:
// term resolves against tag-space alone. node B carries the tag team=payments
// and the node: label env=prod, node A carries neither.
func TestMCP_ListNodes_TagSelectorResolves(t *testing.T) {
	ts := newTestServer(t)
	session := ts.connect(t)

	ids := func(selector string) []string {
		t.Helper()
		res := callTool(t, session, "list_nodes", map[string]any{"selector": selector})
		if res.IsError {
			t.Fatalf("list_nodes(%q): %s", selector, toolErrorText(t, res))
		}
		var out mcp.ListNodesOutput
		decodeResult(t, res, &out)
		var got []string
		for _, n := range out.Nodes {
			got = append(got, n.NodeID)
		}
		return got
	}

	if got := ids("tag:team=payments"); len(got) != 1 || got[0] != ts.nodeB {
		t.Errorf("list_nodes(tag:team=payments) = %v, want only %s", got, ts.nodeB)
	}
	// env=prod is a node: label on node B; tag: never reads node-space.
	if got := ids("tag:env=prod"); len(got) != 0 {
		t.Errorf("list_nodes(tag:env=prod) = %v, want none: node B carries env=prod as a node: label, not a tag", got)
	}
	if got := ids("node:env=prod, tag:team=payments"); len(got) != 1 || got[0] != ts.nodeB {
		t.Errorf("list_nodes(node:env=prod, tag:team=payments) = %v, want only %s", got, ts.nodeB)
	}
}

// TestMCP_ListNodes_RefusesMalformedBareAndUnknownStateTerms is QRY-42: a
// malformed term, a bare key and an unknown state: key are refused, never
// answered with an empty list. A tag: term with no value is one of the
// malformed terms, not a tag refusal, and a refused Selector writes no read
// record.
func TestMCP_ListNodes_RefusesMalformedBareAndUnknownStateTerms(t *testing.T) {
	for name, selector := range map[string]string{
		"malformed node term":     "node:role",
		"malformed tag term":      "tag:team",
		"bare key":                "role=web",
		"unknown state: key":      "state:bogus",
		"empty tag key":           "tag:=payments",
		"unknown namespace":       "team:x=y",
		"good term and a bad one": "tag:team=payments, node:role",
	} {
		t.Run(name, func(t *testing.T) {
			ts := newTestServer(t)
			session := ts.connect(t)

			before := len(auditReadRecords(t, ts))
			res := callTool(t, session, "list_nodes", map[string]any{"selector": selector})
			if !res.IsError {
				var out mcp.ListNodesOutput
				decodeResult(t, res, &out)
				t.Fatalf("list_nodes(%q) succeeded with %d Nodes, want a refusal", selector, len(out.Nodes))
			}
			// The lane's own error would double the internal package prefix;
			// list_nodes maps it back to the wrap run_operation and raw_exec use.
			if msg := toolErrorText(t, res); !strings.HasPrefix(msg, "invalid selector: capability:") {
				t.Errorf("refusal text = %q, want prefix %q", msg, "invalid selector: capability:")
			}
			if after := len(auditReadRecords(t, ts)); after != before {
				t.Errorf("a refused Selector added %d read records; the trail is not caller storage", after-before)
			}
		})
	}
}

// TestMCP_NodeReads_ReturnTagsAsTheirOwnMap is QRY-40 on MCP: list_nodes and
// describe_node return a Node's tags as tag_labels, a map of their own that is
// never merged into node_labels or relay_labels, and an empty object when the
// Node has none.
func TestMCP_NodeReads_ReturnTagsAsTheirOwnMap(t *testing.T) {
	ts := newTestServer(t)
	session := ts.connect(t)

	check := func(where string, n mcp.NodeItem) {
		t.Helper()
		switch n.NodeID {
		case ts.nodeB:
			if n.TagLabels["team"] != "payments" || len(n.TagLabels) != 1 {
				t.Errorf("%s: node B tag_labels = %v, want {team: payments}", where, n.TagLabels)
			}
			if _, ok := n.NodeLabels["team"]; ok {
				t.Errorf("%s: a tag leaked into node_labels: %v", where, n.NodeLabels)
			}
			if _, ok := n.RelayLabels["team"]; ok {
				t.Errorf("%s: a tag leaked into relay_labels: %v", where, n.RelayLabels)
			}
		case ts.nodeA:
			if n.TagLabels == nil || len(n.TagLabels) != 0 {
				t.Errorf("%s: node A tag_labels = %#v, want an empty object, not null", where, n.TagLabels)
			}
		}
	}

	var list mcp.ListNodesOutput
	decodeResult(t, callTool(t, session, "list_nodes", nil), &list)
	for _, n := range list.Nodes {
		check("list_nodes", n)
	}
	if len(list.Nodes) != 2 {
		t.Fatalf("list_nodes returned %d Nodes, want 2", len(list.Nodes))
	}

	for _, id := range []string{ts.nodeA, ts.nodeB} {
		var d mcp.DescribeNodeOutput
		decodeResult(t, callTool(t, session, "describe_node", map[string]any{"node_id": id}), &d)
		check("describe_node", d.NodeItem)
	}

	// The wire shape: null never appears for a Node with no tags.
	raw := resultText(t, callTool(t, session, "list_nodes", map[string]any{"selector": "node:role=web"}))
	if strings.Contains(raw, `"tag_labels":null`) || !strings.Contains(raw, `"tag_labels":{}`) {
		t.Errorf("a Node with no tags did not render tag_labels as {}: %s", raw)
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

// TestMCP_ListNodes_ReturnsMatchesInNodeIdOrder is QRY-41's ordering half at
// the surface the claim names: list_nodes returns the matches in Node-ID
// order, and this adapter does not re-order what the capability read lane
// handed it. The lane's own half is capability's
// TestListNodes_ReturnsMatchesInNodeIdOrder.
//
// The extra Nodes are seeded out of ID order and interleaved around the
// fixture's node-a/node-b, so insertion order and ID order genuinely differ —
// with only node-a and node-b the two coincide and the assertion would be
// vacuous.
//
// Residual: proves the MCP surface does not re-order what the lane returned,
// for the EMPTY Selector only. A filtered resolution's order is asserted
// neither here nor at the lane. The order originates in the registry's List
// and is preserved by Selector.Resolve; neither is pinned by this test.
func TestMCP_ListNodes_ReturnsMatchesInNodeIdOrder(t *testing.T) {
	ts := newTestServer(t)

	insertion := []string{ts.nodeA, ts.nodeB}
	for _, id := range []string{"node-z", "node-0", "node-m"} {
		if _, err := ts.reg.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
		insertion = append(insertion, id)
	}

	session := ts.connect(t)
	res := callTool(t, session, "list_nodes", nil)
	var out mcp.ListNodesOutput
	decodeResult(t, res, &out)

	got := make([]string, 0, len(out.Nodes))
	for _, n := range out.Nodes {
		got = append(got, n.NodeID)
	}
	want := append([]string(nil), insertion...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("list_nodes order = %v, want Node-ID order %v", got, want)
	}
	// Non-vacuity: the seeded order is not the sorted order, so a surface
	// that simply echoed insertion order would have failed above.
	if reflect.DeepEqual(insertion, want) {
		t.Fatalf("the fixture's insertion order %v already IS Node-ID order — this test cannot fail", insertion)
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

	// Neither Node in this fixture is ever connected (newTestServerWithConfig
	// never calls SetConnected), so state:offline matches both — and does so
	// through the same resolver list_nodes itself uses, not a second one.
	t.Run("state: filter matches every offline Node", func(t *testing.T) {
		res := callTool(t, session, "list_nodes", map[string]any{"selector": "state:offline"})
		var out mcp.ListNodesOutput
		decodeResult(t, res, &out)
		if len(out.Nodes) != 2 {
			t.Fatalf("list_nodes(state:offline) = %+v, want both Nodes", out.Nodes)
		}
	})

	t.Run("state: key outside the closed vocabulary is a tool error, not an empty list", func(t *testing.T) {
		res := callTool(t, session, "list_nodes", map[string]any{"selector": "state:bogus"})
		if !res.IsError {
			t.Fatalf("list_nodes(state:bogus): IsError = false, want true (closed vocabulary, fail-closed)")
		}
	})

	// A Selector matching no Node resolves through capability.Selector.Resolve,
	// which returns a NIL slice — the response must still render an empty
	// JSON array, never null (#207/#253), so this is the regression guard for
	// the nil-slice trap the lane's return value introduces.
	t.Run("a Selector matching nothing renders an empty array, never null", func(t *testing.T) {
		res := callTool(t, session, "list_nodes", map[string]any{"selector": "node:role=no-such-role"})
		var out mcp.ListNodesOutput
		decodeResult(t, res, &out)
		if out.Nodes == nil {
			t.Error("ListNodesOutput.Nodes decoded as nil, want a non-nil empty slice")
		}
		if len(out.Nodes) != 0 {
			t.Errorf("list_nodes(node:role=no-such-role) = %+v, want none", out.Nodes)
		}
		text := resultText(t, res)
		if !strings.Contains(text, `"nodes":[]`) {
			t.Errorf("list_nodes JSON = %s, want it to contain %q", text, `"nodes":[]`)
		}
		if strings.Contains(text, `"nodes":null`) {
			t.Errorf("list_nodes JSON = %s, must never contain %q", text, `"nodes":null`)
		}
	})
}

// TestMCP_ListNodes_StateLabels covers acceptance 8: state_labels renders on
// every Node, prefixed and never null.
func TestMCP_ListNodes_StateLabels(t *testing.T) {
	ts := newTestServer(t)
	session := ts.connect(t)

	res := callTool(t, session, "list_nodes", nil)
	var out mcp.ListNodesOutput
	decodeResult(t, res, &out)

	if len(out.Nodes) == 0 {
		t.Fatal("list_nodes(): no Nodes returned")
	}
	for _, n := range out.Nodes {
		if n.StateLabels == nil {
			t.Errorf("node %q: StateLabels is null, want a (possibly empty) array", n.NodeID)
		}
		found := false
		for _, l := range n.StateLabels {
			if l == "state:offline" {
				found = true
			}
			if !strings.HasPrefix(l, "state:") {
				t.Errorf("node %q: state label %q is not state:-prefixed", n.NodeID, l)
			}
		}
		if !found {
			t.Errorf("node %q: StateLabels = %v, want state:offline (never connected in this fixture)", n.NodeID, n.StateLabels)
		}
	}
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

// TestMCP_DescribeNode_BoundsTheNodeIdBeforeRecordingIt is QRY-27's MCP-seam
// proof: the capability read lane bounds a Node ID BEFORE it records
// (readlane_registry.go's validateNodeID, ahead of recordQueryRead), so once
// describe_node goes through the lane a missing or oversized id is refused
// with nothing on the trail. Deliberately distinct from the lane's own
// TestDescribeNode_BoundsTheNodeIdBeforeRecordingIt (QRY-22's proof row,
// capability seam): that test proves the lane's ordering, and this one
// proves the MCP surface actually goes through the lane rather than
// recording first itself.
func TestMCP_DescribeNode_BoundsTheNodeIdBeforeRecordingIt(t *testing.T) {
	ts := newTestServer(t)
	session := ts.connect(t)

	cases := []struct {
		name   string
		nodeID string
	}{
		{"empty node_id", ""},
		{"oversized node_id", strings.Repeat("a", 257)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(auditReadRecords(t, ts))
			res := callTool(t, session, "describe_node", map[string]any{"node_id": tc.nodeID})
			if !res.IsError {
				t.Fatalf("describe_node(%q): IsError = false, want true", tc.nodeID)
			}
			after := len(auditReadRecords(t, ts))
			if after != before {
				t.Errorf("describe_node(%q) left %d new read record(s) on the trail, want 0 (QRY-27: the lane bounds a Node ID before it records)", tc.nodeID, after-before)
			}
			// LOW 5 (security review, cycle 2): the lane's ErrInvalidFilter
			// carries an internal "capability: invalid query filter: …"
			// prefix that must never reach a model-facing tool error.
			msg := toolErrorText(t, res)
			if strings.Contains(msg, "capability:") {
				t.Errorf("describe_node(%q) refusal text = %q, leaks the internal capability: package prefix", tc.nodeID, msg)
			}
			const want = "invalid node_id: must be 1-256 bytes"
			if msg != want {
				t.Errorf("describe_node(%q) refusal text = %q, want %q", tc.nodeID, msg, want)
			}
		})
	}
}

// TestMCP_ListOperations_BoundsTheNodeIdBeforeRecordingIt mirrors
// TestMCP_DescribeNode_BoundsTheNodeIdBeforeRecordingIt for list_operations:
// an oversized node_id is refused by the lane's before-any-record bound
// (validateNodeID), so the refusal must carry neither a trail record nor the
// lane's internal "capability:" package prefix (security review, cycle 2,
// LOW 5).
func TestMCP_ListOperations_BoundsTheNodeIdBeforeRecordingIt(t *testing.T) {
	ts := newTestServer(t)
	session := ts.connect(t)

	oversized := strings.Repeat("a", 257)
	before := len(auditReadRecords(t, ts))
	res := callTool(t, session, "list_operations", map[string]any{"node_id": oversized})
	if !res.IsError {
		t.Fatalf("list_operations(%q): IsError = false, want true", oversized)
	}
	after := len(auditReadRecords(t, ts))
	if after != before {
		t.Errorf("list_operations(%q) left %d new read record(s) on the trail, want 0", oversized, after-before)
	}
	msg := toolErrorText(t, res)
	if strings.Contains(msg, "capability:") {
		t.Errorf("list_operations(%q) refusal text = %q, leaks the internal capability: package prefix", oversized, msg)
	}
	const want = "invalid node_id: must be 1-256 bytes"
	if msg != want {
		t.Errorf("list_operations(%q) refusal text = %q, want %q", oversized, msg, want)
	}
}

// TestMCP_ListOperations_UnknownNodeIsRefusedNotAnEmptyVocabulary is QRY-26's
// MCP-seam proof: a well-formed but unknown node_id is refused as "no such
// Node" — not answered with a successful, empty (templates_reported=false)
// result — and the refused probe is recorded with the id it asked about.
func TestMCP_ListOperations_UnknownNodeIsRefusedNotAnEmptyVocabulary(t *testing.T) {
	ts := newTestServer(t)
	session := ts.connect(t)

	const unknown = "no-such-node"
	res := callTool(t, session, "list_operations", map[string]any{"node_id": unknown})
	if !res.IsError {
		var out mcp.ListOperationsOutput
		decodeResult(t, res, &out)
		t.Fatalf("list_operations(%q): IsError = false, want true (got templates_reported=%v, a successful-but-empty result)",
			unknown, out.TemplatesReported)
	}
	msg := toolErrorText(t, res)
	if !strings.Contains(msg, unknown) || !strings.Contains(msg, "not found") {
		t.Errorf("refusal text = %q, want it to name the unknown Node as not found", msg)
	}

	found := false
	for _, r := range auditReadRecords(t, ts) {
		if r.OperationName == "list_operations" && r.NodeID == unknown {
			found = true
		}
	}
	if !found {
		t.Error("no list_operations read record aimed at the probed unknown Node — QRY-26 requires the refused read to be recorded with the probed id")
	}
}

// TestMCP_ReadToolsRecordThroughTheRealLane is QRY-28's MCP-seam proof: every
// read tool records exactly one entry per call — including a fleet-wide
// list_operations, whose record carries the tool and no target — and every
// one of them fails closed (and returns nothing) when the trail cannot be
// written.
func TestMCP_ReadToolsRecordThroughTheRealLane(t *testing.T) {
	ts := newTestServer(t)
	session := ts.connect(t)

	callTool(t, session, "list_nodes", nil)
	callTool(t, session, "describe_node", map[string]any{"node_id": ts.nodeA})
	callTool(t, session, "list_operations", map[string]any{"node_id": ts.nodeA})
	callTool(t, session, "list_operations", nil)

	counts := map[[2]string]int{}
	for _, r := range auditReadRecords(t, ts) {
		counts[[2]string{r.OperationName, r.NodeID}]++
	}
	wantCounts := map[[2]string]int{
		{"list_nodes", ""}:            1,
		{"describe_node", ts.nodeA}:   1,
		{"list_operations", ts.nodeA}: 1,
		{"list_operations", ""}:       1,
	}
	for k, want := range wantCounts {
		if counts[k] != want {
			t.Errorf("read records for tool=%q node=%q = %d, want %d", k[0], k[1], counts[k], want)
		}
	}

	tsFail := newTestServerWithFailingReadSink(t)
	sessionFail := tsFail.connect(t)
	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"list_nodes", nil},
		{"describe_node", map[string]any{"node_id": tsFail.nodeA}},
		{"list_operations", map[string]any{"node_id": tsFail.nodeA}},
		{"list_operations", nil},
	} {
		t.Run(tc.tool+" fails closed when the trail cannot be written", func(t *testing.T) {
			res := callTool(t, sessionFail, tc.tool, tc.args)
			if !res.IsError {
				t.Fatalf("%s: IsError = false, want true (the audit sink refuses every RecordRead)", tc.tool)
			}
		})
	}
}

// TestMCP_ListNodes_SelectorIsResolvedByTheLane is QRY-28's Selector-routing
// proof: the lane records the CANONICAL Selector form, not the caller's raw
// bytes, and a refused Selector (validated before it is recorded) leaves
// nothing on the trail. TestMCP_ListNodes_RefusesMalformedBareAndUnknownStateTerms
// proves the refusal text itself; this test proves what the lane does to the
// trail around that same call.
func TestMCP_ListNodes_SelectorIsResolvedByTheLane(t *testing.T) {
	ts := newTestServer(t)
	session := ts.connect(t)

	callTool(t, session, "list_nodes", map[string]any{"selector": "  node:role=web  "})
	found := false
	for _, r := range auditReadRecords(t, ts) {
		if r.OperationName != "list_nodes" {
			continue
		}
		found = true
		if r.Selector != "node:role=web" {
			t.Errorf("recorded Selector = %q, want the canonical form %q", r.Selector, "node:role=web")
		}
	}
	if !found {
		t.Fatal("no list_nodes read record found")
	}

	before := len(auditReadRecords(t, ts))
	res := callTool(t, session, "list_nodes", map[string]any{"selector": "node:role"})
	if !res.IsError {
		t.Fatal("list_nodes(node:role): IsError = false, want true")
	}
	after := len(auditReadRecords(t, ts))
	if after != before {
		t.Errorf("a refused Selector left %d new read record(s), want 0 (the lane validates before it records)", after-before)
	}
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
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no credential: status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	respWrong := post(ts.plain, "wrong-"+testToken)
	defer respWrong.Body.Close()
	if respWrong.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong credential: status = %d, want %d", respWrong.StatusCode, http.StatusUnauthorized)
	}

	respOK := post(ts.plain, testToken)
	defer respOK.Body.Close()
	if respOK.StatusCode != http.StatusOK {
		t.Errorf("valid credential: status = %d, want %d", respOK.StatusCode, http.StatusOK)
	}
}

// testAdminName names the first admin staticVerifier authenticates as. No
// name is reserved, so it is an ordinary name.
const testAdminName = "first-admin"

// testAdminAttribution is the audit attribution of staticVerifier's Account.
var testAdminAttribution = testAdminName + ":" + string(accounts.RoleAdmin)

// staticVerifier is a controlplane.TokenVerifier accepting exactly one
// credential, as the founding admin Account — enough for the MCP surface
// tests, whose subject is the tool surface rather than the credential path
// (that is internal/controlplane's and the cmd/relay e2e's job).
type staticVerifier struct {
	credential string
	// accountID, when set, is the authenticated Account's ID. Empty by default:
	// most tests need no verified AccountID (#895's keys do).
	accountID string
}

func (v staticVerifier) Verify(_ context.Context, credential string) (accounts.Account, accounts.APIToken, error) {
	if credential != v.credential {
		return accounts.Account{}, accounts.APIToken{}, accounts.ErrTokenInvalid
	}
	return accounts.Account{
		ID:      v.accountID,
		Name:    testAdminName,
		Kind:    accounts.KindHuman,
		Role:    accounts.RoleAdmin,
		Enabled: true,
	}, accounts.APIToken{ID: "tok-test"}, nil
}
