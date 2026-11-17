package mcp_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/auditquery"
	"github.com/Felag-Engineering/relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

// failingDispatchRecordSink wraps a real *auditsink.Sink but refuses the
// KindDispatch record, as a trail that took the dispatch's intent but cannot take
// its outcome would. Every other AuditSink method is inherited unchanged.
type failingDispatchRecordSink struct {
	*auditsink.Sink
}

func (s failingDispatchRecordSink) Record(ctx context.Context, e capability.AuditEntry) error {
	if e.Kind == capability.AuditKindDispatch {
		return errors.New("mcp_test: audit trail unavailable")
	}
	return s.Sink.Record(ctx, e)
}

// newTestServerWithFailingDispatchRecord mirrors newTestServerWithFailingReadSink
// over one connected Node, with failingDispatchRecordSink in the real layer.
func newTestServerWithFailingDispatchRecord(t *testing.T) testServer {
	t.Helper()

	const nodeA = "node-a"

	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{
		NodeID: nodeA,
		Facts:  registry.Facts{Hostname: "web-1", OS: "linux"},
	}.WithNodeLabels(map[string]string{"os": "linux"})); err != nil {
		t.Fatalf("seed node A: %v", err)
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	conduit := newFakeConduit()
	conduit.connect(nodeA)
	conduit.results[nodeA] = jobs.Result{Outcome: jobs.OutcomeSuccess, Stdout: []byte(`{"hostname":"web-1"}`)}
	q := auditquery.New(st.AuditQueries(), st.JobQueries())
	capSvc := newCapService(t, capSeams{
		reg:       reg,
		authz:     testAuthorizer{},
		audit:     failingDispatchRecordSink{Sink: auditsink.New(st.Audit())},
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
	handler := mcp.New(testReadLane{svc: capSvc.ReadLane}, opsLister{}, capSvc.Execution, results, nil)

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

// Proves EX-66.
func TestMCP_GetJobShowsAFailedOutcomeWrite(t *testing.T) {
	ts := newTestServerWithFailingDispatchRecord(t)
	session := ts.connect(t)

	res := callTool(t, session, "run_operation", map[string]any{"selector": capability.WholeFleetSelector, "operation": "system.facts", "wait_seconds": 300})
	var run mcp.RunOrPlanOutput
	decodeResult(t, res, &run)
	if run.JobID == "" {
		t.Fatalf("run_operation: job_id is empty: %+v", run)
	}
	if run.OutcomeAuditFailure == nil || run.OutcomeAuditFailure.Reason != jobs.OutcomeAuditFailureReason {
		t.Fatalf("run_operation outcome_audit_failure = %+v, want the fixed reason", run.OutcomeAuditFailure)
	}

	got := callTool(t, session, "get_job", map[string]any{"job_id": run.JobID})
	var job mcp.ExecutionOutput
	decodeResult(t, got, &job)
	if job.OutcomeAuditFailure == nil {
		t.Fatalf("get_job outcome_audit_failure is absent: %+v", job)
	}
	if *job.OutcomeAuditFailure != *run.OutcomeAuditFailure {
		t.Errorf("get_job outcome_audit_failure = %+v, want the run's %+v", *job.OutcomeAuditFailure, *run.OutcomeAuditFailure)
	}
	if job.OutcomeAuditFailure.At == "" || job.OutcomeAuditFailure.Reason != jobs.OutcomeAuditFailureReason {
		t.Errorf("get_job outcome_audit_failure = %+v, want a time and the fixed reason", *job.OutcomeAuditFailure)
	}
}
