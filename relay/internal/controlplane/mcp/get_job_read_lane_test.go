package mcp_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

const getJobSecretOutput = "SECRET-OUTPUT"

// orderedLog is one append-only log shared by the sink and the Job source, so
// a test can assert the record landed before the store was read.
type orderedLog struct {
	mu      sync.Mutex
	entries []string
}

func (l *orderedLog) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, s)
}

func (l *orderedLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.entries...)
}

func (l *orderedLog) count(prefix string) int {
	n := 0
	for _, e := range l.snapshot() {
		if strings.HasPrefix(e, prefix) {
			n++
		}
	}
	return n
}

// orderedSink is a capability.AuditSink whose RecordRead is logged and may be
// made to fail; every other method is a no-op.
type orderedSink struct {
	log *orderedLog
	err error
}

func (s orderedSink) Record(context.Context, capability.AuditEntry) error        { return nil }
func (s orderedSink) RecordFreeze(context.Context, capability.FreezeEvent) error { return nil }
func (s orderedSink) RecordCancel(context.Context, capability.Principal, string) error {
	return nil
}
func (s orderedSink) RecordAccountAdmin(context.Context, capability.Principal, capability.AccountAdminEvent) error {
	return nil
}
func (s orderedSink) RecordRead(_ context.Context, _ capability.Principal, tool, _, _, jobID string) error {
	s.log.add("record:" + tool + ":" + jobID)
	return s.err
}

// orderedJobs is a capability.JobResultSource holding one Job whose Task
// carries output.
type orderedJobs struct{ log *orderedLog }

func (j orderedJobs) GetJob(_ context.Context, id string) (jobs.Job, error) {
	j.log.add("GetJob")
	return jobs.Job{ID: id}, nil
}

func (j orderedJobs) TasksByJob(_ context.Context, jobID string) ([]jobs.Task, error) {
	j.log.add("TasksByJob")
	return []jobs.Task{{
		JobID:  jobID,
		NodeID: "node-a",
		State:  jobs.DispatchStateResolved,
		Stdout: []byte(getJobSecretOutput),
	}}, nil
}

// emptyQueries satisfies the lane's two query seams; get_job reads neither.
type emptyQueries struct {
	capability.AuditQuery
	capability.JobQuery
}

// countingResults and countingReads stand for the adapter-held seams get_job
// no longer uses: any call to either is a fallback around the read lane.
type countingResults struct{ calls *int }

func (c countingResults) GetJob(context.Context, string) (jobs.Job, error) {
	*c.calls++
	return jobs.Job{}, errors.New("countingResults: must not be called")
}

func (c countingResults) TasksByJob(context.Context, string) ([]jobs.Task, error) {
	*c.calls++
	return nil, errors.New("countingResults: must not be called")
}

type countingReads struct{ calls *int }

func (c countingReads) RecordRead(context.Context, mcp.ReadEvent) error {
	*c.calls++
	return nil
}

// getJobServer mounts an MCP server whose get_job reads through lane (nil for
// none) and returns a connected session plus the fallback-call counters.
func getJobServer(t *testing.T, lane mcp.ReadLane) (*sdkmcp.ClientSession, *int, *int) {
	t.Helper()
	var resultCalls, readCalls int
	handler := mcp.New(lane, opsLister{}, nil, countingResults{&resultCalls}, countingReads{&readCalls})
	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	srv := httptest.NewServer(controlplane.NewAuthenticator(staticVerifier{credential: testToken}).Middleware(mux))
	t.Cleanup(srv.Close)

	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "mcp-test-client", Version: "0.0.1"}, nil)
	transport := &sdkmcp.StreamableClientTransport{
		Endpoint:   srv.URL + "/mcp",
		HTTPClient: &http.Client{Transport: relaytest.BearerRoundTripper{Base: http.DefaultTransport, Token: testToken}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session, &resultCalls, &readCalls
}

func getJobLane(log *orderedLog, sinkErr error) mcp.ReadLane {
	rec := capability.NewRecorder(orderedSink{log: log, err: sinkErr}, nil, nil)
	lane := capability.NewReadLane(rec, registry.NewInMemory(), emptyQueries{}, emptyQueries{}, nil, nil,
		&capability.StaticOperatorSettings{}, nil,
		capability.WithJobResultSource(orderedJobs{log: log}))
	return testReadLane{svc: lane}
}

func resultContains(res *sdkmcp.CallToolResult, needle string) bool {
	for _, c := range res.Content {
		if tc, ok := c.(*sdkmcp.TextContent); ok && strings.Contains(tc.Text, needle) {
			return true
		}
	}
	return false
}

// A server built with no read lane has no sink to record into, so get_job is
// refused and never falls back to its own Job reader or auditor.
func TestMCP_GetJob_AMissingSinkRefusesTheRead(t *testing.T) {
	session, resultCalls, readCalls := getJobServer(t, nil)

	res := callTool(t, session, "get_job", map[string]any{"job_id": "job-1"})
	if !res.IsError {
		t.Fatalf("IsError = false, want true; content = %+v", res.Content)
	}
	if resultContains(res, getJobSecretOutput) {
		t.Errorf("a refused read carried Task output")
	}
	if *resultCalls != 0 || *readCalls != 0 {
		t.Errorf("fallback seams used: results=%d reads=%d, want 0 and 0", *resultCalls, *readCalls)
	}
}

func TestMCP_GetJob_AFailingRecordRefusesTheRead(t *testing.T) {
	log := &orderedLog{}
	session, resultCalls, readCalls := getJobServer(t, getJobLane(log, errors.New("disk full")))

	res := callTool(t, session, "get_job", map[string]any{"job_id": "job-1"})
	if !res.IsError {
		t.Fatalf("IsError = false, want true; content = %+v", res.Content)
	}
	if resultContains(res, getJobSecretOutput) {
		t.Errorf("a refused read carried Task output")
	}
	if got := log.snapshot(); len(got) != 1 || got[0] != "record:get_job:job-1" {
		t.Errorf("log = %v, want only the attempted record (the store is never consulted)", got)
	}
	if *resultCalls != 0 || *readCalls != 0 {
		t.Errorf("fallback seams used: results=%d reads=%d, want 0 and 0", *resultCalls, *readCalls)
	}
}

func TestMCP_GetJob_RecordsOnceBeforeTheResult(t *testing.T) {
	log := &orderedLog{}
	session, resultCalls, readCalls := getJobServer(t, getJobLane(log, nil))

	res := callTool(t, session, "get_job", map[string]any{"job_id": "job-1"})
	if res.IsError {
		t.Fatalf("IsError = true; content = %+v", res.Content)
	}
	if !resultContains(res, getJobSecretOutput) {
		t.Errorf("result does not carry the Task's stdout: %+v", res.Content)
	}
	want := []string{"record:get_job:job-1", "GetJob", "TasksByJob"}
	got := log.snapshot()
	if len(got) != len(want) {
		t.Fatalf("log = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("log = %v, want %v", got, want)
		}
	}
	if n := log.count("record:"); n != 1 {
		t.Errorf("RecordRead calls = %d, want exactly 1", n)
	}
	if *resultCalls != 0 || *readCalls != 0 {
		t.Errorf("fallback seams used: results=%d reads=%d, want 0 and 0", *resultCalls, *readCalls)
	}
}
