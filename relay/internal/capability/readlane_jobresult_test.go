package capability

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// jobResultLog is one ordered log shared by a sink and a Job source.
type jobResultLog struct {
	mu      sync.Mutex
	entries []string
}

func (l *jobResultLog) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, s)
}

func (l *jobResultLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.entries...)
}

// loggingReadSink logs each read record before it delegates to the spy.
type loggingReadSink struct {
	*spyAuditSink
	log *jobResultLog
}

func (s *loggingReadSink) RecordRead(ctx context.Context, p Principal, tool, selector, nodeID, jobID string) error {
	s.log.add("record")
	return s.spyAuditSink.RecordRead(ctx, p, tool, selector, nodeID, jobID)
}

// spyJobResults is a JobResultSource holding one Job whose read-class Task has
// output.
type spyJobResults struct {
	log    *jobResultLog
	getErr error
}

func (s spyJobResults) GetJob(_ context.Context, id string) (jobs.Job, error) {
	s.log.add("GetJob")
	if s.getErr != nil {
		return jobs.Job{}, s.getErr
	}
	return jobs.Job{ID: id}, nil
}

func (s spyJobResults) TasksByJob(_ context.Context, jobID string) ([]jobs.Task, error) {
	s.log.add("TasksByJob")
	return []jobs.Task{{JobID: jobID, NodeID: "node-1", Stdout: []byte("hello")}}, nil
}

func jobResultLane(t *testing.T, sink AuditSink, src JobResultSource) *ReadLane {
	t.Helper()
	return build(t, seams{reg: registry.NewInMemory(), audit: sink, jobResults: src}).ReadLane
}

func TestGetJob_RecordsTheReadBeforeTheStoreIsRead(t *testing.T) {
	log := &jobResultLog{}
	spy := &spyAuditSink{}
	lane := jobResultLane(t, &loggingReadSink{spyAuditSink: spy, log: log}, spyJobResults{log: log})

	res, err := lane.GetJob(context.Background(), testPrincipal, "job-1")
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if got, want := strings.Join(log.all(), ","), "record,GetJob,TasksByJob"; got != want {
		t.Errorf("event order = %s, want %s", got, want)
	}
	want := readCall{Principal: testPrincipal, Tool: "get_job", JobID: "job-1"}
	if len(spy.readCalls) != 1 || spy.readCalls[0] != want {
		t.Errorf("read calls = %+v, want exactly [%+v]", spy.readCalls, want)
	}
	if len(res.Tasks) != 1 || string(res.Tasks[0].Stdout) != "hello" {
		t.Errorf("Tasks = %+v, want the read-class Task's stdout kept", res.Tasks)
	}
}

func TestGetJob_AFailedRecordRefusesTheReadBeforeTheStore(t *testing.T) {
	log := &jobResultLog{}
	spy := &spyAuditSink{err: errors.New("audit store down")}
	lane := jobResultLane(t, &loggingReadSink{spyAuditSink: spy, log: log}, spyJobResults{log: log})

	_, err := lane.GetJob(context.Background(), testPrincipal, "job-1")
	if !errors.Is(err, ErrReadUnaudited) {
		t.Fatalf("err = %v, want ErrReadUnaudited", err)
	}
	if got := strings.Join(log.all(), ","); got != "record" {
		t.Errorf("event order = %q, want only the attempted record", got)
	}
}

func TestGetJob_RefusesOnTheNoopSink(t *testing.T) {
	log := &jobResultLog{}
	lane := jobResultLane(t, nil, spyJobResults{log: log})

	_, err := lane.GetJob(context.Background(), testPrincipal, "job-1")
	if !errors.Is(err, ErrReadUnaudited) {
		t.Fatalf("err = %v, want ErrReadUnaudited on a lane with no audit sink", err)
	}
	if got := log.all(); len(got) != 0 {
		t.Errorf("the store was consulted on an unaudited lane: %v", got)
	}
}

func TestGetJob_WithNoJobStoreIsUnavailable(t *testing.T) {
	spy := &spyAuditSink{}
	lane := jobResultLane(t, spy, nil)

	_, err := lane.GetJob(context.Background(), testPrincipal, "job-1")
	if !errors.Is(err, ErrQueriesUnavailable) {
		t.Fatalf("err = %v, want ErrQueriesUnavailable", err)
	}
	if len(spy.readCalls) != 0 {
		t.Errorf("%d read records with no Job store, want 0", len(spy.readCalls))
	}
}

func TestGetJob_RecordsAProbeForAMissingJob(t *testing.T) {
	log := &jobResultLog{}
	spy := &spyAuditSink{}
	lane := jobResultLane(t, spy, spyJobResults{log: log, getErr: jobs.ErrJobNotFound})

	_, err := lane.GetJob(context.Background(), testPrincipal, "job-x")
	if !errors.Is(err, jobs.ErrJobNotFound) {
		t.Fatalf("err = %v, want jobs.ErrJobNotFound", err)
	}
	if len(spy.readCalls) != 1 || spy.readCalls[0].JobID != "job-x" {
		t.Errorf("read calls = %+v, want one for job-x", spy.readCalls)
	}
}

func TestGetJob_BoundsTheJobIdBeforeRecordingIt(t *testing.T) {
	log := &jobResultLog{}
	spy := &spyAuditSink{}
	lane := jobResultLane(t, spy, spyJobResults{log: log})

	_, err := lane.GetJob(context.Background(), testPrincipal, strings.Repeat("a", maxJobIDBytes+1))
	if !errors.Is(err, jobs.ErrJobNotFound) {
		t.Fatalf("err = %v, want jobs.ErrJobNotFound", err)
	}
	if len(spy.readCalls) != 0 {
		t.Errorf("%d read records for an oversized id, want 0", len(spy.readCalls))
	}
	if got := log.all(); len(got) != 0 {
		t.Errorf("the store was consulted for an oversized id: %v", got)
	}
}
