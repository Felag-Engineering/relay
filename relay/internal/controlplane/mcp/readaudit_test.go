package mcp

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// structFields returns v's field names.
func structFields(v any) []string {
	t := reflect.TypeOf(v)
	out := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		out = append(out, t.Field(i).Name)
	}
	return out
}

// recordingAuditor captures what the read surface reports.
type recordingAuditor struct {
	events []ReadEvent
	err    error
}

func (a *recordingAuditor) RecordRead(_ context.Context, e ReadEvent) error {
	a.events = append(a.events, e)
	return a.err
}

func TestAuditRead_RecordsToolAndTarget(t *testing.T) {
	a := &recordingAuditor{}
	if err := auditRead(context.Background(), a, "get_job", ReadEvent{JobID: "job-42"}); err != nil {
		t.Fatalf("auditRead: %v", err)
	}
	if len(a.events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(a.events))
	}
	if a.events[0].Tool != "get_job" || a.events[0].JobID != "job-42" {
		t.Errorf("event = %+v, want the tool name and its target", a.events[0])
	}
}

// Fail closed: an unauditable read must not silently happen. That is the
// entire point of auditing reads — a read surface that keeps answering when
// its trail is broken is the state #288 set out to fix.
func TestAuditRead_FailsTheCallWhenTheTrailCannotBeWritten(t *testing.T) {
	a := &recordingAuditor{err: errors.New("disk full")}
	err := auditRead(context.Background(), a, "get_job", ReadEvent{JobID: "job-42"})
	if err == nil {
		t.Fatal("auditRead returned nil on an audit-write failure; the read must fail instead")
	}
	if !errors.Is(err, a.err) {
		t.Errorf("err = %v, want it to wrap the underlying write failure", err)
	}
	if got := err.Error(); !strings.Contains(got, "get_job") {
		t.Errorf("err = %q, does not name the tool that could not be recorded", got)
	}
}

// A nil auditor is the pre-#288 behaviour, kept so an unwired surface degrades
// to "debug log only" rather than failing shut on a missing dependency.
func TestAuditRead_NilAuditorIsANoop(t *testing.T) {
	if err := auditRead(context.Background(), nil, "get_job", ReadEvent{}); err != nil {
		t.Errorf("auditRead with a nil auditor: %v, want nil", err)
	}
}

// The event type must carry no result field. This is the structural half of
// "metadata only, never content" — a field added later would be caught here
// rather than discovered in a trail that has been copying command output.
func TestReadEvent_CarriesNoResultField(t *testing.T) {
	allowed := map[string]bool{"Tool": true, "JobID": true}
	for _, f := range structFields(ReadEvent{}) {
		if !allowed[f] {
			t.Errorf("ReadEvent has an unexpected field %q — a read record must carry what was read, never what came back", f)
		}
	}
}
