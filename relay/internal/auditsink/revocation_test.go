package auditsink

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

// batchRepo counts the writes the sink makes and fails AppendAll on demand.
type batchRepo struct {
	audit.Repository
	appendCalls    int
	appendAllCalls [][]audit.Record
	appendAllErr   error
}

func (r *batchRepo) Append(context.Context, audit.Record) error {
	r.appendCalls++
	return nil
}

func (r *batchRepo) AppendAll(_ context.Context, rs []audit.Record) error {
	r.appendAllCalls = append(r.appendAllCalls, rs)
	return r.appendAllErr
}

var revokePrincipal = capability.Principal{
	AccountID: "acct-7", Account: "olive", Role: "admin", Kind: capability.PrincipalKindHuman,
	AuthMethod: capability.AuthMethodConsoleSession, Source: "10.0.0.9",
}

func TestRecordNodeRevokes_OneAttributedRecordPerNodeInOneAppendAll(t *testing.T) {
	at := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	repo := &batchRepo{}
	sink := New(repo, WithNewID(sequentialIDs("audit-")), WithClock(func() time.Time { return at }))
	asserted := capability.Assertions{OnBehalfOf: "carol", ChangeRef: "CHG-1"}
	ids := []string{"node-1", "node-2"}

	err := sink.RecordNodeRevokes(context.Background(), capability.NodeRevokeEvent{
		Principal: revokePrincipal, Asserted: asserted, NodeIDs: ids, Reason: "stolen",
	})
	if err != nil {
		t.Fatalf("RecordNodeRevokes: %v", err)
	}
	if repo.appendCalls != 0 || len(repo.appendAllCalls) != 1 {
		t.Fatalf("Append calls = %d, AppendAll calls = %d, want 0 and 1", repo.appendCalls, len(repo.appendAllCalls))
	}
	recs := repo.appendAllCalls[0]
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2", len(recs))
	}
	seen := map[string]bool{}
	for i, r := range recs {
		if r.Kind != audit.KindNodeRevoke || r.NodeID != ids[i] || r.Reason != "stolen" ||
			r.Principal != revokePrincipal.Attribution() || !r.Timestamp.Equal(at) {
			t.Errorf("record %d = kind %q node %q reason %q principal %q at %v", i, r.Kind, r.NodeID, r.Reason, r.Principal, r.Timestamp)
		}
		if v := r.Attribution.Verified; v.AccountID != "acct-7" || v.Role != "admin" || v.Source != "10.0.0.9" {
			t.Errorf("record %d verified lane = %+v", i, v)
		}
		if a := r.Attribution.Asserted; a.OnBehalfOf != "carol" || a.ChangeRef != "CHG-1" {
			t.Errorf("record %d asserted lane = %+v", i, a)
		}
		if r.ID == "" || seen[r.ID] {
			t.Errorf("record %d id %q is empty or repeated", i, r.ID)
		}
		seen[r.ID] = true
	}
}

func TestRecordNodeRevokes_AnIDFailureWritesNothing(t *testing.T) {
	repo := &batchRepo{}
	calls := 0
	sink := New(repo, WithNewID(func() (string, error) {
		calls++
		if calls == 2 {
			return "", errors.New("test: no entropy")
		}
		return "audit-1", nil
	}))

	err := sink.RecordNodeRevokes(context.Background(), capability.NodeRevokeEvent{
		Principal: revokePrincipal, NodeIDs: []string{"node-1", "node-2"}, Reason: "stolen",
	})
	if err == nil {
		t.Fatal("want the id failure")
	}
	if len(repo.appendAllCalls) != 0 || repo.appendCalls != 0 {
		t.Errorf("writes = %d + %d, want none: a chunk is all or nothing", len(repo.appendAllCalls), repo.appendCalls)
	}
}

func TestRecordNodeRevokes_AnAppendAllFailureIsReturned(t *testing.T) {
	repo := &batchRepo{appendAllErr: errors.New("test: disk full")}
	sink := New(repo, WithNewID(sequentialIDs("audit-")))

	err := sink.RecordNodeRevokes(context.Background(), capability.NodeRevokeEvent{
		Principal: revokePrincipal, NodeIDs: []string{"node-1"}, Reason: "stolen",
	})
	if !errors.Is(err, repo.appendAllErr) {
		t.Fatalf("error = %v, want the repository's", err)
	}
}

func TestRecordEnrollmentTokenRevoke_ReasonNamesTheTokenAndAnIncompleteCascade(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")))
	for _, incomplete := range []bool{false, true} {
		err := sink.RecordEnrollmentTokenRevoke(context.Background(), capability.EnrollmentTokenRevokeEvent{
			Principal: revokePrincipal, TokenID: "tok-1", CascadeIncomplete: incomplete,
		})
		if err != nil {
			t.Fatalf("RecordEnrollmentTokenRevoke: %v", err)
		}
	}
	all, err := repo.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("records = %d, want 2", len(all))
	}
	want := map[string]bool{"token_id=tok-1": false, "token_id=tok-1 cascade=incomplete": false}
	for _, r := range all {
		if r.Kind != audit.KindTokenRevoke || r.Principal != revokePrincipal.Attribution() {
			t.Errorf("record = kind %q principal %q", r.Kind, r.Principal)
		}
		if _, ok := want[r.Reason]; !ok {
			t.Errorf("unexpected reason %q", r.Reason)
		}
		want[r.Reason] = true
	}
	for reason, seen := range want {
		if !seen {
			t.Errorf("no record with reason %q", reason)
		}
	}
}
