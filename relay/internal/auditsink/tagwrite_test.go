package auditsink

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

var tagOperatorPrincipal = capability.Principal{
	AccountID: "acct-7", Account: "olive", Role: "operator", Kind: capability.PrincipalKindHuman,
	AuthMethod: capability.AuthMethodConsoleSession, Source: "10.0.0.9",
}

// realTagWriter is the real capability layer over the real store and the given
// Sink: the composition the Control API uses.
func realTagWriter(t *testing.T, st *store.Store, sink *Sink) *capability.TagWriter {
	t.Helper()
	rec := capability.NewRecorder(sink, nil, nil)
	ctl := capability.NewControl(rec, authz.NewRoleGate(), neverFrozen{})
	return capability.NewTagWriter(ctl, st.Registry())
}

func seedTagNodes(t *testing.T, st *store.Store, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if _, err := st.Registry().Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("Upsert(%s): %v", id, err)
		}
	}
}

func tagWriteRecords(t *testing.T, repo audit.Repository) []audit.Record {
	t.Helper()
	all, err := repo.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Record
	for _, r := range all {
		if r.Kind == audit.KindTagWrite {
			out = append(out, r)
		}
	}
	return out
}

// TestRecordTagWrite_OneRecordPerNodeWithOldAndNew is ADR-0050 decision 2's
// audit clause end to end: one tag_write record per changed Node naming the
// Account, the Node and the old and new values, with an empty value distinct
// from an absent one.
func TestRecordTagWrite_OneRecordPerNodeWithOldAndNew(t *testing.T) {
	st, repo, path := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")), WithClock(func() time.Time { return time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC) }))
	w := realTagWriter(t, st, sink)
	ctx := context.Background()
	seedTagNodes(t, st, "n1", "n2")

	steps := []capability.TagWrite{
		{NodeIDs: []string{"n1", "n2"}, Op: capability.TagAdd, Label: "tag:team=payments"},
		{NodeIDs: []string{"n1"}, Op: capability.TagAdd, Label: "tag:team="},
		{NodeIDs: []string{"n1"}, Op: capability.TagRemove, Label: "tag:team"},
	}
	for _, s := range steps {
		if _, err := w.WriteTag(ctx, tagOperatorPrincipal, s); err != nil {
			t.Fatalf("WriteTag(%+v): %v", s, err)
		}
	}

	recs := tagWriteRecords(t, repo)
	want := []struct{ node, reason string }{
		{"n1", `tag:team old=(none) new="payments"`},
		{"n2", `tag:team old=(none) new="payments"`},
		{"n1", `tag:team old="payments" new=""`},
		{"n1", `tag:team old="" new=(none)`},
	}
	if len(recs) != len(want) {
		t.Fatalf("tag_write records = %d, want %d", len(recs), len(want))
	}
	for i, r := range recs {
		if r.NodeID != want[i].node || r.Reason != want[i].reason {
			t.Errorf("record %d = node %q reason %q, want node %q reason %q", i, r.NodeID, r.Reason, want[i].node, want[i].reason)
		}
		if r.Principal != tagOperatorPrincipal.Attribution() {
			t.Errorf("record %d principal = %q", i, r.Principal)
		}
		v := r.Attribution.Verified
		if v.AccountID != "acct-7" || v.Role != "operator" || v.Method != string(capability.AuthMethodConsoleSession) || v.Source != "10.0.0.9" {
			t.Errorf("record %d verified lane = %+v", i, v)
		}
	}
	verdict, err := store.VerifyAuditChain(ctx, path, nil)
	if err != nil || !verdict.Intact() {
		t.Fatalf("chain verdict = %+v, %v; want intact", verdict, err)
	}
}

// TestTagWriter_MachineAndViewerAreRefusedBeforeAnyWrite runs ADR-0050 decision
// 2's refusals through the real RoleGate and the real store: nothing is
// written, and each refusal is on the trail as a refusal, not a tag_write.
func TestTagWriter_MachineAndViewerAreRefusedBeforeAnyWrite(t *testing.T) {
	st, repo, _ := openSinkStore(t)
	w := realTagWriter(t, st, New(repo, WithNewID(sequentialIDs("audit-"))))
	seedTagNodes(t, st, "n1")

	refused := map[string]capability.Principal{
		"human viewer":   {AccountID: "a1", Account: "v", Role: "viewer", Kind: capability.PrincipalKindHuman},
		"machine viewer": {AccountID: "a2", Account: "mv", Role: "viewer", Kind: "machine"},
		"machine admin":  {AccountID: "a3", Account: "ma", Role: "admin", Kind: "machine"},
	}
	for name, p := range refused {
		_, err := w.WriteTag(context.Background(), p, capability.TagWrite{NodeIDs: []string{"n1"}, Op: capability.TagAdd, Label: "tag:team=x"})
		if !errors.Is(err, authz.ErrUnauthorized) {
			t.Errorf("%s: err = %v, want ErrUnauthorized", name, err)
		}
	}
	if n, _ := st.Registry().Get("n1"); len(n.TagLabels) != 0 {
		t.Errorf("tags = %v after only refused writes", n.TagLabels)
	}
	if got := len(tagWriteRecords(t, repo)); got != 0 {
		t.Errorf("tag_write records = %d, want none", got)
	}
}

// TestTagWriter_ChangeIsNotMadeWhenItsRecordCannotBeWritten: a record that
// cannot be written rolls the tag back.
func TestTagWriter_ChangeIsNotMadeWhenItsRecordCannotBeWritten(t *testing.T) {
	st, repo, _ := openSinkStore(t)
	ctx := context.Background()
	seedTagNodes(t, st, "n1")
	if err := repo.Append(ctx, audit.Record{ID: "dup", Timestamp: time.Now().UTC(), Kind: audit.KindRead, Principal: "x"}); err != nil {
		t.Fatal(err)
	}
	head, err := st.AuditChain().ChainHead(ctx)
	if err != nil {
		t.Fatal(err)
	}

	broken := realTagWriter(t, st, New(repo, WithNewID(func() (string, error) { return "dup", nil })))
	_, err = broken.WriteTag(ctx, tagOperatorPrincipal, capability.TagWrite{NodeIDs: []string{"n1"}, Op: capability.TagAdd, Label: "tag:team=x"})
	if err == nil {
		t.Fatal("the write succeeded though its record could not be written")
	}
	if errors.Is(err, capability.ErrTagChanged) || errors.Is(err, authz.ErrUnauthorized) {
		t.Fatalf("err = %v, want an audit-write error", err)
	}
	if n, _ := st.Registry().Get("n1"); len(n.TagLabels) != 0 {
		t.Errorf("tags = %v, want none", n.TagLabels)
	}
	if after, _ := st.AuditChain().ChainHead(ctx); after != head {
		t.Errorf("chain head moved from %+v to %+v", head, after)
	}
}

func TestRecordTagWrite_ARepositoryWithoutTheAtomicWriteRefusesAndWritesNothing(t *testing.T) {
	st, repo, _ := openSinkStore(t)
	ctx := context.Background()
	seedTagNodes(t, st, "n1")
	sink := New(plainRepo{repo}, WithNewID(sequentialIDs("audit-")))
	before, _ := repo.List(ctx)

	err := sink.RecordTagWrite(ctx, capability.TagWriteEvent{
		Principal: tagOperatorPrincipal,
		Changes:   []registry.TagChange{{NodeID: "n1", Key: "team", After: registry.TagValue{Set: true, Value: "x"}}},
	})
	if !errors.Is(err, capability.ErrTagsUnavailable) {
		t.Fatalf("err = %v, want ErrTagsUnavailable", err)
	}
	if after, _ := repo.List(ctx); len(after) != len(before) {
		t.Errorf("audit rows %d -> %d", len(before), len(after))
	}
	if n, _ := st.Registry().Get("n1"); len(n.TagLabels) != 0 {
		t.Errorf("tags = %v", n.TagLabels)
	}
}

func TestRecordTagWrite_MapsStoreConflictsToCapabilitySentinels(t *testing.T) {
	st, repo, _ := openSinkStore(t)
	ctx := context.Background()
	seedTagNodes(t, st, "n1")
	sink := New(repo, WithNewID(sequentialIDs("audit-")))
	set := func(v string) registry.TagValue { return registry.TagValue{Set: true, Value: v} }
	event := func(c ...registry.TagChange) capability.TagWriteEvent {
		return capability.TagWriteEvent{Principal: tagOperatorPrincipal, Changes: c}
	}

	if err := sink.RecordTagWrite(ctx, event(registry.TagChange{NodeID: "n1", Key: "team", After: set("a")})); err != nil {
		t.Fatal(err)
	}
	err := sink.RecordTagWrite(ctx, event(registry.TagChange{NodeID: "n1", Key: "team", Before: set("stale"), After: set("b")}))
	if !errors.Is(err, capability.ErrTagChanged) {
		t.Errorf("stale Before = %v, want ErrTagChanged", err)
	}
	err = sink.RecordTagWrite(ctx, event(registry.TagChange{NodeID: "ghost", Key: "team", After: set("a")}))
	if !errors.Is(err, capability.ErrTagNodeNotFound) {
		t.Errorf("unknown Node = %v, want ErrTagNodeNotFound", err)
	}
	var fill []registry.TagChange
	for i := 0; i < registry.MaxTagsPerNode; i++ {
		fill = append(fill, registry.TagChange{NodeID: "n1", Key: "k" + strings.Repeat("x", i), After: set("v")})
	}
	err = sink.RecordTagWrite(ctx, event(fill...))
	if !errors.Is(err, capability.ErrTooManyTags) {
		t.Errorf("65 tags = %v, want ErrTooManyTags", err)
	}
	if err := sink.RecordTagWrite(ctx, event()); err == nil {
		t.Error("an event that changes nothing was recorded")
	}
	if n := len(tagWriteRecords(t, repo)); n != 1 {
		t.Errorf("tag_write records = %d, want only the first, successful write", n)
	}
}

func TestTagWriteReason_NeverReadsAnEmptyValueAsAbsent(t *testing.T) {
	absent := tagWriteReason(registry.TagChange{Key: "k", After: registry.TagValue{Set: true, Value: ""}})
	empty := tagWriteReason(registry.TagChange{Key: "k", Before: registry.TagValue{Set: true, Value: ""}})
	if absent == empty {
		t.Errorf("reasons collide: %q", absent)
	}
	if absent != `tag:k old=(none) new=""` || empty != `tag:k old="" new=(none)` {
		t.Errorf("reasons = %q, %q", absent, empty)
	}
}
