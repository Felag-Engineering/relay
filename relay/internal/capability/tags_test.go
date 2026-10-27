package capability

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

var tagOperator = Principal{AccountID: "acct-7", Account: "olive", Role: "operator", Kind: PrincipalKindHuman, AuthMethod: AuthMethodConsoleSession}

// fakeTagSink is an AuditSink that is also a TagWriteRecorder. A recorded
// batch is applied to reg, as the real store's transaction applies it, and
// store sentinels map onto the capability layer's as auditsink maps them.
type fakeTagSink struct {
	*spyAuditSink
	reg       *registry.InMemory
	events    []TagWriteEvent
	recordErr error
}

func (f *fakeTagSink) RecordTagWrite(_ context.Context, e TagWriteEvent) error {
	if f.recordErr != nil {
		return f.recordErr
	}
	switch err := f.reg.ApplyTagChanges(e.Changes); {
	case err == nil:
	case errors.Is(err, registry.ErrTagChanged):
		return ErrTagChanged
	case errors.Is(err, registry.ErrTooManyTags):
		return ErrTooManyTags
	case errors.Is(err, registry.ErrNotFound):
		return ErrTagNodeNotFound
	default:
		return err
	}
	f.events = append(f.events, e)
	return nil
}

type tagFixture struct {
	w     *TagWriter
	reg   *registry.InMemory
	sink  *fakeTagSink
	authz *spyAuthorizer
}

// newTagFixture seeds the named Nodes and builds a TagWriter over a Control
// whose authorizer is a spy.
func newTagFixture(t *testing.T, nodeIDs ...string) *tagFixture {
	t.Helper()
	reg := registry.NewInMemory()
	for _, id := range nodeIDs {
		if _, err := reg.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("Upsert(%s): %v", id, err)
		}
	}
	sink := &fakeTagSink{spyAuditSink: &spyAuditSink{}, reg: reg}
	authz := &spyAuthorizer{}
	control := newControl(NewRecorder(sink, nil, nil), authz, noopFreezeStore{})
	return &tagFixture{w: NewTagWriter(control, reg), reg: reg, sink: sink, authz: authz}
}

func (f *tagFixture) tags(t *testing.T, nodeID string) map[string]string {
	t.Helper()
	n, ok := f.reg.Get(nodeID)
	if !ok {
		t.Fatalf("Node %s missing", nodeID)
	}
	return n.TagLabels
}

func TestTagWriter_HumanOperatorAddsReplacesAndRemoves(t *testing.T) {
	f := newTagFixture(t, "n1")
	ctx := context.Background()

	steps := []struct {
		req  TagWrite
		want map[string]string
	}{
		{TagWrite{NodeIDs: []string{"n1"}, Op: TagAdd, Label: "tag:team=payments"}, map[string]string{"team": "payments"}},
		{TagWrite{NodeIDs: []string{"n1"}, Op: TagAdd, Label: "tag:team=billing"}, map[string]string{"team": "billing"}},
		{TagWrite{NodeIDs: []string{"n1"}, Op: TagAdd, Label: "tag:empty="}, map[string]string{"team": "billing", "empty": ""}},
		{TagWrite{NodeIDs: []string{"n1"}, Op: TagRemove, Label: "tag:team"}, map[string]string{"empty": ""}},
	}
	for _, s := range steps {
		res, err := f.w.WriteTag(ctx, tagOperator, s.req)
		if err != nil {
			t.Fatalf("WriteTag(%+v): %v", s.req, err)
		}
		if len(res.Changed) != 1 {
			t.Fatalf("WriteTag(%+v) changed %d Nodes, want 1", s.req, len(res.Changed))
		}
		if got := f.tags(t, "n1"); !reflect.DeepEqual(got, s.want) {
			t.Fatalf("after %+v tags = %v, want %v", s.req, got, s.want)
		}
	}
}

// TestTagWriter_RecordsTheAccountTheNodeAndOldAndNewValues is ADR-0050
// decision 2's audit clause: each change carries the Account, the Node and the
// old and new values, and absent stays distinct from an empty value.
func TestTagWriter_RecordsTheAccountTheNodeAndOldAndNewValues(t *testing.T) {
	f := newTagFixture(t, "n1")
	ctx := WithAssertions(context.Background(), Assertions{OnBehalfOf: "bob"})

	for _, label := range []string{"tag:team=payments", "tag:team=billing"} {
		if _, err := f.w.WriteTag(ctx, tagOperator, TagWrite{NodeIDs: []string{"n1"}, Op: TagAdd, Label: label}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.w.WriteTag(ctx, tagOperator, TagWrite{NodeIDs: []string{"n1"}, Op: TagRemove, Label: "tag:team"}); err != nil {
		t.Fatal(err)
	}

	set := func(v string) registry.TagValue { return registry.TagValue{Set: true, Value: v} }
	want := []registry.TagChange{
		{NodeID: "n1", Key: "team", After: set("payments")},
		{NodeID: "n1", Key: "team", Before: set("payments"), After: set("billing")},
		{NodeID: "n1", Key: "team", Before: set("billing")},
	}
	if len(f.sink.events) != len(want) {
		t.Fatalf("events = %d, want %d", len(f.sink.events), len(want))
	}
	for i, e := range f.sink.events {
		if e.Principal != tagOperator {
			t.Errorf("event %d principal = %+v, want %+v", i, e.Principal, tagOperator)
		}
		if e.Asserted.OnBehalfOf != "bob" {
			t.Errorf("event %d asserted lane = %+v", i, e.Asserted)
		}
		if len(e.Changes) != 1 || e.Changes[0] != want[i] {
			t.Errorf("event %d changes = %+v, want %+v", i, e.Changes, want[i])
		}
	}
}

// TestTagWriter_TakesNoStepUp: the tag write asks the authorizer for the tag
// floor only, and its signature has no step-up evidence to consult.
func TestTagWriter_TakesNoStepUp(t *testing.T) {
	f := newTagFixture(t, "n1")
	if _, err := f.w.WriteTag(context.Background(), tagOperator, TagWrite{NodeIDs: []string{"n1"}, Op: TagAdd, Label: "tag:a=b"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.authz.controlCalls, []ControlAction{ControlTagWrite}) {
		t.Errorf("authorizer asked %v, want only ControlTagWrite", f.authz.controlCalls)
	}

	m, ok := reflect.TypeOf(&TagWriter{}).MethodByName("WriteTag")
	if !ok {
		t.Fatal("WriteTag missing")
	}
	var got []reflect.Type
	for i := 1; i < m.Type.NumIn(); i++ { // 0 is the receiver
		got = append(got, m.Type.In(i))
	}
	want := []reflect.Type{reflect.TypeOf((*context.Context)(nil)).Elem(), reflect.TypeOf(Principal{}), reflect.TypeOf(TagWrite{})}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("WriteTag takes %v, want %v: no step-up parameter", got, want)
	}
}

func TestTagWriter_NoChangeRecordsNothing(t *testing.T) {
	f := newTagFixture(t, "n1", "n2")
	ctx := context.Background()
	if _, err := f.w.WriteTag(ctx, tagOperator, TagWrite{NodeIDs: []string{"n1"}, Op: TagAdd, Label: "tag:team=a"}); err != nil {
		t.Fatal(err)
	}
	before := len(f.sink.events)

	res, err := f.w.WriteTag(ctx, tagOperator, TagWrite{NodeIDs: []string{"n1"}, Op: TagAdd, Label: "tag:team=a"})
	if err != nil || len(res.Changed) != 0 || !reflect.DeepEqual(res.Unchanged, []string{"n1"}) {
		t.Fatalf("re-adding = %+v, %v; want unchanged [n1]", res, err)
	}
	res, err = f.w.WriteTag(ctx, tagOperator, TagWrite{NodeIDs: []string{"n2"}, Op: TagRemove, Label: "tag:team"})
	if err != nil || len(res.Changed) != 0 || !reflect.DeepEqual(res.Unchanged, []string{"n2"}) {
		t.Fatalf("removing an absent tag = %+v, %v; want unchanged [n2]", res, err)
	}
	if len(f.sink.events) != before || len(f.sink.entries) != 0 {
		t.Errorf("a no-op recorded %d events and %d entries", len(f.sink.events)-before, len(f.sink.entries))
	}
}

func TestTagWriter_BulkIsOneEventOverEveryChangedNode(t *testing.T) {
	f := newTagFixture(t, "n1", "n2", "n3")
	ctx := context.Background()
	if _, err := f.w.WriteTag(ctx, tagOperator, TagWrite{NodeIDs: []string{"n2"}, Op: TagAdd, Label: "tag:team=a"}); err != nil {
		t.Fatal(err)
	}
	f.sink.events = nil

	// n3 appears twice and n2 already holds the tag.
	res, err := f.w.WriteTag(ctx, tagOperator, TagWrite{NodeIDs: []string{"n3", "n2", "n1", "n3"}, Op: TagAdd, Label: "tag:team=a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.sink.events) != 1 {
		t.Fatalf("recorded %d events, want one for the whole list", len(f.sink.events))
	}
	var changed []string
	for _, c := range f.sink.events[0].Changes {
		changed = append(changed, c.NodeID)
	}
	if !reflect.DeepEqual(changed, []string{"n3", "n1"}) {
		t.Errorf("changed = %v, want [n3 n1] in first-seen order, duplicates once", changed)
	}
	if !reflect.DeepEqual(res.Unchanged, []string{"n2"}) {
		t.Errorf("unchanged = %v, want [n2]", res.Unchanged)
	}
}

func TestTagWriter_UnknownNodeRefusesTheWholeWrite(t *testing.T) {
	f := newTagFixture(t, "n1")
	_, err := f.w.WriteTag(context.Background(), tagOperator, TagWrite{NodeIDs: []string{"n1", "ghost"}, Op: TagAdd, Label: "tag:a=b"})
	if !errors.Is(err, ErrTagNodeNotFound) {
		t.Fatalf("err = %v, want ErrTagNodeNotFound", err)
	}
	var missing *TagNodesNotFoundError
	if !errors.As(err, &missing) || !reflect.DeepEqual(missing.NodeIDs, []string{"ghost"}) {
		t.Errorf("TagNodesNotFoundError = %+v, want ghost named", missing)
	}
	if len(f.tags(t, "n1")) != 0 || len(f.sink.events) != 0 {
		t.Error("a write naming an unknown Node changed or recorded something")
	}
	if len(f.sink.entries) != 1 || strings.Contains(f.sink.entries[0].Reason, "ghost") {
		t.Errorf("entries = %+v, want one refusal that does not echo the id", f.sink.entries)
	}
}

func TestTagWriter_ANodeThatVanishesMidWriteIsAGeneric404(t *testing.T) {
	f := newTagFixture(t, "n1")
	f.sink.recordErr = ErrTagNodeNotFound
	_, err := f.w.WriteTag(context.Background(), tagOperator, TagWrite{NodeIDs: []string{"n1"}, Op: TagAdd, Label: "tag:a=b"})
	var missing *TagNodesNotFoundError
	if !errors.As(err, &missing) || len(missing.NodeIDs) != 0 || !errors.Is(err, ErrTagNodeNotFound) {
		t.Fatalf("err = %v, want a TagNodesNotFoundError naming no id", err)
	}
}

func TestTagWriter_RefusesTheSixtyFifthTag(t *testing.T) {
	f := newTagFixture(t, "n1", "n2")
	ctx := context.Background()
	for i := 0; i < registry.MaxTagsPerNode; i++ {
		if _, err := f.w.WriteTag(ctx, tagOperator, TagWrite{NodeIDs: []string{"n1"}, Op: TagAdd, Label: fmt.Sprintf("tag:k%d=v", i)}); err != nil {
			t.Fatalf("tag %d: %v", i, err)
		}
	}
	f.sink.events, f.sink.entries = nil, nil

	_, err := f.w.WriteTag(ctx, tagOperator, TagWrite{NodeIDs: []string{"n1"}, Op: TagAdd, Label: "tag:one-too-many=v"})
	if !errors.Is(err, ErrTooManyTags) {
		t.Fatalf("err = %v, want ErrTooManyTags", err)
	}
	if len(f.sink.entries) != 1 || len(f.sink.events) != 0 {
		t.Errorf("entries = %d, events = %d; want one refusal and no write", len(f.sink.entries), len(f.sink.events))
	}

	// Replacing an existing key, and a Node with room in the same list, are not
	// held to the cap; the full Node still refuses the whole list.
	if _, err := f.w.WriteTag(ctx, tagOperator, TagWrite{NodeIDs: []string{"n1"}, Op: TagAdd, Label: "tag:k0=other"}); err != nil {
		t.Errorf("replacing a value on a full Node: %v", err)
	}
	if _, err := f.w.WriteTag(ctx, tagOperator, TagWrite{NodeIDs: []string{"n2", "n1"}, Op: TagAdd, Label: "tag:fresh=v"}); !errors.Is(err, ErrTooManyTags) {
		t.Errorf("a list including a full Node = %v, want ErrTooManyTags", err)
	}
	if len(f.tags(t, "n2")) != 0 {
		t.Error("the Node with room was written although the list was refused")
	}
}

func TestTagWriter_StoreConflictIsUnauditedAndRetryable(t *testing.T) {
	f := newTagFixture(t, "n1")
	f.sink.recordErr = ErrTagChanged
	_, err := f.w.WriteTag(context.Background(), tagOperator, TagWrite{NodeIDs: []string{"n1"}, Op: TagAdd, Label: "tag:a=b"})
	if !errors.Is(err, ErrTagChanged) {
		t.Fatalf("err = %v, want ErrTagChanged", err)
	}
	if len(f.sink.entries) != 0 {
		t.Errorf("a store conflict recorded %d refusals", len(f.sink.entries))
	}
}

func TestTagWriter_RefusalsAreAudited(t *testing.T) {
	t.Run("a role or human-only refusal", func(t *testing.T) {
		f := newTagFixture(t, "n1")
		denied := errors.New("denied by the gate")
		f.authz.controlErr = denied
		_, err := f.w.WriteTag(context.Background(), tagOperator, TagWrite{NodeIDs: []string{"n1"}, Op: TagAdd, Label: "tag:a=b"})
		if !errors.Is(err, denied) {
			t.Fatalf("err = %v, want the gate's refusal", err)
		}
		if len(f.sink.entries) != 1 || f.sink.entries[0].Kind != AuditKindRefusal || len(f.sink.events) != 0 {
			t.Errorf("entries = %+v events = %d, want one refusal and no write", f.sink.entries, len(f.sink.events))
		}
	})
	t.Run("authorization runs before the label is parsed", func(t *testing.T) {
		f := newTagFixture(t, "n1")
		f.authz.controlErr = errors.New("denied")
		_, err := f.w.WriteTag(context.Background(), tagOperator, TagWrite{NodeIDs: []string{"n1"}, Op: TagAdd, Label: "node:role=web"})
		if errors.Is(err, ErrTagNamespaceRequired) {
			t.Error("a refused caller learned the label rules")
		}
	})
	t.Run("malformed requests", func(t *testing.T) {
		cases := map[string]struct {
			req  TagWrite
			want error
		}{
			"no nodes":     {TagWrite{Op: TagAdd, Label: "tag:a=b"}, ErrTagNoNodes},
			"empty id":     {TagWrite{NodeIDs: []string{""}, Op: TagAdd, Label: "tag:a=b"}, ErrTagNodeIDInvalid},
			"bad label":    {TagWrite{NodeIDs: []string{"n1"}, Op: TagAdd, Label: "tag:a b=c"}, ErrTagMalformed},
			"unknown op":   {TagWrite{NodeIDs: []string{"n1"}, Op: "toggle", Label: "tag:a=b"}, ErrTagOpUnknown},
			"add no value": {TagWrite{NodeIDs: []string{"n1"}, Op: TagAdd, Label: "tag:a"}, ErrTagAddNeedsAValue},
		}
		for name, c := range cases {
			t.Run(name, func(t *testing.T) {
				f := newTagFixture(t, "n1")
				_, err := f.w.WriteTag(context.Background(), tagOperator, c.req)
				if !errors.Is(err, c.want) {
					t.Fatalf("err = %v, want %v", err, c.want)
				}
				if len(f.sink.entries) != 1 || f.sink.entries[0].Kind != AuditKindRefusal || len(f.sink.events) != 0 {
					t.Errorf("entries = %+v, want exactly one refusal and no write", f.sink.entries)
				}
			})
		}
	})
}

// TestTagWriter_CapsNodesPerWrite pins MaxTagWriteNodes: a write naming 256
// Nodes is applied, and one naming 257 is refused, audited, and changes nothing.
func TestTagWriter_CapsNodesPerWrite(t *testing.T) {
	ids := make([]string, MaxTagWriteNodes+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("n%03d", i)
	}
	if MaxTagWriteNodes != 256 {
		t.Fatalf("MaxTagWriteNodes = %d, want 256", MaxTagWriteNodes)
	}

	t.Run("256 accepted", func(t *testing.T) {
		f := newTagFixture(t, ids...)
		res, err := f.w.WriteTag(context.Background(), tagOperator, TagWrite{NodeIDs: ids[:MaxTagWriteNodes], Op: TagAdd, Label: "tag:a=b"})
		if err != nil {
			t.Fatalf("WriteTag(256) = %v, want success", err)
		}
		if len(res.Changed) != MaxTagWriteNodes {
			t.Errorf("changed %d Nodes, want %d", len(res.Changed), MaxTagWriteNodes)
		}
	})
	t.Run("257 refused", func(t *testing.T) {
		f := newTagFixture(t, ids...)
		_, err := f.w.WriteTag(context.Background(), tagOperator, TagWrite{NodeIDs: ids, Op: TagAdd, Label: "tag:a=b"})
		if !errors.Is(err, ErrTagTooManyNodes) {
			t.Fatalf("WriteTag(257) = %v, want ErrTagTooManyNodes", err)
		}
		if len(f.sink.entries) != 1 || f.sink.entries[0].Kind != AuditKindRefusal || len(f.sink.events) != 0 {
			t.Errorf("entries = %+v events = %d, want one refusal and no write", f.sink.entries, len(f.sink.events))
		}
		if got := f.tags(t, ids[0]); len(got) != 0 {
			t.Errorf("Node %s tags = %v, want none", ids[0], got)
		}
	})
}

// TestTagWriter_RefusesEveryOtherNamespace is invariant 7's request-side half:
// no node:, relay: or state: label is written on request, for either op.
func TestTagWriter_RefusesEveryOtherNamespace(t *testing.T) {
	for _, label := range []string{"node:role=web", "relay:node-id=x", "state:offline", "role=web", "TAG:x=y", "tagx=y"} {
		for _, op := range []TagOp{TagAdd, TagRemove} {
			t.Run(string(op)+" "+label, func(t *testing.T) {
				f := newTagFixture(t, "n1")
				_, err := f.w.WriteTag(context.Background(), tagOperator, TagWrite{NodeIDs: []string{"n1"}, Op: op, Label: label})
				if !errors.Is(err, ErrTagNamespaceRequired) {
					t.Fatalf("err = %v, want ErrTagNamespaceRequired", err)
				}
				if len(f.sink.entries) != 1 || len(f.sink.events) != 0 {
					t.Errorf("entries = %d, events = %d; want one refusal and no change", len(f.sink.entries), len(f.sink.events))
				}
			})
		}
	}
}

func TestTagWriter_UnwiredIsUnavailable(t *testing.T) {
	w := newTagWriter(newControl(NewRecorder(&spyAuditSink{}, nil, nil), &spyAuthorizer{}, noopFreezeStore{}), nil, nil)
	if _, err := w.WriteTag(context.Background(), tagOperator, TagWrite{NodeIDs: []string{"n1"}, Op: TagAdd, Label: "tag:a=b"}); !errors.Is(err, ErrTagsUnavailable) {
		t.Errorf("WriteTag = %v, want ErrTagsUnavailable", err)
	}
}

// plainTagSink is an AuditSink that is not a TagWriteRecorder.
type plainTagSink struct{ *spyAuditSink }

func TestNewTagWriter_PanicsOnAnUnsafeComposition(t *testing.T) {
	reg := registry.NewInMemory()
	real := &spyAuthorizer{}
	tagSink := &fakeTagSink{spyAuditSink: &spyAuditSink{}, reg: reg}
	good := func(authz Authorizer, sink AuditSink) *Control {
		return newControl(NewRecorder(sink, nil, nil), authz, noopFreezeStore{})
	}
	cases := map[string]func(){
		"nil control":    func() { NewTagWriter(nil, reg) },
		"nil reader":     func() { NewTagWriter(good(real, tagSink), nil) },
		"allow-all":      func() { NewTagWriter(good(allowAllAuthorizer{}, tagSink), reg) },
		"no-op sink":     func() { NewTagWriter(good(real, noopAuditSink{}), reg) },
		"not a recorder": func() { NewTagWriter(good(real, plainTagSink{&spyAuditSink{}}), reg) },
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("did not panic")
				}
			}()
			f()
		})
	}
	if NewTagWriter(good(real, tagSink), reg) == nil {
		t.Error("a safe composition returned nil")
	}
}

// TestParseTagLabel is the allowlist (AC6) at the capability seam: a tag's key
// and value are held to registry.WellFormedLabel exactly, and nothing is
// sanitised.
func TestParseTagLabel(t *testing.T) {
	ok := []struct {
		op         TagOp
		in, k, val string
	}{
		{TagAdd, "tag:team=payments", "team", "payments"},
		{TagAdd, "tag:k.1_x-y=V.2", "k.1_x-y", "V.2"},
		{TagAdd, "tag:empty=", "empty", ""},
		{TagRemove, "tag:team", "team", ""},
	}
	for _, c := range ok {
		k, v, err := ParseTagLabel(c.op, c.in)
		if err != nil || k != c.k || v != c.val {
			t.Errorf("ParseTagLabel(%s, %q) = %q, %q, %v; want %q, %q", c.op, c.in, k, v, err, c.k, c.val)
		}
	}

	bad := []struct {
		op   TagOp
		in   string
		want error
	}{
		{TagAdd, "tag:a,b=c", ErrTagMalformed},
		{TagAdd, "tag:a=b,c", ErrTagMalformed},
		{TagAdd, "tag:a b=c", ErrTagMalformed},
		{TagAdd, "tag:a=b c", ErrTagMalformed},
		{TagAdd, "tag:a\t=c", ErrTagMalformed},
		{TagAdd, "tag:a:b=c", ErrTagMalformed},
		{TagAdd, "tag:a=b:c", ErrTagMalformed},
		{TagAdd, "tag:a=b=c", ErrTagMalformed},
		{TagAdd, "tag:a/b=c", ErrTagMalformed},
		{TagAdd, "tag:a@b=c", ErrTagMalformed},
		{TagAdd, "tag:a\u200b=c", ErrTagMalformed},
		{TagAdd, "tag:=v", ErrTagMalformed},
		{TagAdd, "tag:" + strings.Repeat("k", registry.MaxTagKeyLen+1) + "=v", ErrTagTooLong},
		{TagAdd, "tag:k=" + strings.Repeat("v", registry.MaxTagValueLen+1), ErrTagTooLong},
		{TagRemove, "tag:" + strings.Repeat("k", registry.MaxTagKeyLen+1), ErrTagTooLong},
		{TagAdd, "tag:", ErrTagAddNeedsAValue},
		{TagAdd, "tag:key", ErrTagAddNeedsAValue},
		{TagRemove, "tag:key=value", ErrTagRemoveNamesAKey},
		{TagRemove, "tag:", ErrTagMalformed},
		{TagRemove, "tag:a b", ErrTagMalformed},
		{TagAdd, "node:a=b", ErrTagNamespaceRequired},
		{TagAdd, "a=b", ErrTagNamespaceRequired},
		{TagAdd, "Tag:a=b", ErrTagNamespaceRequired},
		{"", "tag:a=b", ErrTagOpUnknown},
		{"toggle", "tag:a=b", ErrTagOpUnknown},
	}
	for _, c := range bad {
		if _, _, err := ParseTagLabel(c.op, c.in); !errors.Is(err, c.want) {
			t.Errorf("ParseTagLabel(%q, %q) = %v, want %v", c.op, c.in, err, c.want)
		}
	}
}

// TestTagNodesNotFoundError_MatchesTheSentinelAndNamesTheIDs: the caller-facing
// error names the ids, and still matches the sentinel the trail records.
func TestTagNodesNotFoundError_MatchesTheSentinelAndNamesTheIDs(t *testing.T) {
	e := &TagNodesNotFoundError{NodeIDs: []string{"a", "b"}}
	if !errors.Is(e, ErrTagNodeNotFound) {
		t.Error("TagNodesNotFoundError does not match ErrTagNodeNotFound")
	}
	if !strings.Contains(e.Error(), "a, b") {
		t.Errorf("Error() = %q, want the ids named", e.Error())
	}
	if (&TagNodesNotFoundError{}).Error() != ErrTagNodeNotFound.Error() {
		t.Error("an empty TagNodesNotFoundError should read as the bare sentinel")
	}
}

// TestTagWriter_WriteInitialTags_OneRecordPerTagAttributedToTheMinter checks
// that an Enrollment Token's initial tags land as one tag_write record each,
// attributed to the Account that minted the token, and are then ordinary tags.
// Tags the Node already carries at the value are skipped, and a key it carries
// at another value is replaced with the old value on the record.
//
// Proves EN-41.
func TestTagWriter_WriteInitialTags_OneRecordPerTagAttributedToTheMinter(t *testing.T) {
	f := newTagFixture(t, "n1")
	ctx := context.Background()

	if err := f.w.WriteInitialTags(ctx, tagOperator, "tok-1", "n1", []string{"tag:role=web", "tag:env=prod", "tag:team=payments"}); err != nil {
		t.Fatalf("WriteInitialTags: %v", err)
	}
	if got, want := f.tags(t, "n1"), map[string]string{"role": "web", "env": "prod", "team": "payments"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("tags = %v, want %v", got, want)
	}
	if len(f.sink.events) != 1 {
		t.Fatalf("events = %d, want one batch", len(f.sink.events))
	}
	e := f.sink.events[0]
	if e.Principal != tagOperator {
		t.Errorf("recorded as %+v, want the minting Account %+v", e.Principal, tagOperator)
	}
	var keys []string
	for _, c := range e.Changes {
		keys = append(keys, c.Key)
		if c.NodeID != "n1" || c.Before.Set || !c.After.Set {
			t.Errorf("change %+v is not a plain add on n1", c)
		}
	}
	if want := []string{"env", "role", "team"}; !reflect.DeepEqual(keys, want) {
		t.Errorf("changes in key order = %v, want %v", keys, want)
	}
	// The records name the Enrollment Token, so an enrollment-time write never
	// reads as the minter writing live; the token's secret has no way in.
	if want := "(initial tag from Enrollment Token tok-1)"; e.Provenance != want {
		t.Errorf("provenance = %q, want %q", e.Provenance, want)
	}

	// An ordinary tag write now removes one.
	if _, err := f.w.WriteTag(ctx, tagOperator, TagWrite{NodeIDs: []string{"n1"}, Op: TagRemove, Label: "tag:env"}); err != nil {
		t.Fatalf("removing an initial tag: %v", err)
	}

	// Re-writing at the stored value records nothing; another value replaces.
	before := len(f.sink.events)
	if err := f.w.WriteInitialTags(ctx, tagOperator, "tok-1", "n1", []string{"tag:role=web"}); err != nil {
		t.Fatal(err)
	}
	if len(f.sink.events) != before {
		t.Error("a tag already at its value was recorded again")
	}
	if err := f.w.WriteInitialTags(ctx, tagOperator, "tok-1", "n1", []string{"tag:role=db"}); err != nil {
		t.Fatal(err)
	}
	last := f.sink.events[len(f.sink.events)-1].Changes[0]
	if !last.Before.Set || last.Before.Value != "web" || last.After.Value != "db" {
		t.Errorf("replacing change = %+v, want web -> db", last)
	}
}

// TestTagWriter_WriteInitialTags_RefusesAMachineMinter checks that who may write
// a tag stays the Authorizer's decision: a refusal for the minter writes
// nothing and is audited as a refusal.
//
// Proves EN-44.
func TestTagWriter_WriteInitialTags_RefusesAMachineMinter(t *testing.T) {
	f := newTagFixture(t, "n1")
	denied := errors.New("only a human Account writes tags")
	f.authz.controlErr = denied

	err := f.w.WriteInitialTags(context.Background(), Principal{Account: "bot", Role: "admin"}, "tok-1", "n1", []string{"tag:env=prod"})
	if !errors.Is(err, denied) {
		t.Fatalf("err = %v, want the gate's refusal", err)
	}
	if len(f.tags(t, "n1")) != 0 || len(f.sink.events) != 0 {
		t.Error("a refused minter wrote a tag")
	}
	if len(f.sink.entries) != 1 || f.sink.entries[0].Kind != AuditKindRefusal {
		t.Errorf("entries = %+v, want exactly one refusal", f.sink.entries)
	}
	if len(f.authz.controlCalls) != 1 || f.authz.controlCalls[0] != ControlTagWrite {
		t.Errorf("authorized %v, want the tag write", f.authz.controlCalls)
	}
}

// TestTagWriter_CheckInitialTags_DecidesBeforeAnyNodeExists checks that the
// pre-enrollment check reaches the same refusals as the write, with the
// refusal audited and nothing written, and passes a minter the gate allows
// without touching a Node.
//
// Proves EN-44.
func TestTagWriter_CheckInitialTags_DecidesBeforeAnyNodeExists(t *testing.T) {
	ctx := context.Background()
	t.Run("a refused minter", func(t *testing.T) {
		f := newTagFixture(t, "n1")
		denied := errors.New("only a human Account writes tags")
		f.authz.controlErr = denied
		err := f.w.CheckInitialTags(ctx, Principal{Account: "bot", Role: "admin"}, []string{"tag:env=prod"})
		if !errors.Is(err, denied) {
			t.Fatalf("err = %v, want the gate's refusal", err)
		}
		if len(f.sink.events) != 0 || len(f.sink.entries) != 1 || f.sink.entries[0].Kind != AuditKindRefusal {
			t.Errorf("events = %d entries = %+v, want one refusal and no write", len(f.sink.events), f.sink.entries)
		}
	})
	t.Run("a relay: label", func(t *testing.T) {
		f := newTagFixture(t, "n1")
		err := f.w.CheckInitialTags(ctx, tagOperator, []string{"relay:env=prod"})
		if !errors.Is(err, registry.ErrInitialTagRelayLabel) {
			t.Fatalf("err = %v, want ErrInitialTagRelayLabel", err)
		}
	})
	t.Run("an allowed minter", func(t *testing.T) {
		f := newTagFixture(t, "n1")
		if err := f.w.CheckInitialTags(ctx, tagOperator, []string{"tag:env=prod"}); err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if len(f.sink.events) != 0 || len(f.sink.entries) != 0 || len(f.tags(t, "n1")) != 0 {
			t.Error("the check wrote or recorded something")
		}
	})
}

// TestTagWriter_WriteInitialTags_Refusals checks that tags that do not hold, an
// unknown Node and a Node that would exceed the cap each write nothing and are
// audited, and that no tags is a no-op that asks nobody.
//
// Proves EN-40.
func TestTagWriter_WriteInitialTags_Refusals(t *testing.T) {
	ctx := context.Background()
	t.Run("a relay: label", func(t *testing.T) {
		f := newTagFixture(t, "n1")
		err := f.w.WriteInitialTags(ctx, tagOperator, "tok-1", "n1", []string{"relay:env=prod"})
		if !errors.Is(err, registry.ErrInitialTagRelayLabel) {
			t.Fatalf("err = %v, want ErrInitialTagRelayLabel", err)
		}
		if len(f.tags(t, "n1")) != 0 || len(f.sink.entries) != 1 {
			t.Errorf("tags = %v entries = %d, want nothing written and one refusal", f.tags(t, "n1"), len(f.sink.entries))
		}
	})
	t.Run("an unknown Node", func(t *testing.T) {
		f := newTagFixture(t, "n1")
		if err := f.w.WriteInitialTags(ctx, tagOperator, "tok-1", "ghost", []string{"tag:a=b"}); !errors.Is(err, ErrTagNodeNotFound) {
			t.Fatalf("err = %v, want ErrTagNodeNotFound", err)
		}
	})
	t.Run("a Node that would exceed the cap", func(t *testing.T) {
		f := newTagFixture(t, "n1")
		for i := 0; i < registry.MaxTagsPerNode; i++ {
			if _, err := f.w.WriteTag(ctx, tagOperator, TagWrite{NodeIDs: []string{"n1"}, Op: TagAdd, Label: fmt.Sprintf("tag:k%d=v", i)}); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.w.WriteInitialTags(ctx, tagOperator, "tok-1", "n1", []string{"tag:one-more=v"}); !errors.Is(err, ErrTooManyTags) {
			t.Fatalf("err = %v, want ErrTooManyTags", err)
		}
		if len(f.tags(t, "n1")) != registry.MaxTagsPerNode {
			t.Error("a refused write changed the Node")
		}
	})
	t.Run("no tags", func(t *testing.T) {
		f := newTagFixture(t, "n1")
		f.authz.controlErr = errors.New("would be refused")
		if err := f.w.WriteInitialTags(ctx, tagOperator, "tok-1", "n1", nil); err != nil {
			t.Fatalf("no tags: %v", err)
		}
		if len(f.sink.entries) != 0 {
			t.Error("writing no tags recorded a refusal")
		}
	})
}

// TestParseInitialTags_AgreesWithParseTagLabel pins that the one parse of an
// Enrollment Token's initial tags (registry.ParseInitialTags) accepts exactly
// what a tag write's ParseTagLabel accepts, so a tag a mint takes is a tag the
// write path takes.
//
// Proves EN-40.
func TestParseInitialTags_AgreesWithParseTagLabel(t *testing.T) {
	for _, entry := range []string{
		"tag:env=prod", "tag:env=", "tag:a.b_c-d=e.f", "tag:env", "tag:=v", "tag:", "tag:a b=c", "tag:a=b=c",
		"env=prod", "node:env=prod", "state:x=y", "TAG:env=prod", "tag:" + strings.Repeat("k", 63) + "=v",
		"tag:" + strings.Repeat("k", 64) + "=v", "tag:k=" + strings.Repeat("v", 255), "tag:k=" + strings.Repeat("v", 256),
		"tag:k\u200b=v", "",
	} {
		_, _, writeErr := ParseTagLabel(TagAdd, entry)
		_, mintErr := registry.ParseInitialTags([]string{entry})
		if (writeErr == nil) != (mintErr == nil) {
			t.Errorf("%q: tag write says %v, initial tags say %v", entry, writeErr, mintErr)
		}
	}
}
