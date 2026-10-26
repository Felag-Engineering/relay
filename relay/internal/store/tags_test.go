package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

func tagVal(v string) registry.TagValue { return registry.TagValue{Set: true, Value: v} }

func tagRecord(id, nodeID string) audit.Record {
	return audit.Record{
		ID:        id,
		Timestamp: time.Date(2026, 10, 25, 0, 0, 1, 0, time.UTC),
		Kind:      audit.KindTagWrite,
		NodeID:    nodeID,
		Principal: "olive",
		Reason:    "tag:team old=(none) new=\"x\"",
	}
}

// writeTags applies changes through the store's atomic tag write with one
// record per change, ids tag-<prefix>-<i>.
func writeTags(t *testing.T, st *Store, prefix string, changes ...registry.TagChange) error {
	t.Helper()
	app, ok := st.Audit().(audit.TagWriteAppender)
	if !ok {
		t.Fatal("the store's audit Repository is not a TagWriteAppender")
	}
	recs := make([]audit.Record, len(changes))
	for i, c := range changes {
		recs[i] = tagRecord(fmt.Sprintf("tag-%s-%d", prefix, i), c.NodeID)
	}
	return app.AppendWithTagWrite(context.Background(), recs, changes)
}

func seedNodes(t *testing.T, st *Store, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if _, err := st.Registry().Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("Upsert(%s): %v", id, err)
		}
	}
}

func tagsOf(t *testing.T, st *Store, nodeID string) map[string]string {
	t.Helper()
	n, ok := st.Registry().Get(nodeID)
	if !ok {
		t.Fatalf("Get(%s): not found", nodeID)
	}
	return n.TagLabels
}

func auditRows(t *testing.T, st *Store) int {
	t.Helper()
	recs, err := st.Audit().List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	return len(recs)
}

func TestStoreAudit_OffersTheAtomicTagWrite(t *testing.T) {
	st, _ := openTestStore(t)
	if _, ok := st.Audit().(audit.TagWriteAppender); !ok {
		t.Fatal("st.Audit() does not offer the atomic tag write")
	}
}

// TestAppendWithTagWrite_ChangesAndRecordsCommitTogether is ADR-0050 decision
// 2's atomicity: a list of changes lands with one record per change, and the
// tags read back through getNode.
func TestAppendWithTagWrite_ChangesAndRecordsCommitTogether(t *testing.T) {
	st, _ := openTestStore(t)
	seedNodes(t, st, "n1", "n2")

	if err := writeTags(t, st, "a",
		registry.TagChange{NodeID: "n1", Key: "team", After: tagVal("payments")},
		registry.TagChange{NodeID: "n2", Key: "team", After: tagVal("payments")},
	); err != nil {
		t.Fatalf("add: %v", err)
	}
	if got := tagsOf(t, st, "n1"); !reflect.DeepEqual(got, map[string]string{"team": "payments"}) {
		t.Errorf("n1 tags = %v", got)
	}
	if got := auditRows(t, st); got != 2 {
		t.Errorf("audit rows = %d, want one per change", got)
	}

	if err := writeTags(t, st, "b", registry.TagChange{NodeID: "n1", Key: "team", Before: tagVal("payments"), After: tagVal("billing")}); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if err := writeTags(t, st, "c", registry.TagChange{NodeID: "n2", Key: "team", Before: tagVal("payments")}); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if got := tagsOf(t, st, "n1"); !reflect.DeepEqual(got, map[string]string{"team": "billing"}) {
		t.Errorf("n1 tags after replace = %v", got)
	}
	if got := tagsOf(t, st, "n2"); len(got) != 0 {
		t.Errorf("n2 tags after remove = %v, want none", got)
	}
	recs, err := st.Audit().ByNode(context.Background(), "n1")
	if err != nil || len(recs) != 2 || recs[0].Kind != audit.KindTagWrite {
		t.Errorf("ByNode(n1) = %d records, %v; want two tag_write records", len(recs), err)
	}
}

// TestAppendWithTagWrite_AnUnwritableRecordLeavesTagsUnchanged: the changes are
// written before the records, so a record that cannot be written rolls every
// change back.
func TestAppendWithTagWrite_AnUnwritableRecordLeavesTagsUnchanged(t *testing.T) {
	st, _ := openTestStore(t)
	seedNodes(t, st, "n1", "n2")
	if err := writeTags(t, st, "dup", registry.TagChange{NodeID: "n1", Key: "team", After: tagVal("a")}); err != nil {
		t.Fatal(err)
	}
	before := headAt(t, st)

	app := st.Audit().(audit.TagWriteAppender)
	// The second record reuses an audit id that is already taken.
	err := app.AppendWithTagWrite(context.Background(),
		[]audit.Record{tagRecord("fresh", "n1"), tagRecord("tag-dup-0", "n2")},
		[]registry.TagChange{
			{NodeID: "n1", Key: "team", Before: tagVal("a"), After: tagVal("b")},
			{NodeID: "n2", Key: "team", After: tagVal("b")},
		})
	if err == nil || errors.Is(err, registry.ErrTagChanged) {
		t.Fatalf("err = %v, want an audit-write error", err)
	}
	if got := tagsOf(t, st, "n1"); !reflect.DeepEqual(got, map[string]string{"team": "a"}) {
		t.Errorf("n1 tags = %v, want the original", got)
	}
	if got := tagsOf(t, st, "n2"); len(got) != 0 {
		t.Errorf("n2 tags = %v, want none", got)
	}
	if after := headAt(t, st); after != before {
		t.Error("chain head moved on a failed write")
	}
}

func TestAppendWithTagWrite_RefusesAStaleBefore(t *testing.T) {
	st, _ := openTestStore(t)
	seedNodes(t, st, "n1", "n2")
	if err := writeTags(t, st, "a", registry.TagChange{NodeID: "n1", Key: "team", After: tagVal("a")}); err != nil {
		t.Fatal(err)
	}
	before := headAt(t, st)

	for name, c := range map[string]registry.TagChange{
		"expected absent, present": {NodeID: "n1", Key: "team", After: tagVal("b")},
		"expected other value":     {NodeID: "n1", Key: "team", Before: tagVal("zzz"), After: tagVal("b")},
		"expected present, absent": {NodeID: "n1", Key: "other", Before: tagVal("a")},
	} {
		// A second, valid change rides along and must not land either.
		err := writeTags(t, st, "stale", registry.TagChange{NodeID: "n2", Key: "team", After: tagVal("ok")}, c)
		if !errors.Is(err, registry.ErrTagChanged) {
			t.Fatalf("%s: err = %v, want ErrTagChanged", name, err)
		}
	}
	if got := tagsOf(t, st, "n2"); len(got) != 0 {
		t.Errorf("n2 tags = %v, want the valid change rolled back too", got)
	}
	if after := headAt(t, st); after != before {
		t.Error("chain head moved on a refused write")
	}
}

// TestAppendWithTagWrite_RefusesOverSixtyFourTags: the cap is re-checked inside
// the transaction, and only for a Node that gains a tag.
func TestAppendWithTagWrite_RefusesOverSixtyFourTags(t *testing.T) {
	st, _ := openTestStore(t)
	seedNodes(t, st, "n1", "n2")
	var fill []registry.TagChange
	for i := 0; i < registry.MaxTagsPerNode; i++ {
		fill = append(fill, registry.TagChange{NodeID: "n1", Key: fmt.Sprintf("k%d", i), After: tagVal("v")})
	}
	if err := writeTags(t, st, "fill", fill...); err != nil {
		t.Fatalf("filling to the cap: %v", err)
	}
	before := headAt(t, st)

	err := writeTags(t, st, "over",
		registry.TagChange{NodeID: "n2", Key: "fresh", After: tagVal("v")},
		registry.TagChange{NodeID: "n1", Key: "over", After: tagVal("v")})
	if !errors.Is(err, registry.ErrTooManyTags) {
		t.Fatalf("err = %v, want ErrTooManyTags", err)
	}
	if got := tagsOf(t, st, "n2"); len(got) != 0 {
		t.Errorf("n2 tags = %v, want the list rolled back", got)
	}
	if after := headAt(t, st); after != before {
		t.Error("chain head moved on a refused write")
	}

	// A replace and a remove on the full Node stay possible.
	if err := writeTags(t, st, "shed",
		registry.TagChange{NodeID: "n1", Key: "k0", Before: tagVal("v"), After: tagVal("w")},
		registry.TagChange{NodeID: "n1", Key: "k1", Before: tagVal("v")}); err != nil {
		t.Errorf("replace and remove on a full Node: %v", err)
	}

	// A Node already over the cap by direct tampering can still shed a tag.
	for i := 0; i < registry.MaxTagsPerNode+5; i++ {
		insertLabel(t, st, nsTag, "n2", fmt.Sprintf("raw%d", i), "v")
	}
	if err := writeTags(t, st, "tamper", registry.TagChange{NodeID: "n2", Key: "raw0", Before: tagVal("v")}); err != nil {
		t.Errorf("a Node over the cap could not shed a tag: %v", err)
	}
}

func TestAppendWithTagWrite_UnknownNodeWritesNothing(t *testing.T) {
	st, _ := openTestStore(t)
	seedNodes(t, st, "n1")
	before := headAt(t, st)
	err := writeTags(t, st, "ghost",
		registry.TagChange{NodeID: "n1", Key: "team", After: tagVal("a")},
		registry.TagChange{NodeID: "ghost", Key: "team", After: tagVal("a")})
	if !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if got := tagsOf(t, st, "n1"); len(got) != 0 {
		t.Errorf("n1 tags = %v, want none", got)
	}
	if after := headAt(t, st); after != before {
		t.Error("chain head moved on a refused write")
	}
}

func TestAppendWithTagWrite_RefusesAMalformedCall(t *testing.T) {
	st, _ := openTestStore(t)
	seedNodes(t, st, "n1")
	app := st.Audit().(audit.TagWriteAppender)
	ctx := context.Background()
	good := registry.TagChange{NodeID: "n1", Key: "team", After: tagVal("a")}
	rec := func(mut func(*audit.Record)) []audit.Record {
		r := tagRecord("x", "n1")
		if mut != nil {
			mut(&r)
		}
		return []audit.Record{r}
	}
	cases := map[string]struct {
		rs []audit.Record
		cs []registry.TagChange
	}{
		"no changes":        {nil, nil},
		"record count":      {append(rec(nil), tagRecord("y", "n1")), []registry.TagChange{good}},
		"no record id":      {rec(func(r *audit.Record) { r.ID = "" }), []registry.TagChange{good}},
		"wrong kind":        {rec(func(r *audit.Record) { r.Kind = audit.KindRead }), []registry.TagChange{good}},
		"wrong node":        {rec(func(r *audit.Record) { r.NodeID = "n2" }), []registry.TagChange{good}},
		"no change":         {rec(nil), []registry.TagChange{{NodeID: "n1", Key: "team", Before: tagVal("a"), After: tagVal("a")}}},
		"empty key":         {rec(nil), []registry.TagChange{{NodeID: "n1", Key: "", After: tagVal("a")}}},
		"comma in key":      {rec(nil), []registry.TagChange{{NodeID: "n1", Key: "a,b", After: tagVal("a")}}},
		"space in value":    {rec(nil), []registry.TagChange{{NodeID: "n1", Key: "k", After: tagVal("a b")}}},
		"colon in value":    {rec(nil), []registry.TagChange{{NodeID: "n1", Key: "k", After: tagVal("a:b")}}},
		"equals in value":   {rec(nil), []registry.TagChange{{NodeID: "n1", Key: "k", After: tagVal("a=b")}}},
		"non-ascii":         {rec(nil), []registry.TagChange{{NodeID: "n1", Key: "k", After: tagVal("a\u200b")}}},
		"same tag twice":    {append(rec(nil), tagRecord("y", "n1")), []registry.TagChange{good, {NodeID: "n1", Key: "team", Before: tagVal("a"), After: tagVal("b")}}},
		"neither side set":  {rec(nil), []registry.TagChange{{NodeID: "n1", Key: "team"}}},
		"no node on change": {rec(func(r *audit.Record) { r.NodeID = "" }), []registry.TagChange{{Key: "team", After: tagVal("a")}}},
	}
	names := make([]string, 0, len(cases))
	for n := range cases {
		names = append(names, n)
	}
	sort.Strings(names)
	before := headAt(t, st)
	for _, name := range names {
		c := cases[name]
		if err := app.AppendWithTagWrite(ctx, c.rs, c.cs); err == nil {
			t.Errorf("%s: err = nil, want a refusal", name)
		}
	}
	if got := tagsOf(t, st, "n1"); len(got) != 0 {
		t.Errorf("tags = %v after only malformed calls", got)
	}
	if after := headAt(t, st); after != before {
		t.Error("chain head moved on a malformed call")
	}
}

func TestTagLabels_TableHoldsNodeKeyValueOnly(t *testing.T) {
	st, _ := openTestStore(t)
	rows, err := st.db.Query(`SELECT name FROM pragma_table_info('tag_labels')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		cols = append(cols, c)
	}
	sort.Strings(cols)
	if want := []string{"key", "node_id", "value"}; !reflect.DeepEqual(cols, want) {
		t.Fatalf("tag_labels columns = %v, want %v", cols, want)
	}
}

func TestTagLabels_SurviveARestart(t *testing.T) {
	st, path := openTestStore(t)
	seedNodes(t, st, "n1")
	if err := writeTags(t, st, "a", registry.TagChange{NodeID: "n1", Key: "team", After: tagVal("payments")}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := tagsOf(t, reopened, "n1"); !reflect.DeepEqual(got, map[string]string{"team": "payments"}) {
		t.Fatalf("after restart = %v", got)
	}
}

// TestGetNode_DoesNotServeAMalformedTag: a tag row written around the gate is
// declined on read-back, counted, and left in place, and the tag writer treats
// the key as changed rather than deleting the row through the filtered view.
func TestGetNode_DoesNotServeAMalformedTag(t *testing.T) {
	st, _ := openTestStore(t)
	seedNodes(t, st, "n1")
	insertLabel(t, st, nsTag, "n1", "good", "v")
	insertLabel(t, st, nsTag, "n1", "bad", "a b")

	if got := tagsOf(t, st, "n1"); !reflect.DeepEqual(got, map[string]string{"good": "v"}) {
		t.Errorf("tags = %v, want only the well-formed row", got)
	}
	if got := st.reg.declined[nsTag].Load(); got == 0 {
		t.Error("the declined tag was not counted")
	}

	// The filtered view shows the key as absent, so a write that read it
	// expects Before absent and must be refused, never overwrite or delete.
	err := writeTags(t, st, "bad", registry.TagChange{NodeID: "n1", Key: "bad", After: tagVal("fixed")})
	if !errors.Is(err, registry.ErrTagChanged) {
		t.Fatalf("err = %v, want ErrTagChanged", err)
	}
	var raw string
	if err := st.db.QueryRow(`SELECT value FROM tag_labels WHERE node_id = 'n1' AND key = 'bad'`).Scan(&raw); err != nil || raw != "a b" {
		t.Errorf("the declined row = %q, %v; want it left in place untouched", raw, err)
	}
}
