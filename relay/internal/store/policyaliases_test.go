package store

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/policyalias"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

const (
	aliasFPa = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	aliasFPb = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func aliasRecord(id string) audit.Record {
	return audit.Record{
		ID:        id,
		Timestamp: time.Date(2026, 10, 18, 0, 0, 1, 0, time.UTC),
		Kind:      audit.KindPolicyAlias,
		Principal: "alice",
		Reason:    "fingerprint=" + aliasFPa,
	}
}

func appendAlias(t *testing.T, st *Store, id string, c policyalias.Change) error {
	t.Helper()
	app, ok := st.Audit().(audit.PolicyAliasAppender)
	if !ok {
		t.Fatal("the store's audit Repository is not a PolicyAliasAppender")
	}
	return app.AppendWithPolicyAlias(context.Background(), aliasRecord(id), c)
}

func listAliases(t *testing.T, st *Store) map[string]string {
	t.Helper()
	got, err := st.PolicyAliases().List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	return got
}

func TestStoreAudit_OffersTheAtomicPolicyAliasWrite(t *testing.T) {
	st, _ := openTestStore(t)
	if _, ok := st.Audit().(audit.PolicyAliasAppender); !ok {
		t.Fatal("st.Audit() does not offer the atomic Policy alias write")
	}
}

func TestPolicyAliases_ListIsEmptyAndNeverNil(t *testing.T) {
	st, _ := openTestStore(t)
	if got := listAliases(t, st); got == nil || len(got) != 0 {
		t.Fatalf("List = %#v, want an empty non-nil map", got)
	}
}

func TestPolicyAliases_TableHoldsAFingerprintAndANameOnly(t *testing.T) {
	st, _ := openTestStore(t)
	rows, err := st.db.Query(`SELECT name FROM pragma_table_info('policy_aliases')`)
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
	if want := []string{"alias", "fingerprint", "updated_at"}; !reflect.DeepEqual(cols, want) {
		t.Fatalf("policy_aliases columns = %v, want %v", cols, want)
	}
}

func TestPolicyAliases_SurviveARestart(t *testing.T) {
	st, path := openTestStore(t)
	if err := appendAlias(t, st, "aud-1", policyalias.Change{Fingerprint: aliasFPa, To: "web"}); err != nil {
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
	if got := listAliases(t, reopened); !reflect.DeepEqual(got, map[string]string{aliasFPa: "web"}) {
		t.Fatalf("after restart = %v", got)
	}
}

func TestAppendWithPolicyAlias_SetRenameClearWriteOneRecordEach(t *testing.T) {
	st, _ := openTestStore(t)
	steps := []struct {
		id   string
		c    policyalias.Change
		want map[string]string
	}{
		{"aud-1", policyalias.Change{Fingerprint: aliasFPa, To: "web"}, map[string]string{aliasFPa: "web"}},
		{"aud-2", policyalias.Change{Fingerprint: aliasFPa, From: "web", To: "web-prod"}, map[string]string{aliasFPa: "web-prod"}},
		{"aud-3", policyalias.Change{Fingerprint: aliasFPa, From: "web-prod"}, map[string]string{}},
	}
	for _, s := range steps {
		if err := appendAlias(t, st, s.id, s.c); err != nil {
			t.Fatalf("%s: %v", s.id, err)
		}
		if got := listAliases(t, st); !reflect.DeepEqual(got, s.want) {
			t.Fatalf("%s: aliases = %v, want %v", s.id, got, s.want)
		}
	}
	recs, err := st.Audit().List(context.Background())
	if err != nil || len(recs) != 3 {
		t.Fatalf("audit rows = %d, %v; want 3", len(recs), err)
	}
}

func TestAppendWithPolicyAlias_OneAliasPerFingerprint(t *testing.T) {
	st, _ := openTestStore(t)
	for i, c := range []policyalias.Change{
		{Fingerprint: aliasFPa, To: "web"},
		{Fingerprint: aliasFPa, From: "web", To: "web-prod"},
	} {
		if err := appendAlias(t, st, "aud-"+string(rune('1'+i)), c); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM policy_aliases`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rows = %d, %v; want one row for the fingerprint", n, err)
	}
}

func TestAppendWithPolicyAlias_OneFingerprintPerAlias(t *testing.T) {
	st, _ := openTestStore(t)
	if err := appendAlias(t, st, "aud-1", policyalias.Change{Fingerprint: aliasFPa, To: "web"}); err != nil {
		t.Fatal(err)
	}
	before := headAt(t, st)
	err := appendAlias(t, st, "aud-2", policyalias.Change{Fingerprint: aliasFPb, To: "web"})
	if !errors.Is(err, policyalias.ErrTaken) {
		t.Fatalf("err = %v, want ErrTaken", err)
	}
	if got := listAliases(t, st); !reflect.DeepEqual(got, map[string]string{aliasFPa: "web"}) {
		t.Errorf("aliases = %v", got)
	}
	if after := headAt(t, st); after != before {
		t.Errorf("chain head moved on a refused change")
	}
}

func TestAppendWithPolicyAlias_RefusesAStaleFrom(t *testing.T) {
	st, _ := openTestStore(t)
	if err := appendAlias(t, st, "aud-1", policyalias.Change{Fingerprint: aliasFPa, To: "web"}); err != nil {
		t.Fatal(err)
	}
	before := headAt(t, st)
	err := appendAlias(t, st, "aud-2", policyalias.Change{Fingerprint: aliasFPa, From: "other", To: "x"})
	if !errors.Is(err, policyalias.ErrChanged) {
		t.Fatalf("err = %v, want ErrChanged", err)
	}
	if got := listAliases(t, st); !reflect.DeepEqual(got, map[string]string{aliasFPa: "web"}) {
		t.Errorf("aliases = %v", got)
	}
	if after := headAt(t, st); after != before {
		t.Errorf("chain head moved on a refused change")
	}
}

func TestAppendWithPolicyAlias_AnUnwritableRecordLeavesTheAliasUnchanged(t *testing.T) {
	st, _ := openTestStore(t)
	if err := appendAlias(t, st, "aud-dup", policyalias.Change{Fingerprint: aliasFPa, To: "web"}); err != nil {
		t.Fatal(err)
	}
	before := headAt(t, st)

	for name, c := range map[string]policyalias.Change{
		"rename": {Fingerprint: aliasFPa, From: "web", To: "web-prod"},
		"clear":  {Fingerprint: aliasFPa, From: "web"},
		"set":    {Fingerprint: aliasFPb, To: "db"},
	} {
		err := appendAlias(t, st, "aud-dup", c) // the audit id is already taken
		if err == nil || errors.Is(err, policyalias.ErrTaken) || errors.Is(err, policyalias.ErrChanged) {
			t.Fatalf("%s: err = %v, want an audit-write error", name, err)
		}
	}
	if got := listAliases(t, st); !reflect.DeepEqual(got, map[string]string{aliasFPa: "web"}) {
		t.Errorf("aliases = %v, want the original", got)
	}
	if after := headAt(t, st); after != before {
		t.Errorf("chain head moved from %+v to %+v", before, after)
	}
}

func TestAppendWithPolicyAlias_RefusesAMalformedCall(t *testing.T) {
	st, _ := openTestStore(t)
	app := st.Audit().(audit.PolicyAliasAppender)
	ctx := context.Background()
	cases := map[string]struct {
		r audit.Record
		c policyalias.Change
	}{
		"no id":       {func() audit.Record { r := aliasRecord("x"); r.ID = ""; return r }(), policyalias.Change{Fingerprint: aliasFPa, To: "a"}},
		"wrong kind":  {func() audit.Record { r := aliasRecord("x"); r.Kind = audit.KindRead; return r }(), policyalias.Change{Fingerprint: aliasFPa, To: "a"}},
		"no print":    {aliasRecord("x"), policyalias.Change{To: "a"}},
		"no change":   {aliasRecord("x"), policyalias.Change{Fingerprint: aliasFPa, From: "a", To: "a"}},
		"both absent": {aliasRecord("x"), policyalias.Change{Fingerprint: aliasFPa}},
		"short print": {aliasRecord("x"), policyalias.Change{Fingerprint: aliasFPa[:63], To: "a"}},
		"long print":  {aliasRecord("x"), policyalias.Change{Fingerprint: aliasFPa + "a", To: "a"}},
		"upper print": {aliasRecord("x"), policyalias.Change{Fingerprint: strings.Repeat("A", 64), To: "a"}},
		"non-hex":     {aliasRecord("x"), policyalias.Change{Fingerprint: strings.Repeat("z", 64), To: "a"}},
		"prefixed":    {aliasRecord("x"), policyalias.Change{Fingerprint: "sha256:node-a-fingerprint", To: "a"}},
	}
	for name, c := range cases {
		if err := app.AppendWithPolicyAlias(ctx, c.r, c.c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if got := listAliases(t, st); len(got) != 0 {
		t.Errorf("aliases = %v", got)
	}
}

func TestPolicyAliases_StayAttachedWithNoNodeReportingTheFingerprint(t *testing.T) {
	st, _ := openTestStore(t)
	if err := appendAlias(t, st, "aud-1", policyalias.Change{Fingerprint: aliasFPa, To: "retired"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Registry().Upsert(registry.Report{NodeID: "node-1", PolicyFingerprint: aliasFPb}); err != nil {
		t.Fatal(err)
	}
	if got := listAliases(t, st); !reflect.DeepEqual(got, map[string]string{aliasFPa: "retired"}) {
		t.Fatalf("aliases = %v", got)
	}
}
