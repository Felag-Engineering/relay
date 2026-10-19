package capability

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

const (
	aliasFPa = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	aliasFPb = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// fakeAliasStore is a PolicyAliasSource and PolicyAliasRecorder over a map: a
// recorded change is applied to it, as the real store's transaction applies it.
type fakeAliasStore struct {
	mu        sync.Mutex
	aliases   map[string]string
	events    []PolicyAliasEvent
	listCalls int
	recordErr error
}

func newFakeAliasStore(seed map[string]string) *fakeAliasStore {
	s := &fakeAliasStore{aliases: map[string]string{}}
	for k, v := range seed {
		s.aliases[k] = v
	}
	return s
}

func (f *fakeAliasStore) List(context.Context) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	out := make(map[string]string, len(f.aliases))
	for k, v := range f.aliases {
		out[k] = v
	}
	return out, nil
}

func (f *fakeAliasStore) RecordPolicyAlias(_ context.Context, e PolicyAliasEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.recordErr != nil {
		return f.recordErr
	}
	f.events = append(f.events, e)
	if e.New == "" {
		delete(f.aliases, e.Fingerprint)
	} else {
		f.aliases[e.Fingerprint] = e.New
	}
	return nil
}

// aliasAuditSink is a spyAuditSink that is also a PolicyAliasRecorder.
type aliasAuditSink struct {
	*spyAuditSink
	store *fakeAliasStore
}

func (a *aliasAuditSink) RecordPolicyAlias(ctx context.Context, e PolicyAliasEvent) error {
	return a.store.RecordPolicyAlias(ctx, e)
}

func aliasFixture(t *testing.T, seed map[string]string, nodes ...registry.Report) (*testSvc, *fakeAliasStore, *spyAuditSink) {
	t.Helper()
	reg := registry.NewInMemory()
	for _, r := range nodes {
		if _, err := reg.Upsert(r); err != nil {
			t.Fatalf("Upsert(%s): %v", r.NodeID, err)
		}
	}
	store := newFakeAliasStore(seed)
	spy := &spyAuditSink{}
	svc := build(t, seams{reg: reg, audit: &aliasAuditSink{spy, store}, aliases: store})
	return svc, store, spy
}

var aliasAdmin = Principal{AccountID: "acct-1", Account: "alice", Role: "admin", Kind: PrincipalKindHuman, AuthMethod: AuthMethodConsoleSession}

func TestPolicyAliasAdmin_HumanAdminSetsRenamesAndClears(t *testing.T) {
	svc, _, _ := aliasFixture(t, nil)
	ctx := context.Background()

	read := func() map[string]string {
		t.Helper()
		got, err := svc.PolicyAliases(ctx, aliasAdmin)
		if err != nil {
			t.Fatalf("PolicyAliases: %v", err)
		}
		return got
	}
	if err := svc.SetPolicyAlias(ctx, aliasAdmin, aliasFPa, "web-hardened"); err != nil {
		t.Fatalf("SetPolicyAlias: %v", err)
	}
	if got := read(); !reflect.DeepEqual(got, map[string]string{aliasFPa: "web-hardened"}) {
		t.Fatalf("after set = %v", got)
	}
	if err := svc.SetPolicyAlias(ctx, aliasAdmin, aliasFPa, "web-prod"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if got := read(); !reflect.DeepEqual(got, map[string]string{aliasFPa: "web-prod"}) {
		t.Fatalf("after rename = %v", got)
	}
	if err := svc.ClearPolicyAlias(ctx, aliasAdmin, aliasFPa); err != nil {
		t.Fatalf("ClearPolicyAlias: %v", err)
	}
	if got := read(); len(got) != 0 {
		t.Fatalf("after clear = %v, want empty", got)
	}
}

func TestPolicyAliasAdmin_RecordsTheActorFingerprintOldAndNewValue(t *testing.T) {
	svc, store, _ := aliasFixture(t, nil)
	ctx := WithAssertions(context.Background(), Assertions{OnBehalfOf: "bob"})

	steps := []struct {
		do       func() error
		old, new string
	}{
		{func() error { return svc.SetPolicyAlias(ctx, aliasAdmin, aliasFPa, "web") }, "", "web"},
		{func() error { return svc.SetPolicyAlias(ctx, aliasAdmin, aliasFPa, "web-prod") }, "web", "web-prod"},
		{func() error { return svc.ClearPolicyAlias(ctx, aliasAdmin, aliasFPa) }, "web-prod", ""},
	}
	for _, s := range steps {
		if err := s.do(); err != nil {
			t.Fatal(err)
		}
	}
	if len(store.events) != len(steps) {
		t.Fatalf("events = %d, want %d", len(store.events), len(steps))
	}
	for i, s := range steps {
		e := store.events[i]
		if e.Principal != aliasAdmin || e.Fingerprint != aliasFPa || e.Old != s.old || e.New != s.new {
			t.Errorf("event %d = %+v, want principal %v fingerprint %s old %q new %q", i, e, aliasAdmin, aliasFPa, s.old, s.new)
		}
		if e.Asserted.OnBehalfOf != "bob" {
			t.Errorf("event %d asserted lane = %+v", i, e.Asserted)
		}
	}
}

func TestPolicyAliasAdmin_NoChangeRecordsNothing(t *testing.T) {
	svc, store, spy := aliasFixture(t, map[string]string{aliasFPa: "web"})
	ctx := context.Background()

	// The normalized value is what is compared, so surrounding space is no change.
	for _, name := range []string{"web", "  web  "} {
		if err := svc.SetPolicyAlias(ctx, aliasAdmin, aliasFPa, name); err != nil {
			t.Fatalf("SetPolicyAlias(%q): %v", name, err)
		}
	}
	if err := svc.ClearPolicyAlias(ctx, aliasAdmin, aliasFPb); err != nil {
		t.Fatalf("ClearPolicyAlias of an unset alias: %v", err)
	}
	if len(store.events) != 0 || len(spy.entries) != 0 {
		t.Fatalf("a no-op recorded %d alias events, %d entries", len(store.events), len(spy.entries))
	}
}

func TestPolicyAliasAdmin_StoreConflicts(t *testing.T) {
	t.Run("changed is returned unaudited", func(t *testing.T) {
		svc, store, spy := aliasFixture(t, nil)
		store.recordErr = ErrPolicyAliasChanged
		err := svc.SetPolicyAlias(context.Background(), aliasAdmin, aliasFPa, "web")
		if !errors.Is(err, ErrPolicyAliasChanged) {
			t.Fatalf("err = %v, want ErrPolicyAliasChanged", err)
		}
		if len(spy.entries) != 0 {
			t.Errorf("a store conflict recorded %d refusals", len(spy.entries))
		}
	})
	t.Run("a lost race for a name is a recorded refusal", func(t *testing.T) {
		svc, store, spy := aliasFixture(t, nil)
		store.recordErr = ErrPolicyAliasTaken
		err := svc.SetPolicyAlias(context.Background(), aliasAdmin, aliasFPa, "web")
		if !errors.Is(err, ErrPolicyAliasTaken) {
			t.Fatalf("err = %v, want ErrPolicyAliasTaken", err)
		}
		if len(spy.entries) != 1 || spy.entries[0].Kind != AuditKindRefusal {
			t.Errorf("entries = %+v, want one refusal", spy.entries)
		}
	})
}

func TestPolicyAliasAdmin_SetsAnAliasForAFingerprintNoNodeReports(t *testing.T) {
	svc, _, _ := aliasFixture(t, nil)
	if err := svc.SetPolicyAlias(context.Background(), aliasAdmin, aliasFPa, "retired-baseline"); err != nil {
		t.Fatalf("SetPolicyAlias on an empty registry: %v", err)
	}
	got, err := svc.PolicyAliases(context.Background(), aliasAdmin)
	if err != nil || got[aliasFPa] != "retired-baseline" {
		t.Fatalf("PolicyAliases = %v, %v", got, err)
	}
}

func TestPolicyAlias_IsNeverASelectorTerm(t *testing.T) {
	node := registry.Report{NodeID: "node-1", PolicyFingerprint: aliasFPa}
	svc, store, _ := aliasFixture(t, map[string]string{aliasFPa: "web-hardened"}, node)
	ctx := context.Background()

	// A name given where a fingerprint belongs resolves nothing; it is never
	// looked up in the alias table. A parse refusal proves the same thing as a
	// parse that matches no Node, so either outcome passes.
	listing, err := svc.ListNodes(ctx, aliasAdmin, "state:policy-fingerprint=web-hardened")
	if err == nil && len(listing.Nodes) != 0 {
		t.Errorf("an alias matched %d Nodes as a fingerprint", len(listing.Nodes))
	}
	listing, err = svc.ListNodes(ctx, aliasAdmin, "state:policy-fingerprint="+aliasFPa)
	if err != nil || len(listing.Nodes) != 1 {
		t.Errorf("the fingerprint matched %d Nodes, err %v; want 1", len(listing.Nodes), err)
	}
	if _, err := ParseSelector("state:policy-alias=web-hardened"); err == nil {
		t.Error("state:policy-alias parsed; the state: vocabulary is closed")
	}

	sel, err := ParseSelector("state:policy-fingerprint=web-hardened")
	if err == nil {
		pr, perr := svc.Plan(ctx, aliasAdmin, sel, jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"})
		if perr == nil && !pr.NoNodesMatched {
			t.Errorf("a Plan over an alias-valued Selector matched %d Nodes", pr.Matched)
		}
	}
	if store.listCalls != 0 {
		t.Errorf("Selector resolution consulted the alias source %d times", store.listCalls)
	}
}

func TestPolicyAliasShapes_NameNoNodeLabelOrSelector(t *testing.T) {
	var fields []string
	typ := reflect.TypeOf(PolicyAliasEvent{})
	for i := 0; i < typ.NumField(); i++ {
		fields = append(fields, typ.Field(i).Name)
	}
	sort.Strings(fields)
	if want := []string{"Asserted", "Fingerprint", "New", "Old", "Principal"}; !reflect.DeepEqual(fields, want) {
		t.Errorf("PolicyAliasEvent fields = %v, want %v", fields, want)
	}

	ctxT := reflect.TypeOf((*context.Context)(nil)).Elem()
	principalT := reflect.TypeOf(Principal{})
	stringT := reflect.TypeOf("")
	for name, want := range map[string][]reflect.Type{
		"SetPolicyAlias":   {ctxT, principalT, stringT, stringT},
		"ClearPolicyAlias": {ctxT, principalT, stringT},
	} {
		m, ok := reflect.TypeOf(&PolicyAliasAdmin{}).MethodByName(name)
		if !ok {
			t.Fatalf("%s missing", name)
		}
		var got []reflect.Type
		for i := 1; i < m.Type.NumIn(); i++ { // 0 is the receiver
			got = append(got, m.Type.In(i))
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s takes %v, want %v: no step-up, Node, Selector or registry parameter", name, got, want)
		}
	}
}

func TestReadLane_PolicyAliasesRecordsTheReadBeforeConsultingTheSource(t *testing.T) {
	svc, store, spy := aliasFixture(t, map[string]string{aliasFPa: "web"})
	if _, err := svc.PolicyAliases(context.Background(), aliasAdmin); err != nil {
		t.Fatal(err)
	}
	if len(spy.readCalls) != 1 || spy.readCalls[0].Tool != "list_policy_aliases" || spy.readCalls[0].Principal != aliasAdmin {
		t.Errorf("readCalls = %+v", spy.readCalls)
	}
	if store.listCalls != 1 {
		t.Errorf("source consulted %d times, want 1", store.listCalls)
	}
}

func TestReadLane_PolicyAliasesFailsClosedWhenTheReadCannotBeRecorded(t *testing.T) {
	svc, store, spy := aliasFixture(t, map[string]string{aliasFPa: "web"})
	spy.err = errors.New("trail down")
	got, err := svc.PolicyAliases(context.Background(), aliasAdmin)
	if !errors.Is(err, ErrReadUnaudited) || got != nil {
		t.Fatalf("PolicyAliases = %v, %v; want ErrReadUnaudited and no data", got, err)
	}
	if store.listCalls != 0 {
		t.Errorf("source consulted %d times after an unrecorded read", store.listCalls)
	}
}

func TestReadLane_PolicyAliasesUnwiredIsAnErrorNotAnEmptySet(t *testing.T) {
	svc := build(t, seams{reg: registry.NewInMemory(), audit: &spyAuditSink{}})
	got, err := svc.PolicyAliases(context.Background(), aliasAdmin)
	if !errors.Is(err, ErrPolicyAliasesUnavailable) || got != nil {
		t.Fatalf("PolicyAliases = %v, %v; want ErrPolicyAliasesUnavailable", got, err)
	}
}

func TestReadLane_PolicyAliasesReturnsACopy(t *testing.T) {
	svc, store, _ := aliasFixture(t, map[string]string{aliasFPa: "web"})
	got, err := svc.PolicyAliases(context.Background(), aliasAdmin)
	if err != nil {
		t.Fatal(err)
	}
	got[aliasFPb] = "mutated"
	if _, ok := store.aliases[aliasFPb]; ok {
		t.Error("mutating the returned map reached the source")
	}
}

func TestPolicyAliasAdmin_UnwiredIsUnavailable(t *testing.T) {
	svc := build(t, seams{reg: registry.NewInMemory(), audit: &spyAuditSink{}})
	if err := svc.SetPolicyAlias(context.Background(), aliasAdmin, aliasFPa, "web"); !errors.Is(err, ErrPolicyAliasesUnavailable) {
		t.Errorf("SetPolicyAlias = %v", err)
	}
	if err := svc.ClearPolicyAlias(context.Background(), aliasAdmin, aliasFPa); !errors.Is(err, ErrPolicyAliasesUnavailable) {
		t.Errorf("ClearPolicyAlias = %v", err)
	}
}

// plainAuditSink is an AuditSink that is not a PolicyAliasRecorder.
type plainAuditSink struct{ *spyAuditSink }

func TestNewPolicyAliasAdmin_PanicsOnAnUnsafeComposition(t *testing.T) {
	store := newFakeAliasStore(nil)
	real := &spyAuthorizer{}
	good := func(authz Authorizer, sink AuditSink) *Control {
		return newControl(NewRecorder(sink, nil, nil), authz, noopFreezeStore{})
	}
	aliasSink := &aliasAuditSink{&spyAuditSink{}, store}
	cases := map[string]func(){
		"nil control":       func() { NewPolicyAliasAdmin(nil, store) },
		"nil source":        func() { NewPolicyAliasAdmin(good(real, aliasSink), nil) },
		"allow-all":         func() { NewPolicyAliasAdmin(good(allowAllAuthorizer{}, aliasSink), store) },
		"no-op sink":        func() { NewPolicyAliasAdmin(good(real, noopAuditSink{}), store) },
		"not a recorder":    func() { NewPolicyAliasAdmin(good(real, plainAuditSink{&spyAuditSink{}}), store) },
		"control, no audit": func() { NewPolicyAliasAdmin(&Control{rec: &Recorder{audit: noopAuditSink{}}, authz: real}, store) },
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
	if NewPolicyAliasAdmin(good(real, aliasSink), store) == nil {
		t.Error("a safe composition returned nil")
	}
}

func TestValidPolicyFingerprint(t *testing.T) {
	cases := map[string]bool{
		aliasFPa:                              true,
		strings.Repeat("0123456789abcdef", 4): true,
		"":                                    false,
		aliasFPa[:63]:                         false,
		aliasFPa + "a":                        false,
		strings.ToUpper(aliasFPa):             false,
		strings.Repeat("g", 64):               false,
		strings.Repeat("a", 63) + "é":         false,
	}
	for in, want := range cases {
		if got := ValidPolicyFingerprint(in); got != want {
			t.Errorf("ValidPolicyFingerprint(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestNormalizePolicyAlias(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
		err  error
	}{
		{"plain", "web-prod", "web-prod", nil},
		{"trimmed", "  web-prod  ", "web-prod", nil},
		{"edge control whitespace trimmed", "\tweb-prod\u0085", "web-prod", nil},
		{"edge LF and TAB trimmed", "\nweb-prod\t", "web-prod", nil},
		{"64 multi-byte runes", strings.Repeat("é", 64), strings.Repeat("é", 64), nil},
		{"empty", "", "", ErrPolicyAliasEmpty},
		{"blank", "   ", "", ErrPolicyAliasEmpty},
		{"65 runes", strings.Repeat("é", 65), "", ErrPolicyAliasTooLong},
		{"invalid utf-8", "web\xffprod", "", ErrPolicyAliasInvalidUTF8},
		{"NUL", "web\x00prod", "", ErrPolicyAliasControlCharacter},
		{"TAB mid-name", "web\tprod", "", ErrPolicyAliasControlCharacter},
		{"DEL", "web\x7fprod", "", ErrPolicyAliasControlCharacter},
		{"NEL mid-name", "web\u0085prod", "", ErrPolicyAliasControlCharacter},
		{"RLO", "web\u202eprod", "", ErrPolicyAliasControlCharacter},
		{"LRI", "web\u2066prod", "", ErrPolicyAliasControlCharacter},
		{"ZWSP", "web\u200bprod", "", ErrPolicyAliasControlCharacter},
		{"BOM", "web\ufeffprod", "", ErrPolicyAliasControlCharacter},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := NormalizePolicyAlias(c.in)
			if !errors.Is(err, c.err) || got != c.want {
				t.Errorf("NormalizePolicyAlias(%q) = %q, %v; want %q, %v", c.in, got, err, c.want, c.err)
			}
		})
	}
}
