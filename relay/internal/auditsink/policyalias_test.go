package auditsink

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

const (
	aliasFPa = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	aliasFPb = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

var aliasAdminPrincipal = capability.Principal{
	AccountID: "acct-1", Account: "alice", Role: "admin", Kind: capability.PrincipalKindHuman,
	AuthMethod: capability.AuthMethodConsoleSession, Source: "10.0.0.7",
}

type neverFrozen struct{}

func (neverFrozen) Frozen(context.Context) (bool, error)          { return false, nil }
func (neverFrozen) Engage(context.Context, string) error          { return nil }
func (neverFrozen) Release(context.Context, string, string) error { return nil }

// realAliasAdmin is the real capability layer over the real store and the
// given Sink: the composition the Console will construct.
func realAliasAdmin(t *testing.T, st *store.Store, sink *Sink) *capability.PolicyAliasAdmin {
	t.Helper()
	rec := capability.NewRecorder(sink, nil, nil)
	ctl := capability.NewControl(rec, authz.NewRoleGate(), neverFrozen{})
	return capability.NewPolicyAliasAdmin(ctl, st.PolicyAliases())
}

func policyAliasRecords(t *testing.T, repo audit.Repository) []audit.Record {
	t.Helper()
	all, err := repo.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Record
	for _, r := range all {
		if r.Kind == audit.KindPolicyAlias {
			out = append(out, r)
		}
	}
	return out
}

func TestRecordPolicyAlias_ReasonCarriesFingerprintOldAndNew(t *testing.T) {
	st, repo, path := openSinkStore(t)
	sink := New(repo, WithNewID(sequentialIDs("audit-")), WithClock(func() time.Time { return time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC) }))
	admin := realAliasAdmin(t, st, sink)
	ctx := context.Background()

	if err := admin.SetPolicyAlias(ctx, aliasAdminPrincipal, aliasFPa, "web hardened"); err != nil {
		t.Fatal(err)
	}
	if err := admin.SetPolicyAlias(ctx, aliasAdminPrincipal, aliasFPa, "web-prod"); err != nil {
		t.Fatal(err)
	}
	if err := admin.ClearPolicyAlias(ctx, aliasAdminPrincipal, aliasFPa); err != nil {
		t.Fatal(err)
	}

	recs := policyAliasRecords(t, repo)
	wantReasons := []string{
		`fingerprint=` + aliasFPa + ` old="" new="web hardened"`,
		`fingerprint=` + aliasFPa + ` old="web hardened" new="web-prod"`,
		`fingerprint=` + aliasFPa + ` old="web-prod" new=""`,
	}
	if len(recs) != len(wantReasons) {
		t.Fatalf("policy_alias records = %d, want %d", len(recs), len(wantReasons))
	}
	for i, r := range recs {
		if r.Reason != wantReasons[i] {
			t.Errorf("record %d reason = %q, want %q", i, r.Reason, wantReasons[i])
		}
		if r.Principal != aliasAdminPrincipal.Attribution() {
			t.Errorf("record %d principal = %q", i, r.Principal)
		}
		v := r.Attribution.Verified
		if v.AccountID != "acct-1" || v.Role != "admin" || v.Method != string(capability.AuthMethodConsoleSession) || v.Source != "10.0.0.7" {
			t.Errorf("record %d verified lane = %+v", i, v)
		}
	}
	verdict, err := store.VerifyAuditChain(ctx, path, nil)
	if err != nil || !verdict.Intact() {
		t.Fatalf("chain verdict = %+v, %v; want intact", verdict, err)
	}
}

func TestPolicyAliasAdmin_ChangeIsNotMadeWhenItsRecordCannotBeWritten(t *testing.T) {
	st, repo, _ := openSinkStore(t)
	ctx := context.Background()

	good := realAliasAdmin(t, st, New(repo, WithNewID(sequentialIDs("good-"))))
	if err := good.SetPolicyAlias(ctx, aliasAdminPrincipal, aliasFPa, "web"); err != nil {
		t.Fatal(err)
	}
	if err := repo.Append(ctx, audit.Record{ID: "dup", Timestamp: time.Now().UTC(), Kind: audit.KindRead, Principal: "x"}); err != nil {
		t.Fatal(err)
	}
	head, err := st.AuditChain().ChainHead(ctx)
	if err != nil {
		t.Fatal(err)
	}

	broken := realAliasAdmin(t, st, New(repo, WithNewID(func() (string, error) { return "dup", nil })))
	for name, do := range map[string]func() error{
		"rename": func() error { return broken.SetPolicyAlias(ctx, aliasAdminPrincipal, aliasFPa, "web-prod") },
		"clear":  func() error { return broken.ClearPolicyAlias(ctx, aliasAdminPrincipal, aliasFPa) },
		"set":    func() error { return broken.SetPolicyAlias(ctx, aliasAdminPrincipal, aliasFPb, "db") },
	} {
		err := do()
		if err == nil {
			t.Fatalf("%s succeeded though its record could not be written", name)
		}
		if errors.Is(err, capability.ErrPolicyAliasTaken) || errors.Is(err, capability.ErrPolicyAliasChanged) || errors.Is(err, authz.ErrUnauthorized) {
			t.Fatalf("%s: err = %v, want an audit-write error", name, err)
		}
	}
	got, err := st.PolicyAliases().List(ctx)
	if err != nil || !reflect.DeepEqual(got, map[string]string{aliasFPa: "web"}) {
		t.Fatalf("aliases = %v, %v; want the original", got, err)
	}
	if after, _ := st.AuditChain().ChainHead(ctx); after != head {
		t.Errorf("chain head moved from %+v to %+v", head, after)
	}
}

// plainRepo embeds audit.Repository only, so it does not offer
// AppendWithPolicyAlias even over a store that does.
type plainRepo struct{ audit.Repository }

func TestRecordPolicyAlias_ARepositoryWithoutTheAtomicWriteRefusesAndWritesNothing(t *testing.T) {
	st, repo, _ := openSinkStore(t)
	ctx := context.Background()
	sink := New(plainRepo{repo}, WithNewID(sequentialIDs("audit-")))
	before, _ := repo.List(ctx)

	err := sink.RecordPolicyAlias(ctx, capability.PolicyAliasEvent{Principal: aliasAdminPrincipal, Fingerprint: aliasFPa, New: "web"})
	if !errors.Is(err, capability.ErrPolicyAliasesUnavailable) {
		t.Fatalf("err = %v, want ErrPolicyAliasesUnavailable", err)
	}
	after, _ := repo.List(ctx)
	if len(after) != len(before) {
		t.Errorf("audit rows %d -> %d", len(before), len(after))
	}
	if got, _ := st.PolicyAliases().List(ctx); len(got) != 0 {
		t.Errorf("aliases = %v", got)
	}
}

func TestRecordPolicyAlias_TranslatesStoreConflicts(t *testing.T) {
	_, repo, _ := openSinkStore(t)
	ctx := context.Background()
	sink := New(repo, WithNewID(sequentialIDs("audit-")))
	if err := sink.RecordPolicyAlias(ctx, capability.PolicyAliasEvent{Principal: aliasAdminPrincipal, Fingerprint: aliasFPa, New: "web"}); err != nil {
		t.Fatal(err)
	}
	err := sink.RecordPolicyAlias(ctx, capability.PolicyAliasEvent{Principal: aliasAdminPrincipal, Fingerprint: aliasFPb, New: "web"})
	if !errors.Is(err, capability.ErrPolicyAliasTaken) {
		t.Errorf("duplicate name = %v, want ErrPolicyAliasTaken", err)
	}
	err = sink.RecordPolicyAlias(ctx, capability.PolicyAliasEvent{Principal: aliasAdminPrincipal, Fingerprint: aliasFPa, Old: "stale", New: "x"})
	if !errors.Is(err, capability.ErrPolicyAliasChanged) {
		t.Errorf("stale old = %v, want ErrPolicyAliasChanged", err)
	}
	if err := sink.RecordPolicyAlias(ctx, capability.PolicyAliasEvent{Principal: aliasAdminPrincipal, Fingerprint: aliasFPa, Old: "web", New: "web"}); err == nil {
		t.Error("an event that changes nothing was recorded")
	}
	if n := len(policyAliasRecords(t, repo)); n != 1 {
		t.Errorf("policy_alias records = %d, want 1", n)
	}
}
