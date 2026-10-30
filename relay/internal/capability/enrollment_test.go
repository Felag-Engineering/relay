package capability

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	enrollmentTestJoinString = "glp_join_FAKEJOINSTRINGXYZ"
	enrollmentTestCredential = "tokid.FAKECREDENTIALSECRET"
)

// fakeEnrollmentIssuer returns a token carrying enrollmentTestJoinString and
// counts what it is asked to do.
type fakeEnrollmentIssuer struct {
	issued      []EnrollmentMint
	withdrawn   []string
	issueErr    error
	withdrawErr error
}

func (f *fakeEnrollmentIssuer) IssueEnrollmentToken(_ context.Context, _ Principal, req EnrollmentMint) (MintedEnrollmentToken, error) {
	f.issued = append(f.issued, req)
	if f.issueErr != nil {
		return MintedEnrollmentToken{}, f.issueErr
	}
	return NewMintedEnrollmentToken("tok-1", enrollmentTestCredential, enrollmentTestJoinString, req.InitialTags, time.Now().Add(req.TTL), req.MaxUses, req.Unlimited), nil
}

func (f *fakeEnrollmentIssuer) WithdrawEnrollmentToken(_ context.Context, id string) error {
	f.withdrawn = append(f.withdrawn, id)
	return f.withdrawErr
}

// enrollmentSink is a spyAuditSink that is also an EnrollmentMintRecorder.
type enrollmentSink struct {
	*spyAuditSink
	events    []EnrollmentMintEvent
	recordErr error
}

func (s *enrollmentSink) RecordEnrollmentTokenMint(_ context.Context, e EnrollmentMintEvent) error {
	if s.recordErr != nil {
		return s.recordErr
	}
	s.events = append(s.events, e)
	return nil
}

type enrollmentFix struct {
	tokens *EnrollmentTokens
	authz  *spyAuthorizer
	sink   *enrollmentSink
	issuer *fakeEnrollmentIssuer
}

func newEnrollmentFix() *enrollmentFix {
	f := &enrollmentFix{
		authz:  &spyAuthorizer{},
		sink:   &enrollmentSink{spyAuditSink: &spyAuditSink{}},
		issuer: &fakeEnrollmentIssuer{},
	}
	control := newControl(NewRecorder(f.sink, nil, nil), f.authz, noopFreezeStore{})
	f.tokens = newEnrollmentTokens(control, f.issuer, f.sink)
	return f
}

var enrollmentAdmin = Principal{AccountID: "acct-admin", Account: "mike", Role: "admin", Kind: PrincipalKindHuman}

func goodMint() EnrollmentMint {
	return EnrollmentMint{MaxUses: 3, TTL: DefaultEnrollmentTokenTTL}
}

// Proves EN-36.
func TestEnrollmentTokens_AuthorizesAtTheMintActionBeforeItReadsTheRequest(t *testing.T) {
	f := newEnrollmentFix()
	if _, err := f.tokens.MintEnrollmentToken(context.Background(), enrollmentAdmin, goodMint()); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if len(f.authz.controlCalls) != 1 || f.authz.controlCalls[0] != ControlMintEnrollmentToken {
		t.Errorf("controlCalls = %v, want exactly [%s]", f.authz.controlCalls, ControlMintEnrollmentToken)
	}

	refused := errors.New("authz: not an admin")
	f = newEnrollmentFix()
	f.authz.controlErr = refused
	_, err := f.tokens.MintEnrollmentToken(context.Background(), enrollmentAdmin, EnrollmentMint{})
	if !errors.Is(err, refused) {
		t.Errorf("err = %v, want the authorization refusal, not an input error", err)
	}
	if len(f.issuer.issued) != 0 {
		t.Error("a refused caller reached the issuer")
	}
	if len(f.sink.entries) != 1 || f.sink.entries[0].Kind != AuditKindRefusal {
		t.Errorf("entries = %+v, want one audited refusal", f.sink.entries)
	}
}

// Proves EN-36, EN-46.
func TestEnrollmentTokens_UseLimitIsTheNumberOfNodesAndThereIsNoUnlimitedForm(t *testing.T) {
	f := newEnrollmentFix()
	if _, err := f.tokens.MintEnrollmentTokenFromForm(context.Background(), enrollmentAdmin, EnrollmentMintForm{Nodes: 7, TTL: time.Hour}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if len(f.issuer.issued) != 1 || f.issuer.issued[0].MaxUses != 7 || f.issuer.issued[0].Unlimited {
		t.Fatalf("issued = %+v, want one request for 7, not unlimited", f.issuer.issued)
	}

	for _, n := range []int{0, -1} {
		f := newEnrollmentFix()
		_, err := f.tokens.MintEnrollmentTokenFromForm(context.Background(), enrollmentAdmin, EnrollmentMintForm{Nodes: n, TTL: time.Hour})
		if !errors.Is(err, ErrEnrollmentFormNodes) || len(f.issuer.issued) != 0 {
			t.Errorf("Nodes %d: err = %v, issued = %d, want ErrEnrollmentFormNodes and no issue", n, err, len(f.issuer.issued))
		}
	}

	typ := reflect.TypeOf(EnrollmentMintForm{})
	for i := 0; i < typ.NumField(); i++ {
		if strings.Contains(strings.ToLower(typ.Field(i).Name), "unlimited") || typ.Field(i).Type.Kind() == reflect.Bool {
			t.Errorf("EnrollmentMintForm has a field %s that could ask for unlimited use", typ.Field(i).Name)
		}
	}
}

// Proves EN-31.
func TestEnrollmentTokens_TheUseLimitIsNamedOrExplicitlyUnlimited(t *testing.T) {
	accepted := []struct {
		name string
		req  EnrollmentMint
	}{
		{"a named limit", EnrollmentMint{MaxUses: 3}},
		{"explicitly unlimited", EnrollmentMint{Unlimited: true}},
		{"zero uses with unlimited", EnrollmentMint{MaxUses: 0, Unlimited: true}},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			f := newEnrollmentFix()
			tc.req.TTL = time.Hour
			minted, err := f.tokens.MintEnrollmentToken(context.Background(), enrollmentAdmin, tc.req)
			if err != nil {
				t.Fatalf("mint: %v", err)
			}
			if len(f.issuer.issued) != 1 || !reflect.DeepEqual(f.issuer.issued[0], tc.req) || minted.Unlimited() != tc.req.Unlimited {
				t.Errorf("issued = %+v, unlimited = %v, want one request %+v passed through", f.issuer.issued, minted.Unlimited(), tc.req)
			}
		})
	}

	refused := []struct {
		name string
		req  EnrollmentMint
	}{
		{"no limit named", EnrollmentMint{}},
		{"a limit and unlimited", EnrollmentMint{MaxUses: 2, Unlimited: true}},
		{"a negative limit", EnrollmentMint{MaxUses: -1}},
		{"a negative limit and unlimited", EnrollmentMint{MaxUses: -1, Unlimited: true}},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			f := newEnrollmentFix()
			tc.req.TTL = time.Hour
			_, err := f.tokens.MintEnrollmentToken(context.Background(), enrollmentAdmin, tc.req)
			if !errors.Is(err, ErrEnrollmentUseLimit) {
				t.Fatalf("err = %v, want ErrEnrollmentUseLimit", err)
			}
			if len(f.issuer.issued) != 0 || len(f.sink.events) != 0 || len(f.sink.entries) != 0 {
				t.Errorf("issued = %d, events = %d, entries = %d, want nothing", len(f.issuer.issued), len(f.sink.events), len(f.sink.entries))
			}
		})
	}

	for _, want := range []string{"max_uses", "unlimited"} {
		if !strings.Contains(ErrEnrollmentUseLimit.Error(), want) {
			t.Errorf("ErrEnrollmentUseLimit %q does not name %q", ErrEnrollmentUseLimit, want)
		}
	}
}

// Proves EN-46.
func TestEnrollmentTokens_AFormMintIsForAtMost256Nodes(t *testing.T) {
	f := newEnrollmentFix()
	if _, err := f.tokens.MintEnrollmentTokenFromForm(context.Background(), enrollmentAdmin, EnrollmentMintForm{Nodes: 256, TTL: time.Hour}); err != nil {
		t.Fatalf("256: %v", err)
	}
	if len(f.issuer.issued) != 1 || f.issuer.issued[0].MaxUses != 256 || len(f.sink.events) != 1 {
		t.Fatalf("issued = %+v, events = %d, want one request for 256 and one record", f.issuer.issued, len(f.sink.events))
	}

	f = newEnrollmentFix()
	_, err := f.tokens.MintEnrollmentTokenFromForm(context.Background(), enrollmentAdmin, EnrollmentMintForm{Nodes: 257, TTL: time.Hour})
	if !errors.Is(err, ErrEnrollmentFormNodes) || !strings.Contains(err.Error(), "256") {
		t.Fatalf("257: err = %v, want ErrEnrollmentFormNodes naming 256", err)
	}
	if len(f.issuer.issued) != 0 || len(f.sink.events) != 0 {
		t.Errorf("257: issued = %d, events = %d, want nothing", len(f.issuer.issued), len(f.sink.events))
	}
}

// Proves EN-36, EN-46.
func TestEnrollmentTokens_AFormMintAuthorizesBeforeItChecksTheCount(t *testing.T) {
	f := newEnrollmentFix()
	refused := errors.New("authz: not an admin")
	f.authz.controlErr = refused
	_, err := f.tokens.MintEnrollmentTokenFromForm(context.Background(), enrollmentAdmin, EnrollmentMintForm{Nodes: 257, TTL: time.Hour})
	if !errors.Is(err, refused) || errors.Is(err, ErrEnrollmentFormNodes) {
		t.Errorf("err = %v, want the authorization refusal, not the count error", err)
	}
	if len(f.sink.entries) != 1 || f.sink.entries[0].Kind != AuditKindRefusal {
		t.Errorf("entries = %+v, want one audited refusal", f.sink.entries)
	}
}

// Proves EN-46.
func TestCheckEnrollmentFormNodes(t *testing.T) {
	for _, n := range []int{1, MaxEnrollmentFormNodes} {
		if err := CheckEnrollmentFormNodes(n); err != nil {
			t.Errorf("%d: %v", n, err)
		}
	}
	for _, n := range []int{0, -1, MaxEnrollmentFormNodes + 1} {
		if err := CheckEnrollmentFormNodes(n); !errors.Is(err, ErrEnrollmentFormNodes) {
			t.Errorf("%d: err = %v, want ErrEnrollmentFormNodes", n, err)
		}
	}
}

// Proves EN-31.
func TestEnrollmentTokens_TTLIsPositiveAndAtMostAYear(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second, MaxEnrollmentTokenTTL + time.Second} {
		f := newEnrollmentFix()
		_, err := f.tokens.MintEnrollmentToken(context.Background(), enrollmentAdmin, EnrollmentMint{MaxUses: 1, TTL: ttl})
		if !errors.Is(err, ErrEnrollmentTTL) || len(f.issuer.issued) != 0 {
			t.Errorf("TTL %v: err = %v, issued = %d, want ErrEnrollmentTTL and no issue", ttl, err, len(f.issuer.issued))
		}
	}
	f := newEnrollmentFix()
	if _, err := f.tokens.MintEnrollmentToken(context.Background(), enrollmentAdmin, EnrollmentMint{MaxUses: 1, TTL: MaxEnrollmentTokenTTL}); err != nil {
		t.Errorf("exactly one year was refused: %v", err)
	}
}

// Proves EN-36, EN-4.
func TestEnrollmentTokens_RecordsTheTokenIDAndNeverTheJoinString(t *testing.T) {
	f := newEnrollmentFix()
	minted, err := f.tokens.MintEnrollmentToken(context.Background(), enrollmentAdmin, goodMint())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if len(f.sink.events) != 1 || f.sink.events[0].TokenID != minted.ID() || f.sink.events[0].Principal.AccountID != enrollmentAdmin.AccountID {
		t.Fatalf("events = %+v, want one naming %s and the caller", f.sink.events, minted.ID())
	}

	typ := reflect.TypeOf(EnrollmentMintEvent{})
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Type.Kind() == reflect.String && typ.Field(i).Name != "TokenID" {
			t.Errorf("EnrollmentMintEvent has a string field %s besides TokenID", typ.Field(i).Name)
		}
	}

	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		got := fmt.Sprintf(verb, minted)
		if strings.Contains(got, enrollmentTestJoinString) || strings.Contains(got, enrollmentTestCredential) {
			t.Errorf("fmt %s of a minted token shows the join string or credential: %s", verb, got)
		}
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("minted", "token", minted)
	if strings.Contains(buf.String(), enrollmentTestJoinString) || strings.Contains(buf.String(), enrollmentTestCredential) {
		t.Errorf("slog shows the join string or credential: %s", buf.String())
	}
	if minted.Credential() != enrollmentTestCredential {
		t.Error("the caller cannot read the credential it is meant to show once")
	}
	if minted.JoinString() != enrollmentTestJoinString {
		t.Error("the caller cannot read the join string it is meant to show once")
	}
}

// Proves EN-4.
func TestEnrollmentTokens_AnUnrecordedMintIsWithdrawnAndRevealsNothing(t *testing.T) {
	f := newEnrollmentFix()
	f.sink.recordErr = errors.New("disk full")
	minted, err := f.tokens.MintEnrollmentToken(context.Background(), enrollmentAdmin, goodMint())
	if !errors.Is(err, ErrEnrollmentMintNotRecorded) {
		t.Fatalf("err = %v, want ErrEnrollmentMintNotRecorded", err)
	}
	if errors.Is(err, ErrEnrollmentTokenMayBeLive) {
		t.Errorf("err = %v claims a live token though the withdrawal succeeded", err)
	}
	if len(f.issuer.withdrawn) != 1 || f.issuer.withdrawn[0] != "tok-1" {
		t.Errorf("withdrawn = %v, want [tok-1]", f.issuer.withdrawn)
	}
	if minted.JoinString() != "" {
		t.Error("an unrecorded mint still hands back its join string")
	}
}

func TestEnrollmentTokens_AnUnrecordedMintThatCannotBeWithdrawnNamesTheLiveToken(t *testing.T) {
	f := newEnrollmentFix()
	f.sink.recordErr = errors.New("disk full")
	f.issuer.withdrawErr = errors.New("store down")
	minted, err := f.tokens.MintEnrollmentToken(context.Background(), enrollmentAdmin, goodMint())
	if !errors.Is(err, ErrEnrollmentTokenMayBeLive) {
		t.Fatalf("err = %v, want ErrEnrollmentTokenMayBeLive", err)
	}
	var live *EnrollmentTokenLiveError
	if !errors.As(err, &live) || live.TokenID != "tok-1" {
		t.Fatalf("err = %v, want an EnrollmentTokenLiveError naming tok-1", err)
	}
	if !strings.Contains(err.Error(), "tok-1") || strings.Contains(err.Error(), enrollmentTestJoinString) {
		t.Errorf("error text %q must name the token ID and never the join string", err.Error())
	}
	if minted.JoinString() != "" {
		t.Error("an unrecorded mint still hands back its join string")
	}
}

// Proves EN-44.
func TestEnrollmentTokens_MachineMinterNamingTagsIsAnAuditedRefusal(t *testing.T) {
	f := newEnrollmentFix()
	f.issuer.issueErr = ErrEnrollmentInitialTagsNeedHuman
	_, err := f.tokens.MintEnrollmentToken(context.Background(), enrollmentAdmin, EnrollmentMint{MaxUses: 1, TTL: time.Hour, InitialTags: []string{"tag:a=b"}})
	if !errors.Is(err, ErrEnrollmentInitialTagsNeedHuman) {
		t.Fatalf("err = %v", err)
	}
	if len(f.sink.entries) != 1 || f.sink.entries[0].Kind != AuditKindRefusal || len(f.sink.events) != 0 {
		t.Errorf("entries = %+v, events = %+v, want one refusal and no mint record", f.sink.entries, f.sink.events)
	}
}

func TestEnrollmentTokens_AnIssuerFailureIsReturnedUnrecorded(t *testing.T) {
	f := newEnrollmentFix()
	f.issuer.issueErr = errors.New("store down")
	_, err := f.tokens.MintEnrollmentToken(context.Background(), enrollmentAdmin, goodMint())
	if err == nil || len(f.sink.events) != 0 || len(f.sink.entries) != 0 {
		t.Errorf("err = %v, events = %d, entries = %d, want a bare error and nothing recorded", err, len(f.sink.events), len(f.sink.entries))
	}
}

func TestNewEnrollmentTokens_PanicsOnAnUnsafeComposition(t *testing.T) {
	real := &spyAuthorizer{}
	sink := &enrollmentSink{spyAuditSink: &spyAuditSink{}}
	issuer := &fakeEnrollmentIssuer{}
	good := func(authz Authorizer, s AuditSink) *Control {
		return newControl(NewRecorder(s, nil, nil), authz, noopFreezeStore{})
	}
	cases := map[string]func(){
		"nil control":    func() { NewEnrollmentTokens(nil, issuer) },
		"nil issuer":     func() { NewEnrollmentTokens(good(real, sink), nil) },
		"allow-all":      func() { NewEnrollmentTokens(good(allowAllAuthorizer{}, sink), issuer) },
		"no-op sink":     func() { NewEnrollmentTokens(good(real, noopAuditSink{}), issuer) },
		"not a recorder": func() { NewEnrollmentTokens(good(real, plainTagSink{&spyAuditSink{}}), issuer) },
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
	if NewEnrollmentTokens(good(real, sink), issuer) == nil {
		t.Error("a safe composition returned nil")
	}
}
