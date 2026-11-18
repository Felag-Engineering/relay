package capability

import (
	"context"
	"errors"
	"testing"
)

// controlActs lists the three entry points beside the ControlAction each asks
// the Authorizer about.
var controlActs = []struct {
	name  string
	call  func(*Control, context.Context, Principal) error
	asked ControlAction
}{
	{"mint", (*Control).AuthorizeEnrollmentTokenMint, ControlMintEnrollmentToken},
	{"token revoke", (*Control).AuthorizeEnrollmentTokenRevoke, ControlRevokeEnrollmentToken},
	{"node revoke", (*Control).AuthorizeNodeRevoke, ControlRevokeNode},
}

func TestControlActs_EachAsksTheAuthorizerAtItsOwnControlAction(t *testing.T) {
	for _, tc := range controlActs {
		t.Run(tc.name, func(t *testing.T) {
			gate := &spyAuthorizer{}
			c := newControl(NewRecorder(&spyAuditSink{}, nil, nil), gate, new(fakeFreezeStore))

			if err := tc.call(c, context.Background(), Principal{Account: "a", Role: "admin"}); err != nil {
				t.Fatalf("error = %v, want nil", err)
			}
			if len(gate.controlCalls) != 1 || gate.controlCalls[0] != tc.asked {
				t.Errorf("controlCalls = %v, want exactly [%s]", gate.controlCalls, tc.asked)
			}
		})
	}
}

func TestControlActs_ARefusalIsAuditedAsARefusalWithThePrincipalAndAssertions(t *testing.T) {
	want := Assertions{OnBehalfOf: "ops-team", SessionRef: "conv_1"}
	p := Principal{Account: "gleipnir", Role: "operator", Kind: "machine"}
	for _, tc := range controlActs {
		t.Run(tc.name, func(t *testing.T) {
			gate := &spyAuthorizer{controlErr: errRefused}
			sink := &spyAuditSink{}
			store := new(fakeFreezeStore)
			c := newControl(NewRecorder(sink, nil, nil), gate, store)

			err := tc.call(c, WithAssertions(context.Background(), want), p)
			if !errors.Is(err, errRefused) {
				t.Fatalf("error = %v, want the gate's refusal", err)
			}
			if len(sink.entries) != 1 {
				t.Fatalf("audit entries = %d, want exactly 1 refusal", len(sink.entries))
			}
			got := sink.entries[0]
			if got.Kind != AuditKindRefusal {
				t.Errorf("Kind = %v, want AuditKindRefusal", got.Kind)
			}
			if got.Principal != p {
				t.Errorf("Principal = %+v, want %+v", got.Principal, p)
			}
			if got.Reason != errRefused.Error() {
				t.Errorf("Reason = %q, want %q", got.Reason, errRefused.Error())
			}
			if got.Asserted != want {
				t.Errorf("Asserted = %+v, want %+v: the record keeps the caller's claims, only the Authorizer is denied them", got.Asserted, want)
			}
			if len(got.Selector.Predicates) != 0 || got.Action.Kind != 0 || got.JobID != "" {
				t.Errorf("entry carries a Selector, Action or Job (%+v, %v, %q) for an act that has none", got.Selector, got.Action.Kind, got.JobID)
			}
			if len(sink.freezeCalls) != 0 || len(store.engageCalls) != 0 {
				t.Errorf("a Freeze was recorded or engaged by a refused control act")
			}
		})
	}
}

func TestControlActs_AnAllowedActRecordsNothing(t *testing.T) {
	for _, tc := range controlActs {
		t.Run(tc.name, func(t *testing.T) {
			sink := &spyAuditSink{}
			c := newControl(NewRecorder(sink, nil, nil), &spyAuthorizer{}, new(fakeFreezeStore))

			if err := tc.call(c, context.Background(), Principal{Account: "a", Role: "admin"}); err != nil {
				t.Fatalf("error = %v, want nil", err)
			}
			if len(sink.entries) != 0 {
				t.Errorf("audit entries = %+v, want none: the act's own record belongs to whoever performs it", sink.entries)
			}
		})
	}
}

func TestControlActs_AnUnrecordedRefusalIsStillTheRefusal(t *testing.T) {
	recordErr := errors.New("test: audit store down")
	for _, tc := range controlActs {
		t.Run(tc.name, func(t *testing.T) {
			sink := &spyAuditSink{err: recordErr}
			c := newControl(NewRecorder(sink, nil, nil), &spyAuthorizer{controlErr: errRefused}, new(fakeFreezeStore))

			err := tc.call(c, context.Background(), Principal{Account: "a", Role: "viewer"})
			if !errors.Is(err, errRefused) || !errors.Is(err, recordErr) {
				t.Fatalf("error = %v, want both the refusal and the record failure", err)
			}
			if got := FirstRefusal(err); got != errRefused {
				t.Errorf("FirstRefusal = %v, want %v", got, errRefused)
			}
		})
	}
}

// Pins the three control-act entry points: authorizing needs no assertions.
func TestControlActs_AuthorizeWithoutAssertions(t *testing.T) {
	p := Principal{Account: "gleipnir", Role: "admin", Kind: "machine"}
	ctx := WithAssertions(context.Background(), Assertions{OnBehalfOf: "ops-team", ChangeRef: "CHG-1"})
	for _, tc := range controlActs {
		t.Run(tc.name, func(t *testing.T) {
			spy := &assertionSpyAuthorizer{}
			c := newControl(NewRecorder(&spyAuditSink{}, nil, nil), spy, new(fakeFreezeStore))

			if err := tc.call(c, ctx, p); err != nil {
				t.Fatalf("error = %v, want nil", err)
			}
			if !spy.called {
				t.Fatal("the Authorizer was never asked")
			}
			if !spy.sawAssertions.IsZero() {
				t.Errorf("the Authorizer saw %+v, want none: a decision never rests on caller-asserted attribution", spy.sawAssertions)
			}
			if spy.sawPrincipal != p {
				t.Errorf("the Authorizer saw Principal %+v, want %+v", spy.sawPrincipal, p)
			}
		})
	}
}
