package capability

import (
	"context"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

func TestAssertions_ContextRoundTrip(t *testing.T) {
	want := Assertions{OnBehalfOf: "ops-team", Traceparent: "00-abc-def-01", SessionRef: "conv_1", ChangeRef: "CHG-1"}
	ctx := WithAssertions(context.Background(), want)

	if got := AssertionsFromContext(ctx); got != want {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}
	if got := AssertionsFromContext(context.Background()); !got.IsZero() {
		t.Errorf("a context with no assertions returned %+v, want zero", got)
	}
}

// The load-bearing claim of the asserted lane: **a caller-controlled value can
// never widen what a caller may do.**
//
// This is asserted structurally rather than behaviourally, because behaviour
// only proves today's Authorizer ignores them. The Authorizer interface takes
// (ctx, Principal, Action, Selector) — and this test pins that an
// implementation reading the ctx it is handed finds nothing there, because
// Service.Run attaches assertions to the audit entry, never to the
// authorization call's context. If a future change routes them through, the
// recorded assertions here will start appearing and this fails.
func TestAssertionsAreNotAnAuthorizationInput(t *testing.T) {
	spy := &assertionSpyAuthorizer{}
	reg := registry.NewInMemory()
	svc := build(t, seams{reg: reg, authz: spy})

	ctx := WithAssertions(context.Background(), Assertions{
		OnBehalfOf:  "ops-team",
		SessionRef:  "conv_1",
		Traceparent: "00-abc-def-01",
		ChangeRef:   "CHG-1",
	})

	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}
	_, _ = svc.Run(ctx, Principal{AccountID: "acct-1", Account: "gleipnir", Role: "admin"}, Selector{}, act)

	if !spy.called {
		t.Fatal("the Authorizer was never called; this test proves nothing")
	}
	if !spy.sawAssertions.IsZero() {
		t.Errorf("the Authorizer could see caller-asserted attribution %+v — a value the caller controls must never reach an authorization decision",
			spy.sawAssertions)
	}
	if spy.sawPrincipal.Account != "gleipnir" {
		t.Errorf("the Authorizer saw principal %+v, want the verified acting Account", spy.sawPrincipal)
	}
}

// assertionSpyAuthorizer records whether caller-asserted attribution is
// reachable from the context an Authorizer is handed.
type assertionSpyAuthorizer struct {
	called        bool
	sawAssertions Assertions
	sawPrincipal  Principal
}

func (a *assertionSpyAuthorizer) Authorize(ctx context.Context, p Principal, _ jobs.Action, _ Selector) error {
	a.called = true
	a.sawPrincipal = p
	a.sawAssertions = AssertionsFromContext(ctx)
	return nil
}

func (a *assertionSpyAuthorizer) AuthorizeControl(ctx context.Context, p Principal, _ ControlAction) error {
	a.called = true
	a.sawPrincipal = p
	a.sawAssertions = AssertionsFromContext(ctx)
	return nil
}
