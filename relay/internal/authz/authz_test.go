package authz

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// The two Action shapes the gate distinguishes. Their RiskClasses are chosen
// to be the *opposite* of what a risk-class-based gate would want, so a test
// that passes here cannot be passing because risk class happened to agree:
// the Operation is read-class and the Raw Exec mutate-class, yet see
// TestRoleGate_RiskClassIsNotAnAuthorizationInput for the case that matters.
var (
	operationAction = jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}
	rawExecAction   = jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/true"}, RiskClass: jobs.RiskClassMutate}
)

func principal(role accounts.Role) capability.Principal {
	return capability.Principal{AccountID: "acct-1", Account: "someone", Role: string(role)}
}

func authorize(t *testing.T, p capability.Principal, act jobs.Action) error {
	t.Helper()
	return NewRoleGate().Authorize(context.Background(), p, act, capability.Selector{})
}

// The role ladder, asserted as one table: viewer dispatches nothing, operator
// runs Operations but not Raw Exec, admin runs both.
func TestRoleGate_Ladder(t *testing.T) {
	cases := []struct {
		role      accounts.Role
		operation bool
		rawExec   bool
	}{
		{accounts.RoleViewer, false, false},
		{accounts.RoleOperator, true, false},
		{accounts.RoleAdmin, true, true},
	}
	for _, c := range cases {
		t.Run(string(c.role), func(t *testing.T) {
			if got := authorize(t, principal(c.role), operationAction) == nil; got != c.operation {
				t.Errorf("Operation authorized = %v, want %v", got, c.operation)
			}
			if got := authorize(t, principal(c.role), rawExecAction) == nil; got != c.rawExec {
				t.Errorf("Raw Exec authorized = %v, want %v", got, c.rawExec)
			}
		})
	}
}

// Acceptance: "an operator may run_operation but is refused raw_exec". The
// refusal is recognizable via errors.Is and legible in the audit Reason.
func TestRoleGate_OperatorIsRefusedRawExec(t *testing.T) {
	err := authorize(t, principal(accounts.RoleOperator), rawExecAction)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want errors.Is(err, ErrUnauthorized)", err)
	}
	msg := err.Error()
	for _, want := range []string{"Raw Exec", "admin", "operator"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal %q does not mention %q — an audit reader needs who, what, and what it needed", msg, want)
		}
	}
}

// Fail closed on the role side: an unknown, future, or corrupted role read
// from the store authorizes nothing, rather than out-ranking admin by
// accident. (accounts.Role.AtLeast is the single comparator; this pins that
// the gate actually routes through it.)
func TestRoleGate_UnknownRolesAuthorizeNothing(t *testing.T) {
	for _, role := range []string{"", "root", "Admin", "superuser", "admin "} {
		p := capability.Principal{Account: "someone", Role: role}
		if err := authorize(t, p, operationAction); !errors.Is(err, ErrUnauthorized) {
			t.Errorf("role %q authorized an Operation: %v", role, err)
		}
		if err := authorize(t, p, rawExecAction); !errors.Is(err, ErrUnauthorized) {
			t.Errorf("role %q authorized Raw Exec: %v", role, err)
		}
	}
	if err := authorize(t, capability.Principal{}, operationAction); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("zero-value principal authorized an Operation: %v", err)
	}
}

// Fail closed on the Action side: an unrecognized kind is denied outright,
// including for an admin. A kind added later must have its floor decided
// deliberately, not inherit the weakest one by falling through.
func TestRoleGate_UnknownActionKindIsDeniedEvenForAdmin(t *testing.T) {
	unknown := jobs.Action{Kind: jobs.ActionUnspecified}
	future := jobs.Action{Kind: jobs.ActionKind(99)}

	for _, act := range []jobs.Action{unknown, future} {
		if err := authorize(t, principal(accounts.RoleAdmin), act); !errors.Is(err, ErrUnauthorized) {
			t.Errorf("action kind %v authorized for admin: %v", act.Kind, err)
		}
	}
}

// Risk class picks the blast cap (ADR-0012); it must never double as an
// authorization input. A read-class Raw Exec still requires admin — "this
// command only reads" is precisely the claim an arbitrary-command path cannot
// make on its own behalf.
func TestRoleGate_RiskClassIsNotAnAuthorizationInput(t *testing.T) {
	readRawExec := jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/cat", "/etc/hostname"}, RiskClass: jobs.RiskClassRead}
	if err := authorize(t, principal(accounts.RoleOperator), readRawExec); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("a read-class Raw Exec was authorized for an operator: %v", err)
	}

	// ...and the converse: a mutate-class Operation is still operator-level.
	// Requiring admin for it would quietly make the typed path admin-only,
	// which is the opposite of what ADR-0001's tiers are for.
	mutateOperation := jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", RiskClass: jobs.RiskClassMutate}
	if err := authorize(t, principal(accounts.RoleOperator), mutateOperation); err != nil {
		t.Fatalf("a mutate-class Operation was refused for an operator: %v", err)
	}
}
