package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// operationAction and rawExecAction are the two Action shapes Staged must
// treat identically (every ActionKind, every RiskClass, is authorized for an
// admin Role and denied for everyone else).
var (
	operationAction = jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}
	rawExecAction   = jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: []string{"/bin/true"}, RiskClass: jobs.RiskClassMutate}
)

func TestStaged_AdminAuthorized(t *testing.T) {
	s := NewStaged()
	admin := capability.Principal{Account: "founding-admin", Role: "admin"}

	t.Run("Operation action", func(t *testing.T) {
		if err := s.Authorize(context.Background(), admin, operationAction, capability.Selector{}); err != nil {
			t.Fatalf("Authorize(admin, operation): %v, want nil", err)
		}
	})

	t.Run("Raw Exec action", func(t *testing.T) {
		if err := s.Authorize(context.Background(), admin, rawExecAction, capability.Selector{}); err != nil {
			t.Fatalf("Authorize(admin, raw_exec): %v, want nil", err)
		}
	})
}

func TestStaged_NonAdminDenied(t *testing.T) {
	s := NewStaged()

	cases := []struct {
		name string
		p    capability.Principal
	}{
		{"operator role", capability.Principal{Account: "someone", Role: "operator"}},
		{"viewer role", capability.Principal{Account: "someone", Role: "viewer"}},
		{"empty role", capability.Principal{Account: "someone", Role: ""}},
		{"unknown role", capability.Principal{Account: "someone", Role: "root"}},
		{"zero-value principal", capability.Principal{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.Authorize(context.Background(), tc.p, operationAction, capability.Selector{})
			if err == nil {
				t.Fatalf("Authorize(%+v): got nil, want ErrUnauthorized", tc.p)
			}
			if !errors.Is(err, ErrUnauthorized) {
				t.Errorf("Authorize(%+v): err = %v, want errors.Is(err, ErrUnauthorized)", tc.p, err)
			}
		})
	}
}

func TestStaged_NonAdminDeniedForRawExec(t *testing.T) {
	s := NewStaged()
	operator := capability.Principal{Account: "someone", Role: "operator"}

	err := s.Authorize(context.Background(), operator, rawExecAction, capability.Selector{})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Authorize(operator, raw_exec): err = %v, want errors.Is(err, ErrUnauthorized)", err)
	}
}
