package capability_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// callshape_rolefloor_test.go is external for the reason askable_rolefloor_test.go
// gives: authz imports capability, so the real role ladder cannot be built
// from inside package capability.

// recordingAuditSink keeps each recorded entry's Kind and Reason.
type recordingAuditSink struct {
	nopAuditSink
	mu      sync.Mutex
	entries []capability.AuditEntry
}

func (s *recordingAuditSink) Record(_ context.Context, e capability.AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, e)
	return nil
}

// TestCallShape_EmptyArgvFromAnOperatorIsUnauthorized: an operator's Raw Exec
// call with an empty argv is refused as unauthorized (EX-52) and never as
// malformed, whereas an admin's reaches the call-shape stage and is refused as
// malformed.
//
// Proves EX-67.
func TestCallShape_EmptyArgvFromAnOperatorIsUnauthorized(t *testing.T) {
	roleGate := authz.NewRoleGate()
	gate, err := approval.NewGate(nil)
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	now := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)

	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}.WithNodeLabels(map[string]string{"os": "linux"})); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	wholeFleet, err := capability.ParseSelector(capability.WholeFleetSelector)
	if err != nil {
		t.Fatalf("ParseSelector: %v", err)
	}
	act := jobs.Action{Kind: jobs.ActionRawExec, RawExecArgv: nil}

	newLayer := func(t *testing.T) (*capLayer, *recordingAuditSink) {
		sink := &recordingAuditSink{}
		return newCapService(t, capSeams{
			reg: reg, authz: roleGate, audit: sink, gate: gate,
			approvals: capability.NewMemApprovalStoreForTest(), approvalAuthz: roleGate,
			now: func() time.Time { return now },
		}), sink
	}
	principal := func(role accounts.Role) capability.Principal {
		return capability.Principal{
			AccountID: "acct-" + string(role), Account: "acct-" + string(role),
			Role: string(role), Kind: capability.PrincipalKindHuman,
		}
	}
	calls := map[string]func(*capLayer, capability.Principal) error{
		"Run": func(s *capLayer, p capability.Principal) error {
			_, err := s.Run(context.Background(), p, wholeFleet, act)
			return err
		},
		"Plan": func(s *capLayer, p capability.Principal) error {
			_, err := s.Plan(context.Background(), p, wholeFleet, act)
			return err
		},
	}

	for name, call := range calls {
		t.Run(name+"/operator", func(t *testing.T) {
			s, sink := newLayer(t)
			err := call(s, principal(accounts.RoleOperator))
			var mal *capability.MalformedCallError
			if !errors.Is(err, authz.ErrUnauthorized) || errors.As(err, &mal) {
				t.Fatalf("err = %v, want authz.ErrUnauthorized and not a malformed-call refusal", err)
			}
			if len(sink.entries) != 1 || sink.entries[0].Kind != capability.AuditKindRefusal {
				t.Errorf("audit entries = %+v, want one refusal", sink.entries)
			}
		})
		t.Run(name+"/admin", func(t *testing.T) {
			s, _ := newLayer(t)
			err := call(s, principal(accounts.RoleAdmin))
			var mal *capability.MalformedCallError
			if !errors.As(err, &mal) {
				t.Fatalf("err = %v, want a *MalformedCallError: the role gate passed and the call-shape stage refused", err)
			}
		})
	}
}
