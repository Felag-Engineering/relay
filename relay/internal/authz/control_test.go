package authz

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
)

// control_test.go covers AuthorizeControl — the administrative half of the
// ladder (#397). Its dispatch sibling is covered in authz_test.go.
//
// These tests are the authoritative statement of each floor. The surfaces'
// own tests prove that a refusal renders as 403 and lands in the audit trail;
// what the floor actually IS is decided here, once.

// human builds a human Account Principal at role.
func human(role accounts.Role) capability.Principal {
	return capability.Principal{Account: "person-" + string(role), Role: string(role), Kind: capability.PrincipalKindHuman}
}

// machine builds a machine Account Principal at role — an AI-agent, a CI job,
// an Ansible playbook.
func machine(role accounts.Role) capability.Principal {
	return capability.Principal{Account: "robot-" + string(role), Role: string(role), Kind: "machine"}
}

// TestAuthorizeControl_Floors is the issue's headline acceptance: each of the
// five administrative acts refuses every role below its floor and permits
// every role at or above it, for a human Account.
func TestAuthorizeControl_Floors(t *testing.T) {
	gate := NewRoleGate()
	ctx := context.Background()

	roles := []accounts.Role{accounts.RoleViewer, accounts.RoleOperator, accounts.RoleAdmin}

	cases := []struct {
		act   capability.ControlAction
		floor accounts.Role
	}{
		{capability.ControlMintEnrollmentToken, accounts.RoleAdmin},
		{capability.ControlRevokeEnrollmentToken, accounts.RoleAdmin},
		{capability.ControlRevokeNode, accounts.RoleAdmin},
		{capability.ControlFreezeEngage, accounts.RoleOperator},
		{capability.ControlFreezeRelease, accounts.RoleAdmin},
	}

	for _, tc := range cases {
		for _, role := range roles {
			t.Run(string(tc.act)+"/"+string(role), func(t *testing.T) {
				err := gate.AuthorizeControl(ctx, human(role), tc.act)
				wantAllowed := role.AtLeast(tc.floor)
				if wantAllowed && err != nil {
					t.Fatalf("AuthorizeControl(%s, %s) = %v, want nil (floor is %s)", tc.act, role, err, tc.floor)
				}
				if !wantAllowed {
					if err == nil {
						t.Fatalf("AuthorizeControl(%s, %s) = nil, want a refusal (floor is %s)", tc.act, role, tc.floor)
					}
					if !errors.Is(err, ErrUnauthorized) {
						t.Fatalf("refusal %v does not unwrap to ErrUnauthorized; every surface's 403 mapping keys on that", err)
					}
					// The reason reaches the audit trail, so it must name the
					// rule rather than merely assert a denial.
					if !strings.Contains(err.Error(), string(tc.floor)) {
						t.Errorf("refusal %q does not name the required role %q", err, tc.floor)
					}
				}
			})
		}
	}
}

// TestAuthorizeControl_FreezeEngageIsHumanOnly is the review amendment on
// #397: a machine Account may not engage the Freeze at ANY role, while a
// human operator may. A jailbroken AI-agent halting the fleet is a denial of
// service, not a fire alarm.
func TestAuthorizeControl_FreezeEngageIsHumanOnly(t *testing.T) {
	gate := NewRoleGate()
	ctx := context.Background()

	t.Run("machine admin is refused", func(t *testing.T) {
		err := gate.AuthorizeControl(ctx, machine(accounts.RoleAdmin), capability.ControlFreezeEngage)
		if err == nil {
			t.Fatal("AuthorizeControl(freeze_engage, machine admin) = nil, want a refusal")
		}
		if !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("refusal %v does not unwrap to ErrUnauthorized", err)
		}
		// #397's acceptance: the refusal is audited with the Principal's kind,
		// and the reason string is what reaches the trail.
		if !strings.Contains(err.Error(), "machine") {
			t.Errorf("refusal %q does not name the Principal's kind", err)
		}
		if !strings.Contains(err.Error(), "human-only") {
			t.Errorf("refusal %q does not say the act is human-only; an audit reader must not read this as a role problem", err)
		}
	})

	t.Run("machine operator is refused", func(t *testing.T) {
		if err := gate.AuthorizeControl(ctx, machine(accounts.RoleOperator), capability.ControlFreezeEngage); err == nil {
			t.Fatal("AuthorizeControl(freeze_engage, machine operator) = nil, want a refusal")
		}
	})

	t.Run("unknown kind is refused", func(t *testing.T) {
		// Principal.Kind's empty value means "unknown", and every check
		// against it must treat unknown as machine (principal.go). Forgetting
		// to set the field must not be a way through.
		p := capability.Principal{Account: "unset", Role: string(accounts.RoleAdmin)}
		err := gate.AuthorizeControl(ctx, p, capability.ControlFreezeEngage)
		if err == nil {
			t.Fatal("AuthorizeControl(freeze_engage, unknown kind) = nil, want a refusal")
		}
		if !strings.Contains(err.Error(), "unknown") {
			t.Errorf("refusal %q should render the unset kind as %q rather than as an empty field", err, "unknown")
		}
	})

	t.Run("human operator is permitted", func(t *testing.T) {
		if err := gate.AuthorizeControl(ctx, human(accounts.RoleOperator), capability.ControlFreezeEngage); err != nil {
			t.Fatalf("AuthorizeControl(freeze_engage, human operator) = %v, want nil — engage must stay cheap for people (ADR-0013)", err)
		}
	})
}

// TestAuthorizeControl_MachineAdminKeepsTheOtherFour confirms the human-only
// rule is scoped to Freeze engage alone. An Ansible playbook minting an
// Enrollment Token is the standup path ADR-0010 requires to work, and a
// machine admin releasing the Freeze is deliberately still allowed: release
// is the deliberate rung, and gating it on humanity as well would leave an
// incident with no automated way back.
func TestAuthorizeControl_MachineAdminKeepsTheOtherFour(t *testing.T) {
	gate := NewRoleGate()
	ctx := context.Background()

	for _, act := range []capability.ControlAction{
		capability.ControlMintEnrollmentToken,
		capability.ControlRevokeEnrollmentToken,
		capability.ControlRevokeNode,
		capability.ControlFreezeRelease,
	} {
		if err := gate.AuthorizeControl(ctx, machine(accounts.RoleAdmin), act); err != nil {
			t.Errorf("AuthorizeControl(%s, machine admin) = %v, want nil", act, err)
		}
	}
}

// TestAuthorizeControl_UnknownActionIsDeniedForEveryRole is deny-by-default
// in the second direction, mirroring Authorize's unrecognized-kind rule: a
// ControlAction this build does not know must be refused for admin too, so a
// value added later has its floor decided in requiredControlRole rather than
// inheriting the weakest one by falling through.
func TestAuthorizeControl_UnknownActionIsDeniedForEveryRole(t *testing.T) {
	gate := NewRoleGate()
	ctx := context.Background()

	for _, role := range []accounts.Role{accounts.RoleViewer, accounts.RoleOperator, accounts.RoleAdmin} {
		err := gate.AuthorizeControl(ctx, human(role), capability.ControlAction("reconfigure_the_relay"))
		if err == nil {
			t.Fatalf("AuthorizeControl(unknown action, %s) = nil, want a refusal", role)
		}
		if !errors.Is(err, ErrUnauthorized) {
			t.Errorf("refusal %v does not unwrap to ErrUnauthorized", err)
		}
	}
}

// TestAuthorizeControl_CorruptRoleSatisfiesNothing pins the fail-closed half
// of accounts.Role.AtLeast at this gate: a role string that is not on the
// ladder is not "some role", it is no role.
func TestAuthorizeControl_CorruptRoleSatisfiesNothing(t *testing.T) {
	gate := NewRoleGate()
	p := capability.Principal{Account: "weird", Role: "superadmin", Kind: capability.PrincipalKindHuman}

	for _, act := range []capability.ControlAction{
		capability.ControlMintEnrollmentToken,
		capability.ControlRevokeEnrollmentToken,
		capability.ControlRevokeNode,
		capability.ControlFreezeEngage,
		capability.ControlFreezeRelease,
	} {
		if err := gate.AuthorizeControl(context.Background(), p, act); err == nil {
			t.Errorf("AuthorizeControl(%s, role %q) = nil, want a refusal", act, p.Role)
		}
	}
}

// TestRoleGateImplementsControlAuthorizer pins the seam: the production gate
// must satisfy capability.ControlAuthorizer, which is the type the Control
// API's Deps holds and the capability layer's Authorizer embeds. Without this
// the compiler only notices at the composition root.
func TestRoleGateImplementsControlAuthorizer(t *testing.T) {
	var _ capability.ControlAuthorizer = NewRoleGate()
	var _ capability.Authorizer = NewRoleGate()
}
