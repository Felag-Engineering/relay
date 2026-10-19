package authz

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
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
		{capability.ControlCancelJob, accounts.RoleOperator},
		{capability.ControlAccountRead, accounts.RoleAdmin},
		{capability.ControlAccountCreate, accounts.RoleAdmin},
		{capability.ControlAccountRole, accounts.RoleAdmin},
		{capability.ControlAccountEnable, accounts.RoleAdmin},
		{capability.ControlAccountDisable, accounts.RoleAdmin},
		{capability.ControlAPITokenRead, accounts.RoleAdmin},
		{capability.ControlAPITokenMint, accounts.RoleAdmin},
		{capability.ControlAPITokenRevoke, accounts.RoleAdmin},
		{capability.ControlPolicyAlias, accounts.RoleAdmin},
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

// TestAuthorizeControl_MachineAdminKeepsTheOthers confirms the human-only
// rule is scoped to Freeze engage alone. An Ansible playbook minting an
// Enrollment Token is the standup path ADR-0010 requires to work, a machine
// admin releasing the Freeze is deliberately still allowed — release is the
// deliberate rung, and gating it on humanity as well would leave an incident
// with no automated way back — and a machine admin cancelling a Job is the
// AI-agent stopping its own dispatch that #346 requires to work. The eight
// Account/API-Token administration acts (#653) join this list on the same
// status-quo-preservation reasoning: a machine admin creating an Account or
// minting an API Token is a live, tested surface today (see
// TestAuthorizeControl_Floors and authz.go's requiredControlRole doc
// comment), and narrowing it is an owner decision, not settled here.
func TestAuthorizeControl_MachineAdminKeepsTheOthers(t *testing.T) {
	gate := NewRoleGate()
	ctx := context.Background()

	for _, act := range []capability.ControlAction{
		capability.ControlMintEnrollmentToken,
		capability.ControlRevokeEnrollmentToken,
		capability.ControlRevokeNode,
		capability.ControlFreezeRelease,
		capability.ControlCancelJob,
		capability.ControlAccountRead,
		capability.ControlAccountCreate,
		capability.ControlAccountRole,
		capability.ControlAccountEnable,
		capability.ControlAccountDisable,
		capability.ControlAPITokenRead,
		capability.ControlAPITokenMint,
		capability.ControlAPITokenRevoke,
	} {
		if err := gate.AuthorizeControl(ctx, machine(accounts.RoleAdmin), act); err != nil {
			t.Errorf("AuthorizeControl(%s, machine admin) = %v, want nil", act, err)
		}
	}
}

// TestAuthorizeControl_MachineOperatorMayCancelAJob pins #346's decision on
// its own: cancel is not human-only at any role, unlike Freeze engage.
func TestAuthorizeControl_MachineOperatorMayCancelAJob(t *testing.T) {
	gate := NewRoleGate()
	if err := gate.AuthorizeControl(context.Background(), machine(accounts.RoleOperator), capability.ControlCancelJob); err != nil {
		t.Fatalf("AuthorizeControl(cancel_job, machine operator) = %v, want nil (#346: an AI-agent may cancel its own dispatch)", err)
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
		capability.ControlCancelJob,
		capability.ControlAccountRead,
		capability.ControlAccountCreate,
		capability.ControlAccountRole,
		capability.ControlAccountEnable,
		capability.ControlAccountDisable,
		capability.ControlAPITokenRead,
		capability.ControlAPITokenMint,
		capability.ControlAPITokenRevoke,
		capability.ControlPolicyAlias,
	} {
		if err := gate.AuthorizeControl(context.Background(), p, act); err == nil {
			t.Errorf("AuthorizeControl(%s, role %q) = nil, want a refusal", act, p.Role)
		}
	}
}

// TestAuthorizeControl_PolicyAliasIsAdminAndHumanOnly pins the alias write's
// floor: admin, and a human Account. A machine admin is refused it, with the
// human-only reason rather than a role one.
func TestAuthorizeControl_PolicyAliasIsAdminAndHumanOnly(t *testing.T) {
	gate := NewRoleGate()
	ctx := context.Background()

	if err := gate.AuthorizeControl(ctx, human(accounts.RoleAdmin), capability.ControlPolicyAlias); err != nil {
		t.Errorf("human admin refused: %v", err)
	}
	for _, role := range []accounts.Role{accounts.RoleViewer, accounts.RoleOperator} {
		if err := gate.AuthorizeControl(ctx, human(role), capability.ControlPolicyAlias); !errors.Is(err, ErrUnauthorized) {
			t.Errorf("human %s = %v, want ErrUnauthorized", role, err)
		}
	}
	err := gate.AuthorizeControl(ctx, machine(accounts.RoleAdmin), capability.ControlPolicyAlias)
	if !errors.Is(err, ErrUnauthorized) || !strings.Contains(err.Error(), "human-only") {
		t.Errorf("machine admin = %v, want a human-only ErrUnauthorized", err)
	}
	unknownKind := capability.Principal{Account: "x", Role: string(accounts.RoleAdmin)}
	if err := gate.AuthorizeControl(ctx, unknownKind, capability.ControlPolicyAlias); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("unknown-kind admin = %v, want ErrUnauthorized", err)
	}
}

// TestRoleGate_AccountAdministrationRequiresAdmin is #653's headline
// acceptance for the ladder: all eight Account/API-Token administration acts
// refuse viewer and operator and permit admin, for both human and machine
// Accounts (status-quo preservation — see requiredControlRole's doc comment
// on humanOnly).
func TestRoleGate_AccountAdministrationRequiresAdmin(t *testing.T) {
	gate := NewRoleGate()
	ctx := context.Background()

	acts := []capability.ControlAction{
		capability.ControlAccountRead,
		capability.ControlAccountCreate,
		capability.ControlAccountRole,
		capability.ControlAccountEnable,
		capability.ControlAccountDisable,
		capability.ControlAPITokenRead,
		capability.ControlAPITokenMint,
		capability.ControlAPITokenRevoke,
	}
	roles := []accounts.Role{accounts.RoleViewer, accounts.RoleOperator, accounts.RoleAdmin}

	checked := 0
	for _, act := range acts {
		for _, role := range roles {
			for _, p := range []capability.Principal{human(role), machine(role)} {
				checked++
				err := gate.AuthorizeControl(ctx, p, act)
				wantAllowed := role.AtLeast(accounts.RoleAdmin)
				if wantAllowed && err != nil {
					t.Errorf("AuthorizeControl(%s, %s %s) = %v, want nil", act, p.Kind, role, err)
				}
				if !wantAllowed {
					if err == nil {
						t.Errorf("AuthorizeControl(%s, %s %s) = nil, want a refusal", act, p.Kind, role)
					} else if !errors.Is(err, ErrUnauthorized) {
						t.Errorf("refusal %v does not unwrap to ErrUnauthorized", err)
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("checked 0 cases — the guard must actually inspect something")
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
