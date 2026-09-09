package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/authz"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/enroll"
)

// role_gates_test.go is #397's acceptance at the Control API surface: three
// route families authenticated the caller and then never checked their role,
// so a viewer could mint a token stamping `relay:` labels, revoke Nodes, and
// engage or release the fleet Freeze.
//
// Every refusal here comes from the production authz.RoleGate — the same
// object the capability layer authorizes dispatches with. That is deliberate
// and is the whole shape of the fix: what the floors ARE is decided once, in
// authz.requiredControlRole (and tested in that package); what these tests
// own is that each route reaches the gate, refuses with 403, changes nothing,
// and leaves the refusal in the audit trail.

// recordingMinter is a TokenMinter that counts calls and mints nothing. The
// mint path's happy case is covered against the real enroll.Service in
// api_test.go; a refusal test needs only "was it reached at all".
type recordingMinter struct{ calls int }

func (m *recordingMinter) Create(_ context.Context, scope []string, _ time.Duration, _ ...enroll.Option) (*enroll.Token, string, error) {
	m.calls++
	return &enroll.Token{ID: "tok-minted", Scope: scope, ExpiresAt: fixedNow().Add(time.Hour)}, "plaintext", nil
}

// newRoleFixture mounts the full route table behind a real Authenticator that
// authenticates testCredential as an Account with the given role and kind,
// with the production RoleGate wired as Deps.Authz.
func newRoleFixture(t *testing.T, role accounts.Role, kind accounts.Kind, d Deps) http.Handler {
	t.Helper()
	if d.Authz == nil {
		d.Authz = authz.NewRoleGate()
	}
	if d.Now == nil {
		d.Now = fixedNow
	}
	authn := controlplane.NewAuthenticator(roleVerifier{credential: testCredential, role: role, kind: kind})
	mux := http.NewServeMux()
	Register(mux, d)
	return authn.Middleware(mux)
}

// wantRefusal asserts a 403 whose body carries the gate's own reason, and
// exactly one audit.KindRefusal record attributed to the caller.
func wantRefusal(t *testing.T, rec *httptest.ResponseRecorder, auditor *fakeAuditor, role accounts.Role) {
	t.Helper()
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
	records := auditor.all()
	if len(records) != 1 {
		t.Fatalf("audit records = %d, want exactly 1 refusal; refusals are the most interesting audit event", len(records))
	}
	got := records[0]
	if got.Kind != audit.KindRefusal {
		t.Errorf("audit Kind = %q, want %q", got.Kind, audit.KindRefusal)
	}
	if !strings.Contains(got.Principal, string(role)) {
		t.Errorf("audit Principal = %q, want it to name the refused role %q", got.Principal, role)
	}
	if got.Attribution.Verified.Role != string(role) {
		t.Errorf("audit verified role = %q, want %q", got.Attribution.Verified.Role, role)
	}
	if got.Reason == "" {
		t.Error("audit Reason is empty; a refusal that does not say why is not a record of anything")
	}
}

// -----------------------------------------------------------------------
// Enrollment Token mint — admin (ADR-0032 §5)
// -----------------------------------------------------------------------

// TestMintToken_RequiresAdmin is the sharp edge of #397: a token's scope
// becomes the enrolling Node's `relay:` labels, the namespace reserved for
// the security-sensitive lane. A viewer minting one manufactures Nodes that
// quarantine and secret distribution will treat as authoritative.
func TestMintToken_RequiresAdmin(t *testing.T) {
	body := mintTokenRequest{Scope: []string{"relay:env=prod"}, TTLSeconds: 3600}

	for _, role := range []accounts.Role{accounts.RoleViewer, accounts.RoleOperator} {
		t.Run(string(role)+" is refused", func(t *testing.T) {
			minter := &recordingMinter{}
			auditor := &fakeAuditor{}
			h := newRoleFixture(t, role, accounts.KindMachine, Deps{Tokens: minter, Audit: auditor})

			rec := do(t, h, http.MethodPost, "/api/v1/enrollment-tokens", body)
			wantRefusal(t, rec, auditor, role)

			// Nothing was minted: the refusal must precede the act, not
			// annotate it.
			if minter.calls != 0 {
				t.Errorf("TokenMinter.Create called %d times on a refused mint, want 0", minter.calls)
			}
		})
	}

	t.Run("admin is permitted", func(t *testing.T) {
		auditor := &fakeAuditor{}
		h := newRoleFixture(t, accounts.RoleAdmin, accounts.KindMachine, Deps{
			Tokens: enroll.NewService(enroll.NewMemoryRepository()), Audit: auditor,
		})

		rec := do(t, h, http.MethodPost, "/api/v1/enrollment-tokens", body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("admin mint: status = %d, want 201; body = %s", rec.Code, rec.Body.String())
		}
		if records := auditor.all(); len(records) != 1 || records[0].Kind != audit.KindTokenMint {
			t.Errorf("audit records = %+v, want exactly one token_mint", records)
		}
	})
}

// -----------------------------------------------------------------------
// Enrollment Token revoke — admin
// -----------------------------------------------------------------------

// TestRevokeToken_RequiresAdmin covers the route #397's table did not name,
// found by the structural guard the issue asked for. Revoking a token
// cascade-revokes every Node it enrolled, which is the same availability
// blast radius as revoking those Nodes one at a time.
func TestRevokeToken_RequiresAdmin(t *testing.T) {
	for _, role := range []accounts.Role{accounts.RoleViewer, accounts.RoleOperator} {
		t.Run(string(role)+" is refused", func(t *testing.T) {
			tr := &fakeTokenRevoker{}
			auditor := &fakeAuditor{}
			h := newRoleFixture(t, role, accounts.KindMachine, Deps{TokenRevoker: tr, Audit: auditor})

			rec := do(t, h, http.MethodDelete, "/api/v1/enrollment-tokens/tok-1", nil)
			wantRefusal(t, rec, auditor, role)

			if len(tr.calledWith) != 0 {
				t.Errorf("TokenRevoker.RevokeToken called with %v on a refused request", tr.calledWith)
			}
		})
	}

	t.Run("admin is permitted", func(t *testing.T) {
		tr := &fakeTokenRevoker{}
		auditor := &fakeAuditor{}
		h := newRoleFixture(t, accounts.RoleAdmin, accounts.KindMachine, Deps{TokenRevoker: tr, Audit: auditor})

		rec := do(t, h, http.MethodDelete, "/api/v1/enrollment-tokens/tok-1", nil)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("admin revoke: status = %d, want 204; body = %s", rec.Code, rec.Body.String())
		}
		if len(tr.calledWith) != 1 || tr.calledWith[0] != "tok-1" {
			t.Errorf("TokenRevoker.RevokeToken calls = %v, want [tok-1]", tr.calledWith)
		}
	})
}

// -----------------------------------------------------------------------
// Node revoke — admin (ADR-0020's incident ladder)
// -----------------------------------------------------------------------

func TestRevokeNode_RequiresAdmin(t *testing.T) {
	for _, role := range []accounts.Role{accounts.RoleViewer, accounts.RoleOperator} {
		t.Run(string(role)+" is refused", func(t *testing.T) {
			nr := &fakeNodeRevoker{}
			auditor := &fakeAuditor{}
			h := newRoleFixture(t, role, accounts.KindMachine, Deps{Nodes: nr, Audit: auditor})

			rec := do(t, h, http.MethodPost, "/api/v1/nodes/node-abc/revoke", nil)
			wantRefusal(t, rec, auditor, role)

			if len(nr.calledWith) != 0 {
				t.Errorf("NodeRevoker.RevokeNode called with %v on a refused request; the Tunnel must stay up", nr.calledWith)
			}
		})
	}

	t.Run("admin is permitted", func(t *testing.T) {
		nr := &fakeNodeRevoker{}
		auditor := &fakeAuditor{}
		h := newRoleFixture(t, accounts.RoleAdmin, accounts.KindMachine, Deps{Nodes: nr, Audit: auditor})

		rec := do(t, h, http.MethodPost, "/api/v1/nodes/node-abc/revoke",
			map[string]string{"reason": "role gate fixture"})
		if rec.Code != http.StatusNoContent {
			t.Fatalf("admin revoke: status = %d, want 204; body = %s", rec.Code, rec.Body.String())
		}
		if len(nr.calledWith) != 1 || nr.calledWith[0] != "node-abc" {
			t.Errorf("NodeRevoker.RevokeNode calls = %v, want [node-abc]", nr.calledWith)
		}
	})
}

// -----------------------------------------------------------------------
// Freeze — engage: human operator+; release: admin
// -----------------------------------------------------------------------

// newFreezeFixture mounts the routes with a Freezer that runs the production
// RoleGate, standing in for the capability layer (see fakeFreezer).
func newFreezeFixture(t *testing.T, role accounts.Role, kind accounts.Kind) (http.Handler, *fakeFreezer) {
	t.Helper()
	fz := &fakeFreezer{gate: authz.NewRoleGate()}
	return newRoleFixture(t, role, kind, Deps{Freeze: fz, Audit: &fakeAuditor{}}), fz
}

// TestFreezeEngage_RequiresHumanOperator is the review amendment on #397: the
// floor is `operator`, and engaging is human-only whatever the role.
func TestFreezeEngage_RequiresHumanOperator(t *testing.T) {
	t.Run("human operator is permitted", func(t *testing.T) {
		h, fz := newFreezeFixture(t, accounts.RoleOperator, accounts.KindHuman)

		rec := do(t, h, http.MethodPost, "/api/v1/freeze/engage", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
		}
		if len(fz.engageCalls) != 1 {
			t.Fatalf("EngageFreeze calls = %d, want 1", len(fz.engageCalls))
		}
		if !fz.engageCalls[0].Human() {
			t.Error("the Principal the route handed the capability layer is not marked human; the gate cannot answer the kind question without it")
		}
	})

	t.Run("machine admin is refused", func(t *testing.T) {
		h, _ := newFreezeFixture(t, accounts.RoleAdmin, accounts.KindMachine)

		rec := do(t, h, http.MethodPost, "/api/v1/freeze/engage", nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (a machine Account must not be able to halt the fleet at any role); body = %s",
				rec.Code, rec.Body.String())
		}
		if body := rec.Body.String(); !strings.Contains(body, "human-only") {
			t.Errorf("body = %s, want it to state the human-only rule rather than read as a role problem", body)
		}
	})

	t.Run("human viewer is refused", func(t *testing.T) {
		h, _ := newFreezeFixture(t, accounts.RoleViewer, accounts.KindHuman)

		rec := do(t, h, http.MethodPost, "/api/v1/freeze/engage", nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
		}
	})
}

// TestFreezeRelease_RequiresAdmin is ADR-0013's fire-alarm asymmetry: anyone
// (human) may pull the handle, the chief clears re-entry.
func TestFreezeRelease_RequiresAdmin(t *testing.T) {
	body := freezeReleaseRequest{Reason: "incident closed"}

	for _, role := range []accounts.Role{accounts.RoleViewer, accounts.RoleOperator} {
		t.Run(string(role)+" is refused", func(t *testing.T) {
			h, _ := newFreezeFixture(t, role, accounts.KindHuman)

			rec := do(t, h, http.MethodPost, "/api/v1/freeze/release", body)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
			}
		})
	}

	t.Run("admin is permitted", func(t *testing.T) {
		h, fz := newFreezeFixture(t, accounts.RoleAdmin, accounts.KindHuman)

		rec := do(t, h, http.MethodPost, "/api/v1/freeze/release", body)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
		}
		if len(fz.releaseCalls) != 1 || fz.releaseCalls[0].Reason != body.Reason {
			t.Errorf("ReleaseFreeze calls = %+v, want one carrying the reason", fz.releaseCalls)
		}
	})

	t.Run("a machine admin may still release", func(t *testing.T) {
		// Deliberate: the human-only rule is scoped to engage. Gating release
		// on humanity as well would leave an incident with no automated way
		// back, which is the opposite of what the asymmetry is for.
		h, _ := newFreezeFixture(t, accounts.RoleAdmin, accounts.KindMachine)

		rec := do(t, h, http.MethodPost, "/api/v1/freeze/release", body)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
		}
	})
}

// TestFreezeRelease_RequiresAReason pins ADR-0013's audited-reason rule on
// the route, for an admin who would otherwise be permitted.
func TestFreezeRelease_RequiresAReason(t *testing.T) {
	for _, reason := range []string{"", "   "} {
		h, fz := newFreezeFixture(t, accounts.RoleAdmin, accounts.KindHuman)

		rec := do(t, h, http.MethodPost, "/api/v1/freeze/release", freezeReleaseRequest{Reason: reason})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("reason %q: status = %d, want 400; body = %s", reason, rec.Code, rec.Body.String())
		}
		if len(fz.releaseCalls) != 0 {
			t.Errorf("reason %q: ReleaseFreeze was called on a reasonless release", reason)
		}
	}
}

// -----------------------------------------------------------------------
// The unwired-gate direction
// -----------------------------------------------------------------------

// TestAdministrativeRoutes_RefuseWithoutAGate is the fail-closed direction.
// #397 happened because an ungated administrative route failed OPEN and
// nothing said so; a Deps with no Authz must therefore be loud and closed,
// even for an admin, rather than quietly permissive.
func TestAdministrativeRoutes_RefuseWithoutAGate(t *testing.T) {
	cases := []struct {
		method, path string
		body         any
		deps         Deps
	}{
		{http.MethodPost, "/api/v1/enrollment-tokens",
			mintTokenRequest{Scope: []string{"relay:env=prod"}, TTLSeconds: 3600},
			Deps{Tokens: enroll.NewService(enroll.NewMemoryRepository()), Audit: &fakeAuditor{}}},
		{http.MethodDelete, "/api/v1/enrollment-tokens/tok-1", nil,
			Deps{TokenRevoker: &fakeTokenRevoker{}, Audit: &fakeAuditor{}}},
		{http.MethodPost, "/api/v1/nodes/node-abc/revoke", nil,
			Deps{Nodes: &fakeNodeRevoker{}, Audit: &fakeAuditor{}}},
	}

	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			d := tc.deps
			d.Now = fixedNow
			// Explicitly NOT newRoleFixture: that helper supplies the
			// production gate, and the point here is its absence.
			authn := controlplane.NewAuthenticator(staticVerifier{credential: testCredential})
			mux := http.NewServeMux()
			Register(mux, d)
			h := authn.Middleware(mux)

			rec := do(t, h, tc.method, tc.path, tc.body)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500 — an unwired gate must refuse, not fall open", rec.Code)
			}
		})
	}
}
