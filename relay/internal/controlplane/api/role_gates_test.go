package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/relay/relay/internal/enroll"
)

// role_gates_test.go is #397's acceptance at the Control API surface: three
// route families authenticated the caller and then never checked their role,
// so a viewer could mint a token naming initial tags, revoke Nodes, and
// engage or release the fleet Freeze.
//
// Every refusal here comes from the production authz.RoleGate — the same
// object the capability layer authorizes dispatches with. That is deliberate
// and is the whole shape of the fix: what the floors ARE is decided once, in
// authz.requiredControlRole (and tested in that package); what these tests
// own is that each route reaches the gate, refuses with 403, changes nothing,
// and leaves the refusal in the audit trail.

// recordingMinter is a TokenMinter that counts calls and delegates to the real
// capability mint. The mint path's happy case is covered in api_test.go; a
// refusal test needs only "was it reached at all".
type recordingMinter struct {
	calls int
	inner TokenMinter
}

func newRecordingMinter(t *testing.T) *recordingMinter {
	t.Helper()
	return &recordingMinter{inner: newTestEnrollmentTokens(t, enroll.NewService(enroll.NewMemoryRepository()))}
}

func (m *recordingMinter) MintEnrollmentToken(ctx context.Context, p capability.Principal, req capability.EnrollmentMint) (capability.MintedEnrollmentToken, error) {
	m.calls++
	return m.inner.MintEnrollmentToken(ctx, p, req)
}

// newRoleFixture mounts the full route table behind a real Authenticator that
// authenticates testCredential as an Account with the given role and kind,
// with a real capability Control over the production RoleGate wired as
// Deps.Gate, unless the test supplies its own.
func newRoleFixture(t *testing.T, role accounts.Role, kind accounts.Kind, d Deps) http.Handler {
	t.Helper()
	if d.Gate == nil {
		d.Gate = newTestGate(new(fakeCapabilityAuditSink))
	}
	authn := controlplane.NewAuthenticator(roleVerifier{credential: testCredential, role: role, kind: kind})
	mux := http.NewServeMux()
	Register(mux, d)
	return authn.Middleware(mux)
}

// newTestGate is the capability layer's authorization of the administrative
// routes, over the production RoleGate, recording its refusals to sink.
func newTestGate(sink capability.AuditSink) ControlGate {
	return capability.NewControl(capability.NewRecorder(sink, nil, nil), authz.NewRoleGate(), neverFrozen{})
}

// wantLayerRefusal asserts a 403 whose body carries the gate's own reason,
// exactly one refusal recorded by the capability layer attributed to the
// caller, and no second record from the surface.
func wantLayerRefusal(t *testing.T, rec *httptest.ResponseRecorder, sink *mintSink, role accounts.Role) {
	t.Helper()
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
	refusals := sink.refusals()
	if len(refusals) != 1 {
		t.Fatalf("layer refusals = %d, want exactly 1; refusals are the most interesting audit event", len(refusals))
	}
	got := refusals[0]
	if got.Principal.Role != string(role) {
		t.Errorf("refusal Principal.Role = %q, want %q", got.Principal.Role, role)
	}
	if got.Principal.Account == "" {
		t.Error("refusal Principal.Account is empty; the refusal must name who was refused")
	}
	if got.Reason == "" {
		t.Error("refusal Reason is empty; a refusal that does not say why is not a record of anything")
	}
	var problem struct {
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode problem body %q: %v", rec.Body.String(), err)
	}
	if problem.Detail != got.Reason {
		t.Errorf("problem detail = %q, want the recorded Reason %q", problem.Detail, got.Reason)
	}
	if events := sink.revokeEvents(); len(events) != 0 {
		t.Errorf("revoke events = %+v, want none: a refused caller revokes nothing", events)
	}
}

// -----------------------------------------------------------------------
// Enrollment Token mint — admin (ADR-0032 §5)
// -----------------------------------------------------------------------

// TestMintToken_RequiresAdmin is the sharp edge of #397: a token's initial tags
// become each enrolling Node's first tags, which a Selector then targets. Only
// an admin mints one.
// Proves EN-1, EN-23.
func TestMintToken_RequiresAdmin(t *testing.T) {
	body := mintTokenRequest{TTLSeconds: 3600, MaxUses: 1}

	for _, role := range []accounts.Role{accounts.RoleViewer, accounts.RoleOperator} {
		t.Run(string(role)+" is refused", func(t *testing.T) {
			minter := newRecordingMinter(t)
			sink := newMintSink()
			h := newRoleFixture(t, role, accounts.KindMachine, Deps{Tokens: minter, Gate: newTestGate(sink)})

			rec := do(t, h, http.MethodPost, "/api/v1/enrollment-tokens", body)
			wantLayerRefusal(t, rec, sink, role)

			// Nothing was minted: the refusal must precede the act, not
			// annotate it.
			if minter.calls != 0 {
				t.Errorf("TokenMinter.Create called %d times on a refused mint, want 0", minter.calls)
			}
		})
	}

	t.Run("admin is permitted", func(t *testing.T) {
		sink := newMintSink()
		h := newRoleFixture(t, accounts.RoleAdmin, accounts.KindMachine, Deps{
			Tokens: newTestEnrollmentTokensWithSink(t, enroll.NewService(enroll.NewMemoryRepository()), sink),
		})

		rec := do(t, h, http.MethodPost, "/api/v1/enrollment-tokens", body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("admin mint: status = %d, want 201; body = %s", rec.Code, rec.Body.String())
		}
		if events := sink.mintEvents(); len(events) != 1 {
			t.Errorf("capability mint events = %+v, want exactly one", events)
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
// Proves EN-23.
func TestRevokeToken_RequiresAdmin(t *testing.T) {
	for _, role := range []accounts.Role{accounts.RoleViewer, accounts.RoleOperator} {
		t.Run(string(role)+" is refused", func(t *testing.T) {
			tr := &fakeTokenRevoker{}
			sink := newMintSink()
			h := newRoleFixture(t, role, accounts.KindMachine, Deps{Revocations: newTestRevocations(sink, revokers{tr: tr})})

			rec := do(t, h, http.MethodDelete, "/api/v1/enrollment-tokens/tok-1", nil)
			wantLayerRefusal(t, rec, sink, role)

			if len(tr.calledWith) != 0 {
				t.Errorf("TokenRevoker.RevokeToken called with %v on a refused request", tr.calledWith)
			}
		})
	}

	t.Run("admin is permitted", func(t *testing.T) {
		tr := &fakeTokenRevoker{}
		h := newRoleFixture(t, accounts.RoleAdmin, accounts.KindMachine, Deps{Revocations: newTestRevocations(newMintSink(), revokers{tr: tr})})

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
			sink := newMintSink()
			h := newRoleFixture(t, role, accounts.KindMachine, Deps{
				Revocations: newTestRevocations(sink, revokers{nr: nr}),
				Gate:        newTestGate(sink),
			})

			rec := do(t, h, http.MethodPost, "/api/v1/nodes/node-abc/revoke", nil)
			wantLayerRefusal(t, rec, sink, role)

			if len(nr.calledWith) != 0 {
				t.Errorf("NodeRevoker.RevokeNodeRecorded called with %v on a refused request; the Tunnel must stay up", nr.calledWith)
			}
		})
	}

	t.Run("admin is permitted", func(t *testing.T) {
		nr := &fakeNodeRevoker{}
		h := newRoleFixture(t, accounts.RoleAdmin, accounts.KindMachine, Deps{Revocations: newTestRevocations(newMintSink(), revokers{nr: nr})})

		rec := do(t, h, http.MethodPost, "/api/v1/nodes/node-abc/revoke",
			map[string]string{"reason": "role gate fixture"})
		if rec.Code != http.StatusNoContent {
			t.Fatalf("admin revoke: status = %d, want 204; body = %s", rec.Code, rec.Body.String())
		}
		if len(nr.calledWith) != 1 || nr.calledWith[0] != "node-abc" {
			t.Errorf("NodeRevoker.RevokeNodeRecorded calls = %v, want [node-abc]", nr.calledWith)
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
	return newRoleFixture(t, role, kind, Deps{Freeze: fz}), fz
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
// nothing said so; a Deps with no Gate must therefore be loud and closed,
// even for an admin, rather than quietly permissive.
func TestAdministrativeRoutes_RefuseWithoutAGate(t *testing.T) {
	cases := []struct {
		method, path string
		body         any
		deps         Deps
	}{
		{http.MethodPost, "/api/v1/enrollment-tokens",
			mintTokenRequest{InitialTags: []string{"tag:env=prod"}, TTLSeconds: 3600, MaxUses: 1},
			Deps{Tokens: newTestEnrollmentTokens(t, enroll.NewService(enroll.NewMemoryRepository()))}},
		{http.MethodDelete, "/api/v1/enrollment-tokens/tok-1", nil,
			Deps{}},
		{http.MethodPost, "/api/v1/nodes/node-abc/revoke", nil,
			Deps{Revocations: newTestRevocations(newMintSink(), revokers{nr: &fakeNodeRevoker{}})}},
		// The identity routes (#653): a nil AccountAdmin must refuse with 500,
		// on the same unwired-gate posture as every other administrative
		// route here, rather than falling open now that the floor lives in
		// the capability layer instead of a per-handler requireAdmin call.
		{http.MethodGet, "/api/v1/accounts", nil,
			Deps{}},
	}

	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			d := tc.deps
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
