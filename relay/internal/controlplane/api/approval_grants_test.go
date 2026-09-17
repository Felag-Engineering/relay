package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/authz"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// approval_grants_test.go tests what the ROUTES do (#378): what they hand the
// capability layer, what they refuse before getting there, and how a domain
// refusal reaches the caller. The eligibility rules themselves belong to the
// domain and are tested there.

// fakeGrants is a hand-rolled ApprovalGrantService recording what the handler
// passed down.
type fakeGrants struct {
	grant   approval.Grant
	request approval.Request
	active  []approval.Grant

	lastPrincipal capability.Principal
	lastRequest   capability.GrantRequest
	lastRevokeID  string
	lastReason    string

	createErr error
	getErr    error
	revokeErr error
}

func (f *fakeGrants) RequestGrant(_ context.Context, p capability.Principal, in capability.GrantRequest) (approval.Grant, approval.Request, error) {
	f.lastPrincipal, f.lastRequest = p, in
	if f.createErr != nil {
		return approval.Grant{}, approval.Request{}, f.createErr
	}
	return f.grant, f.request, nil
}

func (f *fakeGrants) ActiveGrants(context.Context) ([]approval.Grant, error) {
	return f.active, nil
}

func (f *fakeGrants) Grant(_ context.Context, id string) (approval.Grant, error) {
	if f.getErr != nil {
		return approval.Grant{}, f.getErr
	}
	if id != f.grant.ID {
		return approval.Grant{}, approval.ErrGrantNotFound
	}
	return f.grant, nil
}

func (f *fakeGrants) RevokeGrant(_ context.Context, p capability.Principal, id, reason string) (approval.Grant, error) {
	f.lastPrincipal, f.lastRevokeID, f.lastReason = p, id, reason
	if f.revokeErr != nil {
		return approval.Grant{}, f.revokeErr
	}
	g := f.grant
	g.RevokedAt, g.RevokedBy, g.RevokeReason = grantNow, p.Account, reason
	return g, nil
}

// grantNow is the surface's clock (Deps.Now), which is what renderGrant asks
// "is this active?" against. Anchoring the fixture here rather than to apiNow
// keeps one clock in play: a window measured against a different clock than the
// one rendering it is the kind of fixture that passes for the wrong reason.
var grantNow = fixedNow()

func testGrant() approval.Grant {
	return approval.Grant{
		ID: "grant-1", RequestID: "req-1",
		Scope: approval.Scope{
			Account: "gleipnir-prod", RiskClass: jobs.RiskClassMutate,
			MaxFanOut: 5, Operations: []string{"service.restart"},
		},
		StartsAt: grantNow, ExpiresAt: grantNow.Add(2 * time.Hour),
		MaxUses: 10, Uses: 3,
		Summary:   "service.restart [mutate] requested by gleipnir-prod",
		CreatedAt: grantNow,
	}
}

func newGrantFixture(t *testing.T, role accounts.Role, g *fakeGrants) http.Handler {
	t.Helper()
	authn := controlplane.NewAuthenticator(roleVerifier{credential: testCredential, role: role})
	mux := http.NewServeMux()
	Register(mux, Deps{ApprovalGrants: g, Now: fixedNow})
	return authn.Middleware(mux)
}

func validGrantBody() map[string]any {
	return map[string]any{
		"scope": map[string]any{
			"account":     "gleipnir-prod",
			"risk_class":  "mutate",
			"max_fan_out": 5,
			"operations":  []string{"service.restart"},
		},
		"expires_at": grantNow.Add(2 * time.Hour).Format(time.RFC3339),
		"max_uses":   10,
	}
}

// -----------------------------------------------------------------------
// Create
// -----------------------------------------------------------------------

// TestCreateGrant_PassesTheScopeDownVerbatim: the route decodes and delegates.
// Every wall the caller named must arrive at the capability layer unchanged —
// a surface that quietly filled in a default would be a surface that widened a
// grant nobody asked to widen.
func TestCreateGrant_PassesTheScopeDownVerbatim(t *testing.T) {
	g := &fakeGrants{grant: testGrant(), request: testApprovalRequest("req-1", jobs.Action{
		Kind: jobs.ActionOperation, OperationName: "service.restart", RiskClass: jobs.RiskClassMutate,
	})}
	h := newGrantFixture(t, accounts.RoleOperator, g)

	rec := do(t, h, http.MethodPost, "/api/v1/approval-grants", validGrantBody())
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", rec.Code, rec.Body)
	}

	got := g.lastRequest
	if got.Scope.Account != "gleipnir-prod" || got.Scope.RiskClass != jobs.RiskClassMutate {
		t.Errorf("scope = %+v, want the account and class as written", got.Scope)
	}
	if got.Scope.MaxFanOut != 5 || got.MaxUses != 10 {
		t.Errorf("bounds = fan-out %d / uses %d, want 5 / 10", got.Scope.MaxFanOut, got.MaxUses)
	}
	if len(got.Scope.Operations) != 1 || got.Scope.Operations[0] != "service.restart" {
		t.Errorf("operations = %v, want the allow-list as written", got.Scope.Operations)
	}
	if !got.ExpiresAt.Equal(grantNow.Add(2 * time.Hour)) {
		t.Errorf("expires_at = %v, want %v", got.ExpiresAt, grantNow.Add(2*time.Hour))
	}
	// An absent starts_at is left zero for the capability layer to default to
	// its own clock — the surface does not have one, and two clocks is one too
	// many for a window.
	if !got.StartsAt.IsZero() {
		t.Errorf("starts_at = %v, want zero when the body omitted it", got.StartsAt)
	}
}

// TestCreateGrant_ReturnsBothHalvesOfTheFlow: a caller must never be left
// holding a grant ID with no idea what still has to happen to it. The response
// carries the pending request and where to answer it.
func TestCreateGrant_ReturnsBothHalvesOfTheFlow(t *testing.T) {
	g := &fakeGrants{grant: testGrant(), request: testApprovalRequest("req-1", jobs.Action{
		Kind: jobs.ActionOperation, OperationName: "service.restart", RiskClass: jobs.RiskClassMutate,
	})}
	h := newGrantFixture(t, accounts.RoleOperator, g)

	rec := do(t, h, http.MethodPost, "/api/v1/approval-grants", validGrantBody())
	var out createGrantResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v; body = %s", err, rec.Body)
	}

	if out.Grant.GrantID != "grant-1" || out.Grant.RequestID != "req-1" {
		t.Errorf("grant = %+v, want it to name its authorizing request", out.Grant)
	}
	if out.Approval.State != "pending" {
		t.Errorf("approval state = %q, want pending — creating a grant is not being granted one", out.Approval.State)
	}
	if out.DecisionPath != "/api/v1/approvals/req-1/decision" {
		t.Errorf("decision_path = %q, want the ordinary out-of-band decision route", out.DecisionPath)
	}
	if out.Grant.Summary != g.grant.Summary {
		t.Errorf("summary = %q, want the Relay-authored text verbatim", out.Grant.Summary)
	}
	if out.Grant.Remaining != 7 || out.Grant.Progress != "3 of 10 used" {
		t.Errorf("remaining/progress = %d/%q, want 7 and \"3 of 10 used\"", out.Grant.Remaining, out.Grant.Progress)
	}
}

// TestCreateGrant_RefusesAnUnnamedRiskClass: there is no default and no "any".
// A grant written for a read sweep must never silently cover a mutate, so an
// absent or unknown class is refused rather than guessed.
func TestCreateGrant_RefusesAnUnnamedRiskClass(t *testing.T) {
	for _, class := range []string{"", "any", "Mutate!"} {
		g := &fakeGrants{grant: testGrant()}
		h := newGrantFixture(t, accounts.RoleOperator, g)

		body := validGrantBody()
		body["scope"].(map[string]any)["risk_class"] = class
		rec := do(t, h, http.MethodPost, "/api/v1/approval-grants", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("risk_class %q: status = %d, want 400; body = %s", class, rec.Code, rec.Body)
		}
		if g.lastRequest.Scope.Account != "" {
			t.Errorf("risk_class %q reached the capability layer", class)
		}
	}
}

// TestCreateGrant_RefusesAnAbsentWindow: a grant without a window is a standing
// authorization, which is the one thing this mechanism must never become.
func TestCreateGrant_RefusesAnAbsentWindow(t *testing.T) {
	g := &fakeGrants{grant: testGrant()}
	h := newGrantFixture(t, accounts.RoleOperator, g)

	body := validGrantBody()
	delete(body, "expires_at")
	if rec := do(t, h, http.MethodPost, "/api/v1/approval-grants", body); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body)
	}
	if g.lastRequest.MaxUses != 0 {
		t.Error("a windowless grant reached the capability layer")
	}
}

// TestCreateGrant_RefusesTheRetiredSelectorNamespace is #482, acceptance 1: a
// Grant's Scope has no namespace term, and a body that still carries
// selector_namespace is REFUSED with 400 naming the field — never silently
// ignored, which would price the grant as if the field had been honoured.
// decodeJSON's DisallowUnknownFields is what does the refusing; this pins
// that it still reaches a nested "scope" object.
func TestCreateGrant_RefusesTheRetiredSelectorNamespace(t *testing.T) {
	g := &fakeGrants{grant: testGrant()}
	h := newGrantFixture(t, accounts.RoleOperator, g)

	body := validGrantBody()
	body["scope"].(map[string]any)["selector_namespace"] = "node"
	rec := do(t, h, http.MethodPost, "/api/v1/approval-grants", body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "selector_namespace") {
		t.Errorf("body = %s, want the refusal to name the retired field", rec.Body)
	}
	if g.lastRequest.Scope.Account != "" {
		t.Error("a body carrying selector_namespace reached the capability layer — refused, not ignored")
	}
}

// TestCreateGrant_MapsDomainRefusals: each refusal reaches the caller as the
// status that describes it, with the domain's own sentence in the detail. An
// operator told only "rejected" learns nothing except to try again wider.
func TestCreateGrant_MapsDomainRefusals(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"unbounded scope", approval.ErrGrantUnbounded, http.StatusUnprocessableEntity},
		{"nothing gated", capability.ErrGrantCoversNothingGated, http.StatusUnprocessableEntity},
		{"malformed scope", approval.ErrGrantInvalid, http.StatusBadRequest},
		{"role floor", authz.ErrUnauthorized, http.StatusForbidden},
		{"grants not wired", capability.ErrApprovalUnavailable, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := &fakeGrants{grant: testGrant(), createErr: tc.err}
			h := newGrantFixture(t, accounts.RoleOperator, g)

			rec := do(t, h, http.MethodPost, "/api/v1/approval-grants", validGrantBody())
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, tc.want, rec.Body)
			}
			if tc.want != http.StatusInternalServerError && !strings.Contains(rec.Body.String(), tc.err.Error()) {
				t.Errorf("body = %s, want the domain's own explanation", rec.Body)
			}
		})
	}
}

// TestGrantRoutes_UnwiredFailLoudly: a surface offering grants against a Relay
// that never wired them must not silently accept requests that grant nothing.
func TestGrantRoutes_UnwiredFailLoudly(t *testing.T) {
	authn := controlplane.NewAuthenticator(roleVerifier{credential: testCredential, role: accounts.RoleAdmin})
	mux := http.NewServeMux()
	Register(mux, Deps{Now: fixedNow})
	h := authn.Middleware(mux)

	for _, call := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/api/v1/approval-grants", validGrantBody()},
		{http.MethodGet, "/api/v1/approval-grants", nil},
		{http.MethodGet, "/api/v1/approval-grants/grant-1", nil},
		{http.MethodPost, "/api/v1/approval-grants/grant-1/revoke", map[string]any{"reason": "x"}},
	} {
		if rec := do(t, h, call.method, call.path, call.body); rec.Code != http.StatusInternalServerError {
			t.Errorf("%s %s: status = %d, want 500", call.method, call.path, rec.Code)
		}
	}
}

// -----------------------------------------------------------------------
// Read
// -----------------------------------------------------------------------

// TestListGrants_ViewerMayRead: a live grant is a period of reduced friction,
// which is fleet state the operators watching the fleet are entitled to see.
func TestListGrants_ViewerMayRead(t *testing.T) {
	g := &fakeGrants{grant: testGrant(), active: []approval.Grant{testGrant()}}
	h := newGrantFixture(t, accounts.RoleViewer, g)

	rec := do(t, h, http.MethodGet, "/api/v1/approval-grants", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body)
	}
	var out listGrantsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Grants) != 1 || out.Grants[0].GrantID != "grant-1" {
		t.Fatalf("grants = %+v, want the one live grant", out.Grants)
	}
	if !out.Grants[0].Active {
		t.Error("active = false for a grant inside its window with uses left")
	}
}

// TestGetGrant_UnknownIs404: distinguishable from a grant that exists and is
// closed, which is a different fact about the world.
func TestGetGrant_UnknownIs404(t *testing.T) {
	g := &fakeGrants{grant: testGrant()}
	h := newGrantFixture(t, accounts.RoleOperator, g)

	if rec := do(t, h, http.MethodGet, "/api/v1/approval-grants/grant-nope", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", rec.Code, rec.Body)
	}
}

// -----------------------------------------------------------------------
// Revoke
// -----------------------------------------------------------------------

// TestRevokeGrant_AttributesToTheAuthenticatedCaller: the revoker is the
// authenticated Principal, never anything the body said.
func TestRevokeGrant_AttributesToTheAuthenticatedCaller(t *testing.T) {
	g := &fakeGrants{grant: testGrant()}
	h := newGrantFixture(t, accounts.RoleOperator, g)

	rec := do(t, h, http.MethodPost, "/api/v1/approval-grants/grant-1/revoke",
		map[string]any{"reason": "incident 42"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body)
	}
	if g.lastRevokeID != "grant-1" || g.lastReason != "incident 42" {
		t.Errorf("revoke = %q / %q, want the path id and the body's reason", g.lastRevokeID, g.lastReason)
	}
	if g.lastPrincipal.Account == "" {
		t.Error("the capability layer was handed no principal; a revocation must be attributed")
	}

	var out grantResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.RevokedAt == "" || out.RevokeReason != "incident 42" {
		t.Errorf("response = %+v, want the revocation visible", out)
	}
}

// TestRevokeGrant_AlreadyClosedIs409: revoking twice is not a silent no-op. An
// operator reaching for this is usually mid-incident and needs a truthful
// answer about whether the window is theirs to have closed.
func TestRevokeGrant_AlreadyClosedIs409(t *testing.T) {
	g := &fakeGrants{grant: testGrant(), revokeErr: approval.ErrGrantNotActive}
	h := newGrantFixture(t, accounts.RoleOperator, g)

	rec := do(t, h, http.MethodPost, "/api/v1/approval-grants/grant-1/revoke", map[string]any{})
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body = %s", rec.Code, rec.Body)
	}
}

// TestRevokeGrant_RefusesAnOversizedReason: the reason is echoed into an audit
// record, so an unbounded one lets a caller size a row in the trail.
func TestRevokeGrant_RefusesAnOversizedReason(t *testing.T) {
	g := &fakeGrants{grant: testGrant()}
	h := newGrantFixture(t, accounts.RoleOperator, g)

	long := make([]byte, maxDecisionReasonLen+1)
	for i := range long {
		long[i] = 'x'
	}
	rec := do(t, h, http.MethodPost, "/api/v1/approval-grants/grant-1/revoke",
		map[string]any{"reason": string(long)})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body)
	}
	if g.lastRevokeID != "" {
		t.Error("an oversized reason reached the capability layer")
	}
}
