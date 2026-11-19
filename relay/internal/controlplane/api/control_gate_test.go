package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

// control_gate_test.go is the Control API's end of the capability layer's
// authorization of the administrative acts it performs outside a capability
// service, and of the revoke routes' own refusals: the layer decides, records
// the refusal, and this surface renders it.

// gateRoute is one administrative route and the words its refusal must carry.
type gateRoute struct {
	name, method, path string
	body               any
	act                string
}

var gateRoutes = []gateRoute{
	{"mint", http.MethodPost, "/api/v1/enrollment-tokens", mintTokenRequest{TTLSeconds: 3600, MaxUses: 1}, "minting an Enrollment Token"},
	{"token revoke", http.MethodDelete, "/api/v1/enrollment-tokens/tok-1", nil, "revoking an Enrollment Token"},
	{"node revoke", http.MethodPost, "/api/v1/nodes/node-abc/revoke", map[string]string{"reason": "gate fixture"}, "revoking a Node"},
}

// TestControlGate_ARefusalIsOneRefusalRecordInTheTrail drives each route over a
// real store and auditsink.Sink: a refused caller leaves exactly one refusal
// record, written by the capability layer, and the act is never reached. The
// Gate and Revocations share the one sink, and a refused Node revoke stops at
// the pre-gate, so it still leaves one record.
// Proves EN-23.
func TestControlGate_ARefusalIsOneRefusalRecordInTheTrail(t *testing.T) {
	for _, route := range gateRoutes {
		for _, role := range []accounts.Role{accounts.RoleViewer, accounts.RoleOperator} {
			t.Run(route.name+" "+string(role), func(t *testing.T) {
				st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
				if err != nil {
					t.Fatalf("store.Open: %v", err)
				}
				t.Cleanup(func() { st.Close() })

				minter := newRecordingMinter(t)
				tr := &fakeTokenRevoker{}
				nr := &fakeNodeRevoker{}
				sink := auditsink.New(st.Audit())
				h := newRoleFixture(t, role, accounts.KindMachine, Deps{
					Gate:        newTestGate(sink),
					Tokens:      minter,
					Revocations: newTestRevocations(sink, revokers{tr: tr, nr: nr}),
				})

				rec := do(t, h, route.method, route.path, route.body)
				if rec.Code != http.StatusForbidden {
					t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
				}
				var problem struct {
					Title  string `json:"title"`
					Detail string `json:"detail"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
					t.Fatalf("decode problem body %q: %v", rec.Body.String(), err)
				}
				if problem.Title != "forbidden" {
					t.Errorf("title = %q, want forbidden", problem.Title)
				}
				if !strings.Contains(problem.Detail, route.act) || !strings.Contains(problem.Detail, "admin") {
					t.Errorf("detail = %q, want it to name %q and the admin floor", problem.Detail, route.act)
				}

				records, err := st.Audit().List(context.Background())
				if err != nil {
					t.Fatalf("Audit().List: %v", err)
				}
				if len(records) != 1 {
					t.Fatalf("audit records = %+v, want exactly one refusal", records)
				}
				got := records[0]
				if got.Kind != audit.KindRefusal {
					t.Errorf("Kind = %q, want %q", got.Kind, audit.KindRefusal)
				}
				if got.Attribution.Verified.Role != string(role) {
					t.Errorf("verified role = %q, want %q", got.Attribution.Verified.Role, role)
				}
				if !strings.Contains(got.Principal, string(role)) {
					t.Errorf("Principal = %q, want it to name %q", got.Principal, role)
				}
				if got.NodeID != "" || got.JobID != "" {
					t.Errorf("NodeID = %q, JobID = %q, want both empty on an administrative refusal", got.NodeID, got.JobID)
				}
				if got.Reason != problem.Detail {
					t.Errorf("Reason = %q, want the problem detail %q", got.Reason, problem.Detail)
				}

				if minter.calls != 0 || len(tr.calledWith) != 0 || len(nr.calledWith) != 0 {
					t.Errorf("the act was reached: mint calls %d, token revokes %v, node revokes %v",
						minter.calls, tr.calledWith, nr.calledWith)
				}
			})
		}
	}
}

// TestMintToken_ARefusedCallerIsRefusedBeforeTheBodyIsRead sends a viewer a
// malformed body: the refusal must win over the 400 the body would earn.
// Proves EN-1.
func TestMintToken_ARefusedCallerIsRefusedBeforeTheBodyIsRead(t *testing.T) {
	minter := newRecordingMinter(t)
	sink := newMintSink()
	h := newRoleFixture(t, accounts.RoleViewer, accounts.KindMachine, Deps{
		Tokens: minter, Gate: newTestGate(sink),
	})

	rec := doRaw(t, h, http.MethodPost, "/api/v1/enrollment-tokens", "{not json")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 before the body is read; body = %s", rec.Code, rec.Body.String())
	}
	if n := len(sink.refusals()); n != 1 {
		t.Errorf("refusals = %d, want 1", n)
	}
	if minter.calls != 0 {
		t.Errorf("mint calls = %d, want 0", minter.calls)
	}
}

// preGatedRoutes are the routes that ask a ControlGate before reading their
// body. The token-revoke route asks the capability layer inside Revocations.
func preGatedRoutes() []gateRoute {
	var out []gateRoute
	for _, route := range gateRoutes {
		if route.name != "token revoke" {
			out = append(out, route)
		}
	}
	return out
}

// fakeControlGate answers every act with err.
type fakeControlGate struct{ err error }

func (g fakeControlGate) AuthorizeEnrollmentTokenMint(context.Context, capability.Principal) error {
	return g.err
}
func (g fakeControlGate) AuthorizeNodeRevoke(context.Context, capability.Principal) error {
	return g.err
}

// TestGateControl_RefusalLogging pins how a refusal is rendered. One the layer
// could not record arrives joined with the record failure: it is still a 403
// that never shows the failure, and it is logged. One the layer did record is
// a plain 403 with nothing logged as unrecorded.
func TestGateControl_RefusalLogging(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantLogged bool
	}{
		{"unrecorded refusal is logged, never shown",
			errors.Join(errors.New("needs admin"), errors.New("audit store down")), true},
		{"recorded refusal is not logged as unrecorded",
			errors.Join(errors.New("needs admin")), false},
		{"plain refusal is not logged as unrecorded", errors.New("needs admin"), false},
	}
	for _, tc := range cases {
		for _, route := range preGatedRoutes() {
			t.Run(tc.name+" "+route.name, func(t *testing.T) {
				var logs strings.Builder
				h := newRoleFixture(t, accounts.RoleAdmin, accounts.KindMachine, Deps{
					Gate:        fakeControlGate{err: tc.err},
					Tokens:      newRecordingMinter(t),
					Revocations: newTestRevocations(newMintSink(), revokers{tr: &fakeTokenRevoker{}, nr: &fakeNodeRevoker{}}),
					Logger:      slog.New(slog.NewTextHandler(&logs, nil)),
				})

				rec := do(t, h, route.method, route.path, route.body)
				if rec.Code != http.StatusForbidden {
					t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
				}
				if strings.Contains(rec.Body.String(), "audit store down") {
					t.Errorf("body = %s, want the record failure never shown", rec.Body.String())
				}
				if !strings.Contains(rec.Body.String(), "needs admin") {
					t.Errorf("body = %s, want the refusal's reason", rec.Body.String())
				}
				if got := strings.Contains(logs.String(), "audit store down"); got != tc.wantLogged {
					t.Errorf("record failure logged = %v, want %v; log = %q", got, tc.wantLogged, logs.String())
				}
				if !tc.wantLogged && strings.Contains(logs.String(), "not recorded") {
					t.Errorf("a recorded refusal was logged as unrecorded: %q", logs.String())
				}
			})
		}
	}
}

// failingRefusalSink is a mintSink whose refusal record cannot be written.
type failingRefusalSink struct{ *mintSink }

func (failingRefusalSink) Record(context.Context, capability.AuditEntry) error {
	return errors.New("audit store down")
}

// TestRevokeToken_AnUnrecordedRefusalIsLoggedNeverShown is the token-revoke
// route's half of TestGateControl_RefusalLogging: the refusal is made inside
// Revocations, and when its record fails the route is still a 403 that carries
// the refusal and never the failure, with the failure in the log.
func TestRevokeToken_AnUnrecordedRefusalIsLoggedNeverShown(t *testing.T) {
	var logs strings.Builder
	tr := &fakeTokenRevoker{}
	h := newRoleFixture(t, accounts.RoleViewer, accounts.KindMachine, Deps{
		Revocations: newTestRevocations(failingRefusalSink{newMintSink()}, revokers{tr: tr}),
		Logger:      slog.New(slog.NewTextHandler(&logs, nil)),
	})

	rec := do(t, h, http.MethodDelete, "/api/v1/enrollment-tokens/tok-1", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "revoking an Enrollment Token") {
		t.Errorf("body = %s, want the refusal's reason", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "audit store down") {
		t.Errorf("body = %s, want the record failure never shown", rec.Body.String())
	}
	if !strings.Contains(logs.String(), "audit store down") {
		t.Errorf("log = %q, want the record failure logged", logs.String())
	}
	if len(tr.calledWith) != 0 {
		t.Errorf("a refused revoke reached the revoker: %v", tr.calledWith)
	}
}

// TestRevokeToken_ARefusedCallerIsRefusedBeforeTheTokenIDIsRendered sends a
// viewer an id that cannot be rendered into a revocation reason: the refusal
// must win over the 400 the id would earn.
func TestRevokeToken_ARefusedCallerIsRefusedBeforeTheTokenIDIsRendered(t *testing.T) {
	sink := newMintSink()
	tr := &fakeTokenRevoker{}
	h := newRoleFixture(t, accounts.RoleViewer, accounts.KindMachine, Deps{
		Revocations: newTestRevocations(sink, revokers{tr: tr}),
	})

	rec := doRaw(t, h, http.MethodDelete, "/api/v1/enrollment-tokens/tok%0Abad", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 before the id is rendered; body = %s", rec.Code, rec.Body.String())
	}
	if n := len(sink.refusals()); n != 1 {
		t.Errorf("refusals = %d, want 1", n)
	}
	if len(tr.calledWith) != 0 {
		t.Errorf("revoker calls = %v, want none", tr.calledWith)
	}
}

// TestRevokeRoutes_AnUnwiredRevocationsRefusesWith500 is the fail-closed
// direction for the two revoke routes: with no Revocations an admin is refused
// with a 500, never answered as though the revoke happened.
func TestRevokeRoutes_AnUnwiredRevocationsRefusesWith500(t *testing.T) {
	var routes []gateRoute
	for _, route := range gateRoutes {
		if route.name == "token revoke" || route.name == "node revoke" {
			routes = append(routes, route)
		}
	}
	if len(routes) != 2 {
		t.Fatalf("selected %d revoke routes, want 2", len(routes))
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			h := newRoleFixture(t, accounts.RoleAdmin, accounts.KindMachine, Deps{})

			rec := do(t, h, route.method, route.path, route.body)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500; body = %s", rec.Code, rec.Body.String())
			}
			var body problem
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode problem body %q: %v", rec.Body.String(), err)
			}
			if body.Title != "revocation unavailable" {
				t.Errorf("title = %q, want revocation unavailable", body.Title)
			}
		})
	}
}
