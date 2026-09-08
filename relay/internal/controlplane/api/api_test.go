package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/authz"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/enroll"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

// -----------------------------------------------------------------------
// Fakes for the narrow collaborator interfaces in api.go.
// -----------------------------------------------------------------------

// fakeTokenRevoker is a TokenRevoker fake that records every id it was
// called with and returns a configurable error.
type fakeTokenRevoker struct {
	mu         sync.Mutex
	calledWith []string
	err        error
}

func (f *fakeTokenRevoker) RevokeToken(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calledWith = append(f.calledWith, id)
	return f.err
}

// fakeNodeRevoker is a NodeRevoker fake that records every node_id it was
// called with.
type fakeNodeRevoker struct {
	mu         sync.Mutex
	calledWith []string
}

func (f *fakeNodeRevoker) RevokeNode(nodeID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calledWith = append(f.calledWith, nodeID)
}

// fakeNodeReader is a NodeReader fake over a fixed map.
type fakeNodeReader map[string]registry.Node

func (f fakeNodeReader) Get(nodeID string) (registry.Node, bool) {
	n, ok := f[nodeID]
	return n, ok
}

// releaseCall captures one ReleaseFreeze invocation.
type releaseCall struct {
	Principal capability.Principal
	Reason    string
}

// fakeFreezer is a Freezer fake that records every Engage/Release call and
// returns configurable errors.
//
// gate, when set, runs the REAL authz.RoleGate before the canned result,
// standing in for what capability.Service does with the same object (#397).
// The reasoning is fakeExecutor's, and identical: the Freeze floor is the
// central ladder's answer, so proving it against a fake that returns a canned
// 403 would prove only that this file can spell errors. What these tests own
// is that the route hands the capability layer the right Principal and
// renders its refusal as 403 rather than 500.
type fakeFreezer struct {
	mu           sync.Mutex
	engageCalls  []capability.Principal
	releaseCalls []releaseCall
	engageErr    error
	releaseErr   error

	gate capability.ControlAuthorizer
}

func (f *fakeFreezer) EngageFreeze(ctx context.Context, p capability.Principal) error {
	f.mu.Lock()
	f.engageCalls = append(f.engageCalls, p)
	f.mu.Unlock()
	if f.gate != nil {
		if err := f.gate.AuthorizeControl(ctx, p, capability.ControlFreezeEngage); err != nil {
			return err
		}
	}
	return f.engageErr
}

func (f *fakeFreezer) ReleaseFreeze(ctx context.Context, p capability.Principal, reason string) error {
	f.mu.Lock()
	f.releaseCalls = append(f.releaseCalls, releaseCall{Principal: p, Reason: reason})
	f.mu.Unlock()
	if f.gate != nil {
		if err := f.gate.AuthorizeControl(ctx, p, capability.ControlFreezeRelease); err != nil {
			return err
		}
	}
	return f.releaseErr
}

// fakeAuditor is an Auditor fake that records every appended Record.
type fakeAuditor struct {
	mu      sync.Mutex
	records []audit.Record
	err     error
}

func (f *fakeAuditor) Append(_ context.Context, r audit.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, r)
	return f.err
}

func (f *fakeAuditor) all() []audit.Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]audit.Record, len(f.records))
	copy(out, f.records)
	return out
}

// -----------------------------------------------------------------------
// Test harness: mount Register's routes behind the real
// controlplane.Authenticator.Middleware, so principal-threading is exactly
// what production wiring produces (invariant 10 — one auth path).
// -----------------------------------------------------------------------

const testCredential = accounts.TokenPrefix + "1234567890abcdef.test-secret" //nolint:gosec // test fixture, not a real credential

// staticVerifier is a controlplane.TokenVerifier that accepts exactly one
// credential, as the founding admin Account. The identity-management tests in
// accounts_test.go use the REAL TokenService over a real store; this fake
// exists only so the pre-existing lifecycle-route tests keep their focus on
// the routes rather than on minting a credential first.
const testTokenID = "tok-test"

type staticVerifier struct{ credential string }

func (v staticVerifier) Verify(_ context.Context, credential string) (accounts.Account, accounts.APIToken, error) {
	if credential != v.credential {
		return accounts.Account{}, accounts.APIToken{}, accounts.ErrTokenInvalid
	}
	return accounts.Account{
		Name:    accounts.FoundingAdminName,
		Kind:    accounts.KindHuman,
		Role:    accounts.RoleAdmin,
		Enabled: true,
	}, accounts.APIToken{ID: testTokenID}, nil
}

// testPrincipal is the acting identity staticVerifier produces, including the
// TokenID the verified audit lane records (#300): which credential acted is
// part of the identity, not decoration on it.
func testPrincipal() capability.Principal {
	p := controlplane.FoundingAdmin()
	p.TokenID = testTokenID
	p.AuthMethod = capability.AuthMethodAPIToken
	// The authentication boundary now stamps the peer address into the
	// verified attribution lane (#418). httptest.NewRequest's default
	// RemoteAddr is 192.0.2.1:1234, and the port is stripped.
	p.Source = "192.0.2.1"
	return p
}

// newTestHandler builds an http.Handler that mounts Register(mux, d) behind
// a real controlplane.Authenticator accepting testCredential.
//
// An unset d.Authz defaults to the PRODUCTION authz.RoleGate (#397), not to a
// permissive fake. staticVerifier authenticates as the founding admin, so
// every pre-existing lifecycle test keeps passing the real ladder rather than
// being waved through — which is the point: if a floor were later raised
// above admin, these tests would notice.
func newTestHandler(d Deps) http.Handler {
	if d.Authz == nil {
		d.Authz = authz.NewRoleGate()
	}
	authn := controlplane.NewAuthenticator(staticVerifier{credential: testCredential})
	mux := http.NewServeMux()
	Register(mux, d)
	return authn.Middleware(mux)
}

// do issues an authenticated request with an optional JSON body and returns
// the recorded response.
func do(t *testing.T, h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("json.Marshal request body: %v", err)
		}
		reader = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Authorization", "Bearer "+testCredential)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// doRaw issues an authenticated request with a raw string body (for
// malformed-JSON test cases that a Go value can't represent).
func doRaw(t *testing.T, h http.Handler, method, path, rawBody string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(rawBody))
	req.Header.Set("Authorization", "Bearer "+testCredential)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func fixedNow() time.Time { return time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC) }

// -----------------------------------------------------------------------
// Enrollment Token mint
// -----------------------------------------------------------------------

func TestHandleMintToken_Success(t *testing.T) {
	repo := enroll.NewMemoryRepository()
	tokenSvc := enroll.NewService(repo)
	auditor := &fakeAuditor{}
	d := Deps{Tokens: tokenSvc, Audit: auditor, Now: fixedNow}
	h := newTestHandler(d)

	rec := do(t, h, http.MethodPost, "/api/v1/enrollment-tokens", mintTokenRequest{
		Scope:      []string{"relay:env=prod", "relay:role=web"},
		TTLSeconds: 3600,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var resp mintTokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ID == "" {
		t.Error("response id is empty")
	}
	if resp.Token == "" || resp.Token == resp.ID {
		t.Errorf("response token is empty or equals id: %q", resp.Token)
	}
	if len(resp.Scope) != 2 || resp.Scope[0] != "relay:env=prod" || resp.Scope[1] != "relay:role=web" {
		t.Errorf("response scope = %v, want the requested scope", resp.Scope)
	}
	expiresAt, err := time.Parse(time.RFC3339, resp.ExpiresAt)
	if err != nil {
		t.Fatalf("expires_at %q is not RFC3339: %v", resp.ExpiresAt, err)
	}
	if !expiresAt.After(fixedNow()) {
		t.Errorf("expires_at %v is not after now", expiresAt)
	}

	// The plaintext credential must never reach the persisted Token: fetch
	// it back from the repository and confirm CreatedBy carries the
	// authenticated principal (ADR-0006 mint attribution).
	stored, err := repo.ByID(context.Background(), resp.ID)
	if err != nil {
		t.Fatalf("repo.ByID: %v", err)
	}
	if stored.CreatedBy != controlplane.FoundingAdmin().Attribution() {
		t.Errorf("stored token CreatedBy = %q, want %q", stored.CreatedBy, controlplane.FoundingAdmin().Attribution())
	}

	// Exactly one KindTokenMint audit Record, attributed to the principal,
	// and the plaintext must never appear anywhere in it.
	records := auditor.all()
	if len(records) != 1 {
		t.Fatalf("audit records = %d, want 1", len(records))
	}
	got := records[0]
	if got.Kind != audit.KindTokenMint {
		t.Errorf("audit Kind = %q, want %q", got.Kind, audit.KindTokenMint)
	}
	if got.Principal != controlplane.FoundingAdmin().Attribution() {
		t.Errorf("audit Principal = %q, want %q", got.Principal, controlplane.FoundingAdmin().Attribution())
	}
	if got.ID == "" {
		t.Error("audit Record.ID is empty")
	}
	if strings.Contains(fmt.Sprintf("%+v", got), resp.Token) {
		t.Errorf("audit Record contains the token plaintext: %+v", got)
	}
}

func TestHandleMintToken_InvalidScopeOrTTL(t *testing.T) {
	cases := []struct {
		name string
		req  mintTokenRequest
	}{
		{"empty scope", mintTokenRequest{Scope: nil, TTLSeconds: 3600}},
		{"non-relay scope", mintTokenRequest{Scope: []string{"env=prod"}, TTLSeconds: 3600}},
		{"zero ttl", mintTokenRequest{Scope: []string{"relay:env=prod"}, TTLSeconds: 0}},
		{"negative ttl", mintTokenRequest{Scope: []string{"relay:env=prod"}, TTLSeconds: -1}},
		{"over-max ttl", mintTokenRequest{Scope: []string{"relay:env=prod"}, TTLSeconds: maxTTLSeconds + 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tokenSvc := enroll.NewService(enroll.NewMemoryRepository())
			auditor := &fakeAuditor{}
			d := Deps{Tokens: tokenSvc, Audit: auditor, Now: fixedNow}
			h := newTestHandler(d)

			rec := do(t, h, http.MethodPost, "/api/v1/enrollment-tokens", tc.req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
			if len(auditor.all()) != 0 {
				t.Errorf("audit records = %d, want 0 on a rejected mint", len(auditor.all()))
			}
		})
	}
}

func TestHandleMintToken_MalformedOrUnknownField(t *testing.T) {
	tokenSvc := enroll.NewService(enroll.NewMemoryRepository())
	d := Deps{Tokens: tokenSvc, Audit: &fakeAuditor{}, Now: fixedNow}
	h := newTestHandler(d)

	t.Run("malformed JSON", func(t *testing.T) {
		rec := doRaw(t, h, http.MethodPost, "/api/v1/enrollment-tokens", `{"scope":`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
	})

	t.Run("unknown field", func(t *testing.T) {
		rec := doRaw(t, h, http.MethodPost, "/api/v1/enrollment-tokens",
			`{"scope":["relay:env=prod"],"ttl_seconds":3600,"unexpected_field":true}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
	})
}

// -----------------------------------------------------------------------
// Enrollment Token revoke
// -----------------------------------------------------------------------

func TestHandleRevokeToken(t *testing.T) {
	tr := &fakeTokenRevoker{}
	auditor := &fakeAuditor{}
	d := Deps{TokenRevoker: tr, Audit: auditor, Now: fixedNow}
	h := newTestHandler(d)

	rec := do(t, h, http.MethodDelete, "/api/v1/enrollment-tokens/tok-123", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if got := tr.calledWith; len(got) != 1 || got[0] != "tok-123" {
		t.Errorf("TokenRevoker.RevokeToken called with %v, want [tok-123]", got)
	}

	records := auditor.all()
	if len(records) != 1 {
		t.Fatalf("audit records = %d, want 1", len(records))
	}
	got := records[0]
	if got.Kind != audit.KindTokenRevoke {
		t.Errorf("audit Kind = %q, want %q", got.Kind, audit.KindTokenRevoke)
	}
	if got.Principal != controlplane.FoundingAdmin().Attribution() {
		t.Errorf("audit Principal = %q, want %q", got.Principal, controlplane.FoundingAdmin().Attribution())
	}
	if got.ID == "" {
		t.Error("audit Record.ID is empty")
	}
	if !strings.Contains(got.Reason, "tok-123") {
		t.Errorf("audit Reason = %q, want it to reference tok-123", got.Reason)
	}
}

// -----------------------------------------------------------------------
// Node revoke
// -----------------------------------------------------------------------

func TestHandleRevokeNode(t *testing.T) {
	nr := &fakeNodeRevoker{}
	auditor := &fakeAuditor{}
	d := Deps{Nodes: nr, Audit: auditor, Now: fixedNow}
	h := newTestHandler(d)

	rec := do(t, h, http.MethodPost, "/api/v1/nodes/node-abc/revoke",
		map[string]string{"reason": "compromised host, INC-4471"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if got := nr.calledWith; len(got) != 1 || got[0] != "node-abc" {
		t.Errorf("NodeRevoker.RevokeNode called with %v, want [node-abc]", got)
	}

	records := auditor.all()
	if len(records) != 1 {
		t.Fatalf("audit records = %d, want 1", len(records))
	}
	got := records[0]
	if got.Kind != audit.KindNodeRevoke {
		t.Errorf("audit Kind = %q, want %q", got.Kind, audit.KindNodeRevoke)
	}
	if got.NodeID != "node-abc" {
		t.Errorf("audit NodeID = %q, want %q", got.NodeID, "node-abc")
	}
	if got.Principal != controlplane.FoundingAdmin().Attribution() {
		t.Errorf("audit Principal = %q, want %q", got.Principal, controlplane.FoundingAdmin().Attribution())
	}
	// The point of #487: the record answers WHY, not just who and when.
	if got.Reason != "compromised host, INC-4471" {
		t.Errorf("audit Reason = %q, want the reason the caller supplied", got.Reason)
	}
}

// TestHandleRevokeNode_RefusesWithoutAUsableReason covers #487's requirement
// half. Each case asserts BOTH that the request is refused AND that the Node
// was NOT revoked: an irreversible act that happened behind a 400 would be
// strictly worse than the unattributed revoke this ticket set out to fix, so
// the ordering (validate, then revoke) is the property under test, not the
// status code.
func TestHandleRevokeNode_RefusesWithoutAUsableReason(t *testing.T) {
	tooLong := strings.Repeat("x", capability.MaxRevokeReasonBytes+1)
	cases := []struct {
		name string
		body any
	}{
		{"no body at all — the pre-#487 caller", nil},
		{"absent reason field", map[string]string{}},
		{"empty reason", map[string]string{"reason": ""}},
		{"whitespace-only reason", map[string]string{"reason": "   \t  "}},
		{"one byte over the cap", map[string]string{"reason": tooLong}},
		{"embedded newline", map[string]string{"reason": "revoked\nrevoked by nobody"}},
		{"embedded NUL", map[string]string{"reason": "revoked\x00"}},
		{"invalid UTF-8", map[string]string{"reason": "revoked \xff\xfe"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nr := &fakeNodeRevoker{}
			auditor := &fakeAuditor{}
			h := newTestHandler(Deps{Nodes: nr, Audit: auditor, Now: fixedNow})

			rec := do(t, h, http.MethodPost, "/api/v1/nodes/node-abc/revoke", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
			}
			if len(nr.calledWith) != 0 {
				t.Errorf("the Node was revoked anyway: RevokeNode called with %v", nr.calledWith)
			}
			if n := len(auditor.all()); n != 0 {
				t.Errorf("audit records = %d, want 0 — nothing happened to record", n)
			}
		})
	}
}

// TestHandleRevokeNode_RefusesWhenItCannotBeAudited pins the fail-closed half
// of #487: the reason is worthless if the record carrying it can be dropped
// silently, so an audit-write failure refuses the revocation rather than
// performing it and returning 204.
//
// This deliberately inverts recordLifecycle's best-effort contract, which the
// other lifecycle actions keep — see recordLifecycleErr for why revoke can and
// they cannot.
func TestHandleRevokeNode_RefusesWhenItCannotBeAudited(t *testing.T) {
	nr := &fakeNodeRevoker{}
	auditor := &fakeAuditor{err: errors.New("audit store unavailable")}
	h := newTestHandler(Deps{Nodes: nr, Audit: auditor, Now: fixedNow})

	rec := do(t, h, http.MethodPost, "/api/v1/nodes/node-abc/revoke",
		map[string]string{"reason": "compromised host"})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body = %s", rec.Code, rec.Body.String())
	}
	if len(nr.calledWith) != 0 {
		t.Errorf("the Node was revoked despite an unwritable trail: %v", nr.calledWith)
	}
	// The detail must not leak the store's error to the caller.
	if strings.Contains(rec.Body.String(), "audit store unavailable") {
		t.Errorf("the audit backend error leaked into the response: %s", rec.Body.String())
	}
}

// TestHandleRevokeNode_ReasonIsTrimmedAndBounded pins the two edges of the
// accepted range, so a later change to the bound has to move this test too.
func TestHandleRevokeNode_ReasonIsTrimmedAndBounded(t *testing.T) {
	t.Run("surrounding whitespace is trimmed before recording", func(t *testing.T) {
		nr := &fakeNodeRevoker{}
		auditor := &fakeAuditor{}
		h := newTestHandler(Deps{Nodes: nr, Audit: auditor, Now: fixedNow})

		rec := do(t, h, http.MethodPost, "/api/v1/nodes/node-abc/revoke",
			map[string]string{"reason": "   decommissioned   "})
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204; body = %s", rec.Code, rec.Body.String())
		}
		if got := auditor.all()[0].Reason; got != "decommissioned" {
			t.Errorf("audit Reason = %q, want it trimmed", got)
		}
	})

	t.Run("exactly at the cap is accepted", func(t *testing.T) {
		nr := &fakeNodeRevoker{}
		auditor := &fakeAuditor{}
		h := newTestHandler(Deps{Nodes: nr, Audit: auditor, Now: fixedNow})

		atCap := strings.Repeat("x", capability.MaxRevokeReasonBytes)
		rec := do(t, h, http.MethodPost, "/api/v1/nodes/node-abc/revoke",
			map[string]string{"reason": atCap})
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204 at exactly the cap; body = %s", rec.Code, rec.Body.String())
		}
		if got := auditor.all()[0].Reason; got != atCap {
			t.Errorf("audit Reason was altered at the cap boundary")
		}
	})
}

// -----------------------------------------------------------------------
// Node read (#414, ADR-0034)
// -----------------------------------------------------------------------

// TestHandleGetNode_StateLabels covers acceptance 8 on the Control API: a
// Node's derived state: labels render on GET /nodes/{id}, prefixed and never
// null — the same nodestate.Labels every other surface renders.
func TestHandleGetNode_StateLabels(t *testing.T) {
	t.Run("offline Node carries state:offline", func(t *testing.T) {
		nr := fakeNodeReader{"node-a": {NodeID: "node-a"}} // never connected
		d := Deps{NodeReader: nr, Audit: &fakeAuditor{}, Now: fixedNow}
		h := newTestHandler(d)

		rec := do(t, h, http.MethodGet, "/api/v1/nodes/node-a", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
		}
		var out nodeResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		if out.StateLabels == nil {
			t.Fatal("state_labels is null, want a (possibly empty) array")
		}
		found := false
		for _, l := range out.StateLabels {
			if l == "state:offline" {
				found = true
			}
			if !strings.HasPrefix(l, "state:") {
				t.Errorf("state label %q is not state:-prefixed", l)
			}
		}
		if !found {
			t.Errorf("state_labels = %v, want state:offline (never connected)", out.StateLabels)
		}
	})

	t.Run("no Node carries no state label at all: empty array, not null", func(t *testing.T) {
		n := registry.Node{NodeID: "node-b", Connected: true}
		nr := fakeNodeReader{"node-b": n}
		d := Deps{NodeReader: nr, Audit: &fakeAuditor{}, Now: fixedNow}
		h := newTestHandler(d)

		rec := do(t, h, http.MethodGet, "/api/v1/nodes/node-b", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
		}
		var out nodeResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		if out.StateLabels == nil {
			t.Fatal("state_labels is null, want []")
		}
		if len(out.StateLabels) != 0 {
			t.Errorf("state_labels = %v, want empty — this Node is connected, current, and its template set is not unloadable", out.StateLabels)
		}
	})
}

// -----------------------------------------------------------------------
// Freeze engage / release
// -----------------------------------------------------------------------

func TestHandleFreeze_EngageAndRelease(t *testing.T) {
	fz := &fakeFreezer{}
	auditor := &fakeAuditor{}
	d := Deps{Freeze: fz, Audit: auditor, Now: fixedNow}
	h := newTestHandler(d)

	engageRec := do(t, h, http.MethodPost, "/api/v1/freeze/engage", nil)
	if engageRec.Code != http.StatusOK {
		t.Fatalf("engage status = %d, want %d; body = %s", engageRec.Code, http.StatusOK, engageRec.Body.String())
	}
	var engageResp freezeResponse
	if err := json.Unmarshal(engageRec.Body.Bytes(), &engageResp); err != nil {
		t.Fatalf("decode engage response: %v", err)
	}
	if !engageResp.Engaged {
		t.Error("engage response Engaged = false, want true")
	}
	if len(fz.engageCalls) != 1 || fz.engageCalls[0] != testPrincipal() {
		t.Errorf("EngageFreeze calls = %v, want exactly [%v]", fz.engageCalls, testPrincipal())
	}

	noReasonRec := do(t, h, http.MethodPost, "/api/v1/freeze/release", freezeReleaseRequest{Reason: ""})
	if noReasonRec.Code != http.StatusBadRequest {
		t.Fatalf("release without reason: status = %d, want %d", noReasonRec.Code, http.StatusBadRequest)
	}

	whitespaceReasonRec := do(t, h, http.MethodPost, "/api/v1/freeze/release", freezeReleaseRequest{Reason: "   "})
	if whitespaceReasonRec.Code != http.StatusBadRequest {
		t.Fatalf("release with whitespace-only reason: status = %d, want %d", whitespaceReasonRec.Code, http.StatusBadRequest)
	}
	if len(fz.releaseCalls) != 0 {
		t.Fatalf("ReleaseFreeze calls after whitespace-only reason = %d, want 0", len(fz.releaseCalls))
	}

	withReasonRec := do(t, h, http.MethodPost, "/api/v1/freeze/release", freezeReleaseRequest{Reason: "  incident resolved  "})
	if withReasonRec.Code != http.StatusOK {
		t.Fatalf("release with reason: status = %d, want %d; body = %s", withReasonRec.Code, http.StatusOK, withReasonRec.Body.String())
	}
	var releaseResp freezeResponse
	if err := json.Unmarshal(withReasonRec.Body.Bytes(), &releaseResp); err != nil {
		t.Fatalf("decode release response: %v", err)
	}
	if releaseResp.Engaged {
		t.Error("release response Engaged = true, want false")
	}
	if len(fz.releaseCalls) != 1 {
		t.Fatalf("ReleaseFreeze calls = %d, want 1", len(fz.releaseCalls))
	}
	if fz.releaseCalls[0].Principal != testPrincipal() {
		t.Errorf("ReleaseFreeze principal = %v, want %v", fz.releaseCalls[0].Principal, testPrincipal())
	}
	if fz.releaseCalls[0].Reason != "incident resolved" {
		t.Errorf("ReleaseFreeze reason = %q, want %q", fz.releaseCalls[0].Reason, "incident resolved")
	}

	// Freeze's audit trail is intrinsic to capability.Service (RecordFreeze):
	// this package must NEVER call recordLifecycle for freeze routes, or the
	// event would be double-audited.
	if got := auditor.all(); len(got) != 0 {
		t.Errorf("audit records after freeze engage/release = %d, want 0 (freeze audits intrinsically)", len(got))
	}
}

// -----------------------------------------------------------------------
// Principal threading / defensive missing-principal path
// -----------------------------------------------------------------------

// TestPrincipal_MissingContext_Returns500 exercises the defensive branch:
// a request that reaches a route's mux WITHOUT ever going through
// Authenticator.Middleware (which should never happen behind
// controlplane.Server.Mux() in production, but principal() must not fail
// open) gets a 500, never a 200.
func TestPrincipal_MissingContext_Returns500(t *testing.T) {
	d := Deps{Freeze: &fakeFreezer{}, Audit: &fakeAuditor{}, Now: fixedNow}
	mux := http.NewServeMux()
	Register(mux, d)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/freeze/engage", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// -----------------------------------------------------------------------
// R1 regression: two sequential lifecycle actions in one test session must
// BOTH produce audit rows. Uses the real SQLite-backed audit.Repository
// (internal/store) so the audit_id PRIMARY KEY constraint is genuinely
// exercised — a fake Auditor would not catch an empty/duplicate Record.ID.
// -----------------------------------------------------------------------

func TestMintThenRevokeToken_BothProduceAuditRows(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() }) //nolint:errcheck

	tokenSvc := enroll.NewService(enroll.NewMemoryRepository())
	tr := &fakeTokenRevoker{}
	d := Deps{Tokens: tokenSvc, TokenRevoker: tr, Audit: st.Audit(), Now: fixedNow}
	h := newTestHandler(d)

	mintRec := do(t, h, http.MethodPost, "/api/v1/enrollment-tokens", mintTokenRequest{
		Scope:      []string{"relay:env=prod"},
		TTLSeconds: 3600,
	})
	if mintRec.Code != http.StatusCreated {
		t.Fatalf("mint status = %d, want %d; body = %s", mintRec.Code, http.StatusCreated, mintRec.Body.String())
	}
	var mintResp mintTokenResponse
	if err := json.Unmarshal(mintRec.Body.Bytes(), &mintResp); err != nil {
		t.Fatalf("decode mint response: %v", err)
	}

	revokeRec := do(t, h, http.MethodDelete, "/api/v1/enrollment-tokens/"+mintResp.ID, nil)
	if revokeRec.Code != http.StatusNoContent {
		t.Fatalf("revoke status = %d, want %d; body = %s", revokeRec.Code, http.StatusNoContent, revokeRec.Body.String())
	}

	records, err := st.Audit().List(context.Background())
	if err != nil {
		t.Fatalf("st.Audit().List: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("audit records = %d, want 2 (mint + revoke both persisted)", len(records))
	}
	if records[0].ID == "" || records[1].ID == "" {
		t.Fatalf("audit Record.ID must be non-empty on every row: %+v, %+v", records[0], records[1])
	}
	if records[0].ID == records[1].ID {
		t.Fatalf("audit Record.ID must be unique per row, both are %q", records[0].ID)
	}
	kinds := map[string]bool{records[0].Kind: true, records[1].Kind: true}
	if !kinds[audit.KindTokenMint] || !kinds[audit.KindTokenRevoke] {
		t.Errorf("audit Kinds = %v, want both %q and %q present", kinds, audit.KindTokenMint, audit.KindTokenRevoke)
	}
}
