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
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/revocation"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

// -----------------------------------------------------------------------
// Fakes for the narrow collaborator interfaces in api.go.
// -----------------------------------------------------------------------

// fakeTokenRevoker is a TokenRevoker fake that records every id it was
// called with and returns a configurable error.
//
// cascade, when non-empty, stands in for the Nodes revocation.Service's
// re-scan would have found: RevokeToken calls record(cascade) ONCE, with the
// whole cascade as one chunk — mirroring the real Service's one-call-per-chunk
// contract — COLLECTING the returned error into recordErrs. Collecting rather
// than discarding the return value is what makes mutation 4 (a recorder
// closure that swallows the audit error) redden. cascadeErr, if set, is
// returned from RevokeToken after the record call, standing in for
// revocation.Service's own ErrCascadeNotRecorded return.
type fakeTokenRevoker struct {
	mu         sync.Mutex
	calledWith []string
	err        error

	cascade    []string
	cascadeErr error
	recordErrs []error
}

func (f *fakeTokenRevoker) RevokeToken(_ context.Context, id string, record revocation.RevocationRecorder) error {
	f.mu.Lock()
	f.calledWith = append(f.calledWith, id)
	cascade := f.cascade
	f.mu.Unlock()

	if len(cascade) > 0 {
		err := record(cascade)
		f.mu.Lock()
		f.recordErrs = append(f.recordErrs, err)
		f.mu.Unlock()
	}
	if f.cascadeErr != nil {
		return f.cascadeErr
	}
	return f.err
}

// fakeNodeRevoker is a NodeRevoker fake that records every node_id it was
// called with.
//
// This double proves only that the route hands NodeRevoker the right node_id
// and the right recorder, and renders the recorder's own error correctly —
// the real ordering (record before act), the Node lock, and the
// cascade-record suppression are all proven at their actual seam in
// internal/revocation (#605), not here.
type fakeNodeRevoker struct {
	mu         sync.Mutex
	calledWith []string

	// err, when set, is returned by RevokeNodeRecorded instead of calling
	// record — for a test that needs the method itself to fail, as opposed
	// to the recorder it was handed.
	err error
}

func (f *fakeNodeRevoker) RevokeNodeRecorded(_ context.Context, nodeID string, record revocation.RevocationRecorder) error {
	f.mu.Lock()
	err := f.err
	f.mu.Unlock()
	if err != nil {
		return err
	}

	if recErr := record([]string{nodeID}); recErr != nil {
		return recErr
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.calledWith = append(f.calledWith, nodeID)
	return nil
}

// fakeCapabilityAuditSink is a minimal capability.AuditSink test double
// (#680): NodeReader is now the capability read lane itself, so exercising
// it needs a real *capability.ReadLane, which needs a real (non-noop)
// AuditSink. Only RecordRead is exercised by DescribeNode; the rest of the
// interface is a no-op.
type fakeCapabilityAuditSink struct {
	err       error
	readCalls int
}

func (*fakeCapabilityAuditSink) Record(context.Context, capability.AuditEntry) error { return nil }
func (*fakeCapabilityAuditSink) RecordFreeze(context.Context, capability.FreezeEvent) error {
	return nil
}
func (*fakeCapabilityAuditSink) RecordCancel(context.Context, capability.Principal, string) error {
	return nil
}
func (s *fakeCapabilityAuditSink) RecordRead(context.Context, capability.Principal, string, string, string, string) error {
	s.readCalls++
	return s.err
}
func (*fakeCapabilityAuditSink) RecordAccountAdmin(context.Context, capability.Principal, capability.AccountAdminEvent) error {
	return nil
}

// newNodeReaderLane builds a real *capability.ReadLane over reg, wired as a
// NodeReader (#680): capability.ReadLane satisfies NodeReader directly, with
// no adapter, exactly like Exec/Approvals/AccountAdmin already do. now and
// certExpiringWithin are pinned so a test asserting a state: label does not
// race the wall clock — the `state:` instant now comes from the lane's own
// clock (detail.Eval), not from Deps.Now/Deps.CertExpiringWithin.
func newNodeReaderLane(t *testing.T, reg registry.Repository, sink capability.AuditSink, now func() time.Time, certExpiringWithin time.Duration) NodeReader {
	t.Helper()
	return newCapService(t, capSeams{
		reg:        reg,
		audit:      sink,
		now:        now,
		certWindow: certExpiringWithin,
	}).ReadLane
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
// standing in for what capability.Execution does with the same object (#397).
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
//
// appendCalls tracks only what arrived through the SINGULAR Append, kept
// distinct from records (which also holds what AppendAll wrote) so a test can
// assert a KindNodeRevoke row never arrives through Append — the tell for a
// recorder closure that reverted to looping over single-record Append calls.
type fakeAuditor struct {
	mu          sync.Mutex
	records     []audit.Record
	appendCalls []audit.Record
	allCalls    [][]audit.Record
	err         error
}

// Append keeps r even when f.err is set — it reports the failure but does not
// pretend the record was never offered. audit.Repository.Append declares no
// such contract itself; keeping r is this fake's own long-standing behaviour,
// and the tests that exercise it assert on the returned error, not on
// whether records was mutated.
func (f *fakeAuditor) Append(_ context.Context, r audit.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, r)
	f.appendCalls = append(f.appendCalls, r)
	return f.err
}

// AppendAll drops everything in rs on error instead of keeping it, unlike
// Append above — that asymmetry is the all-or-nothing contract itself
// (audit.Repository.AppendAll), not a fake-specific shortcut: a real error
// from AppendAll means the transaction rolled back and nothing was written.
func (f *fakeAuditor) AppendAll(_ context.Context, rs []audit.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allCalls = append(f.allCalls, append([]audit.Record(nil), rs...))
	if f.err != nil {
		return f.err
	}
	f.records = append(f.records, rs...)
	return nil
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

const testCredential = accounts.TokenPrefix + "1234567890abcdef.test-secret" // test fixture, not a real credential

// staticVerifier is a controlplane.TokenVerifier that accepts exactly one
// credential, as the founding admin Account. The identity-management tests in
// accounts_test.go use the REAL TokenService over a real store; this fake
// exists only so the pre-existing lifecycle-route tests keep their focus on
// the routes rather than on minting a credential first.
const testTokenID = "tok-test"

// testFoundingAdminAccountID is staticVerifier's stand-in for the Relay-
// assigned stable identifier a real store.Accounts().EnsureFoundingAdmin
// would mint. Given so tests can assert Attribution.Verified.AccountID is
// non-empty and identity-stable, mirroring what principalFromAccount does
// with a real Account in production.
const testFoundingAdminAccountID = "acct-founding-admin"

type staticVerifier struct{ credential string }

func (v staticVerifier) Verify(_ context.Context, credential string) (accounts.Account, accounts.APIToken, error) {
	if credential != v.credential {
		return accounts.Account{}, accounts.APIToken{}, accounts.ErrTokenInvalid
	}
	return accounts.Account{
		ID:      testFoundingAdminAccountID,
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
	p.AccountID = testFoundingAdminAccountID
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
		// #555: the scope is relay:-prefixed but fails the well-formedness
		// gate. This is an end-to-end status check through the REAL
		// enroll.Service (tokenSvc below), so it also pins that a violation
		// still maps to 400 and not 500 — RED ON introducing a second
		// sentinel without adding it to tokens.go's errors.Is list.
		{"comma-injected second term", mintTokenRequest{Scope: []string{"relay:env=prod,node:role=web"}, TTLSeconds: 3600}},
		{"zero width space in key", mintTokenRequest{Scope: []string{"relay:quarantine\u200b=on"}, TTLSeconds: 3600}},
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

// TestHandleRevokeToken_CascadeRecordsCarryPrincipalAndDerivedReason is the
// heart of #557: it must fail if the cascade's per-Node records exist but are
// unattributed, not just if they are missing. A test that only counted audit
// records would be satisfied by a KindNodeRevoke row with an empty Principal
// and a blank Attribution — exactly the half-fix the issue's testing note
// warns about — so this asserts field VALUES, never the count alone
// (mutation 3).
func TestHandleRevokeToken_CascadeRecordsCarryPrincipalAndDerivedReason(t *testing.T) {
	tr := &fakeTokenRevoker{cascade: []string{"node-a", "node-b"}}
	auditor := &fakeAuditor{}
	d := Deps{TokenRevoker: tr, Audit: auditor, Now: fixedNow}
	h := newTestHandler(d)

	// The ASSERTED lane is exercised too, not just the verified one. The two are
	// kept structurally apart (ADR-0027 decision 10, GLOSSARY.md "Attribution"),
	// and a cascade row that carried the verified lane while silently dropping
	// the asserted one would be half-attributed in exactly the way that split
	// exists to prevent. Nothing pinned it until the security review asked.
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/enrollment-tokens/tok-123", nil)
	req.Header.Set("Authorization", "Bearer "+testCredential)
	req.Header.Set(controlplane.HeaderOnBehalfOf, "carol@example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	records := auditor.all()
	if len(records) != 3 {
		t.Fatalf("audit records = %d, want 3 (one token_revoke + two node_revoke)", len(records))
	}

	seenIDs := map[string]bool{}
	nodeRows := map[string]audit.Record{}
	for _, r := range records {
		if r.ID == "" {
			t.Errorf("audit Record.ID is empty: %+v", r)
		}
		if seenIDs[r.ID] {
			t.Errorf("audit Record.ID %q reused across rows", r.ID)
		}
		seenIDs[r.ID] = true
		if r.Kind == audit.KindNodeRevoke {
			nodeRows[r.NodeID] = r
		}
	}
	if len(nodeRows) != 2 {
		t.Fatalf("node_revoke rows = %v, want exactly node-a and node-b", nodeRows)
	}

	wantPrincipal := controlplane.FoundingAdmin().Attribution()
	for _, nodeID := range []string{"node-a", "node-b"} {
		row, ok := nodeRows[nodeID]
		if !ok {
			t.Fatalf("no node_revoke row for %s", nodeID)
		}
		if row.Principal != wantPrincipal {
			t.Errorf("%s: Principal = %q, want %q", nodeID, row.Principal, wantPrincipal)
		}
		v := row.Attribution.Verified
		if v.AccountID == "" || v.AccountID != testFoundingAdminAccountID {
			t.Errorf("%s: Verified.AccountID = %q, want the founding admin's non-empty id %q", nodeID, v.AccountID, testFoundingAdminAccountID)
		}
		if v.AccountName == "" || v.AccountName != accounts.FoundingAdminName {
			t.Errorf("%s: Verified.AccountName = %q, want %q", nodeID, v.AccountName, accounts.FoundingAdminName)
		}
		if v.Role == "" || v.Role != string(accounts.RoleAdmin) {
			t.Errorf("%s: Verified.Role = %q, want %q", nodeID, v.Role, accounts.RoleAdmin)
		}
		// The asserted lane, kept structurally apart from the verified one.
		// A cascade row carrying one and dropping the other is half-attributed
		// in exactly the way that split exists to prevent, and it survives
		// context.WithoutCancel only because Value lookups delegate to the
		// parent — which is worth pinning rather than trusting.
		if got := row.Attribution.Asserted.OnBehalfOf; got != "carol@example.com" {
			t.Errorf("%s: Asserted.OnBehalfOf = %q, want the header's value — the asserted "+
				"lane did not survive onto the cascade row", nodeID, got)
		}
		wantReason := capability.CascadeRevokeReason("tok-123")
		if row.Reason != wantReason {
			t.Errorf("%s: Reason = %q, want %q", nodeID, row.Reason, wantReason)
		}
	}
}

// TestHandleRevokeToken_UnrecordedCascadeStillRecordsTheTokenRevoke covers the
// completed-but-unrecorded 500: RevokeToken returning an error wrapping
// ErrCascadeNotRecorded means the token and its Nodes WERE revoked, so the
// KindTokenRevoke row must still be written even though the response is a
// 500.
func TestHandleRevokeToken_UnrecordedCascadeStillRecordsTheTokenRevoke(t *testing.T) {
	tr := &fakeTokenRevoker{
		cascade:    []string{"node-a"},
		cascadeErr: fmt.Errorf("wrap: %w", revocation.ErrCascadeNotRecorded),
	}
	auditor := &fakeAuditor{}
	d := Deps{TokenRevoker: tr, Audit: auditor, Now: fixedNow}
	h := newTestHandler(d)

	rec := do(t, h, http.MethodDelete, "/api/v1/enrollment-tokens/tok-123", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}

	var sawTokenRevoke bool
	for _, r := range auditor.all() {
		if r.Kind == audit.KindTokenRevoke {
			sawTokenRevoke = true
		}
	}
	if !sawTokenRevoke {
		t.Error("no KindTokenRevoke record was written despite the token and its Nodes having been revoked")
	}
}

// TestHandleRevokeToken_IncompleteCascadeRecordsTheRevokeAndSaysNodesMayBeTrusted
// covers G-E0's API half: RevokeToken returning an *IncompleteCascade means
// the token WAS revoked but the registry could not be read completely. The
// response must be an error that says Nodes may still be trusted — never the
// "Nodes were revoked" answer of the NotRecorded case — and the token revoke
// must still be on the trail, attributed and marked incomplete.
func TestHandleRevokeToken_IncompleteCascadeRecordsTheRevokeAndSaysNodesMayBeTrusted(t *testing.T) {
	tr := &fakeTokenRevoker{
		cascade: []string{"node-a"},
		cascadeErr: &revocation.IncompleteCascade{
			Revoked: 1, UnreadableNodeIDs: []string{"node-bad"}, UnreadableCount: 1,
			Err: errors.New("store unavailable"),
		},
	}
	auditor := &fakeAuditor{}
	d := Deps{TokenRevoker: tr, Audit: auditor, Now: fixedNow}
	h := newTestHandler(d)

	rec := do(t, h, http.MethodDelete, "/api/v1/enrollment-tokens/tok-123", nil)
	if rec.Code < 500 {
		t.Fatalf("status = %d, want a 5xx; body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "revoke not fully recorded") || strings.Contains(body, "Nodes were revoked") {
		t.Errorf("body = %s: an incomplete cascade must never claim the token's Nodes were revoked", body)
	}
	if !strings.Contains(body, "may still be trusted") {
		t.Errorf("body = %s: want it to say Nodes enrolled under the token may still be trusted", body)
	}

	var tokenRevokes []audit.Record
	for _, r := range auditor.all() {
		if r.Kind == audit.KindTokenRevoke {
			tokenRevokes = append(tokenRevokes, r)
		}
	}
	if len(tokenRevokes) != 1 {
		t.Fatalf("KindTokenRevoke records = %d, want 1: the token was revoked, so the trail must say who did it", len(tokenRevokes))
	}
	if got, want := tokenRevokes[0].Reason, "token_id=tok-123 cascade=incomplete"; got != want {
		t.Errorf("KindTokenRevoke Reason = %q, want %q", got, want)
	}
	if got, want := tokenRevokes[0].Principal, controlplane.FoundingAdmin().Attribution(); got != want {
		t.Errorf("KindTokenRevoke Principal = %q, want %q", got, want)
	}
}

// TestHandleRevokeToken_CascadeRecorderReportsAuditFailure asserts the
// recorder closure this handler builds propagates a real audit failure back
// to the caller (revocation.Service) rather than swallowing it — mutation 4.
// AppendAll's all-or-nothing contract means a single failing call loses the
// whole chunk, so this also asserts no KindNodeRevoke row exists afterward.
func TestHandleRevokeToken_CascadeRecorderReportsAuditFailure(t *testing.T) {
	auditErr := errors.New("audit store unavailable")
	tr := &fakeTokenRevoker{cascade: []string{"node-a", "node-b"}}
	auditor := &fakeAuditor{err: auditErr}
	d := Deps{TokenRevoker: tr, Audit: auditor, Now: fixedNow}
	h := newTestHandler(d)

	do(t, h, http.MethodDelete, "/api/v1/enrollment-tokens/tok-123", nil)

	if len(tr.recordErrs) != 1 {
		t.Fatalf("recordErrs = %v, want 1 entry (one call, covering the whole cascade chunk)", tr.recordErrs)
	}
	if tr.recordErrs[0] == nil {
		t.Error("recordErrs[0] = nil, want the recorder to report the audit failure")
	}
	for _, r := range auditor.all() {
		if r.Kind == audit.KindNodeRevoke {
			t.Errorf("found a KindNodeRevoke record %+v despite AppendAll erroring — "+
				"the all-or-nothing contract means none of the chunk should have been kept", r)
		}
	}
}

// TestHandleRevokeToken_CascadeRecorderWritesAllInOneCall asserts the
// recorder closure this handler builds writes a cascade's records through
// ONE Auditor.AppendAll call rather than looping over Append — the fix #563
// exists for. It goes red if the closure reverts to N Append calls.
func TestHandleRevokeToken_CascadeRecorderWritesAllInOneCall(t *testing.T) {
	tr := &fakeTokenRevoker{cascade: []string{"node-a", "node-b", "node-c"}}
	auditor := &fakeAuditor{}
	d := Deps{TokenRevoker: tr, Audit: auditor, Now: fixedNow}
	h := newTestHandler(d)

	rec := do(t, h, http.MethodDelete, "/api/v1/enrollment-tokens/tok-123", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	if len(auditor.allCalls) != 1 {
		t.Fatalf("AppendAll was called %d times, want exactly 1", len(auditor.allCalls))
	}
	call := auditor.allCalls[0]
	if len(call) != 3 {
		t.Fatalf("the one AppendAll call carried %d records, want 3", len(call))
	}
	seenIDs := map[string]bool{}
	for _, r := range call {
		if r.Kind != audit.KindNodeRevoke {
			t.Errorf("AppendAll record Kind = %q, want %q", r.Kind, audit.KindNodeRevoke)
		}
		if r.ID == "" || seenIDs[r.ID] {
			t.Errorf("AppendAll record ID = %q, want non-empty and unique across the call", r.ID)
		}
		seenIDs[r.ID] = true
	}

	for _, r := range auditor.appendCalls {
		if r.Kind == audit.KindNodeRevoke {
			t.Error("a KindNodeRevoke record arrived through a single Append call, want only AppendAll")
		}
	}
}

// TestHandleRevokeToken_RejectsUnrenderableTokenID asserts a token id that
// cannot be rendered into a valid revocation reason (an embedded control
// character) is refused with 400 before TokenRevoker is ever called and
// before any audit record is written — mutation 10.
func TestHandleRevokeToken_RejectsUnrenderableTokenID(t *testing.T) {
	tr := &fakeTokenRevoker{}
	auditor := &fakeAuditor{}
	d := Deps{TokenRevoker: tr, Audit: auditor, Now: fixedNow}
	h := newTestHandler(d)

	rec := doRaw(t, h, http.MethodDelete, "/api/v1/enrollment-tokens/tok%0Abad", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if len(tr.calledWith) != 0 {
		t.Errorf("TokenRevoker.RevokeToken called with %v, want it never called", tr.calledWith)
	}
	if len(auditor.all()) != 0 {
		t.Errorf("audit records = %v, want none", auditor.all())
	}
}

// TestRevokeTokenCascade_PersistsOneRowPerNode mirrors
// TestMintThenRevokeToken_BothProduceAuditRows: it drives a 5-Node cascade
// through the REAL SQLite-backed audit.Repository.
//
// The justification is narrower than it first looks, and a code review was right
// to press on it: the reused-ID check below runs in Go over the returned rows,
// so a fake Auditor would catch a duplicated Record.ID just as well. What the
// real store adds is that the writes GO THROUGH the schema at all — N rows for
// one request actually INSERT and read back, against the live audit table and
// its audit_id PRIMARY KEY, rather than accumulating in a slice. That is a
// weaker claim than "only SQLite can catch this", and it is the true one.
func TestRevokeTokenCascade_PersistsOneRowPerNode(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	cascade := []string{"node-1", "node-2", "node-3", "node-4", "node-5"}
	tr := &fakeTokenRevoker{cascade: cascade}
	d := Deps{TokenRevoker: tr, Audit: st.Audit(), Now: fixedNow}
	h := newTestHandler(d)

	rec := do(t, h, http.MethodDelete, "/api/v1/enrollment-tokens/tok-123", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	records, err := st.Audit().List(context.Background())
	if err != nil {
		t.Fatalf("st.Audit().List: %v", err)
	}
	if len(records) != len(cascade)+1 {
		t.Fatalf("audit records = %d, want %d (one token_revoke + %d node_revoke)",
			len(records), len(cascade)+1, len(cascade))
	}
	seen := map[string]bool{}
	for _, r := range records {
		if r.ID == "" {
			t.Errorf("audit Record.ID is empty: %+v", r)
		}
		if seen[r.ID] {
			t.Errorf("audit Record.ID %q reused across rows", r.ID)
		}
		seen[r.ID] = true
	}
	if len(seen) != len(cascade)+1 {
		t.Errorf("distinct audit_ids = %d, want %d", len(seen), len(cascade)+1)
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
		// This one refuses at decodeJSON's Content-Type check, BEFORE the reason
		// gate runs, so it is not a regression guard for this change — it would
		// pass with the validation deleted. It is here to document what a
		// pre-#487 caller now experiences. The case below it, an empty JSON
		// object, is the one that reaches and exercises the gate.
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
// other lifecycle actions keep — see revocation.Service.RevokeNodeRecorded
// for why revoke can and they cannot.
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

// TestHandleRevokeNode_RefusesWhenTheRevokerFails covers the branch where
// RevokeNodeRecorded itself fails before ever calling the recorder — e.g. a
// caller whose wait for the Node's lock was abandoned. This is distinct from
// TestHandleRevokeNode_RefusesWhenItCannotBeAudited, which fails INSIDE the
// recorder: here the record closure is never invoked at all.
func TestHandleRevokeNode_RefusesWhenTheRevokerFails(t *testing.T) {
	nr := &fakeNodeRevoker{err: errors.New("node lock wait: context canceled")}
	auditor := &fakeAuditor{}
	h := newTestHandler(Deps{Nodes: nr, Audit: auditor, Now: fixedNow})

	rec := do(t, h, http.MethodPost, "/api/v1/nodes/node-abc/revoke",
		map[string]string{"reason": "compromised host"})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body = %s", rec.Code, rec.Body.String())
	}
	if len(auditor.all()) != 0 {
		t.Errorf("a record was written despite RevokeNodeRecorded failing before ever calling the recorder: %v",
			auditor.all())
	}
	if strings.Contains(rec.Body.String(), nr.err.Error()) {
		t.Errorf("the revoker's error leaked into the response: %s", rec.Body.String())
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

// TestHandleRevokeNode_PassesExactlyOneNodeIDToTheRecorder guards against a
// future caller widening the slice the route's recorder closure receives:
// this route revokes exactly one Node, named by the path, and the recorder
// it hands to NodeRevoker.RevokeNodeRecorded must cover that node_id and
// nothing else.
func TestHandleRevokeNode_PassesExactlyOneNodeIDToTheRecorder(t *testing.T) {
	nr := &fakeNodeRevoker{}
	auditor := &fakeAuditor{}
	h := newTestHandler(Deps{Nodes: nr, Audit: auditor, Now: fixedNow})

	rec := do(t, h, http.MethodPost, "/api/v1/nodes/node-abc/revoke",
		map[string]string{"reason": "compromised host"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body = %s", rec.Code, rec.Body.String())
	}
	if len(auditor.allCalls) != 1 {
		t.Fatalf("AppendAll was called %d times, want exactly 1", len(auditor.allCalls))
	}
	if got := auditor.allCalls[0]; len(got) != 1 || got[0].NodeID != "node-abc" {
		t.Errorf("the one AppendAll call carried %+v, want exactly one record for node-abc", got)
	}
}

// -----------------------------------------------------------------------
// Node read (#414, ADR-0034)
// -----------------------------------------------------------------------

// TestHandleGetNode_StateLabels covers acceptance 8 on the Control API: a
// Node's derived state: labels render on GET /nodes/{id}, prefixed and never
// null — the same nodestate.Labels every other surface renders.
func TestHandleGetNode_StateLabels(t *testing.T) {
	t.Run("offline Node carries state:offline", func(t *testing.T) {
		reg := registry.NewInMemory()
		if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil { // never connected
			t.Fatalf("Upsert: %v", err)
		}
		lane := newNodeReaderLane(t, reg, &fakeCapabilityAuditSink{}, fixedNow, 0)
		d := Deps{NodeReader: lane, Audit: &fakeAuditor{}, Now: fixedNow}
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
		reg := registry.NewInMemory()
		if _, err := reg.Upsert(registry.Report{NodeID: "node-b"}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		reg.SetConnected("node-b", true)
		lane := newNodeReaderLane(t, reg, &fakeCapabilityAuditSink{}, fixedNow, 0)
		d := Deps{NodeReader: lane, Audit: &fakeAuditor{}, Now: fixedNow}
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

// TestHandleGetNode_FailsClosedWhenTheReadCannotBeRecorded is the Control
// API's half of QRY-28's fail-closed proof, and closes the "QRY-17, Control
// API half" no-row gap: a real *capability.ReadLane over an AuditSink whose
// RecordRead errors must answer 500 with the problem body — never a
// node_id, Labels or Facts in the response.
func TestHandleGetNode_FailsClosedWhenTheReadCannotBeRecorded(t *testing.T) {
	reg := registry.NewInMemory()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	lane := newNodeReaderLane(t, reg, &fakeCapabilityAuditSink{err: errors.New("the trail is unwritable")}, fixedNow, 0)
	d := Deps{NodeReader: lane, Audit: &fakeAuditor{}, Now: fixedNow}
	h := newTestHandler(d)

	rec := do(t, h, http.MethodGet, "/api/v1/nodes/node-a", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "node-a") || strings.Contains(body, "node_id") {
		t.Errorf("response body = %s, must not disclose the Node when the read could not be recorded", body)
	}
}

// TestHandleGetNode_AnOversizedNodeIdIsRefusedNotNotFound pins the
// behaviour change named in the PR body (#680): an oversized node_id used
// to record the probe and return 404; the lane's validateNodeID now refuses
// it first, returning 400 with nothing on the trail.
func TestHandleGetNode_AnOversizedNodeIdIsRefusedNotNotFound(t *testing.T) {
	reg := registry.NewInMemory()
	sink := &fakeCapabilityAuditSink{}
	lane := newNodeReaderLane(t, reg, sink, fixedNow, 0)
	d := Deps{NodeReader: lane, Audit: &fakeAuditor{}, Now: fixedNow}
	h := newTestHandler(d)

	oversized := strings.Repeat("n", 257)
	rec := do(t, h, http.MethodGet, "/api/v1/nodes/"+oversized, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (oversized node_id refused before recording); body = %s",
			rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if sink.readCalls != 0 {
		t.Errorf("RecordRead was called %d time(s) for an oversized id, want 0 — the trail is not caller storage", sink.readCalls)
	}

	// LOW 5 (security review, cycle 2): the lane's ErrInvalidFilter carries
	// an internal "capability: invalid query filter: " prefix that must
	// never reach a published problem detail.
	var body problem
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode problem body: %v", err)
	}
	if strings.Contains(body.Title, "capability:") || strings.Contains(body.Detail, "capability:") {
		t.Errorf("problem body = %+v, leaks the internal capability: package prefix", body)
	}
	if body.Detail != "must be 1-256 bytes" {
		t.Errorf("problem detail = %q, want the route's own wording", body.Detail)
	}
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

	// Freeze's audit trail is intrinsic to capability.Control (RecordFreeze):
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
	t.Cleanup(func() { st.Close() })

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
