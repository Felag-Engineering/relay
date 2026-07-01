package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/ca"
	gleipnirv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/gleipnir/v1"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mintToken creates an Enrollment Token in svc with the given scope and a 1-hour TTL.
// It returns the stored *Token (for tok.ID, used in Revoke tests) and the plaintext credential.
func mintToken(t *testing.T, svc *Service, scope []string) (*Token, string) {
	t.Helper()
	tok, plaintext, err := svc.Create(context.Background(), scope, time.Hour)
	if err != nil {
		t.Fatalf("mintToken: %v", err)
	}
	return tok, plaintext
}

// genCSR generates a fresh ECDSA P-256 CSR with the given CommonName.
// The CN is deliberately set to a value that must NOT appear in the issued cert,
// proving that SignCSR ignores the CSR subject (ADR-0006).
func genCSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genCSR: generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("genCSR: create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// newEnrollServer is a test helper that wires up a Server with the provided Service.
func newEnrollServer(t *testing.T, svc *Service) (*Server, *registry.InMemory, *ca.CA) {
	t.Helper()
	realCA, err := ca.Open(t.TempDir())
	if err != nil {
		t.Fatalf("ca.Open: %v", err)
	}
	reg := registry.NewInMemory()
	return NewServer(svc, realCA, reg), reg, realCA
}

// parseCert decodes a PEM certificate and returns the parsed *x509.Certificate.
func parseCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("parseCert: invalid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parseCert: %v", err)
	}
	return cert
}

// TestEnroll_Success verifies the happy path: a valid token + valid CSR + node: self_labels
// produce a signed cert (CN == NodeId, not the CSR CN), the correct CA bundle, relay: labels
// from the token scope, and a fully-populated registry entry.
func TestEnroll_Success(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, reg, realCA := newEnrollServer(t, svc)

	scope := []string{"relay:role=web", "relay:env=prod"}
	tok, plaintext := mintToken(t, svc, scope)

	req := &gleipnirv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "bogus-daemon-cn-must-be-ignored"),
		SelfLabels: []*gleipnirv1.Label{
			{Key: "node:role", Value: "web"},
		},
		Facts: &gleipnirv1.Facts{
			Hostname: "host-1",
			Os:       "linux",
		},
	}

	resp, err := srv.Enroll(context.Background(), req)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// NodeId must be non-empty and have the "node-" prefix.
	if resp.NodeId == "" {
		t.Error("NodeId must not be empty")
	}
	if !strings.HasPrefix(resp.NodeId, "node-") {
		t.Errorf("NodeId must have node- prefix, got %q", resp.NodeId)
	}

	// Certificate: parse and assert CN == NodeId (not the bogus CSR CN).
	cert := parseCert(t, resp.Certificate)
	if cert.Subject.CommonName != resp.NodeId {
		t.Errorf("cert CN: got %q, want NodeId %q (Relay must assign identity)", cert.Subject.CommonName, resp.NodeId)
	}

	// CaBundle must match the real CA.
	if string(resp.CaBundle) != string(realCA.Bundle()) {
		t.Error("CaBundle does not match CA bundle")
	}

	// AssignedLabels must carry the relay: namespace prefix in Key.
	if len(resp.AssignedLabels) != 2 {
		t.Fatalf("AssignedLabels len: got %d, want 2", len(resp.AssignedLabels))
	}
	assignedByKey := make(map[string]string, len(resp.AssignedLabels))
	for _, l := range resp.AssignedLabels {
		assignedByKey[l.Key] = l.Value
	}
	if assignedByKey["relay:role"] != "web" {
		t.Errorf("AssignedLabels[relay:role]: got %q, want web", assignedByKey["relay:role"])
	}
	if assignedByKey["relay:env"] != "prod" {
		t.Errorf("AssignedLabels[relay:env]: got %q, want prod", assignedByKey["relay:env"])
	}

	// Registry entry: node: labels from self_labels (bare keys), relay: labels from scope (bare keys).
	node, ok := reg.Get(resp.NodeId)
	if !ok {
		t.Fatal("Node not found in registry")
	}
	if node.NodeLabels["role"] != "web" {
		t.Errorf("NodeLabels[role]: got %q, want web", node.NodeLabels["role"])
	}
	if node.RelayLabels["role"] != "web" {
		t.Errorf("RelayLabels[role]: got %q, want web", node.RelayLabels["role"])
	}
	if node.RelayLabels["env"] != "prod" {
		t.Errorf("RelayLabels[env]: got %q, want prod", node.RelayLabels["env"])
	}
	if node.EnrollingTokenID != tok.ID {
		t.Errorf("EnrollingTokenID: got %q, want %q", node.EnrollingTokenID, tok.ID)
	}
	// Facts mapping: prove the proto→domain mapping actually ran.
	if node.Facts.Hostname != "host-1" {
		t.Errorf("Facts.Hostname: got %q, want host-1", node.Facts.Hostname)
	}
}

// TestEnroll_IdentityNotFromCSR proves that the issued cert CN is the Relay-assigned
// node_id and not the CN the daemon placed in the CSR (ADR-0006).
func TestEnroll_IdentityNotFromCSR(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, _, _ := newEnrollServer(t, svc)

	_, plaintext := mintToken(t, svc, []string{"relay:env=prod"})

	const csrCN = "daemon-wants-this-identity"
	req := &gleipnirv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, csrCN),
	}

	resp, err := srv.Enroll(context.Background(), req)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	cert := parseCert(t, resp.Certificate)
	if cert.Subject.CommonName == csrCN {
		t.Errorf("cert CN must not match CSR CN %q; Relay must assign node identity", csrCN)
	}
}

// TestEnroll_InvalidToken verifies that a garbage credential returns PermissionDenied
// and leaves no registry entry.
func TestEnroll_InvalidToken(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, reg, _ := newEnrollServer(t, svc)

	req := &gleipnirv1.EnrollRequest{
		EnrollmentToken: "deadbeef.notavalidtoken",
		Csr:             genCSR(t, "cn"),
	}

	_, err := srv.Enroll(context.Background(), req)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("invalid token: want PermissionDenied, got %v", err)
	}
	if len(reg.List()) != 0 {
		t.Errorf("registry must be empty after rejection, got %d entries", len(reg.List()))
	}
}

// TestEnroll_ExpiredToken verifies that an expired token returns PermissionDenied
// and leaves no registry entry.
func TestEnroll_ExpiredToken(t *testing.T) {
	svc, clk := newTestService(t) // fakeNow defined in token_test.go
	srv, reg, _ := newEnrollServer(t, svc)

	_, plaintext := mintToken(t, svc, []string{"relay:env=prod"})
	clk.advance(2 * time.Hour) // past the 1-hour TTL

	req := &gleipnirv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "cn"),
	}

	_, err := srv.Enroll(context.Background(), req)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("expired token: want PermissionDenied, got %v", err)
	}
	if len(reg.List()) != 0 {
		t.Errorf("registry must be empty after rejection, got %d entries", len(reg.List()))
	}
}

// TestEnroll_RevokedToken verifies that a revoked token returns PermissionDenied
// and leaves no registry entry.
func TestEnroll_RevokedToken(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, reg, _ := newEnrollServer(t, svc)

	tok, plaintext := mintToken(t, svc, []string{"relay:env=prod"})
	if err := svc.Revoke(context.Background(), tok.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	req := &gleipnirv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "cn"),
	}

	_, err := srv.Enroll(context.Background(), req)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("revoked token: want PermissionDenied, got %v", err)
	}
	if len(reg.List()) != 0 {
		t.Errorf("registry must be empty after rejection, got %d entries", len(reg.List()))
	}
}

// TestEnroll_ExhaustedToken verifies that a single-use token can enroll exactly once.
// The second Enroll returns PermissionDenied and must not add a new registry entry.
func TestEnroll_ExhaustedToken(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, reg, _ := newEnrollServer(t, svc)

	_, pt, err := svc.Create(context.Background(), []string{"relay:env=prod"}, time.Hour, WithMaxUses(1))
	if err != nil {
		t.Fatalf("Create single-use: %v", err)
	}

	// First enrollment must succeed.
	if _, err := srv.Enroll(context.Background(), &gleipnirv1.EnrollRequest{
		EnrollmentToken: pt,
		Csr:             genCSR(t, "cn"),
	}); err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	if len(reg.List()) != 1 {
		t.Errorf("after first Enroll: want 1 registry entry, got %d", len(reg.List()))
	}

	// Second enrollment must be rejected — MaxUses exhausted.
	_, err = srv.Enroll(context.Background(), &gleipnirv1.EnrollRequest{
		EnrollmentToken: pt,
		Csr:             genCSR(t, "cn"),
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("exhausted token: want PermissionDenied, got %v", err)
	}
	// Must still be exactly 1 entry — the second rejection must not add one.
	if len(reg.List()) != 1 {
		t.Errorf("after second (rejected) Enroll: want 1 registry entry, got %d", len(reg.List()))
	}
}

// TestEnroll_BadCSR verifies that a malformed CSR returns InvalidArgument
// and leaves no registry entry.
func TestEnroll_BadCSR(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, reg, _ := newEnrollServer(t, svc)

	_, plaintext := mintToken(t, svc, []string{"relay:env=prod"})

	req := &gleipnirv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             []byte("this is not a valid CSR"),
	}

	_, err := srv.Enroll(context.Background(), req)
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad CSR: want InvalidArgument, got %v", err)
	}
	if len(reg.List()) != 0 {
		t.Errorf("registry must be empty after bad CSR, got %d entries", len(reg.List()))
	}
}

// TestEnroll_NonNodeSelfLabel verifies that self_labels without the "node:" prefix
// (or with an empty bare key) are rejected with InvalidArgument, and the registry
// and relay space remain untouched.
func TestEnroll_NonNodeSelfLabel(t *testing.T) {
	cases := []struct {
		name  string
		label *gleipnirv1.Label
	}{
		{"relay-prefix", &gleipnirv1.Label{Key: "relay:env", Value: "prod"}},
		{"bare-key", &gleipnirv1.Label{Key: "role", Value: "web"}},
		{"empty-bare-key", &gleipnirv1.Label{Key: "node:", Value: ""}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewService(NewMemoryRepository())
			srv, reg, _ := newEnrollServer(t, svc)

			_, plaintext := mintToken(t, svc, []string{"relay:env=prod"})

			req := &gleipnirv1.EnrollRequest{
				EnrollmentToken: plaintext,
				Csr:             genCSR(t, "cn"),
				SelfLabels:      []*gleipnirv1.Label{tc.label},
			}

			_, err := srv.Enroll(context.Background(), req)
			if status.Code(err) != codes.InvalidArgument {
				t.Errorf("non-node: label %q: want InvalidArgument, got %v", tc.label.Key, err)
			}
			if len(reg.List()) != 0 {
				t.Errorf("registry must be empty after rejection, got %d entries", len(reg.List()))
			}
		})
	}
}

// fakeDenylister implements NodeDenylister and records every RevokeNode call for
// assertion in tests. It does not interact with any real denylist.
type fakeDenylister struct{ revoked []string }

func (f *fakeDenylister) RevokeNode(nodeID string) { f.revoked = append(f.revoked, nodeID) }

// buildRaceServer is a test helper that wires a Server with a real CA, registry,
// and the given token Service plus a fakeDenylister and WithPostEnrollRevocationCheck.
// It returns the server, the registry, and the denylister for assertions.
func buildRaceServer(t *testing.T, svc *Service) (*Server, *registry.InMemory, *fakeDenylister) {
	t.Helper()
	realCA, err := ca.Open(t.TempDir())
	if err != nil {
		t.Fatalf("ca.Open: %v", err)
	}
	reg := registry.NewInMemory()
	den := &fakeDenylister{}
	srv := NewServer(svc, realCA, reg, WithPostEnrollRevocationCheck(svc, den))
	return srv, reg, den
}

// TestEnroll_PostUpsertRevocationCheck_ClosesRaceWindow is the primary DoD test for
// issue #57. It simulates the escape window: Validate succeeds (token valid), then
// the token is revoked before Upsert (mimicking a concurrent RevokeToken cascade
// completing its bounded re-scan), and the post-check must catch and close the gap.
//
// Assertions:
//   - Enroll returns codes.PermissionDenied (fail-closed).
//   - The fakeDenylister recorded a RevokeNode call for the minted node id
//     (self-denylist ran). Note: this is verified via the fake recorder, not the
//     real Denylist.
//   - The Node IS present in the registry (Upsert ran before the post-check),
//     confirming the bounded cascade scan would have missed it.
func TestEnroll_PostUpsertRevocationCheck_ClosesRaceWindow(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, reg, den := buildRaceServer(t, svc)

	tok, plaintext := mintToken(t, svc, []string{"relay:env=prod"})

	// Inject newID to simulate the race: revoke the token mid-enrollment (after
	// Validate succeeds, before Upsert) and return a deterministic node id.
	srv.newID = func() (string, error) {
		if err := svc.Revoke(context.Background(), tok.ID); err != nil {
			t.Errorf("race hook Revoke: %v", err)
		}
		return "node-race-1", nil
	}

	req := &gleipnirv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "bogus-cn"),
	}
	_, err := srv.Enroll(context.Background(), req)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("race window: want PermissionDenied, got %v", err)
	}

	// The minted node must have been self-denylisted.
	if len(den.revoked) != 1 || den.revoked[0] != "node-race-1" {
		t.Errorf("denylist: want [node-race-1], got %v", den.revoked)
	}

	// The Node must be in the registry — Upsert ran; the cascade would have missed it.
	if _, ok := reg.Get("node-race-1"); !ok {
		t.Error("registry: node-race-1 must be present (Upsert ran before post-check)")
	}
}

// TestEnroll_PostUpsertRevocationCheck_AllowsCleanEnroll verifies no false positive:
// when the token is still valid at post-check time, Enroll succeeds and the
// denylister records no calls.
func TestEnroll_PostUpsertRevocationCheck_AllowsCleanEnroll(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, _, den := buildRaceServer(t, svc)

	_, plaintext := mintToken(t, svc, []string{"relay:env=prod"})

	req := &gleipnirv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "bogus-cn"),
	}
	_, err := srv.Enroll(context.Background(), req)
	if err != nil {
		t.Errorf("clean enroll: want nil error, got %v", err)
	}
	if len(den.revoked) != 0 {
		t.Errorf("clean enroll: denylist must be empty, got %v", den.revoked)
	}
}

// TestEnroll_NoPostCheck_BackwardCompatible verifies that NewServer without any
// option (revocationChecker == nil) still handles a happy-path enrollment
// correctly — the post-check is skipped entirely.
func TestEnroll_NoPostCheck_BackwardCompatible(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, _, _ := newEnrollServer(t, svc) // plain NewServer, no option

	_, plaintext := mintToken(t, svc, []string{"relay:env=prod"})

	req := &gleipnirv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             genCSR(t, "bogus-cn"),
	}
	_, err := srv.Enroll(context.Background(), req)
	if err != nil {
		t.Errorf("backward compat: want nil error, got %v", err)
	}
}

// TestEnroll_EmptyTokenOrCSR verifies that missing token or CSR returns InvalidArgument.
func TestEnroll_EmptyTokenOrCSR(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, _, _ := newEnrollServer(t, svc)

	csrPEM := genCSR(t, "cn")

	cases := []struct {
		name string
		req  *gleipnirv1.EnrollRequest
	}{
		{"empty-token", &gleipnirv1.EnrollRequest{Csr: csrPEM}},
		{"empty-csr", &gleipnirv1.EnrollRequest{EnrollmentToken: "some.token"}},
		{"both-empty", &gleipnirv1.EnrollRequest{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := srv.Enroll(context.Background(), tc.req)
			if status.Code(err) != codes.InvalidArgument {
				t.Errorf("%s: want InvalidArgument, got %v", tc.name, err)
			}
		})
	}
}
