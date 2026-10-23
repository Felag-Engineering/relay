package enroll

import (
	"context"
	"crypto/x509"
	"testing"

	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestRenew_Success verifies the happy path: a context carrying a valid node_id
// (as injected by the mTLS interceptor) plus a valid CSR produces a renewed
// certificate whose CN equals the context node_id (not the CSR CN), and whose
// CaBundle and NodeId fields are populated correctly.
func TestRenew_Success(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, _, realCA := newEnrollServer(t, svc)

	ctx := transport.NewContextWithNodeID(context.Background(), "node-abc")
	req := &relayv1.RenewRequest{
		Csr: genCSR(t, "bogus-csr-cn-must-be-ignored"),
	}

	resp, err := srv.Renew(ctx, req)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}

	if resp.NodeId != "node-abc" {
		t.Errorf("NodeId: got %q, want node-abc", resp.NodeId)
	}

	cert := parseCert(t, resp.Certificate)
	if cert.Subject.CommonName != "node-abc" {
		t.Errorf("cert CN: got %q, want node-abc", cert.Subject.CommonName)
	}

	if string(resp.CaBundle) != string(realCA.Bundle()) {
		t.Error("CaBundle does not match CA bundle")
	}

	// Verify the issued cert chains to the real CA using the CA bundle from the response.
	// The leaf cert is issued with ExtKeyUsageClientAuth (not ServerAuth), so we must
	// specify that in the verify options — the default checks for server auth.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(resp.CaBundle) {
		t.Fatal("failed to parse CaBundle into cert pool")
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("cert does not chain to CA: %v", err)
	}
}

// TestRenew_IgnoresCSRSubject proves that the issued cert CN is derived from
// the context node_id, not from the CN the daemon placed in the CSR.
// Proves EN-17.
func TestRenew_IgnoresCSRSubject(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, _, _ := newEnrollServer(t, svc)

	const csrCN = "daemon-wants-this-identity"
	ctx := transport.NewContextWithNodeID(context.Background(), "node-relay-assigned")
	req := &relayv1.RenewRequest{
		Csr: genCSR(t, csrCN),
	}

	resp, err := srv.Renew(ctx, req)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}

	cert := parseCert(t, resp.Certificate)
	if cert.Subject.CommonName == csrCN {
		t.Errorf("cert CN must not match CSR CN %q; node_id must come from the peer cert", csrCN)
	}
	if cert.Subject.CommonName != "node-relay-assigned" {
		t.Errorf("cert CN: got %q, want node-relay-assigned", cert.Subject.CommonName)
	}
}

// TestRenew_MissingNodeID verifies that a context without a node_id (i.e. no
// verified mTLS client cert) returns codes.Unauthenticated — fail closed.
// Proves EN-17.
func TestRenew_MissingNodeID(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, _, _ := newEnrollServer(t, svc)

	req := &relayv1.RenewRequest{
		Csr: genCSR(t, "cn"),
	}

	// Plain context.Background() carries no node_id — simulates a certless caller.
	_, err := srv.Renew(context.Background(), req)
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("missing node_id: want Unauthenticated, got %v", err)
	}
}

// TestRenew_EmptyCSR verifies that an empty CSR field returns codes.InvalidArgument.
func TestRenew_EmptyCSR(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, _, _ := newEnrollServer(t, svc)

	ctx := transport.NewContextWithNodeID(context.Background(), "node-abc")
	_, err := srv.Renew(ctx, &relayv1.RenewRequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty CSR: want InvalidArgument, got %v", err)
	}
}

// TestRenew_GarbageCSR verifies that a malformed CSR returns codes.InvalidArgument.
func TestRenew_GarbageCSR(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	srv, _, _ := newEnrollServer(t, svc)

	ctx := transport.NewContextWithNodeID(context.Background(), "node-abc")
	_, err := srv.Renew(ctx, &relayv1.RenewRequest{
		Csr: []byte("this is not a valid CSR"),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("garbage CSR: want InvalidArgument, got %v", err)
	}
}
