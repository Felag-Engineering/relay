package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"google.golang.org/grpc/test/bufconn"

	"github.com/Felag-Engineering/relay/relay/internal/enroll"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// seedToken creates an hour-long Enrollment Token naming initialTags through the
// test-only deps.tokens path, which no production surface reaches, and returns
// it with its plaintext.
func seedToken(ctx context.Context, t *testing.T, deps *appDeps, initialTags []string, opts ...enroll.Option) (*enroll.Token, string) {
	t.Helper()
	tok, plaintext, err := deps.tokens.Create(ctx, initialTags, time.Hour, opts...)
	if err != nil {
		t.Fatalf("seed Enrollment Token: %v", err)
	}
	return tok, plaintext
}

// enrolledNode is a Node a test enrolled: its Relay-assigned ID, the client
// certificate it presents on a Tunnel, and a pool trusting the Relay CA.
type enrolledNode struct {
	ID   string
	Cert tls.Certificate
	Pool *x509.CertPool
}

// tryEnroll sends one certless Enroll over lis presenting token, as a linux
// Node named hostname, and returns the Relay's answer with the key behind the
// CSR. The CSR's subject is a placeholder: the Relay never trusts it.
func tryEnroll(ctx context.Context, t *testing.T, lis *bufconn.Listener, deps *appDeps, token, hostname string) (*relayv1.EnrollResponse, *ecdsa.PrivateKey, error) {
	t.Helper()
	conn := dialTLS(t, lis, &tls.Config{RootCAs: relaytest.CertPool(t, deps.ca.Bundle())})
	csrPEM, key := relaytest.NewCSR(t, "ignored-cn")
	resp, err := relayv1.NewEnrollmentClient(conn).Enroll(ctx, &relayv1.EnrollRequest{
		EnrollmentToken: token,
		Csr:             csrPEM,
		Facts:           &relayv1.Facts{Hostname: hostname, Os: "linux"},
	})
	return resp, key, err
}

// enrollNode is tryEnroll for a test that needs the enrollment to succeed: a
// refusal or an empty node_id fails the test.
func enrollNode(ctx context.Context, t *testing.T, lis *bufconn.Listener, deps *appDeps, token, hostname string) enrolledNode {
	t.Helper()
	resp, key, err := tryEnroll(ctx, t, lis, deps, token, hostname)
	if err != nil {
		t.Fatalf("Enroll as %s: %v", hostname, err)
	}
	if resp.GetNodeId() == "" {
		t.Fatalf("Enroll as %s: node_id is empty", hostname)
	}
	return enrolledNode{
		ID:   resp.GetNodeId(),
		Cert: relaytest.AssembleClientCert(t, resp.GetCertificate(), key),
		Pool: relaytest.CertPool(t, deps.ca.Bundle()),
	}
}
