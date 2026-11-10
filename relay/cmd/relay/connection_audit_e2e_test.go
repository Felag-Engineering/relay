package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// connAuditEnroll enrolls a Node and returns its ID, client certificate and the
// CA pool.
func connAuditEnroll(ctx context.Context, t *testing.T, f *relayFixture) (string, tls.Certificate, *x509.CertPool) {
	t.Helper()
	_, plaintext, err := f.Deps.tokens.Create(ctx, nil, time.Hour)
	if err != nil {
		t.Fatalf("seed Enrollment Token: %v", err)
	}
	pool := relaytest.CertPool(t, f.Deps.ca.Bundle())
	csrPEM, key := relaytest.NewCSR(t, "ignored-cn")
	resp, err := relayv1.NewEnrollmentClient(dialTLS(t, f.Bufconn, &tls.Config{RootCAs: pool})).Enroll(ctx, &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             csrPEM,
		Facts:           &relayv1.Facts{Hostname: "host-1298", Os: "linux"},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return resp.GetNodeId(), relaytest.AssembleClientCert(t, resp.GetCertificate(), key), pool
}

// connAuditRenew renews over an mTLS connection presenting cert and returns
// the renewed certificate.
func connAuditRenew(ctx context.Context, t *testing.T, f *relayFixture, cert tls.Certificate, pool *x509.CertPool) tls.Certificate {
	t.Helper()
	csrPEM, key := relaytest.NewCSR(t, "ignored-cn")
	conn := dialTLS(t, f.Bufconn, &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool})
	resp, err := relayv1.NewEnrollmentClient(conn).Renew(ctx, &relayv1.RenewRequest{Csr: csrPEM})
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	return relaytest.AssembleClientCert(t, resp.GetCertificate(), key)
}

// connAuditConnect opens a Tunnel presenting cert, sends hello and requires
// the Ping. The returned func ends the stream.
func connAuditConnect(ctx context.Context, t *testing.T, f *relayFixture, cert tls.Certificate, pool *x509.CertPool, hello *relayv1.Hello) func() {
	t.Helper()
	conn := dialTLS(t, f.Bufconn, &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool})
	sctx, cancel := context.WithCancel(ctx)
	stream, err := relayv1.NewTunnelClient(conn).Open(sctx)
	if err != nil {
		cancel()
		t.Fatalf("Tunnel Open: %v", err)
	}
	if err := stream.Send(&relayv1.DaemonMessage{Body: &relayv1.DaemonMessage_Hello{Hello: hello}}); err != nil {
		cancel()
		t.Fatalf("send Hello: %v", err)
	}
	msg, err := stream.Recv()
	if err != nil {
		cancel()
		t.Fatalf("recv Ping: %v", err)
	}
	if msg.GetPing() == nil {
		cancel()
		t.Fatalf("expected Ping after Hello, got %T", msg.Body)
	}
	return cancel
}

// connAuditRecords returns the audit records of one kind for nodeID.
func connAuditRecords(ctx context.Context, t *testing.T, f *relayFixture, nodeID, kind string) []audit.Record {
	t.Helper()
	all, err := f.Deps.audit.ByNode(ctx, nodeID)
	if err != nil {
		t.Fatalf("ByNode: %v", err)
	}
	var out []audit.Record
	for _, r := range all {
		if r.Kind == kind {
			out = append(out, r)
		}
	}
	return out
}

// connAuditFingerprint is the certificate fingerprint the registry holds for nodeID.
func connAuditFingerprint(t *testing.T, f *relayFixture, nodeID string) string {
	t.Helper()
	n, ok := f.Deps.registry.Get(nodeID)
	if !ok {
		t.Fatalf("node %s not in the registry", nodeID)
	}
	return n.CertFingerprint
}

// Proves NC-35.
func TestTunnelOpen_RenewThenReconnectWritesOneCertChangedRecord(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clk := &revokedDialClock{t: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	f := startRelay(t, WithConnectionClock(clk.Now))
	nodeID, cert1, pool := connAuditEnroll(ctx, t, f)
	fp1 := connAuditFingerprint(t, f, nodeID)

	end := connAuditConnect(ctx, t, f, cert1, pool, &relayv1.Hello{})
	if n := len(connAuditRecords(ctx, t, f, nodeID, audit.KindNodeCertChanged)); n != 0 {
		t.Fatalf("cert records after the first connect = %d, want 0", n)
	}
	end()

	cert2 := connAuditRenew(ctx, t, f, cert1, pool)
	end = connAuditConnect(ctx, t, f, cert2, pool, &relayv1.Hello{})
	defer end()
	fp2 := connAuditFingerprint(t, f, nodeID)
	if fp2 == fp1 {
		t.Fatal("renewal left the stored fingerprint unchanged")
	}

	recs := connAuditRecords(ctx, t, f, nodeID, audit.KindNodeCertChanged)
	if len(recs) != 1 {
		t.Fatalf("cert records after renew and reconnect = %d, want 1", len(recs))
	}
	want := "cert_fingerprint_before=" + fp1 + " cert_fingerprint_after=" + fp2 + " changes=1"
	if recs[0].Reason != want {
		t.Errorf("Reason = %q, want %q", recs[0].Reason, want)
	}
	if recs[0].Principal != "" {
		t.Errorf("Principal = %q, want empty", recs[0].Principal)
	}
	if !recs[0].Timestamp.Equal(clk.Now().UTC()) {
		t.Errorf("Timestamp = %v, want the injected clock %v", recs[0].Timestamp, clk.Now().UTC())
	}
}

// Proves NC-35.
func TestTunnelOpen_RenewalBeforeTheFirstConnectIsRecordedOnThatConnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	f := startRelay(t)
	nodeID, cert1, pool := connAuditEnroll(ctx, t, f)
	fp1 := connAuditFingerprint(t, f, nodeID)
	cert2 := connAuditRenew(ctx, t, f, cert1, pool)

	end := connAuditConnect(ctx, t, f, cert2, pool, &relayv1.Hello{DaemonVersion: "0.2.0"})
	defer end()
	fp2 := connAuditFingerprint(t, f, nodeID)

	recs := connAuditRecords(ctx, t, f, nodeID, audit.KindNodeCertChanged)
	if len(recs) != 1 {
		t.Fatalf("cert records = %d, want 1", len(recs))
	}
	want := "cert_fingerprint_before=" + fp1 + " cert_fingerprint_after=" + fp2 + " changes=1"
	if recs[0].Reason != want {
		t.Errorf("Reason = %q, want %q", recs[0].Reason, want)
	}
	if n := len(connAuditRecords(ctx, t, f, nodeID, audit.KindNodeDaemonVersionChanged)); n != 0 {
		t.Errorf("version records on a first connect = %d, want 0", n)
	}
}

// Proves NC-35.
func TestTunnelOpen_SameCertificateReconnectWritesNoCertRecord(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	f := startRelay(t)
	nodeID, cert, pool := connAuditEnroll(ctx, t, f)
	connAuditConnect(ctx, t, f, cert, pool, &relayv1.Hello{})()
	end := connAuditConnect(ctx, t, f, cert, pool, &relayv1.Hello{})
	defer end()

	if n := len(connAuditRecords(ctx, t, f, nodeID, audit.KindNodeCertChanged)); n != 0 {
		t.Errorf("cert records for an unchanged certificate = %d, want 0", n)
	}
}

// Proves NC-34.
func TestTunnelOpen_DaemonVersionBelowTheMinimumStillConnectsAndIsAudited(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	f := startRelay(t, WithConfig(func(c *Config) { c.MinDaemonVersion = "0.5.0" }))
	nodeID, cert, pool := connAuditEnroll(ctx, t, f)

	connAuditConnect(ctx, t, f, cert, pool, &relayv1.Hello{DaemonVersion: "0.4.0"})()
	if n := len(connAuditRecords(ctx, t, f, nodeID, audit.KindNodeDaemonVersionChanged)); n != 0 {
		t.Fatalf("version records after the first connect = %d, want 0", n)
	}

	end := connAuditConnect(ctx, t, f, cert, pool, &relayv1.Hello{DaemonVersion: "0.3.0"})
	defer end()
	n, ok := f.Deps.registry.Get(nodeID)
	if !ok || !n.Connected || !n.Outdated {
		t.Errorf("node = %+v (found %v), want Connected and Outdated", n, ok)
	}
	recs := connAuditRecords(ctx, t, f, nodeID, audit.KindNodeDaemonVersionChanged)
	if len(recs) != 1 {
		t.Fatalf("version records = %d, want 1", len(recs))
	}
	if want := "version_before=0.4.0 version_after=0.3.0 downgrade=true changes=1"; recs[0].Reason != want {
		t.Errorf("Reason = %q, want %q", recs[0].Reason, want)
	}
	if recs[0].Principal != "" {
		t.Errorf("Principal = %q, want empty", recs[0].Principal)
	}
}
