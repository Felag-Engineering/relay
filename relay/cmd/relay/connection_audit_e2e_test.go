package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
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

// connAuditSession is one whole stream: connAuditConnect, then msgs, then a
// clean end. The client's EOF arrives only after the handler and every
// deferred step has run, so every write of the stream, the Policy record
// included, has happened when it returns.
func connAuditSession(ctx context.Context, t *testing.T, f *relayFixture, cert tls.Certificate, pool *x509.CertPool, hello *relayv1.Hello, msgs ...*relayv1.DaemonMessage) {
	t.Helper()
	conn := dialTLS(t, f.Bufconn, &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool})
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := relayv1.NewTunnelClient(conn).Open(sctx)
	if err != nil {
		t.Fatalf("Tunnel Open: %v", err)
	}
	if err := stream.Send(&relayv1.DaemonMessage{Body: &relayv1.DaemonMessage_Hello{Hello: hello}}); err != nil {
		t.Fatalf("send Hello: %v", err)
	}
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv Ping: %v", err)
	}
	if msg.GetPing() == nil {
		t.Fatalf("expected Ping after Hello, got %T", msg.Body)
	}
	for _, m := range msgs {
		if err := stream.Send(m); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	for {
		if _, err := stream.Recv(); err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("stream ended with %v, want a clean end", err)
			}
			return
		}
	}
}

// Proves NC-33.
func TestTunnelOpen_ChangedPolicyWritesOneNodePolicyChangedRow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fpA, fpB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	clk := &revokedDialClock{t: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	f := startRelay(t, WithConnectionClock(clk.Now))
	nodeID, cert, pool := connAuditEnroll(ctx, t, f)

	connAuditSession(ctx, t, f, cert, pool, &relayv1.Hello{PolicyFingerprint: fpA}, policyMsg(false))
	if n := len(connAuditRecords(ctx, t, f, nodeID, audit.KindNodePolicyChanged)); n != 0 {
		t.Fatalf("policy records after the first connect = %d, want 0", n)
	}

	connAuditSession(ctx, t, f, cert, pool, &relayv1.Hello{PolicyFingerprint: fpB}, policyMsg(true))
	recs := connAuditRecords(ctx, t, f, nodeID, audit.KindNodePolicyChanged)
	if len(recs) != 1 {
		t.Fatalf("policy records after the change = %d, want 1", len(recs))
	}
	want := "policy_fingerprint_before=" + fpA + " policy_fingerprint_after=" + fpB +
		" raw_exec_before=false raw_exec_after=true changes=1"
	if recs[0].Reason != want {
		t.Errorf("Reason = %q, want %q", recs[0].Reason, want)
	}
	if recs[0].Principal != "" {
		t.Errorf("Principal = %q, want empty", recs[0].Principal)
	}
	if !recs[0].Timestamp.Equal(clk.Now().UTC()) {
		t.Errorf("Timestamp = %v, want the injected clock %v", recs[0].Timestamp, clk.Now().UTC())
	}
	if n, _ := f.Deps.registry.Get(nodeID); n.ReportedRawExec != registry.RawExecReportedEnabled {
		t.Errorf("ReportedRawExec = %v, want enabled", n.ReportedRawExec)
	}
}

// Proves NC-39.
func TestTunnelOpen_AlternatingDaemonVersionsWriteOneRowPerWindow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clk := &revokedDialClock{t: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	f := startRelay(t, WithConnectionClock(clk.Now))
	nodeID, cert, pool := connAuditEnroll(ctx, t, f)

	// The version record is written before the Ping, so it is complete when
	// connAuditConnect returns.
	connect := func(version string) {
		t.Helper()
		connAuditConnect(ctx, t, f, cert, pool, &relayv1.Hello{DaemonVersion: version})()
	}
	rows := func() []audit.Record {
		t.Helper()
		return connAuditRecords(ctx, t, f, nodeID, audit.KindNodeDaemonVersionChanged)
	}

	connect("0.1.0") // first connect: none
	if n := len(rows()); n != 0 {
		t.Fatalf("rows after the first connect = %d, want 0", n)
	}
	connect("0.2.0")
	recs := rows()
	if len(recs) != 1 || recs[0].Reason != "version_before=0.1.0 version_after=0.2.0 downgrade=false changes=1" {
		t.Fatalf("rows after the first change = %+v, want one with changes=1", recs)
	}
	for _, v := range []string{"0.1.0", "0.2.0", "0.1.0"} {
		connect(v)
	}
	if n := len(rows()); n != 1 {
		t.Fatalf("rows inside the window = %d, want 1", n)
	}

	clk.Advance(10 * time.Minute) // the recorder's window
	connect("0.2.0")
	recs = rows()
	if len(recs) != 2 || recs[1].Reason != "version_before=0.1.0 version_after=0.2.0 downgrade=false changes=4" {
		t.Fatalf("rows after the window = %+v, want a second with changes=4", recs)
	}
	connect("0.1.0")
	if n := len(rows()); n != 2 {
		t.Errorf("rows inside the new window = %d, want 2", n)
	}
}

// twoStreamsWriteOneReplacedRow opens a second stream for a Node while its first
// is live and requires exactly one node_stream_replaced row. A stream that was
// fully torn down before it is not an overlap. The row is written before the
// Ping, so it exists when connAuditConnect returns. It asserts nothing about
// how the older stream ends.
func twoStreamsWriteOneReplacedRow(t *testing.T, opts ...FixtureOption) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clk := &revokedDialClock{t: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	f := startRelay(t, append(opts, WithConnectionClock(clk.Now))...)
	nodeID, cert, pool := connAuditEnroll(ctx, t, f)
	rows := func() []audit.Record {
		t.Helper()
		return connAuditRecords(ctx, t, f, nodeID, audit.KindNodeStreamReplaced)
	}

	connAuditSession(ctx, t, f, cert, pool, &relayv1.Hello{})
	if n := len(rows()); n != 0 {
		t.Fatalf("rows after one stream that ended before the next = %d, want 0", n)
	}
	endA := connAuditConnect(ctx, t, f, cert, pool, &relayv1.Hello{})
	defer endA()
	if n := len(rows()); n != 0 {
		t.Fatalf("rows with one live stream = %d, want 0", n)
	}
	endB := connAuditConnect(ctx, t, f, cert, pool, &relayv1.Hello{})
	defer endB()

	recs := rows()
	if len(recs) != 1 {
		t.Fatalf("rows with two live streams = %d, want 1", len(recs))
	}
	if recs[0].Reason != "replacements=1" || recs[0].Principal != "" || !recs[0].Timestamp.Equal(clk.Now().UTC()) {
		t.Errorf("row = Reason %q Principal %q Timestamp %v, want replacements=1 / none / %v",
			recs[0].Reason, recs[0].Principal, recs[0].Timestamp, clk.Now().UTC())
	}
}

// Proves NC-36.
func TestTunnelOpen_TwoStreamsOnOneCertificateWriteOneReplacedRow(t *testing.T) {
	twoStreamsWriteOneReplacedRow(t)
}

// Proves NC-36.
func TestTunnelOpen_TwoStreamsOnOneCertificateWriteOneReplacedRowWithControlPlane(t *testing.T) {
	twoStreamsWriteOneReplacedRow(t, WithControlPlane())
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
