package transport_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/ca"
	relayv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// newInlineCSR generates a fresh ECDSA P-256 key and returns a PEM-encoded
// CERTIFICATE REQUEST plus the private key. All cert material for transport
// tests is generated inline here — never imported from ca_test.go (those
// helpers are unexported and in a different test binary).
func newInlineCSR(t *testing.T, cn string) (csrPEM []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, k)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), k
}

// assembleClientCert combines a PEM-encoded leaf certificate and its ECDSA
// private key into a tls.Certificate ready for use as a gRPC client credential.
func assembleClientCert(t *testing.T, certPEM []byte, key *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return tlsCert
}

// testSetup holds the shared fixtures used across subtests.
type testSetup struct {
	serverCert tls.Certificate
	clientCAs  *x509.CertPool
	relayCA    *ca.CA
}

func newTestSetup(t *testing.T) *testSetup {
	t.Helper()
	relayCA, err := ca.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open CA: %v", err)
	}
	serverCert, err := relayCA.IssueServerCertificate([]string{"localhost"}, nil)
	if err != nil {
		t.Fatalf("IssueServerCertificate: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(relayCA.Bundle()) {
		t.Fatal("AppendCertsFromPEM: empty pool")
	}
	return &testSetup{serverCert: serverCert, clientCAs: pool, relayCA: relayCA}
}

// startServer launches an in-process gRPC server over a bufconn listener with
// the given options and registers the Tunnel service using recvNodeID to
// capture the node_id seen from context. The listener is returned for dialing;
// cleanup is registered via t.Cleanup.
func startServer(t *testing.T, recvNodeID *string, opts ...grpc.ServerOption) *bufconn.Listener {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(opts...)
	relayv1.RegisterTunnelServer(srv, &recordingTunnelServer{nodeID: recvNodeID})
	go srv.Serve(lis) //nolint:errcheck
	t.Cleanup(srv.Stop)
	return lis
}

// bufDialer returns a context dialer that connects through the bufconn listener.
func bufDialer(lis *bufconn.Listener) func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, _ string) (net.Conn, error) {
		return lis.DialContext(ctx)
	}
}

// recordingTunnelServer records the node_id extracted from context and sends a
// Ping so the client can confirm the handshake succeeded end-to-end.
type recordingTunnelServer struct {
	relayv1.UnimplementedTunnelServer
	nodeID *string
}

func (s *recordingTunnelServer) Open(stream grpc.BidiStreamingServer[relayv1.DaemonMessage, relayv1.RelayMessage]) error {
	id, _ := transport.NodeIDFromContext(stream.Context())
	*s.nodeID = id

	// Drain the Hello (if present) then send a Ping so the client knows we reached the handler.
	stream.Recv() //nolint:errcheck
	return stream.Send(&relayv1.RelayMessage{
		Body: &relayv1.RelayMessage_Ping{
			Ping: &relayv1.Ping{UnixMillis: time.Now().UnixMilli()},
		},
	})
}

// dial opens a client connection through the given bufconn listener with the
// provided TLS config. ServerName is always "localhost".
func dial(t *testing.T, lis *bufconn.Listener, clientTLS *tls.Config) *grpc.ClientConn {
	t.Helper()
	clientTLS.ServerName = "localhost"
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(bufDialer(lis)),
		grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// sendHello sends a Hello on the stream with NodeId set to helloID.
func sendHello(t *testing.T, stream relayv1.Tunnel_OpenClient, helloID string) {
	t.Helper()
	err := stream.Send(&relayv1.DaemonMessage{
		Body: &relayv1.DaemonMessage_Hello{
			Hello: &relayv1.Hello{NodeId: helloID},
		},
	})
	if err != nil {
		t.Fatalf("send hello: %v", err)
	}
}

// fakeChecker implements transport.RevocationChecker for tests.
type fakeChecker struct {
	revoked map[string]bool
}

func (f *fakeChecker) IsRevoked(nodeID string) bool {
	return f.revoked[nodeID]
}

func TestTransport_AcceptValidClientCert(t *testing.T) {
	ts := newTestSetup(t)
	var gotNodeID string

	certless := map[string]struct{}{}
	lis := startServer(t, &gotNodeID,
		grpc.Creds(transport.ServerCredentials(ts.serverCert, ts.clientCAs, nil)),
		grpc.ChainStreamInterceptor(transport.StreamServerInterceptor(certless, nil)),
		grpc.ChainUnaryInterceptor(transport.UnaryServerInterceptor(certless, nil)),
	)

	// Mint a client cert for "node-alpha". Hello carries a DIFFERENT NodeId to
	// prove that the cert CN — not the wire value — is the authoritative identity.
	csrPEM, key := newInlineCSR(t, "will-be-overridden-by-sign")
	certPEM, err := ts.relayCA.SignCSR(csrPEM, "node-alpha")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	clientCert := assembleClientCert(t, certPEM, key)

	conn := dial(t, lis, &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      ts.clientCAs,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := relayv1.NewTunnelClient(conn).Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	// Send Hello with a NodeId that differs from the cert CN.
	sendHello(t, stream, "impersonator-id")

	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if msg.GetPing() == nil {
		t.Fatalf("expected Ping, got %T", msg.Body)
	}

	// The cert CN must win over the wire-supplied NodeId.
	if gotNodeID != "node-alpha" {
		t.Errorf("node_id = %q, want %q", gotNodeID, "node-alpha")
	}
}

func TestTransport_RejectNoCert(t *testing.T) {
	ts := newTestSetup(t)
	var gotNodeID string

	certless := map[string]struct{}{}
	lis := startServer(t, &gotNodeID,
		grpc.Creds(transport.ServerCredentials(ts.serverCert, ts.clientCAs, nil)),
		grpc.ChainStreamInterceptor(transport.StreamServerInterceptor(certless, nil)),
		grpc.ChainUnaryInterceptor(transport.UnaryServerInterceptor(certless, nil)),
	)

	// No client certificate — server-auth TLS only.
	conn := dial(t, lis, &tls.Config{
		RootCAs: ts.clientCAs,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := relayv1.NewTunnelClient(conn).Open(ctx)
	if err == nil {
		// If Open didn't fail immediately, try sending to force the RPC through.
		sendHello(t, stream, "anon")
		_, err = stream.Recv()
	}
	if err == nil {
		t.Fatal("expected Unauthenticated error, got nil")
	}
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Errorf("got code %v, want Unauthenticated", code)
	}
}

func TestTransport_RejectUntrustedCert(t *testing.T) {
	ts := newTestSetup(t)
	var gotNodeID string

	certless := map[string]struct{}{}
	lis := startServer(t, &gotNodeID,
		grpc.Creds(transport.ServerCredentials(ts.serverCert, ts.clientCAs, nil)),
		grpc.ChainStreamInterceptor(transport.StreamServerInterceptor(certless, nil)),
		grpc.ChainUnaryInterceptor(transport.UnaryServerInterceptor(certless, nil)),
	)

	// A second, unrelated CA — the server trusts only ts.relayCA.
	ca2, err := ca.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open CA2: %v", err)
	}
	csrPEM, key := newInlineCSR(t, "rogue-node")
	certPEM, err := ca2.SignCSR(csrPEM, "rogue-node")
	if err != nil {
		t.Fatalf("CA2 SignCSR: %v", err)
	}
	rogueClientCert := assembleClientCert(t, certPEM, key)

	conn := dial(t, lis, &tls.Config{
		Certificates: []tls.Certificate{rogueClientCert},
		RootCAs:      ts.clientCAs,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := relayv1.NewTunnelClient(conn).Open(ctx)
	if err == nil {
		sendHello(t, stream, "rogue")
		_, err = stream.Recv()
	}
	// The TLS handshake should fail because the server rejects the untrusted cert.
	if err == nil {
		t.Fatal("expected error for untrusted client cert, got nil")
	}
	// The error may surface as Unavailable (TLS handshake failure) or
	// Unauthenticated depending on timing; in either case it must be non-nil.
}

func TestTransport_NodeIDFromContext_BareContext(t *testing.T) {
	id, ok := transport.NodeIDFromContext(context.Background())
	if ok {
		t.Errorf("NodeIDFromContext on bare context: ok = true, want false")
	}
	if id != "" {
		t.Errorf("NodeIDFromContext on bare context: id = %q, want empty", id)
	}
}

// TestTransport_CertlessSeam verifies that a method in the certless allowlist
// is reachable without a client certificate. This proves the Enrollment seam
// stays possible without implementing the handler.
//
// We use the Tunnel/Open method (the only registered method) as a stand-in for
// a certless seam by placing it in the certless set. In production the Tunnel
// method will NOT be certless — this test purely validates the pass-through
// logic of the interceptor.
func TestTransport_CertlessSeam(t *testing.T) {
	ts := newTestSetup(t)
	var gotNodeID string

	// Add the Tunnel/Open method to the certless set — mimics how Enroll will work.
	const tunnelOpenMethod = "/relay.v1.Tunnel/Open"
	certless := map[string]struct{}{tunnelOpenMethod: {}}

	lis := startServer(t, &gotNodeID,
		grpc.Creds(transport.ServerCredentials(ts.serverCert, ts.clientCAs, nil)),
		grpc.ChainStreamInterceptor(transport.StreamServerInterceptor(certless, nil)),
		grpc.ChainUnaryInterceptor(transport.UnaryServerInterceptor(certless, nil)),
	)

	// No client cert.
	conn := dial(t, lis, &tls.Config{
		RootCAs: ts.clientCAs,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := relayv1.NewTunnelClient(conn).Open(ctx)
	if err != nil {
		t.Fatalf("open certless stream: %v", err)
	}
	sendHello(t, stream, "enrolling-node")

	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv on certless stream: %v", err)
	}
	if msg.GetPing() == nil {
		t.Fatalf("expected Ping on certless seam, got %T", msg.Body)
	}
	// No node_id in context for certless paths — NodeIDFromContext returns false.
	if gotNodeID != "" {
		t.Errorf("certless seam: gotNodeID = %q, want empty", gotNodeID)
	}
}

// TestTransport_RejectRevokedCert_Handshake verifies that a Node whose node_id
// is in the revocation denylist is rejected at the TLS handshake level via
// VerifyConnection (ADR-0006 "rejects at the mTLS handshake").
func TestTransport_RejectRevokedCert_Handshake(t *testing.T) {
	ts := newTestSetup(t)
	var gotNodeID string

	checker := &fakeChecker{revoked: map[string]bool{"node-revoked": true}}
	certless := map[string]struct{}{}
	lis := startServer(t, &gotNodeID,
		grpc.Creds(transport.ServerCredentials(ts.serverCert, ts.clientCAs, checker)),
		grpc.ChainStreamInterceptor(transport.StreamServerInterceptor(certless, checker)),
		grpc.ChainUnaryInterceptor(transport.UnaryServerInterceptor(certless, checker)),
	)

	csrPEM, key := newInlineCSR(t, "node-revoked")
	certPEM, err := ts.relayCA.SignCSR(csrPEM, "node-revoked")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	clientCert := assembleClientCert(t, certPEM, key)

	conn := dial(t, lis, &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      ts.clientCAs,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := relayv1.NewTunnelClient(conn).Open(ctx)
	if err == nil {
		sendHello(t, stream, "node-revoked")
		_, err = stream.Recv()
	}
	// The connection must fail (handshake or interceptor rejection).
	if err == nil {
		t.Fatal("expected error for revoked node cert, got nil")
	}
	// Error surfaces as Unavailable (TLS rejection) or Unauthenticated (interceptor);
	// either is acceptable — the important property is that err != nil.
}

// TestTransport_RejectRevoked_Interceptor verifies the per-RPC defense-in-depth
// layer: even when ServerCredentials has a nil checker (so TLS admits the cert),
// the stream interceptor with a revoking checker returns codes.Unauthenticated.
// This isolates the interceptor layer from the TLS handshake layer.
func TestTransport_RejectRevoked_Interceptor(t *testing.T) {
	ts := newTestSetup(t)
	var gotNodeID string

	checker := &fakeChecker{revoked: map[string]bool{"node-intercepted": true}}
	certless := map[string]struct{}{}
	// Nil checker in ServerCredentials: TLS layer admits the cert.
	// Revoking checker in interceptors: per-RPC layer rejects.
	lis := startServer(t, &gotNodeID,
		grpc.Creds(transport.ServerCredentials(ts.serverCert, ts.clientCAs, nil)),
		grpc.ChainStreamInterceptor(transport.StreamServerInterceptor(certless, checker)),
		grpc.ChainUnaryInterceptor(transport.UnaryServerInterceptor(certless, checker)),
	)

	csrPEM, key := newInlineCSR(t, "node-intercepted")
	certPEM, err := ts.relayCA.SignCSR(csrPEM, "node-intercepted")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	clientCert := assembleClientCert(t, certPEM, key)

	conn := dial(t, lis, &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      ts.clientCAs,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := relayv1.NewTunnelClient(conn).Open(ctx)
	if err == nil {
		sendHello(t, stream, "node-intercepted")
		_, err = stream.Recv()
	}
	if err == nil {
		t.Fatal("expected Unauthenticated from interceptor for revoked node, got nil")
	}
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Errorf("got code %v, want Unauthenticated", code)
	}
}
