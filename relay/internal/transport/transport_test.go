package transport_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/ca"
	"github.com/Felag-Engineering/relay/relay/internal/ca/catest"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/transport"
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
	relayCA, err := catest.Generate()
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

// certificate presents ts.serverCert through the per-handshake seam
// ServerCredentials takes. Production hands it *ca.ServerCertificate's method,
// which re-issues before expiry; a fixed certificate is all these tests need.
func (ts *testSetup) certificate() transport.GetCertificateFunc {
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return &ts.serverCert, nil
	}
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
	go srv.Serve(lis)
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
	stream.Recv()
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

// trySendHello sends a Hello but tolerates a Send error. On rejection paths
// the server aborts the stream concurrently with the client's Send, so Send
// may return io.EOF; per the gRPC ClientStream contract the RPC status must
// then be retrieved via Recv, which the caller does next.
func trySendHello(stream relayv1.Tunnel_OpenClient, helloID string) {
	_ = stream.Send(&relayv1.DaemonMessage{
		Body: &relayv1.DaemonMessage_Hello{
			Hello: &relayv1.Hello{NodeId: helloID},
		},
	})
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
		grpc.Creds(transport.ServerCredentials(ts.certificate(), ts.clientCAs, nil, nil)),
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
		grpc.Creds(transport.ServerCredentials(ts.certificate(), ts.clientCAs, nil, nil)),
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
		trySendHello(stream, "anon")
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
		grpc.Creds(transport.ServerCredentials(ts.certificate(), ts.clientCAs, nil, nil)),
		grpc.ChainStreamInterceptor(transport.StreamServerInterceptor(certless, nil)),
		grpc.ChainUnaryInterceptor(transport.UnaryServerInterceptor(certless, nil)),
	)

	// A second, unrelated CA — the server trusts only ts.relayCA.
	ca2, err := catest.Generate()
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
		trySendHello(stream, "rogue")
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
		grpc.Creds(transport.ServerCredentials(ts.certificate(), ts.clientCAs, nil, nil)),
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
		grpc.Creds(transport.ServerCredentials(ts.certificate(), ts.clientCAs, checker, nil)),
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
		trySendHello(stream, "node-revoked")
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
		grpc.Creds(transport.ServerCredentials(ts.certificate(), ts.clientCAs, nil, nil)),
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
		trySendHello(stream, "node-intercepted")
		_, err = stream.Recv()
	}
	if err == nil {
		t.Fatal("expected Unauthenticated from interceptor for revoked node, got nil")
	}
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Errorf("got code %v, want Unauthenticated", code)
	}
}

// TestTransport_CertificateIsFetchedEveryHandshake is the structural guard on
// the defect behind #403: the node plane must ASK for its server certificate
// per handshake, never capture one at startup. A certificate captured once
// expires while the process still runs, and every daemon then fail-closes off
// the Relay.
//
// The test rotates the certificate between two handshakes and asserts the
// second connection is served the new leaf. No rotation policy is under test
// here — only that the transport consults the seam at all.
func TestTransport_CertificateIsFetchedEveryHandshake(t *testing.T) {
	ts := newTestSetup(t)

	rotated, err := ts.relayCA.IssueServerCertificate([]string{"localhost"}, nil)
	if err != nil {
		t.Fatalf("IssueServerCertificate: %v", err)
	}

	var calls atomic.Int64
	creds := transport.ServerCredentials(func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		if calls.Add(1) == 1 {
			return &ts.serverCert, nil
		}
		return &rotated, nil
	}, ts.clientCAs, nil, nil)

	first := handshakePeerLeaf(t, creds, ts.clientCAs)
	second := handshakePeerLeaf(t, creds, ts.clientCAs)

	if n := calls.Load(); n != 2 {
		t.Fatalf("server certificate fetched %d times over 2 handshakes, want 2 (a static certificate was captured)", n)
	}
	if first.SerialNumber.Cmp(second.SerialNumber) == 0 {
		t.Fatal("second handshake was served the first certificate; the rotated leaf never reached the wire")
	}
	if want := rotated.Leaf.SerialNumber; second.SerialNumber.Cmp(want) != 0 {
		t.Errorf("second handshake served serial %s, want the rotated leaf's %s", second.SerialNumber, want)
	}
}

// handshakePeerLeaf completes one TLS handshake against creds over an
// in-memory pipe and returns the leaf certificate the server presented. The
// client is certless, like a daemon reaching Enroll: what is under test is the
// certificate the SERVER presents.
func handshakePeerLeaf(t *testing.T, creds credentials.TransportCredentials, roots *x509.CertPool) *x509.Certificate {
	t.Helper()
	return handshakePeerChain(t, creds, roots)[0]
}

// handshakePeerChain is handshakePeerLeaf returning the whole chain the server
// presented, leaf first.
func handshakePeerChain(t *testing.T, creds credentials.TransportCredentials, roots *x509.CertPool) []*x509.Certificate {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		serverConn.Close()
		clientConn.Close()
	})

	done := make(chan error, 1)
	go func() {
		_, _, err := creds.ServerHandshake(serverConn)
		done <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := tls.Client(clientConn, &tls.Config{
		RootCAs:    roots,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
		// gRPC's credentials enforce ALPN; a real client negotiates h2.
		NextProtos: []string{"h2"},
	})
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	certs := client.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("server presented no certificate")
	}
	return certs
}

// TestNodePlane_PresentsCAAfterLeaf: the node-plane chain is the leaf followed
// by the CA certificate, so a daemon pinning the CA by SHA-256 over its DER can
// check the pin from the wire (ADR-0031). The handshake is certless and
// succeeds, which is the evidence client authentication is unchanged.
func TestNodePlane_PresentsCAAfterLeaf(t *testing.T) {
	ts := newTestSetup(t)

	sc, err := ts.relayCA.NewServerCertificate([]string{"localhost"}, nil)
	if err != nil {
		t.Fatalf("NewServerCertificate: %v", err)
	}
	creds := transport.ServerCredentials(sc.GetCertificate, ts.clientCAs, nil, nil)

	chain := handshakePeerChain(t, creds, ts.clientCAs)
	if len(chain) != 2 {
		t.Fatalf("presented chain has %d certificates, want 2 (leaf, CA)", len(chain))
	}
	block, _ := pem.Decode(ts.relayCA.Bundle())
	if block == nil {
		t.Fatal("CA bundle is not PEM")
	}
	if !bytes.Equal(chain[1].Raw, block.Bytes) {
		t.Error("second certificate is not the CA certificate")
	}
	if got := hex.EncodeToString(sha256Sum(chain[1].Raw)); got != ts.relayCA.Fingerprint() {
		t.Errorf("SHA-256 over the presented CA = %s, want the CA fingerprint %s", got, ts.relayCA.Fingerprint())
	}
	if err := chain[0].CheckSignatureFrom(chain[1]); err != nil {
		t.Errorf("leaf is not signed by the presented CA: %v", err)
	}
	if chain[0].IsCA {
		t.Error("first certificate is a CA, want the leaf")
	}
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// revokedDialObserver records the Node IDs it is told of, then blocks on gate
// so a test can observe the handshake while the observer is still running.
type revokedDialObserver struct {
	told chan string
	gate chan struct{}
}

func (o *revokedDialObserver) RevokedDial(nodeID string) {
	o.told <- nodeID
	<-o.gate
}

// rawHandshake runs one TLS handshake between creds and a client presenting
// clientCert (none when nil) over a bufconn connection. srvErr and cliErr each
// report what that side saw: the client's covers the handshake and one Read,
// since under TLS 1.3 a server-side refusal reaches the client as an alert on
// its first read.
func rawHandshake(t *testing.T, ts *testSetup, creds credentials.TransportCredentials, clientCert *tls.Certificate) (srvErr, cliErr chan error) {
	t.Helper()
	lis := bufconn.Listen(1 << 16)
	t.Cleanup(func() { lis.Close() })

	srvErr = make(chan error, 1)
	cliErr = make(chan error, 1)
	deadline := time.Now().Add(10 * time.Second)

	go func() {
		conn, err := lis.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(deadline)
		_, _, err = creds.ServerHandshake(conn)
		srvErr <- err
	}()

	raw, err := lis.Dial()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { raw.Close() })
	raw.SetDeadline(deadline)

	cfg := &tls.Config{
		RootCAs:    ts.clientCAs,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2"},
	}
	if clientCert != nil {
		cfg.Certificates = []tls.Certificate{*clientCert}
	}
	client := tls.Client(raw, cfg)
	go func() {
		if err := client.Handshake(); err != nil {
			cliErr <- err
			return
		}
		_, err := client.Read(make([]byte, 1))
		cliErr <- err
	}()
	return srvErr, cliErr
}

func signedClientCert(t *testing.T, ts *testSetup, cn string) *tls.Certificate {
	t.Helper()
	csrPEM, key := newInlineCSR(t, cn)
	certPEM, err := ts.relayCA.SignCSR(csrPEM, cn)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	c := assembleClientCert(t, certPEM, key)
	return &c
}

// Proves DI-23.
func TestServerCredentials_ReportsRevokedBeforeRefusing(t *testing.T) {
	ts := newTestSetup(t)
	obs := &revokedDialObserver{told: make(chan string, 1), gate: make(chan struct{})}
	checker := &fakeChecker{revoked: map[string]bool{"node-revoked": true}}
	creds := transport.ServerCredentials(ts.certificate(), ts.clientCAs, checker, obs)

	srvErr, cliErr := rawHandshake(t, ts, creds, signedClientCert(t, ts, "node-revoked"))

	select {
	case got := <-obs.told:
		if got != "node-revoked" {
			t.Fatalf("observer told %q, want node-revoked", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("observer was never told of the revoked dial")
	}

	// The observer is still running: the refusal must not have been returned.
	select {
	case err := <-srvErr:
		t.Fatalf("server handshake returned (%v) before the observer finished", err)
	case err := <-cliErr:
		t.Fatalf("client saw a result (%v) before the observer finished", err)
	case <-time.After(200 * time.Millisecond):
	}

	close(obs.gate)

	for name, ch := range map[string]chan error{"server": srvErr, "client": cliErr} {
		select {
		case err := <-ch:
			if err == nil {
				t.Errorf("%s side saw no error for a revoked certificate", name)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("%s side never finished after the observer returned", name)
		}
	}
}

func TestServerCredentials_DoesNotReportAnUnrevokedCert(t *testing.T) {
	ts := newTestSetup(t)
	obs := &revokedDialObserver{told: make(chan string, 1), gate: make(chan struct{})}
	close(obs.gate) // a wrongly called observer returns, so the test fails rather than hangs
	checker := &fakeChecker{revoked: map[string]bool{"node-revoked": true}}
	creds := transport.ServerCredentials(ts.certificate(), ts.clientCAs, checker, obs)

	srvErr, _ := rawHandshake(t, ts, creds, signedClientCert(t, ts, "node-fine"))

	if err := <-srvErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	select {
	case got := <-obs.told:
		t.Fatalf("observer told %q of an unrevoked certificate", got)
	default:
	}
}

func TestServerCredentials_DoesNotReportACertlessHandshake(t *testing.T) {
	ts := newTestSetup(t)
	obs := &revokedDialObserver{told: make(chan string, 1), gate: make(chan struct{})}
	close(obs.gate) // a wrongly called observer returns, so the test fails rather than hangs
	checker := &fakeChecker{revoked: map[string]bool{"node-revoked": true}}
	creds := transport.ServerCredentials(ts.certificate(), ts.clientCAs, checker, obs)

	srvErr, _ := rawHandshake(t, ts, creds, nil)

	if err := <-srvErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	select {
	case got := <-obs.told:
		t.Fatalf("observer told %q of a certless handshake", got)
	default:
	}
}

func TestServerCredentials_NilObserverStillRefusesARevokedCert(t *testing.T) {
	ts := newTestSetup(t)
	checker := &fakeChecker{revoked: map[string]bool{"node-revoked": true}}
	creds := transport.ServerCredentials(ts.certificate(), ts.clientCAs, checker, nil)

	srvErr, _ := rawHandshake(t, ts, creds, signedClientCert(t, ts, "node-revoked"))

	if err := <-srvErr; err == nil {
		t.Fatal("a revoked certificate was admitted with a nil observer")
	}
}
