package transport_test

// Tests for UnaryServerInterceptor: the per-RPC mTLS identity and revocation
// gate on every unary daemon-plane RPC, of which Enrollment/Renew is the one
// that must be cert-authenticated (ADR-0006: Node identity is its client cert;
// invariant 6). The end-to-end tests run real TLS over bufconn against a
// recording Enrollment stub, so the refusals are proven at the interceptor and
// never by the handler; the direct-call tests reach the refusal branches real
// TLS cannot produce.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/revocation"
	"github.com/Felag-Engineering/relay/relay/internal/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// recordingEnrollmentServer stands in for the Enrollment service. It records
// every call that got past the interceptor and the node_id the interceptor
// injected, so a test can assert a refusal never reached the handler.
type recordingEnrollmentServer struct {
	relayv1.UnimplementedEnrollmentServer

	mu          sync.Mutex
	renewCalls  int
	renewNodeID string
	enrollCalls int
	enrollHadID bool
}

func (s *recordingEnrollmentServer) Renew(ctx context.Context, _ *relayv1.RenewRequest) (*relayv1.RenewResponse, error) {
	id, _ := transport.NodeIDFromContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.renewCalls++
	s.renewNodeID = id
	return &relayv1.RenewResponse{}, nil
}

func (s *recordingEnrollmentServer) Enroll(ctx context.Context, _ *relayv1.EnrollRequest) (*relayv1.EnrollResponse, error) {
	_, ok := transport.NodeIDFromContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enrollCalls++
	s.enrollHadID = ok
	return &relayv1.EnrollResponse{}, nil
}

func (s *recordingEnrollmentServer) snapshot() (renewCalls int, renewNodeID string, enrollCalls int, enrollHadID bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.renewCalls, s.renewNodeID, s.enrollCalls, s.enrollHadID
}

// productionCertless is the certless allowlist exactly as the composition root
// builds it: Enroll is the one certless RPC, and Renew is absent from it.
func productionCertless() map[string]struct{} {
	return map[string]struct{}{relayv1.Enrollment_Enroll_FullMethodName: {}}
}

// startEnrollmentServer serves rec over bufconn behind creds and the unary
// interceptor built from certless and checker.
func startEnrollmentServer(t *testing.T, rec *recordingEnrollmentServer, creds credentials.TransportCredentials,
	certless map[string]struct{}, checker transport.RevocationChecker) *bufconn.Listener {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(
		grpc.Creds(creds),
		grpc.ChainUnaryInterceptor(transport.UnaryServerInterceptor(certless, checker)),
	)
	relayv1.RegisterEnrollmentServer(srv, rec)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return lis
}

// mintClientCert signs a fresh key's CSR under ts.relayCA with nodeID as the
// authoritative CN.
func mintClientCert(t *testing.T, ts *testSetup, nodeID string) tls.Certificate {
	t.Helper()
	csrPEM, key := newInlineCSR(t, "csr-subject-is-ignored")
	certPEM, err := ts.relayCA.SignCSR(csrPEM, nodeID)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	return assembleClientCert(t, certPEM, key)
}

func renew(t *testing.T, conn *grpc.ClientConn) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := relayv1.NewEnrollmentClient(conn).Renew(ctx, &relayv1.RenewRequest{Csr: []byte("csr")})
	return err
}

// TestUnaryInterceptor_RenewWithValidCert_InjectsCertCN is the positive control
// the refusals below are measured against: a verified client cert reaches
// Renew, and the node_id the handler sees is the cert's CN.
func TestUnaryInterceptor_RenewWithValidCert_InjectsCertCN(t *testing.T) {
	ts := newTestSetup(t)
	rec := &recordingEnrollmentServer{}
	lis := startEnrollmentServer(t, rec,
		transport.ServerCredentials(ts.certificate(), ts.clientCAs, nil), productionCertless(), nil)

	conn := dial(t, lis, &tls.Config{
		Certificates: []tls.Certificate{mintClientCert(t, ts, "node-renewing")},
		RootCAs:      ts.clientCAs,
	})

	if err := renew(t, conn); err != nil {
		t.Fatalf("Renew with a valid client cert: %v", err)
	}
	calls, gotID, _, _ := rec.snapshot()
	if calls != 1 {
		t.Fatalf("Renew handler calls = %d, want 1", calls)
	}
	if gotID != "node-renewing" {
		t.Errorf("node_id seen by Renew = %q, want the cert CN %q", gotID, "node-renewing")
	}
}

// TestUnaryInterceptor_RenewWithoutPeerCert_Refused proves Renew is not
// certless: a TLS connection that presents no client certificate is admitted
// by the handshake (VerifyClientCertIfGiven keeps Enroll reachable) and must be
// refused by the interceptor before the handler runs.
func TestUnaryInterceptor_RenewWithoutPeerCert_Refused(t *testing.T) {
	ts := newTestSetup(t)
	rec := &recordingEnrollmentServer{}
	denylist := revocation.NewDenylist()
	lis := startEnrollmentServer(t, rec,
		transport.ServerCredentials(ts.certificate(), ts.clientCAs, denylist), productionCertless(), denylist)

	conn := dial(t, lis, &tls.Config{RootCAs: ts.clientCAs})

	err := renew(t, conn)
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Fatalf("Renew without a client cert: code = %v (err %v), want Unauthenticated", code, err)
	}
	if calls, _, _, _ := rec.snapshot(); calls != 0 {
		t.Errorf("Renew handler ran %d times for a certless caller, want 0", calls)
	}
}

// TestUnaryInterceptor_CertlessEnroll_PassesWithoutIdentity proves the other
// side of the allowlist on the same server: Enroll is reachable with no client
// cert, and its context carries no node_id.
func TestUnaryInterceptor_CertlessEnroll_PassesWithoutIdentity(t *testing.T) {
	ts := newTestSetup(t)
	rec := &recordingEnrollmentServer{}
	lis := startEnrollmentServer(t, rec,
		transport.ServerCredentials(ts.certificate(), ts.clientCAs, nil), productionCertless(), nil)

	conn := dial(t, lis, &tls.Config{RootCAs: ts.clientCAs})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := relayv1.NewEnrollmentClient(conn).Enroll(ctx, &relayv1.EnrollRequest{}); err != nil {
		t.Fatalf("certless Enroll: %v", err)
	}
	_, _, enrollCalls, hadID := rec.snapshot()
	if enrollCalls != 1 {
		t.Fatalf("Enroll handler calls = %d, want 1", enrollCalls)
	}
	if hadID {
		t.Error("certless Enroll context carried a node_id, want none")
	}
}

// TestUnaryInterceptor_RevokedAfterConnect_RenewRefused is the defense-in-depth
// case the handshake check cannot cover: a Node that was trusted when its
// connection came up, and is revoked while that connection stays open. The
// next Renew on the SAME connection must be refused by the interceptor.
//
// The handshake counter proves the refusal happened on the established
// connection: had gRPC redialled, the handshake-level VerifyConnection check
// would have refused it instead, and this test would not be exercising the
// interceptor at all.
func TestUnaryInterceptor_RevokedAfterConnect_RenewRefused(t *testing.T) {
	ts := newTestSetup(t)
	rec := &recordingEnrollmentServer{}
	// One denylist feeds both layers, as the composition root wires it.
	denylist := revocation.NewDenylist()

	var handshakes atomic.Int64
	getCert := func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		handshakes.Add(1)
		return &ts.serverCert, nil
	}
	lis := startEnrollmentServer(t, rec,
		transport.ServerCredentials(getCert, ts.clientCAs, denylist), productionCertless(), denylist)

	conn := dial(t, lis, &tls.Config{
		Certificates: []tls.Certificate{mintClientCert(t, ts, "node-later-revoked")},
		RootCAs:      ts.clientCAs,
	})

	if err := renew(t, conn); err != nil {
		t.Fatalf("Renew before revocation: %v", err)
	}

	denylist.Add("node-later-revoked")

	err := renew(t, conn)
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Fatalf("Renew after revocation: code = %v (err %v), want Unauthenticated", code, err)
	}
	if calls, _, _, _ := rec.snapshot(); calls != 1 {
		t.Errorf("Renew handler calls = %d, want 1 (only the pre-revocation call)", calls)
	}
	if n := handshakes.Load(); n != 1 {
		t.Errorf("TLS handshakes = %d, want 1: the refused Renew must ride the pre-revocation connection", n)
	}
}

// TestUnaryInterceptor_RefusesWithoutVerifiedIdentity covers the refusal
// branches real TLS cannot reach, by calling the interceptor directly with a
// hand-built peer. Every case must be Unauthenticated and must never run the
// handler, with or without a revocation checker.
func TestUnaryInterceptor_RefusesWithoutVerifiedIdentity(t *testing.T) {
	emptyCN := &x509.Certificate{Subject: pkix.Name{CommonName: ""}}
	tlsPeer := func(chains [][]*x509.Certificate) context.Context {
		return peer.NewContext(context.Background(), &peer.Peer{
			Addr:     &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
			AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{VerifiedChains: chains}},
		})
	}

	cases := []struct {
		name string
		ctx  context.Context
	}{
		{name: "no peer in context", ctx: context.Background()},
		{name: "peer auth info is not TLS", ctx: peer.NewContext(context.Background(), &peer.Peer{
			Addr:     &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
			AuthInfo: nonTLSAuthInfo{},
		})},
		{name: "TLS peer with no verified chains", ctx: tlsPeer(nil)},
		{name: "TLS peer with an empty verified chain", ctx: tlsPeer([][]*x509.Certificate{{}})},
		{name: "verified leaf with empty CN", ctx: tlsPeer([][]*x509.Certificate{{emptyCN}})},
	}

	checkers := []struct {
		name    string
		checker transport.RevocationChecker
	}{
		{name: "nil checker", checker: nil},
		{name: "denylist", checker: revocation.NewDenylist()},
	}

	for _, ck := range checkers {
		interceptor := transport.UnaryServerInterceptor(productionCertless(), ck.checker)
		for _, tc := range cases {
			t.Run(ck.name+"/"+tc.name, func(t *testing.T) {
				handlerRan := false
				handler := func(context.Context, any) (any, error) {
					handlerRan = true
					return "reached", nil
				}
				info := &grpc.UnaryServerInfo{FullMethod: relayv1.Enrollment_Renew_FullMethodName}

				resp, err := interceptor(tc.ctx, &relayv1.RenewRequest{}, info, handler)
				if code := status.Code(err); code != codes.Unauthenticated {
					t.Fatalf("code = %v (err %v), want Unauthenticated", code, err)
				}
				if resp != nil {
					t.Errorf("response = %v, want nil on refusal", resp)
				}
				if handlerRan {
					t.Error("handler ran on a refused call")
				}
			})
		}
	}
}

// TestUnaryInterceptor_CertlessMethodSkipsRevocationCheck pins a design
// property of the allowlist: a certless method has no identity to check, so
// it reaches the handler with no peer at all and without consulting the
// checker. A checker that would revoke anything makes a consultation visible.
func TestUnaryInterceptor_CertlessMethodSkipsRevocationCheck(t *testing.T) {
	checker := &countingChecker{}
	interceptor := transport.UnaryServerInterceptor(productionCertless(), checker)
	info := &grpc.UnaryServerInfo{FullMethod: relayv1.Enrollment_Enroll_FullMethodName}

	resp, err := interceptor(context.Background(), &relayv1.EnrollRequest{}, info,
		func(ctx context.Context, _ any) (any, error) {
			if _, ok := transport.NodeIDFromContext(ctx); ok {
				t.Error("certless handler context carried a node_id")
			}
			return "reached", nil
		})
	if err != nil {
		t.Fatalf("certless Enroll: %v", err)
	}
	if resp != "reached" {
		t.Errorf("response = %v, want the handler's", resp)
	}
	if n := checker.calls.Load(); n != 0 {
		t.Errorf("revocation checker consulted %d times for a certless method, want 0", n)
	}
}

// nonTLSAuthInfo is a credentials.AuthInfo that is not credentials.TLSInfo,
// as a server built with insecure or ALTS credentials would attach.
type nonTLSAuthInfo struct{}

func (nonTLSAuthInfo) AuthType() string { return "not-tls" }

// countingChecker revokes every node_id and counts consultations.
type countingChecker struct{ calls atomic.Int64 }

func (c *countingChecker) IsRevoked(string) bool {
	c.calls.Add(1)
	return true
}
