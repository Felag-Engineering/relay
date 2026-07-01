// Package transport builds the mTLS server credentials and per-RPC identity /
// auth interceptors for the Relay's gRPC server.
//
// Design: a single listener uses tls.VerifyClientCertIfGiven rather than
// tls.RequireAndVerifyClientCert. This keeps the TLS handshake open to
// certless connections, which is required for a future Enrollment endpoint
// (ADR-0005: one daemon-initiated connection; ADR-0006: identity = client cert).
// Any presented certificate is still cryptographically verified against
// ClientCAs at the TLS layer, so untrusted certs are rejected there.
//
// The interceptors enforce default-deny per-RPC: every method must present a
// verified client cert and have its CN injected as node_id into the context,
// UNLESS its FullMethod string appears in the `certless` allowlist. The
// allowlist is the documented seam for Enrollment: when that handler lands
// (issue #25), add gleipnirv1.Enrollment_Enroll_FullMethodName to the set.
package transport

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// ctxKey is the unexported key used to store node_id in a context. Using a
// package-local type prevents collisions with keys from other packages.
type ctxKey struct{}

// RevocationChecker reports whether a node_id has been revoked. *revocation.Denylist
// satisfies this interface. The interface lives here so the transport package has no
// dependency on the revocation package — the concrete type is injected by main.
type RevocationChecker interface {
	IsRevoked(nodeID string) bool
}

// ServerCredentials builds TLS transport credentials for the Relay's gRPC
// server. ClientAuth is VerifyClientCertIfGiven: presented certs are verified
// against clientCAs, but the handshake succeeds with no cert too — enabling
// the certless Enrollment seam. TLS 1.3 is the minimum version.
//
// When checker is non-nil, VerifyConnection is set to reject any client whose
// verified cert CN appears in the denylist. Certless connections (no verified
// chain) skip the check so the Enrollment seam is unaffected. This is the
// handshake-level rejection mandated by ADR-0006.
func ServerCredentials(serverCert tls.Certificate, clientCAs *x509.CertPool, checker RevocationChecker) credentials.TransportCredentials {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		MinVersion:   tls.VersionTLS13,
	}
	if checker != nil {
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			// No verified chain means this is the certless Enroll path — skip check.
			if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
				return nil
			}
			cn := cs.VerifiedChains[0][0].Subject.CommonName
			if cn != "" && checker.IsRevoked(cn) {
				return errors.New("client certificate revoked")
			}
			return nil
		}
	}
	return credentials.NewTLS(cfg)
}

// NodeIDFromContext returns the node_id injected by the stream/unary
// interceptors and a boolean indicating whether it was present.
func NodeIDFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ctxKey{}).(string)
	return v, ok && v != ""
}

// NewContextWithNodeID stores nodeID in ctx under the same key read by
// NodeIDFromContext. This is the single authoritative writer of that key;
// both interceptors and test helpers must go through this function so there
// is exactly one place that injects node identity into a context.
func NewContextWithNodeID(ctx context.Context, nodeID string) context.Context {
	return context.WithValue(ctx, ctxKey{}, nodeID)
}

// PeerCertFingerprint returns the SHA-256 fingerprint (hex-encoded) of the
// verified TLS leaf certificate carried in ctx, and true. Returns ("", false)
// when ctx carries no verified TLS peer — for example in interceptor-based
// unit tests that inject node_id without real TLS.
//
// The value matches the fingerprint the Enrollment handler stores
// (enroll/handler.go:119-123): both hash the raw DER bytes of the leaf cert.
// A Hello Upsert that recomputes the fingerprint from the same cert therefore
// never blanks the enrollment-set value (registry.Upsert always overwrites
// CertFingerprint, so producing the same value is essential for consistency).
func PeerCertFingerprint(ctx context.Context) (string, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", false
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", false
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return "", false
	}
	sum := sha256.Sum256(tlsInfo.State.VerifiedChains[0][0].Raw)
	return hex.EncodeToString(sum[:]), true
}

// nodeIDFromPeer extracts the verified client certificate CN from the gRPC
// peer info. It returns codes.Unauthenticated if any required information is
// absent: no peer, auth info is not TLS, no verified chains, or empty CN.
// CN is the sole authoritative identity source (ADR-0006).
func nodeIDFromPeer(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no peer info")
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no TLS auth info")
	}

	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return "", status.Error(codes.Unauthenticated, "client certificate required")
	}

	cn := tlsInfo.State.VerifiedChains[0][0].Subject.CommonName
	if cn == "" {
		return "", status.Error(codes.Unauthenticated, "client certificate has empty CN")
	}

	return cn, nil
}

// wrappedStream overrides the embedded ServerStream's Context so the handler
// receives the enriched context carrying node_id.
type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w wrappedStream) Context() context.Context { return w.ctx }

// StreamServerInterceptor returns a gRPC stream interceptor that enforces
// default-deny mTLS: methods not in certless must supply a verified client
// certificate. The CN of that certificate is stored as node_id in the stream
// context before calling the handler.
//
// When checker is non-nil, a revoked node_id is rejected with
// codes.Unauthenticated even on an already-established connection (defense in
// depth: blocks new RPCs on pre-revocation connections, covers any TLS
// session-resumption gap).
func StreamServerInterceptor(certless map[string]struct{}, checker RevocationChecker) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if _, ok := certless[info.FullMethod]; ok {
			return handler(srv, ss)
		}

		nodeID, err := nodeIDFromPeer(ss.Context())
		if err != nil {
			return err
		}

		if checker != nil && checker.IsRevoked(nodeID) {
			return status.Error(codes.Unauthenticated, "node revoked")
		}

		enriched := NewContextWithNodeID(ss.Context(), nodeID)
		return handler(srv, wrappedStream{ServerStream: ss, ctx: enriched})
	}
}

// UnaryServerInterceptor returns a gRPC unary interceptor that enforces the
// same default-deny mTLS policy and revocation check as StreamServerInterceptor.
func UnaryServerInterceptor(certless map[string]struct{}, checker RevocationChecker) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if _, ok := certless[info.FullMethod]; ok {
			return handler(ctx, req)
		}

		nodeID, err := nodeIDFromPeer(ctx)
		if err != nil {
			return nil, err
		}

		if checker != nil && checker.IsRevoked(nodeID) {
			return nil, status.Error(codes.Unauthenticated, "node revoked")
		}

		enriched := NewContextWithNodeID(ctx, nodeID)
		return handler(enriched, req)
	}
}
