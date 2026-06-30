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
	"crypto/tls"
	"crypto/x509"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// ctxKey is the unexported key used to store node_id in a context. Using a
// package-local type prevents collisions with keys from other packages.
type ctxKey struct{}

// ServerCredentials builds TLS transport credentials for the Relay's gRPC
// server. ClientAuth is VerifyClientCertIfGiven: presented certs are verified
// against clientCAs, but the handshake succeeds with no cert too — enabling
// the certless Enrollment seam. TLS 1.3 is the minimum version.
func ServerCredentials(serverCert tls.Certificate, clientCAs *x509.CertPool) credentials.TransportCredentials {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		MinVersion:   tls.VersionTLS13,
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
func StreamServerInterceptor(certless map[string]struct{}) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if _, ok := certless[info.FullMethod]; ok {
			return handler(srv, ss)
		}

		nodeID, err := nodeIDFromPeer(ss.Context())
		if err != nil {
			return err
		}

		enriched := NewContextWithNodeID(ss.Context(), nodeID)
		return handler(srv, wrappedStream{ServerStream: ss, ctx: enriched})
	}
}

// UnaryServerInterceptor returns a gRPC unary interceptor that enforces the
// same default-deny mTLS policy as StreamServerInterceptor.
func UnaryServerInterceptor(certless map[string]struct{}) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if _, ok := certless[info.FullMethod]; ok {
			return handler(ctx, req)
		}

		nodeID, err := nodeIDFromPeer(ctx)
		if err != nil {
			return nil, err
		}

		enriched := NewContextWithNodeID(ctx, nodeID)
		return handler(enriched, req)
	}
}
