package enroll

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log/slog"
	"net"
	"strings"

	gleipnirv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/gleipnir/v1"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/protoconv"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Signer signs a CSR and provides the CA bundle. *ca.CA satisfies this interface.
type Signer interface {
	SignCSR(csrPEM []byte, nodeID string) ([]byte, error)
	Bundle() []byte
}

// Registrar records Nodes in the fleet registry. *registry.InMemory satisfies this interface.
type Registrar interface {
	Upsert(registry.Report) (registry.Node, error)
	SetRelayLabels(nodeID string, labels map[string]string) error
}

// TokenRevocationChecker reports whether an Enrollment Token is revoked.
// *Service satisfies this interface.
type TokenRevocationChecker interface {
	IsRevoked(ctx context.Context, id string) (bool, error)
}

// NodeDenylister adds a Node to the Relay-side denylist and tears down any live
// connection (ADR-0006). *revocation.Service satisfies this interface.
type NodeDenylister interface {
	RevokeNode(nodeID string)
}

// RateLimiter gates Enrollment requests. *ratelimit.Limiter satisfies this
// interface. Kept as an interface so the enroll package carries no compile-time
// dependency on the ratelimit package.
type RateLimiter interface {
	Allow(ip string) bool
}

// ServerOption configures a Server at construction.
type ServerOption func(*Server)

// WithPostEnrollRevocationCheck enables the post-Upsert recheck that closes the
// in-flight-enroll vs token-cascade-revocation race (issue #57). When set, after a
// Node is recorded the handler re-reads the enrolling token's revocation state and,
// if it was revoked mid-enrollment, self-denylists the freshly minted node_id and
// rejects the enrollment (fail-closed).
//
// Panics if either argument is nil.
func WithPostEnrollRevocationCheck(checker TokenRevocationChecker, denylister NodeDenylister) ServerOption {
	if checker == nil || denylister == nil {
		panic("enroll: WithPostEnrollRevocationCheck: checker and denylister must not be nil")
	}
	return func(s *Server) {
		s.revocationChecker = checker
		s.nodeDenylister = denylister
	}
}

// WithRateLimiter attaches a per-IP + global rate limiter to the Server. The
// limiter is checked as the very first statement in Enroll — before any token
// validation or CSR signing — so a throttled caller cannot use error distinctions
// to test whether an Enrollment Token is valid (no oracle). The rejection is
// identical regardless of token validity (codes.ResourceExhausted).
//
// Panics if l is nil (matching the WithPostEnrollRevocationCheck convention).
// Pass a nil limiter field (the default) to skip rate-limiting, preserving
// backward compatibility for servers constructed without this option.
func WithRateLimiter(l RateLimiter) ServerOption {
	if l == nil {
		panic("enroll: WithRateLimiter: limiter must not be nil")
	}
	return func(s *Server) {
		s.limiter = l
	}
}

// Server implements gleipnirv1.EnrollmentServer. It validates Enrollment Tokens,
// signs CSRs, and records Nodes in the registry (ADR-0006).
type Server struct {
	gleipnirv1.UnimplementedEnrollmentServer
	tokens            *Service
	signer            Signer
	registry          Registrar
	newID             func() (string, error)
	revocationChecker TokenRevocationChecker
	nodeDenylister    NodeDenylister
	limiter           RateLimiter
}

// NewServer creates a Server backed by the given token Service, Signer (CA), and Registrar.
// Optional opts (e.g. WithPostEnrollRevocationCheck) are applied after construction.
func NewServer(tokens *Service, signer Signer, reg Registrar, opts ...ServerOption) *Server {
	s := &Server{
		tokens:   tokens,
		signer:   signer,
		registry: reg,
		newID:    randomNodeID,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// randomNodeID generates a random 16-byte node_id, hex-encoded with a "node-" prefix.
func randomNodeID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "node-" + hex.EncodeToString(b), nil
}

// peerIP extracts the source IP from the gRPC peer Addr in ctx, stripping the
// port so all connections from one host share a rate-limit bucket.
//
// Returns "unknown" when the context carries no peer Addr — unreachable in
// production (the certless Enroll always arrives over TCP with a peer), but
// possible in tests that omit the peer context. Tests must use ctxFromIP to
// inject a peer so they do not all share the "unknown" bucket.
func peerIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		// Addr string is not host:port (e.g. a Unix socket path). Use raw string.
		return p.Addr.String()
	}
	return host
}

// Enroll validates the Enrollment Token, signs the CSR with a Relay-assigned node_id,
// records the Node in the registry, and returns the issued certificate, CA bundle, and
// relay-space labels stamped from the token scope.
//
// Sign and registry writes happen ONLY after the token validates; any rejection leaves
// no certificate and no registry entry (fail-closed).
func (s *Server) Enroll(ctx context.Context, req *gleipnirv1.EnrollRequest) (*gleipnirv1.EnrollResponse, error) {
	// a. Rate-limit check: runs BEFORE any token validation or CSR signing so that
	//    a throttled rejection cannot be used to probe whether an Enrollment Token
	//    is valid (no oracle). Nil limiter is skipped to preserve backward
	//    compatibility for servers constructed without WithRateLimiter.
	if s.limiter != nil && !s.limiter.Allow(peerIP(ctx)) {
		return nil, status.Error(codes.ResourceExhausted, "enrollment rate limit exceeded")
	}

	// b. Reject empty token or empty CSR.
	if req.GetEnrollmentToken() == "" || len(req.GetCsr()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "enrollment_token and csr are required")
	}

	// c. Parse self_labels (no side effects). Require "node:" prefix and a non-empty
	//    bare key to enforce the structural boundary: a daemon can never inject relay-space
	//    labels (ADR-0006 two-namespace invariant).
	nodeLabels := make(map[string]string, len(req.GetSelfLabels()))
	for _, l := range req.GetSelfLabels() {
		bare, ok := protoconv.ParseNodeLabel(l.GetKey())
		if !ok {
			return nil, status.Error(codes.InvalidArgument, "self_labels must be node:-prefixed")
		}
		nodeLabels[bare] = l.GetValue()
	}

	// d. Extract the public token ID from the credential for provenance storage.
	//    This is the non-secret half of "id.secret"; used only after Validate succeeds.
	var tokenID string
	if parts := strings.SplitN(req.GetEnrollmentToken(), secretSep, 2); len(parts) == 2 {
		tokenID = parts[0]
	}

	// e. Validate the token. Collapse all sentinel rejection errors into a single
	//    PermissionDenied so the caller cannot use error distinctions as a state oracle.
	scope, err := s.tokens.Validate(ctx, req.GetEnrollmentToken())
	if err != nil {
		if errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrExpired) ||
			errors.Is(err, ErrRevoked) || errors.Is(err, ErrExhausted) {
			return nil, status.Error(codes.PermissionDenied, "enrollment token rejected")
		}
		return nil, status.Error(codes.Internal, "enrollment failed")
	}

	// f. Generate a Relay-assigned node_id; the CSR subject is never trusted (ADR-0006).
	nodeID, err := s.newID()
	if err != nil {
		return nil, status.Error(codes.Internal, "enrollment failed")
	}

	// g. Sign the CSR. SignCSR ignores the CSR subject and sets CN=nodeID authoritatively.
	certPEM, err := s.signer.SignCSR(req.GetCsr(), nodeID)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid CSR")
	}

	// h. Compute SHA-256 cert fingerprint (hex of DER bytes) for the registry record.
	//    The nil-block branch is unreachable: SignCSR guarantees valid PEM on success.
	var fp string
	if block, _ := pem.Decode(certPEM); block != nil {
		sum := sha256.Sum256(block.Bytes)
		fp = hex.EncodeToString(sum[:])
	}

	// i. Map proto Facts -> registry.Facts; nil-safe.
	facts := protoconv.FactsFromProto(req.GetFacts())

	// j. Record the Node. This is the only write path for node-space labels + Facts.
	if _, err := s.registry.Upsert(registry.Report{
		NodeID:           nodeID,
		CertFingerprint:  fp,
		Facts:            facts,
		NodeLabels:       nodeLabels,
		EnrollingTokenID: tokenID,
	}); err != nil {
		if errors.Is(err, registry.ErrAtCapacity) {
			return nil, status.Error(codes.ResourceExhausted, "fleet registry at capacity")
		}
		return nil, status.Error(codes.Internal, "enrollment failed")
	}

	// k. Parse the token scope into bare relay-space keys and stamp them on the Node.
	relayBare := make(map[string]string, len(scope))
	for _, entry := range scope {
		bare := strings.TrimPrefix(entry, "relay:")
		kv := strings.SplitN(bare, "=", 2)
		if len(kv) == 2 {
			relayBare[kv[0]] = kv[1]
		} else {
			relayBare[kv[0]] = ""
		}
	}
	if err := s.registry.SetRelayLabels(nodeID, relayBare); err != nil {
		return nil, status.Error(codes.Internal, "enrollment failed")
	}

	// Post-Upsert recheck (issue #57): the Validate→Upsert sequence is not atomic,
	// so a concurrent RevokeToken cascade can complete its bounded re-scan in the
	// window between our Validate and this Upsert, missing this Node. Re-read the
	// enrolling token's state now that the Node is durably recorded; if it was
	// revoked mid-flight, self-denylist this node_id and fail closed. Skipped when
	// the check is not wired (revocationChecker == nil) to preserve existing behavior.
	if s.revocationChecker != nil {
		revoked, err := s.revocationChecker.IsRevoked(ctx, tokenID)
		if err != nil || revoked {
			// Fail closed: on an indeterminate check OR a confirmed revocation,
			// revoke the just-minted identity. RevokeNode is idempotent and the
			// Node has no live Tunnel yet, so Disconnect is a harmless no-op; the
			// denylist entry blocks the daemon's later Tunnel dial (ADR-0006).
			//
			// Invariant: WithPostEnrollRevocationCheck sets revocationChecker and
			// nodeDenylister together and panics if either is nil, so nodeDenylister
			// is non-nil whenever revocationChecker is. The guard is defensive only
			// against direct struct construction (e.g. in tests) and keeps the denial
			// path from silently skipping the denylist.
			if s.nodeDenylister != nil {
				s.nodeDenylister.RevokeNode(nodeID)
			}
			// Log the raw check error (nil on the confirmed-revocation path) so the
			// denial reason is unambiguous once a persistent store makes err != nil
			// reachable. err is a repository error, never credential material.
			slog.Warn("enrollment denied: token revoked mid-enrollment",
				"node_id", nodeID, "token_id", tokenID, "check_err", err)
			return nil, status.Error(codes.PermissionDenied, "enrollment token rejected")
		}
	}

	// l. Build assigned_labels, keeping the "relay:" namespace prefix in Key per proto convention.
	assigned := make([]*gleipnirv1.Label, 0, len(scope))
	for _, entry := range scope {
		bare := strings.TrimPrefix(entry, "relay:")
		kv := strings.SplitN(bare, "=", 2)
		l := &gleipnirv1.Label{Key: "relay:" + kv[0]}
		if len(kv) == 2 {
			l.Value = kv[1]
		}
		assigned = append(assigned, l)
	}

	// m. Log one audit line. tokenID is the public half of the credential — safe to log.
	//    Never log the secret half or the full plaintext credential.
	slog.Info("node enrolled",
		"node_id", nodeID,
		"token_id", tokenID,
		"hostname", facts.Hostname,
		"node_label_count", len(nodeLabels),
		"relay_label_count", len(relayBare),
	)

	// n. Return the response.
	return &gleipnirv1.EnrollResponse{
		NodeId:         nodeID,
		Certificate:    certPEM,
		CaBundle:       s.signer.Bundle(),
		AssignedLabels: assigned,
	}, nil
}

// Renew issues a fresh certificate for the same node_id authenticated via the
// caller's existing mTLS identity. The CSR supplies only the new public key;
// node_id and CN are derived exclusively from the verified TLS peer cert
// (ADR-0006 invariant: identity = client cert, never the CSR subject).
//
// The registry is NOT touched: no Upsert, no label changes, no new EnrollingTokenID.
// This structurally preserves provenance and labels from initial enrollment.
// The registry's CertFingerprint reflects the renewed cert only after the daemon's
// next Hello Upsert (on reconnect). Operators must not treat the fingerprint as a
// liveness assertion of the current live client cert.
func (s *Server) Renew(ctx context.Context, req *gleipnirv1.RenewRequest) (*gleipnirv1.RenewResponse, error) {
	// a. Reject an empty CSR immediately.
	if len(req.GetCsr()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "csr is required")
	}

	// b. Derive node_id solely from the verified TLS peer cert CN injected by
	//    UnaryServerInterceptor. Fail closed: if the context carries no node
	//    identity the caller has no valid mTLS cert (ADR-0006).
	nodeID, ok := transport.NodeIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no node identity")
	}

	// c. Sign the new CSR. SignCSR sets CN=nodeID authoritatively and ignores the
	//    CSR subject/SANs (ADR-0006). Any parse error means a bad CSR from the caller.
	certPEM, err := s.signer.SignCSR(req.GetCsr(), nodeID)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid CSR")
	}

	// d. Audit log: node_id only — no key material, no CSR contents.
	slog.Info("node cert renewed", "node_id", nodeID)

	return &gleipnirv1.RenewResponse{
		NodeId:      nodeID,
		Certificate: certPEM,
		CaBundle:    s.signer.Bundle(),
	}, nil
}
