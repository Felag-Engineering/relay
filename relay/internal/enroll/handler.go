package enroll

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log/slog"
	"strings"

	gleipnirv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/gleipnir/v1"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/transport"
	"google.golang.org/grpc/codes"
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

// Server implements gleipnirv1.EnrollmentServer. It validates Enrollment Tokens,
// signs CSRs, and records Nodes in the registry (ADR-0006).
type Server struct {
	gleipnirv1.UnimplementedEnrollmentServer
	tokens   *Service
	signer   Signer
	registry Registrar
	newID    func() (string, error)
}

// NewServer creates a Server backed by the given token Service, Signer (CA), and Registrar.
func NewServer(tokens *Service, signer Signer, reg Registrar) *Server {
	return &Server{
		tokens:   tokens,
		signer:   signer,
		registry: reg,
		newID:    randomNodeID,
	}
}

// randomNodeID generates a random 16-byte node_id, hex-encoded with a "node-" prefix.
func randomNodeID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "node-" + hex.EncodeToString(b), nil
}

// Enroll validates the Enrollment Token, signs the CSR with a Relay-assigned node_id,
// records the Node in the registry, and returns the issued certificate, CA bundle, and
// relay-space labels stamped from the token scope.
//
// Sign and registry writes happen ONLY after the token validates; any rejection leaves
// no certificate and no registry entry (fail-closed).
func (s *Server) Enroll(ctx context.Context, req *gleipnirv1.EnrollRequest) (*gleipnirv1.EnrollResponse, error) {
	// a. Reject empty token or empty CSR.
	if req.GetEnrollmentToken() == "" || len(req.GetCsr()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "enrollment_token and csr are required")
	}

	// b. Parse self_labels (no side effects). Require "node:" prefix and a non-empty
	//    bare key to enforce the structural boundary: a daemon can never inject relay-space
	//    labels (ADR-0006 two-namespace invariant).
	nodeLabels := make(map[string]string, len(req.GetSelfLabels()))
	for _, l := range req.GetSelfLabels() {
		if !strings.HasPrefix(l.GetKey(), "node:") {
			return nil, status.Error(codes.InvalidArgument, "self_labels must be node:-prefixed")
		}
		bareKey := strings.TrimPrefix(l.GetKey(), "node:")
		if bareKey == "" {
			return nil, status.Error(codes.InvalidArgument, "self_labels must be node:-prefixed")
		}
		nodeLabels[bareKey] = l.GetValue()
	}

	// c. Extract the public token ID from the credential for provenance storage.
	//    This is the non-secret half of "id.secret"; used only after Validate succeeds.
	var tokenID string
	if parts := strings.SplitN(req.GetEnrollmentToken(), secretSep, 2); len(parts) == 2 {
		tokenID = parts[0]
	}

	// d. Validate the token. Collapse all sentinel rejection errors into a single
	//    PermissionDenied so the caller cannot use error distinctions as a state oracle.
	scope, err := s.tokens.Validate(ctx, req.GetEnrollmentToken())
	if err != nil {
		if errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrExpired) ||
			errors.Is(err, ErrRevoked) || errors.Is(err, ErrExhausted) {
			return nil, status.Error(codes.PermissionDenied, "enrollment token rejected")
		}
		return nil, status.Error(codes.Internal, "enrollment failed")
	}

	// e. Generate a Relay-assigned node_id; the CSR subject is never trusted (ADR-0006).
	nodeID, err := s.newID()
	if err != nil {
		return nil, status.Error(codes.Internal, "enrollment failed")
	}

	// f. Sign the CSR. SignCSR ignores the CSR subject and sets CN=nodeID authoritatively.
	certPEM, err := s.signer.SignCSR(req.GetCsr(), nodeID)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid CSR")
	}

	// g. Compute SHA-256 cert fingerprint (hex of DER bytes) for the registry record.
	//    The nil-block branch is unreachable: SignCSR guarantees valid PEM on success.
	var fp string
	if block, _ := pem.Decode(certPEM); block != nil {
		sum := sha256.Sum256(block.Bytes)
		fp = hex.EncodeToString(sum[:])
	}

	// h. Map proto Facts → registry.Facts; nil-safe.
	var facts registry.Facts
	if pf := req.GetFacts(); pf != nil {
		facts = registry.Facts{
			Hostname:    pf.GetHostname(),
			OS:          pf.GetOs(),
			Kernel:      pf.GetKernel(),
			Arch:        pf.GetArch(),
			IPAddresses: append([]string(nil), pf.GetIpAddresses()...),
		}
	}

	// i. Record the Node. This is the only write path for node-space labels + Facts.
	if _, err := s.registry.Upsert(registry.Report{
		NodeID:           nodeID,
		CertFingerprint:  fp,
		Facts:            facts,
		NodeLabels:       nodeLabels,
		EnrollingTokenID: tokenID,
	}); err != nil {
		return nil, status.Error(codes.Internal, "enrollment failed")
	}

	// j. Parse the token scope into bare relay-space keys and stamp them on the Node.
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

	// k. Build assigned_labels, keeping the "relay:" namespace prefix in Key per proto convention.
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

	// l. Log one audit line. tokenID is the public half of the credential — safe to log.
	//    Never log the secret half or the full plaintext credential.
	slog.Info("node enrolled",
		"node_id", nodeID,
		"token_id", tokenID,
		"hostname", facts.Hostname,
		"node_label_count", len(nodeLabels),
		"relay_label_count", len(relayBare),
	)

	// m. Return the response.
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
