package enroll

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/logctx"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/protoconv"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	relayv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"
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

	// RecordEnrollment and RecordRenewal persist the certificate provenance the
	// Relay itself knows: what it just signed, and when.
	//
	// Two methods rather than one with a flag. This server is the only caller of
	// either, and it calls one from Enroll and the other from Renew — so
	// "renewal preserves the join date" is a property of which function each
	// path can reach, not of a boolean somebody has to get right.
	RecordEnrollment(nodeID string, cert registry.Certificate, at time.Time) error
	RecordRenewal(nodeID string, cert registry.Certificate, at time.Time) error
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

// EnrollmentObserver records a successful Enrollment for observability.
// *metrics.Metrics satisfies this interface. Kept as an interface so enroll
// carries no compile-time dependency on the metrics package.
type EnrollmentObserver interface {
	IncEnrollment()
}

// AttemptReason is the closed vocabulary of Relay-side outcomes for one
// Enroll attempt (feeding the Console's day-one screen). It is distinct from
// EnrollmentObserver: that counter is success-only; this covers every
// terminal point of Enroll, success and rejection alike.
type AttemptReason string

const (
	AttemptExpired              AttemptReason = "expired"
	AttemptRevoked              AttemptReason = "revoked"
	AttemptUnknown              AttemptReason = "unknown"
	AttemptExhausted            AttemptReason = "exhausted"
	AttemptMalformed            AttemptReason = "malformed"
	AttemptRateLimited          AttemptReason = "rate_limited"
	AttemptAtCapacity           AttemptReason = "at_capacity"
	AttemptRevokedMidEnrollment AttemptReason = "revoked_mid_enrollment"
	AttemptInternal             AttemptReason = "internal"
	// AttemptInvalidScope: the token's STORED scope is not well-formed — a fault in
	// a token this Relay minted before the gate existed, never in the daemon's
	// request. Deliberately not AttemptMalformed, which means "the caller sent
	// something malformed" and would send an operator to debug the wrong side.
	AttemptInvalidScope AttemptReason = "invalid_scope"
)

// AttemptEvent is one Enroll attempt, accepted or rejected.
//
// SECURITY NOTE: the distinct Reason here goes ONLY to AttemptObserver, over
// the in-process event bus and on to the Console's authenticated surface —
// never onto the wire. Every rejection Enroll actually RETURNS to the
// enrolling daemon still collapses to the same codes.PermissionDenied
// (below); this event exists beside that response, not instead of it, so
// the no-oracle property enrollment relies on stays exactly as it was
// before this type existed.
type AttemptEvent struct {
	Accepted bool
	Reason   AttemptReason
	// TokenID is the PUBLIC half of the presented credential (see tokenID's
	// extraction below at (d)) — never the plaintext, and never the secret
	// half. Empty when the credential did not parse.
	TokenID string
	NodeID  string
	// Source is the caller's IP (peerIP(ctx)).
	Source string
}

// AttemptObserver records one Enroll attempt. The composition root supplies
// an adapter that publishes to the event bus.
//
// No error return — an enrollment must never fail because an event could
// not be published, mirroring EnrollmentObserver and, in package mcp,
// ToolCallObserver.
type AttemptObserver interface {
	Attempt(ctx context.Context, e AttemptEvent)
}

// WithAttemptObserver attaches an AttemptObserver, called at every terminal
// point of Enroll — accept and reject alike (Renew publishes nothing: it is
// certificate-authenticated, not an enrollment attempt). Pass a nil observer
// (the default) to skip observation, matching WithEnrollmentObserver.
func WithAttemptObserver(o AttemptObserver) ServerOption {
	return func(s *Server) {
		s.attempts = o
	}
}

// ServerOption configures a Server at construction.
type ServerOption func(*Server)

// WithPostEnrollRevocationCheck enables the post-Upsert recheck that closes the
// in-flight-enroll vs token-cascade-revocation race. When set, after a
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

// WithEnrollmentObserver attaches an EnrollmentObserver whose IncEnrollment is
// called once per successful Enroll — only the success path, since every
// failure path returns earlier. Pass a nil observer (the default) to skip
// observation.
func WithEnrollmentObserver(o EnrollmentObserver) ServerOption {
	return func(s *Server) {
		s.observer = o
	}
}

// Server implements relayv1.EnrollmentServer. It validates Enrollment Tokens,
// signs CSRs, and records Nodes in the registry (ADR-0006).
type Server struct {
	relayv1.UnimplementedEnrollmentServer
	tokens            *Service
	signer            Signer
	registry          Registrar
	newID             func() (string, error)
	revocationChecker TokenRevocationChecker
	nodeDenylister    NodeDenylister
	limiter           RateLimiter
	observer          EnrollmentObserver
	attempts          AttemptObserver
	now               func() time.Time
	log               *slog.Logger // nil means slog.Default() (logger)
}

// WithServerLogger sets the logger the Server reports enrollment and renewal
// events to. Observational only. Without it the Server logs through
// slog.Default().
func WithServerLogger(l *slog.Logger) ServerOption {
	return func(s *Server) { s.log = l }
}

func (s *Server) logger() *slog.Logger { return logctx.Or(s.log) }

// WithServerClock overrides the clock used to stamp certificate provenance.
// Tests use it so an assertion about enrolled_at is not a race with the
// wall clock. Defaults to time.Now().UTC().
//
// Named apart from WithClock, which already configures the token Service in this
// package and returns a different option type.
func WithServerClock(now func() time.Time) ServerOption {
	return func(s *Server) {
		if now != nil {
			s.now = now
		}
	}
}

// issuedCertificate reads back what the CA actually signed: the SHA-256
// fingerprint of the DER bytes, and the expiry.
//
// Reading the certificate rather than recomputing from ca.LeafValidity is the
// point. The record then describes what a Node is holding, not what this code
// would issue today, so changing the validity constant cannot retroactively
// rewrite the fleet's expiries.
//
// A malformed certificate yields a zero NotAfter, which the domain reads as
// "not recorded" (registry.Node.CertProvenanceKnown) — never as an expiry at
// the epoch, which would render as catastrophically overdue.
func issuedCertificate(certPEM []byte) registry.Certificate {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return registry.Certificate{}
	}
	sum := sha256.Sum256(block.Bytes)
	c := registry.Certificate{Fingerprint: hex.EncodeToString(sum[:])}
	if leaf, err := x509.ParseCertificate(block.Bytes); err == nil {
		c.NotAfter = leaf.NotAfter.UTC()
	}
	return c
}

// NewServer creates a Server backed by the given token Service, Signer (CA), and Registrar.
// Optional opts (e.g. WithPostEnrollRevocationCheck) are applied after construction.
func NewServer(tokens *Service, signer Signer, reg Registrar, opts ...ServerOption) *Server {
	s := &Server{
		tokens:   tokens,
		signer:   signer,
		registry: reg,
		newID:    randomNodeID,
		now:      func() time.Time { return time.Now().UTC() },
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

// tokenIDLen is the exact length of a genuine token id: 16 random bytes,
// hex-encoded (token.go's Create). Anything else is not a real id.
const tokenIDLen = 32

// looksLikeTokenID reports whether s has the exact shape Create produces:
// tokenIDLen lowercase hex characters, no more, no less. e.TokenID reaches
// this function BEFORE Validate has confirmed the id names a real token
// (e.g. on the AttemptUnknown path), so it must be validated by shape
// alone, not by a repository lookup.
func looksLikeTokenID(s string) bool {
	if len(s) != tokenIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// attempt publishes e via s.attempts, the ONE place an AttemptEvent is
// built. e.TokenID reaches this function as SplitN(presented, secretSep,
// 2)[0] of the RAW, UNAUTHENTICATED, PRE-VALIDATION request field (d,
// below) — attacker-controlled in both length and content up to gRPC's
// message-size limit, and the bus retains published events for the full
// retention window. A genuine token id is always exactly tokenIDLen
// lowercase hex characters (token.go's Create), so anything else —
// oversized, wrong charset, containing secretSep, empty — is blanked
// before publish. This is lossless for every real token and bounds both
// the bytes this pre-auth endpoint can push into the bus and the
// control-character/newline injection surface a future SSE renderer
// would otherwise inherit.
//
// A nil s.attempts (the default) is a no-op, matching s.observer.
func (s *Server) attempt(ctx context.Context, e AttemptEvent) {
	if s.attempts == nil {
		return
	}
	if !looksLikeTokenID(e.TokenID) {
		e.TokenID = ""
	}
	s.attempts.Attempt(ctx, e)
}

// Enroll validates the Enrollment Token, signs the CSR with a Relay-assigned node_id,
// records the Node in the registry, and returns the issued certificate, CA bundle, and
// relay-space labels stamped from the token scope.
//
// Sign and registry writes happen ONLY after the token validates; any rejection leaves
// no certificate and no registry entry (fail-closed).
func (s *Server) Enroll(ctx context.Context, req *relayv1.EnrollRequest) (*relayv1.EnrollResponse, error) {
	source := peerIP(ctx)

	// a. Rate-limit check: runs BEFORE any token validation or CSR signing so that
	//    a throttled rejection cannot be used to probe whether an Enrollment Token
	//    is valid (no oracle). Nil limiter is skipped to preserve backward
	//    compatibility for servers constructed without WithRateLimiter.
	if s.limiter != nil && !s.limiter.Allow(source) {
		// The token is not parsed yet, and parsing it here would undo the
		// no-oracle ordering above (rate-limit before Validate) — TokenID
		// stays empty.
		s.attempt(ctx, AttemptEvent{Reason: AttemptRateLimited, Source: source})
		return nil, status.Error(codes.ResourceExhausted, "enrollment rate limit exceeded")
	}

	// b. Reject empty token or empty CSR.
	if req.GetEnrollmentToken() == "" || len(req.GetCsr()) == 0 {
		s.attempt(ctx, AttemptEvent{Reason: AttemptMalformed, Source: source})
		return nil, status.Error(codes.InvalidArgument, "enrollment_token and csr are required")
	}

	// c. Parse self_labels (no side effects). Require a "node:" prefix, a
	//    non-empty bare key, AND a well-formed (bare key, value) pair
	//    (registry.WellFormedLabel) to enforce the structural
	//    boundary: a daemon can never inject relay-space labels (ADR-0006
	//    two-namespace invariant), and it can never enroll a label that
	//    would render as more than one Selector term. The relay-space
	//    sibling of this refuse-vs-drop argument lives at Service.Validate:
	//    the scope is refused before Validate returns, for the same
	//    fail-closed reason — this is one-shot and supervised, so a
	//    rejection here tears down nothing that was already up.
	//
	//    WHY enrollment REJECTS where Hello (tunnel.go) DROPS: enrollment is
	//    one-shot, pre-identity and supervised — a human is watching the
	//    install, and a rejection here leaves no certificate and no registry
	//    row at all (fail-closed on the whole request, not just the label).
	//    Softening this to a per-label drop would let a Node join with
	//    silently fewer labels than it asked for, which is the same
	//    silent-targeting-drift this issue exists to close, just moved to a
	//    different moment. Hello is long-lived, unattended and
	//    reconnect-driven, where a hard refusal costs reachability instead —
	//    a cost enrollment does not pay, because failing here does not tear
	//    down anything that was already up.
	nodeLabels := make(map[string]string, len(req.GetSelfLabels()))
	for _, l := range req.GetSelfLabels() {
		bare, ok := protoconv.ParseNodeLabel(l.GetKey(), l.GetValue())
		if !ok {
			s.attempt(ctx, AttemptEvent{Reason: AttemptMalformed, Source: source})
			return nil, status.Errorf(codes.InvalidArgument,
				"self_labels must be node:-prefixed, with a non-empty bare key and a "+
					"(possibly empty) value whose every byte is in [A-Za-z0-9._-] (offending key: %q)",
				l.GetKey())
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
		// ErrInvalidToken deliberately fuses malformed/unknown-id/wrong-secret
		// at the RPC boundary (token.go), so AttemptUnknown is the honest name
		// for it here — the Console gets one bucket for "not a real token",
		// same as the daemon's single PermissionDenied.
		reason := AttemptInternal
		switch {
		case errors.Is(err, ErrExpired):
			reason = AttemptExpired
		case errors.Is(err, ErrRevoked):
			reason = AttemptRevoked
		case errors.Is(err, ErrExhausted):
			reason = AttemptExhausted
		case errors.Is(err, ErrInvalidToken):
			reason = AttemptUnknown
		case errors.Is(err, ErrInvalidScope):
			reason = AttemptInvalidScope
		}
		s.attempt(ctx, AttemptEvent{Reason: reason, TokenID: tokenID, Source: source})
		if errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrExpired) ||
			errors.Is(err, ErrRevoked) || errors.Is(err, ErrExhausted) ||
			errors.Is(err, ErrInvalidScope) {
			if errors.Is(err, ErrInvalidScope) {
				// The offending entry surfaces here and nowhere else: it never
				// goes on the wire, and the collapse below returns the same
				// PermissionDenied every other token rejection returns, so it
				// cannot become an oracle that distinguishes this rejection
				// from any other. (Scope is already loggable: Token.LogValue
				// emits it.)
				s.logger().WarnContext(ctx, "enrollment denied: stored token scope is not well-formed",
					"token_id", tokenID, "err", err)
			}
			return nil, status.Error(codes.PermissionDenied, "enrollment token rejected")
		}
		return nil, status.Error(codes.Internal, "enrollment failed")
	}

	// f. Generate a Relay-assigned node_id; the CSR subject is never trusted (ADR-0006).
	nodeID, err := s.newID()
	if err != nil {
		s.attempt(ctx, AttemptEvent{Reason: AttemptInternal, TokenID: tokenID, Source: source})
		return nil, status.Error(codes.Internal, "enrollment failed")
	}

	// g. Sign the CSR. SignCSR ignores the CSR subject and sets CN=nodeID authoritatively.
	certPEM, err := s.signer.SignCSR(req.GetCsr(), nodeID)
	if err != nil {
		// A caller-supplied CSR failing to sign reads more honestly as
		// malformed input than a Relay-internal failure.
		s.attempt(ctx, AttemptEvent{Reason: AttemptMalformed, TokenID: tokenID, NodeID: nodeID, Source: source})
		return nil, status.Error(codes.InvalidArgument, "invalid CSR")
	}

	// h. Read back what was actually signed: the SHA-256 fingerprint of the DER
	//    bytes, and the expiry the CA set.
	//
	//    Read from the certificate rather than recomputed from ca.LeafValidity,
	//    so the record says what this Node is holding rather than what the code
	//    would issue today. If the validity constant changes, already-issued
	//    Nodes keep their true expiry instead of being retroactively rewritten.
	//
	//    The nil-block branch is unreachable: SignCSR guarantees valid PEM on
	//    success. A parse failure leaves NotAfter zero, which the domain reads as
	//    "not recorded" (registry.Node.CertProvenanceKnown) rather than as an
	//    expiry at the epoch.
	issued := issuedCertificate(certPEM)
	fp := issued.Fingerprint

	// i. Map proto Facts -> registry.Facts; nil-safe.
	facts := protoconv.FactsFromProto(req.GetFacts())

	// j. Record the Node. This is the only write path for node-space labels + Facts.
	if _, err := s.registry.Upsert(registry.Report{
		NodeID:           nodeID,
		CertFingerprint:  fp,
		Facts:            facts,
		EnrollingTokenID: tokenID,
	}.WithNodeLabels(nodeLabels)); err != nil {
		if errors.Is(err, registry.ErrAtCapacity) {
			s.attempt(ctx, AttemptEvent{Reason: AttemptAtCapacity, TokenID: tokenID, NodeID: nodeID, Source: source})
			return nil, status.Error(codes.ResourceExhausted, "fleet registry at capacity")
		}
		s.attempt(ctx, AttemptEvent{Reason: AttemptInternal, TokenID: tokenID, NodeID: nodeID, Source: source})
		return nil, status.Error(codes.Internal, "enrollment failed")
	}

	// j2. Record the certificate provenance. AFTER the Upsert, because that is
	//     what creates the row; a failure here is logged and not fatal, since the
	//     Node is enrolled and working and refusing it would strand a machine
	//     over a bookkeeping write. The cost of the miss is bounded: the next
	//     renewal records the expiry, and that is at most one leaf lifetime away.
	//
	//     Deliberately publishes NO AttemptEvent: this is not a terminal
	//     branch — Enroll falls through to (k), the revocation recheck, and
	//     (n) IncEnrollment, then returns success. Publishing here would emit
	//     a phantom rejection ahead of the real Accepted:true event for what
	//     is, from the enrolling daemon's point of view, a successful
	//     enrollment — exactly the false alarm the Console's day-one screen
	//     must not show.
	if err := s.registry.RecordEnrollment(nodeID, issued, s.now()); err != nil {
		s.logger().WarnContext(ctx, "recording enrollment certificate provenance failed",
			"node_id", nodeID, "err", err)
	}

	// k. Parse the token scope into bare relay-space keys and stamp them on the Node.
	//    The scope is well-formed BY CONSTRUCTION here — Service.Validate
	//    already refused otherwise, before any certificate was signed or any row
	//    written — so nothing this stamps can render as more than one Selector term.
	relayBare := make(map[string]string, len(scope))
	for _, entry := range scope {
		key, value := splitScopeEntry(entry)
		relayBare[key] = value
	}
	if err := s.registry.SetRelayLabels(nodeID, relayBare); err != nil {
		s.attempt(ctx, AttemptEvent{Reason: AttemptInternal, TokenID: tokenID, NodeID: nodeID, Source: source})
		return nil, status.Error(codes.Internal, "enrollment failed")
	}

	// Post-Upsert recheck: the Validate→Upsert sequence is not atomic,
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
			s.logger().WarnContext(ctx, "enrollment denied: token revoked mid-enrollment",
				"node_id", nodeID, "token_id", tokenID, "check_err", err)
			s.attempt(ctx, AttemptEvent{Reason: AttemptRevokedMidEnrollment, TokenID: tokenID, NodeID: nodeID, Source: source})
			return nil, status.Error(codes.PermissionDenied, "enrollment token rejected")
		}
	}

	// l. Build assigned_labels, keeping the "relay:" namespace prefix in Key per proto convention.
	//    Setting Value unconditionally is wire-identical to the old conditional
	//    assignment: proto3 already renders an unset string field as "".
	assigned := make([]*relayv1.Label, 0, len(scope))
	for _, entry := range scope {
		key, value := splitScopeEntry(entry)
		assigned = append(assigned, &relayv1.Label{Key: scopePrefix + key, Value: value})
	}

	// m. Log one audit line. tokenID is the public half of the credential — safe to log.
	//    Never log the secret half or the full plaintext credential.
	s.logger().InfoContext(ctx, "node enrolled",
		"node_id", nodeID,
		"token_id", tokenID,
		"hostname", facts.Hostname,
		"node_label_count", len(nodeLabels),
		"relay_label_count", len(relayBare),
	)

	// n. Record the successful Enrollment for observability. Only the success
	//    path reaches here — every failure path above returns earlier.
	if s.observer != nil {
		s.observer.IncEnrollment()
	}
	s.attempt(ctx, AttemptEvent{Accepted: true, NodeID: nodeID, TokenID: tokenID, Source: source})

	// o. Return the response.
	return &relayv1.EnrollResponse{
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
func (s *Server) Renew(ctx context.Context, req *relayv1.RenewRequest) (*relayv1.RenewResponse, error) {
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

	// d. Record the reissue: new expiry, renewal count, renewal time. Never the
	//    join date — RecordRenewal has no path to it.
	//
	//    Non-fatal for the same reason as at enrollment: the Node now holds a
	//    valid certificate, and failing the RPC over a bookkeeping write would
	//    push it toward the expiry this record exists to warn about.
	if err := s.registry.RecordRenewal(nodeID, issuedCertificate(certPEM), s.now()); err != nil {
		s.logger().WarnContext(ctx, "recording renewal certificate provenance failed",
			"node_id", nodeID, "err", err)
	}

	// e. Audit log: node_id only — no key material, no CSR contents.
	s.logger().InfoContext(ctx, "node cert renewed", "node_id", nodeID)

	return &relayv1.RenewResponse{
		NodeId:      nodeID,
		Certificate: certPEM,
		CaBundle:    s.signer.Bundle(),
	}, nil
}
