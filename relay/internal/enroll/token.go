// Package enroll mints, validates, and revokes Enrollment Tokens.
//
// An Enrollment Token is the reusable, scoped, expiring, revocable credential a
// relay-daemon presents to join the fleet. It authorizes enrollment only — it can
// never run Operations. The token secret is stored as a SHA-256 hash and is never
// logged. See CONTEXT.md ("Enrollment Token") and ADR-0006.
package enroll

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// secretSep separates the public id from the secret part in the plaintext credential.
// Neither hex (id) nor base64.RawURLEncoding (secret) emit '.', so a split into
// exactly two parts is unambiguous.
const secretSep = "."

// Sentinel errors returned by Service methods. Use errors.Is to check.
var (
	// ErrInvalidToken covers malformed credential, unknown id, and wrong secret as a
	// single error so Validate does not act as an existence or state oracle.
	ErrInvalidToken = errors.New("enroll: invalid token")

	// ErrExpired is returned when the token's ExpiresAt is in the past.
	ErrExpired = errors.New("enroll: token expired")

	// ErrRevoked is returned when the token has been explicitly revoked.
	ErrRevoked = errors.New("enroll: token revoked")

	// ErrExhausted is returned when MaxUses > 0 and Uses has reached MaxUses.
	ErrExhausted = errors.New("enroll: token max-uses exhausted")

	// ErrNotFound is returned by Revoke and by Repository when the id is unknown.
	ErrNotFound = errors.New("enroll: not found")

	// ErrDuplicateID is returned by Repository.Create when a token with the same
	// id already exists. Distinct from ErrInvalidToken: it signals a store-level
	// id collision, not a validation failure on a presented credential.
	ErrDuplicateID = errors.New("enroll: token id already exists")

	// ErrInvalidScope is returned when the scope is empty or any entry lacks a
	// "relay:" prefix (ADR-0006 invariant #7).
	ErrInvalidScope = errors.New("enroll: scope must contain at least one relay:-prefixed label")

	// ErrInvalidTTL is returned when Create is called with a zero or negative TTL.
	ErrInvalidTTL = errors.New("enroll: TTL must be positive")
)

// Token is the stored form of an Enrollment Token. It contains no plaintext secret;
// only the SHA-256 hash of the secret part is kept. Callers must treat SecretHash as
// opaque and must never log it.
type Token struct {
	ID         string   // public identifier; appears in credentials and Revoke calls
	SecretHash []byte   // sha256 of the secret part only; the plaintext is never stored
	Scope      []string // relay: Labels stamped at enrollment (ADR-0006)
	ExpiresAt  time.Time
	Revoked    bool
	MaxUses    int // 0 = unlimited (reusable); >0 = hard cap on successful Validate calls
	Uses       int // count of successful Validate calls
	CreatedAt  time.Time
	CreatedBy  string // principal who minted the token
}

// LogValue implements slog.LogValuer. It returns a structured group that deliberately
// omits SecretHash so that logging a Token via slog never emits the hash. The
// plaintext secret is never stored on Token, so it is structurally unloggable.
func (t *Token) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", t.ID),
		slog.Any("scope", t.Scope),
		slog.Time("expires_at", t.ExpiresAt),
		slog.Bool("revoked", t.Revoked),
		slog.Int("uses", t.Uses),
		slog.Int("max_uses", t.MaxUses),
		slog.String("created_by", t.CreatedBy),
	)
}

// Repository is the storage layer for Tokens. It is pure persistence; all domain
// rules (expiry, revocation, max-uses) live in Service.
type Repository interface {
	// Create inserts t. Returns ErrDuplicateID if a token with the same ID already exists.
	Create(ctx context.Context, t *Token) error
	// ByID returns a defensive copy of the stored token or ErrNotFound.
	ByID(ctx context.Context, id string) (*Token, error)
	// Save persists mutations to an existing token (Uses, Revoked). Returns ErrNotFound
	// if no token with that ID exists.
	Save(ctx context.Context, t *Token) error
}

// createOpts accumulates optional parameters for Service.Create.
type createOpts struct {
	maxUses   int
	createdBy string
}

// Option configures a single Enrollment Token at Create time.
type Option func(*createOpts)

// WithMaxUses sets the maximum number of successful Validate calls allowed for the
// token. Values <= 0 are treated as unlimited (the default: reusable forever).
func WithMaxUses(n int) Option {
	return func(o *createOpts) {
		if n > 0 {
			o.maxUses = n
		}
	}
}

// WithCreatedBy records the principal who minted the token (audit trail).
func WithCreatedBy(s string) Option {
	return func(o *createOpts) { o.createdBy = s }
}

// ServiceOption configures a Service at construction time.
type ServiceOption func(*Service)

// WithClock injects a clock function. Used by tests for deterministic expiry
// assertions; defaults to time.Now.
func WithClock(fn func() time.Time) ServiceOption {
	return func(s *Service) { s.now = fn }
}

// Service mints, validates, and revokes Enrollment Tokens. It delegates storage to a
// Repository and enforces all domain rules itself.
type Service struct {
	repo Repository
	now  func() time.Time

	// mu globally serializes Validate and Revoke so the read→check→increment sequence
	// is atomic and MaxUses can never be exceeded under concurrent enrollment. This is
	// acceptable for the in-memory repository; a future persistent repository should
	// not inherit this as a silent bottleneck — revisit when adding persistence.
	mu sync.Mutex
}

// NewService creates a Service backed by repo. Optional sopts override defaults.
func NewService(repo Repository, sopts ...ServiceOption) *Service {
	s := &Service{repo: repo, now: time.Now}
	for _, o := range sopts {
		o(s)
	}
	return s
}

// validateScope returns ErrInvalidScope if scope is empty or any entry is not
// prefixed with "relay:", enforcing ADR-0006 invariant #7.
func validateScope(scope []string) error {
	if len(scope) == 0 {
		return ErrInvalidScope
	}
	for _, e := range scope {
		if !strings.HasPrefix(e, "relay:") {
			return ErrInvalidScope
		}
	}
	return nil
}

// Create mints a new Enrollment Token scoped to the given relay: Labels with the
// given TTL. It returns the Token record (suitable for storage) and the plaintext
// credential string, which is of the form id + secretSep + secret. The plaintext is
// returned exactly once and is never persisted or stored on the Token.
func (s *Service) Create(ctx context.Context, scope []string, ttl time.Duration, opts ...Option) (*Token, string, error) {
	if ttl <= 0 {
		return nil, "", ErrInvalidTTL
	}
	if err := validateScope(scope); err != nil {
		return nil, "", err
	}

	o := &createOpts{}
	for _, fn := range opts {
		fn(o)
	}

	// Generate a 16-byte random public id (hex-encoded, 32 chars) and a 32-byte random
	// secret (base64url, 43 chars). Neither encoding contains '.', so the credential
	// id+"."+secret is unambiguously splittable.
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, "", err
	}
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, "", err
	}

	id := hex.EncodeToString(idBytes)
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	hashArr := sha256.Sum256([]byte(secret))

	now := s.now()
	t := &Token{
		ID:         id,
		SecretHash: hashArr[:],
		Scope:      append([]string(nil), scope...),
		ExpiresAt:  now.Add(ttl),
		MaxUses:    o.maxUses,
		CreatedAt:  now,
		CreatedBy:  o.createdBy,
	}

	if err := s.repo.Create(ctx, t); err != nil {
		return nil, "", err
	}

	plaintext := id + secretSep + secret
	return t, plaintext, nil
}

// Validate checks a presented credential string. On success it returns the token's
// Scope (a defensive copy) and increments the use count. Errors:
//   - ErrInvalidToken: malformed credential, unknown id, or wrong secret
//     (collapsed into one error to avoid an existence/state oracle).
//   - ErrRevoked, ErrExpired, ErrExhausted: state errors, disclosed only after the
//     secret is verified (so a party without the secret learns nothing about state).
func (s *Service) Validate(ctx context.Context, presented string) ([]string, error) {
	// mu makes the read→check→increment sequence atomic so MaxUses is never exceeded.
	s.mu.Lock()
	defer s.mu.Unlock()

	parts := strings.SplitN(presented, secretSep, 2)
	if len(parts) != 2 {
		return nil, ErrInvalidToken
	}
	id, secretPart := parts[0], parts[1]

	t, err := s.repo.ByID(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrInvalidToken // do not disclose whether the id exists
	}
	if err != nil {
		return nil, err
	}

	// Verify the secret BEFORE disclosing any token state. A party without the correct
	// secret must not learn whether the token is revoked, expired, or exhausted.
	presented256 := sha256.Sum256([]byte(secretPart))
	if subtle.ConstantTimeCompare(presented256[:], t.SecretHash) != 1 {
		return nil, ErrInvalidToken
	}

	if t.Revoked {
		return nil, ErrRevoked
	}
	if s.now().After(t.ExpiresAt) {
		return nil, ErrExpired
	}
	if t.MaxUses > 0 && t.Uses >= t.MaxUses {
		return nil, ErrExhausted
	}

	t.Uses++
	if err := s.repo.Save(ctx, t); err != nil {
		return nil, err
	}

	return append([]string(nil), t.Scope...), nil
}

// Revoke marks a token as revoked. It is idempotent: revoking an already-revoked
// token returns nil. Returns ErrNotFound if the id is unknown.
func (s *Service) Revoke(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, err := s.repo.ByID(ctx, id)
	if err != nil {
		return err
	}
	t.Revoked = true
	return s.repo.Save(ctx, t)
}
