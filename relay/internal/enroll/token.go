// Package enroll mints, validates, and revokes Enrollment Tokens.
//
// An Enrollment Token is the reusable, expiring, revocable credential a
// relay-daemon presents to join the fleet, carrying the initial tags its Nodes
// are written with. It authorizes enrollment only — it can
// never run Operations. The token secret is stored as a SHA-256 hash and is never
// logged. See GLOSSARY.md ("Enrollment Token") and ADR-0006.
package enroll

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// secretSep separates the public id from the secret part in the plaintext credential.
// Neither hex (id) nor base64.RawURLEncoding (secret) emit '.', so a split into
// exactly two parts is unambiguous.
const secretSep = "."

// scopePrefix is the one spelling of the relay-space prefix: a legacy scope
// entry carries it, and so does the relay:node-id enrollment assigns.
const scopePrefix = "relay:"

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

	// ErrInvalidScope is returned when a legacy scope (relay: labels an earlier
	// release minted) holds an entry that is not "relay:"-prefixed with a
	// well-formed bare key/value pair (registry.WellFormedLabel), so a stored
	// malformed scope still refuses its token (EN-26).
	ErrInvalidScope = errors.New("enroll: a legacy scope entry must be " +
		"relay:-prefixed with a non-empty bare key and a (possibly empty) value whose every " +
		"byte is in [A-Za-z0-9._-]")

	// ErrInvalidInitialTags is returned when a mint, or a stored token, names
	// initial tags that are not each a well-formed tag: label, or that name a
	// relay: label. It wraps the registry's refusal, which names the
	// offending entry.
	ErrInvalidInitialTags = errors.New("enroll: invalid initial tags")

	// ErrInitialTagsNeedHuman is returned when a token names initial tags and
	// its minter is not a human Account: only a human Account writes tags.
	ErrInitialTagsNeedHuman = errors.New("enroll: only a human Account writes tags, so a machine Account's mint names no initial tag (ADR-0050)")

	// ErrInvalidTTL is returned when Create is called with a zero or negative TTL.
	ErrInvalidTTL = errors.New("enroll: TTL must be positive")
)

// Token is the stored form of an Enrollment Token. It contains no plaintext secret;
// only the SHA-256 hash of the secret part is kept. Callers must treat SecretHash as
// opaque and must never log it.
type Token struct {
	ID         string // public identifier; appears in credentials and Revoke calls
	SecretHash []byte // sha256 of the secret part only; the plaintext is never stored
	// LegacyScope is the relay: Labels an earlier release minted. It is never
	// stamped; a malformed one still refuses the token at Validate (EN-26).
	LegacyScope []string
	// InitialTags are written as each joining Node's first tags, in written
	// form tag:key=value (EN-40, EN-41).
	InitialTags []string
	ExpiresAt   time.Time
	Revoked     bool
	MaxUses     int // 0 = unlimited (reusable); >0 = hard cap on successful Validate calls
	Uses        int // count of successful Validate calls
	CreatedAt   time.Time
	// CreatedBy is the minting Principal's attribution, "name:role", and the
	// only home of the minter's name and role.
	CreatedBy string
	// CreatedByAccountID and CreatedByHuman snapshot the minter at mint, so the
	// initial tags are written as that Account's act.
	CreatedByAccountID string
	CreatedByHuman     bool
}

// MintedBy is the Account that minted a token, as recorded at mint: the Account
// whose act the token's initial tags are written as. Human is false for a
// machine Account and for a minter that was never recorded, the restrictive
// answer.
type MintedBy struct {
	AccountID string
	Account   string
	Role      string
	Human     bool
}

// minter rebuilds who minted t from its stored snapshot. An Account name cannot
// contain ':' (accounts.ValidateName), so the first ':' of CreatedBy splits name
// from role.
func (t Token) minter() MintedBy {
	name, role, _ := strings.Cut(t.CreatedBy, ":")
	return MintedBy{AccountID: t.CreatedByAccountID, Account: name, Role: role, Human: t.CreatedByHuman}
}

// Grant is what a successful Validate hands enrollment: the initial tags to
// write on the joining Node, and the Account that minted the token, whose act
// the write is.
type Grant struct {
	InitialTags []string
	MintedBy    MintedBy
}

// Unlimited reports whether the token has no use limit (stored MaxUses <= 0).
func (t *Token) Unlimited() bool { return t.MaxUses <= 0 }

// LogValue implements slog.LogValuer. It returns a structured group that deliberately
// omits SecretHash so that logging a Token via slog never emits the hash. The
// plaintext secret is never stored on Token, so it is structurally unloggable.
func (t *Token) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", t.ID),
		slog.Any("initial_tags", t.InitialTags),
		slog.Time("expires_at", t.ExpiresAt),
		slog.Bool("revoked", t.Revoked),
		slog.Int("uses", t.Uses),
		slog.Int("max_uses", t.MaxUses),
		slog.String("created_by", t.CreatedBy),
		slog.Bool("created_by_human", t.CreatedByHuman),
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
	maxUses            int
	createdBy          string
	createdByAccountID string
	createdByHuman     bool
}

// Option configures a single Enrollment Token at Create time.
type Option func(*createOpts)

// WithMaxUses sets the maximum number of successful Validate calls allowed for the
// token. Values <= 0 leave it unlimited, which is Create's storage default; a mint
// has no default and names its limit through Minter.Mint (EN-31).
func WithMaxUses(n int) Option {
	return func(o *createOpts) {
		if n > 0 {
			o.maxUses = n
		}
	}
}

// withUseLimit sets the stored use limit unconditionally. Only Minter.Mint uses it,
// after UseLimit.resolve has validated n.
func withUseLimit(n int) Option {
	return func(o *createOpts) { o.maxUses = n }
}

// WithCreatedBy records the principal who minted the token (audit trail). It
// leaves the minter not human, so a token minted this way names no initial tag;
// use WithMinter when the minter is an Account.
func WithCreatedBy(s string) Option {
	return func(o *createOpts) { o.createdBy = s }
}

// MintingAccount is the Account minting a token, as the capability layer's
// Principal presents it. Whether it is human is read from the Account here, so
// no adapter passes the answer in as a bare flag.
type MintingAccount interface {
	Attribution() string
	Human() bool
}

// WithMinter records the Account that minted the token: its ID, its attribution
// ("name:role") and whether it is human.
func WithMinter(accountID string, a MintingAccount) Option {
	return func(o *createOpts) {
		o.createdBy = a.Attribution()
		o.createdByAccountID = accountID
		o.createdByHuman = a.Human()
	}
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

// splitScopeEntry decomposes a legacy scope entry into its bare relay-space key
// and value. Callers must have established the relay: prefix first.
func splitScopeEntry(entry string) (key, value string) {
	bare := strings.TrimPrefix(entry, scopePrefix)
	key, value, _ = strings.Cut(bare, "=")
	return key, value
}

// validateLegacyScope returns ErrInvalidScope if any entry of a legacy scope is
// not "relay:"-prefixed with a well-formed bare key/value pair
// (registry.WellFormedLabel). An empty scope is valid: new tokens carry none.
func validateLegacyScope(scope []string) error {
	for _, e := range scope {
		if !strings.HasPrefix(e, scopePrefix) {
			return fmt.Errorf("%w (offending entry: %q)", ErrInvalidScope, e)
		}
		key, value := splitScopeEntry(e)
		if !registry.WellFormedLabel(key, value) {
			return fmt.Errorf("%w (offending entry: %q)", ErrInvalidScope, e)
		}
	}
	return nil
}

// Create mints a new Enrollment Token naming the given initial tags, each in
// written form tag:key=value, with the given TTL. It returns the Token record
// (suitable for storage) and the plaintext credential string, which is of the
// form id + secretSep + secret. The plaintext is returned exactly once and is
// never persisted or stored on the Token.
//
// The tags are parsed before the minter is looked at, so a relay: label is
// refused naming the label whoever mints (EN-35), and the rule that only a human
// Account names an initial tag (EN-44) runs on well-formed tags only. A mint
// naming no tag is unaffected by it.
//
// Create is the storage step and applies no use-limit rule; every mint goes through
// Minter.Mint, which requires the limit to be named (EN-31).
func (s *Service) Create(ctx context.Context, initialTags []string, ttl time.Duration, opts ...Option) (*Token, string, error) {
	if ttl <= 0 {
		return nil, "", ErrInvalidTTL
	}

	o := &createOpts{}
	for _, fn := range opts {
		fn(o)
	}
	if _, err := registry.ParseInitialTags(initialTags); err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrInvalidInitialTags, err)
	}
	if len(initialTags) > 0 && !o.createdByHuman {
		return nil, "", ErrInitialTagsNeedHuman
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
		ID:                 id,
		SecretHash:         hashArr[:],
		InitialTags:        append([]string{}, initialTags...),
		ExpiresAt:          now.Add(ttl),
		MaxUses:            o.maxUses,
		CreatedAt:          now,
		CreatedBy:          o.createdBy,
		CreatedByAccountID: o.createdByAccountID,
		CreatedByHuman:     o.createdByHuman,
	}

	if err := s.repo.Create(ctx, t); err != nil {
		return nil, "", err
	}

	plaintext := id + secretSep + secret
	return t, plaintext, nil
}

// Validate checks a presented credential string. On success it returns the
// token's Grant (defensive copies) and increments the use count. Errors:
//   - ErrInvalidToken: malformed credential, unknown id, or wrong secret
//     (collapsed into one error to avoid an existence/state oracle).
//   - ErrRevoked, ErrExpired, ErrExhausted, ErrInvalidScope,
//     ErrInvalidInitialTags: state errors, disclosed only after the secret is
//     verified (so a party without the secret learns nothing about state).
func (s *Service) Validate(ctx context.Context, presented string) (Grant, error) {
	return s.validate(ctx, presented, nil)
}

// validate is Validate with a refusal hook. check, when non-nil, sees the
// Grant after every stored-state rule has held and before the use is counted,
// so a refusal it returns burns no use. The Server passes the decision on a
// token's initial tags through it.
func (s *Service) validate(ctx context.Context, presented string, check func(context.Context, Grant) error) (Grant, error) {
	// mu makes the read→check→increment sequence atomic so MaxUses is never exceeded.
	s.mu.Lock()
	defer s.mu.Unlock()

	parts := strings.SplitN(presented, secretSep, 2)
	if len(parts) != 2 {
		return Grant{}, ErrInvalidToken
	}
	id, secretPart := parts[0], parts[1]

	t, err := s.repo.ByID(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return Grant{}, ErrInvalidToken // do not disclose whether the id exists
	}
	if err != nil {
		return Grant{}, err
	}

	// Verify the secret BEFORE disclosing any token state. A party without the correct
	// secret must not learn whether the token is revoked, expired, or exhausted.
	presented256 := sha256.Sum256([]byte(secretPart))
	if subtle.ConstantTimeCompare(presented256[:], t.SecretHash) != 1 {
		return Grant{}, ErrInvalidToken
	}

	if t.Revoked {
		return Grant{}, ErrRevoked
	}
	if s.now().After(t.ExpiresAt) {
		return Grant{}, ErrExpired
	}
	if !t.Unlimited() && t.Uses >= t.MaxUses {
		return Grant{}, ErrExhausted
	}

	// Re-validate what the token STORES, not just what Create checked at mint
	// time: a token minted before this release may carry a malformed legacy
	// scope, and a stored token whose initial tags no longer hold, or whose
	// minter is not human, must not write them on every Node it enrolls. These
	// sit BEFORE the Uses increment below so a refusal never burns a use. They
	// are safe for the no-oracle property the same way Revoked, Expired and
	// Exhausted are: they fire only after the secret is verified, and the
	// handler collapses them into the identical wire rejection.
	if err := validateLegacyScope(t.LegacyScope); err != nil {
		return Grant{}, err
	}
	if _, err := registry.ParseInitialTags(t.InitialTags); err != nil {
		return Grant{}, fmt.Errorf("%w: %w", ErrInvalidInitialTags, err)
	}
	if len(t.InitialTags) > 0 && !t.CreatedByHuman {
		return Grant{}, fmt.Errorf("%w: %w", ErrInvalidInitialTags, ErrInitialTagsNeedHuman)
	}

	grant := Grant{InitialTags: append([]string(nil), t.InitialTags...), MintedBy: t.minter()}
	if check != nil {
		if err := check(ctx, grant); err != nil {
			return Grant{}, err
		}
	}

	t.Uses++
	if err := s.repo.Save(ctx, t); err != nil {
		return Grant{}, err
	}

	return grant, nil
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

// IsRevoked reports whether the token with the given id is currently revoked.
// An unknown id returns (false, nil): a token that never existed cannot have
// minted the Node under revocation, so it is treated as not-revoked. Any other
// repository error is returned to the caller, which must fail closed.
//
// Note: this takes the exclusive mutex (matching the existing Validate/Revoke
// precedent) rather than a read lock. A future persistent store must not
// silently inherit this serialization — revisit when adding persistence.
func (s *Service) IsRevoked(ctx context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, err := s.repo.ByID(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return t.Revoked, nil
}
