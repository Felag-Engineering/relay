package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"
)

// TokenPrefix is the identifying prefix every minted API Token carries.
//
// A fixed, recognizable prefix is a security feature, not branding: it is what
// makes a leaked token greppable in a repository, a paste, or a CI log, and it
// is what secret scanners key on. GLOSSARY.md pins it (`glp_`).
const TokenPrefix = "glp_"

var (
	// ErrTokenNotFound is returned when a token does not exist.
	ErrTokenNotFound = errors.New("accounts: api token not found")

	// ErrTokenInvalid is the single error returned for every failed
	// verification — malformed, unknown, revoked, expired, or belonging to a
	// disabled Account.
	//
	// Deliberately indistinguishable: a caller learning *why* their token
	// failed learns whether it was ever real, which turns the auth endpoint
	// into an oracle for token-guessing. The operator's view (via the API,
	// #297) reports the real state; the presenter of a bad token learns
	// nothing.
	ErrTokenInvalid = errors.New("accounts: api token invalid")

	// ErrInvalidTTL is returned when minting with a negative TTL. Zero means
	// no expiry, which is a deliberate, auditable choice rather than an error.
	ErrInvalidTTL = errors.New("accounts: token TTL must not be negative")
)

// Plaintext is a minted token's secret, in the one moment it exists in
// memory. It exists as a distinct type so that the compiler, not reviewer
// discipline, keeps it out of logs and error strings — the Go counterpart of
// the Rust no-`Debug` guarantee pinned in docs/security/secret-handling-audit.md.
//
// String, GoString, LogValue, and MarshalJSON all redact, so every accidental
// path — `fmt.Sprintf("%s"/"%v"/"%#v")`, `slog.Any`, `json.Marshal`, a struct
// embedding it — emits the redaction rather than the secret. Reading the real
// value requires calling [Plaintext.Reveal], which is greppable in review and
// whose permitted call sites are enumerated — not assumed singular — on
// Reveal's own doc comment below, and checked by
// TestPlaintext_RevealCallSitesAreEnumerated.
type Plaintext struct {
	secret string
}

// NewPlaintext wraps a freshly minted secret.
func NewPlaintext(secret string) Plaintext { return Plaintext{secret: secret} }

// Reveal returns the secret. Every call site is a place the plaintext
// escapes, so the permitted ones are enumerated rather than assumed to be
// singular (#653: there were already two — the mint response on each surface
// that mints a credential):
//
//   - relay/internal/controlplane/api/accounts.go — the Control API's mint
//     response (#297).
//   - relay/cmd/relay/bootstrap_token.go — `relay bootstrap-token`'s stdout
//     (#295).
//   - relay/internal/controlplane/console/accounts_write.go — the Console's
//     mint response (#655). It is the one write route on that surface that
//     does not post-redirect-get, precisely so the plaintext never enters a
//     URL.
//
// TestPlaintext_RevealCallSitesAreEnumerated (tokens_test.go) makes this list
// a checked fact rather than a comment a fourth call site could silently
// outdate: a new caller of Reveal() must be added there deliberately, and a
// removed one must be deleted from there, because the check is an EQUALITY in
// both directions.
func (p Plaintext) Reveal() string { return p.secret }

// redacted is what every incidental rendering of a Plaintext produces.
const redacted = "[REDACTED api token]"

// String implements fmt.Stringer with a redaction, so %s and %v are safe.
func (p Plaintext) String() string { return redacted }

// GoString implements fmt.GoStringer with a redaction, so %#v is safe.
func (p Plaintext) GoString() string { return redacted }

// LogValue implements slog.LogValuer with a redaction, so slog.Any is safe.
func (p Plaintext) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalJSON emits the redaction, so a Plaintext embedded in a response
// struct cannot leak by being serialized. The mint response serializes
// Reveal() explicitly instead — an act a reviewer can see.
func (p Plaintext) MarshalJSON() ([]byte, error) { return json.Marshal(redacted) }

// APIToken is the stored form of a token. It holds no plaintext — only the
// SHA-256 hash of the secret — so a token is structurally unrecoverable from
// the store, a dump, or a backup.
//
// A token is a *credential for* an Account, never an identity of its own: it
// carries no role. Authorization reads the Account's role at verification
// time, which is what makes "a token inherits role changes of its Account"
// true by construction rather than by a synchronization step.
type APIToken struct {
	// ID is the public identifier: safe to log, list, and put in a revoke
	// call. It is also the first component of the presented credential.
	ID string

	// AccountID is the Account this token authenticates as.
	AccountID string

	// Name is an operator-facing label ("ci-deploy", "laptop") so a fleet with
	// twenty tokens can be audited and pruned. Not unique.
	Name string

	// SecretHash is the SHA-256 of the secret component. Opaque; never log it.
	SecretHash []byte

	CreatedAt time.Time

	// ExpiresAt is zero for a token that never expires.
	ExpiresAt time.Time

	// LastUsedAt is the most recent successful verification, zero if never
	// used. It is what makes "is this token still in use?" answerable before
	// someone revokes it.
	LastUsedAt time.Time

	// RevokedAt is non-zero once revoked. Revocation is immediate and
	// permanent: there is no un-revoke, because a credential that can be
	// resurrected is not one you can confidently retire.
	RevokedAt time.Time
}

// LogValue implements slog.LogValuer, deliberately omitting SecretHash so that
// logging a token can never emit even the hash (the enroll.Token precedent).
func (t *APIToken) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", t.ID),
		slog.String("account_id", t.AccountID),
		slog.String("name", t.Name),
		slog.Time("created_at", t.CreatedAt),
		slog.Time("expires_at", t.ExpiresAt),
		slog.Bool("revoked", t.Revoked()),
	)
}

// Revoked reports whether the token has been revoked.
func (t *APIToken) Revoked() bool { return !t.RevokedAt.IsZero() }

// Expired reports whether the token is expired at now. A zero ExpiresAt never
// expires.
func (t *APIToken) Expired(now time.Time) bool {
	return !t.ExpiresAt.IsZero() && !now.Before(t.ExpiresAt)
}

// Usable reports whether the token is neither revoked nor expired at now.
// It says nothing about the Account — the verifier checks that separately,
// because a token can be perfectly valid while its Account is disabled.
func (t *APIToken) Usable(now time.Time) bool {
	return !t.Revoked() && !t.Expired(now)
}

// TokenRepository persists API Tokens. Pure persistence: expiry, revocation,
// and Account state are decided by the verifier, not here.
type TokenRepository interface {
	// CreateToken stores a newly minted token.
	CreateToken(ctx context.Context, t APIToken) error

	// TokenByID returns the stored token, or ErrTokenNotFound.
	TokenByID(ctx context.Context, id string) (APIToken, error)

	// TokensByAccount lists an Account's tokens, newest first. Returns the
	// stored form — hashes included — so callers must not serialize it
	// directly to a surface; #297 renders a redacted view.
	TokensByAccount(ctx context.Context, accountID string) ([]APIToken, error)

	// RevokeToken marks a token revoked at the given time. Revoking an
	// already-revoked token is a no-op, not an error: revocation is an
	// assertion about the end state, and an operator racing themselves during
	// an incident should not see a failure.
	RevokeToken(ctx context.Context, id string, at time.Time) error

	// TouchTokenLastUsed records a successful verification. Best-effort: a
	// failure must never fail the request it accompanies.
	TouchTokenLastUsed(ctx context.Context, id string, at time.Time) error
}
