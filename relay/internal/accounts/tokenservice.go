package accounts

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Credential layout: TokenPrefix + <id> + "." + <secret>.
//
//	glp_1f3c…a9.g7Kx…_Q
//
// The id is hex and the secret base64url, neither of which contains ".", so
// the split is unambiguous. The id travels in the credential so verification
// is a single indexed lookup rather than a scan over every stored hash — which
// matters because a scan's duration would leak how many tokens exist.
const (
	tokenIDBytes     = 16
	tokenSecretBytes = 32
	credentialSep    = "."
)

// TokenService mints and verifies API Tokens against an Account store.
type TokenService struct {
	tokens   TokenRepository
	accounts Repository
	now      func() time.Time
}

// NewTokenService wires a TokenService. now defaults to time.Now.
func NewTokenService(tokens TokenRepository, accts Repository, now func() time.Time) *TokenService {
	if now == nil {
		now = time.Now
	}
	return &TokenService{tokens: tokens, accounts: accts, now: now}
}

// Mint issues a new token for accountID and returns the stored record plus the
// plaintext credential — **the only moment the plaintext exists**. It is never
// stored, never logged, and cannot be recovered afterwards; an operator who
// loses it mints another and revokes this one.
//
// ttl of 0 means no expiry. A negative ttl is ErrInvalidTTL.
//
// Minting for a disabled Account is refused: a credential for an identity that
// cannot authenticate is a trap that looks like access.
func (s *TokenService) Mint(ctx context.Context, accountID, name string, ttl time.Duration) (APIToken, Plaintext, error) {
	if ttl < 0 {
		return APIToken{}, Plaintext{}, ErrInvalidTTL
	}

	acct, err := s.accounts.Get(ctx, accountID)
	if err != nil {
		return APIToken{}, Plaintext{}, err
	}
	if !acct.Enabled {
		return APIToken{}, Plaintext{}, fmt.Errorf("%w: account is disabled", ErrTokenInvalid)
	}

	tok, plaintext, err := GenerateToken(acct.ID, name, ttl, s.now())
	if err != nil {
		return APIToken{}, Plaintext{}, err
	}

	if err := s.tokens.CreateToken(ctx, tok); err != nil {
		return APIToken{}, Plaintext{}, err
	}

	return tok, plaintext, nil
}

// GenerateToken makes a new API Token for accountID, and its plaintext
// credential, without storing either and without reading the Account. Mint is
// the path every surface takes; this is for the one caller that stores the
// token inside a transaction it opens itself, because the Account it is for is
// created in that same transaction (the first admin, made by `relay init`).
// It skips Mint's existence and enabled checks, so its call sites are
// enumerated by TestGenerateToken_CallSitesAreEnumerated.
//
// ttl of 0 means no expiry. A negative ttl is ErrInvalidTTL.
func GenerateToken(accountID, name string, ttl time.Duration, now time.Time) (APIToken, Plaintext, error) {
	if ttl < 0 {
		return APIToken{}, Plaintext{}, ErrInvalidTTL
	}
	if accountID == "" {
		return APIToken{}, Plaintext{}, errors.New("accounts: a token needs an account id")
	}
	idBytes := make([]byte, tokenIDBytes)
	if _, err := rand.Read(idBytes); err != nil {
		return APIToken{}, Plaintext{}, fmt.Errorf("generate token id: %w", err)
	}
	secretBytes := make([]byte, tokenSecretBytes)
	if _, err := rand.Read(secretBytes); err != nil {
		return APIToken{}, Plaintext{}, fmt.Errorf("generate token secret: %w", err)
	}

	id := hex.EncodeToString(idBytes)
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	sum := sha256.Sum256([]byte(secret))

	tok := APIToken{
		ID:         id,
		AccountID:  accountID,
		Name:       name,
		SecretHash: sum[:],
		CreatedAt:  now,
	}
	if ttl > 0 {
		tok.ExpiresAt = now.Add(ttl)
	}

	return tok, NewPlaintext(TokenPrefix + id + credentialSep + secret), nil
}

// Verify authenticates a presented credential and returns the Account it
// authenticates as.
//
// Every failure — malformed, unknown id, wrong secret, revoked, expired,
// missing or disabled Account — returns the same ErrTokenInvalid. The caller
// cannot tell which, by design (see ErrTokenInvalid).
//
// The Account is read fresh on every call rather than captured at mint time,
// which is what makes "a token inherits role changes of its Account" true by
// construction: there is no cached copy of the role to go stale, and a
// disablement takes effect on the very next request.
func (s *TokenService) Verify(ctx context.Context, credential string) (Account, APIToken, error) {
	id, secret, ok := splitCredential(credential)
	if !ok {
		return Account{}, APIToken{}, ErrTokenInvalid
	}

	tok, err := s.tokens.TokenByID(ctx, id)
	if err != nil {
		// Includes ErrTokenNotFound: an unknown id is indistinguishable from a
		// wrong secret.
		return Account{}, APIToken{}, ErrTokenInvalid
	}

	// Constant-time compare, always performed even for a token we already know
	// is revoked or expired, so verification time does not reveal which check
	// failed.
	presented := sha256.Sum256([]byte(secret))
	secretOK := subtle.ConstantTimeCompare(presented[:], tok.SecretHash) == 1

	now := s.now()
	if !secretOK || !tok.Usable(now) {
		return Account{}, APIToken{}, ErrTokenInvalid
	}

	acct, err := s.accounts.Get(ctx, tok.AccountID)
	if err != nil {
		return Account{}, APIToken{}, ErrTokenInvalid
	}
	if !acct.Enabled {
		return Account{}, APIToken{}, ErrTokenInvalid
	}

	// Best-effort: the caller has authenticated; last-used is advisory.
	_ = s.tokens.TouchTokenLastUsed(ctx, tok.ID, now)
	_ = s.accounts.TouchLastSeen(ctx, acct.ID, now)

	return acct, tok, nil
}

// Revoke cuts a token off immediately and permanently.
func (s *TokenService) Revoke(ctx context.Context, id string) error {
	return s.tokens.RevokeToken(ctx, id, s.now())
}

// List returns an Account's tokens, newest first.
func (s *TokenService) List(ctx context.Context, accountID string) ([]APIToken, error) {
	return s.tokens.TokensByAccount(ctx, accountID)
}

// LooksLikeAPIToken reports whether a presented credential carries the API
// Token prefix.
//
// Used by the auth boundary to route a credential to the right verifier
// without trial-and-error, so a seeded-credential failure is never attributed
// to a token (or vice versa) in logs. It says nothing about validity.
func LooksLikeAPIToken(credential string) bool {
	return strings.HasPrefix(credential, TokenPrefix)
}

// splitCredential parses "glp_<id>.<secret>". ok is false for anything
// malformed; the caller maps that to the same generic failure as a wrong
// secret.
func splitCredential(credential string) (id, secret string, ok bool) {
	rest, found := strings.CutPrefix(credential, TokenPrefix)
	if !found {
		return "", "", false
	}
	id, secret, found = strings.Cut(rest, credentialSep)
	if !found || id == "" || secret == "" {
		return "", "", false
	}
	return id, secret, true
}

// IsInvalidToken reports whether err is the generic token-verification failure.
func IsInvalidToken(err error) bool { return errors.Is(err, ErrTokenInvalid) }
