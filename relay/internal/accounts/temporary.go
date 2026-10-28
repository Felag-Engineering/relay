package accounts

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"time"
)

// TemporaryPasswordLifetime is how long a temporary password is accepted. A
// constant, not configuration: the terms on which a credential is accepted
// are not a runtime setting (ADR-0045, "Invariant 11, read").
const TemporaryPasswordLifetime = 72 * time.Hour

// TemporaryPassword is a Relay-generated temporary password and the instant it
// stops being accepted. It redacts under every stringifying interface; the
// plaintext leaves it only through Password.Reveal.
type TemporaryPassword struct {
	Password  Password
	ExpiresAt time.Time
}

func (t TemporaryPassword) String() string {
	return fmt.Sprintf("TemporaryPassword{%s expires_at=%s}", redactedPassword, t.ExpiresAt.UTC().Format(time.RFC3339))
}

func (t TemporaryPassword) GoString() string { return t.String() }

func (t TemporaryPassword) LogValue() slog.Value {
	return slog.GroupValue(slog.Time("expires_at", t.ExpiresAt))
}

// GenerateTemporaryPassword mints a temporary password from the same source as
// an API Token's secret (ADR-0045 decision 1), expiring TemporaryPasswordLifetime
// after now.
func GenerateTemporaryPassword(now time.Time) (TemporaryPassword, error) {
	raw := make([]byte, tokenSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return TemporaryPassword{}, fmt.Errorf("accounts: generate temporary password: %w", err)
	}
	return TemporaryPassword{
		Password:  NewPassword(base64.RawURLEncoding.EncodeToString(raw)),
		ExpiresAt: now.UTC().Add(TemporaryPasswordLifetime),
	}, nil
}

// StoredPassword is a stored verifier with its temporary state (ADR-0045).
type StoredPassword struct {
	Hash PasswordHash
	// TemporaryUntil is the instant a temporary password stops being
	// accepted; the zero time means the human (or relay init) set it.
	TemporaryUntil time.Time
}

// Temporary reports whether the password is a temporary one.
func (s StoredPassword) Temporary() bool { return !s.TemporaryUntil.IsZero() }

// ExpiredAt reports whether the password is a temporary one that is refused
// at now: at and after TemporaryUntil.
func (s StoredPassword) ExpiredAt(now time.Time) bool {
	return s.Temporary() && !now.Before(s.TemporaryUntil)
}

// LogValue emits only whether the password is temporary, never the hash.
func (s StoredPassword) LogValue() slog.Value {
	return slog.GroupValue(slog.Bool("temporary", s.Temporary()))
}

// PasswordStatus is what an admin may know of an Account's password. It has
// no hash field, so a status read cannot leak one.
type PasswordStatus struct {
	// Own is true when a non-temporary password is stored: the human, or
	// relay init, set it.
	Own bool
	// TemporaryUntil is when the live or expired temporary password stops
	// being accepted; zero when none was issued.
	TemporaryUntil time.Time
}

// PasswordStatusReader reads PasswordStatus. It is a seam apart from
// PasswordRepository so its holders structurally cannot reach a hash.
type PasswordStatusReader interface {
	// Status returns ErrNotFound for an unknown Account.
	Status(ctx context.Context, accountID string) (PasswordStatus, error)
}
