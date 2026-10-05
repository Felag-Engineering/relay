package accounts

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// password.go is the Console's local password credential (#418, spec
// docs/design/console/12-login.md).
//
// # Why the Relay holds password hashes at all
//
// ADR-0009 (revised 2026-07-02) accepted this deliberately: local
// username/password is the BASELINE so a small fleet without an IdP can use
// the Console, and OIDC is an additional method rather than a replacement.
// The cost — this process now holds material worth cracking — is paid down
// here, in the choice of KDF and in the fact that a hash never leaves this
// package as a loggable value.
//
// # Why a separate credential kind from an API Token
//
// An API Token (tokens.go) is a high-entropy secret the Relay generated, so a
// SHA-256 of it is enough: there is no dictionary to run against 256 bits of
// randomness. A password is human-chosen and low-entropy, so it needs a
// memory-hard KDF instead. Same table of Accounts, deliberately different
// storage: using one scheme for both would either waste work on tokens or
// leave passwords under-protected, and the second mistake is the one that
// matters.

// Argon2id parameters. These follow the OWASP Password Storage Cheat Sheet's
// argon2id recommendation (m=19 MiB, t=2, p=1), which is the configuration
// chosen to be defensible on a server that is also doing other work.
//
// They are compiled-in constants and NOT Relay configuration. Invariant 11
// keeps the Control API away from Relay config; this goes one further and
// keeps it away from an operator too, because a KDF cost that any surface can
// lower is a KDF cost an attacker who reaches that surface has already
// lowered. Changing these is a code change and a migration question, which is
// the review this decision deserves.
//
// They are also recorded in every encoded hash (see PasswordHash), so raising
// them later re-verifies existing credentials at their original cost rather
// than locking every operator out.
const (
	argonMemoryKiB uint32 = 19 * 1024
	argonTime      uint32 = 2
	argonThreads   uint8  = 1
	argonSaltBytes        = 16
	argonKeyBytes  uint32 = 32
)

// MinPasswordBytes is the shortest local password the Relay will set.
//
// Above NIST SP 800-63B's floor of 8 because of what this credential reaches:
// a Console session is the front half of a fleet-execution surface (ADR-0026),
// and the throttle in front of it (spec 12) deliberately has NO hard lockout,
// so an attacker gets slow, unlimited attempts. Length is what makes that
// safe.
const MinPasswordBytes = 12

// MaxPasswordBytes bounds what is fed to the KDF.
//
// Not a complexity rule — long passphrases are the good case and 4 KiB is far
// beyond any of them. It exists because argon2 work is attacker-controllable
// through input length otherwise, and an unauthenticated route that lets a
// caller choose how much memory-hard work the Relay does is a denial-of-
// service primitive (the same lesson as audit.MaxAssertedFieldBytes).
const MaxPasswordBytes = 4096

var (
	// ErrPasswordTooShort / ErrPasswordTooLong are returned when SETTING a
	// password. They are never returned from a login: a failed sign-in has
	// exactly one error (see Verify), because distinguishing "too short to be
	// real" from "wrong" is an oracle.
	ErrPasswordTooShort = errors.New("accounts: password shorter than the minimum")
	ErrPasswordTooLong  = errors.New("accounts: password longer than the maximum")

	// ErrNoPassword means the Account exists but has no local password set —
	// a machine Account, or a human who signs in through OIDC only.
	ErrNoPassword = errors.New("accounts: account has no local password")

	// ErrPasswordHashMalformed means a stored hash could not be parsed. It is
	// a fail-closed read error, never a login outcome: a corrupt row must
	// refuse the sign-in rather than be treated as "no password set", which
	// would turn database damage into an authentication bypass.
	ErrPasswordHashMalformed = errors.New("accounts: stored password hash is malformed")
)

const redactedPassword = "[REDACTED password]"

// Password is a plaintext password in transit — from a login form to Verify,
// or from an admin-set to HashPassword. It exists for one reason: to make the
// plaintext impossible to log by accident.
//
// Every stringifying interface the standard library and slog reach for is
// implemented to return a constant, so a `slog.Any("form", v)`, a `%v`, or a
// JSON encode of a struct containing one cannot spill the secret. Reveal is
// the single, greppable way out (mirrors Plaintext in tokens.go).
type Password struct{ secret string }

// NewPassword wraps a plaintext password.
func NewPassword(secret string) Password { return Password{secret: secret} }

// Reveal returns the plaintext. The only way out of the type, so `grep
// -rn '\.Reveal()'` enumerates every place a password is in the clear.
func (p Password) Reveal() string { return p.secret }

// IsZero reports whether no password was supplied at all.
func (p Password) IsZero() bool { return p.secret == "" }

func (p Password) String() string               { return redactedPassword }
func (p Password) GoString() string             { return redactedPassword }
func (p Password) LogValue() slog.Value         { return slog.StringValue(redactedPassword) }
func (p Password) MarshalJSON() ([]byte, error) { return json.Marshal(redactedPassword) }

// Validate checks a password against the length bounds. Call it when SETTING
// a password; never on the login path.
func (p Password) Validate() error {
	switch {
	case len(p.secret) < MinPasswordBytes:
		return ErrPasswordTooShort
	case len(p.secret) > MaxPasswordBytes:
		return ErrPasswordTooLong
	}
	return nil
}

const redactedHash = "[REDACTED password hash]"

// PasswordHash is a stored password verifier in PHC string format:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<b64 salt>$<b64 key>
//
// The parameters travel WITH the hash rather than being read from the
// constants above at verification time. That is what makes raising the cost a
// safe change: an old credential still verifies at the cost it was created
// with, and can be re-hashed at the new one on the next successful sign-in,
// instead of every operator being locked out by a constant edit.
//
// It redacts under every stringifying interface for the same reason Password
// does. A hash is not a credential, but it IS the input to an offline attack,
// and an audit trail or a crash dump is a poor place to publish one.
type PasswordHash struct{ encoded string }

// Encoded returns the PHC string for storage. Named so that the store's write
// is the one obvious place a hash leaves this package.
func (h PasswordHash) Encoded() string { return h.encoded }

// IsZero reports whether h holds no hash at all.
func (h PasswordHash) IsZero() bool { return h.encoded == "" }

func (h PasswordHash) String() string               { return redactedHash }
func (h PasswordHash) GoString() string             { return redactedHash }
func (h PasswordHash) LogValue() slog.Value         { return slog.StringValue(redactedHash) }
func (h PasswordHash) MarshalJSON() ([]byte, error) { return json.Marshal(redactedHash) }

// HashPassword validates p and derives a new verifier with a fresh random
// salt.
func HashPassword(p Password) (PasswordHash, error) {
	if err := p.Validate(); err != nil {
		return PasswordHash{}, err
	}
	salt := make([]byte, argonSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return PasswordHash{}, fmt.Errorf("accounts: generate password salt: %w", err)
	}
	return PasswordHash{encoded: encodeArgon2id(argonParams{
		memoryKiB: argonMemoryKiB,
		time:      argonTime,
		threads:   argonThreads,
	}, salt, p.Reveal())}, nil
}

// ParsePasswordHash reads a stored PHC string back into a PasswordHash,
// rejecting anything it cannot verify against.
//
// The parse happens on the READ path, not lazily inside Verify, so that a
// corrupt or truncated row surfaces as ErrPasswordHashMalformed — an error the
// login handler turns into a refusal — rather than as a silent `false` that
// looks exactly like a wrong password to whoever is reading the audit trail.
func ParsePasswordHash(encoded string) (PasswordHash, error) {
	if _, _, _, err := decodeArgon2id(encoded); err != nil {
		return PasswordHash{}, err
	}
	return PasswordHash{encoded: encoded}, nil
}

// Verify reports whether p is the password h was derived from.
//
// It returns a bool and not an error on purpose: at the login boundary there
// is exactly one failure — "that did not work" — and a function that could
// return several would eventually have them told apart by a caller, which is
// the enumeration oracle spec 12 forbids. A malformed hash is caught at
// ParsePasswordHash instead, on the read path.
func (h PasswordHash) Verify(p Password) bool {
	params, salt, want, err := decodeArgon2id(h.encoded)
	if err != nil {
		return false
	}
	// Bound the work an attacker can ask for even here: a caller who could
	// post a 10 MiB "password" would otherwise choose the Relay's CPU cost.
	if len(p.secret) > MaxPasswordBytes {
		return false
	}
	got := argon2.IDKey([]byte(p.secret), salt, params.time, params.memoryKiB, params.threads, uint32(len(want))) //nolint:gosec // G115: the length of a decoded argon2id hash, a few dozen bytes
	return subtle.ConstantTimeCompare(got, want) == 1
}

// VerifyNothing performs one full argon2id derivation and discards it.
//
// This is the no-user-enumeration control (spec 12: "a wrong username and a
// wrong password produce the same message and the same response time"). A
// login for an unknown Account, or for one with no local password, must still
// pay for a KDF run — otherwise the response time alone tells an attacker
// which usernames exist, and no amount of identical error text hides it.
//
// The dummy verifier is derived once from random material at first use, and
// [WarmPasswordVerifier] exists so that "first use" is process startup rather
// than the first unknown username — which would itself be a timing signal.
func VerifyNothing(p Password) {
	_ = dummyHash().Verify(p)
}

// dummyHash is the verifier VerifyNothing burns time against. Random secret,
// never stored, never comparable to anything.
var dummyHash = sync.OnceValue(func() PasswordHash {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		// A process whose CSPRNG is unavailable cannot mint tokens, issue
		// certificates, or generate session identifiers either. Failing here
		// is honest; carrying on with a predictable dummy is not.
		panic("accounts: cannot read random bytes for the password timing verifier: " + err.Error())
	}
	h, err := HashPassword(NewPassword(base64.RawStdEncoding.EncodeToString(raw)))
	if err != nil {
		panic("accounts: cannot build the password timing verifier: " + err.Error())
	}
	return h
})

// WarmPasswordVerifier precomputes the dummy verifier. Call it at startup: it
// costs one argon2id derivation and it is what keeps the FIRST unknown-username
// login from being measurably slower than the rest.
func WarmPasswordVerifier() { _ = dummyHash() }

// argonParams are the cost parameters carried in an encoded hash.
type argonParams struct {
	memoryKiB uint32
	time      uint32
	threads   uint8
}

// encodeArgon2id derives a key and renders it in PHC string format.
func encodeArgon2id(params argonParams, salt []byte, secret string) string {
	key := argon2.IDKey([]byte(secret), salt, params.time, params.memoryKiB, params.threads, argonKeyBytes)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, params.memoryKiB, params.time, params.threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

// decodeArgon2id parses a PHC string into its parameters, salt and key.
//
// Strict on every field, including the algorithm name and the argon2 version:
// this parser sits on the authentication path, and "accept what looks close
// enough" is how a verifier ends up comparing against something that was never
// argon2id at all.
func decodeArgon2id(encoded string) (argonParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	// A well-formed PHC string starts with an empty segment (it opens with
	// '$'), giving six segments in total.
	if len(parts) != 6 || parts[0] != "" {
		return argonParams{}, nil, nil, ErrPasswordHashMalformed
	}
	if parts[1] != "argon2id" {
		return argonParams{}, nil, nil, ErrPasswordHashMalformed
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return argonParams{}, nil, nil, ErrPasswordHashMalformed
	}

	var params argonParams
	var threads int
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.memoryKiB, &params.time, &threads); err != nil {
		return argonParams{}, nil, nil, ErrPasswordHashMalformed
	}
	// Refuse degenerate costs outright. A hash claiming m=1,t=1 verifies
	// almost instantly, so a caller who could write one into the store would
	// have turned the KDF off; rejecting it here means database tampering
	// fails closed instead of downgrading the algorithm.
	if params.memoryKiB < 8*1024 || params.time < 1 || threads < 1 || threads > 255 {
		return argonParams{}, nil, nil, ErrPasswordHashMalformed
	}
	params.threads = uint8(threads)

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < argonSaltBytes {
		return argonParams{}, nil, nil, ErrPasswordHashMalformed
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) < 16 {
		return argonParams{}, nil, nil, ErrPasswordHashMalformed
	}
	return params, salt, key, nil
}

// PasswordRepository persists local password credentials, keyed by Account ID.
//
// Deliberately a separate seam from [Repository] rather than a field on
// Account. Two reasons, both about blast radius:
//
//   - Account values are read on every authenticated request and rendered by
//     three surfaces. A hash that rode along on the struct would eventually be
//     serialised into an API response or a Console template by someone adding
//     a field list, and nothing in the type system would stop them. A hash you
//     have to ask a different repository for is a hash you cannot leak by
//     accident.
//   - The set of components that may READ a hash is exactly one (the Console's
//     login service). Keeping it off Repository means every other holder of an
//     accounts.Repository — the Control API, the authenticator, the token
//     service — structurally cannot reach it.
type PasswordRepository interface {
	// SetPassword stores h as accountID's local password, replacing any
	// existing one. Returns ErrNotFound if the Account does not exist.
	SetPassword(ctx context.Context, accountID string, h PasswordHash) error

	// GetPassword returns accountID's stored password hash, or ErrNoPassword
	// if the Account has none (a machine Account, or an OIDC-only human).
	//
	// ErrNoPassword and ErrNotFound are distinct here, at the repository — and
	// the login path collapses them into one indistinguishable refusal, which
	// is where that decision belongs.
	GetPassword(ctx context.Context, accountID string) (PasswordHash, error)

	// ClearPassword removes accountID's local password. Removing a credential
	// is not the same act as disabling the Account (Account.Enabled), and the
	// two are kept separate for the same reason revoking a token is not
	// disabling its Account.
	ClearPassword(ctx context.Context, accountID string) error
}
