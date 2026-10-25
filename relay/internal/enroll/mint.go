package enroll

// The Minter is the capability that issues enrollment material: a minted Enrollment
// Token and the join string that carries it (ADR-0031). Adapters pass its result
// through and never assemble it (invariant 10).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"time"
)

// Minter and address errors. Each message is constant.
var (
	ErrMinterNoTokens       = errors.New("enroll: minter: no token service")
	ErrMinterFingerprint    = errors.New("enroll: minter: CA fingerprint is not 64 hex characters")
	ErrMinterAddress        = errors.New("enroll: minter: advertised address is not host:port")
	ErrAdvertisedListenAddr = errors.New("enroll: advertised address: listen address has no port")
	ErrAdvertisedHostname   = errors.New("enroll: advertised address: no certificate hostname to advertise")
	ErrMintJoinString       = errors.New("enroll: mint: could not encode the join string")
)

// Use-limit errors. ErrInvalidUseLimit is the parent every refusal wraps. Each
// message is constant.
var (
	ErrInvalidUseLimit  = errors.New("enroll: invalid use limit")
	ErrUseLimitMissing  = fmt.Errorf("%w: name a positive max_uses, or set unlimited to true", ErrInvalidUseLimit)
	ErrUseLimitConflict = fmt.Errorf("%w: a positive max_uses and unlimited are exclusive; name one", ErrInvalidUseLimit)
	ErrUseLimitNegative = fmt.Errorf("%w: max_uses must be positive", ErrInvalidUseLimit)
)

// UseLimit is how a mint names its use limit: a positive MaxUses, or Unlimited set
// explicitly (EN-31, ADR-0031). The zero value names neither and is refused.
type UseLimit struct {
	MaxUses   int
	Unlimited bool
}

// resolve returns the MaxUses to store: n for a limited token, 0 for an unlimited
// one. A negative MaxUses is checked first so it is never read as unlimited.
func (l UseLimit) resolve() (int, error) {
	switch {
	case l.MaxUses < 0:
		return 0, ErrUseLimitNegative
	case l.MaxUses > 0 && l.Unlimited:
		return 0, ErrUseLimitConflict
	case l.MaxUses > 0:
		return l.MaxUses, nil
	case l.Unlimited:
		return 0, nil
	default:
		return 0, ErrUseLimitMissing
	}
}

// FingerprintSource reports the SHA-256 over the Relay CA certificate's DER as
// lowercase hex. *ca.CA satisfies it.
type FingerprintSource interface {
	Fingerprint() string
}

// AdvertisedAddress is the node-plane address a join string tells Nodes to dial.
// A configured value is returned unchanged. Unset, it is the certificate hostname
// plus the port of the node-plane listen address; the listen host (0.0.0.0, [::],
// empty) is dropped because it is not an address a Node can dial.
func AdvertisedAddress(configured, certHostname, listenAddr string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil || port == "" {
		return "", ErrAdvertisedListenAddr
	}
	if certHostname == "" {
		return "", ErrAdvertisedHostname
	}
	return net.JoinHostPort(certHostname, port), nil
}

// Minted is the result of minting: the stored Token record, the plaintext
// credential and the join string carrying it. The plaintext and join string are
// held behind pointers and the type owns every fmt verb, so neither fmt, slog nor
// encoding/json can reach them, including when a Minted sits in an unexported field.
type Minted struct {
	token      *Token
	plaintext  *string
	joinString *string
}

// Token is the stored record. It never holds the plaintext.
func (m Minted) Token() *Token { return m.token }

// Plaintext is the Enrollment Token credential. Handle it as a secret.
func (m Minted) Plaintext() string {
	if m.plaintext == nil {
		return ""
	}
	return *m.plaintext
}

// JoinString is the text form of the join string. Handle it as a secret.
func (m Minted) JoinString() string {
	if m.joinString == nil {
		return ""
	}
	return *m.joinString
}

func (m Minted) id() string {
	if m.token == nil {
		return ""
	}
	return m.token.ID
}

// String renders only the token id.
func (m Minted) String() string {
	return "Minted{token_id=" + m.id() + " token=[REDACTED] join_string=[REDACTED]}"
}

// GoString renders the same redacted text for %#v.
func (m Minted) GoString() string { return m.String() }

// Format owns every verb, as JoinString.Format does.
func (m Minted) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(m.String())) }

// LogValue implements slog.LogValuer. The group carries only the token id.
func (m Minted) LogValue() slog.Value {
	return slog.GroupValue(slog.String("token_id", m.id()))
}

// MarshalJSON renders only the token id, so a Minted that reaches encoding/json
// cannot carry a secret.
func (m Minted) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		TokenID string `json:"token_id"`
	}{m.id()})
}

// Minter mints Enrollment Tokens and assembles their join strings.
type Minter struct {
	tokens        *Service
	relayAddress  string
	caFingerprint [sha256.Size]byte
}

// NewMinter builds a Minter over tokens. The CA fingerprint is read once, from the
// one digest implementation in the CA, and advertisedAddress must be a host:port.
func NewMinter(tokens *Service, ca FingerprintSource, advertisedAddress string) (*Minter, error) {
	if tokens == nil {
		return nil, ErrMinterNoTokens
	}
	raw, err := hex.DecodeString(ca.Fingerprint())
	if err != nil || len(raw) != sha256.Size {
		return nil, ErrMinterFingerprint
	}
	host, port, err := net.SplitHostPort(advertisedAddress)
	if err != nil || host == "" || port == "" {
		return nil, ErrMinterAddress
	}
	m := &Minter{tokens: tokens, relayAddress: advertisedAddress}
	copy(m.caFingerprint[:], raw)
	return m, nil
}

// Mint creates an Enrollment Token and returns it with its join string. The use
// limit must be named (EN-31) and overrides any WithMaxUses in opts. Token errors
// (ErrInvalidScope, ErrInvalidTTL) and use-limit errors (ErrInvalidUseLimit and its
// children) pass through unchanged. A refused mint stores nothing. Mint logs nothing.
func (m *Minter) Mint(ctx context.Context, scope []string, ttl time.Duration, limit UseLimit, opts ...Option) (Minted, error) {
	maxUses, err := limit.resolve()
	if err != nil {
		return Minted{}, err
	}
	tok, plaintext, err := m.tokens.Create(ctx, scope, ttl, slices.Concat(opts, []Option{withUseLimit(maxUses)})...)
	if err != nil {
		return Minted{}, err
	}
	joinString, err := NewJoinString(m.relayAddress, m.caFingerprint, plaintext).Encode()
	if err != nil {
		// Nobody holds the plaintext of the stored token, and no audit record will
		// name it, so it is revoked rather than left live until its TTL.
		_ = m.tokens.Revoke(ctx, tok.ID)
		return Minted{}, ErrMintJoinString
	}
	return Minted{token: tok, plaintext: &plaintext, joinString: &joinString}, nil
}
