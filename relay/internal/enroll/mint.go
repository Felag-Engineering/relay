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

// Mint creates an Enrollment Token and returns it with its join string. Token
// errors (ErrInvalidScope, ErrInvalidTTL) pass through unchanged. Mint logs nothing.
func (m *Minter) Mint(ctx context.Context, scope []string, ttl time.Duration, opts ...Option) (Minted, error) {
	tok, plaintext, err := m.tokens.Create(ctx, scope, ttl, opts...)
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
