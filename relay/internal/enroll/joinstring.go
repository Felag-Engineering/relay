package enroll

// The join string codec (ADR-0031). The wire form is relay.v1.JoinString. The codec
// never logs or echoes its input, and the value it returns redacts the token.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
)

// JoinStringPrefix opens the text form of a join string.
const JoinStringPrefix = "glp_join_"

const joinStringFormatVersion uint32 = 1

// Join string errors. Each message is constant and never contains the input.
var (
	ErrJoinStringPrefix      = errors.New("enroll: join string: missing glp_join_ prefix")
	ErrJoinStringEncoding    = errors.New("enroll: join string: not unpadded base64url")
	ErrJoinStringMessage     = errors.New("enroll: join string: malformed message")
	ErrJoinStringVersion     = errors.New("enroll: join string: unknown format version")
	ErrJoinStringEmptyField  = errors.New("enroll: join string: empty field")
	ErrJoinStringFingerprint = errors.New("enroll: join string: CA fingerprint is not 32 bytes")
)

// JoinString is a decoded join string. Its fields are unexported so encoding/json
// cannot reach the Enrollment Token. The token is held behind a pointer because fmt
// cannot call Format or String on a JoinString nested in an unexported field of another
// struct and walks its fields instead; a pointer prints as an address, not the secret.
// Compare two values by their accessors, not with ==.
type JoinString struct {
	relayAddress    string
	caFingerprint   [sha256.Size]byte
	enrollmentToken *string
}

// NewJoinString builds a JoinString from its parts.
func NewJoinString(relayAddress string, caFingerprint [sha256.Size]byte, enrollmentToken string) JoinString {
	return JoinString{relayAddress: relayAddress, caFingerprint: caFingerprint, enrollmentToken: &enrollmentToken}
}

// RelayAddress is the host:port the daemon dials to enroll.
func (j JoinString) RelayAddress() string { return j.relayAddress }

// CAFingerprint is the SHA-256 over the Relay CA certificate's DER.
func (j JoinString) CAFingerprint() [sha256.Size]byte { return j.caFingerprint }

// EnrollmentToken is the Enrollment Token plaintext. Handle it as a secret.
func (j JoinString) EnrollmentToken() string {
	if j.enrollmentToken == nil {
		return ""
	}
	return *j.enrollmentToken
}

// String renders the value with the token redacted. The address is quoted so control
// characters in it cannot forge log lines.
func (j JoinString) String() string {
	return "JoinString{relay_address=" + strconv.Quote(j.relayAddress) +
		" ca_fingerprint=" + hex.EncodeToString(j.caFingerprint[:]) +
		" enrollment_token=[REDACTED]}"
}

// GoString renders the same redacted text for %#v.
func (j JoinString) GoString() string { return j.String() }

// Format owns every verb. fmt consults Stringer only for v, s, x, X and q; for other
// verbs it walks the fields and would print the token, so this must not be removed.
func (j JoinString) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(j.String())) }

// LogValue implements slog.LogValuer. The group omits the token.
func (j JoinString) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("relay_address", j.relayAddress),
		slog.String("ca_fingerprint", hex.EncodeToString(j.caFingerprint[:])),
	)
}

func emptyField(name string) error {
	return fmt.Errorf("%w: %s", ErrJoinStringEmptyField, name)
}

// Encode returns the text form: JoinStringPrefix and the unpadded base64url of the
// deterministic serialization of relay.v1.JoinString.
func (j JoinString) Encode() (string, error) {
	if j.relayAddress == "" {
		return "", emptyField("relay_address")
	}
	if j.EnrollmentToken() == "" {
		return "", emptyField("enrollment_token")
	}
	b, err := marshalJoinString(joinStringFormatVersion, j.relayAddress, j.caFingerprint[:], j.EnrollmentToken())
	if err != nil {
		return "", ErrJoinStringMessage
	}
	return JoinStringPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func marshalJoinString(version uint32, addr string, fp []byte, token string) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(&relayv1.JoinString{
		FormatVersion:       version,
		RelayAddress:        addr,
		CaFingerprintSha256: fp,
		EnrollmentToken:     token,
	})
}

func isBase64URLByte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// DecodeJoinString parses the text form. It is strict: anything that is not the
// canonical encoding of a format_version 1 message is refused, with an error that
// names a category and never the input. The checks run in a fixed order that the
// Rust codec mirrors.
func DecodeJoinString(s string) (JoinString, error) {
	if !strings.HasPrefix(s, JoinStringPrefix) {
		return JoinString{}, ErrJoinStringPrefix
	}
	payload := s[len(JoinStringPrefix):]
	// Go's base64 decoder silently skips CR and LF, so the alphabet is checked first.
	for i := 0; i < len(payload); i++ {
		if !isBase64URLByte(payload[i]) {
			return JoinString{}, ErrJoinStringEncoding
		}
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(payload)
	if err != nil {
		return JoinString{}, ErrJoinStringEncoding
	}

	var msg relayv1.JoinString
	if err := proto.Unmarshal(raw, &msg); err != nil {
		return JoinString{}, ErrJoinStringMessage
	}
	// A known field sent with the wrong wire type is stored as unknown here, while
	// the Rust decoder fails the decode. Report it as malformed, before the version.
	if err := refuseKnownFieldsInUnknown(msg.ProtoReflect().GetUnknown()); err != nil {
		return JoinString{}, err
	}
	if msg.GetFormatVersion() != joinStringFormatVersion {
		return JoinString{}, ErrJoinStringVersion
	}
	// Compare against a fresh message built from the four known fields: Go writes
	// unknown fields back on marshal, so re-marshalling msg would accept them.
	canonical, err := marshalJoinString(msg.GetFormatVersion(), msg.GetRelayAddress(),
		msg.GetCaFingerprintSha256(), msg.GetEnrollmentToken())
	if err != nil || !bytes.Equal(canonical, raw) {
		return JoinString{}, ErrJoinStringMessage
	}
	if msg.GetRelayAddress() == "" {
		return JoinString{}, emptyField("relay_address")
	}
	if len(msg.GetCaFingerprintSha256()) == 0 {
		return JoinString{}, emptyField("ca_fingerprint_sha256")
	}
	if msg.GetEnrollmentToken() == "" {
		return JoinString{}, emptyField("enrollment_token")
	}
	if len(msg.GetCaFingerprintSha256()) != sha256.Size {
		return JoinString{}, ErrJoinStringFingerprint
	}
	var fp [sha256.Size]byte
	copy(fp[:], msg.GetCaFingerprintSha256())
	return NewJoinString(msg.GetRelayAddress(), fp, msg.GetEnrollmentToken()), nil
}

// refuseKnownFieldsInUnknown returns ErrJoinStringMessage if unknown holds a field
// numbered 1 to 4.
func refuseKnownFieldsInUnknown(unknown []byte) error {
	for len(unknown) > 0 {
		num, typ, n := protowire.ConsumeTag(unknown)
		if n < 0 {
			return ErrJoinStringMessage
		}
		if num >= 1 && num <= 4 {
			return ErrJoinStringMessage
		}
		m := protowire.ConsumeFieldValue(num, typ, unknown[n:])
		if m < 0 {
			return ErrJoinStringMessage
		}
		unknown = unknown[n+m:]
	}
	return nil
}
