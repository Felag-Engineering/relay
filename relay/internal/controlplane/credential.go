// Package controlplane is the Relay's control-plane HTTP surface: MCP (#117) and
// the Control API (#116) mount onto the one *Server this package exposes, behind
// a single shared bearer-auth Middleware. This is the only control path — never
// build a parallel one (ADR-0009/0010, CLAUDE.md invariant 10).
//
// The seeded admin credential (ADR-0010) authenticates every request on this
// listener. Its plaintext lives only in the operator's vault; the Relay stores
// and compares only a SHA-256 hash, and the plaintext is never logged, echoed
// in an error, or otherwise persisted.
package controlplane

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// ErrMalformedCredentialHash is returned when a credential hash string does not
// match the canonical "sha256:<64 lowercase hex>" form. It deliberately never
// embeds the offending input, so a caller cannot leak a near-miss secret by
// logging or displaying the error.
var ErrMalformedCredentialHash = errors.New("controlplane: malformed control credential hash")

// hashPattern matches the canonical credential-hash encoding: "sha256:" followed
// by exactly 64 lowercase hex characters (a SHA-256 digest).
var hashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ParseCredentialHash parses the canonical "sha256:<64 lowercase hex>" encoding
// of a control-plane credential hash and returns the decoded 32-byte digest.
// Leading/trailing whitespace in s is trimmed before validation. On any
// malformation ParseCredentialHash returns ErrMalformedCredentialHash; the
// error never embeds s, so a malformed hash — which may be a near-miss of a
// real secret — is never echoed back to a log or an operator's terminal.
func ParseCredentialHash(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if !hashPattern.MatchString(s) {
		return nil, ErrMalformedCredentialHash
	}

	digest, err := hex.DecodeString(s[len("sha256:"):])
	if err != nil {
		// hashPattern already guarantees this succeeds; kept defensive rather
		// than assumed unreachable.
		return nil, ErrMalformedCredentialHash
	}
	return digest, nil
}

// LoadCredentialHashFile reads the control-plane credential hash from the
// root-owned file at path and parses it with ParseCredentialHash. Both a
// missing/unreadable file and malformed contents error generically: the
// returned error never echoes the file's contents, and names only path (a
// filesystem location, not a secret) for operator diagnosis.
func LoadCredentialHashFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("controlplane: cannot read control credential hash file %s: %w", path, err)
	}
	digest, err := ParseCredentialHash(string(raw))
	if err != nil {
		return nil, fmt.Errorf("controlplane: %s: %w", path, ErrMalformedCredentialHash)
	}
	return digest, nil
}
