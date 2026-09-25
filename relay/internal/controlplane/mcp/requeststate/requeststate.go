// Package requeststate seals and opens the MRTR requestState: an opaque
// token an MCP client carries between the moment a mutate call is parked for
// approval and the moment it answers, that the server can trust without
// looking anything up.
//
// # What it binds and why the seal is load-bearing
//
// A sealed state binds a format version, the calling Account's ID, the
// approval Request's ID, the plan hash the approver saw, the tool name, a
// canonical digest of the call's arguments, and an absolute expiry. At
// decision time the seal — the HMAC plus [State.Bind] — is the ONLY thing
// binding an answer to the request it purports to answer: a tampered state, a
// state carried over from another request, another Account, another tool, or
// different arguments is refused by the seal alone, never by a database
// lookup. The plan hash travels inside the seal so the decision can be
// checked against the plan the approver actually saw, by
// approval.Request.Decide's ErrPlanChanged — this package does not compare it
// itself; see [State.Bind]. Spec: docs/specs/approval.md AP-65. Owner
// decisions: ADR-0029 decisions 5 and 6.
//
// # The key is process-lifetime, by construction
//
// A Sealer is keyed with 32 bytes from crypto/rand, minted once for the
// process's lifetime — the same shape as consoleauth's CSRF pepper. There is
// no config key, flag, environment variable or file for it: nothing on the
// wire can reach it, so invariant 11 (the security floor) holds by
// construction rather than by discipline. A restart, or a retry landing on a
// replica with a different key, invalidates every outstanding state; Open
// refuses it with ErrTampered, fail-closed. That cost is accepted, not
// solved, here: docs/specs/approval-assurance.md "Restarts strand an
// in-flight approval" and threat-model R27 record it, with two candidate
// fixes and neither chosen.
//
// # Replay is by design
//
// A seal is deterministic and carries no nonce: sealing the same fields under
// the same key twice produces the same state, and a state opens as many
// times as asked until its sealed expiry passes. Single use is enforced by
// the caller's own controls, not here, in two places: approval.Request.Decide
// refuses a second decision once the Request it names is no longer pending;
// and, for a Request whose required approval count is greater than one —
// where the Request stays pending after a first approval so a replayed state
// still opens — Decide separately refuses a second decision from the same,
// already-verified Account ID (the duplicate-decider check). That check
// relies on Seal having refused to seal a state with an empty AccountID, so
// the identity it compares against always came from a real seal, never a
// zero value.
//
// # Holding a Sealer
//
// Callers obtain a *Sealer from [New] or [Mint] and hold the pointer, never
// a Sealer value kept independently; the zero Sealer is not usable, and Seal
// and Open on one refuse with ErrInvalidKey rather than sealing or opening
// under an empty key. See the Sealer type's doc for precisely what redacts
// the key, and why.
//
// # Import boundary
//
// This package must never import its parent package (mcp), approval, or
// capability: a crypto primitive that seals and opens bytes decides nothing,
// and every decision stays in the one file ADR-0029 decision 5 names.
// imports_test.go pins this.
package requeststate

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
)

// KeyBytes is the length, in bytes, of a Sealer's key.
const KeyBytes = 32

// prefix is the versioned wire prefix on every sealed state. The format
// version is ALSO carried inside the MACed payload (payload.V); the prefix is
// authenticated as part of the MAC input (see macLabel), so neither can
// change independently of the other without Open refusing.
const prefix = "rs1."

// currentVersion is the payload version this package produces and accepts.
const currentVersion = 1

// macLabel domain-separates this package's MAC from any other HMAC-SHA256
// user of the same key, and is followed by a NUL byte so no label is a prefix
// of another. The MAC input is macLabel + prefix + payload bytes, so the
// version prefix is authenticated too: a state cannot be re-prefixed to
// change its declared version without invalidating the MAC.
const macLabel = "relay-requeststate-v1\x00"

// MaxFieldBytes bounds each of the four string fields Seal accepts.
const MaxFieldBytes = 256

// MaxEncodedBytes bounds a sealed state Open will consider, checked before
// any decode or MAC work.
//
// Arithmetic (proven by TestSeal_StaysUnderClientRequestStateLimit, not only
// asserted here): the four string fields are restricted to the byte alphabet
// fieldByteOK accepts, none of which encoding/json escapes, so each field's
// JSON form is exactly its byte length plus two quote bytes. The payload
// marshals as `{"v":1,"a":"...","r":"...","p":"...","t":"...","d":"...","e":...}`;
// worst case:
//
//	1                            "{"
//	+ 5                          "v":1
//	+ 4 x (4 + MaxFieldBytes+2)  "a":"...", "r":"...", "p":"...", "t":"..." = 1048
//	+ 70                         "d":"...", the hex ArgsDigest (64 hex + 2 quotes + `"d":`)
//	+ 24                         "e":..., an int64 with a sign (20 digits) + `"e":`
//	+ 6                          the six commas between the seven fields
//	+ 1                          "}"
//	                                                              body     = 1155
//
// + 32 MAC bytes = 1187. Base64 (RawURLEncoding) expands that to
// ceil(1187*4/3) = 1583, + the 4-byte prefix = 1587 — comfortably under
// MaxEncodedBytes, and far under Gleipnir's 16 KiB requestState limit.
const MaxEncodedBytes = 2048

// macLen is the length, in bytes, of an HMAC-SHA256 tag.
const macLen = sha256.Size

// base64URLByteOK reports whether b is a byte of unpadded base64url
// (RFC 4648 §5): A-Z, a-z, 0-9, '-' or '_'. Open checks every byte of the
// encoded remainder against this before decoding it, because
// base64.Encoding's decoder silently skips CR and LF rather than rejecting
// them (kept, upstream, for compatibility with PEM-wrapped input): without
// this check, "rs1.AB\r\nCD..." decodes to the exact same bytes as the
// canonical "rs1.ABCD...", so the encoded string would not uniquely
// determine the sealed state. TestOpen_RefusesTamperedState proves the
// rejection.
func base64URLByteOK(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		return true
	case b == '-' || b == '_':
		return true
	default:
		return false
	}
}

// Sentinel errors. Every message is prefixed "requeststate: ".
var (
	// ErrOversized is returned when a sealed state exceeds MaxEncodedBytes,
	// before any decode or MAC work is done on it.
	ErrOversized = errors.New("requeststate: state exceeds the size bound")

	// ErrUnknownVersion is returned for a missing or unrecognized version
	// prefix, or a payload whose internal version field does not match
	// currentVersion.
	ErrUnknownVersion = errors.New("requeststate: unknown or missing version")

	// ErrMalformed is returned for a state that is not validly encoded: bad
	// base64, too short to hold a MAC, or (after the MAC has verified) a
	// payload that fails strict JSON decoding.
	ErrMalformed = errors.New("requeststate: malformed state")

	// ErrTampered is returned when the MAC does not verify. A state sealed
	// under a different key — a restart, or a retry landing on another
	// replica — is cryptographically indistinguishable from a tampered one
	// and yields this same sentinel.
	ErrTampered = errors.New("requeststate: tampered or sealed under another key")

	// ErrExpired is returned when now is at or after the state's sealed
	// expiry, and also when now itself is the zero time: a zero now would
	// otherwise never be "before" any real expiry, silently disabling
	// expiry checking, so it is refused instead.
	ErrExpired = errors.New("requeststate: expired")

	// ErrInvalidField is returned by Seal when a field fails validation.
	ErrInvalidField = errors.New("requeststate: invalid field")

	// ErrBindingMismatch is returned by State.Bind when the caller's facts
	// do not match the opened state.
	ErrBindingMismatch = errors.New("requeststate: binding mismatch")

	// ErrInvalidArgs is returned by DigestArgs for input it cannot digest
	// canonically.
	ErrInvalidArgs = errors.New("requeststate: invalid arguments")

	// ErrInvalidKey is returned by New for a key that is not exactly
	// KeyBytes long or is all zero, and by Seal or Open called on a
	// zero-value or nil *Sealer.
	ErrInvalidKey = errors.New("requeststate: invalid key")
)

// Digest is a canonical digest of a call's arguments, produced by DigestArgs.
type Digest [sha256.Size]byte

// State is the set of fields a seal binds.
//
// An empty AccountID is refused by Seal: a Principal with no stored Account
// never has a state sealed for it.
type State struct {
	// AccountID is the calling Account's ID.
	AccountID string

	// RequestID is the parked approval Request's ID.
	RequestID string

	// PlanHash is the plan hash the approver saw. Bind deliberately does not
	// compare it: the caller passes it to approval.Request.Decide, whose
	// ErrPlanChanged enforces it against the plan as decided.
	PlanHash string

	// Tool is the MCP tool name the call names.
	Tool string

	// ArgsDigest is DigestArgs' canonical digest of the call's arguments.
	ArgsDigest Digest

	// ExpiresAt is the parked Request's ExpiresAt, as supplied by the
	// caller when sealing. Open returns it in UTC; compare with Equal.
	ExpiresAt time.Time
}

// Call is the current caller's facts, checked against an opened State by
// Bind. PlanHash is deliberately absent — see State's doc.
type Call struct {
	AccountID  string
	RequestID  string
	Tool       string
	ArgsDigest Digest
}

// Bind reports whether c matches the fields st was sealed with, checking
// AccountID, RequestID, Tool and ArgsDigest in that order and returning on
// the first mismatch. ArgsDigest is compared with ==, which is safe here:
// unlike the seal's MAC, a digest is not a secret an attacker must be denied
// a timing oracle over — it is a public function of the (also visible) call
// arguments.
func (st State) Bind(c Call) error {
	switch {
	case st.AccountID != c.AccountID:
		return fmt.Errorf("%w: account id", ErrBindingMismatch)
	case st.RequestID != c.RequestID:
		return fmt.Errorf("%w: request id", ErrBindingMismatch)
	case st.Tool != c.Tool:
		return fmt.Errorf("%w: tool", ErrBindingMismatch)
	case st.ArgsDigest != c.ArgsDigest:
		return fmt.Errorf("%w: args digest", ErrBindingMismatch)
	}
	return nil
}

// payload is the JSON shape sealed inside the MAC. Short tags keep the
// encoded size down; see MaxEncodedBytes' arithmetic.
type payload struct {
	V int    `json:"v"`
	A string `json:"a"`
	R string `json:"r"`
	P string `json:"p"`
	T string `json:"t"`
	D string `json:"d"`
	E int64  `json:"e"`
}

// equalMAC and computeMAC are the package's only test seams: they exist so
// requeststate_test.go can prove Open's comparison is constant-time
// (equalMAC) and that the size bound is checked before any MAC work
// (computeMAC), without weakening the production path. Only the package-level
// var declarations below may bind them — TestConstantTimeCompare_ASTScan, in
// requeststate_test.go, fails on any assignment to either identifier outside
// a _test.go file.
var (
	equalMAC   = hmac.Equal
	computeMAC = func(key, msg []byte) []byte {
		mac := hmac.New(sha256.New, key)
		mac.Write(msg)
		return mac.Sum(nil)
	}
)

const redactedKey = "requeststate.Sealer{key:REDACTED}"

// Sealer seals and opens request states under one process-lifetime key.
// Construct with New or Mint; callers hold only the returned *Sealer, never
// a dereferenced Sealer value they keep around independently. The zero
// Sealer is not usable: Seal and Open on it refuse with ErrInvalidKey rather
// than operating under an empty key.
//
// The key is held behind a pointer (key *[KeyBytes]byte), not inline as
// key []byte, precisely because that is what redacts: fmt and slog cannot
// invoke a value's String, GoString or LogValue method through an
// unexported struct field — reflect.Value.Interface panics on a value
// reached that way, so fmt falls back to printing the field's raw
// representation. For a []byte key that raw representation is the key
// itself; for a *[KeyBytes]byte it is only a pointer's address. So a Sealer
// value (or a *Sealer) sitting in an unexported field of some other struct —
// exactly the shape reflection-based formatting cannot call methods
// through — never renders the key, under %v, %+v, %#v or slog's
// TextHandler and JSONHandler, whether or not that struct ever sees this
// type's own String/GoString/LogValue.
//
// String, GoString and LogValue are declared on the value receiver too, so
// that a Sealer or *Sealer formatted directly (not reached through another
// struct's unexported field) also redacts explicitly rather than relying on
// the pointer alone.
type Sealer struct {
	key *[KeyBytes]byte
}

func (s Sealer) String() string       { return redactedKey }
func (s Sealer) GoString() string     { return redactedKey }
func (s Sealer) LogValue() slog.Value { return slog.StringValue(redactedKey) }

// usable reports ErrInvalidKey unless s is non-nil and holds a key. Without
// this guard, hmac.New accepts a nil or empty key, so a zero-value Sealer{}
// would silently seal and open under an empty key rather than refusing.
func (s *Sealer) usable() error {
	if s == nil || s.key == nil {
		return ErrInvalidKey
	}
	return nil
}

// NewKey returns KeyBytes bytes of key material from crypto/rand.
func NewKey() ([]byte, error) {
	key := make([]byte, KeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("requeststate: generate key: %w", err)
	}
	return key, nil
}

// New constructs a Sealer from an existing key, which must be exactly
// KeyBytes long and not all zero. It stores a private copy of key, behind a
// pointer — see Sealer's doc for why that indirection is what redacts.
func New(key []byte) (*Sealer, error) {
	if len(key) != KeyBytes || isAllZero(key) {
		return nil, ErrInvalidKey
	}
	var owned [KeyBytes]byte
	copy(owned[:], key)
	return &Sealer{key: &owned}, nil
}

// Mint generates a fresh key with NewKey and constructs a Sealer from it.
// This is the constructor the MCP server uses to obtain a process-lifetime
// Sealer: the key is never persisted or configured.
func Mint() (*Sealer, error) {
	key, err := NewKey()
	if err != nil {
		return nil, err
	}
	return New(key)
}

func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// fieldByteOK reports whether b is allowed in AccountID, RequestID, PlanHash
// or Tool: printable ASCII (0x21..0x7E) excluding double quote, backslash,
// less-than, greater-than and ampersand — the bytes encoding/json escapes
// (the latter three only under its default HTML-escaping). Every real value
// already fits this set: hex request and plan-hash strings, "acct-" plus hex
// Account IDs, and snake_case MCP tool names. Restricting to it makes each
// field's JSON form exactly its byte length plus two quotes, which is what
// makes MaxEncodedBytes' bound closed-form and the round trip exact — an
// escaped byte would need the decoder to unescape it, and invalid UTF-8 or
// U+2028/U+2029 (which encoding/json also escapes) are excluded structurally
// rather than by a separate UTF-8 check.
func fieldByteOK(b byte) bool {
	if b < 0x21 || b > 0x7E {
		return false
	}
	switch b {
	case '"', '\\', '<', '>', '&':
		return false
	}
	return true
}

// validateField reports ErrInvalidField, naming name, unless v is non-empty,
// at most MaxFieldBytes long, and built only from fieldByteOK bytes.
func validateField(name, v string) error {
	if v == "" {
		return fmt.Errorf("%w: %s is empty", ErrInvalidField, name)
	}
	if len(v) > MaxFieldBytes {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalidField, name, MaxFieldBytes)
	}
	for i := 0; i < len(v); i++ {
		if !fieldByteOK(v[i]) {
			return fmt.Errorf("%w: %s contains a disallowed byte", ErrInvalidField, name)
		}
	}
	return nil
}

// unixNanoRoundTrips reports whether t survives a UnixNano-and-back
// conversion unchanged. UnixNano's result is undefined outside roughly the
// years 1678-2262; Seal refuses an ExpiresAt outside that range rather than
// silently sealing a different instant. A parked Request's expiry is minutes
// to days away, so this is never a real limit in practice.
func unixNanoRoundTrips(t time.Time) bool {
	return time.Unix(0, t.UnixNano()).Equal(t)
}

var zeroDigest Digest

// Seal validates st and, if valid, returns an opaque, versioned, MACed
// encoding of it.
func (s *Sealer) Seal(st State) (string, error) {
	if err := s.usable(); err != nil {
		return "", err
	}
	if err := validateField("account id", st.AccountID); err != nil {
		return "", err
	}
	if err := validateField("request id", st.RequestID); err != nil {
		return "", err
	}
	if err := validateField("plan hash", st.PlanHash); err != nil {
		return "", err
	}
	if err := validateField("tool", st.Tool); err != nil {
		return "", err
	}
	if st.ArgsDigest == zeroDigest {
		return "", fmt.Errorf("%w: args digest is zero", ErrInvalidField)
	}
	if st.ExpiresAt.IsZero() {
		return "", fmt.Errorf("%w: expires at is zero", ErrInvalidField)
	}
	if !unixNanoRoundTrips(st.ExpiresAt) {
		return "", fmt.Errorf("%w: expires at is outside the representable range", ErrInvalidField)
	}

	p := payload{
		V: currentVersion,
		A: st.AccountID,
		R: st.RequestID,
		P: st.PlanHash,
		T: st.Tool,
		D: hex.EncodeToString(st.ArgsDigest[:]),
		E: st.ExpiresAt.UnixNano(),
	}
	body, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("requeststate: marshal payload: %w", err)
	}

	mac := computeMAC(s.key[:], append([]byte(macLabel+prefix), body...))

	encoded := make([]byte, 0, len(body)+len(mac))
	encoded = append(encoded, body...)
	encoded = append(encoded, mac...)
	out := prefix + base64.RawURLEncoding.EncodeToString(encoded)
	if len(out) > MaxEncodedBytes {
		// Defensive: unreachable given the field alphabet and MaxFieldBytes,
		// but Seal never emits a state Open would refuse purely on size.
		return "", ErrOversized
	}
	return out, nil
}

// Open validates and decodes state, sealed by Seal under the same key, as of
// now. now must be the caller's current time; a zero now is refused with
// ErrExpired rather than treated as "always valid". Every error path returns
// the zero State.
//
// Open alone does not check that the opened State belongs to the current
// caller, request or call — that is [State.Bind]'s job, and skipping it
// fails open on a cross-account, cross-request, wrong-tool or wrong-args
// state. Open stays exported for callers that need the opened State before
// deciding how to bind it (and for this package's own tests); the answer
// path itself must use [Sealer.OpenFor], which never returns an unbound
// State.
func (s *Sealer) Open(state string, now time.Time) (State, error) {
	if err := s.usable(); err != nil {
		return State{}, err
	}
	if now.IsZero() {
		return State{}, fmt.Errorf("%w: zero now", ErrExpired)
	}
	if len(state) > MaxEncodedBytes {
		return State{}, ErrOversized
	}
	if !strings.HasPrefix(state, prefix) {
		return State{}, ErrUnknownVersion
	}
	rest := strings.TrimPrefix(state, prefix)
	for i := 0; i < len(rest); i++ {
		if !base64URLByteOK(rest[i]) {
			return State{}, fmt.Errorf("%w: invalid character in encoded state", ErrMalformed)
		}
	}

	decoded, err := base64.RawURLEncoding.Strict().DecodeString(rest)
	if err != nil {
		return State{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if len(decoded) <= macLen {
		return State{}, fmt.Errorf("%w: too short to hold a mac", ErrMalformed)
	}

	body := decoded[:len(decoded)-macLen]
	mac := decoded[len(decoded)-macLen:]
	want := computeMAC(s.key[:], append([]byte(macLabel+prefix), body...))
	if !equalMAC(mac, want) {
		return State{}, ErrTampered
	}

	var p payload
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return State{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return State{}, fmt.Errorf("%w: trailing data", ErrMalformed)
	}
	if p.V != currentVersion {
		return State{}, ErrUnknownVersion
	}
	digestBytes, err := hex.DecodeString(p.D)
	if err != nil || len(digestBytes) != len(Digest{}) {
		return State{}, fmt.Errorf("%w: args digest", ErrMalformed)
	}
	var digest Digest
	copy(digest[:], digestBytes)

	exp := time.Unix(0, p.E).UTC()
	if !now.Before(exp) {
		return State{}, ErrExpired
	}

	return State{
		AccountID:  p.A,
		RequestID:  p.R,
		PlanHash:   p.P,
		Tool:       p.T,
		ArgsDigest: digest,
		ExpiresAt:  exp,
	}, nil
}

// OpenFor opens state as of now and binds the result to c, returning the
// zero State on any failure from either step. This is the verifier the
// answer path must use: it cannot be called correctly while forgetting to
// bind, the way a bare Open followed by a separate, skippable Bind call can.
func (s *Sealer) OpenFor(state string, now time.Time, c Call) (State, error) {
	st, err := s.Open(state, now)
	if err != nil {
		return State{}, err
	}
	if err := st.Bind(c); err != nil {
		return State{}, err
	}
	return st, nil
}
