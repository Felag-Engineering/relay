// Package consoleauth is the Console's human authentication lane (specs
// docs/design/console/12-login.md and 11-console-shell.md): local password
// verification, session issuance, and the step-up recent-auth window.
//
// # Why this is not in package console
//
// The Console renders and requests; it never decides (ADR-0009, invariant 10).
// Deciding whether a credential is good is a decision, so it lives here, on the
// far side of a seam the console package reaches through an interface. The
// practical effect is that console's no_dispatch guard has one less thing to
// police, and that this logic is testable without a browser.
//
// # Why this is not in package controlplane
//
// controlplane owns the authentication BOUNDARY — it reads a credential off a
// request and injects a Principal. It does not own credential kinds; the API
// Token lane already lives in accounts.TokenService, and this is that same
// shape for the browser lane. controlplane depends on an interface, not on
// this package.
//
// # Sessions are held in memory, deliberately
//
// A session identifier is a bearer credential for a fleet-execution surface
// (ADR-0026). Written to disk it becomes something a database dump, a backup,
// or a stolen replica yields directly — with no KDF in the way, because a
// session id is checked by equality. Held in memory it costs a re-login after
// a Relay restart, which is a cost paid by a handful of operators, once, and
// visibly.
//
// Even in memory, identifiers are stored HASHED and never at rest in the
// clear: a heap dump or a core file is a real artefact that leaves a running
// process, and hashing costs one SHA-256 per request.
//
// HA is out of scope (roadmap: the HA/routing spike). When it arrives,
// shared session state is one of the things it has to answer; a durable store
// added now would prejudge that answer for the wrong reason.
package consoleauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
)

// Lifetime defaults. These are Relay configuration in the invariant-11 sense —
// file-only, operator-set at startup, unreachable from any API — and the
// defaults live here so a deployment that sets nothing still gets bounded
// sessions.
const (
	// DefaultAbsoluteLifetime is the hard ceiling on a session's age. It is
	// not extended by activity: a session that has existed this long ends,
	// which is what makes a stolen cookie a bounded loss rather than a
	// permanent one.
	DefaultAbsoluteLifetime = 12 * time.Hour

	// DefaultIdleTimeout ends a session that has gone unused. The two bounds
	// answer different threats — idle catches the unlocked laptop, absolute
	// catches the exfiltrated cookie — so the shell spec requires both and
	// neither substitutes for the other.
	DefaultIdleTimeout = 30 * time.Minute

	// DefaultStepUpWindow is how recently a human must have proved they are
	// present for a step-up-gated action to proceed.
	//
	// Short on purpose. Step-up is the strongest per-action intent binding in
	// the system and the reason ADR-0026 could give a browser an execution
	// surface at all; a window long enough to be convenient is a window long
	// enough for someone else at the same keyboard.
	//
	// **No Account of any role may extend it** (spec 11). An admin who could
	// widen their own step-up window has removed the control, so this is
	// file-only configuration and there is no code path from a request to it.
	DefaultStepUpWindow = 5 * time.Minute

	// MaxStepUpWindow is the ceiling an operator's step-up window is clamped
	// to. A window long enough to be convenient is long enough for someone
	// else at the keyboard, so a typo (or a deliberate "24h") must not turn
	// the control into a formality.
	MaxStepUpWindow = 15 * time.Minute
)

// ClampStepUpWindow caps d at MaxStepUpWindow and reports whether it did.
// Non-positive values pass through unchanged: WithStepUpWindow already maps
// them to DefaultStepUpWindow.
func ClampStepUpWindow(d time.Duration) (time.Duration, bool) {
	if d > MaxStepUpWindow {
		return MaxStepUpWindow, true
	}
	return d, false
}

// sessionIDBytes is the entropy in a session identifier. 32 bytes is the same
// budget the CSRF pepper and the API Token secret carry: guessing is not a
// threat model anyone needs to think about again.
const sessionIDBytes = 32

// csrfPepperBytes is the entropy in a Store's CSRF pepper. See CSRFToken and
// the Store field it keys.
const csrfPepperBytes = 32

var (
	// ErrNoSession means the presented identifier matches no live session —
	// unknown, already ended, or expired. Deliberately one error: the Console
	// shows the same sign-in page for all of them.
	ErrNoSession = errors.New("consoleauth: no live session")

	// ErrStepUpRequired means the session is valid but its last proof of human
	// presence is older than the step-up window.
	ErrStepUpRequired = errors.New("consoleauth: step-up re-authentication required")
)

const (
	redactedSessionID = "[REDACTED session id]"
	redactedCSRFToken = "[REDACTED csrf token]"
)

// SessionID is a Console session's bearer identifier — the value that rides in
// the cookie.
//
// It redacts under every stringifying interface, exactly as Password and
// api-token Plaintext do, and for the sharper reason: this one is checked by
// EQUALITY, so a copy of it in a log line is a working credential rather than
// a cracking target.
type SessionID struct{ id string }

// Reveal returns the identifier. The single way out of the type.
func (s SessionID) Reveal() string { return s.id }

// IsZero reports whether no identifier is held.
func (s SessionID) IsZero() bool { return s.id == "" }

func (s SessionID) String() string               { return redactedSessionID }
func (s SessionID) GoString() string             { return redactedSessionID }
func (s SessionID) LogValue() slog.Value         { return slog.StringValue(redactedSessionID) }
func (s SessionID) MarshalJSON() ([]byte, error) { return json.Marshal(redactedSessionID) }

// ParseSessionID wraps an identifier read off a request.
func ParseSessionID(raw string) SessionID { return SessionID{id: raw} }

// CSRFToken is a session's derived CSRF token, held in a type that redacts
// under every stringifying interface.
//
// Redacting for SessionID's reason, verbatim: this value is checked by
// EQUALITY, so a copy of it in a log line is a working credential rather than
// a cracking target. A STORED per-session secret is rejected partly because
// "a heap dump, a core file, or a log leak" would each be sufficient — the
// attacker never needs the session cookie, since the victim's browser attaches
// it. Deriving rather than storing answers the heap and core-file halves; only
// a type that refuses to print itself answers the log half, and logs are the
// cheap one because they ship off-box.
//
// So a bare string here would leave the argument for derivation half-made. The
// hazard is concrete: one slog.Debug("request", "session", cs) or a %+v of a
// struct carrying this, anywhere in a handler or middleware, and an attacker
// with log access needs only to get the victim's browser to issue one POST.
type CSRFToken struct{ token string }

// Reveal returns the token. The single way out of the type, used where the
// value must actually be compared or rendered.
func (c CSRFToken) Reveal() string { return c.token }

// IsZero reports whether no token is held.
func (c CSRFToken) IsZero() bool { return c.token == "" }

func (c CSRFToken) String() string               { return redactedCSRFToken }
func (c CSRFToken) GoString() string             { return redactedCSRFToken }
func (c CSRFToken) LogValue() slog.Value         { return slog.StringValue(redactedCSRFToken) }
func (c CSRFToken) MarshalJSON() ([]byte, error) { return json.Marshal(redactedCSRFToken) }

// ParseCSRFToken wraps a token value a test fixture or a caller already holds.
// It is NOT a mint — the only way to obtain a real token is Store.CSRFToken,
// which derives it and checks the session is live. Mirrors ParseSessionID.
func ParseCSRFToken(raw string) CSRFToken { return CSRFToken{token: raw} }

// Session is one signed-in human.
//
// It carries a SNAPSHOT of the Account for rendering only. Authorization never
// reads these fields: the Principal handed to the capability layer is
// projected from the Account read fresh on each request, so a role change or a
// disablement takes effect on the very next click rather than at the next
// sign-in. See Store.Lookup.
type Session struct {
	// AccountID is the join back to the stored Account, and the only field
	// here that authorization depends on.
	AccountID string

	// Account, Role and Kind are the snapshot taken at sign-in.
	Account string
	Role    accounts.Role
	Kind    accounts.Kind

	// Method is how the human authenticated: "password" or "oidc". It travels
	// into the audit trail's verified lane.
	Method string

	// Source is the address the session was issued to, recorded for audit.
	Source string

	CreatedAt  time.Time
	LastSeenAt time.Time

	// AuthenticatedAt is the step-up stamp: the last moment a human proved
	// presence by re-entering a credential. It is ZERO until the session's
	// first successful step-up: sign-in does NOT set it. Proving who you are
	// at sign-in authorises the session; step-up binds intent to an act. Never
	// refreshed by activity, which is the difference between it and
	// LastSeenAt.
	AuthenticatedAt time.Time
}

// StepUpFresh reports whether the session's proof of human presence is newer
// than window.
func (s Session) StepUpFresh(now time.Time, window time.Duration) bool {
	return !s.AuthenticatedAt.IsZero() && now.Sub(s.AuthenticatedAt) < window
}

// Store holds live Console sessions, keyed by the SHA-256 of their identifier.
//
// The zero value is not usable; construct with NewStore.
type Store struct {
	mu       sync.Mutex
	sessions map[string]*Session

	absoluteLifetime time.Duration
	idleTimeout      time.Duration
	now              func() time.Time

	// maxSessions bounds the map. A login route is reachable by anyone who can
	// reach the Console, and a successful login allocates; without a ceiling,
	// a compromised credential is also a memory-exhaustion primitive. On
	// overflow the OLDEST session is evicted rather than the newest refused,
	// so an attacker cannot deny service to real operators by filling the
	// table first.
	maxSessions int

	// csrfPepper is the key CSRFToken derives every session's CSRF token
	// from. See CSRFToken's doc for the threat model this buys and NewStore
	// for why it is minted here rather than taken as configuration.
	csrfPepper []byte
}

// DefaultMaxSessions is a ceiling far above any real operator population and
// far below anything that matters as an allocation.
const DefaultMaxSessions = 4096

// StoreOption configures a Store.
type StoreOption func(*Store)

// WithClock overrides the Store's clock. Tests use it to advance time without
// sleeping (mirrors registry.WithClock and ratelimit.WithClock).
func WithClock(now func() time.Time) StoreOption {
	return func(s *Store) { s.now = now }
}

// WithLifetimes overrides the absolute lifetime and idle timeout. Non-positive
// values keep the default, so a partially-populated config cannot accidentally
// mean "unbounded".
func WithLifetimes(absolute, idle time.Duration) StoreOption {
	return func(s *Store) {
		if absolute > 0 {
			s.absoluteLifetime = absolute
		}
		if idle > 0 {
			s.idleTimeout = idle
		}
	}
}

// WithMaxSessions overrides the session ceiling. Non-positive keeps the
// default.
func WithMaxSessions(n int) StoreOption {
	return func(s *Store) {
		if n > 0 {
			s.maxSessions = n
		}
	}
}

// NewStore constructs an empty session store.
//
// It mints the CSRF pepper here, once, for the Store's whole process
// lifetime — see CSRFToken for why a pepper that dies with the process is
// exactly right rather than a limitation.
func NewStore(opts ...StoreOption) *Store {
	pepper := make([]byte, csrfPepperBytes)
	if _, err := rand.Read(pepper); err != nil {
		// crypto/rand.Read on the standard Reader only fails if the OS
		// entropy source is broken, which is unrecoverable — the same
		// composition-root-wiring-bug treatment events.NewBus's epoch mint
		// gives, for the identical reason: NewStore's signature has no error
		// to return.
		panic("consoleauth: mint CSRF pepper: " + err.Error())
	}

	s := &Store{
		sessions:         make(map[string]*Session),
		absoluteLifetime: DefaultAbsoluteLifetime,
		idleTimeout:      DefaultIdleTimeout,
		now:              func() time.Time { return time.Now().UTC() },
		maxSessions:      DefaultMaxSessions,
		csrfPepper:       pepper,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Now returns the Store's current time.
//
// It exists so that everything reasoning about session ages — the expiry
// checks in here, and Service.RequireStepUp out there — reads ONE clock.
// A Service with its own clock is a Service whose step-up window can disagree
// with the session's own timestamps, and a step-up check that silently passes
// because two clocks drifted is the worst possible failure of the strongest
// control in the system. (It was also a real bug, caught by
// TestStepUp_RefreshesPresenceOnlyWithACredential.)
func (s *Store) Now() time.Time { return s.now() }

// Issue creates a session for sess and returns its new identifier.
//
// CreatedAt and LastSeenAt are stamped here from the Store's clock rather than
// taken from the caller: a session's own lifetime must not be settable by
// whoever is asking for one. AuthenticatedAt is explicitly zeroed, so a
// caller-supplied Session can never arrive pre-stamped; only StepUp sets it.
func (s *Store) Issue(sess Session) (SessionID, error) {
	id, err := newSessionID()
	if err != nil {
		return SessionID{}, err
	}

	now := s.now()
	sess.CreatedAt = now
	sess.LastSeenAt = now
	sess.AuthenticatedAt = time.Time{}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictExpiredLocked(now)
	s.enforceCeilingLocked()
	s.sessions[hashID(id)] = &sess
	return id, nil
}

// Lookup returns the live session for id, refreshing its idle clock.
//
// It returns ErrNoSession for an unknown, ended or expired identifier — one
// error for all three, because the Console's answer to all three is the same
// sign-in page, and an answer that distinguished them would confirm that a
// guessed identifier had once been real.
func (s *Store) Lookup(id SessionID) (Session, error) {
	if id.IsZero() {
		return Session{}, ErrNoSession
	}
	key := hashID(id)
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[key]
	if !ok {
		return Session{}, ErrNoSession
	}
	if s.expiredLocked(sess, now) {
		delete(s.sessions, key)
		return Session{}, ErrNoSession
	}
	// The idle clock is refreshed by USE. The absolute clock is not, and
	// nothing here touches AuthenticatedAt: browsing the Console must never
	// extend the step-up window, or the window would measure activity rather
	// than presence.
	sess.LastSeenAt = now
	return *sess, nil
}

// Rotate issues a fresh identifier for an existing session and retires the old
// one, preserving everything else about it.
//
// This is the session-fixation control (spec 12: "rotate the session
// identifier on login"). An identifier that survives the authentication
// boundary can have been planted before it — by a link, by a shared machine,
// by an attacker who set the cookie themselves — and would then be a valid
// credential for the session the victim went on to authenticate.
//
// A plain rotation with no stamp. Store.StepUp is the privilege-change
// rotation.
func (s *Store) Rotate(old SessionID) (SessionID, error) {
	newID, err := newSessionID()
	if err != nil {
		return SessionID{}, err
	}
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.rotateLocked(hashID(old), newID, now); err != nil {
		return SessionID{}, err
	}
	return newID, nil
}

// rotateLocked moves the session under oldKey to newID's key, keeping the same
// *Session (so CreatedAt, the absolute clock, carries over). An absent or
// expired session is ErrNoSession, and an expired one is evicted. The caller
// holds s.mu and mints newID beforehand so nothing under the lock can fail on
// randomness.
func (s *Store) rotateLocked(oldKey string, newID SessionID, now time.Time) (*Session, error) {
	sess, ok := s.sessions[oldKey]
	if !ok {
		return nil, ErrNoSession
	}
	if s.expiredLocked(sess, now) {
		delete(s.sessions, oldKey)
		return nil, ErrNoSession
	}
	delete(s.sessions, oldKey)
	s.sessions[hashID(newID)] = sess
	return sess, nil
}

// CSRFToken derives THIS session's Console CSRF token: HMAC-SHA256 of id's
// identifier, keyed by the Store's process-lifetime pepper, base64-encoded.
// It returns "" for a zero identifier — there is nothing to derive from.
//
// # Derive, never store
//
// An earlier design minted a per-session secret and stored it on the Session
// in the clear, reasoning that it was "not a credential on its own" because a
// heap-dump reader would not also have the (hashed) session identifier. That
// reasoning does not survive contact with what CSRF actually is: the
// attacker NEVER needs the session cookie, because the victim's own browser
// attaches it. So an attacker who learned only the stored secret — from a
// heap dump, a core file, or a log leak — could forge the exact same-site
// request this control exists to stop, against any browser still holding a
// live session, without ever touching that session's identifier. Storing N
// plaintext secrets for up to the session's absolute lifetime reintroduced,
// for the CSRF half, precisely the exposure this package already refuses for
// the identifier half (see hashID). The asymmetry was convenience, not
// safety.
//
// Deriving instead of storing changes what a heap reader gets: ONE pepper,
// process-wide, plus N hashed identifiers. The pepper alone is inert —
// forging a token needs HMAC(pepper, rawID), and a raw identifier is exactly
// what this package never keeps at rest (Lookup and hashID). There is no
// table of secrets to leak, because there is no table: this is the ONE
// derivation in the process, computed fresh from whatever identifier the
// caller already resolved.
//
// # Why the pepper is process-lifetime, not persisted
//
// Sessions are held in memory (see the package doc), and a Relay restart
// already ends every one of them. A pepper that dies with the process
// invalidates tokens and sessions together, in the same step — there is
// nothing to migrate, because there is nothing left to protect. A persisted
// pepper would be a stored credential whose only job is to make a stored
// credential (the token) unnecessary; that is not a saving, it is the same
// liability moved one level up. It is minted in NewStore, never taken from
// configuration (invariant 11: nothing here is settable, and nothing here is
// a request away from being read).
//
// # What this closes
//
// Binding the token to the session this way also closes classic LOGIN CSRF
// — forcing a victim's browser to submit credentials into an
// attacker-controlled account — because the sign-in POST is covered by its
// own lane (security.go's signInCSRFValid) rather than by this derivation,
// which has no session to bind to yet. See security.go's file doc for the
// two-lane scheme this method is half of.
func (s *Store) CSRFToken(id SessionID) CSRFToken {
	// A zero-value Store would derive under a nil HMAC key: a value anyone who
	// knows the raw identifier can recompute, identical in every process. No
	// construction path produces one (NewStore is the only one and it panics on
	// a broken entropy source), and the type doc says the zero value is not
	// usable — but the single way to get a universally-forgeable token should be
	// loud rather than silent, for exactly NewStore's reason.
	if len(s.csrfPepper) == 0 {
		panic("consoleauth: CSRFToken called on a Store built without NewStore")
	}
	if id.IsZero() {
		return CSRFToken{}
	}

	// LIVENESS, not just shape. Without it this method is a forgery oracle for
	// any identifier a caller can name: it would hand back a permanently-valid
	// token for a session the caller does not own, and nothing in the signature
	// would warn them. Today's only caller has already resolved the session, so
	// the check is redundant TODAY — and that is precisely the kind of safety
	// that stops holding when a second caller appears, especially one that
	// (like handleLoginSubmit, deliberately) reads the raw cookie rather than a
	// resolved session.
	//
	// Refusing an unknown identifier also makes the token's lifetime match the
	// session's at both ends rather than only at issue.
	key := hashID(id)
	now := s.now()
	s.mu.Lock()
	sess, ok := s.sessions[key]
	expired := ok && s.expiredLocked(sess, now)
	s.mu.Unlock()
	if !ok || expired {
		return CSRFToken{}
	}

	mac := hmac.New(sha256.New, s.csrfPepper)
	mac.Write([]byte(id.Reveal()))
	return CSRFToken{token: base64.RawURLEncoding.EncodeToString(mac.Sum(nil))}
}

// CSRFTokensEqual reports whether a CSRF token the server holds and one a
// request submitted match, in constant time.
//
// Deliberately origin-neutral in both name and parameters, because it has two
// callers with different notions of "held": the session lane compares a token
// DERIVED from the session identifier, and the sign-in lane compares the value
// of a double-submit cookie. The comparison and its guard are identical for
// both, and duplicating a security-sensitive guard across two files to keep the
// parameter names specific would be the worse trade.
//
// The empty guard is load-bearing and must stay: subtle.ConstantTimeCompare
// of two empty slices returns 1, so without it a request presenting no token
// at all would validate against a session whose token happened to be empty
// (a zero SessionID, or a caller that never derived one). Refusing empties on
// EITHER side, before the comparison runs, is what makes "no token" and "the
// zero value" the same failure rather than a bypass.
func CSRFTokensEqual(held, submitted string) bool {
	if held == "" || submitted == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(held), []byte(submitted)) == 1
}

// StepUp stamps the session's proof of human presence and rotates its
// identifier, returning the new one. Call it only after a credential has been
// re-verified — never on activity.
//
// A step-up is a privilege change, so this Store can never stamp a session
// without rotating its id in the same critical section: no interleaving can
// observe a stamped old id or an unstamped new one. The old id is dead on
// return; its CSRF token changes with it, because the token is derived from
// the id.
func (s *Store) StepUp(old SessionID) (SessionID, error) {
	newID, err := newSessionID()
	if err != nil {
		return SessionID{}, err
	}
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	sess, err := s.rotateLocked(hashID(old), newID, now)
	if err != nil {
		return SessionID{}, err
	}
	sess.AuthenticatedAt = now
	return newID, nil
}

// End retires a session. Ending one that is already gone is not an error: the
// postcondition holds either way, and a sign-out that could fail is a sign-out
// people learn to ignore.
func (s *Store) End(id SessionID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, hashID(id))
}

// EndAllFor retires every session belonging to accountID and returns how many
// were ended.
//
// The lever behind "this Account is compromised": disabling an Account stops
// the next authentication, and this stops the ones already in flight. Without
// it, a disabled human keeps their Console until their session lapses.
func (s *Store) EndAllFor(accountID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	ended := 0
	for key, sess := range s.sessions {
		if sess.AccountID == accountID {
			delete(s.sessions, key)
			ended++
		}
	}
	return ended
}

// Len returns the number of live sessions. For tests and for the operational
// question "how many people are signed in"; it exposes no identifier.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictExpiredLocked(s.now())
	return len(s.sessions)
}

// expiredLocked reports whether sess has passed either bound.
func (s *Store) expiredLocked(sess *Session, now time.Time) bool {
	return now.Sub(sess.CreatedAt) >= s.absoluteLifetime ||
		now.Sub(sess.LastSeenAt) >= s.idleTimeout
}

// evictExpiredLocked drops every expired session. Called on the write paths
// rather than from a background goroutine: the map only grows on a successful
// login, so sweeping there bounds it without a timer to leak.
func (s *Store) evictExpiredLocked(now time.Time) {
	for key, sess := range s.sessions {
		if s.expiredLocked(sess, now) {
			delete(s.sessions, key)
		}
	}
}

// enforceCeilingLocked evicts oldest-first until there is room for one more.
func (s *Store) enforceCeilingLocked() {
	for len(s.sessions) >= s.maxSessions {
		oldestKey := ""
		var oldest time.Time
		for key, sess := range s.sessions {
			if oldestKey == "" || sess.CreatedAt.Before(oldest) {
				oldestKey, oldest = key, sess.CreatedAt
			}
		}
		if oldestKey == "" {
			return
		}
		delete(s.sessions, oldestKey)
	}
}

// newSessionID mints a fresh identifier.
func newSessionID() (SessionID, error) {
	raw := make([]byte, sessionIDBytes)
	if _, err := rand.Read(raw); err != nil {
		return SessionID{}, errors.New("consoleauth: cannot read random bytes for a session identifier")
	}
	return SessionID{id: base64.RawURLEncoding.EncodeToString(raw)}, nil
}

// hashID is the map key: sessions are held under the SHA-256 of their
// identifier so the live value is never at rest in the process, not even in a
// heap dump.
//
// A plain hash rather than a KDF is right here and would be wrong for a
// password: the input is 256 bits of CSPRNG output, so there is no dictionary
// to run and nothing for a work factor to buy.
func hashID(id SessionID) string {
	sum := sha256.Sum256([]byte(id.Reveal()))
	return string(sum[:])
}

// SessionCookieName is the Console session cookie.
//
// It lives here, in the package that mints and resolves sessions, because two
// other packages need to agree on it: the console package sets and clears it,
// and the control plane's authenticator reads it. A name defined twice is a
// name that eventually differs in one place.
//
// The `__Host-` prefix is a browser-enforced guarantee and not decoration: a
// cookie carrying it is refused unless it is Secure, has Path=/, and has NO
// Domain attribute. That last part is the one that matters — it makes the
// cookie host-only, so a sibling subdomain (or anything that manages to set a
// cookie for the parent domain) cannot plant or overwrite a Console session.
// The shell spec asks for a host-only session cookie; this is the version of
// that the browser enforces rather than the version we promise.
const SessionCookieName = "__Host-relay_console_session"
