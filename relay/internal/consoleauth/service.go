package consoleauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
)

// The audit vocabulary this package writes, named once so the Kind strings
// have exactly one definition in the process. internal/audit owns them;
// aliasing rather than re-declaring is what keeps a renamed kind from
// silently becoming two kinds.
const (
	auditKindLoginSucceeded = audit.KindLoginSucceeded
	auditKindLoginFailed    = audit.KindLoginFailed
	auditKindLoginThrottled = audit.KindLoginThrottled
	auditKindLogout         = audit.KindLogout

	auditKindStepUp          = audit.KindStepUp
	auditKindStepUpFailed    = audit.KindStepUpFailed
	auditKindStepUpThrottled = audit.KindStepUpThrottled
)

// Authentication methods, as recorded in the audit trail's verified lane.
const (
	// MethodPassword is the local username/password baseline (ADR-0009,
	// revised 2026-07-02).
	MethodPassword = "console_password"

	// MethodOIDC is the human browser flow against a configured provider.
	// Reserved here so the audit vocabulary is settled; the flow itself is
	// spec 12's optional half and is not built in this change.
	MethodOIDC = "console_oidc"
)

var (
	// ErrBadCredentials is THE login failure. Every way a sign-in can fail
	// that is not a throttle returns exactly this: an unknown name, a
	// disabled Account, a machine Account, an Account with no local password,
	// a corrupt stored hash, and a wrong password.
	//
	// One error, one message, one code path — because spec 12 requires a
	// wrong username and a wrong password to be indistinguishable, and the
	// most reliable way to guarantee that is to make it impossible to write a
	// caller that tells them apart.
	ErrBadCredentials = errors.New("consoleauth: invalid credentials")

	// ErrNotConfigured means no local password credential exists anywhere yet.
	// Distinct from ErrBadCredentials because it is not about any particular
	// attempt and reveals nothing about any Account: it is the day-zero state,
	// and telling an operator "no Console password has been set — see the
	// quickstart" beats letting them guess at a credential that cannot exist.
	ErrNotConfigured = errors.New("consoleauth: no Console password has been set")
)

// ThrottledError is returned when an attempt was refused before any credential
// was checked. RetryAfter is how long the caller must wait.
//
// It carries the wait because spec 12 requires the Console to "say so plainly,
// and when the next attempt is accepted" rather than pretending the password
// was wrong. A throttle disguised as a failure teaches operators that the
// product is flaky.
type ThrottledError struct{ RetryAfter time.Duration }

func (e *ThrottledError) Error() string {
	return fmt.Sprintf("consoleauth: too many recent attempts, retry in %s", e.RetryAfter.Round(time.Second))
}

// Throttled reports whether err is a ThrottledError, and the wait if so.
func Throttled(err error) (time.Duration, bool) {
	var t *ThrottledError
	if errors.As(err, &t) {
		return t.RetryAfter, true
	}
	return 0, false
}

// Attempt is one sign-in request.
type Attempt struct {
	// Name is the submitted username, as typed.
	Name string

	// Password is the submitted plaintext, wrapped so it cannot be logged.
	Password accounts.Password

	// Source is the peer address the attempt arrived from, as the handler read
	// it off the connection. Never from a header.
	Source string

	// Existing is the session identifier the browser already presented, if
	// any. It is RETIRED on a successful sign-in — the session-fixation
	// control (spec 12), because an identifier that survives the
	// authentication boundary may have been planted before it.
	Existing SessionID
}

// LoginEvent is one auditable authentication event.
type LoginEvent struct {
	// Kind is one of audit.KindLoginSucceeded, KindLoginFailed,
	// KindLoginThrottled, KindLogout, KindStepUp, KindStepUpFailed or
	// KindStepUpThrottled.
	Kind string

	// Account and AccountID identify the acting Account. Both are empty on a
	// failure, ALWAYS — including a failure against an Account that exists.
	//
	// That is deliberate and it costs something real: a trail that named the
	// Account would answer "who is being guessed at" directly. It would also
	// be a user-enumeration oracle for anyone with audit read access, which
	// on this product includes every viewer. SubmittedName below carries what
	// was typed, in the asserted lane where a claim belongs.
	Account   string
	AccountID string
	Role      string

	// SubmittedName is what the caller typed. Caller-controlled and untrusted:
	// it belongs to the asserted lane and is never matched against an Account.
	SubmittedName string

	// Method is how the identity was established (MethodPassword, MethodOIDC).
	// Set even on a failure: "someone is guessing passwords" and "someone is
	// replaying OIDC assertions" are different incidents.
	Method string

	// Source is the peer address, for the verified lane.
	Source string

	// Reason is a short, non-oracular note. It never distinguishes an unknown
	// Account from a wrong password.
	Reason string
}

// Auditor records authentication events. *auditsink.Sink satisfies it via the
// composition root's adapter.
//
// An interface rather than a direct dependency for the usual reason and one
// specific one: this package must be testable without a store, and an audit
// failure must be able to fail the login (see Service.Login) rather than being
// swallowed by a package that cannot see the error.
type Auditor interface {
	RecordLogin(ctx context.Context, e LoginEvent) error
}

// Service authenticates humans into the Console.
type Service struct {
	accounts  accounts.Repository
	passwords accounts.PasswordRepository
	sessions  *Store
	throttle  *Throttle
	audit     Auditor

	stepUpWindow time.Duration
}

// now reads the SESSION STORE's clock, never one of its own. See Store.Now:
// two clocks that can disagree about a session's age is how a step-up check
// silently passes when it should not.
func (s *Service) now() time.Time { return s.sessions.Now() }

// ServiceOption configures a Service.
type ServiceOption func(*Service)

// WithStepUpWindow overrides how recently a human must have proved presence
// for a step-up-gated action. Non-positive keeps the default.
//
// This is file-only Relay configuration (spec 11, invariant 11): the
// composition root reads it at startup and there is no code path from any
// request to this option. An admin who could widen their own step-up window
// has removed the control.
func WithStepUpWindow(d time.Duration) ServiceOption {
	return func(s *Service) {
		if d > 0 {
			s.stepUpWindow = d
		}
	}
}

// NewService constructs the Console's authentication service.
//
// It warms the password timing verifier at construction. That is not an
// optimisation: it is what keeps the FIRST unknown-username sign-in from
// being measurably slower than every later one, which would leak exactly the
// fact the no-enumeration rule exists to hide.
func NewService(
	accts accounts.Repository,
	passwords accounts.PasswordRepository,
	sessions *Store,
	throttle *Throttle,
	auditor Auditor,
	opts ...ServiceOption,
) *Service {
	accounts.WarmPasswordVerifier()

	s := &Service{
		accounts:     accts,
		passwords:    passwords,
		sessions:     sessions,
		throttle:     throttle,
		audit:        auditor,
		stepUpWindow: DefaultStepUpWindow,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// StepUpWindow reports the configured recent-auth window, so the Console can
// tell a human how long their confirmation lasts without holding the value
// itself.
func (s *Service) StepUpWindow() time.Duration { return s.stepUpWindow }

// Login authenticates a, issues a session, and returns its identifier.
//
// # The shape of this function is the security property
//
// Every failure path below does the same three things in the same order —
// burn a KDF run, record the failure, audit, return ErrBadCredentials — so
// that an unknown username, a disabled Account, a machine Account, an Account
// with no password, a corrupt hash, and a wrong password are indistinguishable
// in message, in timing, and in the audit trail. The temptation to
// short-circuit any of them (an early return for "no such account" is the
// obvious one) is the bug this arrangement exists to prevent.
func (s *Service) Login(ctx context.Context, a Attempt) (SessionID, Session, error) {
	name := accounts.NormalizeName(a.Name)

	if wait := s.throttle.Check(a.Source, name); wait > 0 {
		if err := s.recordLogin(ctx, LoginEvent{
			Kind:          auditKindLoginThrottled,
			SubmittedName: a.Name,
			Method:        MethodPassword,
			Source:        a.Source,
			Reason:        fmt.Sprintf("refused before any credential was checked; next attempt accepted in %s", wait.Round(time.Second)),
		}); err != nil {
			return SessionID{}, Session{}, err
		}
		return SessionID{}, Session{}, &ThrottledError{RetryAfter: wait}
	}

	acct, hash, ok := s.resolve(ctx, name)
	if !ok || !hash.Verify(a.Password) {
		// The equal-time burn for every non-verification failure. When the
		// Account resolved, hash.Verify has already done a real derivation and
		// this is skipped — otherwise a wrong password would cost twice what a
		// wrong username does, which is the same oracle read backwards.
		if !ok {
			accounts.VerifyNothing(a.Password)
		}
		s.throttle.Fail(a.Source, name)
		if err := s.recordLogin(ctx, LoginEvent{
			Kind:          auditKindLoginFailed,
			SubmittedName: a.Name,
			Method:        MethodPassword,
			Source:        a.Source,
			Reason:        "invalid credentials",
		}); err != nil {
			return SessionID{}, Session{}, err
		}
		return SessionID{}, Session{}, ErrBadCredentials
	}

	// Session fixation: whatever identifier the browser arrived holding is
	// retired here, before a new one is minted. It may have been planted.
	if !a.Existing.IsZero() {
		s.sessions.End(a.Existing)
	}

	sess := Session{
		AccountID: acct.ID,
		Account:   acct.Name,
		Role:      acct.Role,
		Kind:      acct.Kind,
		Method:    MethodPassword,
		Source:    a.Source,
	}
	id, err := s.sessions.Issue(sess)
	if err != nil {
		return SessionID{}, Session{}, err
	}

	s.throttle.Succeed(a.Source, name)
	if err := s.accounts.TouchLastSeen(ctx, acct.ID, s.now()); err != nil {
		// Advisory bookkeeping ("is this Account still in use?"). It must not
		// fail a sign-in, but it must not vanish either — the audit record
		// below is the authoritative trail and it is still written.
		_ = err
	}
	if err := s.recordLogin(ctx, LoginEvent{
		Kind:          auditKindLoginSucceeded,
		Account:       acct.Name,
		AccountID:     acct.ID,
		Role:          string(acct.Role),
		SubmittedName: a.Name,
		Method:        MethodPassword,
		Source:        a.Source,
	}); err != nil {
		// The session was issued but could not be recorded. End it: an
		// unauditable Console session on a fleet-execution surface is worse
		// than a failed sign-in, and ADR-0025's posture throughout this
		// product is that an action that cannot be recorded does not happen.
		s.sessions.End(id)
		return SessionID{}, Session{}, err
	}

	issued, err := s.sessions.Lookup(id)
	if err != nil {
		return SessionID{}, Session{}, err
	}
	return id, issued, nil
}

// Logout ends the session and records it. Signing out is audited for the same
// reason signing in is: the trail should say when someone stopped being able
// to act, not merely when they started.
func (s *Service) Logout(ctx context.Context, id SessionID, source string) error {
	sess, err := s.sessions.Lookup(id)
	if err != nil {
		// Already gone. Nothing to end and nothing to attribute.
		return nil
	}
	s.sessions.End(id)
	return s.recordLogin(ctx, LoginEvent{
		Kind:      auditKindLogout,
		Account:   sess.Account,
		AccountID: sess.AccountID,
		Role:      string(sess.Role),
		Method:    sess.Method,
		Source:    source,
	})
}

// Resolve turns a presented session identifier into the CURRENT Account.
//
// It re-reads the Account on every call rather than trusting the snapshot in
// the session. That is what makes a role change or a disablement take effect
// on the very next click: a session issued to an admin who has since been
// demoted resolves as an operator, and one issued to an Account since disabled
// resolves as nothing at all.
//
// This is the seam controlplane.Authenticator reads on the browser lane.
func (s *Service) Resolve(ctx context.Context, id SessionID) (Session, accounts.Account, error) {
	sess, err := s.sessions.Lookup(id)
	if err != nil {
		return Session{}, accounts.Account{}, err
	}
	acct, err := s.accounts.Get(ctx, sess.AccountID)
	if err != nil {
		// The Account is gone. So is the session.
		s.sessions.End(id)
		return Session{}, accounts.Account{}, ErrNoSession
	}
	if !acct.Enabled {
		// Disabling an Account is the durable off-switch (#296). It has to
		// reach sessions already in flight, or a disabled human keeps their
		// Console until the session lapses on its own.
		s.sessions.EndAllFor(acct.ID)
		return Session{}, accounts.Account{}, ErrNoSession
	}
	return sess, acct, nil
}

// StepUp re-verifies a password against the session's own Account and, on
// success, refreshes the proof of human presence.
//
// It takes the same Attempt shape and runs the same throttle as Login, because
// it IS a login — the strongest one in the system. What it must never be is a
// cheaper check than the one that established the session.
//
// Every exit below is audited, deliberately under its OWN kinds
// (KindStepUp/Failed/Throttled) rather than the sign-in ones: the step-up
// door is reached only from an already-authenticated session, so "someone is
// guessing at the front door" and "something inside this session is trying
// to escalate" are different questions, and ADR-0026's threat model is the
// second one (see audit.go's doc). audit.AuthFailureKinds is how a consumer
// asks both refusal questions at once when it needs to.
func (s *Service) StepUp(ctx context.Context, id SessionID, password accounts.Password, source string) error {
	sess, acct, err := s.Resolve(ctx, id)
	if err != nil {
		return err
	}
	name := accounts.NormalizeName(sess.Account)

	if wait := s.throttle.Check(source, name); wait > 0 {
		if err := s.recordLogin(ctx, LoginEvent{
			Kind:          auditKindStepUpThrottled,
			SubmittedName: sess.Account,
			Method:        MethodPassword,
			Source:        source,
			Reason: fmt.Sprintf("step-up re-authentication refused before any credential "+
				"was checked; next attempt accepted in %s", wait.Round(time.Second)),
		}); err != nil {
			return err
		}
		return &ThrottledError{RetryAfter: wait}
	}

	_, hash, ok := s.resolve(ctx, name)
	if !ok || !hash.Verify(password) {
		if !ok {
			accounts.VerifyNothing(password)
		}
		s.throttle.Fail(source, name)
		if err := s.recordLogin(ctx, LoginEvent{
			Kind:          auditKindStepUpFailed,
			SubmittedName: sess.Account,
			Method:        MethodPassword,
			Source:        source,
			Reason:        "step-up re-authentication refused",
		}); err != nil {
			return err
		}
		return ErrBadCredentials
	}
	s.throttle.Succeed(source, name)
	if err := s.sessions.StepUp(id); err != nil {
		return err
	}
	return s.recordLogin(ctx, LoginEvent{
		Kind:      auditKindStepUp,
		Account:   acct.Name,
		AccountID: acct.ID,
		Role:      string(acct.Role),
		Method:    MethodPassword,
		Source:    source,
		Reason:    "step-up re-authentication",
	})
}

// RequireStepUp reports whether the session's proof of human presence is still
// fresh, returning ErrStepUpRequired when it is not.
func (s *Service) RequireStepUp(id SessionID) error {
	sess, err := s.sessions.Lookup(id)
	if err != nil {
		return err
	}
	if !sess.StepUpFresh(s.now(), s.stepUpWindow) {
		return ErrStepUpRequired
	}
	return nil
}

// resolve looks up the Account and its password hash, collapsing every reason
// a sign-in cannot proceed into a single false.
//
// The collapse happens HERE, below the caller, on purpose: Login cannot
// accidentally branch on a distinction it never receives.
func (s *Service) resolve(ctx context.Context, name string) (accounts.Account, accounts.PasswordHash, bool) {
	acct, err := s.accounts.GetByName(ctx, name)
	if err != nil {
		return accounts.Account{}, accounts.PasswordHash{}, false
	}
	if !acct.Enabled {
		return accounts.Account{}, accounts.PasswordHash{}, false
	}
	// The Console establishes a per-HUMAN identity (ADR-0009: reusing a shared
	// machine credential for humans yields no per-human identity, no RBAC and
	// no per-human audit). A machine Account has no business holding a browser
	// session even if someone sets a password on it.
	if acct.Kind != accounts.KindHuman {
		return accounts.Account{}, accounts.PasswordHash{}, false
	}
	hash, err := s.passwords.GetPassword(ctx, acct.ID)
	if err != nil {
		// Includes ErrNoPassword and ErrPasswordHashMalformed. A damaged
		// credential refuses the sign-in; it never falls through to "no
		// password required".
		return accounts.Account{}, accounts.PasswordHash{}, false
	}
	return acct, hash, true
}

// recordLogin writes one authentication event, tolerating a nil Auditor so
// this package is usable in tests without a store.
//
// A recording FAILURE is returned to the caller and fails the sign-in. That is
// the deliberate choice: the login trail is the first link in the chain
// `ui-advisory.md` requires end-to-end, and a Console session nobody can
// account for is not an acceptable degradation on a surface that reaches
// fleet execution.
func (s *Service) recordLogin(ctx context.Context, e LoginEvent) error {
	if s.audit == nil {
		return nil
	}
	if err := s.audit.RecordLogin(ctx, e); err != nil {
		return fmt.Errorf("consoleauth: could not record an authentication event: %w", err)
	}
	return nil
}
