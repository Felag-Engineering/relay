package consoleauth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

// password.go is a human changing their own Console password (ADR-0045
// decisions 5 to 9).

var (
	// ErrCurrentPasswordRequired means no current password was submitted. It
	// is refused before anything is compared or recorded.
	ErrCurrentPasswordRequired = errors.New("consoleauth: the current password is required")

	// ErrPasswordMismatch means the new password and its confirmation differ.
	ErrPasswordMismatch = errors.New("consoleauth: the new password and its confirmation differ")

	// ErrPasswordUnchanged means the new password is the current one.
	ErrPasswordUnchanged = errors.New("consoleauth: the new password must differ from the current one")

	// ErrPasswordChangeRequired means the session is restricted to the
	// password change (a temporary password opened it), so the act asked of it
	// is refused.
	ErrPasswordChangeRequired = errors.New("consoleauth: this session may only change its password")

	// ErrPasswordChangeUnavailable means no recorder is configured, so a change
	// could not be recorded and is not made.
	ErrPasswordChangeUnavailable = errors.New("consoleauth: password changes are not configured on this Relay")

	// ErrChangedSessionEnded means the password changed but the session that
	// changed it ended before it could be rotated.
	ErrChangedSessionEnded = errors.New("consoleauth: the password changed, but this session ended")
)

// PasswordChange is one change request. Every password is wrapped so it cannot
// be logged.
type PasswordChange struct {
	Current, New, Confirm accounts.Password

	// Source is the peer address, for the verified lane and the throttle.
	Source string
}

// PasswordChangeEvent is what a recorder writes for one change. It carries
// hashes and no plaintext.
type PasswordChangeEvent struct {
	AccountID, Account, Role, Method, Source string

	// Expect is the stored hash the current password was verified against; the
	// write is a compare-and-set on it. New replaces it.
	Expect, New accounts.PasswordHash

	// Forced is true when the change redeemed a temporary password.
	Forced bool

	// SessionsEnded is how many other sessions of the Account the change ends.
	SessionsEnded int
}

// PasswordChangeRecorder writes the new password and its password_change
// record in one transaction: nil means both landed, an error means neither did.
type PasswordChangeRecorder interface {
	RecordPasswordChange(ctx context.Context, e PasswordChangeEvent) error
}

// WithPasswordChanges sets the recorder ChangePassword writes through.
func WithPasswordChanges(r PasswordChangeRecorder) ServiceOption {
	return func(s *Service) { s.passwordChanges = r }
}

// ChangePassword changes the session's OWN Account's password and returns the
// session's rotated identifier. The caller MUST reissue the cookie from it.
//
// It lives here beside Login and StepUp, not in the capability layer, because
// it is a credential act on the session's own Account, proven by this lane's
// step-up: no target Account is taken from the request, so the Console decides
// nothing (ADR-0045 decisions 6 and 7, invariant 10). The capability layer
// holds the admin issuance acts.
//
// The proof of the current password is a step-up: throttled on the same
// (source, name) as sign-in, recorded as step_up, step_up_failed or
// step_up_throttled, and verified on every request. The recent-authentication
// window is never consulted (decision 7). Bounds, confirmation and "unchanged"
// are refused before any credential is compared and record nothing.
//
// A successful change ends the Account's other sessions and rotates this one
// (decision 9). The recorded count is taken before the write; a session that
// signs in between is still ended, so the count can under-report by such a
// session.
func (s *Service) ChangePassword(ctx context.Context, id SessionID, c PasswordChange) (SessionID, error) {
	if s.passwordChanges == nil {
		return SessionID{}, ErrPasswordChangeUnavailable
	}
	sess, acct, err := s.Resolve(ctx, id)
	if err != nil {
		return SessionID{}, err
	}

	if c.Current.IsZero() {
		return SessionID{}, ErrCurrentPasswordRequired
	}
	if err := c.New.Validate(); err != nil {
		return SessionID{}, err
	}
	if subtle.ConstantTimeCompare([]byte(c.New.Reveal()), []byte(c.Confirm.Reveal())) != 1 {
		return SessionID{}, ErrPasswordMismatch
	}
	if subtle.ConstantTimeCompare([]byte(c.New.Reveal()), []byte(c.Current.Reveal())) == 1 {
		return SessionID{}, ErrPasswordUnchanged
	}

	name := accounts.NormalizeName(sess.Account)
	event := func(kind, reason string) LoginEvent {
		return LoginEvent{
			Kind:      kind,
			Account:   acct.Name,
			AccountID: acct.ID,
			Role:      string(acct.Role),
			Method:    sess.Method,
			Source:    c.Source,
			Reason:    reason,
		}
	}

	if wait := s.throttle.Check(c.Source, name); wait > 0 {
		if err := s.recordLogin(ctx, event(auditKindStepUpThrottled, fmt.Sprintf(
			"password change refused before any credential was checked; next attempt accepted in %s", ceilSecond(wait)))); err != nil {
			return SessionID{}, err
		}
		return SessionID{}, &ThrottledError{RetryAfter: wait}
	}

	_, stored, ok := s.credential(ctx, acct, true)
	if !ok || !stored.Hash.Verify(c.Current) {
		if !ok {
			accounts.VerifyNothing(c.Current)
		}
		s.throttle.Fail(c.Source, name)
		if err := s.recordLogin(ctx, event(auditKindStepUpFailed, "step-up re-authentication refused for a password change")); err != nil {
			return SessionID{}, err
		}
		return SessionID{}, ErrBadCredentials
	}
	s.throttle.Succeed(c.Source, name)
	if err := s.recordLogin(ctx, event(auditKindStepUp, "step-up re-authentication for a password change")); err != nil {
		return SessionID{}, err
	}

	newHash, err := accounts.HashPassword(c.New)
	if err != nil {
		return SessionID{}, err
	}
	if err := s.passwordChanges.RecordPasswordChange(ctx, PasswordChangeEvent{
		AccountID:     acct.ID,
		Account:       acct.Name,
		Role:          string(acct.Role),
		Method:        sess.Method,
		Source:        c.Source,
		Expect:        stored.Hash,
		New:           newHash,
		Forced:        stored.Temporary(),
		SessionsEnded: s.sessions.CountOthers(acct.ID, id),
	}); err != nil {
		return SessionID{}, err
	}

	newID, _, err := s.sessions.CompletePasswordChange(id)
	if err != nil {
		// The change landed but this session is gone: end the rest, as a
		// change would have, and say so.
		s.sessions.EndAllFor(acct.ID)
		return SessionID{}, ErrChangedSessionEnded
	}
	return newID, nil
}
