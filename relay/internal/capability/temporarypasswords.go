package capability

import (
	"context"
	"errors"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

// temporarypasswords.go holds the admin acts of ADR-0045: creating a human
// Account with a Relay-generated temporary password, and re-issuing one while
// the Account's human has never set their own. Only the Console is handed this
// object, so the Control API creates humans with no password and MCP has none
// (ADR-0045 decision 11, the narrowing invariant 10 allows an adapter).
//
// The plaintext exists only in the TemporaryPassword returned to the caller.
// It is hashed here and the recorder receives the hash alone, so no audit
// record, event or store call can carry it; every error path returns the zero
// TemporaryPassword.

// ErrTemporaryPasswordsUnavailable means temporary passwords are not
// configured on this Relay.
var ErrTemporaryPasswordsUnavailable = errors.New("capability: temporary passwords are not configured on this Relay")

// TemporaryPasswords issues temporary passwords. Construct it with
// NewTemporaryPasswords.
type TemporaryPasswords struct {
	control  *Control
	rec      TemporaryPasswordRecorder
	status   TemporaryPasswordStatusSource
	sessions SessionEnder
	now      func() time.Time
}

// SessionEnder ends every Console session of an Account. A re-issue uses it so
// that a credential the admin replaced leaves no session behind.
type SessionEnder interface {
	EndAllFor(accountID string) int
}

// EndSessionsWith makes a successful re-issue end the target Account's Console
// sessions through e. Wire it once at the composition root, before serving;
// without it a re-issue is refused, because a replaced credential must leave
// no session behind.
func (t *TemporaryPasswords) EndSessionsWith(e SessionEnder) { t.sessions = e }

// NewTemporaryPasswords returns TemporaryPasswords over control and a status
// source. Like NewAccountAdmin it requires a real Authorizer and an AuditSink
// that is also a TemporaryPasswordRecorder: an unfloored or unrecorded issuance
// is a composition-root bug and panics.
func NewTemporaryPasswords(control *Control, status TemporaryPasswordStatusSource) *TemporaryPasswords {
	if control == nil {
		panic("capability: NewTemporaryPasswords: control must not be nil")
	}
	if status == nil {
		panic("capability: NewTemporaryPasswords: status source must not be nil")
	}
	if _, ok := control.authz.(allowAllAuthorizer); ok {
		panic("capability: NewTemporaryPasswords: requires a real Authorizer (NewControl); allowAllAuthorizer would fail open on every temporary password")
	}
	if _, ok := control.rec.audit.(noopAuditSink); ok {
		panic("capability: NewTemporaryPasswords: requires a real AuditSink (NewRecorder); noopAuditSink would record no issuance")
	}
	rec, ok := control.rec.audit.(TemporaryPasswordRecorder)
	if !ok {
		panic("capability: NewTemporaryPasswords: the AuditSink must also be a TemporaryPasswordRecorder; without it an issuance cannot be recorded atomically")
	}
	return &TemporaryPasswords{control: control, rec: rec, status: status, now: time.Now}
}

// CreateHumanAccount creates the human Account a with a generated temporary
// password, authorized at ControlAccountCreate and ControlTemporaryPasswordIssue
// and recorded as one account_create and one password_temporary_set in the
// transaction that makes the Account. A machine Account never holds a
// password: accounts.ErrMachinePassword, recording nothing.
func (t *TemporaryPasswords) CreateHumanAccount(ctx context.Context, p Principal, a accounts.Account) (accounts.Account, accounts.TemporaryPassword, error) {
	if t.rec == nil {
		return accounts.Account{}, accounts.TemporaryPassword{}, ErrTemporaryPasswordsUnavailable
	}
	for _, act := range []ControlAction{ControlAccountCreate, ControlTemporaryPasswordIssue} {
		if err := t.control.authz.AuthorizeControl(withoutAssertions(ctx), p, act); err != nil {
			return accounts.Account{}, accounts.TemporaryPassword{}, t.control.rec.refuseControl(ctx, p, err)
		}
	}
	if a.Kind != accounts.KindHuman {
		return accounts.Account{}, accounts.TemporaryPassword{}, accounts.ErrMachinePassword
	}
	tp, h, err := t.generate()
	if err != nil {
		return accounts.Account{}, accounts.TemporaryPassword{}, err
	}
	created, err := t.rec.RecordAccountCreateWithTemporaryPassword(ctx, TemporaryPasswordEvent{
		Principal: p,
		Hash:      h,
		ExpiresAt: tp.ExpiresAt,
		Asserted:  AssertionsFromContext(ctx),
	}, a)
	if err != nil {
		return accounts.Account{}, accounts.TemporaryPassword{}, err
	}
	return created, tp, nil
}

// IssueTemporaryPassword issues accountID a fresh temporary password, replacing
// any previous one, while the Account's human has never set their own. Store
// refusals (accounts.ErrPasswordOwned, ErrMachinePassword, ErrNotFound) return
// unwrapped and unrecorded: nothing changed.
func (t *TemporaryPasswords) IssueTemporaryPassword(ctx context.Context, p Principal, accountID string) (accounts.TemporaryPassword, error) {
	if t.rec == nil || t.sessions == nil {
		return accounts.TemporaryPassword{}, ErrTemporaryPasswordsUnavailable
	}
	if err := t.control.authz.AuthorizeControl(withoutAssertions(ctx), p, ControlTemporaryPasswordIssue); err != nil {
		return accounts.TemporaryPassword{}, t.control.rec.refuseControl(ctx, p, err)
	}
	tp, h, err := t.generate()
	if err != nil {
		return accounts.TemporaryPassword{}, err
	}
	if err := t.rec.RecordTemporaryPasswordIssue(ctx, TemporaryPasswordEvent{
		Principal: p,
		AccountID: accountID,
		Hash:      h,
		ExpiresAt: tp.ExpiresAt,
		Asserted:  AssertionsFromContext(ctx),
	}); err != nil {
		return accounts.TemporaryPassword{}, err
	}
	// After the record commits: the new credential is in force, so every
	// session opened with the one it replaced ends.
	t.sessions.EndAllFor(accountID)
	return tp, nil
}

// PasswordStatus reports whether accountID's human has set their own password
// and when any temporary one expires. Authorized at ControlAccountRead;
// records nothing on success.
func (t *TemporaryPasswords) PasswordStatus(ctx context.Context, p Principal, accountID string) (accounts.PasswordStatus, error) {
	if t.status == nil {
		return accounts.PasswordStatus{}, ErrTemporaryPasswordsUnavailable
	}
	if err := t.control.authz.AuthorizeControl(withoutAssertions(ctx), p, ControlAccountRead); err != nil {
		return accounts.PasswordStatus{}, t.control.rec.refuseControl(ctx, p, err)
	}
	return t.status.Status(ctx, accountID)
}

// generate mints a temporary password and its hash. The expiry is stamped with
// this object's clock; the sign-in check against it uses the session store's,
// which is the authoritative one.
func (t *TemporaryPasswords) generate() (accounts.TemporaryPassword, accounts.PasswordHash, error) {
	tp, err := accounts.GenerateTemporaryPassword(t.now())
	if err != nil {
		return accounts.TemporaryPassword{}, accounts.PasswordHash{}, err
	}
	h, err := accounts.HashPassword(tp.Password)
	if err != nil {
		return accounts.TemporaryPassword{}, accounts.PasswordHash{}, err
	}
	return tp, h, nil
}
