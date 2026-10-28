package auditsink

import (
	"context"
	"fmt"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
)

// passwords.go records the Console password acts of ADR-0045. Every Reason
// starts with account_id= so Access draws the subject, and none carries a
// password or a hash: the events hold only a hash, and nothing here reads it
// into text. Logs name the kind and the Account id only.

// RecordAccountCreateWithTemporaryPassword implements
// capability.TemporaryPasswordRecorder: the Account, its temporary password, an
// account_create record and a password_temporary_set record commit in one
// transaction. A repository that cannot make them atomic refuses before an id
// is minted.
func (s *Sink) RecordAccountCreateWithTemporaryPassword(ctx context.Context, e capability.TemporaryPasswordEvent, a accounts.Account) (accounts.Account, error) {
	app, ok := s.repo.(audit.PasswordAppender)
	if !ok {
		return accounts.Account{}, fmt.Errorf("auditsink: the audit repository cannot record a temporary password atomically: %w", capability.ErrTemporaryPasswordsUnavailable)
	}
	createID, err := s.newID()
	if err != nil {
		return accounts.Account{}, fmt.Errorf("auditsink: record temporary password: generate audit record id: %w", err)
	}
	issueID, err := s.newID()
	if err != nil {
		return accounts.Account{}, fmt.Errorf("auditsink: record temporary password: generate audit record id: %w", err)
	}
	now := s.now()
	created, err := app.AppendWithTemporaryAccount(ctx, a, e.Hash, e.ExpiresAt, func(created accounts.Account) ([]audit.Record, error) {
		create := s.passwordRecord(createID, now, audit.KindAccountCreate, e.Principal, e.Asserted,
			accountAdminReason(capability.AccountAdminEvent{
				Kind:        capability.AccountAdminCreate,
				AccountID:   created.ID,
				AccountName: created.Name,
				AccountKind: string(created.Kind),
				Role:        string(created.Role),
			}))
		issue := s.passwordRecord(issueID, now, audit.KindPasswordTemporarySet, e.Principal, e.Asserted,
			fmt.Sprintf("account_id=%s name=%s expires_at=%s", created.ID, created.Name, expiresAt(e.ExpiresAt)))
		return []audit.Record{create, issue}, nil
	})
	if err != nil {
		return accounts.Account{}, err
	}
	s.log.Info("account created with a temporary password", "principal", e.Principal.Attribution(), "account_id", created.ID)
	return created, nil
}

// RecordTemporaryPasswordIssue implements capability.TemporaryPasswordRecorder
// for a re-issue.
func (s *Sink) RecordTemporaryPasswordIssue(ctx context.Context, e capability.TemporaryPasswordEvent) error {
	app, ok := s.repo.(audit.PasswordAppender)
	if !ok {
		return fmt.Errorf("auditsink: the audit repository cannot record a temporary password atomically: %w", capability.ErrTemporaryPasswordsUnavailable)
	}
	id, err := s.newID()
	if err != nil {
		return fmt.Errorf("auditsink: record temporary password: generate audit record id: %w", err)
	}
	rec := s.passwordRecord(id, s.now(), audit.KindPasswordTemporarySet, e.Principal, e.Asserted,
		fmt.Sprintf("account_id=%s expires_at=%s", e.AccountID, expiresAt(e.ExpiresAt)))
	if err := app.AppendWithTemporaryPassword(ctx, e.AccountID, e.Hash, e.ExpiresAt, rec); err != nil {
		return err
	}
	s.log.Info("temporary password issued", "principal", rec.Principal, "account_id", e.AccountID)
	return nil
}

// RecordPasswordChange implements consoleauth.PasswordChangeRecorder: the new
// password and its password_change record commit in one transaction. The
// verified lane is the acting Account, which is also the subject.
func (s *Sink) RecordPasswordChange(ctx context.Context, e consoleauth.PasswordChangeEvent) error {
	app, ok := s.repo.(audit.PasswordAppender)
	if !ok {
		return fmt.Errorf("auditsink: the audit repository cannot record a password change atomically: %w", consoleauth.ErrPasswordChangeUnavailable)
	}
	id, err := s.newID()
	if err != nil {
		return fmt.Errorf("auditsink: record password change: generate audit record id: %w", err)
	}
	// forced= precedes every field that could carry free text; the only field
	// before it is the Relay-minted account_id, so a reader that matches on it
	// cannot be fed by anything further along.
	rec := audit.Record{
		ID:        id,
		Timestamp: s.now(),
		Kind:      audit.KindPasswordChange,
		Principal: e.Account + ":" + e.Role,
		Attribution: audit.Attribution{
			Verified: audit.Verified{
				AccountID:   e.AccountID,
				AccountName: e.Account,
				Role:        e.Role,
				Method:      e.Method,
				Source:      e.Source,
			},
		},
		Reason: fmt.Sprintf("account_id=%s forced=%t other_sessions_ended=%d", e.AccountID, e.Forced, e.SessionsEnded),
	}
	if err := app.AppendWithPasswordChange(ctx, e.AccountID, e.Expect, e.New, rec); err != nil {
		return err
	}
	s.log.Info("password changed", "account_id", e.AccountID)
	return nil
}

func (s *Sink) passwordRecord(id string, now time.Time, kind string, p capability.Principal, a capability.Assertions, reason string) audit.Record {
	return audit.Record{
		ID:          id,
		Timestamp:   now,
		Kind:        kind,
		Principal:   p.Attribution(),
		Attribution: attribution(p, a),
		Reason:      reason,
	}
}

func expiresAt(t time.Time) string { return t.UTC().Format(time.RFC3339) }
