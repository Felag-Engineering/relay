package capability

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
)

// accountadmin.go is Account and API-Token administration (#653): the eight
// ControlActions floored at admin (authz.RoleGate's requiredControlRole),
// each authorized, acted on, and — for a write — audited through the same
// capability pipeline as every other administrative act (EngageFreeze,
// CancelJob).
//
// It lives HERE, in the capability layer, rather than behind an adapter of
// its own, because invariant 10 requires MCP, the Control API, and the
// Console to inherit one answer to "who may administer Accounts" — and
// because docs/specs/accounts-and-access.md names today's per-route check as
// "a gap to close, not an accepted adapter split". Before this file, the
// Control API declared its own AccountManager/APITokenService interfaces
// bound straight to accounts.Repository/TokenService and gated role in its
// own handlers (requireAdmin); that is the second control path this file
// closes.
//
// WHICH RULE IS DELIBERATELY NOT HERE: the last-enabled-admin guard. That
// rule is a COUNT over the whole accounts table, not a property this layer
// can decide from the one row a caller named, and a check-then-write above
// the store would race another writer between the count and the write —
// exactly the argument internal/store/accounts.go already makes for
// ErrNameTaken (see its insert, and SetRole/SetEnabled's doc comments in
// internal/accounts/accounts.go). It is enforced in one guarded UPDATE, in
// the store, and surfaces here only as accounts.ErrLastAdmin bubbling up
// from SetAccountRole/SetAccountEnabled.
//
// READS RECORD NOTHING. Accounts, Account, and APITokens are authorized and
// answered, but write no audit row on success — matching the Control API's
// behaviour before this issue. A REFUSED read is still recorded, through the
// same refuseControl every write's refusal goes through; only a successful
// read is silent. This is load-bearing for the Control API's own audit-trail
// tests, which expect a create/mint to be the only rows a read-only session
// produces.

// ErrAccountsUnavailable is returned by every method in this file when the
// Service was built without WithAccountAdmin — mirrors ErrQueriesUnavailable
// (readlane.go): never an empty slice or a zero Account, either of which
// would be a claim about state this Service has not actually looked at.
var ErrAccountsUnavailable = errors.New("capability: account administration is not configured on this Relay")

// ErrSelfTargeted is returned by SetAccountRole and by SetAccountEnabled(id,
// false) when the acting Principal names itself: "an Account cannot change
// its own role or disable itself" (#653's own acceptance criterion). This is
// the ONLY rule in this file that needs the ACTING Principal, which is why it
// lives here rather than in the store: accounts.Repository has no notion of
// who is asking, only what is being asked.
//
// Exported and typed like ErrJobNotRequestedByCaller, so a surface recognizes
// it via errors.Is without string-matching. The refusal is audited via
// refuseControl exactly like a role-floor denial.
var ErrSelfTargeted = errors.New("capability: an account cannot change its own role or disable itself")

// Accounts lists every Account (#653). Authorized at ControlAccountRead;
// records nothing on success (see this file's header).
func (s *Service) Accounts(ctx context.Context, p Principal) ([]accounts.Account, error) {
	if s.accountsStore == nil {
		return nil, ErrAccountsUnavailable
	}
	if err := s.authz.AuthorizeControl(withoutAssertions(ctx), p, ControlAccountRead); err != nil {
		return nil, s.refuseControl(ctx, p, err)
	}
	return s.accountsStore.List(ctx)
}

// Account reads one Account by id (#653). Authorized at ControlAccountRead;
// records nothing on success.
func (s *Service) Account(ctx context.Context, p Principal, id string) (accounts.Account, error) {
	if s.accountsStore == nil {
		return accounts.Account{}, ErrAccountsUnavailable
	}
	if err := s.authz.AuthorizeControl(withoutAssertions(ctx), p, ControlAccountRead); err != nil {
		return accounts.Account{}, s.refuseControl(ctx, p, err)
	}
	return s.accountsStore.Get(ctx, id)
}

// CreateAccount creates a new Account (#653). Authorized at
// ControlAccountCreate; the create is audited (AccountAdminCreate) with the
// Account's assigned id, name, kind, and initial role.
func (s *Service) CreateAccount(ctx context.Context, p Principal, a accounts.Account) (accounts.Account, error) {
	if s.accountsStore == nil {
		return accounts.Account{}, ErrAccountsUnavailable
	}
	if err := s.authz.AuthorizeControl(withoutAssertions(ctx), p, ControlAccountCreate); err != nil {
		return accounts.Account{}, s.refuseControl(ctx, p, err)
	}

	created, err := s.accountsStore.Create(ctx, a)
	if err != nil {
		return accounts.Account{}, err
	}

	if auditErr := s.audit.RecordAccountAdmin(ctx, p, AccountAdminEvent{
		Kind:        AccountAdminCreate,
		AccountID:   created.ID,
		AccountName: created.Name,
		Role:        string(created.Role),
		AccountKind: string(created.Kind),
		Asserted:    AssertionsFromContext(ctx),
	}); auditErr != nil {
		return created, fmt.Errorf("capability: record audit entry: %w", auditErr)
	}
	return created, nil
}

// SetAccountRole changes id's role (#653). Authorized at ControlAccountRole;
// refused with ErrSelfTargeted if the acting Principal names itself
// (invariant: an Account cannot elevate itself); refused with
// accounts.ErrLastAdmin if it would demote the last enabled admin (enforced
// in the store, not here — see this file's header). The change is audited
// (AccountAdminRole) with the new role.
func (s *Service) SetAccountRole(ctx context.Context, p Principal, id string, role accounts.Role) error {
	if s.accountsStore == nil {
		return ErrAccountsUnavailable
	}
	if err := s.authz.AuthorizeControl(withoutAssertions(ctx), p, ControlAccountRole); err != nil {
		return s.refuseControl(ctx, p, err)
	}
	if p.AccountID != "" && p.AccountID == id {
		return s.refuseControl(ctx, p, ErrSelfTargeted)
	}

	if err := s.accountsStore.SetRole(ctx, id, role); err != nil {
		return err
	}

	if auditErr := s.audit.RecordAccountAdmin(ctx, p, AccountAdminEvent{
		Kind:      AccountAdminRole,
		AccountID: id,
		Role:      string(role),
		Asserted:  AssertionsFromContext(ctx),
	}); auditErr != nil {
		return fmt.Errorf("capability: record audit entry: %w", auditErr)
	}
	return nil
}

// SetAccountEnabled enables or disables id (#653). Authorized at
// ControlAccountEnable/ControlAccountDisable depending on enabled; a disable
// is refused with ErrSelfTargeted if the acting Principal names itself, and
// with accounts.ErrLastAdmin if it would disable the last enabled admin
// (enforced in the store). Enabling is never self-targeting-refused: this
// mirrors the Control API's own rule that only self-DISABLE and self-
// re-role are lockout risks. The change is audited (AccountAdminEnable/
// AccountAdminDisable).
func (s *Service) SetAccountEnabled(ctx context.Context, p Principal, id string, enabled bool) error {
	if s.accountsStore == nil {
		return ErrAccountsUnavailable
	}
	act := ControlAccountEnable
	kind := AccountAdminEnable
	if !enabled {
		act = ControlAccountDisable
		kind = AccountAdminDisable
	}
	if err := s.authz.AuthorizeControl(withoutAssertions(ctx), p, act); err != nil {
		return s.refuseControl(ctx, p, err)
	}
	if !enabled && p.AccountID != "" && p.AccountID == id {
		return s.refuseControl(ctx, p, ErrSelfTargeted)
	}

	if err := s.accountsStore.SetEnabled(ctx, id, enabled); err != nil {
		return err
	}

	if auditErr := s.audit.RecordAccountAdmin(ctx, p, AccountAdminEvent{
		Kind:      kind,
		AccountID: id,
		Asserted:  AssertionsFromContext(ctx),
	}); auditErr != nil {
		return fmt.Errorf("capability: record audit entry: %w", auditErr)
	}
	return nil
}

// APITokens lists accountID's API Tokens, redacted (#653). Authorized at
// ControlAPITokenRead; records nothing on success.
func (s *Service) APITokens(ctx context.Context, p Principal, accountID string) ([]accounts.APIToken, error) {
	if s.apiTokens == nil {
		return nil, ErrAccountsUnavailable
	}
	if err := s.authz.AuthorizeControl(withoutAssertions(ctx), p, ControlAPITokenRead); err != nil {
		return nil, s.refuseControl(ctx, p, err)
	}
	return s.apiTokens.List(ctx, accountID)
}

// MintAPIToken issues a new credential for accountID (#653). Authorized at
// ControlAPITokenMint. The audit event carries TokenID only — never the
// returned Plaintext, which this method passes back to its caller untouched:
// no log line, no audit field, no error-string interpolation (#653's
// acceptance criterion, "the mint audit row has no field a Plaintext could
// occupy", enforced structurally by AccountAdminEvent's shape).
func (s *Service) MintAPIToken(ctx context.Context, p Principal, accountID, name string, ttl time.Duration) (accounts.APIToken, accounts.Plaintext, error) {
	if s.apiTokens == nil {
		return accounts.APIToken{}, accounts.Plaintext{}, ErrAccountsUnavailable
	}
	if err := s.authz.AuthorizeControl(withoutAssertions(ctx), p, ControlAPITokenMint); err != nil {
		return accounts.APIToken{}, accounts.Plaintext{}, s.refuseControl(ctx, p, err)
	}

	tok, plaintext, err := s.apiTokens.Mint(ctx, accountID, name, ttl)
	if err != nil {
		return accounts.APIToken{}, accounts.Plaintext{}, err
	}

	if auditErr := s.audit.RecordAccountAdmin(ctx, p, AccountAdminEvent{
		Kind:      AccountAdminTokenMint,
		AccountID: accountID,
		TokenID:   tok.ID,
		Asserted:  AssertionsFromContext(ctx),
	}); auditErr != nil {
		return tok, plaintext, fmt.Errorf("capability: record audit entry: %w", auditErr)
	}
	return tok, plaintext, nil
}

// RevokeAPIToken revokes id (#653). Authorized at ControlAPITokenRevoke.
// Idempotent, mirroring accounts.TokenService.Revoke: revoking an
// already-revoked token is a success, not an error, and is still recorded —
// an operator racing themselves mid-incident should not see a failure.
func (s *Service) RevokeAPIToken(ctx context.Context, p Principal, id string) error {
	if s.apiTokens == nil {
		return ErrAccountsUnavailable
	}
	if err := s.authz.AuthorizeControl(withoutAssertions(ctx), p, ControlAPITokenRevoke); err != nil {
		return s.refuseControl(ctx, p, err)
	}

	if err := s.apiTokens.Revoke(ctx, id); err != nil {
		return err
	}

	if auditErr := s.audit.RecordAccountAdmin(ctx, p, AccountAdminEvent{
		Kind:     AccountAdminTokenRevoke,
		TokenID:  id,
		Asserted: AssertionsFromContext(ctx),
	}); auditErr != nil {
		return fmt.Errorf("capability: record audit entry: %w", auditErr)
	}
	return nil
}
