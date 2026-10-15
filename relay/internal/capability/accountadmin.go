package capability

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

// accountadmin.go is Account and API-Token administration: the eight
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
// from SetAccountRole/SetAccountEnabled. The role compare-and-set is
// the same kind of thing: a clause of the store's one UPDATE, not a check in
// this layer.
//
// READS RECORD NOTHING. Accounts, Account, and APITokens are authorized and
// answered, but write no audit row on success — matching the Control API's
// behaviour before this issue. A REFUSED read is still recorded, through the
// same refuseControl every write's refusal goes through; only a successful
// read is silent. This is load-bearing for the Control API's own audit-trail
// tests, which expect a create/mint to be the only rows a read-only session
// produces.

// AccountAdmin is Account and API-Token administration: the eight
// ControlActions above, authorized by the Control's Authorizer and recorded on
// its Recorder's trail. Construct it with NewAccountAdmin.
type AccountAdmin struct {
	control      *Control
	accountStore AccountStore
	tokens       APITokenStore
}

// NewAccountAdmin returns an AccountAdmin over control and the two stores. All
// three are required together — an Account store with no Token store can
// create identities with no way to issue them a credential, and a Token store
// with no Account store cannot resolve whose credential it is minting or
// revoking; passing an incomplete set is a composition-root bug, so it panics
// rather than degrading.
//
// It also requires a real Authorizer AND a real AuditSink, read through
// control: an un-floored Account-administration surface is a fail-open no less
// serious than an un-floored dispatch — every role would pass
// account_role/account_disable/api_token_mint — and an unaudited one means
// "who created this Account" is unanswerable after a compromise, exactly what
// ADR-0025 forbids for the read lane.
func NewAccountAdmin(control *Control, accountStore AccountStore, tokens APITokenStore) *AccountAdmin {
	if control == nil {
		panic("capability: NewAccountAdmin: control must not be nil")
	}
	if accountStore == nil {
		panic("capability: NewAccountAdmin: account store must not be nil")
	}
	if tokens == nil {
		panic("capability: NewAccountAdmin: API token store must not be nil")
	}
	if _, ok := control.authz.(allowAllAuthorizer); ok {
		panic("capability: NewAccountAdmin: requires a real Authorizer (NewControl); allowAllAuthorizer would fail open on every Account/API-Token administration act")
	}
	if _, ok := control.rec.audit.(noopAuditSink); ok {
		panic("capability: NewAccountAdmin: requires a real AuditSink (NewRecorder); noopAuditSink would record no Account/API-Token administration act")
	}
	return newAccountAdmin(control, accountStore, tokens)
}

// newAccountAdmin assembles an AccountAdmin with no checks. Only NewAccountAdmin
// and _test.go files call it; it is the only route to an AccountAdmin with no
// stores.
func newAccountAdmin(control *Control, accountStore AccountStore, tokens APITokenStore) *AccountAdmin {
	return &AccountAdmin{control: control, accountStore: accountStore, tokens: tokens}
}

// ErrAccountsUnavailable is returned by every method in this file on an
// AccountAdmin assembled with no store (unreachable through NewAccountAdmin) —
// mirrors ErrQueriesUnavailable (readlane.go): never an empty slice or a zero
// Account, either of which would be a claim about state this AccountAdmin has
// not actually looked at.
var ErrAccountsUnavailable = errors.New("capability: account administration is not configured on this Relay")

// ErrSelfTargeted is returned by SetAccountRole and by SetAccountEnabled(id,
// false) when the acting Principal names itself: "an Account cannot change
// its own role or disable itself". This is the ONLY rule in this file that
// needs the ACTING Principal, which is why it lives here rather than in the
// store: accounts.Repository has no notion of who is asking, only what is
// being asked.
//
// Exported and typed like ErrJobNotRequestedByCaller, so a surface recognizes
// it via errors.Is without string-matching. The refusal is audited via
// refuseControl exactly like a role-floor denial.
var ErrSelfTargeted = errors.New("capability: an account cannot change its own role or disable itself")

// SelfTargeted reports whether accountID names the acting Principal itself — the one test
// behind ErrSelfTargeted. Exported so a surface can consume the rule (for example to not offer
// a control that would only be refused) rather than re-derive it (invariant 10). Both sides
// must be non-empty: a Principal with no AccountID is never "self".
func SelfTargeted(p Principal, accountID string) bool {
	return p.AccountID != "" && p.AccountID == accountID
}

// Accounts lists every Account. Authorized at ControlAccountRead;
// records nothing on success (see this file's header).
func (a *AccountAdmin) Accounts(ctx context.Context, p Principal) ([]accounts.Account, error) {
	if a.accountStore == nil {
		return nil, ErrAccountsUnavailable
	}
	if err := a.control.authz.AuthorizeControl(withoutAssertions(ctx), p, ControlAccountRead); err != nil {
		return nil, a.control.rec.refuseControl(ctx, p, err)
	}
	return a.accountStore.List(ctx)
}

// Account reads one Account by id. Authorized at ControlAccountRead;
// records nothing on success.
func (a *AccountAdmin) Account(ctx context.Context, p Principal, id string) (accounts.Account, error) {
	if a.accountStore == nil {
		return accounts.Account{}, ErrAccountsUnavailable
	}
	if err := a.control.authz.AuthorizeControl(withoutAssertions(ctx), p, ControlAccountRead); err != nil {
		return accounts.Account{}, a.control.rec.refuseControl(ctx, p, err)
	}
	return a.accountStore.Get(ctx, id)
}

// CreateAccount creates a new Account. Authorized at
// ControlAccountCreate; the create is audited (AccountAdminCreate) with the
// Account's assigned id, name, kind, and initial role.
func (a *AccountAdmin) CreateAccount(ctx context.Context, p Principal, acct accounts.Account) (accounts.Account, error) {
	if a.accountStore == nil {
		return accounts.Account{}, ErrAccountsUnavailable
	}
	if err := a.control.authz.AuthorizeControl(withoutAssertions(ctx), p, ControlAccountCreate); err != nil {
		return accounts.Account{}, a.control.rec.refuseControl(ctx, p, err)
	}

	created, err := a.accountStore.Create(ctx, acct)
	if err != nil {
		return accounts.Account{}, err
	}

	if auditErr := a.control.rec.audit.RecordAccountAdmin(ctx, p, AccountAdminEvent{
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

// SetAccountRole changes id's role. Authorized at ControlAccountRole;
// refused with ErrSelfTargeted if the acting Principal names itself
// (invariant: an Account cannot elevate itself); refused with
// accounts.ErrLastAdmin if it would demote the last enabled admin (enforced
// in the store, not here — see this file's header). The change is audited
// (AccountAdminRole) with the new role.
//
// "Unconditional" for a caller that decided nothing from the current role
// (the Control API). The store write is still a compare-and-set, against the
// role this method reads just after authorizing, so ErrRoleChanged is
// possible only if another writer lands between that read and the UPDATE; the
// caller may simply retry. A surface whose own decision depended on the role
// it read uses SetAccountRoleFrom.
func (a *AccountAdmin) SetAccountRole(ctx context.Context, p Principal, id string, role accounts.Role) error {
	if a.accountStore == nil {
		return ErrAccountsUnavailable
	}
	if err := a.control.authz.AuthorizeControl(withoutAssertions(ctx), p, ControlAccountRole); err != nil {
		return a.control.rec.refuseControl(ctx, p, err)
	}
	if SelfTargeted(p, id) {
		return a.control.rec.refuseControl(ctx, p, ErrSelfTargeted)
	}

	// Validate before the read so an invalid role is a 400 whether or not
	// the Account exists, as it was before the read was added.
	if !role.Valid() {
		return accounts.ErrInvalidRole
	}
	cur, err := a.accountStore.Get(ctx, id)
	if err != nil {
		return err
	}
	return a.setAccountRole(ctx, p, id, cur.Role, role)
}

// SetAccountRoleFrom changes id's role from `from` to `to`, refusing with
// accounts.ErrRoleChanged if the stored role is no longer `from`. For
// a surface whose own decision depended on the role it read (the Console's
// step-up classification): the decision and the write become one
// compare-and-set in the store. Authorized at ControlAccountRole and
// self-target-refused exactly as SetAccountRole is, in the same order.
func (a *AccountAdmin) SetAccountRoleFrom(ctx context.Context, p Principal, id string, from, to accounts.Role) error {
	if a.accountStore == nil {
		return ErrAccountsUnavailable
	}
	if err := a.control.authz.AuthorizeControl(withoutAssertions(ctx), p, ControlAccountRole); err != nil {
		return a.control.rec.refuseControl(ctx, p, err)
	}
	if SelfTargeted(p, id) {
		return a.control.rec.refuseControl(ctx, p, ErrSelfTargeted)
	}
	return a.setAccountRole(ctx, p, id, from, to)
}

// setAccountRole is the post-authorization body shared by SetAccountRole and
// SetAccountRoleFrom. Store refusals (ErrRoleChanged, ErrLastAdmin,
// ErrNotFound, ErrInvalidRole) return unwrapped and unaudited: nothing
// changed, and they are store conflicts, not authorization refusals.
func (a *AccountAdmin) setAccountRole(ctx context.Context, p Principal, id string, from, to accounts.Role) error {
	if err := a.accountStore.SetRole(ctx, id, from, to); err != nil {
		return err
	}

	if auditErr := a.control.rec.audit.RecordAccountAdmin(ctx, p, AccountAdminEvent{
		Kind:      AccountAdminRole,
		AccountID: id,
		Role:      string(to),
		Asserted:  AssertionsFromContext(ctx),
	}); auditErr != nil {
		return fmt.Errorf("capability: record audit entry: %w", auditErr)
	}
	return nil
}

// SetAccountEnabled enables or disables id. Authorized at
// ControlAccountEnable/ControlAccountDisable depending on enabled; a disable
// is refused with ErrSelfTargeted if the acting Principal names itself, and
// with accounts.ErrLastAdmin if it would disable the last enabled admin
// (enforced in the store). Enabling is never self-targeting-refused: this
// mirrors the Control API's own rule that only self-DISABLE and self-
// re-role are lockout risks. The change is audited (AccountAdminEnable/
// AccountAdminDisable).
func (a *AccountAdmin) SetAccountEnabled(ctx context.Context, p Principal, id string, enabled bool) error {
	if a.accountStore == nil {
		return ErrAccountsUnavailable
	}
	act := ControlAccountEnable
	kind := AccountAdminEnable
	if !enabled {
		act = ControlAccountDisable
		kind = AccountAdminDisable
	}
	if err := a.control.authz.AuthorizeControl(withoutAssertions(ctx), p, act); err != nil {
		return a.control.rec.refuseControl(ctx, p, err)
	}
	if !enabled && SelfTargeted(p, id) {
		return a.control.rec.refuseControl(ctx, p, ErrSelfTargeted)
	}

	if err := a.accountStore.SetEnabled(ctx, id, enabled); err != nil {
		return err
	}

	if auditErr := a.control.rec.audit.RecordAccountAdmin(ctx, p, AccountAdminEvent{
		Kind:      kind,
		AccountID: id,
		Asserted:  AssertionsFromContext(ctx),
	}); auditErr != nil {
		return fmt.Errorf("capability: record audit entry: %w", auditErr)
	}
	return nil
}

// APITokens lists accountID's API Tokens, redacted. Authorized at
// ControlAPITokenRead; records nothing on success.
func (a *AccountAdmin) APITokens(ctx context.Context, p Principal, accountID string) ([]accounts.APIToken, error) {
	if a.tokens == nil {
		return nil, ErrAccountsUnavailable
	}
	if err := a.control.authz.AuthorizeControl(withoutAssertions(ctx), p, ControlAPITokenRead); err != nil {
		return nil, a.control.rec.refuseControl(ctx, p, err)
	}
	return a.tokens.List(ctx, accountID)
}

// MintAPIToken issues a new credential for accountID. Authorized at
// ControlAPITokenMint. The audit event carries TokenID only — never the
// returned Plaintext, which this method passes back to its caller untouched:
// no log line, no audit field, no error-string interpolation ("the mint
// audit row has no field a Plaintext could occupy", enforced structurally by
// AccountAdminEvent's shape).
func (a *AccountAdmin) MintAPIToken(ctx context.Context, p Principal, accountID, name string, ttl time.Duration) (accounts.APIToken, accounts.Plaintext, error) {
	if a.tokens == nil {
		return accounts.APIToken{}, accounts.Plaintext{}, ErrAccountsUnavailable
	}
	if err := a.control.authz.AuthorizeControl(withoutAssertions(ctx), p, ControlAPITokenMint); err != nil {
		return accounts.APIToken{}, accounts.Plaintext{}, a.control.rec.refuseControl(ctx, p, err)
	}

	tok, plaintext, err := a.tokens.Mint(ctx, accountID, name, ttl)
	if err != nil {
		return accounts.APIToken{}, accounts.Plaintext{}, err
	}

	if auditErr := a.control.rec.audit.RecordAccountAdmin(ctx, p, AccountAdminEvent{
		Kind:      AccountAdminTokenMint,
		AccountID: accountID,
		TokenID:   tok.ID,
		Asserted:  AssertionsFromContext(ctx),
	}); auditErr != nil {
		return tok, plaintext, fmt.Errorf("capability: record audit entry: %w", auditErr)
	}
	return tok, plaintext, nil
}

// RevokeAPIToken revokes id. Authorized at ControlAPITokenRevoke.
// Idempotent, mirroring accounts.TokenService.Revoke: revoking an
// already-revoked token is a success, not an error, and is still recorded —
// an operator racing themselves mid-incident should not see a failure.
func (a *AccountAdmin) RevokeAPIToken(ctx context.Context, p Principal, id string) error {
	if a.tokens == nil {
		return ErrAccountsUnavailable
	}
	if err := a.control.authz.AuthorizeControl(withoutAssertions(ctx), p, ControlAPITokenRevoke); err != nil {
		return a.control.rec.refuseControl(ctx, p, err)
	}

	if err := a.tokens.Revoke(ctx, id); err != nil {
		return err
	}

	if auditErr := a.control.rec.audit.RecordAccountAdmin(ctx, p, AccountAdminEvent{
		Kind:     AccountAdminTokenRevoke,
		TokenID:  id,
		Asserted: AssertionsFromContext(ctx),
	}); auditErr != nil {
		return fmt.Errorf("capability: record audit entry: %w", auditErr)
	}
	return nil
}
