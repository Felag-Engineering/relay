package auditsink

// hostlever.go builds the audit records for the host-side credential lever,
// `relay init`: the first admin's creation, Console password and first API
// Token, and a recovery re-mint.
//
// These are record BUILDERS, not Sink methods: Sink.append is a write of its
// own, and the fail-closed rule for these acts needs the record and the
// credential change in ONE transaction, which only the store can open. The
// caller hands the built record to the store, which writes both or neither.
//
// No builder takes a password, hash, token value or other secret, so a record
// structurally cannot carry one.

import (
	"errors"
	"fmt"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

// hostPrincipal is root on the Relay host: role-less and AccountID-less,
// exactly what capability.localHostPrincipal is, so these rows attribute
// identically to a freeze_engage from the local signal.
func hostPrincipal() capability.Principal {
	return capability.Principal{Account: audit.PrincipalLocalHost}
}

func hostRecord(id string, now time.Time, kind, reason string) audit.Record {
	p := hostPrincipal()
	return audit.Record{
		ID:          id,
		Timestamp:   now.UTC(),
		Kind:        kind,
		Principal:   p.Attribution(),
		Attribution: attribution(p, capability.Assertions{}),
		Reason:      reason,
	}
}

// HostAccountCreateRecord builds the account_create record for the first
// admin, created by `relay init`. The Reason is the API create's own, byte for
// byte, so a trail query for one matches the other; attribution tells them
// apart.
func HostAccountCreateRecord(id string, now time.Time, accountID, accountName, kind, role string) (audit.Record, error) {
	if id == "" || accountID == "" || accountName == "" || kind == "" || role == "" {
		return audit.Record{}, errors.New("auditsink: a host account-create record needs an audit id, an account id, a name, a kind and a role")
	}
	reason := accountAdminReason(capability.AccountAdminEvent{
		Kind: capability.AccountAdminCreate, AccountID: accountID, AccountName: accountName,
		AccountKind: kind, Role: role,
	})
	return hostRecord(id, now, audit.KindAccountCreate, reason), nil
}

// HostPasswordSetRecord builds the password_set record for a Console password
// set on the named Account by the host lever. It names the Account, never the
// password or its hash.
func HostPasswordSetRecord(id string, now time.Time, accountID, accountName string) (audit.Record, error) {
	if id == "" || accountID == "" {
		return audit.Record{}, errors.New("auditsink: a host password record needs an audit id and an account id")
	}
	return hostRecord(id, now, audit.KindPasswordSet,
		fmt.Sprintf("account_id=%s name=%s", accountID, accountName)), nil
}

// HostPasswordClearRecord builds the password_clear record for the host
// lever's -clear. removed says whether a password was actually there to
// remove: clearing an Account with none is not an error, but the trail must
// not claim a password was removed when none was.
func HostPasswordClearRecord(id string, now time.Time, accountID, accountName string, removed bool) (audit.Record, error) {
	if id == "" || accountID == "" {
		return audit.Record{}, errors.New("auditsink: a host password record needs an audit id and an account id")
	}
	return hostRecord(id, now, audit.KindPasswordClear,
		fmt.Sprintf("account_id=%s name=%s removed=%t", accountID, accountName, removed)), nil
}

// HostAPITokenMintRecord builds the api_token_mint record for a token minted
// by `relay init`, first or recovered. The Reason is the API mint's own, byte for byte,
// so a trail query for one matches the other; attribution tells them apart.
// It carries the token's public ID, never its secret.
func HostAPITokenMintRecord(id string, now time.Time, accountID, tokenID string) (audit.Record, error) {
	if id == "" || accountID == "" || tokenID == "" {
		return audit.Record{}, errors.New("auditsink: a host token-mint record needs an audit id, an account id and a token id")
	}
	reason := accountAdminReason(capability.AccountAdminEvent{
		Kind: capability.AccountAdminTokenMint, AccountID: accountID, TokenID: tokenID,
	})
	return hostRecord(id, now, audit.KindAPITokenMint, reason), nil
}
