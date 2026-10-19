package auditsink

// hostlever.go builds the audit records for the host-side credential levers
// (`relay console-password`, `relay bootstrap-token`) and for the host's
// configuration reload (SIGHUP).
//
// These are record BUILDERS, not Sink methods: Sink.append is a write of its
// own, and the fail-closed rule for these acts needs the record and the
// credential change in ONE transaction, which only the store can open. The
// caller hands the built record to the store, which writes both or neither.
//
// No builder takes a password, hash, token value or other secret, so a record
// structurally cannot carry one. The reload builders admit only members of the
// configuration schema's closed key set and fixed stage phrases.

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/relayconfig"
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
// by `relay bootstrap-token`. The Reason is the API mint's own, byte for byte,
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

// ReloadStage is the point at which a configuration reload was refused. Its
// String is a fixed phrase, so no error text can reach a record's Reason.
type ReloadStage int

const (
	ReloadRefusedFile ReloadStage = iota + 1
	ReloadRefusedRestart
	ReloadRefusedNamedFiles
	ReloadRefusedCA
	ReloadRefusedSettings
	ReloadRefusedAudit
	ReloadRefusedInternal
)

func (s ReloadStage) String() string {
	switch s {
	case ReloadRefusedFile:
		return "the configuration file was refused (file check, decode or validation)"
	case ReloadRefusedRestart:
		return "restart required"
	case ReloadRefusedNamedFiles:
		return "a file the configuration names, or the store or CA directory, was refused"
	case ReloadRefusedCA:
		return "restart required: the CA on disk is not the CA this Relay is running"
	case ReloadRefusedSettings:
		return "an operator setting was refused"
	case ReloadRefusedAudit:
		return "the reload's audit record could not be written"
	case ReloadRefusedInternal:
		return "the reload failed unexpectedly"
	}
	return ""
}

// settingKeys checks that every key is a member of the schema's closed key
// set, which a value can never be.
func settingKeys(keys []string) error {
	for _, k := range keys {
		if !relayconfig.IsSettingKey(k) {
			return errors.New("auditsink: a reload record names only configuration setting keys")
		}
	}
	return nil
}

// HostConfigReloadRecord builds the config_reload record for a reload the host
// applied. changed holds setting keys, never values; a secret setting appears
// by key like any other (RC-18).
func HostConfigReloadRecord(id string, now time.Time, changed []string) (audit.Record, error) {
	if id == "" {
		return audit.Record{}, errors.New("auditsink: a host reload record needs an audit id")
	}
	if err := settingKeys(changed); err != nil {
		return audit.Record{}, err
	}
	reason := "configuration reloaded on the Relay host; no setting changed"
	if len(changed) > 0 {
		reason = "configuration reloaded on the Relay host; changed: " + strings.Join(changed, ", ")
	}
	return hostRecord(id, now, audit.KindConfigReload, reason), nil
}

// HostConfigReloadRefusedRecord builds the config_reload_refused record for a
// reload the Relay refused. restartRequired holds the setting keys that need a
// restart, and is required exactly when stage is ReloadRefusedRestart.
func HostConfigReloadRefusedRecord(id string, now time.Time, stage ReloadStage, restartRequired []string) (audit.Record, error) {
	if id == "" {
		return audit.Record{}, errors.New("auditsink: a host reload record needs an audit id")
	}
	phrase := stage.String()
	if phrase == "" {
		return audit.Record{}, errors.New("auditsink: unknown reload stage")
	}
	if (stage == ReloadRefusedRestart) != (len(restartRequired) > 0) {
		return audit.Record{}, errors.New("auditsink: restart-required keys belong to the restart stage, and only to it")
	}
	if err := settingKeys(restartRequired); err != nil {
		return audit.Record{}, err
	}
	if stage == ReloadRefusedRestart {
		phrase += ": " + strings.Join(restartRequired, ", ")
	}
	return hostRecord(id, now, audit.KindConfigReloadRefused,
		"configuration reload refused on the Relay host; "+phrase), nil
}
