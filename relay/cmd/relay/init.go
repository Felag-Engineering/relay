package main

// init.go implements `relay init`, the binary's one local act (ADR-0030, amended
// 2026-10-16; RC-28): it creates the first admin, or re-mints an API Token for an
// enabled human admin who has lost theirs. Both exist only because no credential can
// yet exist, or none is left, to do them over the wire; everything else is the Control
// API's or the Console's.
//
// It runs as the Relay's own account, on the store the Relay created at its first
// start, and loads the configuration file through the same start-time check as the
// server, so it refuses to run as root (RC-15). It creates neither the CA nor the store.
//
// Every credential change it makes is in one store transaction with its audit records,
// attributed to local-host rather than to any Account: a change the trail cannot show
// is not made. The credential goes to stdout alone; every diagnostic goes to stderr. The
// password is read from the terminal with echo off, or as one line from a stdin that is
// not a terminal, and never from a flag or the environment (invariant 11).

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/relay/relay/internal/relayconfig"
	"github.com/Felag-Engineering/relay/relay/internal/startup"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

const initUsage = `Usage:
  relay init [--config PATH] [--ttl DURATION] --admin NAME
  relay init [--config PATH] [--ttl DURATION] --recover NAME

Run as the Relay's own account, after the Relay has started once:
  sudo -u relay relay init --admin alice

--admin NAME    On a Relay with no human Account, create the first admin: a human
                admin Account named NAME, its Console password (prompted for, not
                echoed) and its first API Token, which is printed to stdout once.
                With any human Account present it creates nothing, prints no
                credential, and reports what is there.
--recover NAME  Mint a new API Token for NAME, an enabled human admin, and print it
                to stdout once. For an admin who has lost every API Token.
--ttl DURATION  Lifetime of the API Token minted, e.g. 24h. Default 0: no expiry.
--config PATH   The Relay's configuration file (default /etc/relay/relay.toml).

The Console password set by --admin is the only one any surface sets, and nothing
resets it: --recover mints an API Token and never touches a password.

There is no flag that takes the password: a password on a command line is a password
in every process listing and shell history. When stdin is not a terminal, the password
is its first line.

Every act is recorded on the audit trail, attributed to local-host rather than to any
Account, and no record carries a credential. If a record cannot be written, nothing is
changed. Managing Accounts is the Control API's and the Console's, not this command's.
`

// initTokenName and recoveryTokenName label the tokens init mints, so an admin
// reading the Account's tokens can tell which to revoke.
const (
	initTokenName     = "init"
	recoveryTokenName = "recovery"
)

// recordedTokens makes TokenService.Mint write its audit record in the same
// transaction as the token. The token's ID exists only inside Mint, so the
// record is built at CreateToken time; every other method delegates.
type recordedTokens struct {
	accounts.TokenRepository
	st *store.Store
}

func (r recordedTokens) CreateToken(ctx context.Context, t accounts.APIToken) error {
	id, err := hostAuditID()
	if err != nil {
		return fmt.Errorf("generate audit record id: %w", err)
	}
	rec, err := auditsink.HostAPITokenMintRecord(id, time.Now(), t.AccountID, t.ID)
	if err != nil {
		return err
	}
	return r.st.CreateAPITokenRecorded(ctx, t, rec)
}

// initOptions are the validated flags of `relay init`.
type initOptions struct {
	configPath  string
	admin       string
	recoverName string
	ttl         time.Duration
}

// parseInitFlags parses and validates the arguments. done is true when the
// command must stop with exitCode: a parse or validation refusal, or --help.
func parseInitFlags(args []string, stderr *os.File) (opts initOptions, exitCode int, done bool) {
	set := flag.NewFlagSet("init", flag.ContinueOnError)
	set.SetOutput(stderr)
	set.Usage = func() { fmt.Fprint(stderr, initUsage) }
	path := set.String("config", relayconfig.DefaultPath, "path of the Relay's configuration file")
	admin := set.String("admin", "", "name of the first admin to create")
	recoverName := set.String("recover", "", "name of the enabled human admin to mint a new API Token for")
	ttl := set.Duration("ttl", 0, "lifetime of the API Token minted; 0 means no expiry")
	if err := set.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return initOptions{}, 0, true
		}
		return initOptions{}, 2, true
	}
	switch {
	case set.NArg() > 0:
		fmt.Fprintln(stderr, "relay init: takes no positional arguments")
		return initOptions{}, 2, true
	case *path == "":
		fmt.Fprintln(stderr, "relay init: --config must name a file")
		return initOptions{}, 2, true
	case (*admin == "") == (*recoverName == ""):
		fmt.Fprintln(stderr, "relay init: give exactly one of --admin NAME or --recover NAME")
		fmt.Fprint(stderr, initUsage)
		return initOptions{}, 2, true
	case *ttl < 0:
		fmt.Fprintln(stderr, "relay init: --ttl must not be negative")
		return initOptions{}, 2, true
	}
	return initOptions{configPath: *path, admin: *admin, recoverName: *recoverName, ttl: *ttl}, 0, false
}

// openRelayStoreForInit runs the server's own front door, in the server's order
// (ADR-0043): no bypass. It returns the Relay's existing store, or the exit
// code to stop with.
func openRelayStoreForInit(configPath string, envErr error, stderr *os.File) (*store.Store, int) {
	if envErr != nil {
		fmt.Fprintf(stderr, "relay init: %v\n", envErr)
		return nil, 1
	}
	sc, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "relay init: %v\n", err)
		return nil, 1
	}
	for _, w := range sc.Warnings {
		fmt.Fprintf(stderr, "relay init: warning: %s\n", w.String())
	}
	storePath := sc.Config.StorePath
	if err := startup.CheckExistingStore(storePath); err != nil {
		if errors.Is(err, startup.ErrStoreAbsent) {
			fmt.Fprintf(stderr, "relay init: the Relay's store %s does not exist yet. Start the Relay first: it creates its CA and store at its first start, and init acts only on that store.\n", storePath)
			return nil, 1
		}
		fmt.Fprintf(stderr, "relay init: start-time file check refused: %v\n", err)
		return nil, 1
	}
	st, err := store.Open(storePath)
	if err != nil {
		fmt.Fprintf(stderr, "relay init: open store: %v\n", err)
		return nil, 1
	}
	return st, 0
}

// runInitCommand implements `relay init` and returns the process exit code.
// envErr is relayconfig.RefuseRetiredEnv's verdict on the process environment.
func runInitCommand(args []string, envErr error, stdin, stdout, stderr *os.File) int {
	opts, code, done := parseInitFlags(args, stderr)
	if done {
		return code
	}
	st, code := openRelayStoreForInit(opts.configPath, envErr, stderr)
	if st == nil {
		return code
	}
	defer st.Close() //nolint:errcheck

	ctx := context.Background()
	if opts.recoverName != "" {
		return initRecover(ctx, st, opts.recoverName, opts.ttl, stdout, stderr)
	}
	return initFirstAdmin(ctx, st, opts.admin, opts.ttl, stdin, stdout, stderr)
}

// initFirstAdmin creates the first admin on a store with no human Account, or
// reports state and emits nothing.
func initFirstAdmin(ctx context.Context, st *store.Store, name string, ttl time.Duration, stdin, stdout, stderr *os.File) int {
	if err := accounts.ValidateName(name); err != nil {
		fmt.Fprintf(stderr, "relay init: %q is not a valid Account name: 1 to 64 characters of letters, digits, '.', '_' and '-', starting with a letter or digit.\n", name)
		return 2
	}
	// Checked before the prompt, so a re-run never asks for a password it
	// would not use. CreateFirstAdminRecorded checks again inside its
	// transaction.
	all, err := st.Accounts().List(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "relay init: list accounts: %v\n", err)
		return 1
	}
	if reportExisting(all, stderr) {
		return 0
	}
	// A machine Account may already hold the name; refused before the prompt
	// rather than after the operator has typed a password twice.
	for _, a := range all {
		if accounts.NormalizeName(a.Name) == accounts.NormalizeName(name) {
			fmt.Fprintf(stderr, "relay init: an Account named %q already exists (a %s Account); choose another name. Nothing was created.\n", a.Name, a.Kind)
			return 1
		}
	}

	password, err := readNewPassword(stdin, stderr, name)
	if err != nil {
		fmt.Fprintf(stderr, "relay init: %v\n", err)
		fmt.Fprintln(stderr, "Nothing was created.")
		return 1
	}
	if !validPassword(password, stderr) {
		fmt.Fprintln(stderr, "Nothing was created.")
		return 1
	}
	hash, err := accounts.HashPassword(password)
	if err != nil {
		fmt.Fprintf(stderr, "relay init: hash: %v\n", err)
		return 1
	}

	var plaintext accounts.Plaintext
	var tokenID string
	created, err := st.CreateFirstAdminRecorded(ctx, accounts.Account{
		Name: name, Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true,
	}, store.FirstAdminCredentials{
		Password: hash,
		Issue: func(acct accounts.Account) (accounts.APIToken, []audit.Record, error) {
			now := time.Now()
			tok, pt, err := accounts.GenerateToken(acct.ID, initTokenName, ttl, now)
			if err != nil {
				return accounts.APIToken{}, nil, err
			}
			recs, err := firstAdminRecords(now, acct, tok.ID)
			if err != nil {
				return accounts.APIToken{}, nil, err
			}
			plaintext, tokenID = pt, tok.ID
			return tok, recs, nil
		},
	})
	switch {
	case errors.Is(err, accounts.ErrHumanAccountExists):
		fmt.Fprintln(stderr, "relay init: a human Account was created while this command asked for the password; nothing was created and no credential was emitted.")
		return 1
	case errors.Is(err, accounts.ErrNameTaken):
		fmt.Fprintf(stderr, "relay init: an Account named %q already exists; choose another name. Nothing was created.\n", name)
		return 1
	case err != nil:
		fmt.Fprintf(stderr, "relay init: create the first admin: %v\n", err)
		fmt.Fprintln(stderr, "Nothing was created: an Account, password or token that cannot be recorded on the audit trail is not made.")
		return 1
	}

	fmt.Fprintf(stderr, "Created %s (%s), a human admin, with its Console password and its first API Token %s.\n", created.Name, created.ID, tokenID)
	fmt.Fprintf(stderr, "Recorded on the audit trail as %s, %s and %s, attributed to %s.\n",
		audit.KindAccountCreate, audit.KindPasswordSet, audit.KindAPITokenMint, audit.PrincipalLocalHost)
	fmt.Fprintln(stderr, "The API Token below is shown once and cannot be recovered; a lost one is replaced with relay init --recover.")
	fmt.Fprintln(stderr, "Keep the Console password safe: no surface resets it, and relay init --recover does not.")
	return emitCredential(stdout, stderr, plaintext.Reveal(), tokenID)
}

// firstAdminRecords builds the three records of the first admin's creation, in
// the order the acts happen.
func firstAdminRecords(now time.Time, acct accounts.Account, tokenID string) ([]audit.Record, error) {
	ids := make([]string, 3)
	for i := range ids {
		id, err := hostAuditID()
		if err != nil {
			return nil, fmt.Errorf("generate audit record id: %w", err)
		}
		ids[i] = id
	}
	create, err := auditsink.HostAccountCreateRecord(ids[0], now, acct.ID, acct.Name, string(acct.Kind), string(acct.Role))
	if err != nil {
		return nil, err
	}
	password, err := auditsink.HostPasswordSetRecord(ids[1], now, acct.ID, acct.Name)
	if err != nil {
		return nil, err
	}
	mint, err := auditsink.HostAPITokenMintRecord(ids[2], now, acct.ID, tokenID)
	if err != nil {
		return nil, err
	}
	return []audit.Record{create, password, mint}, nil
}

// reportExisting reports the human Accounts on a store that has them and returns
// true; on a store with none it says nothing and returns false.
func reportExisting(all []accounts.Account, stderr io.Writer) bool {
	var humans int
	var admins []string
	for _, a := range all {
		if a.Kind != accounts.KindHuman {
			continue
		}
		humans++
		if a.Role == accounts.RoleAdmin && a.Enabled {
			admins = append(admins, a.Name)
		}
	}
	if humans == 0 {
		return false
	}
	fmt.Fprintf(stderr, "relay init: this Relay already has %d human Account(s), so its first admin exists. Nothing was created and no credential was emitted.\n", humans)
	if len(admins) == 0 {
		fmt.Fprintln(stderr, "No human admin is enabled, so relay init --recover has no Account to mint for.")
		fmt.Fprintln(stderr, "The way out: an enabled admin, a machine Account included, re-enables one through the Control API")
		fmt.Fprintln(stderr, "(POST /api/v1/accounts/{id}/enable). With no enabled admin at all, recovery is local root acting on")
		fmt.Fprintln(stderr, "the store directly; see docs/operations/control-plane-credential.md.")
	} else {
		fmt.Fprintf(stderr, "Enabled human admins: %s.\n", strings.Join(admins, ", "))
		fmt.Fprintln(stderr, "An enabled human admin who has lost every API Token gets a new one with: relay init --recover NAME")
	}
	fmt.Fprintln(stderr, "Further Accounts are created through the Control API or the Console.")
	return true
}

// initRecover re-mints an API Token for an enabled human admin.
func initRecover(ctx context.Context, st *store.Store, name string, ttl time.Duration, stdout, stderr *os.File) int {
	// Naming the Account in a refusal is fine here: this caller can read the
	// store, so there is nothing to enumerate that it cannot already read.
	acct, err := st.Accounts().GetByName(ctx, name)
	switch {
	case errors.Is(err, accounts.ErrNotFound):
		fmt.Fprintf(stderr, "relay init: no Account named %q; nothing was minted.\n", name)
		return 1
	case err != nil:
		fmt.Fprintf(stderr, "relay init: look up %q: %v\n", name, err)
		return 1
	case acct.Kind != accounts.KindHuman:
		fmt.Fprintf(stderr, "relay init: %s is a machine Account; recovery is for a human admin. Nothing was minted.\n", acct.Name)
		fmt.Fprintln(stderr, "A machine Account's tokens are minted by an admin through the Control API or the Console.")
		return 1
	case acct.Role != accounts.RoleAdmin:
		fmt.Fprintf(stderr, "relay init: %s has role %s, not admin; recovery is for a human admin. Nothing was minted.\n", acct.Name, acct.Role)
		return 1
	case !acct.Enabled:
		// Refuse rather than re-enable: disabling an Account retires its
		// authority on purpose, and minting it a credential here would undo
		// that decision where nobody is watching.
		fmt.Fprintf(stderr, "relay init: %s is disabled; refusing to mint a credential for it. Nothing was minted.\n", acct.Name)
		fmt.Fprintln(stderr, "Another admin re-enables it deliberately, through the Control API or the Console, if that is what you want.")
		return 1
	}

	tokenSvc := accounts.NewTokenService(recordedTokens{TokenRepository: st.APITokens(), st: st}, st.Accounts(), nil)
	tok, plaintext, err := tokenSvc.Mint(ctx, acct.ID, recoveryTokenName, ttl)
	if err != nil {
		fmt.Fprintf(stderr, "relay init: mint: %v\n", err)
		fmt.Fprintln(stderr, "No token was minted: a credential that cannot be recorded on the audit trail is not issued.")
		return 1
	}
	fmt.Fprintf(stderr, "Minted API Token %s for %s (%s).\n", tok.ID, acct.Name, acct.ID)
	fmt.Fprintf(stderr, "Recorded on the audit trail as %s, attributed to %s.\n", audit.KindAPITokenMint, audit.PrincipalLocalHost)
	fmt.Fprintln(stderr, "Tokens it no longer holds stay valid until revoked; revoke them once this one works.")
	fmt.Fprintln(stderr, "Its Console password is unchanged: no surface resets a Console password.")
	fmt.Fprintln(stderr, "The API Token below is shown once and cannot be recovered.")
	return emitCredential(stdout, stderr, plaintext.Reveal(), tok.ID)
}

// emitCredential writes the credential, alone, to stdout. A write that fails
// leaves a minted token nobody received, so it says which token to revoke and
// fails the command.
func emitCredential(stdout, stderr io.Writer, credential, tokenID string) int {
	if _, err := fmt.Fprintln(stdout, credential); err != nil {
		fmt.Fprintf(stderr, "relay init: writing the API Token to stdout failed: %v\n", err)
		fmt.Fprintf(stderr, "Token %s was minted and recorded but not delivered: revoke it (DELETE /api/v1/api-tokens/%s), and mint another with relay init --recover.\n", tokenID, tokenID)
		return 1
	}
	return 0
}

// readNewPassword reads the first admin's Console password: on a terminal,
// twice with echo off; otherwise the first line of stdin.
func readNewPassword(stdin *os.File, prompt io.Writer, name string) (accounts.Password, error) {
	if isTerminal(stdin) {
		first, err := promptNoEcho(stdin, prompt, fmt.Sprintf("Console password for %s (not echoed): ", name))
		if err != nil {
			return accounts.Password{}, err
		}
		second, err := promptNoEcho(stdin, prompt, "Again: ")
		if err != nil {
			return accounts.Password{}, err
		}
		if first != second {
			return accounts.Password{}, errors.New("the two passwords differ")
		}
		return accounts.NewPassword(first), nil
	}
	line, err := readLine(stdin)
	if err != nil {
		return accounts.Password{}, fmt.Errorf("read password from stdin: %w", err)
	}
	return accounts.NewPassword(line), nil
}

// promptNoEcho writes label to prompt, reads one line from the terminal with
// echo off, and ends the prompt's line.
func promptNoEcho(term *os.File, prompt io.Writer, label string) (string, error) {
	fmt.Fprint(prompt, label)
	line, err := readNoEcho(term)
	fmt.Fprintln(prompt)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return line, nil
}

// maxPromptBytes bounds a password read from stdin: one byte past the longest
// the Relay accepts, so an over-long one is refused as too long rather than
// truncated into a different password. A terminal has its own, lower, limit:
// see terminalLineLimit.
const maxPromptBytes = accounts.MaxPasswordBytes + 1

// readLine reads one line from r, without its line ending, reading no further
// than maxPromptBytes plus the line ending.
func readLine(r io.Reader) (string, error) {
	line, err := bufio.NewReader(io.LimitReader(r, maxPromptBytes+2)).ReadString('\n')
	if err != nil && line == "" {
		if errors.Is(err, io.EOF) {
			return "", errors.New("stdin is empty")
		}
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// validPassword says why a password is refused, or returns true.
func validPassword(p accounts.Password, stderr io.Writer) bool {
	err := p.Validate()
	switch {
	case err == nil:
		return true
	case errors.Is(err, accounts.ErrPasswordTooShort):
		fmt.Fprintf(stderr, "relay init: the password is shorter than %d characters.\n", accounts.MinPasswordBytes)
		// The reason, so the operator picks a passphrase rather than the
		// shortest thing that passes.
		fmt.Fprintln(stderr, "The Console's throttle deliberately has no lockout, so length is what makes slow guessing hopeless.")
	case errors.Is(err, accounts.ErrPasswordTooLong):
		fmt.Fprintf(stderr, "relay init: the password is longer than %d bytes.\n", accounts.MaxPasswordBytes)
	default:
		fmt.Fprintf(stderr, "relay init: %v\n", err)
	}
	return false
}
