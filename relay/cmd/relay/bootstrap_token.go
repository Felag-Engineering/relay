package main

// bootstrap_token.go implements `relay bootstrap-token`: the local, root-owned
// lever that mints the founding admin Account's first API Token (ADR-0023).
//
// It exists because retiring the config-seeded shared credential leaves
// a chicken-and-egg problem — minting an Account's token requires
// authenticating, and authenticating requires a token. The way out is the same
// one ADR-0002 uses for Node Policy: root the first credential *locally*, in
// the filesystem, rather than over the wire. Anyone who can run this already
// has read/write access to the Relay's store file and could forge any row in
// it; the subcommand grants no authority that local root did not already have,
// it only makes the intended path an obvious one-liner instead of a SQL edit.
//
// Minting writes one api_token_mint audit record, attributed to the principal
// local-host rather than to any Account, in the SAME transaction as the token.
// If the record cannot be written no token is issued: a credential the
// trail cannot show is not issued. The record names the token's public ID and
// never its value.
//
// It never starts a server, never opens a listener, and never reads the
// Relay's startup config.

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
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

// bootstrapTokenUsage is printed for -h and on a usage error.
const bootstrapTokenUsage = `Usage: relay bootstrap-token -store-path <path> [-name <label>] [-ttl <duration>]

Mints an API Token for the founding admin Account and prints it to stdout.

This is the bootstrap path: use the printed credential to create your real
Accounts and mint their tokens over /api/v1, then revoke this one. The
plaintext is shown exactly once and cannot be recovered — losing it means
running this again and revoking the old token.

Requires read/write access to the Relay's store file, which is root-owned.
Safe to run while the Relay is running.

The mint is recorded on the audit trail (api_token_mint), attributed to
local-host rather than to any Account, and the record never carries the token.
If the record cannot be written, no token is issued.

Flags:
  -store-path <path>    Path to the Relay's store (same value as the Relay's
                        -store-path). Required.
  -name <label>         Operator-facing label for the token. Default "bootstrap".
  -ttl <duration>       Token lifetime, e.g. 720h. Default 0, meaning no expiry.
                        A bootstrap credential you intend to revoke promptly is
                        better served by a short TTL.
`

// runBootstrapTokenCommand implements the subcommand. It returns the process
// exit code rather than calling os.Exit, so it is testable.
//
// Stdout carries the credential and nothing else, so it can be piped straight
// into a secret store; every diagnostic goes to stderr.
func runBootstrapTokenCommand(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("bootstrap-token", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, bootstrapTokenUsage) }

	storePath := fs.String("store-path", "", "path to the Relay's store file")
	name := fs.String("name", "bootstrap", "operator-facing label for the token")
	ttl := fs.Duration("ttl", 0, "token lifetime; 0 means no expiry")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *storePath == "" {
		fmt.Fprintln(stderr, "relay bootstrap-token: -store-path is required")
		fmt.Fprint(stderr, bootstrapTokenUsage)
		return 2
	}
	if *ttl < 0 {
		fmt.Fprintln(stderr, "relay bootstrap-token: -ttl must not be negative")
		return 2
	}

	st, err := store.Open(*storePath)
	if err != nil {
		fmt.Fprintf(stderr, "relay bootstrap-token: open store: %v\n", err)
		return 1
	}
	defer st.Close() //nolint:errcheck

	ctx := context.Background()

	// Idempotent and deterministic, exactly as at Relay startup: creates the
	// row on first run, returns the existing one afterwards, and never repairs
	// an operator's deliberate disable or demotion.
	admin, err := st.Accounts().EnsureFoundingAdmin(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "relay bootstrap-token: ensure founding admin account: %v\n", err)
		return 1
	}

	// Refuse rather than re-enable. An operator who disabled the founding
	// admin retired that identity's authority on purpose; silently minting it
	// a fresh credential would undo a security decision at exactly the moment
	// nobody is watching. Re-enabling is an explicit act through the API, by
	// another admin — see ADR-0023 on the residual total-lockout case.
	if !admin.Enabled {
		fmt.Fprintf(stderr, "relay bootstrap-token: the %s account is disabled; refusing to mint a credential for it.\n", admin.Name)
		fmt.Fprintln(stderr, "Re-enable it deliberately (POST /api/v1/accounts/{id}/enable as another admin) if that is what you want.")
		return 1
	}

	tokenSvc := accounts.NewTokenService(recordedTokens{TokenRepository: st.APITokens(), st: st}, st.Accounts(), nil)
	tok, plaintext, err := tokenSvc.Mint(ctx, admin.ID, *name, *ttl)
	if err != nil {
		fmt.Fprintf(stderr, "relay bootstrap-token: mint: %v\n", err)
		fmt.Fprintln(stderr, "No token was minted: a credential that cannot be recorded on the audit trail is not issued.")
		return 1
	}

	// Diagnostics to stderr; the credential alone to stdout.
	fmt.Fprintf(stderr, "Minted API Token %s for account %s (%s).\n", tok.ID, admin.Name, admin.ID)
	fmt.Fprintf(stderr, "Recorded on the audit trail as %s, attributed to %s.\n", audit.KindAPITokenMint, audit.PrincipalLocalHost)
	if tok.ExpiresAt.IsZero() {
		fmt.Fprintln(stderr, "This token does not expire. Revoke it once your real Accounts have tokens:")
	} else {
		fmt.Fprintf(stderr, "This token expires at %s. Revoke it once your real Accounts have tokens:\n", tok.ExpiresAt.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(stderr, "  DELETE /api/v1/api-tokens/%s\n", tok.ID)
	fmt.Fprintln(stderr, "The credential below is shown once and cannot be recovered.")

	// The one place a bootstrap credential's plaintext is emitted.
	fmt.Fprintln(stdout, plaintext.Reveal())
	return 0
}
