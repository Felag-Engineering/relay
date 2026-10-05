package main

// console_password.go implements `relay console-password`: the local,
// root-owned lever that sets a human Account's Admin Console sign-in password
// (#418, docs/design/console/12-login.md).
//
// # Why a local subcommand and not an API
//
// The same chicken-and-egg as `relay bootstrap-token`, and the same answer:
// the FIRST Console credential cannot be set through the Console, because
// reaching the Console requires one. So the first password is rooted locally,
// in the filesystem, exactly as ADR-0002 roots Node Policy and ADR-0023 roots
// the first API Token. Anyone who can run this already has read/write access
// to the Relay's store file and could forge any row in it; this grants no
// authority local root did not already have.
//
// # Why it reads the password from a file or a terminal, never a flag
//
// A password passed as `-password hunter2` is a password in every process
// listing, in the shell history of whoever typed it, and in any crash dump
// taken while it runs — the same reason invariant 11 makes every Relay secret
// a PATH rather than a value. There is deliberately no flag that takes one.
//
// # The audit record
//
// Every set or clear writes one audit record (password_set / password_clear),
// attributed to the principal local-host rather than to any Account, in the
// SAME transaction as the change (#782). If the record cannot be written the
// password is left unchanged: a credential change the trail cannot show is not
// made. The record names the Account and never the password or its hash.
//
// It never starts a server, never opens a listener, and never reads the
// Relay's startup config.

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

// consolePasswordUsage is printed for -h and on a usage error.
const consolePasswordUsage = `Usage: relay console-password -store-path <path> -account <name> [-password-file <path>] [-clear]

Sets a human Account's Admin Console sign-in password, reading it from
-password-file or from standard input.

There is no flag that takes the password itself: a password on a command line
is a password in every process listing and shell history.

The Account must already exist and be a human Account. Create one over
/api/v1/accounts, or use the seeded founding admin.

Requires read/write access to the Relay's store file, which is root-owned.
Safe to run while the Relay is running; the new password takes effect on the
next sign-in, and sessions already open are unaffected.

Every set or clear is recorded on the audit trail (password_set /
password_clear), attributed to local-host rather than to any Account, and the
record never carries the password. If the record cannot be written, the
password is left unchanged.

Flags:
  -store-path <path>      Path to the Relay's store (same value as the Relay's
                          -store-path). Required.
  -account <name>         The Account to set a password for. Required.
  -password-file <path>   Read the password from this file, trailing newline
                          stripped. Default: read one line from stdin.
  -clear                  Remove the Account's password instead of setting one.
                          The Account keeps its API Tokens and its role; it can
                          simply no longer sign in to the Console.
`

// notChangedNote follows any failure at or after the write: the change and its
// audit record are one transaction, so a failure leaves the password as it was.
const notChangedNote = "The password was not changed: a change that cannot be recorded on the audit trail is not made."

// runConsolePasswordCommand implements the subcommand. It returns the process
// exit code rather than calling os.Exit, so it is testable.
//
// Nothing is written to stdout: there is no credential to emit — the operator
// already knows the password they just chose — and a subcommand that echoed
// one would put it in the terminal scrollback of whoever ran it.
func runConsolePasswordCommand(args []string, stdin, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("console-password", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, consolePasswordUsage) }

	storePath := fs.String("store-path", "", "path to the Relay's store file")
	account := fs.String("account", "", "the Account to set a password for")
	passwordFile := fs.String("password-file", "", "read the password from this file instead of stdin")
	clear := fs.Bool("clear", false, "remove the Account's password instead of setting one")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	switch {
	case *storePath == "":
		fmt.Fprintln(stderr, "relay console-password: -store-path is required")
		fmt.Fprint(stderr, consolePasswordUsage)
		return 2
	case *account == "":
		fmt.Fprintln(stderr, "relay console-password: -account is required")
		fmt.Fprint(stderr, consolePasswordUsage)
		return 2
	case *clear && *passwordFile != "":
		fmt.Fprintln(stderr, "relay console-password: -clear and -password-file are mutually exclusive")
		return 2
	}

	st, err := store.Open(*storePath)
	if err != nil {
		fmt.Fprintf(stderr, "relay console-password: open store: %v\n", err)
		return 1
	}
	defer st.Close() //nolint:errcheck

	ctx := context.Background()
	acct, err := st.Accounts().GetByName(ctx, accounts.NormalizeName(*account))
	if err != nil {
		// Naming the Account is fine HERE and would not be on the sign-in
		// page: this caller is local root, who can read the accounts table
		// directly. There is nothing to enumerate that they cannot already
		// SELECT.
		fmt.Fprintf(stderr, "relay console-password: no Account named %q\n", *account)
		return 1
	}
	if acct.Kind != accounts.KindHuman {
		// The Console establishes a per-HUMAN identity (ADR-0009). Setting a
		// Console password on a machine Account would create a credential that
		// can never be used, and would suggest the Console is somewhere a bot
		// belongs.
		fmt.Fprintf(stderr, "relay console-password: %s is a machine Account; the Console signs in humans only.\n", acct.Name)
		fmt.Fprintln(stderr, "Machine Accounts authenticate with API Tokens (POST /api/v1/api-tokens).")
		return 1
	}

	if *clear {
		err := st.ClearPasswordRecorded(ctx, acct.ID, func(removed bool) (audit.Record, error) {
			id, err := hostAuditID()
			if err != nil {
				return audit.Record{}, fmt.Errorf("generate audit record id: %w", err)
			}
			return auditsink.HostPasswordClearRecord(id, time.Now(), acct.ID, acct.Name, removed)
		})
		if err != nil {
			fmt.Fprintf(stderr, "relay console-password: clear: %v\n", err)
			fmt.Fprintln(stderr, notChangedNote)
			return 1
		}
		fmt.Fprintf(stderr, "Removed the Console password for %s (%s). It keeps its role and its API Tokens.\n", acct.Name, acct.ID)
		fmt.Fprintf(stderr, "Recorded on the audit trail as %s, attributed to %s.\n", audit.KindPasswordClear, audit.PrincipalLocalHost)
		fmt.Fprintln(stderr, "Sessions already open are unaffected — disable the Account to end those.")
		return 0
	}

	password, err := readPassword(*passwordFile, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "relay console-password: %v\n", err)
		return 1
	}
	if err := password.Validate(); err != nil {
		switch {
		case errors.Is(err, accounts.ErrPasswordTooShort):
			fmt.Fprintf(stderr, "relay console-password: the password is shorter than %d characters.\n", accounts.MinPasswordBytes)
			// Say why the floor is where it is. An operator who understands
			// the reason picks a good passphrase; one who thinks it is
			// bureaucracy picks the shortest thing that passes.
			fmt.Fprintln(stderr, "The Console's throttle deliberately has no lockout, so length is what makes slow guessing hopeless.")
		case errors.Is(err, accounts.ErrPasswordTooLong):
			fmt.Fprintf(stderr, "relay console-password: the password is longer than %d bytes.\n", accounts.MaxPasswordBytes)
		default:
			fmt.Fprintf(stderr, "relay console-password: %v\n", err)
		}
		return 1
	}

	hash, err := accounts.HashPassword(password)
	if err != nil {
		fmt.Fprintf(stderr, "relay console-password: hash: %v\n", err)
		return 1
	}
	id, err := hostAuditID()
	if err != nil {
		fmt.Fprintf(stderr, "relay console-password: generate audit record id: %v\n", err)
		fmt.Fprintln(stderr, notChangedNote)
		return 1
	}
	rec, err := auditsink.HostPasswordSetRecord(id, time.Now(), acct.ID, acct.Name)
	if err != nil {
		fmt.Fprintf(stderr, "relay console-password: %v\n", err)
		fmt.Fprintln(stderr, notChangedNote)
		return 1
	}
	if err := st.SetPasswordRecorded(ctx, acct.ID, hash, rec); err != nil {
		fmt.Fprintf(stderr, "relay console-password: set: %v\n", err)
		fmt.Fprintln(stderr, notChangedNote)
		return 1
	}

	fmt.Fprintf(stderr, "Set the Console password for %s (%s), role %s.\n", acct.Name, acct.ID, acct.Role)
	fmt.Fprintf(stderr, "Recorded on the audit trail as %s, attributed to %s.\n", audit.KindPasswordSet, audit.PrincipalLocalHost)
	if !acct.Enabled {
		// Worth saying plainly rather than letting them discover it at the
		// sign-in page, where every failure looks the same on purpose.
		fmt.Fprintf(stderr, "NOTE: %s is disabled and will not be able to sign in until it is enabled.\n", acct.Name)
	}
	return 0
}

// readPassword reads the password from path, or one line from stdin.
//
// A trailing newline is stripped in both cases — `echo hunter2 > pw` and a
// typed line both mean the password without it, and a credential that silently
// includes a newline is a credential nobody can reproduce.
func readPassword(path string, stdin *os.File) (accounts.Password, error) {
	if path != "" {
		raw, err := os.ReadFile(path) //nolint:gosec // G304: the operator's own --password-file argument on the host
		if err != nil {
			return accounts.Password{}, fmt.Errorf("read password file: %w", err)
		}
		return accounts.NewPassword(strings.TrimRight(string(raw), "\r\n")), nil
	}
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && line == "" {
		return accounts.Password{}, fmt.Errorf("read password from stdin: %w", err)
	}
	return accounts.NewPassword(strings.TrimRight(line, "\r\n")), nil
}
