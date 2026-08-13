// Command relayctl is the operator's workstation CLI for Relay's Control API
// (#137, #359, ADR-0010).
//
// It is a THIN ADAPTER over /api/v1 and nothing more. Every action it performs
// is an HTTP call a curl invocation could make; it holds no CA key, opens no
// listener, reads no Relay configuration, and has no path to a Node that does
// not go through the Relay's capability layer. That is invariant 10 restated
// for a fourth surface: the CLI is not a control path, it drives the one that
// already exists.
//
// # Why a separate binary
//
// The `relay` binary is a SERVER: it embeds the CA, the SQLite store, and the
// node-plane and control-plane listeners. The CLI runs on an operator's
// workstation. Shipping `relay` to every laptop that needs a CLI would put the
// fleet's certificate authority on those laptops, so relayctl ships alone.
//
// # Generated transport
//
// The HTTP layer is GENERATED from docs/api/openapi.yaml
// (internal/apiclient/client.gen.go, `make gen-apiclient`), never hand-written.
// That makes this CLI a conformance test of the published contract: if the spec
// and the server disagree, the generated client changes and this binary stops
// compiling — a spec that lies fails the build rather than the operator.
//
// # Scope
//
// This is the foundation slice: connection/auth resolution plus the admin
// verbs. The execution verbs (`run`, `raw-exec`) land in v0.4.0 [5/7] with
// their plan-by-default discipline, which is a safety contract in its own right
// and deserves its own change.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// exit codes. Distinct codes let a script tell "you are not allowed" from "the
// Relay is frozen" from "the tool was used wrongly" without parsing prose.
const (
	exitOK          = 0
	exitUsage       = 1 // bad flags, unknown command, missing argument
	exitAPIError    = 2 // the Relay refused or failed the request
	exitAuth        = 3 // missing/invalid credential, or role too low
	exitUnreachable = 4 // could not reach or verify the Relay
)

// globalFlags are the connection flags every subcommand accepts.
type globalFlags struct {
	endpoint  string
	token     string
	tokenFile string
	caCert    string
	profile   string
	timeout   time.Duration
	jsonOut   bool
}

func (g *globalFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&g.endpoint, "endpoint", "", "Relay control-plane base URL (env RELAY_ENDPOINT)")
	fs.StringVar(&g.token, "token", "", "API Token (env RELAY_TOKEN; prefer --token-file, argv is world-readable)")
	fs.StringVar(&g.tokenFile, "token-file", "", "file containing the API Token (env RELAY_TOKEN_FILE)")
	fs.StringVar(&g.caCert, "ca-cert", "", "PEM bundle of the Relay's CA (env RELAY_CA_CERT)")
	fs.StringVar(&g.profile, "profile", "", "named profile from the config file (env RELAY_PROFILE)")
	fs.DurationVar(&g.timeout, "timeout", 0, "per-request timeout (default 60s)")
	fs.BoolVar(&g.jsonOut, "json", false, "emit raw JSON instead of human-readable output")
}

const usage = `relayctl — operator CLI for Relay's Control API.

Usage:
  relayctl <group> <command> [flags]

Groups:
  token        Enrollment Tokens      (mint, revoke)
  node         Nodes                  (revoke)
  freeze       Relay-wide emergency stop (engage, release, ADR-0013)
  account      Accounts               (create, list, get, set-role, enable, disable)
  api-token    Account API Tokens     (mint, list, revoke)

Other:
  version      Print the build version
  help         Print this message

Connection flags (accepted by every command):
  --endpoint    Relay control-plane base URL      (env RELAY_ENDPOINT)
  --token       API Token                         (env RELAY_TOKEN)
  --token-file  File containing the API Token     (env RELAY_TOKEN_FILE)
  --ca-cert     PEM bundle of the Relay's CA      (env RELAY_CA_CERT)
  --profile     Named profile from the config     (env RELAY_PROFILE)
  --timeout     Per-request timeout (default 60s)
  --json        Emit raw JSON

Prefer --token-file over --token: a credential in argv is visible in the
process table to every user on the machine.

Config file (optional): $RELAY_CONFIG, else ~/.config/relay/config.json
  {"default_profile":"prod",
   "profiles":{"prod":{"endpoint":"https://relay.example:9443",
                       "token_file":"/etc/relay/token","ca_cert":"/etc/relay/ca.pem"}}}

Execution verbs (run, raw-exec) arrive in a later slice with plan-by-default.

Exit codes:
  0 ok   1 usage   2 API error   3 auth/role   4 unreachable
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main's testable core: argv in, exit code out, no os.Exit and no
// globals, so every command's behaviour can be asserted in-process.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}

	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	case "version", "--version", "-version":
		fmt.Fprintln(stdout, versionString())
		return exitOK
	}

	group, ok := groups[args[0]]
	if !ok {
		fmt.Fprintf(stderr, "relayctl: unknown command %q\n\n%s", args[0], usage)
		return exitUsage
	}
	if len(args) < 2 {
		fmt.Fprintf(stderr, "relayctl: %s requires a subcommand (%s)\n", args[0], strings.Join(group.names(), ", "))
		return exitUsage
	}

	cmd, ok := group[args[1]]
	if !ok {
		fmt.Fprintf(stderr, "relayctl: unknown %s subcommand %q (want one of: %s)\n",
			args[0], args[1], strings.Join(group.names(), ", "))
		return exitUsage
	}

	fs := flag.NewFlagSet(args[0]+" "+args[1], flag.ContinueOnError)
	fs.SetOutput(stderr)
	var g globalFlags
	g.register(fs)
	cmdFlags := cmd.flags(fs)
	if err := fs.Parse(permute(fs, args[2:])); err != nil {
		return exitUsage
	}

	cfg, err := resolveConfig(&g)
	if err != nil {
		return renderConfigError(stderr, err)
	}
	client, err := newAPIClient(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "relayctl: %v\n", err)
		return exitUnreachable
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	if err := cmd.run(ctx, client, cmdFlags, fs.Args(), &g, stdout); err != nil {
		return renderError(stderr, err)
	}
	return exitOK
}

// renderConfigError turns a configuration failure into a legible message. The
// missing-credential case gets its own text because it is the first thing every
// new operator hits, and "no API Token found" alone does not say what to do.
func renderConfigError(stderr io.Writer, err error) int {
	if errors.Is(err, errNoCredential) {
		fmt.Fprintf(stderr, `relayctl: no API Token found.

Provide one of:
  --token-file /path/to/token     (preferred)
  RELAY_TOKEN_FILE=/path/to/token
  RELAY_TOKEN=glp_...
  a profile with token_file in %s

Mint one with: relayctl api-token mint --account <id> --name <label>
(or, for the first admin, `+"`relay bootstrap-token`"+` on the Relay host).
`, profilePath())
		return exitAuth
	}
	fmt.Fprintf(stderr, "relayctl: %v\n", err)
	return exitUsage
}

// renderError maps an error from a command into an exit code and a message.
//
// An *apiError carries the Relay's own RFC 7807 problem detail, which already
// states the rule that refused the request ("Raw Exec requires role admin",
// "matched 900 nodes, exceeds the mutate-cap of 50"). Those messages are
// written for a human and are reproduced verbatim rather than re-worded here —
// the CLI must not become a second, drifting explanation of the server's rules.
func renderError(stderr io.Writer, err error) int {
	var apiErr *apiError
	if errors.As(err, &apiErr) {
		fmt.Fprintf(stderr, "relayctl: %s\n", apiErr.Error())
		switch apiErr.Status {
		case http.StatusUnauthorized, http.StatusForbidden:
			return exitAuth
		default:
			return exitAPIError
		}
	}
	var urlErr interface{ Timeout() bool }
	if errors.As(err, &urlErr) || isConnectionError(err) {
		fmt.Fprintf(stderr, "relayctl: could not reach the Relay: %v\n", err)
		return exitUnreachable
	}
	fmt.Fprintf(stderr, "relayctl: %v\n", err)
	return exitAPIError
}

func isConnectionError(err error) bool {
	var netErr interface {
		error
		Timeout() bool
	}
	if errors.As(err, &netErr) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "certificate") ||
		strings.Contains(msg, "tls:")
}

// jsonUnmarshal is a tiny indirection so config.go does not import
// encoding/json directly (keeping its imports about configuration).
func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

// permute reorders argv so every flag precedes every positional argument.
//
// Go's flag package stops parsing at the FIRST non-flag argument, so
// `relayctl account set-role <id> --role admin` would silently treat
// "--role admin" as two positionals and report the role as missing. Every CLI
// an operator has used (git, kubectl, docker) accepts flags after positionals,
// and a tool that quietly ignores a flag it was given is worse than one that
// rejects it — the operator believes they set the role.
//
// A flag consumes the following argument unless it is boolean (--json) or was
// written in --flag=value form; fs is inspected for boolean-ness rather than
// hard-coding names, so a flag added later is handled without touching this.
func permute(fs *flag.FlagSet, args []string) []string {
	isBool := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) {
		if bv, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bv.IsBoolFlag() {
			isBool[f.Name] = true
		}
	})

	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			// Everything after "--" is positional by convention.
			positional = append(positional, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") {
			continue // --flag=value carries its own value
		}
		if isBool[name] {
			continue
		}
		if i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positional...)
}
