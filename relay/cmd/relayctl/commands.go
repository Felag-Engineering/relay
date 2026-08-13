package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/apiclient"
)

// commands.go is the verb table: one entry per admin action, each a thin
// translation from flags to a generated client call to rendered output.
//
// No command interprets a Relay rule. A role refusal, a Freeze, a cap — each
// arrives as the server's own problem detail and is reproduced verbatim
// (see renderError). The CLI must never become a second, drifting explanation
// of the server's rules.
//
// Execution verbs are deliberately absent: `run` and `raw-exec` land in
// v0.4.0 [5/7] together with plan-by-default for mutate, which is a safety
// contract that deserves its own change rather than being bolted on here.

// command is one CLI verb.
type command struct {
	summary string
	// flags registers the command's own flags on fs and returns an opaque
	// holder that run receives back.
	flags func(fs *flag.FlagSet) any
	run   func(ctx context.Context, c *apiclient.Client, f any, args []string, g *globalFlags, out io.Writer) error
}

// group is a named set of subcommands ("account" -> {"create": ..., ...}).
type group map[string]command

func (gr group) names() []string {
	out := make([]string, 0, len(gr))
	for k := range gr {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// noFlags is the flags func for a command that takes none.
func noFlags(*flag.FlagSet) any { return nil }

var groups = map[string]group{
	"token":     tokenCommands(),
	"node":      nodeCommands(),
	"freeze":    freezeCommands(),
	"account":   accountCommands(),
	"api-token": apiTokenCommands(),
}

// ---------------------------------------------------------------------------
// Enrollment Tokens
// ---------------------------------------------------------------------------

type mintTokenFlags struct {
	scope   string
	ttl     time.Duration
	maxUses int
}

func tokenCommands() group {
	return group{
		"mint": {
			summary: "Mint a scoped Enrollment Token",
			flags: func(fs *flag.FlagSet) any {
				f := &mintTokenFlags{}
				fs.StringVar(&f.scope, "scope", "", "comma-separated relay: labels stamped on enrolling Nodes, e.g. relay:env=prod")
				fs.DurationVar(&f.ttl, "ttl", time.Hour, "how long the token stays valid")
				fs.IntVar(&f.maxUses, "max-uses", 0, "maximum enrollments (0 = unlimited within the TTL)")
				return f
			},
			run: func(ctx context.Context, c *apiclient.Client, fa any, _ []string, g *globalFlags, out io.Writer) error {
				f := fa.(*mintTokenFlags)
				body := apiclient.MintEnrollmentTokenJSONRequestBody{}
				if scope := splitCSV(f.scope); len(scope) > 0 {
					body.Scope = &scope
				}
				if secs := int64(f.ttl.Seconds()); secs > 0 {
					body.TtlSeconds = &secs
				}
				if f.maxUses > 0 {
					body.MaxUses = &f.maxUses
				}

				var minted apiclient.MintedEnrollmentToken
				resp, err := c.MintEnrollmentToken(ctx, body)
				if err := decode(resp, err, &minted); err != nil {
					return err
				}
				return emit(out, g, minted, func(w io.Writer) {
					// The plaintext is printed once and never again — say so at
					// the moment the operator can still act on it.
					fmt.Fprintf(w, "Enrollment Token minted.\n\n  id:         %s\n  expires at: %s\n",
						minted.Id, minted.ExpiresAt.Format(time.RFC3339))
					fmt.Fprintf(w, "\n  token: %s\n\n", minted.Token)
					fmt.Fprint(w, "This is the only time the token is shown. Store it now.\n")
				})
			},
		},
		"revoke": {
			summary: "Revoke an Enrollment Token (and cascade-revoke Nodes enrolled with it)",
			flags:   noFlags,
			run: func(ctx context.Context, c *apiclient.Client, _ any, args []string, _ *globalFlags, out io.Writer) error {
				id, err := oneArg(args, "token id")
				if err != nil {
					return err
				}
				resp, err := c.RevokeEnrollmentToken(ctx, id)
				if err := decode(resp, err, nil); err != nil {
					return err
				}
				fmt.Fprintf(out, "Enrollment Token %s revoked (its enrolled Nodes were revoked too).\n", id)
				return nil
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Nodes
// ---------------------------------------------------------------------------

func nodeCommands() group {
	return group{
		"revoke": {
			summary: "Revoke a Node and tear down its live Tunnel",
			flags:   noFlags,
			run: func(ctx context.Context, c *apiclient.Client, _ any, args []string, _ *globalFlags, out io.Writer) error {
				id, err := oneArg(args, "node id")
				if err != nil {
					return err
				}
				resp, err := c.RevokeNode(ctx, id)
				if err := decode(resp, err, nil); err != nil {
					return err
				}
				fmt.Fprintf(out, "Node %s revoked; its Tunnel is torn down and it cannot reconnect until it re-enrolls.\n", id)
				return nil
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Freeze
// ---------------------------------------------------------------------------

type releaseFlags struct{ reason string }

func freezeCommands() group {
	return group{
		"engage": {
			summary: "Engage the Relay-wide Freeze — halts all new dispatch",
			flags:   noFlags,
			run: func(ctx context.Context, c *apiclient.Client, _ any, _ []string, _ *globalFlags, out io.Writer) error {
				resp, err := c.EngageFreeze(ctx)
				if err := decode(resp, err, nil); err != nil {
					return err
				}
				fmt.Fprint(out, "Freeze ENGAGED. All new dispatch is refused, every risk class.\n"+
					"Plan mode still answers, so you can keep investigating.\n")
				return nil
			},
		},
		"release": {
			summary: "Release the Freeze (requires a reason)",
			flags: func(fs *flag.FlagSet) any {
				f := &releaseFlags{}
				fs.StringVar(&f.reason, "reason", "", "why the fleet is being un-frozen (recorded in the audit trail)")
				return f
			},
			run: func(ctx context.Context, c *apiclient.Client, fa any, _ []string, _ *globalFlags, out io.Writer) error {
				f := fa.(*releaseFlags)
				if strings.TrimSpace(f.reason) == "" {
					// Checked here as well as server-side so the operator learns
					// it before a round trip; the server remains the enforcer.
					return fmt.Errorf("--reason is required to release the Freeze (ADR-0013: stopping is cheap, restarting is deliberate)")
				}
				resp, err := c.ReleaseFreeze(ctx, apiclient.ReleaseFreezeJSONRequestBody{Reason: f.reason})
				if err := decode(resp, err, nil); err != nil {
					return err
				}
				fmt.Fprint(out, "Freeze RELEASED. Dispatch is permitted again.\n")
				return nil
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

type createAccountFlags struct{ name, kind, role string }
type setRoleFlags struct{ role string }

func accountCommands() group {
	return group{
		"create": {
			summary: "Create an Account",
			flags: func(fs *flag.FlagSet) any {
				f := &createAccountFlags{}
				fs.StringVar(&f.name, "name", "", "Account name")
				fs.StringVar(&f.kind, "kind", "machine", "human | machine")
				fs.StringVar(&f.role, "role", "viewer", "viewer | operator | admin")
				return f
			},
			run: func(ctx context.Context, c *apiclient.Client, fa any, _ []string, g *globalFlags, out io.Writer) error {
				f := fa.(*createAccountFlags)
				if f.name == "" {
					return fmt.Errorf("--name is required")
				}
				var acct apiclient.Account
				resp, err := c.CreateAccount(ctx, apiclient.CreateAccountJSONRequestBody{
					Name: f.name,
					Kind: apiclient.CreateAccountRequestKind(f.kind),
					Role: apiclient.CreateAccountRequestRole(f.role),
				})
				if err := decode(resp, err, &acct); err != nil {
					return err
				}
				return emit(out, g, acct, func(w io.Writer) { printAccount(w, acct) })
			},
		},
		"list": {
			summary: "List Accounts",
			flags:   noFlags,
			run: func(ctx context.Context, c *apiclient.Client, _ any, _ []string, g *globalFlags, out io.Writer) error {
				var list apiclient.AccountList
				resp, err := c.ListAccounts(ctx)
				if err := decode(resp, err, &list); err != nil {
					return err
				}
				return emit(out, g, list, func(w io.Writer) {
					if len(list.Accounts) == 0 {
						fmt.Fprintln(w, "no Accounts")
						return
					}
					fmt.Fprintf(w, "%-26s  %-18s  %-8s  %-9s  %s\n", "ID", "NAME", "KIND", "ROLE", "ENABLED")
					for _, a := range list.Accounts {
						fmt.Fprintf(w, "%-26s  %-18s  %-8s  %-9s  %v\n",
							a.Id, a.Name, a.Kind, a.Role, a.Enabled)
					}
				})
			},
		},
		"get": {
			summary: "Show one Account",
			flags:   noFlags,
			run: func(ctx context.Context, c *apiclient.Client, _ any, args []string, g *globalFlags, out io.Writer) error {
				id, err := oneArg(args, "account id")
				if err != nil {
					return err
				}
				var acct apiclient.Account
				resp, err := c.GetAccount(ctx, id)
				if err := decode(resp, err, &acct); err != nil {
					return err
				}
				return emit(out, g, acct, func(w io.Writer) { printAccount(w, acct) })
			},
		},
		"set-role": {
			summary: "Change an Account's role (takes effect immediately for its existing tokens)",
			flags: func(fs *flag.FlagSet) any {
				f := &setRoleFlags{}
				fs.StringVar(&f.role, "role", "", "viewer | operator | admin")
				return f
			},
			run: func(ctx context.Context, c *apiclient.Client, fa any, args []string, g *globalFlags, out io.Writer) error {
				f := fa.(*setRoleFlags)
				id, err := oneArg(args, "account id")
				if err != nil {
					return err
				}
				if f.role == "" {
					return fmt.Errorf("--role is required")
				}
				var acct apiclient.Account
				resp, err := c.SetAccountRole(ctx, id, apiclient.SetAccountRoleJSONRequestBody{
					Role: apiclient.SetRoleRequestRole(f.role),
				})
				if err := decode(resp, err, &acct); err != nil {
					return err
				}
				return emit(out, g, acct, func(w io.Writer) { printAccount(w, acct) })
			},
		},
		"enable": {
			summary: "Enable an Account",
			flags:   noFlags,
			run:     setEnabled(true),
		},
		"disable": {
			summary: "Disable an Account (its live tokens stop working, without being revoked)",
			flags:   noFlags,
			run:     setEnabled(false),
		},
	}
}

func setEnabled(enable bool) func(context.Context, *apiclient.Client, any, []string, *globalFlags, io.Writer) error {
	return func(ctx context.Context, c *apiclient.Client, _ any, args []string, g *globalFlags, out io.Writer) error {
		id, err := oneArg(args, "account id")
		if err != nil {
			return err
		}
		resp, err := c.DisableAccount(ctx, id)
		if enable {
			resp, err = c.EnableAccount(ctx, id)
		}
		var acct apiclient.Account
		if err := decode(resp, err, &acct); err != nil {
			return err
		}
		return emit(out, g, acct, func(w io.Writer) { printAccount(w, acct) })
	}
}

// ---------------------------------------------------------------------------
// API Tokens
// ---------------------------------------------------------------------------

type mintAPITokenFlags struct {
	account string
	name    string
	ttl     time.Duration
}

func apiTokenCommands() group {
	return group{
		"mint": {
			summary: "Mint an API Token for an Account",
			flags: func(fs *flag.FlagSet) any {
				f := &mintAPITokenFlags{}
				fs.StringVar(&f.account, "account", "", "Account id to mint for")
				fs.StringVar(&f.name, "name", "", "operator-facing label")
				fs.DurationVar(&f.ttl, "ttl", 0, "expiry (0 = no expiry)")
				return f
			},
			run: func(ctx context.Context, c *apiclient.Client, fa any, _ []string, g *globalFlags, out io.Writer) error {
				f := fa.(*mintAPITokenFlags)
				if f.account == "" || f.name == "" {
					return fmt.Errorf("--account and --name are required")
				}
				body := apiclient.MintAPITokenJSONRequestBody{Name: f.name}
				if secs := int64(f.ttl.Seconds()); secs > 0 {
					body.TtlSeconds = &secs
				}
				var minted apiclient.MintedAPIToken
				resp, err := c.MintAPIToken(ctx, f.account, body)
				if err := decode(resp, err, &minted); err != nil {
					return err
				}
				return emit(out, g, minted, func(w io.Writer) {
					fmt.Fprintf(w, "API Token minted.\n\n  id:      %s\n  account: %s\n  name:    %s\n",
						minted.ApiToken.Id, minted.ApiToken.AccountId, minted.ApiToken.Name)
					fmt.Fprintf(w, "\n  token: %s\n\n", minted.Token)
					fmt.Fprint(w, "This is the only time the token is shown. Store it now.\n")
				})
			},
		},
		"list": {
			summary: "List an Account's API Tokens (redacted)",
			flags:   noFlags,
			run: func(ctx context.Context, c *apiclient.Client, _ any, args []string, g *globalFlags, out io.Writer) error {
				id, err := oneArg(args, "account id")
				if err != nil {
					return err
				}
				var list apiclient.APITokenList
				resp, err := c.ListAPITokens(ctx, id)
				if err := decode(resp, err, &list); err != nil {
					return err
				}
				return emit(out, g, list, func(w io.Writer) {
					if len(list.Tokens) == 0 {
						fmt.Fprintln(w, "no API Tokens")
						return
					}
					fmt.Fprintf(w, "%-26s  %-18s  %-9s  %s\n", "ID", "NAME", "REVOKED", "LAST USED")
					for _, t := range list.Tokens {
						fmt.Fprintf(w, "%-26s  %-18s  %-9v  %s\n", t.Id, t.Name, t.Revoked, derefStr(t.LastUsedAt))
					}
				})
			},
		},
		"revoke": {
			summary: "Revoke an API Token",
			flags:   noFlags,
			run: func(ctx context.Context, c *apiclient.Client, _ any, args []string, _ *globalFlags, out io.Writer) error {
				id, err := oneArg(args, "api-token id")
				if err != nil {
					return err
				}
				resp, err := c.RevokeAPIToken(ctx, id)
				if err := decode(resp, err, nil); err != nil {
					return err
				}
				fmt.Fprintf(out, "API Token %s revoked; the next request presenting it is refused.\n", id)
				return nil
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

func printAccount(w io.Writer, a apiclient.Account) {
	fmt.Fprintf(w, "  id:         %s\n  name:       %s\n  kind:       %s\n  role:       %s\n  enabled:    %v\n  created at: %s\n",
		a.Id, a.Name, a.Kind, a.Role, a.Enabled, a.CreatedAt.Format(time.RFC3339))
}

func oneArg(args []string, what string) (string, error) {
	if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		return "", fmt.Errorf("a %s is required", what)
	}
	return args[0], nil
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func derefStr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}
