//go:build integration

// Package main: mcp_account_auth_e2e_test.go is #298's acceptance test — the
// AI-agent as a machine Account (ADR-0010), driving MCP with an Account API
// Token, gated by the role ladder in the capability layer's Authorizer.
//
// It runs against a REAL relay-daemon over the real mTLS Tunnel, through
// newServer's own production wiring (ControlEnabled=true, no injected test
// sink), because the claim under test spans every layer at once: a token
// verified at the HTTP boundary, resolved to an Account, carried through the
// capability pipeline as a Principal, gated by role, dispatched to a Node,
// governed there by Policy, and attributed in audit. A unit test of any one
// layer cannot tell you the chain holds.
//
// Skip condition: RELAY_DAEMON_BIN unset (mirrors mcp_execution_e2e_test.go).
// Run via: make test-integration.
package main

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
)

// accountFleet is the running Relay plus the collaborators this test drives.
type accountFleet struct {
	relay  *relayFixture
	deps   *appDeps
	tokens *accounts.TokenService
	nodeID string
}

// startAccountFleet brings up a Relay with the control plane enabled and one
// real daemon connected, and returns the handles the assertions need.
func startAccountFleet(t *testing.T, daemonBin string) *accountFleet {
	t.Helper()
	ctx := context.Background()

	f := startRelay(t, WithControlPlane(), WithTCPNodePlane())

	_, plaintext, err := f.Deps.tokens.Create(ctx, []string{"relay:env=test"}, time.Hour)
	if err != nil {
		t.Fatalf("seed Enrollment Token: %v", err)
	}
	relaytest.StartDaemon(t, relaytest.DaemonConfig{
		Bin:        daemonBin,
		NodeAddr:   f.NodeAddr,
		CAPath:     relaytest.WriteTempFile(t, "ca-bundle-*.pem", string(f.Deps.ca.Bundle())),
		Token:      plaintext,
		StateDir:   t.TempDir(),
		PolicyPath: relaytest.WriteTempFile(t, "policy-*.toml", relaytest.FixturePolicy),
		Hostname:   "mcp-account-auth-e2e-node",
	})

	nodeID, err := f.Deps.dispatch.WaitForAny(30 * time.Second)
	if err != nil {
		t.Fatalf("WaitForAny: daemon did not complete Hello->Ping handshake within 30s: %v", err)
	}

	return &accountFleet{
		relay:  f,
		deps:   f.Deps,
		tokens: accounts.NewTokenService(f.Deps.store.APITokens(), f.Deps.store.Accounts(), nil),
		nodeID: nodeID,
	}
}

// mintAccount creates an enabled machine Account with the given role and
// returns it with a freshly minted credential.
func (f *accountFleet) mintAccount(t *testing.T, name string, role accounts.Role) (accounts.Account, string) {
	t.Helper()
	ctx := context.Background()
	acct, err := f.deps.store.Accounts().Create(ctx, accounts.Account{
		Name: name, Kind: accounts.KindMachine, Role: role, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create %s Account: %v", role, err)
	}
	_, plaintext, err := f.tokens.Mint(ctx, acct.ID, name+"-token", time.Hour)
	if err != nil {
		t.Fatalf("mint token for %s: %v", name, err)
	}
	return acct, plaintext.Reveal()
}

// clientFor returns an HTTP client presenting credential as its bearer token.
func (f *accountFleet) clientFor(credential string) *http.Client {
	return f.relay.ClientFor(credential)
}

// Acceptance: "An operator machine Account's token drives run_operation via
// MCP but is refused raw_exec; an admin token is not."
//
// Both halves run against the same live daemon and the same Policy, so the
// difference between them is the *role* and nothing else — the operator's
// raw_exec is refused by the Relay before dispatch, on a command the Node's
// Policy would happily have allowed.
func TestMCPAccountAuth_RoleLadder_E2E(t *testing.T) {
	daemonBin := os.Getenv("RELAY_DAEMON_BIN")
	if daemonBin == "" {
		relaytest.SkipMissingBin(t, "RELAY_DAEMON_BIN not set; skipping real-daemon e2e (run via make test-integration)")
	}
	f := startAccountFleet(t, daemonBin)

	operatorAcct, operatorToken := f.mintAccount(t, "gleipnir", accounts.RoleOperator)
	_, adminToken := f.mintAccount(t, "ops", accounts.RoleAdmin)

	// /bin/sleep 0 is allowed by FixturePolicy's raw_exec allow list, so a
	// refusal here can only be the Relay's role gate — never the Node's.
	rawExecArgs := map[string]any{
		"selector": "relay:env=test",
		"argv":     []string{"/bin/sleep", "0"},
	}
	operationArgs := map[string]any{
		"operation": "system.facts",
		"selector":  "relay:env=test",
	}

	t.Run("operator runs an Operation", func(t *testing.T) {
		session := relaytest.Connect(t, f.relay.ControlBase, f.clientFor(operatorToken))
		res := relaytest.CallTool(t, session, "run_operation", operationArgs)
		if res.IsError {
			t.Fatalf("run_operation as operator returned IsError=true: %+v", res.Content)
		}
	})

	t.Run("operator is refused Raw Exec", func(t *testing.T) {
		session := relaytest.Connect(t, f.relay.ControlBase, f.clientFor(operatorToken))
		res := relaytest.CallTool(t, session, "raw_exec", rawExecArgs)
		if !res.IsError {
			t.Fatal("raw_exec as operator SUCCEEDED — the arbitrary-command path must require admin")
		}
		// The refusal must tell the AI-agent what happened and what it would
		// take, so it can pick the typed path or ask for a step-up rather than
		// retry blindly.
		text := toolText(t, res)
		for _, want := range []string{"denied", "Raw Exec", "admin", "operator"} {
			if !strings.Contains(text, want) {
				t.Errorf("raw_exec refusal = %q, does not mention %q", text, want)
			}
		}
	})

	t.Run("admin runs Raw Exec", func(t *testing.T) {
		session := relaytest.Connect(t, f.relay.ControlBase, f.clientFor(adminToken))
		res := relaytest.CallTool(t, session, "raw_exec", rawExecArgs)
		if res.IsError {
			t.Fatalf("raw_exec as admin returned IsError=true: %+v", res.Content)
		}
	})

	// Acceptance: "audit attributes every tool call's dispatch to the Account."
	// The operator's Operation is attributed to the operator; its refused Raw
	// Exec is recorded as a refusal against the same Account.
	records, err := f.deps.audit.List(context.Background())
	if err != nil {
		t.Fatalf("audit.List: %v", err)
	}
	wantAttribution := operatorAcct.Name + ":" + string(accounts.RoleOperator)
	var sawOperatorDispatch, sawOperatorRefusal bool
	for _, r := range records {
		if r.Principal != wantAttribution {
			continue
		}
		switch r.Kind {
		case audit.KindDispatch:
			sawOperatorDispatch = true
		case audit.KindRefusal:
			sawOperatorRefusal = true
		}
	}
	if !sawOperatorDispatch {
		t.Errorf("no dispatch audit record attributed to %q; records = %+v", wantAttribution, principals(records))
	}
	if !sawOperatorRefusal {
		t.Errorf("no refusal audit record attributed to %q — a denied Raw Exec must leave a trail, not vanish", wantAttribution)
	}
}

// Acceptance: "Revoking the token cuts MCP access immediately."
//
// Also covers the Account-level off-switch, which is the coarser lever: it
// cuts every token of that Account at once without revoking any of them.
func TestMCPAccountAuth_RevocationAndDisablement_E2E(t *testing.T) {
	daemonBin := os.Getenv("RELAY_DAEMON_BIN")
	if daemonBin == "" {
		relaytest.SkipMissingBin(t, "RELAY_DAEMON_BIN not set; skipping real-daemon e2e (run via make test-integration)")
	}
	f := startAccountFleet(t, daemonBin)
	ctx := context.Background()

	acct, credential := f.mintAccount(t, "gleipnir", accounts.RoleAdmin)
	client := f.clientFor(credential)

	if _, err := relaytest.TryConnect(t, f.relay.ControlBase, client); err != nil {
		t.Fatalf("connect with a valid token: %v", err)
	}

	list, err := f.tokens.List(ctx, acct.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("list tokens: %v (%d)", err, len(list))
	}
	if err := f.tokens.Revoke(ctx, list[0].ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Immediately — no restart, no cache expiry, no new session needed on the
	// Relay's side.
	if _, err := relaytest.TryConnect(t, f.relay.ControlBase, client); err == nil {
		t.Fatal("MCP accepted a revoked token")
	}

	// A second Account, disabled rather than revoked: its token is never
	// revoked, and it is refused all the same.
	other, otherCredential := f.mintAccount(t, "retired", accounts.RoleAdmin)
	otherClient := f.clientFor(otherCredential)
	if _, err := relaytest.TryConnect(t, f.relay.ControlBase, otherClient); err != nil {
		t.Fatalf("connect before disablement: %v", err)
	}
	if err := f.deps.store.Accounts().SetEnabled(ctx, other.ID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, err := relaytest.TryConnect(t, f.relay.ControlBase, otherClient); err == nil {
		t.Fatal("MCP accepted a token whose Account is disabled")
	}
	stored, err := f.tokens.List(ctx, other.ID)
	if err != nil || len(stored) != 1 || stored[0].Revoked() {
		t.Errorf("disabling the Account revoked its token (%+v); the two levers must stay distinct", stored)
	}

	// A viewer cannot dispatch anything at all, by either path.
	_, viewerCredential := f.mintAccount(t, "watcher", accounts.RoleViewer)
	session := relaytest.Connect(t, f.relay.ControlBase, f.clientFor(viewerCredential))
	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"run_operation", map[string]any{"operation": "system.facts", "selector": "relay:env=test"}},
		{"raw_exec", map[string]any{"selector": "relay:env=test", "argv": []string{"/bin/sleep", "0"}}},
	} {
		if res := relaytest.CallTool(t, session, tc.tool, tc.args); !res.IsError {
			t.Errorf("%s as viewer SUCCEEDED — a viewer may never dispatch", tc.tool)
		}
	}

	// A viewer may not cancel a Job either (#595) — the real RoleGate over
	// the real Service, reached through cancel_job. An unknown id already
	// errors on its own, so asserting the text is what makes this test
	// discriminate a role refusal from a not-found.
	res := relaytest.CallTool(t, session, "cancel_job", map[string]any{"job_id": "job-does-not-exist"})
	if !res.IsError {
		t.Error("cancel_job as viewer SUCCEEDED — a viewer may never cancel a Job")
	} else if text := relaytest.ToolErrorText(t, res); !strings.Contains(text, "operator") {
		t.Errorf("cancel_job as viewer error = %q, want it to name the required role %q", text, "operator")
	}
}

// principals renders audit records as "kind=principal" pairs, so a failure
// message says who the trail actually attributed rather than dumping records.
func principals(records []audit.Record) []string {
	out := make([]string, 0, len(records))
	for _, r := range records {
		out = append(out, r.Kind+"="+r.Principal)
	}
	return out
}

// toolText returns the first text content of a tool result, for asserting
// that a refusal is legible to the AI-agent that provoked it.
func toolText(t *testing.T, res *sdkmcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatal("CallToolResult.Content is empty")
	}
	tc, ok := res.Content[0].(*sdkmcp.TextContent)
	if !ok {
		t.Fatalf("Content[0] = %T, want *sdkmcp.TextContent", res.Content[0])
	}
	return tc.Text
}

// headerRoundTripper adds arbitrary headers to every request, so an e2e can
// present asserted attribution the way a real harness would.
type headerRoundTripper struct {
	base    http.RoundTripper
	headers map[string]string
}

func (rt headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	for k, v := range rt.headers {
		req.Header.Set(k, v)
	}
	return rt.base.RoundTrip(req)
}

// Acceptance (#300): "A dispatch with on_behalf_of + traceparent shows both in
// its audit record, marked asserted; the same record's Account/token fields
// are marked verified."
//
// End to end through MCP against a real daemon, because the two lanes are
// assembled from opposite ends of the request — the verified half from the
// token the Relay checked, the asserted half from headers the caller set — and
// only a real request exercises both at once.
func TestMCPAccountAuth_AttributionLanes_E2E(t *testing.T) {
	daemonBin := os.Getenv("RELAY_DAEMON_BIN")
	if daemonBin == "" {
		relaytest.SkipMissingBin(t, "RELAY_DAEMON_BIN not set; skipping real-daemon e2e (run via make test-integration)")
	}
	f := startAccountFleet(t, daemonBin)
	ctx := context.Background()

	acct, credential := f.mintAccount(t, "gleipnir", accounts.RoleOperator)
	stored, err := f.tokens.List(ctx, acct.ID)
	if err != nil || len(stored) != 1 {
		t.Fatalf("list tokens: %v (%d)", err, len(stored))
	}
	tokenID := stored[0].ID

	const (
		onBehalfOf  = "ops-team"
		traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
		sessionRef  = "conv_01JQ8Z9K2X"
		changeRef   = "CHG-4821"
	)
	client := &http.Client{Transport: headerRoundTripper{
		base: relaytest.BearerRoundTripper{
			Base:  &http.Transport{TLSClientConfig: f.relay.TLSConfig()},
			Token: credential,
		},
		headers: map[string]string{
			controlplane.HeaderOnBehalfOf:  onBehalfOf,
			controlplane.HeaderTraceparent: traceparent,
			controlplane.HeaderSessionRef:  sessionRef,
			controlplane.HeaderChangeRef:   changeRef,
		},
	}}

	session := relaytest.Connect(t, f.relay.ControlBase, client)
	res := relaytest.CallTool(t, session, "run_operation", map[string]any{
		"operation": "system.facts",
		"selector":  "relay:env=test",
	})
	if res.IsError {
		t.Fatalf("run_operation returned IsError=true: %+v", res.Content)
	}

	// The verified lane: queryable by Account ID, which is what makes the
	// trail survive a rename.
	records, err := f.deps.audit.ByAccount(ctx, acct.ID)
	if err != nil {
		t.Fatalf("ByAccount: %v", err)
	}
	var dispatch *audit.Record
	for i := range records {
		if records[i].Kind == audit.KindDispatch {
			dispatch = &records[i]
			break
		}
	}
	if dispatch == nil {
		t.Fatalf("no dispatch record for account %q; got %v", acct.ID, principals(records))
	}

	v := dispatch.Attribution.Verified
	if v.AccountID != acct.ID || v.AccountName != "gleipnir" || v.Role != string(accounts.RoleOperator) {
		t.Errorf("verified lane = %+v, want the acting Account with its role at the time", v)
	}
	if v.TokenID != tokenID {
		t.Errorf("verified TokenID = %q, want %q — which credential acted must be recorded", v.TokenID, tokenID)
	}

	a := dispatch.Attribution.Asserted
	if a.OnBehalfOf != onBehalfOf || a.Traceparent != traceparent || a.SessionRef != sessionRef || a.ChangeRef != changeRef {
		t.Errorf("asserted lane = %+v, want the four values the caller sent", a)
	}

	// The asserted-lane query finds the same dispatch — the join key back to
	// the orchestrator's own session logs.
	byTeam, err := f.deps.audit.ByOnBehalfOf(ctx, onBehalfOf)
	if err != nil {
		t.Fatalf("ByOnBehalfOf: %v", err)
	}
	var found bool
	for _, r := range byTeam {
		if r.ID == dispatch.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("ByOnBehalfOf(%q) did not return the dispatch record", onBehalfOf)
	}

	// A malformed assertion is refused at the boundary — the caller cannot
	// size an audit record.
	oversized := &http.Client{Transport: headerRoundTripper{
		base: relaytest.BearerRoundTripper{
			Base:  &http.Transport{TLSClientConfig: f.relay.TLSConfig()},
			Token: credential,
		},
		headers: map[string]string{
			controlplane.HeaderOnBehalfOf: strings.Repeat("x", audit.MaxAssertedFieldBytes+1),
		},
	}}
	if _, err := relaytest.TryConnect(t, f.relay.ControlBase, oversized); err == nil {
		t.Error("an oversized asserted header was accepted")
	}
}
