// Package main: approval_console_e2e_test.go proves docs/specs/approval.md's
// no-row bullet — "that deciding from the Console records the same decision,
// channel and attribution as the Control API (#435)" — against the REAL
// composition root: real approval-gate file, real store, real control-plane
// listener, real consoleauth.Service, real session cookies. Acceptance
// criteria 1, 2, 3 and 5 of #453 are proven here; criterion 3's machine leg
// is an extension of TestApprovalCallout_MachineCannotSatisfyItsOwnGate in
// approval_e2e_test.go, right beside the domain-level assertion it narrows.
//
// The fixture (startGatedRelay) does NOT mount a Console by default —
// ConsoleEnabled defaults false and consoleSurface{} is appended only when it
// is true (main.go) — so every test here opts in with
// WithConfig(func(c *Config) { c.ConsoleEnabled = true }).
package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/console"
)

// consoleClient builds a browser-shaped http.Client for f: TLS trusting the
// fixture's CA (f.ClientFor builds an equivalent transport for the bearer
// lane; this is the browser lane's counterpart), a cookie jar so the session
// cookie set by sign-in persists across requests the way a real browser's
// would, and CheckRedirect disabled so a decision's 303 is ASSERTED rather
// than silently followed by the client.
//
// Named fallback, not needed today: if Go's cookiejar ever declines to store
// a __Host- cookie for an IP-literal host, the fix is to carry cookies by
// hand — as console's own loginFixture.do does in-package — rather than to
// weaken any cookie attribute to make the jar accept it.
func consoleClient(t *testing.T, f *relayFixture) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &http.Client{
		Transport:     &http.Transport{TLSClientConfig: f.TLSConfig()},
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// readAll reads and closes resp.Body, failing the test on either error.
func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return string(b)
}

// consoleHiddenFieldPattern is built per name rather than once: this file
// scrapes exactly two names (csrf_token, plan_hash), and building the regexp
// from the literal name keeps the call site readable as
// consoleHiddenField(t, body, "plan_hash") rather than a second pattern
// variable per field.
func consoleHiddenField(t *testing.T, body, name string) string {
	t.Helper()
	re := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `" value="([^"]+)"`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no hidden field %q found in the rendered page:\n%s", name, body)
	}
	return m[1]
}

// cookieNamedFromResponse returns the named cookie resp set, or nil.
func cookieNamedFromResponse(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// mintConsoleHumanAccount creates a human Account carrying BOTH an API token
// (so a test can read back through the Control API exactly as the
// requester's own channel does) and a Console password (so it can sign in
// through the browser lane) — the two credentials one Account legitimately
// holds on two different surfaces.
//
// store.Passwords().SetPassword takes an accounts.PasswordHash, never a
// plaintext, so accounts.HashPassword runs first.
//
// role is explicit rather than hardcoded to admin: criterion 1 says "a human
// Account with the RIGHT role" — the operator floor, not admin specifically
// — and TestApprovalCallout_ConsoleDecideRun (admin) proved only the upper
// bound until TestApprovalCallout_ConsoleDecideRunAsOperator (operator) used
// this parameter to prove the floor itself.
func mintConsoleHumanAccount(t *testing.T, f *relayFixture, name, password string, role accounts.Role) (accountID, token string) {
	t.Helper()
	ctx := context.Background()
	acct, err := f.Deps.store.Accounts().Create(ctx, accounts.Account{
		Name: name, Kind: accounts.KindHuman, Role: role, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create account %s: %v", name, err)
	}
	svc := accounts.NewTokenService(f.Deps.store.APITokens(), f.Deps.store.Accounts(), nil)
	_, plaintext, err := svc.Mint(ctx, acct.ID, name+"-token", 0)
	if err != nil {
		t.Fatalf("mint token for %s: %v", name, err)
	}
	hash, err := accounts.HashPassword(accounts.NewPassword(password))
	if err != nil {
		t.Fatalf("hash password for %s: %v", name, err)
	}
	if err := f.Deps.store.Passwords().SetPassword(ctx, acct.ID, hash); err != nil {
		t.Fatalf("set password for %s: %v", name, err)
	}
	return acct.ID, plaintext.Reveal()
}

// consoleSignIn drives the real sign-in form over client (which must carry a
// cookie jar — see consoleClient) and fails the test unless it redirects: a
// genuine browser session established through the production handler, never
// a hand-built cookie.
func consoleSignIn(t *testing.T, client *http.Client, f *relayFixture, username, password string) {
	t.Helper()
	getResp, err := client.Get(f.ControlBase + console.LoginPath)
	if err != nil {
		t.Fatalf("GET login page: %v", err)
	}
	token := consoleHiddenField(t, readAll(t, getResp), "csrf_token")

	form := url.Values{"username": {username}, "password": {password}, "csrf_token": {token}}
	postResp, err := client.PostForm(f.ControlBase+console.LoginPath, form)
	if err != nil {
		t.Fatalf("POST sign-in: %v", err)
	}
	defer postResp.Body.Close()
	if postResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("sign-in status = %d, want 303 (redirect after sign-in)", postResp.StatusCode)
	}
}

// TestApprovalCallout_ConsoleDecideRun is #453's headline acceptance —
// criteria 1 and 5: a human Account approves a parked Job in the browser,
// the decision is attributed and channel-strong exactly as the Control
// API's own decision would be, and the SAME dispatch then runs. This leg
// proves it at admin; TestApprovalCallout_ConsoleDecideRunAsOperator proves
// the same acceptance at the operator FLOOR criterion 1 actually names — "a
// human Account with the right role", not admin specifically.
func TestApprovalCallout_ConsoleDecideRun(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates, WithConfig(func(c *Config) { c.ConsoleEnabled = true }))

	// The requester is a MACHINE Account — the AI-agent side of the callout —
	// so the human deciding below is unambiguously a SECOND party, never the
	// requester answering their own request.
	requester := mintAccount(t, f, "gleipnir-prod", accounts.KindMachine, accounts.RoleAdmin)
	parkResp := restartMutate(t, f, requester)
	defer parkResp.Body.Close()
	if parkResp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", parkResp.StatusCode)
	}
	var parked parkedBody
	if err := json.NewDecoder(parkResp.Body).Decode(&parked); err != nil {
		t.Fatalf("decode park: %v", err)
	}

	_, danaToken := mintConsoleHumanAccount(t, f, "dana", "dana's console password", accounts.RoleAdmin)

	client := consoleClient(t, f)
	consoleSignIn(t, client, f, "dana", "dana's console password")

	cardResp, err := client.Get(f.ControlBase + "/console/approvals/" + parked.RequestID)
	if err != nil {
		t.Fatalf("GET approval card: %v", err)
	}
	cardBody := readAll(t, cardResp)
	csrfToken := consoleHiddenField(t, cardBody, "csrf_token")
	planHash := consoleHiddenField(t, cardBody, "plan_hash")
	if planHash != parked.PlanHash {
		t.Fatalf("card's plan_hash = %q, want the park's own %q", planHash, parked.PlanHash)
	}

	sessionBefore := consoleSessionCookie(t, client, f.ControlBase)

	decideResp, err := client.PostForm(f.ControlBase+"/console/approvals/"+parked.RequestID+"/decision", url.Values{
		"csrf_token": {csrfToken},
		"plan_hash":  {planHash},
		"answer":     {"approve"},
		"reason":     {"looks fine over the browser"},
		"password":   {"dana's console password"},
	})
	if err != nil {
		t.Fatalf("POST decision: %v", err)
	}
	decideBody := readAll(t, decideResp)
	if decideResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("decide status = %d, want 303; body %s", decideResp.StatusCode, decideBody)
	}

	// The decision's step-up rotated the session identifier (#879): the
	// browser now holds a different cookie than the one it signed in with.
	if after := consoleSessionCookie(t, client, f.ControlBase); after == sessionBefore {
		t.Error("the decision's step-up did not rotate the Console session cookie")
	}

	// The decision reads back on the API exactly as a Control-API decision
	// would: approved, attributed to dana, out-of-band, human.
	getApproval := controlAPIRequest(t, f.ClientFor(danaToken), http.MethodGet,
		f.ControlBase+"/api/v1/approvals/"+parked.RequestID, danaToken, nil)
	defer getApproval.Body.Close()
	var approved approvalBody
	if err := json.NewDecoder(getApproval.Body).Decode(&approved); err != nil {
		t.Fatalf("decode approval: %v", err)
	}
	if approved.State != "approved" {
		t.Fatalf("state = %q, want approved", approved.State)
	}
	if len(approved.Decisions) != 1 {
		t.Fatalf("decisions = %+v, want exactly one", approved.Decisions)
	}
	if got := approved.Decisions[0]; got.Account != "dana" || got.Channel != "out-of-band" || !got.Human {
		t.Errorf("decision = %+v, want dana's human out-of-band answer", got)
	}

	// The audit trail carries approval_decided AND a step_up record for
	// dana — the credential event and the decision event, both attributed.
	records, err := f.Deps.audit.List(context.Background())
	if err != nil {
		t.Fatalf("audit List: %v", err)
	}
	var sawDecision, sawStepUp bool
	for _, r := range records {
		if r.Kind == audit.KindApprovalDecided && r.Attribution.Verified.AccountName == "dana" {
			sawDecision = true
		}
		if r.Kind == audit.KindStepUp && r.Attribution.Verified.AccountName == "dana" {
			sawStepUp = true
		}
	}
	if !sawDecision {
		t.Error("no approval_decided record attributed to dana")
	}
	if !sawStepUp {
		t.Error("no step_up record attributed to dana")
	}

	// The requester's re-drive of the SAME dispatch now RUNS, matched by
	// plan hash — a Job exists where it could not before the approval. The
	// Node is registered but never connects, so `unreachable` is the
	// truthful per-Node outcome; what matters is that dispatch happened.
	runResp := restartMutate(t, f, requester)
	defer runResp.Body.Close()
	if runResp.StatusCode != http.StatusOK {
		t.Fatalf("re-drive status = %d, want 200 after the Console's approval", runResp.StatusCode)
	}
	var ran struct {
		JobID   string `json:"job_id"`
		Results []struct {
			NodeID  string `json:"node_id"`
			Outcome string `json:"outcome"`
		} `json:"results"`
	}
	if err := json.NewDecoder(runResp.Body).Decode(&ran); err != nil {
		t.Fatalf("decode run: %v", err)
	}
	if ran.JobID == "" {
		t.Fatal("no job_id after the Console's approval; the approved Plan must actually dispatch")
	}
	if len(ran.Results) != 1 || ran.Results[0].NodeID != "node-e2e-1" || ran.Results[0].Outcome != "unreachable" {
		t.Errorf("results = %+v, want one truthful unreachable result for node-e2e-1", ran.Results)
	}
}

// TestApprovalCallout_ConsoleDecideRunAsOperator proves criterion 1 at the
// role it actually names: "a human Account with the RIGHT role", which is
// the operator FLOOR (console.go's route table, authz.requiredRole's lowest
// return), not admin. TestApprovalCallout_ConsoleDecideRun already proved
// the same acceptance at admin and covers the audit/re-drive detail this
// leg does not repeat; the LOWER bound was otherwise only covered by the
// viewer-404 test and the route table's MinRole declaration, never by an
// operator actually deciding something.
func TestApprovalCallout_ConsoleDecideRunAsOperator(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates, WithConfig(func(c *Config) { c.ConsoleEnabled = true }))

	requester := mintAccount(t, f, "gleipnir-prod", accounts.KindMachine, accounts.RoleAdmin)
	parkResp := restartMutate(t, f, requester)
	defer parkResp.Body.Close()
	if parkResp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", parkResp.StatusCode)
	}
	var parked parkedBody
	if err := json.NewDecoder(parkResp.Body).Decode(&parked); err != nil {
		t.Fatalf("decode park: %v", err)
	}

	patID, patToken := mintConsoleHumanAccount(t, f, "pat", "pat's console password", accounts.RoleOperator)
	if acct, err := f.Deps.store.Accounts().Get(context.Background(), patID); err != nil || acct.Role != accounts.RoleOperator {
		t.Fatalf("pat's role = %+v, err %v, want operator", acct, err)
	}

	client := consoleClient(t, f)
	consoleSignIn(t, client, f, "pat", "pat's console password")

	cardResp, err := client.Get(f.ControlBase + "/console/approvals/" + parked.RequestID)
	if err != nil {
		t.Fatalf("GET approval card: %v", err)
	}
	cardBody := readAll(t, cardResp)
	csrfToken := consoleHiddenField(t, cardBody, "csrf_token")
	planHash := consoleHiddenField(t, cardBody, "plan_hash")

	decideResp, err := client.PostForm(f.ControlBase+"/console/approvals/"+parked.RequestID+"/decision", url.Values{
		"csrf_token": {csrfToken},
		"plan_hash":  {planHash},
		"answer":     {"approve"},
		"password":   {"pat's console password"},
	})
	if err != nil {
		t.Fatalf("POST decision: %v", err)
	}
	decideBody := readAll(t, decideResp)
	if decideResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("decide status = %d, want 303; body %s", decideResp.StatusCode, decideBody)
	}

	getApproval := controlAPIRequest(t, f.ClientFor(patToken), http.MethodGet,
		f.ControlBase+"/api/v1/approvals/"+parked.RequestID, patToken, nil)
	defer getApproval.Body.Close()
	var approved approvalBody
	if err := json.NewDecoder(getApproval.Body).Decode(&approved); err != nil {
		t.Fatalf("decode approval: %v", err)
	}
	if approved.State != "approved" {
		t.Fatalf("state = %q, want approved", approved.State)
	}
	if len(approved.Decisions) != 1 || approved.Decisions[0].Account != "pat" || !approved.Decisions[0].Human {
		t.Errorf("decisions = %+v, want pat's human answer", approved.Decisions)
	}
}

// TestApprovalCallout_ConsoleDenyIsTerminalAndTheRequesterSeesIt is #453's
// criterion 2: deny through the Console is terminal, the requester reads it
// on their OWN channel (the API, never the Console), a second decision is
// refused, and the re-drive does not dispatch.
func TestApprovalCallout_ConsoleDenyIsTerminalAndTheRequesterSeesIt(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates, WithConfig(func(c *Config) { c.ConsoleEnabled = true }))

	requester := f.Credential // the founding admin, over the API
	parkResp := restartMutate(t, f, requester)
	defer parkResp.Body.Close()
	if parkResp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", parkResp.StatusCode)
	}
	var parked parkedBody
	if err := json.NewDecoder(parkResp.Body).Decode(&parked); err != nil {
		t.Fatalf("decode park: %v", err)
	}

	_, danaToken := mintConsoleHumanAccount(t, f, "dana", "dana's console password", accounts.RoleAdmin)

	client := consoleClient(t, f)
	consoleSignIn(t, client, f, "dana", "dana's console password")

	cardResp, err := client.Get(f.ControlBase + "/console/approvals/" + parked.RequestID)
	if err != nil {
		t.Fatalf("GET approval card: %v", err)
	}
	cardBody := readAll(t, cardResp)
	csrfToken := consoleHiddenField(t, cardBody, "csrf_token")
	planHash := consoleHiddenField(t, cardBody, "plan_hash")

	decideResp, err := client.PostForm(f.ControlBase+"/console/approvals/"+parked.RequestID+"/decision", url.Values{
		"csrf_token": {csrfToken},
		"plan_hash":  {planHash},
		"answer":     {"deny"},
		"reason":     {"not during the freeze window"},
		"password":   {"dana's console password"},
	})
	if err != nil {
		t.Fatalf("POST decision: %v", err)
	}
	decideBody := readAll(t, decideResp)
	if decideResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("deny status = %d, want 303; body %s", decideResp.StatusCode, decideBody)
	}

	// The requester reads the denial on THEIR OWN channel — the API, the
	// same channel they parked on, never the Console.
	getApproval := controlAPIRequest(t, f.Client(), http.MethodGet,
		f.ControlBase+"/api/v1/approvals/"+parked.RequestID, requester, nil)
	defer getApproval.Body.Close()
	var denied approvalBody
	if err := json.NewDecoder(getApproval.Body).Decode(&denied); err != nil {
		t.Fatalf("decode approval: %v", err)
	}
	if denied.State != "denied" {
		t.Fatalf("state = %q, want denied", denied.State)
	}
	if len(denied.Decisions) != 1 || denied.Decisions[0].Account != "dana" || denied.Decisions[0].Approve {
		t.Fatalf("decisions = %+v, want exactly dana's denial", denied.Decisions)
	}

	// A second decision is refused: deny is terminal.
	secondResp := controlAPIRequest(t, f.ClientFor(danaToken), http.MethodPost,
		f.ControlBase+parked.DecisionPath, danaToken,
		map[string]any{"approve": true, "plan_hash": parked.PlanHash})
	defer secondResp.Body.Close()
	if secondResp.StatusCode != http.StatusConflict {
		t.Fatalf("second decision status = %d, want 409 (a denial is terminal)", secondResp.StatusCode)
	}

	// The re-drive does not dispatch: it still parks (a fresh Request,
	// matched by the same plan hash finding a terminal one, not a Job).
	retry := restartMutate(t, f, requester)
	defer retry.Body.Close()
	if retry.StatusCode != http.StatusAccepted {
		t.Fatalf("re-drive after denial status = %d, want it still parked", retry.StatusCode)
	}
}

// TestApprovalCallout_ConsoleSelfApprovalIsRefused closes the gap review
// found in decide_test.go's fake-decider tests: those prove the Console
// forwards and renders whatever the domain says, never that the domain
// actually refuses self-approval. This drives the REAL rule, end to end, on
// the Console surface — the SELF-APPROVAL half of criterion 3, the machine
// half already covered by the extension to
// TestApprovalCallout_MachineCannotSatisfyItsOwnGate.
//
// The requester here is a HUMAN Account, deliberately: a machine cannot sign
// in to the Console at all (consoleauth.resolve refuses a non-human Kind),
// so proving THIS rule on THIS surface requires a requester who could
// otherwise reach the route.
func TestApprovalCallout_ConsoleSelfApprovalIsRefused(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates, WithConfig(func(c *Config) { c.ConsoleEnabled = true }))

	_, requesterToken := mintConsoleHumanAccount(t, f, "dana", "dana's console password", accounts.RoleAdmin)

	parkResp := restartMutate(t, f, requesterToken)
	defer parkResp.Body.Close()
	if parkResp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", parkResp.StatusCode)
	}
	var parked parkedBody
	if err := json.NewDecoder(parkResp.Body).Decode(&parked); err != nil {
		t.Fatalf("decode park: %v", err)
	}

	client := consoleClient(t, f)
	consoleSignIn(t, client, f, "dana", "dana's console password")

	cardResp, err := client.Get(f.ControlBase + "/console/approvals/" + parked.RequestID)
	if err != nil {
		t.Fatalf("GET approval card: %v", err)
	}
	cardBody := readAll(t, cardResp)
	if strings.Contains(cardBody, "<form") {
		t.Error("the requester's own card still offered a decision form")
	}

	// The card offers no form (buildApprovalView's CallerIsExcludedRequester
	// gate), so the token comes from the fleet view — the same fallback
	// decide_test.go's identical case uses — and the plan hash is the park's
	// own, exactly as a caller reading only the queue's stored hash would
	// submit.
	fleetResp, err := client.Get(f.ControlBase + "/console/")
	if err != nil {
		t.Fatalf("GET fleet view: %v", err)
	}
	fleetBody := readAll(t, fleetResp)
	csrfToken := consoleHiddenField(t, fleetBody, "csrf_token")

	decideResp, err := client.PostForm(f.ControlBase+"/console/approvals/"+parked.RequestID+"/decision", url.Values{
		"csrf_token": {csrfToken},
		"plan_hash":  {parked.PlanHash},
		"answer":     {"approve"},
		"password":   {"dana's console password"},
	})
	if err != nil {
		t.Fatalf("POST decision: %v", err)
	}
	decideBody := readAll(t, decideResp)
	if decideResp.StatusCode != http.StatusConflict {
		t.Fatalf("self-approval status = %d, want 409; body %s", decideResp.StatusCode, decideBody)
	}

	// It really did not run: the dispatch still parks.
	retry := restartMutate(t, f, requesterToken)
	defer retry.Body.Close()
	if retry.StatusCode != http.StatusAccepted {
		t.Fatalf("re-drive status = %d, want it still parked", retry.StatusCode)
	}
}

// consoleSessionCookie returns the Console session cookie value currently in
// the client jar, failing if there is none.
func consoleSessionCookie(t *testing.T, client *http.Client, base string) string {
	t.Helper()
	u, err := url.Parse(base + "/console/")
	if err != nil {
		t.Fatalf("parse %q: %v", base, err)
	}
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == consoleauth.SessionCookieName {
			return c.Value
		}
	}
	t.Fatal("the client jar holds no Console session cookie")
	return ""
}
