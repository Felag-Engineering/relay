package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/enroll"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

var (
	mintRevealBlock = regexp.MustCompile(`<pre><code>([^<]*)</code></pre>`)
	mintRevealID    = regexp.MustCompile(`<dt>Token ID</dt><dd><code>([^<]+)</code>`)
)

// mintTokenRecords is the token_mint records on the trail.
func mintTokenRecords(t *testing.T, f *relayFixture) []audit.Record {
	t.Helper()
	recs, err := f.Deps.audit.List(context.Background())
	if err != nil {
		t.Fatalf("audit List: %v", err)
	}
	var out []audit.Record
	for _, r := range recs {
		if r.Kind == audit.KindTokenMint {
			out = append(out, r)
		}
	}
	return out
}

// Proves EN-36, EN-47.
func TestConsoleEnrollmentMint_AnAdminMintsThroughTheRealCapabilityLayer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f := startRelay(t, WithControlPlane(), WithConfig(func(c *Config) { c.ConsoleEnabled = true }))

	const password = "the admin's console password"
	adminID, _ := mintConsoleHumanAccount(t, f, "ada", password, accounts.RoleAdmin)
	browser := consoleClient(t, f)
	consoleSignIn(t, browser, f, "ada", password)

	getPage := func(path string) (int, string) {
		t.Helper()
		resp, err := browser.Get(f.ControlBase + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		return resp.StatusCode, readAll(t, resp)
	}
	post := func(form url.Values) (*http.Response, string) {
		t.Helper()
		resp, err := browser.PostForm(f.ControlBase+"/console/add-nodes/tokens", form)
		if err != nil {
			t.Fatalf("POST mint: %v", err)
		}
		return resp, readAll(t, resp)
	}
	form := func(csrf, pw string) url.Values {
		return url.Values{
			"csrf_token": {csrf}, "nodes": {"1"}, "ttl": {"2h"},
			"initial_tags": {"tag:env=prod"}, "password": {pw},
		}
	}

	code, page := getPage("/console/add-nodes")
	if code != http.StatusOK {
		t.Fatalf("GET add-nodes = %d, want 200", code)
	}
	csrf := consoleHiddenField(t, page, "csrf_token")
	firstForm := form(csrf, password)
	resp, body := post(firstForm)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("mint = %d, Cache-Control %q, want 200 and no-store; %s", resp.StatusCode, resp.Header.Get("Cache-Control"), body)
	}
	if nodes := f.Deps.registry.List(); len(nodes) != 0 {
		t.Fatalf("registry holds %d Nodes after a mint; the Console added a Node", len(nodes))
	}

	blocks := mintRevealBlock.FindAllStringSubmatch(body, -1)
	idm := mintRevealID.FindStringSubmatch(body)
	if len(blocks) != 2 || blocks[0][1] != "sudo relay-daemon join" || idm == nil {
		t.Fatalf("the reveal has blocks %v and id %v, want the command then the join string", blocks, idm)
	}
	joinString, tokenID := blocks[1][1], idm[1]
	js, err := enroll.DecodeJoinString(joinString)
	if err != nil {
		t.Fatalf("the revealed join string does not decode: %v", err)
	}

	stored, err := f.Deps.store.Tokens().ByID(ctx, tokenID)
	if err != nil {
		t.Fatalf("ByID(%s): %v", tokenID, err)
	}
	if stored.MaxUses != 1 || stored.CreatedByAccountID != adminID || !stored.CreatedByHuman ||
		len(stored.InitialTags) != 1 || stored.InitialTags[0] != "tag:env=prod" {
		t.Errorf("stored token = %+v", stored)
	}
	if d := time.Until(stored.ExpiresAt) - 2*time.Hour; d > time.Minute || d < -time.Minute {
		t.Errorf("ExpiresAt is %v off two hours from now", d)
	}

	recs := mintTokenRecords(t, f)
	if len(recs) != 1 || recs[0].Reason != "token_id="+tokenID || recs[0].Attribution.Verified.AccountID != adminID {
		t.Fatalf("token_mint records = %+v, want one for %s by the admin", recs, tokenID)
	}
	all, err := f.Deps.audit.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range all {
		b, _ := json.Marshal(r)
		if strings.Contains(string(b), joinString) || strings.Contains(string(b), js.EnrollmentToken()) {
			t.Errorf("audit record %d carries the join string or token", i)
		}
	}

	// A Node enrolls with it, and the Console shows where the Node came from.
	enrollConn := dialTLS(t, f.Bufconn, &tls.Config{RootCAs: relaytest.CertPool(t, f.Deps.ca.Bundle())})
	csrPEM, _ := relaytest.NewCSR(t, "ignored-cn")
	enrolled, err := relayv1.NewEnrollmentClient(enrollConn).Enroll(ctx, &relayv1.EnrollRequest{
		EnrollmentToken: js.EnrollmentToken(), Csr: csrPEM,
		Facts: &relayv1.Facts{Hostname: "host-console-mint", Os: "linux"},
	})
	if err != nil {
		t.Fatalf("Enroll with the revealed join string: %v", err)
	}
	node, ok := f.Deps.registry.Get(enrolled.GetNodeId())
	if !ok || node.EnrollingTokenID != tokenID || node.TagLabels["env"] != "prod" {
		t.Fatalf("enrolled Node = %+v (found %v), want token %s and tag env=prod", node, ok, tokenID)
	}
	if code, nodePage := getPage("/console/nodes/" + enrolled.GetNodeId()); code != http.StatusOK || !strings.Contains(nodePage, "<code>"+tokenID+"</code>") {
		t.Errorf("the Node page = %d and does not show the token %s as provenance", code, tokenID)
	}

	// The session id rotated on the mint, so a wrong password needs a fresh
	// token. It stores nothing and records nothing.
	_, page = getPage("/console/add-nodes")
	resp, body = post(form(consoleHiddenField(t, page, "csrf_token"), "not the password"))
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "That password did not match. Nothing was minted.") {
		t.Errorf("wrong password = %d, body %s", resp.StatusCode, body)
	}
	if got := len(mintTokenRecords(t, f)); got != 1 {
		t.Errorf("token_mint records after a wrong password = %d, want 1", got)
	}

	// A browser refresh of the reveal re-posts the first form: the old CSRF
	// token no longer validates, and nothing more is minted.
	resp, _ = post(firstForm)
	if resp.StatusCode == http.StatusOK {
		t.Error("re-posting the reveal's form minted again")
	}
	if got := len(mintTokenRecords(t, f)); got != 1 {
		t.Errorf("token_mint records after a re-post = %d, want 1", got)
	}
}

// Proves EN-36.
func TestConsoleEnrollmentMint_TheConsoleAndTheControlAPIShareOneFloorAndOneRecord(t *testing.T) {
	f := startRelay(t, WithControlPlane(), WithConfig(func(c *Config) { c.ConsoleEnabled = true }))
	ctx := context.Background()

	const password = "a console password"
	_, operatorToken := mintConsoleHumanAccount(t, f, "olive", password, accounts.RoleOperator)
	adminID, adminToken := mintConsoleHumanAccount(t, f, "ada", password, accounts.RoleAdmin)

	// The floor: an operator is refused on both surfaces.
	operator := consoleClient(t, f)
	consoleSignIn(t, operator, f, "olive", password)
	// A valid CSRF token, from the operator's own account page, so the 404 is
	// the route's absence and not the CSRF check's refusal.
	acctResp, err := operator.Get(f.ControlBase + "/console/account")
	if err != nil {
		t.Fatal(err)
	}
	operatorCSRF := consoleHiddenField(t, readAll(t, acctResp), "csrf_token")
	resp, err := operator.PostForm(f.ControlBase+"/console/add-nodes/tokens",
		url.Values{"csrf_token": {operatorCSRF}, "nodes": {"1"}, "ttl": {"2h"}, "password": {password}})
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, resp)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("an operator's Console mint = %d, want 404", resp.StatusCode)
	}
	apiResp := controlAPIRequest(t, f.ClientFor(""), http.MethodPost, f.ControlBase+"/api/v1/enrollment-tokens", operatorToken,
		map[string]any{"ttl_seconds": 3600, "max_uses": 1})
	apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusForbidden {
		t.Errorf("an operator's API mint = %d, want 403", apiResp.StatusCode)
	}
	if got := len(mintTokenRecords(t, f)); got != 0 {
		t.Fatalf("token_mint records after two refusals = %d, want 0", got)
	}

	// One mint on each surface by the admin.
	browser := consoleClient(t, f)
	consoleSignIn(t, browser, f, "ada", password)
	pageResp, err := browser.Get(f.ControlBase + "/console/add-nodes")
	if err != nil {
		t.Fatal(err)
	}
	csrf := consoleHiddenField(t, readAll(t, pageResp), "csrf_token")
	mintResp, err := browser.PostForm(f.ControlBase+"/console/add-nodes/tokens",
		url.Values{"csrf_token": {csrf}, "nodes": {"1"}, "ttl": {"2h"}, "password": {password}})
	if err != nil {
		t.Fatal(err)
	}
	if body := readAll(t, mintResp); mintResp.StatusCode != http.StatusOK {
		t.Fatalf("admin Console mint = %d; %s", mintResp.StatusCode, body)
	}
	apiResp = controlAPIRequest(t, f.ClientFor(""), http.MethodPost, f.ControlBase+"/api/v1/enrollment-tokens", adminToken,
		map[string]any{"ttl_seconds": 3600, "max_uses": 1})
	apiResp.Body.Close()
	if apiResp.StatusCode != http.StatusCreated {
		t.Fatalf("admin API mint = %d, want 201", apiResp.StatusCode)
	}

	recs := mintTokenRecords(t, f)
	if len(recs) != 2 {
		t.Fatalf("token_mint records = %d, want 2", len(recs))
	}
	for i, r := range recs {
		if !strings.HasPrefix(r.Reason, "token_id=") || len(r.Reason) == len("token_id=") {
			t.Errorf("record %d Reason = %q, want token_id=<id>", i, r.Reason)
		}
		if _, err := f.Deps.store.Tokens().ByID(ctx, strings.TrimPrefix(r.Reason, "token_id=")); err != nil {
			t.Errorf("record %d names a token the store does not hold: %v", i, err)
		}
		if r.Principal != recs[0].Principal || r.Attribution.Verified.AccountID != adminID ||
			r.Attribution.Verified.Role != recs[0].Attribution.Verified.Role {
			t.Errorf("record %d = %+v, differs from record 0 in Principal or verified identity", i, r)
		}
	}
	if recs[0].Kind != recs[1].Kind {
		t.Errorf("the two records differ in Kind: %q, %q", recs[0].Kind, recs[1].Kind)
	}
}
