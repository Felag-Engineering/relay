package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// policyAliasRecords is the policy_alias records on the trail, oldest first.
func policyAliasRecords(t *testing.T, f *relayFixture) []audit.Record {
	t.Helper()
	recs, err := f.Deps.store.Audit().List(context.Background())
	if err != nil {
		t.Fatalf("audit List: %v", err)
	}
	var out []audit.Record
	for _, r := range recs {
		if r.Kind == audit.KindPolicyAlias {
			out = append(out, r)
		}
	}
	return out
}

// aliasReason is the Reason the capability layer records for a change.
func aliasReason(fingerprint, old, next string) string {
	return fmt.Sprintf("fingerprint=%s old=%q new=%q", fingerprint, old, next)
}

// TestConsolePolicyAliases_AHumanAdminSetsRenamesAndClearsThroughTheRealCapabilityLayer
// proves the Console's Policy alias controls through the real composition
// root: a human admin sets, renames and clears an alias from Node detail; the
// alias is drawn beside the full fingerprint on Node detail, Fleet and Compare;
// each change leaves exactly one policy_alias record naming the admin; a name
// another fingerprint holds is refused with the capability layer's words and a
// refusal record; a human operator is offered no control and finds the route
// absent; and a machine Account at admin is drawn no alias name and no
// control, only the letter and the full fingerprint.
func TestConsolePolicyAliases_AHumanAdminSetsRenamesAndClearsThroughTheRealCapabilityLayer(t *testing.T) {
	f := startRelay(t, WithControlPlane(), WithConfig(func(c *Config) { c.ConsoleEnabled = true }))
	fpA, fpB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	for id, fp := range map[string]string{"node-a": fpA, "node-b": fpB} {
		if _, err := f.Deps.registry.Upsert(registry.Report{NodeID: id, PolicyFingerprint: fp}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}

	const password = "the admin's console password"
	adminID, _ := mintConsoleHumanAccount(t, f, "ada", password, accounts.RoleAdmin)
	browser := consoleClient(t, f)
	consoleSignIn(t, browser, f, "ada", password)

	get := func(client *http.Client, path string) (int, string) {
		t.Helper()
		resp, err := client.Get(f.ControlBase + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		return resp.StatusCode, readAll(t, resp)
	}
	post := func(client *http.Client, form url.Values) (*http.Response, string) {
		t.Helper()
		resp, err := client.PostForm(f.ControlBase+"/console/policy-aliases", form)
		if err != nil {
			t.Fatalf("POST the alias: %v", err)
		}
		defer resp.Body.Close()
		return resp, readAll(t, resp)
	}
	drawn := func(path, alias, fp string) bool {
		t.Helper()
		code, body := get(browser, path)
		if code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, code)
		}
		return strings.Contains(body, `<bdi class="fpalias">`+alias+`</bdi> <code class="fphash">`+fp+`</code>`)
	}
	form := func(token, node, fp, op, alias string) url.Values {
		return url.Values{"csrf_token": {token}, "node_id": {node}, "fingerprint": {fp}, "op": {op}, "alias": {alias}}
	}

	// (a) The Node page carries the editor, and a set is drawn everywhere.
	code, page := get(browser, "/console/nodes/node-a")
	if code != http.StatusOK || !strings.Contains(page, `name="fingerprint" value="`+fpA+`"`) {
		t.Fatalf("a human admin's Node page = %d, with the editor = %v", code, strings.Contains(page, "Edit alias"))
	}
	token := consoleHiddenField(t, page, "csrf_token")
	resp, _ := post(browser, form(token, "node-a", fpA, "set", "web-hardened"))
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/console/nodes/node-a" {
		t.Fatalf("set = %d to %q, want 303 back to the Node", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, path := range []string{"/console/nodes/node-a", "/console/?group=-", "/console/compare?nodes=node-a,node-b"} {
		if !drawn(path, "web-hardened", fpA) {
			t.Errorf("%s does not draw the alias beside the full fingerprint", path)
		}
	}
	recs := policyAliasRecords(t, f)
	if len(recs) != 1 {
		t.Fatalf("policy_alias records = %d, want exactly 1", len(recs))
	}
	if recs[0].Attribution.Verified.AccountID != adminID || recs[0].Reason != aliasReason(fpA, "", "web-hardened") {
		t.Errorf("record = account %q reason %q, want the admin and %q",
			recs[0].Attribution.Verified.AccountID, recs[0].Reason, aliasReason(fpA, "", "web-hardened"))
	}

	// (b) A rename leaves one more record.
	resp, _ = post(browser, form(token, "node-a", fpA, "set", "web-v2"))
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("rename = %d, want 303", resp.StatusCode)
	}
	recs = policyAliasRecords(t, f)
	if len(recs) != 2 || recs[1].Reason != aliasReason(fpA, "web-hardened", "web-v2") {
		t.Fatalf("after the rename the records are %d, last reason %q", len(recs), recs[len(recs)-1].Reason)
	}

	// (c) Another fingerprint claiming the name is refused in the capability
	// layer's words; nothing changes, and the refusal is on the trail.
	refusalsBefore := operatorRefusals(t, f, adminID)
	resp, body := post(browser, form(token, "node-b", fpB, "set", "web-v2"))
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body, "already names another Policy fingerprint") || !strings.Contains(body, "Nothing was changed.") {
		t.Errorf("a taken name = %d %q, want 409 in the capability layer's words", resp.StatusCode, body)
	}
	if got := len(policyAliasRecords(t, f)); got != 2 {
		t.Errorf("a refused alias left %d policy_alias records, want 2", got)
	}
	if got := operatorRefusals(t, f, adminID); got != refusalsBefore+1 {
		t.Errorf("refusal records went from %d to %d, want one more", refusalsBefore, got)
	}
	if drawn("/console/nodes/node-b", "web-v2", fpB) {
		t.Error("the refused alias is drawn on the second fingerprint")
	}

	// (e) A human operator is offered no control and finds the route absent.
	const operatorPassword = "the operator's console password"
	mintConsoleHumanAccount(t, f, "olive", operatorPassword, accounts.RoleOperator)
	operator := consoleClient(t, f)
	consoleSignIn(t, operator, f, "olive", operatorPassword)
	code, page = get(operator, "/console/nodes/node-a")
	if code != http.StatusOK || strings.Contains(page, "Edit alias") || !strings.Contains(page, `<bdi class="fpalias">web-v2</bdi>`) {
		t.Errorf("an operator's Node page = %d, editor drawn = %v, alias drawn = %v", code,
			strings.Contains(page, "Edit alias"), strings.Contains(page, `<bdi class="fpalias">web-v2</bdi>`))
	}
	resp, _ = post(operator, form(consoleHiddenField(t, page, "csrf_token"), "node-a", fpA, "set", "operator-name"))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("an operator's POST = %d, want the gated 404", resp.StatusCode)
	}

	// (f) A machine Account at admin is drawn no alias name and no control, only
	// the neutral letter and the full fingerprint: the Console reads and draws
	// alias names for a human only, and the composition root carries the
	// Account's kind into the principal the Console reads.
	machine := mintAccount(t, f, "robot", accounts.KindMachine, accounts.RoleAdmin)
	for _, path := range []string{"/console/nodes/node-a", "/console/?group=-", "/console/compare?nodes=node-a,node-b"} {
		resp := controlAPIRequest(t, f.ClientFor(machine), http.MethodGet, f.ControlBase+path, machine, nil)
		body := readAll(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("a machine admin's GET %s = %d, want 200", path, resp.StatusCode)
		}
		if strings.Contains(body, "web-v2") || strings.Contains(body, `class="fpalias"`) {
			t.Errorf("a machine admin's %s is drawn an alias name", path)
		}
		if !strings.Contains(body, `<span class="fpletter"`) || !strings.Contains(body, `<code class="fphash">`+fpA+`</code>`) {
			t.Errorf("a machine admin's %s is not drawn the letter and the full fingerprint", path)
		}
		if strings.Contains(body, "Edit alias") || strings.Contains(body, `action="/console/policy-aliases"`) {
			t.Errorf("a machine admin's %s is offered the Edit alias control", path)
		}
	}

	// (d) Clear: the alias is gone and the record says so.
	resp, _ = post(browser, form(token, "node-a", fpA, "clear", ""))
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("clear = %d, want 303", resp.StatusCode)
	}
	recs = policyAliasRecords(t, f)
	if len(recs) != 3 || recs[2].Reason != aliasReason(fpA, "web-v2", "") {
		t.Fatalf("after the clear the records are %d, last reason %q", len(recs), recs[len(recs)-1].Reason)
	}
	_, page = get(browser, "/console/nodes/node-a")
	if strings.Contains(page, "web-v2") || !strings.Contains(page, `<span class="fpletter"`) {
		t.Error("a cleared alias is still drawn, or its fingerprint has no letter")
	}
}
