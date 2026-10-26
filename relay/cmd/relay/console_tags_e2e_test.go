package main

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// consoleNodeIDs scrapes every node_id hidden input from a rendered page.
func consoleNodeIDs(body string) []string {
	var ids []string
	for _, m := range regexp.MustCompile(`name="node_id" value="([^"]*)"`).FindAllStringSubmatch(body, -1) {
		ids = append(ids, m[1])
	}
	return ids
}

// tagWriteRecords is the tag_write records on nodeID's trail whose reason names
// the tag key.
func tagWriteRecords(t *testing.T, f *relayFixture, nodeID, key string) []audit.Record {
	t.Helper()
	recs, err := f.Deps.store.Audit().ByNode(context.Background(), nodeID)
	if err != nil {
		t.Fatalf("ByNode(%s): %v", nodeID, err)
	}
	var out []audit.Record
	for _, r := range recs {
		if r.Kind == audit.KindTagWrite && strings.HasPrefix(r.Reason, "tag:"+key+" ") {
			out = append(out, r)
		}
	}
	return out
}

// TestConsoleTags_AHumanOperatorTagsANodeAndASelectionThroughTheRealCapabilityLayer
// proves the Console's tag controls through the real composition root: a Node
// page adds a tag, a malformed namespace is refused with nothing written, a
// confirmed selection is exactly the set tagged even when the fleet changes
// between the page and the click, and a viewer finds the controls absent.
func TestConsoleTags_AHumanOperatorTagsANodeAndASelectionThroughTheRealCapabilityLayer(t *testing.T) {
	f := startRelay(t, WithControlPlane(), WithConfig(func(c *Config) { c.ConsoleEnabled = true }))
	seed := func(id, role string) {
		t.Helper()
		if _, err := f.Deps.registry.Upsert(registry.Report{NodeID: id}.WithNodeLabels(map[string]string{"role": role})); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	seed("node-a", "web")
	seed("node-b", "web")
	seed("node-c", "db")

	const password = "the operator's console password"
	operatorID, _ := mintConsoleHumanAccount(t, f, "olive", password, accounts.RoleOperator)
	browser := consoleClient(t, f)
	consoleSignIn(t, browser, f, "olive", password)

	getPage := func(path string) (int, string) {
		t.Helper()
		resp, err := browser.Get(f.ControlBase + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		code := resp.StatusCode
		return code, readAll(t, resp)
	}
	postForm := func(path string, form url.Values) (int, string) {
		t.Helper()
		resp, err := browser.PostForm(f.ControlBase+path, form)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		code := resp.StatusCode
		return code, readAll(t, resp)
	}

	// (a) Node page: add a tag.
	code, page := getPage("/console/nodes/node-a")
	if code != http.StatusOK {
		t.Fatalf("GET node-a = %d, want 200", code)
	}
	token := consoleHiddenField(t, page, "csrf_token")
	code, _ = postForm("/console/nodes/node-a/tags", url.Values{"csrf_token": {token}, "op": {"add"}, "label": {"tag:env=prod"}})
	if code != http.StatusSeeOther {
		t.Fatalf("POST add tag:env=prod = %d, want 303", code)
	}
	if n, _ := f.Deps.registry.Get("node-a"); n.TagLabels["env"] != "prod" {
		t.Errorf("node-a TagLabels = %v, want env=prod", n.TagLabels)
	}
	writes := tagWriteRecords(t, f, "node-a", "env")
	if len(writes) != 1 {
		t.Fatalf("tag_write records for node-a = %d, want exactly 1", len(writes))
	}
	if writes[0].Attribution.Verified.AccountID != operatorID {
		t.Errorf("tag_write names Account %q, want the signed-in operator %q", writes[0].Attribution.Verified.AccountID, operatorID)
	}

	// (b) A node: label is refused and nothing is written.
	before, _ := f.Deps.registry.Get("node-a")
	refusalsBefore := operatorRefusals(t, f, operatorID)
	code, _ = postForm("/console/nodes/node-a/tags", url.Values{"csrf_token": {token}, "op": {"add"}, "label": {"node:role=evil"}})
	if code != http.StatusBadRequest {
		t.Errorf("POST add node:role=evil = %d, want 400", code)
	}
	if got := operatorRefusals(t, f, operatorID); got != refusalsBefore+1 {
		t.Errorf("refusal records for the operator went from %d to %d, want one more: the capability layer audits the refusal", refusalsBefore, got)
	}
	after, _ := f.Deps.registry.Get("node-a")
	if !slices.Equal(mapPairs(after.NodeLabels), mapPairs(before.NodeLabels)) || !slices.Equal(mapPairs(after.TagLabels), mapPairs(before.TagLabels)) {
		t.Errorf("a refused write changed node-a: node %v tag %v, was node %v tag %v",
			after.NodeLabels, after.TagLabels, before.NodeLabels, before.TagLabels)
	}

	// (c) Bulk: confirm a filtered selection, change the fleet, then click.
	code, confirm := getPage("/console/tags/confirm?" + url.Values{
		"filter": {"node:role=web"}, "op": {"add"}, "label": {"tag:tier=front"},
	}.Encode())
	if code != http.StatusOK {
		t.Fatalf("GET the confirmation page = %d, want 200; %s", code, confirm)
	}
	listed := consoleNodeIDs(confirm)
	if !slices.Equal(listed, []string{"node-a", "node-b"}) {
		t.Fatalf("the confirmation page lists %v, want node-a and node-b", listed)
	}
	confirmToken := consoleHiddenField(t, confirm, "csrf_token")
	seed("node-c", "web") // the labels change between the page and the click
	code, result := postForm("/console/tags", url.Values{
		"csrf_token": {confirmToken}, "node_id": listed, "op": {"add"}, "label": {"tag:tier=front"},
	})
	if code != http.StatusOK {
		t.Fatalf("POST the bulk write = %d, want 200; %s", code, result)
	}
	for _, id := range []string{"node-a", "node-b"} {
		if !strings.Contains(result, ">"+id+"<") {
			t.Errorf("the result page does not list %s", id)
		}
		if n, _ := f.Deps.registry.Get(id); n.TagLabels["tier"] != "front" {
			t.Errorf("%s TagLabels = %v, want tier=front", id, n.TagLabels)
		}
	}
	if n, _ := f.Deps.registry.Get("node-c"); n.TagLabels["tier"] != "" {
		t.Errorf("node-c, which was not confirmed, carries tier=%q", n.TagLabels["tier"])
	}
	// The trail holds the confirmed set and nothing else.
	for _, id := range []string{"node-a", "node-b"} {
		recs := tagWriteRecords(t, f, id, "tier")
		if len(recs) != 1 || recs[0].Attribution.Verified.AccountID != operatorID {
			t.Errorf("tag_write records for %s key tier = %d, want 1 naming the operator", id, len(recs))
		}
	}
	if recs := tagWriteRecords(t, f, "node-c", "tier"); len(recs) != 0 {
		t.Errorf("tag_write records for node-c key tier = %d, want none", len(recs))
	}

	// (d) A viewer sees no control, and its POST is a 404.
	const viewerPassword = "the viewer's console password"
	mintConsoleHumanAccount(t, f, "vera", viewerPassword, accounts.RoleViewer)
	viewer := consoleClient(t, f)
	consoleSignIn(t, viewer, f, "vera", viewerPassword)
	resp, err := viewer.Get(f.ControlBase + "/console/nodes/node-a")
	if err != nil {
		t.Fatalf("viewer GET node-a: %v", err)
	}
	viewerPage := readAll(t, resp)
	if strings.Contains(viewerPage, "/console/nodes/node-a/tags") || strings.Contains(viewerPage, "Add tag") {
		t.Error("a viewer's Node page draws a tag control")
	}
	viewerToken := consoleHiddenField(t, viewerPage, "csrf_token")
	resp, err = viewer.PostForm(f.ControlBase+"/console/nodes/node-a/tags",
		url.Values{"csrf_token": {viewerToken}, "op": {"add"}, "label": {"tag:env=viewer"}})
	if err != nil {
		t.Fatalf("viewer POST: %v", err)
	}
	readAll(t, resp)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("a viewer's tag POST = %d, want 404", resp.StatusCode)
	}
	if n, _ := f.Deps.registry.Get("node-a"); n.TagLabels["env"] != "prod" {
		t.Errorf("a viewer's POST changed node-a: %v", n.TagLabels)
	}
}

// operatorRefusals counts the refusal records on the trail attributed to the
// Account accountID.
func operatorRefusals(t *testing.T, f *relayFixture, accountID string) int {
	t.Helper()
	recs, err := f.Deps.store.Audit().List(context.Background())
	if err != nil {
		t.Fatalf("audit List: %v", err)
	}
	n := 0
	for _, r := range recs {
		if r.Kind == audit.KindRefusal && r.Attribution.Verified.AccountID == accountID {
			n++
		}
	}
	return n
}

// mapPairs is m as sorted key=value pairs, for comparing two label maps.
func mapPairs(m map[string]string) []string {
	var out []string
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	slices.Sort(out)
	return out
}
