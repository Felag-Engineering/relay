package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// TestTags_HumanOperatorWritesOverTheControlAPIAndASelectorResolvesIt proves
// ADR-0050 end to end through the real composition root: a human operator adds
// a tag over the Control API, MCP list_nodes then resolves tag:env=prod to that
// Node and the Node read shows it as tag_labels, a viewer and a machine
// operator are refused on both routes, and the trail holds exactly one
// tag_write record for the Node.
func TestTags_HumanOperatorWritesOverTheControlAPIAndASelectorResolvesIt(t *testing.T) {
	f := startRelay(t, WithControlPlane())
	for _, id := range []string{"node-tag-a", "node-tag-b"} {
		if _, err := f.Deps.registry.Upsert(registry.Report{NodeID: id}); err != nil {
			t.Fatalf("seed registry (%s): %v", id, err)
		}
	}
	operator := mintAccount(t, f, "olive", accounts.KindHuman, accounts.RoleOperator)
	viewer := mintAccount(t, f, "vera", accounts.KindHuman, accounts.RoleViewer)
	machine := mintAccount(t, f, "robot", accounts.KindMachine, accounts.RoleOperator)

	post := func(token, path string, body any) *http.Response {
		t.Helper()
		return controlAPIRequest(t, f.ClientFor(token), http.MethodPost, f.ControlBase+path, token, body)
	}
	oneNode := map[string]string{"op": "add", "label": "tag:env=prod"}
	bulk := map[string]any{"node_ids": []string{"node-tag-b"}, "op": "add", "label": "tag:env=prod"}

	// A viewer and a machine operator are refused on both routes, and nothing
	// is written.
	for name, token := range map[string]string{"viewer": viewer, "machine operator": machine} {
		for path, body := range map[string]any{"/api/v1/nodes/node-tag-a/tags": oneNode, "/api/v1/tags": bulk} {
			resp := post(token, path, body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s POST %s = %d, want 403", name, path, resp.StatusCode)
			}
		}
	}
	if n, _ := f.Deps.registry.Get("node-tag-a"); len(n.TagLabels) != 0 {
		t.Fatalf("a refused write changed the Node: %v", n.TagLabels)
	}

	// A human operator adds the tag.
	resp := post(operator, "/api/v1/nodes/node-tag-a/tags", oneNode)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("operator POST /api/v1/nodes/node-tag-a/tags = %d, want 200", resp.StatusCode)
	}

	// MCP resolves the tag: term to that Node alone.
	session := relaytest.Connect(t, f.ControlBase, f.ClientFor(operator))
	res := relaytest.CallTool(t, session, "list_nodes", map[string]any{"selector": "tag:env=prod"})
	if res.IsError {
		t.Fatalf("list_nodes(tag:env=prod): %s", relaytest.ToolErrorText(t, res))
	}
	var listing mcp.ListNodesOutput
	if err := json.Unmarshal([]byte(mcpToolText(t, res)), &listing); err != nil {
		t.Fatalf("decode list_nodes: %v", err)
	}
	if len(listing.Nodes) != 1 || listing.Nodes[0].NodeID != "node-tag-a" || listing.Nodes[0].TagLabels["env"] != "prod" {
		t.Errorf("list_nodes(tag:env=prod) = %+v, want only node-tag-a carrying the tag", listing.Nodes)
	}

	// The Control API's Node read shows it as its own map.
	get := controlAPIRequest(t, f.ClientFor(operator), http.MethodGet, f.ControlBase+"/api/v1/nodes/node-tag-a", operator, nil)
	defer get.Body.Close()
	var node struct {
		TagLabels  map[string]string `json:"tag_labels"`
		NodeLabels map[string]string `json:"node_labels"`
	}
	if err := json.NewDecoder(get.Body).Decode(&node); err != nil {
		t.Fatalf("decode node: %v", err)
	}
	if node.TagLabels["env"] != "prod" || len(node.NodeLabels) != 0 {
		t.Errorf("GET node = tag_labels %v node_labels %v, want the tag in its own map", node.TagLabels, node.NodeLabels)
	}

	// No MCP tool writes a tag: the tool list the session sees names none.
	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	for _, tool := range tools.Tools {
		if strings.Contains(strings.ToLower(tool.Name), "tag") {
			t.Errorf("MCP exposes a tag-writing tool %q", tool.Name)
		}
	}

	// One tag_write record for the Node, naming the Account and the change.
	recs, err := f.Deps.store.Audit().ByNode(context.Background(), "node-tag-a")
	if err != nil {
		t.Fatalf("ByNode: %v", err)
	}
	var writes []audit.Record
	for _, r := range recs {
		if r.Kind == audit.KindTagWrite {
			writes = append(writes, r)
		}
	}
	if len(writes) != 1 {
		t.Fatalf("tag_write records for node-tag-a = %d, want exactly 1 (refused writes record refusals, not tag writes)", len(writes))
	}
	if writes[0].Reason != `tag:env old=(none) new="prod"` {
		t.Errorf("tag_write reason = %q", writes[0].Reason)
	}
	if got := writes[0].Attribution.Verified.AccountID; got == "" {
		t.Error("the tag_write record names no verified Account")
	}
}
