// Package main: query_read_floor_e2e_test.go proves QRY-15's Control API and
// Console halves (docs/specs/query.md) — "the read floor is `viewer` on MCP,
// the Control API and the Console alike; no narrower role gate applies" — as
// ONE cross-surface parity table driven by ONE viewer Account.
//
// It lives here because only the composition root composes all three surfaces
// over one authenticator, and because the three gates are declared in three
// different kinds of place and one of them is an absence:
//
//   - Control API — a test-local floor table in package api classifies
//     GET /api/v1/nodes/{node_id} as ungated; it is unreachable from here.
//   - Console — the route table's own MinRole, viewer on Fleet, Node detail
//     and Compare.
//   - MCP — no declaration at all: the read tools reach no ControlAction, so
//     the role gate never fires for them.
//
// No single table can read all three. One viewer credential driving all three
// can.
package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
)

// TestConsoleAccounts_AdminSessionListsAccountsThroughTheAccountAdmin proves the
// composition root handed the Console its AccountAdmin: an admin session reads
// /console/accounts through the capability layer's AccountAdmin and sees the
// Account. A surfaceDeps field forgotten in newServer would otherwise surface
// only as a nil dereference at request time, because the Console's account
// writes are not exercised end to end elsewhere.
func TestConsoleAccounts_AdminSessionListsAccountsThroughTheAccountAdmin(t *testing.T) {
	f := startRelay(t, WithControlPlane(), WithConfig(func(c *Config) { c.ConsoleEnabled = true }))

	const password = "ledger keeper's console password"
	mintConsoleHumanAccount(t, f, "ledger-keeper", password, accounts.RoleAdmin)
	browser := consoleClient(t, f)
	consoleSignIn(t, browser, f, "ledger-keeper", password)

	resp, err := browser.Get(f.ControlBase + "/console/accounts")
	if err != nil {
		t.Fatalf("GET /console/accounts: %v", err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /console/accounts as admin = %d, want 200; body = %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "ledger-keeper") {
		t.Errorf("the Accounts page does not list the signed-in Account — it was not read through the AccountAdmin")
	}
}

// TestQueryReadFloor_IsViewerOnMCPTheControlAPIAndTheConsole proves QRY-15's
// Control API and Console halves: the same `viewer` Account reaches every
// query surface on all three adapters, and the same credential is still
// refused where a narrower floor genuinely applies.
//
// Residual: this proves a `viewer` credential reaches each of the ENUMERATED
// query surfaces and that each surface still refuses that same credential
// elsewhere. It does not prove that no narrower gate exists on an unlisted
// query path — today's query reads are enumerated by hand here. Because
// `viewer` is the LOWEST valid role, the API Node read is classified ungated
// and MCP declares no floor at all, this proves "no gate narrower than viewer
// applies on these paths" and cannot distinguish that from "no role gate
// exists on this path". It says nothing about roles above viewer. The Console
// legs assert status, plus — on Compare — that the page really resolved both
// pinned Nodes.
func TestQueryReadFloor_IsViewerOnMCPTheControlAPIAndTheConsole(t *testing.T) {
	f := startRelay(t, WithControlPlane(), WithConfig(func(c *Config) { c.ConsoleEnabled = true }))
	for _, id := range []string{"node-query-a", "node-query-b"} {
		if _, err := f.Deps.registry.Upsert(registry.Report{NodeID: id}.
			WithNodeLabels(map[string]string{"role": "web"})); err != nil {
			t.Fatalf("seed registry (%s): %v", id, err)
		}
	}

	// One Account, two credentials, three surfaces — so role is the only
	// variable between the legs below.
	const password = "watcher's console password"
	_, token := mintConsoleHumanAccount(t, f, "watcher", password, accounts.RoleViewer)

	session := relaytest.Connect(t, f.ControlBase, f.ClientFor(token))
	browser := consoleClient(t, f)
	consoleSignIn(t, browser, f, "watcher", password)

	consoleGET := func(t *testing.T, path string) (int, string) {
		t.Helper()
		resp, err := browser.Get(f.ControlBase + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		return resp.StatusCode, readAll(t, resp)
	}

	t.Run("MCP", func(t *testing.T) {
		for _, tc := range []struct {
			tool string
			args map[string]any
		}{
			{"list_nodes", nil},
			{"describe_node", map[string]any{"node_id": "node-query-a"}},
			{"list_operations", map[string]any{"node_id": "node-query-a"}},
		} {
			res := relaytest.CallTool(t, session, tc.tool, tc.args)
			if res.IsError {
				t.Errorf("%s as viewer was refused: %s", tc.tool, relaytest.ToolErrorText(t, res))
			}
		}
	})

	t.Run("Control API", func(t *testing.T) {
		resp := controlAPIRequest(t, f.ClientFor(token), http.MethodGet,
			f.ControlBase+"/api/v1/nodes/node-query-a", token, nil)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET /api/v1/nodes/node-query-a as viewer = %d, want 200", resp.StatusCode)
		}
	})

	t.Run("Console", func(t *testing.T) {
		for _, path := range []string{"/console/", "/console/nodes/node-query-a"} {
			if code, _ := consoleGET(t, path); code != http.StatusOK {
				t.Errorf("GET %s as viewer = %d, want 200", path, code)
			}
		}

		// Compare carries its pin set as ONE comma-separated ?nodes=, not as
		// repeated parameters: a page given zero pins resolves nothing,
		// queries nothing and still renders 200, so status alone would be a
		// leg that exercised no query surface at all. These three body facts
		// make that impossible.
		const comparePath = "/console/compare?nodes=node-query-a,node-query-b"
		code, body := consoleGET(t, comparePath)
		if code != http.StatusOK {
			t.Fatalf("GET %s as viewer = %d, want 200", comparePath, code)
		}
		for _, id := range []string{"node-query-a", "node-query-b"} {
			// The column heading, rendered only for a Node the screen
			// resolved through the read lane's DescribeNode.
			if !strings.Contains(body, `class="nodeid">`+id) {
				t.Errorf("the Compare page has no column for %s — it resolved no such Node", id)
			}
		}
		if !strings.Contains(body, "What 2 Nodes reported") {
			t.Error("the Compare page does not report two columns — a page that resolved fewer " +
				"Nodes renders the pin-at-least-two placeholder instead")
		}
		if strings.Contains(body, "Not in this Relay's registry") {
			t.Error("the Compare page reports a pinned id as unknown — the seeded Nodes did not resolve")
		}
	})

	// Non-vacuity: the SAME viewer credential, refused where a narrower floor
	// genuinely applies. Without these, every assertion above would also pass
	// against a Relay that gated nothing anywhere.
	t.Run("the same credential is still refused above the read floor", func(t *testing.T) {
		resp := controlAPIRequest(t, f.ClientFor(token), http.MethodGet,
			f.ControlBase+"/api/v1/accounts", token, nil)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("GET /api/v1/accounts as viewer = %d, want 403", resp.StatusCode)
		}

		// The Console answers a route above the session's role with a 404
		// rather than a 403: it does not disclose that the route exists.
		if code, _ := consoleGET(t, "/console/accounts"); code != http.StatusNotFound {
			t.Errorf("GET /console/accounts as viewer = %d, want 404", code)
		}

		// The Selector is well-formed and matches both seeded Nodes, and the
		// capability layer authorizes immediately after resolving — before
		// the empty-match and blast-cap checks — so this refusal cannot be a
		// "no Nodes matched" in disguise. Asserting the required role is named
		// is what discriminates it from an unrelated failure.
		res := relaytest.CallTool(t, session, "run_operation", map[string]any{
			"operation": "system.facts",
			"selector":  "node:role=web",
		})
		if !res.IsError {
			t.Error("run_operation as viewer SUCCEEDED — a viewer may never dispatch")
		} else if text := relaytest.ToolErrorText(t, res); !strings.Contains(text, "operator") {
			t.Errorf("run_operation as viewer error = %q, want it to name the required role %q", text, "operator")
		}
	})
}
