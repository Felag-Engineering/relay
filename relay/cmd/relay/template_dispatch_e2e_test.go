//go:build integration

// Template dispatch end to end (ADR-0042, #626): a Template Operation called
// by name through the production MCP run_operation route, against real
// relay-daemon subprocesses — one that loads the Template and one that does
// not. Before #626 every Template name was refused at the adapter as an
// unknown operation, and the only thing that had ever run one over the wire
// was the devharness backdoor (crossbinary_e2e_test.go).
package main

import (
	"os"
	"strings"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// otherTemplatePack gives the second daemon a loaded, non-empty Template set
// that lacks e2e.template — the "reports a vocabulary, but not this Template"
// case, rather than a Node that reported nothing at all.
const otherTemplatePack = `
[[template]]
name = "e2e.other"
risk_class = "read"
body = "echo other-ran"
`

func TestTemplateDispatchE2E_RunOperationByName(t *testing.T) {
	deps, _, controlBase, authed, _, _ := startSurfaceHarness(t)

	withRule := relaytest.WriteTempFile(t, "policy-*.toml", relaytest.FixturePolicy+relaytest.FixtureTemplatePolicyRule)
	plain := relaytest.WriteTempFile(t, "policy-*.toml", relaytest.FixturePolicy)

	joinHas := mintJoinString(t, deps, "tag:env=test", "tag:node=has")
	joinLacks := mintJoinString(t, deps, "tag:env=test", "tag:node=lacks")

	bin := relaytest.DaemonConfig{Bin: os.Getenv("RELAY_DAEMON_BIN")}
	has := bin
	has.JoinString, has.StateDir, has.PolicyPath, has.Hostname = joinHas, t.TempDir(), withRule, "template-e2e-has"
	has.TemplateDir = relaytest.WriteTemplatePack(t, relaytest.FixtureTemplatePack)
	lacks := bin
	lacks.JoinString, lacks.StateDir, lacks.PolicyPath, lacks.Hostname = joinLacks, t.TempDir(), plain, "template-e2e-lacks"
	lacks.TemplateDir = relaytest.WriteTemplatePack(t, otherTemplatePack)
	relaytest.StartDaemon(t, has)
	relaytest.StartDaemon(t, lacks)

	if got := waitForConnectedNodes(t, deps, 2, 45*time.Second); len(got) != 2 {
		t.Fatalf("connected Nodes = %v, want 2", got)
	}
	hasID := nodeIDForLabel(t, deps, "node", "has")
	lacksID := nodeIDForLabel(t, deps, "node", "lacks")

	session := relaytest.Connect(t, controlBase, authed)

	// The vocabulary arrives just after connect; wait for both reports so
	// neither Node is excluded as "not reported" by a race.
	pollTemplatesReported(t, session, hasID, 30*time.Second)
	pollTemplatesReported(t, session, lacksID, 30*time.Second)

	t.Run("apply", func(t *testing.T) {
		res := relaytest.CallTool(t, session, "run_operation", map[string]any{
			"operation":    "e2e.template",
			"selector":     "tag:env=test",
			"wait_seconds": 300,
		})
		if res.IsError {
			t.Fatalf("run_operation(e2e.template): IsError=true; content = %+v", res.Content)
		}
		var out mcp.ExecutionOutput
		relaytest.DecodeToolJSON(t, res, &out)
		byNode := resultsByNode(out.Results)

		if r := byNode[hasID]; r.Outcome != "success" || r.Stdout != "template-ran\n" {
			t.Errorf("Node with the Template: %+v, want success with stdout %q", r, "template-ran\n")
		}
		if r := byNode[lacksID]; r.Outcome != "unsupported" || r.Stderr != capability.TemplateNotInVocabularyReason {
			t.Errorf("Node without the Template: %+v, want unsupported with the Relay's exclusion reason", r)
		}
	})

	t.Run("preflight_agrees", func(t *testing.T) {
		res := relaytest.CallTool(t, session, "run_operation", map[string]any{
			"operation": "e2e.template",
			"selector":  "tag:env=test",
			"plan":      true,
		})
		if res.IsError {
			t.Fatalf("run_operation(plan=true): IsError=true; content = %+v", res.Content)
		}
		var out mcp.RunOrPlanOutput
		relaytest.DecodeToolJSON(t, res, &out)
		if out.Plan == nil {
			t.Fatal("plan is nil")
		}
		v := verdictsByNode(*out.Plan)
		if v[hasID].Verdict != "allow" {
			t.Errorf("preflight on the Node with the Template = %+v, want allow (the daemon's answer)", v[hasID])
		}
		if v[lacksID].Verdict != "unsupported" {
			t.Errorf("preflight on the Node without it = %+v, want unsupported, as the run reports", v[lacksID])
		}
	})

	t.Run("unknown_name_refused", func(t *testing.T) {
		res := relaytest.CallTool(t, session, "run_operation", map[string]any{
			"operation": "e2e.nowhere",
			"selector":  "tag:env=test",
		})
		if !res.IsError {
			t.Fatal("run_operation(e2e.nowhere): IsError=false, want an unknown-operation refusal")
		}
		if text := relaytest.ToolErrorText(t, res); !strings.Contains(text, "unknown operation") {
			t.Errorf("error = %q, want it to say unknown operation", text)
		}
	})
}

// pollTemplatesReported polls describe_node until nodeID's Template
// vocabulary report has reached the Relay.
func pollTemplatesReported(t *testing.T, session *sdkmcp.ClientSession, nodeID string, deadline time.Duration) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		res := relaytest.CallTool(t, session, "describe_node", map[string]any{"node_id": nodeID})
		if !res.IsError {
			var out mcp.DescribeNodeOutput
			relaytest.DecodeToolJSON(t, res, &out)
			if out.TemplateVocabulary.Reported {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("Node %s never reported its Template vocabulary within %s", nodeID, deadline)
}
