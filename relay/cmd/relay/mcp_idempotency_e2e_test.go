package main

import (
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
)

// TestMCPExecution_ReissuedCallWithTheSameKeyReturnsTheSameJob proves #895
// through the composition root: main wires the idempotency-key store
// (capability.WithIdempotency), so a run_operation re-issued with the same
// idempotency_key by the same Account returns the Job the first call created
// and creates no second one. The in-package suites prove the logic; only this
// one fails if the wiring is dropped.
func TestMCPExecution_ReissuedCallWithTheSameKeyReturnsTheSameJob(t *testing.T) {
	f := startRelay(t, WithControlPlane())
	if _, err := f.Deps.registry.Upsert(registry.Report{NodeID: "node-e2e-1"}); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	session := relaytest.Connect(t, f.ControlBase, f.Client())

	args := map[string]any{"operation": "system.facts", "idempotency_key": "k-e2e-1", "wait_seconds": 60}
	run := func() mcp.RunOrPlanOutput {
		t.Helper()
		res := relaytest.CallTool(t, session, "run_operation", args)
		if res.IsError {
			t.Fatalf("run_operation: IsError=true; content = %+v", res.Content)
		}
		var out mcp.RunOrPlanOutput
		relaytest.DecodeToolJSON(t, res, &out)
		return out
	}

	first := run()
	if first.JobID == "" || first.Reattached {
		t.Fatalf("first call = %+v, want a fresh Job", first)
	}
	second := run()
	if !second.Reattached || second.JobID != first.JobID {
		t.Fatalf("re-issued call = %+v, want Reattached to %s", second, first.JobID)
	}
	if n := len(allJobs(t, f)); n != 1 {
		t.Fatalf("Jobs = %d, want exactly 1 after a re-issued keyed call", n)
	}

	// A key with different arguments is refused, not dispatched.
	res := relaytest.CallTool(t, session, "run_operation", map[string]any{
		"operation": "system.facts", "idempotency_key": "k-e2e-1", "timeout_seconds": 5,
	})
	if !res.IsError || !strings.Contains(relaytest.ToolErrorText(t, res), "different arguments") {
		t.Fatalf("same key, different arguments: IsError=%v, want the conflict refusal", res.IsError)
	}
	if n := len(allJobs(t, f)); n != 1 {
		t.Fatalf("Jobs = %d after the conflicting call, want still 1", n)
	}
}
