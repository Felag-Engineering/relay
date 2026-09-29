package approval

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// The two DEV-ONLY approval-gate fixtures the dev fleet bakes into the relay
// image (docker/relay.Dockerfile): the default three-Node fleet's, and the
// nine-Node demo fleet's, which scripts/demo-fleet.sh selects. The Relay's gate
// loader is fail-closed, so a fixture this parser refuses crash-loops that
// fleet's Relay; these tests catch it here instead, and pin the posture each
// fleet's documentation describes (docs/dev-fleet.md, "The approval gate";
// docs/operations/demo-fleet.md, "The human approver").
//
// Hermetic: they read the committed fixtures and run them through Parse. They
// do not exercise Load's file-mode checks, which the image's COPY --chmod
// satisfies and config_test.go covers.

// fixturesDir is this package's directory walked back up to the repository
// root (relay/internal/approval -> relay/internal -> relay -> .), then down.
const fixturesDir = "../../../docker/fixtures"

func parseFixture(t *testing.T, name string) *Gate {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixturesDir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	g, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse %s: %v", name, err)
	}
	return g
}

// Both fixtures gate exactly the same dispatches; only what they require
// differs. These are the dispatch shapes the runbooks' beats rely on.
var fixtureDispatches = []struct {
	name  string
	d     Dispatch
	gated bool
}{
	{"single-Node mutate runs straight through", Dispatch{RiskClass: jobs.RiskClassMutate, FanOut: 1, Operation: "service.restart"}, false},
	{"fleet-wide mutate parks", Dispatch{RiskClass: jobs.RiskClassMutate, FanOut: 2, Operation: "service.restart"}, true},
	{"fleet-wide read runs straight through", Dispatch{RiskClass: jobs.RiskClassRead, FanOut: 9, Operation: "file.read"}, false},
	{"single-Node Raw Exec parks", Dispatch{RiskClass: jobs.RiskClassMutate, FanOut: 1, RawExec: true}, true},
}

func TestDevFleetGateFixture_OutOfBandAndOnlyDevApprover(t *testing.T) {
	g := parseFixture(t, "approval-gates.json")
	for _, tc := range fixtureDispatches {
		req, _, gated := g.Evaluate(tc.d)
		if gated != tc.gated {
			t.Errorf("%s: gated = %v, want %v", tc.name, gated, tc.gated)
			continue
		}
		if !gated {
			continue
		}
		if req.Channel != ChannelOutOfBand {
			t.Errorf("%s: channel = %v, want out-of-band", tc.name, req.Channel)
		}
		if len(req.Audience) != 1 || req.Audience[0] != "dev-approver" {
			t.Errorf("%s: audience = %v, want [dev-approver]", tc.name, req.Audience)
		}
		if req.RequesterAllowed {
			t.Errorf("%s: requester_allowed = true, want the strict default", tc.name)
		}
	}
}

// The demo fleet's gate must be one an MCP client can answer: in-band, not
// excluding the requester, and with an audience that admits the caller (AP-61).
// An empty audience means any Account whose role clears the decision floor.
func TestDemoFleetGateFixture_InBandOpenAudienceRequesterAllowed(t *testing.T) {
	g := parseFixture(t, "approval-gates.demo.json")
	for _, tc := range fixtureDispatches {
		req, _, gated := g.Evaluate(tc.d)
		if gated != tc.gated {
			t.Errorf("%s: gated = %v, want %v", tc.name, gated, tc.gated)
			continue
		}
		if !gated {
			continue
		}
		if req.Channel != ChannelInBand {
			t.Errorf("%s: channel = %v, want in-band", tc.name, req.Channel)
		}
		if len(req.Audience) != 0 {
			t.Errorf("%s: audience = %v, want none (any Account the surface lets decide)", tc.name, req.Audience)
		}
		if !req.RequesterAllowed {
			t.Errorf("%s: requester_allowed = false, want true", tc.name)
		}
		if req.Count != 1 {
			t.Errorf("%s: count = %d, want 1", tc.name, req.Count)
		}
	}
}
