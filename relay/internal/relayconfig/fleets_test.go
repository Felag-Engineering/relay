package relayconfig

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// The test and demo fleets stage these files onto their read-only config volume
// (docker/dev-fleet-config.sh). The Relay refuses to start on a rule it cannot
// load, so a fixture this loader refuses would crash-loop that fleet's Relay;
// these tests catch it here, and pin the posture each fleet's documentation
// describes (docs/dev-fleet.md, docs/operations/demo-fleet.md).

// fixtureDispatches are the dispatch shapes the runbooks' beats rely on.
var fixtureDispatches = []struct {
	name  string
	d     approval.Dispatch
	gated bool
}{
	{"single-Node mutate runs straight through", approval.Dispatch{RiskClass: jobs.RiskClassMutate, FanOut: 1, Operation: "service.restart"}, false},
	{"fleet-wide mutate parks", approval.Dispatch{RiskClass: jobs.RiskClassMutate, FanOut: 2, Operation: "service.restart"}, true},
	{"fleet-wide read runs straight through", approval.Dispatch{RiskClass: jobs.RiskClassRead, FanOut: 9, Operation: "file.read"}, false},
	{"single-Node Raw Exec parks", approval.Dispatch{RiskClass: jobs.RiskClassMutate, FanOut: 1, RawExec: true}, true},
}

// Proves AP-89.
func TestFleetRelayTOML_GatesFleetWideMutatesAndRawExec(t *testing.T) {
	fleets := []struct {
		file  string
		rules []string
	}{
		{"test/relay.toml", []string{"dev-fleet-wide-mutates-need-a-human", "dev-raw-exec-always-needs-a-human"}},
		{"demo/relay.toml", []string{"demo-fleet-wide-mutates-need-a-human", "demo-raw-exec-always-needs-a-human"}},
		{"demo/relay.oauth.toml", []string{"demo-fleet-wide-mutates-need-a-human", "demo-raw-exec-always-needs-a-human"}},
	}
	for _, fleet := range fleets {
		t.Run(fleet.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(packageDir(t), "..", "..", "..", "deploy", filepath.FromSlash(fleet.file)))
			if err != nil {
				t.Fatal(err)
			}
			cfg, _, err := Load(data)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			var names []string
			for _, r := range cfg.Approval.Rules {
				names = append(names, r.Name)
			}
			if len(names) != len(fleet.rules) || names[0] != fleet.rules[0] || names[1] != fleet.rules[1] {
				t.Fatalf("rules = %v, want %v", names, fleet.rules)
			}
			gate, err := approval.NewGate(cfg.Approval.Rules)
			if err != nil {
				t.Fatalf("NewGate: %v", err)
			}
			for _, tc := range fixtureDispatches {
				req, _, gated := gate.Evaluate(tc.d)
				if gated != tc.gated {
					t.Errorf("%s: gated = %v, want %v", tc.name, gated, tc.gated)
					continue
				}
				if gated && req.TTL != time.Hour {
					t.Errorf("%s: ttl = %v, want 1h", tc.name, req.TTL)
				}
			}
		})
	}
}
