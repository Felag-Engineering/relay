package relayconfig

import (
	"slices"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/approval"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

const (
	shippedMutateRule  = "mutate-needs-a-human"
	shippedRawExecRule = "raw-exec-needs-a-human"
)

// Proves AP-90.
func TestShippedRelayTOML_GatesEveryMutateAndRawExecNeverARead(t *testing.T) {
	subjects := []struct {
		name string
		text func(t *testing.T) string
	}{
		{"packaged relay.toml", func(t *testing.T) string { return renderPackaged(t, "relay.example.com") }},
		{"relay.toml.example", readExample},
	}
	// Raw Exec always carries the mutate class (invariant 13).
	dispatches := []struct {
		name      string
		d         approval.Dispatch
		gated     bool
		wantRules []string
		notRules  []string
	}{
		{
			"single-Node mutate",
			approval.Dispatch{RiskClass: jobs.RiskClassMutate, FanOut: 1, Operation: "service.restart"},
			true, []string{shippedMutateRule}, []string{shippedRawExecRule},
		},
		{
			"fleet-wide mutate on the security lane",
			approval.Dispatch{RiskClass: jobs.RiskClassMutate, FanOut: 100, Namespaces: []string{"relay"}, Account: "ops", Operation: "pkg.install"},
			true, []string{shippedMutateRule}, []string{shippedRawExecRule},
		},
		{
			"single-Node Raw Exec",
			approval.Dispatch{RiskClass: jobs.RiskClassMutate, FanOut: 1, RawExec: true},
			true, []string{shippedRawExecRule}, nil,
		},
		{
			"single-Node read",
			approval.Dispatch{RiskClass: jobs.RiskClassRead, FanOut: 1, Operation: "file.read"},
			false, nil, nil,
		},
		{
			"fleet-wide read on the security lane",
			approval.Dispatch{RiskClass: jobs.RiskClassRead, FanOut: 10000, Namespaces: []string{"relay"}, Account: "ops", Operation: "system.facts"},
			false, nil, nil,
		},
	}

	for _, subject := range subjects {
		t.Run(subject.name, func(t *testing.T) {
			cfg, warnings, err := Load([]byte(subject.text(t)))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if len(warnings) != 0 {
				t.Fatalf("warnings = %v, want none", warnings)
			}
			var names []string
			for _, r := range cfg.Approval.Rules {
				names = append(names, r.Name)
			}
			if want := []string{shippedMutateRule, shippedRawExecRule}; !slices.Equal(names, want) {
				t.Fatalf("rules = %v, want %v", names, want)
			}
			gate, err := approval.NewGate(cfg.Approval.Rules)
			if err != nil {
				t.Fatalf("NewGate: %v", err)
			}
			for _, tc := range dispatches {
				t.Run(tc.name, func(t *testing.T) {
					req, matched, gated := gate.Evaluate(tc.d)
					if gated != tc.gated {
						t.Fatalf("gated = %v, want %v", gated, tc.gated)
					}
					if !gated {
						return
					}
					if req.TTL != time.Hour {
						t.Errorf("ttl = %v, want 1h", req.TTL)
					}
					for _, n := range tc.wantRules {
						if !slices.Contains(matched, n) {
							t.Errorf("matched = %v, missing %s", matched, n)
						}
					}
					for _, n := range tc.notRules {
						if slices.Contains(matched, n) {
							t.Errorf("matched = %v, must not contain %s", matched, n)
						}
					}
				})
			}
		})
	}
}
