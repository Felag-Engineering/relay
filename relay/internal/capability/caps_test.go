package capability

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

func TestBlastCapCheck(t *testing.T) {
	tests := []struct {
		name      string
		readCap   int
		mutateCap int
		class     jobs.RiskClass
		matched   int
		wantErr   bool
	}{
		{"read under cap", 100, 10, jobs.RiskClassRead, 99, false},
		{"read at cap is allowed (inclusive max)", 100, 10, jobs.RiskClassRead, 100, false},
		{"read over cap", 100, 10, jobs.RiskClassRead, 101, true},
		{"mutate under cap", 100, 10, jobs.RiskClassMutate, 9, false},
		{"mutate at cap is allowed (inclusive max)", 100, 10, jobs.RiskClassMutate, 10, false},
		{"mutate over cap", 100, 10, jobs.RiskClassMutate, 11, true},
		{"unspecified under mutate cap", 100, 10, jobs.RiskClassUnspecified, 9, false},
		{"unspecified at mutate cap is allowed", 100, 10, jobs.RiskClassUnspecified, 10, false},
		{"unspecified over mutate cap uses the strict lane, not the generous read-cap", 100, 10, jobs.RiskClassUnspecified, 11, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bc := NewBlastCap(tt.readCap, tt.mutateCap)
			err := bc.Check(tt.class, tt.matched)
			if tt.wantErr && err == nil {
				t.Fatalf("Check(%v, %d) = nil, want an error", tt.class, tt.matched)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Check(%v, %d) = %v, want nil", tt.class, tt.matched, err)
			}
		})
	}
}

func TestNewBlastCapClampsNonPositiveToDefaults(t *testing.T) {
	tests := []struct {
		name          string
		readCap       int
		mutateCap     int
		wantReadCap   int
		wantMutateCap int
	}{
		{"zero clamps to defaults", 0, 0, DefaultReadCap, DefaultMutateCap},
		{"negative clamps to defaults", -1, -100, DefaultReadCap, DefaultMutateCap},
		{"positive values pass through unchanged", 5, 2, 5, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bc := NewBlastCap(tt.readCap, tt.mutateCap)
			if bc.readCap != tt.wantReadCap {
				t.Errorf("readCap = %d, want %d", bc.readCap, tt.wantReadCap)
			}
			if bc.mutateCap != tt.wantMutateCap {
				t.Errorf("mutateCap = %d, want %d", bc.mutateCap, tt.wantMutateCap)
			}
		})
	}
}

func TestCapExceededErrorContent(t *testing.T) {
	bc := NewBlastCap(100, 10)
	err := bc.Check(jobs.RiskClassMutate, 11)
	if err == nil {
		t.Fatal("Check() = nil, want an error")
	}

	msg := err.Error()
	for _, want := range []string{"mutate-cap", "11", "10", "mutate"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message %q does not contain %q", msg, want)
		}
	}

	var capErr *CapExceededError
	if !errors.As(err, &capErr) {
		t.Fatalf("errors.As(err, *CapExceededError) = false, want true (err = %v)", err)
	}
	if capErr.Class != jobs.RiskClassMutate {
		t.Errorf("capErr.Class = %v, want RiskClassMutate", capErr.Class)
	}
	if capErr.Matched != 11 {
		t.Errorf("capErr.Matched = %d, want 11", capErr.Matched)
	}
	if capErr.Cap != 10 {
		t.Errorf("capErr.Cap = %d, want 10", capErr.Cap)
	}
}

func TestCapExceededErrorContentReadCap(t *testing.T) {
	bc := NewBlastCap(10, 100)
	err := bc.Check(jobs.RiskClassRead, 11)
	if err == nil {
		t.Fatal("Check() = nil, want an error")
	}

	msg := err.Error()
	for _, want := range []string{"read-cap", "11", "10", "read"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message %q does not contain %q", msg, want)
		}
	}
}

// seedNodes seeds n Nodes, all matching the "role=web" node: label used by
// seedOneNode's Selector convention, so a Selector of {node:role=web} resolves
// to all n of them.
func seedNodes(t *testing.T, n int) registry.Repository {
	t.Helper()
	reg := registry.NewInMemory()
	for i := 0; i < n; i++ {
		if _, err := reg.Upsert(registry.Report{
			NodeID: fmt.Sprintf("node-%d", i),
		}.WithNodeLabels(map[string]string{"role": "web"})); err != nil {
			t.Fatalf("Upsert(node-%d): %v", i, err)
		}
	}
	return reg
}

// TestRunBlastCapRejectsOversizedSelector mirrors
// TestRunCapCheckDeniedShortCircuits (service_test.go) but wires the real
// BlastCap instead of a spy, proving a Selector matching more Nodes than the
// applicable cap is rejected before any Task is dispatched — for both risk
// classes (acceptance #1).
func TestRunBlastCapRejectsOversizedSelector(t *testing.T) {
	tests := []struct {
		name      string
		operation string // a Native Operation whose opvocab class is the one under test
		readCap   int
		mutateCap int
	}{
		{"read class over the read-cap", "system.facts", 2, 100},
		{"mutate class over the mutate-cap", "service.restart", 100, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := seedNodes(t, 5)
			disp := &spyDispatcher{}
			svc := New(reg, WithCapChecker(NewBlastCap(tt.readCap, tt.mutateCap)))
			svc.disp = disp

			sel := Selector{Predicates: []Predicate{{Namespace: NamespaceNode, Key: "role", Value: "web"}}}
			act := jobs.Action{Kind: jobs.ActionOperation, OperationName: tt.operation}
			_, err := svc.Run(context.Background(), Principal{Account: "alice"}, sel, act)

			if err == nil {
				t.Fatal("Run() with a Selector over the applicable cap should return an error")
			}
			var capErr *CapExceededError
			if !errors.As(err, &capErr) {
				t.Fatalf("Run() error = %v, want errors.As to find a *CapExceededError", err)
			}
			if capErr.Matched != 5 {
				t.Errorf("capErr.Matched = %d, want 5", capErr.Matched)
			}
			if disp.called {
				t.Error("dispatcher must not be called when the blast-radius cap is exceeded")
			}
		})
	}
}
