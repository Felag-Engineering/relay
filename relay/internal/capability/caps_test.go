package capability

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// TestInvariant13_TheCapIsChosenByClassAndAnUnspecifiedClassTakesTheMutateCap
// holds invariant 13: a risk class is contract no caller can set or loosen, and
// it chooses the cap.
// Read and mutate take their own inclusive cap, and an unspecified class takes the mutate cap.
// Proves EX-14.
func TestInvariant13_TheCapIsChosenByClassAndAnUnspecifiedClassTakesTheMutateCap(t *testing.T) {
	if DefaultReadCap != 10000 || DefaultMutateCap != 100 {
		t.Fatalf("default caps = (read %d, mutate %d), want (10000, 100)", DefaultReadCap, DefaultMutateCap)
	}
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
			bc := NewBlastCap(caps(tt.readCap, tt.mutateCap))
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
			bc := NewBlastCap(caps(tt.readCap, tt.mutateCap))
			for class, want := range map[jobs.RiskClass]int{jobs.RiskClassRead: tt.wantReadCap, jobs.RiskClassMutate: tt.wantMutateCap} {
				if err := bc.Check(class, want); err != nil {
					t.Errorf("Check(%v, %d) = %v, want nil at the cap", class, want, err)
				}
				var capErr *CapExceededError
				if err := bc.Check(class, want+1); !errors.As(err, &capErr) || capErr.Cap != want {
					t.Errorf("Check(%v, %d) = %v, want a CapExceededError with Cap %d", class, want+1, err, want)
				}
			}
		})
	}
}

func TestCapExceededErrorContent(t *testing.T) {
	bc := NewBlastCap(caps(100, 10))
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
	bc := NewBlastCap(caps(10, 100))
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
			NodeID:                 fmt.Sprintf("node-%d", i),
			TemplateSetFingerprint: reportedTemplateSet,
		}.WithNodeLabels(map[string]string{"role": "web"})); err != nil {
			t.Fatalf("Upsert(node-%d): %v", i, err)
		}
	}
	return reg
}

// countingJobs counts the Jobs the engine creates.
type countingJobs struct {
	jobs.JobRepository
	created atomic.Int32
}

func (c *countingJobs) CreateJob(ctx context.Context, job jobs.Job) error {
	c.created.Add(1)
	return c.JobRepository.CreateJob(ctx, job)
}

// TestInvariant5_TheBlastCapRefusesBeforeAnyTaskIsStoredOrSent holds invariant 5:
// the blast-radius cap is enforced on the Relay before dispatch.
// A dispatch over its class's cap, counted after Template exclusion, is refused with no Job,
// no Task, no intent and nothing sent; the control row shows the same wiring does persist
// and send when under the cap.
// Proves EX-13.
func TestInvariant5_TheBlastCapRefusesBeforeAnyTaskIsStoredOrSent(t *testing.T) {
	twoOfThreeReport := staticVocab{
		"node-0": reported(readTemplate("svc.status")),
		"node-1": reported(readTemplate("svc.status")),
		"node-2": reported(readTemplate("other")),
	}
	tests := []struct {
		name        string
		nodes       int
		vocab       staticVocab
		act         jobs.Action
		readCap     int
		mutateCap   int
		wantMatched int // 0: the dispatch passes the cap
	}{
		{"read Native over the read cap", 5, staticVocab{}, jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts"}, 2, 100, 5},
		{"mutate Native over the mutate cap", 5, staticVocab{}, jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", OperationArgs: map[string]string{"unit": "nginx"}}, 100, 2, 5},
		{"Template: the cap counts the Nodes left after exclusion", 3, twoOfThreeReport, templateAction("svc.status", nil), 2, 100, 0},
		{"Template over the cap after exclusion", 3, twoOfThreeReport, templateAction("svc.status", nil), 1, 100, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := seedNodes(t, tt.nodes)
			jobsRepo, tasksRepo := testEngineStore(t)
			var log []string
			var ids []string
			for i := 0; i < tt.nodes; i++ {
				ids = append(ids, fmt.Sprintf("node-%d", i))
			}
			conduit := connectedConduit(&log, ids...)
			jc := &countingJobs{JobRepository: jobsRepo}
			recTasks := &recordingTasks{TaskRepository: tasksRepo, log: &log}
			intents := &nonAtomicIntents{tr: recTasks}
			svc := build(t, seams{
				reg:       reg,
				authz:     &spyAuthorizer{},
				cap:       NewBlastCap(caps(tt.readCap, tt.mutateCap)),
				audit:     &spyAuditSink{},
				freeze:    &fakeFreezeStore{},
				jobsRepo:  jc,
				tasksRepo: recTasks,
				conduit:   conduit,
				nodeVocab: tt.vocab,
				intents:   intents,
				newID:     sequentialIDs("id-"),
			})

			_, err := svc.Run(context.Background(), Principal{Account: "alice"}, webSelector(), tt.act)

			if tt.wantMatched == 0 {
				if err != nil {
					t.Fatalf("Run() under the cap = %v, want nil", err)
				}
				if jc.created.Load() != 1 {
					t.Errorf("%d Jobs created, want 1", jc.created.Load())
				}
				if len(intents.recorded()) != 1 {
					t.Errorf("%d intents recorded, want 1", len(intents.recorded()))
				}
				var dispatched []string
				creates := 0
				for _, l := range log {
					if strings.HasPrefix(l, "create:") {
						creates++
					}
					if strings.HasPrefix(l, "dispatch:") {
						dispatched = append(dispatched, l)
					}
				}
				if creates != 3 {
					t.Errorf("%d create: entries in the log, want 3 (one per matched Node)", creates)
				}
				stored, serr := tasksRepo.ByJob(context.Background(), "job-id-1")
				if serr != nil {
					t.Fatalf("ByJob: %v", serr)
				}
				if len(stored) != 3 {
					t.Errorf("%d Tasks stored under the Job, want 3", len(stored))
				}
				sort.Strings(dispatched)
				if len(dispatched) != 2 || dispatched[0] != "dispatch:node-0" || dispatched[1] != "dispatch:node-1" {
					t.Errorf("dispatches = %v, want node-0 and node-1 only", dispatched)
				}
				return
			}

			var capErr *CapExceededError
			if !errors.As(err, &capErr) {
				t.Fatalf("Run() error = %v, want errors.As to find a *CapExceededError", err)
			}
			if capErr.Matched != tt.wantMatched {
				t.Errorf("capErr.Matched = %d, want %d", capErr.Matched, tt.wantMatched)
			}
			if jc.created.Load() != 0 {
				t.Errorf("%d Jobs created over the cap, want 0", jc.created.Load())
			}
			if len(log) != 0 {
				t.Errorf("log = %v, want no Task stored and nothing sent", log)
			}
			if got := intents.recorded(); len(got) != 0 {
				t.Errorf("%d intents recorded over the cap, want 0", len(got))
			}
			// ByJob lists a Job's Tasks in every state, so it sees a Pending Task that
			// InFlight would not; the control row shows the same call sees stored Tasks.
			stored, serr := tasksRepo.ByJob(context.Background(), "job-id-1")
			if serr != nil {
				t.Fatalf("ByJob: %v", serr)
			}
			if len(stored) != 0 {
				t.Errorf("%d Tasks stored over the cap, want 0", len(stored))
			}
			inFlight, ierr := tasksRepo.InFlight(context.Background())
			if ierr != nil {
				t.Fatalf("InFlight: %v", ierr)
			}
			if len(inFlight) != 0 {
				t.Errorf("%d Tasks in flight over the cap, want 0", len(inFlight))
			}
		})
	}
}
