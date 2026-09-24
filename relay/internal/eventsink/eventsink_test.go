package eventsink

import (
	"context"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/enroll"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/events"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
)

// recvOrTimeout reads the next event off sub or fails the test.
func recvOrTimeout(t *testing.T, sub *events.Subscription) events.Event {
	t.Helper()
	select {
	case ev := <-sub.C():
		return ev
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for a published event")
		return events.Event{}
	}
}

// assertNothingPublished fails the test if any event arrives on sub within
// a short window.
func assertNothingPublished(t *testing.T, sub *events.Subscription) {
	t.Helper()
	select {
	case ev := <-sub.C():
		t.Fatalf("unexpected event published: %+v", ev)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestObserveRegistry_SetConnected(t *testing.T) {
	bus := events.NewBus()
	reg := ObserveRegistry(registry.NewInMemory(), bus)
	sub := bus.Subscribe([]events.Kind{events.KindRegistry}, "")
	defer sub.Close()

	if _, err := reg.Upsert(registry.Report{NodeID: "node-1"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	reg.SetConnected("node-1", true)

	ev := recvOrTimeout(t, sub)
	if ev.Kind != events.KindRegistry || ev.Registry == nil {
		t.Fatalf("event = %+v, want a KindRegistry event", ev)
	}
	if ev.Registry.Transition != events.TransitionConnected || ev.Registry.NodeID != "node-1" {
		t.Errorf("Registry = %+v, want TransitionConnected for node-1", ev.Registry)
	}

	reg.SetConnected("node-1", false)
	ev = recvOrTimeout(t, sub)
	if ev.Registry.Transition != events.TransitionDisconnected {
		t.Errorf("Transition = %v, want TransitionDisconnected", ev.Registry.Transition)
	}
}

func TestObserveRegistry_SetRelayLabels(t *testing.T) {
	bus := events.NewBus()
	inner := registry.NewInMemory()
	reg := ObserveRegistry(inner, bus)
	sub := bus.Subscribe([]events.Kind{events.KindRegistry}, "")
	defer sub.Close()

	if _, err := inner.Upsert(registry.Report{NodeID: "node-1"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	labels := map[string]string{"quarantine": "on"}
	if err := reg.SetRelayLabels("node-1", labels); err != nil {
		t.Fatalf("SetRelayLabels: %v", err)
	}

	ev := recvOrTimeout(t, sub)
	if ev.Registry.Transition != events.TransitionLabelsChanged || ev.Registry.NodeID != "node-1" {
		t.Fatalf("Registry = %+v, want TransitionLabelsChanged for node-1", ev.Registry)
	}
	if ev.Registry.RelayLabels["quarantine"] != "on" {
		t.Errorf("RelayLabels = %v, want quarantine=on", ev.Registry.RelayLabels)
	}

	// Mutating the map handed to SetRelayLabels afterward must not affect
	// the published copy (copyLabels).
	labels["quarantine"] = "mutated"
	if ev.Registry.RelayLabels["quarantine"] != "on" {
		t.Error("published RelayLabels aliased the caller's map")
	}
}

func TestObserveRegistry_SetRelayLabels_ErrNotFound_PublishesNothing(t *testing.T) {
	bus := events.NewBus()
	reg := ObserveRegistry(registry.NewInMemory(), bus)
	sub := bus.Subscribe([]events.Kind{events.KindRegistry}, "")
	defer sub.Close()

	err := reg.SetRelayLabels("no-such-node", map[string]string{"a": "b"})
	if err == nil {
		t.Fatal("want an error for an unknown node")
	}

	assertNothingPublished(t, sub)
}

// TestObserveRegistry_HeartbeatAndEverythingElsePublishNothing is the
// acceptance table: every registry.Repository method OTHER than
// SetConnected and a successful SetRelayLabels must publish nothing —
// UpdateLastSeen (the heartbeat) most of all.
func TestObserveRegistry_HeartbeatAndEverythingElsePublishNothing(t *testing.T) {
	bus := events.NewBus()
	inner := registry.NewInMemory()
	reg := ObserveRegistry(inner, bus)
	sub := bus.Subscribe([]events.Kind{events.KindRegistry}, "")
	defer sub.Close()

	if _, err := inner.Upsert(registry.Report{NodeID: "node-1"}); err != nil {
		t.Fatalf("seed Upsert: %v", err)
	}
	assertNothingPublished(t, sub)

	cases := []struct {
		name string
		call func() error
	}{
		{"Upsert", func() error { _, err := reg.Upsert(registry.Report{NodeID: "node-2"}); return err }},
		{"UpdateLastSeen", func() error { return reg.UpdateLastSeen("node-1", time.Now()) }},
		{"SetRevoked", func() error { return reg.SetRevoked("node-1", time.Now()) }},
		{"SetRevokedAll", func() error { _, err := reg.SetRevokedAll([]string{"node-1"}, time.Now()); return err }},
		{"RecordEnrollment", func() error { return reg.RecordEnrollment("node-1", registry.Certificate{}, time.Now()) }},
		{"RecordRenewal", func() error { return reg.RecordRenewal("node-1", registry.Certificate{}, time.Now()) }},
		{"Get", func() error { _, _ = reg.Get("node-1"); return nil }},
		{"List", func() error { _ = reg.List(); return nil }},
		{"RevokedNodeIDs", func() error { _, err := reg.RevokedNodeIDs(); return err }},
		{"Count", func() error { _, _, err := reg.Count(); return err }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			assertNothingPublished(t, sub)
		})
	}
}

func TestJobs_MapsFields_IncludingRawExecOperationName(t *testing.T) {
	bus := events.NewBus()
	sink := Jobs(bus)
	sub := bus.Subscribe([]events.Kind{events.KindJob}, "")
	defer sub.Close()

	sink.RecordJob(capability.JobEvent{
		Transition: capability.JobCompleted,
		JobID:      "job-1",
		Principal:  capability.Principal{Account: "alice", AccountID: "acct-1"},
		Action:     jobs.Action{Kind: jobs.ActionRawExec, RiskClass: jobs.RiskClassMutate},
		Nodes:      3,
		Outcomes: map[jobs.Outcome]int{
			jobs.OutcomeSuccess:     2,
			jobs.OutcomeUnreachable: 1,
		},
	})

	ev := recvOrTimeout(t, sub)
	if ev.Job == nil {
		t.Fatal("event has no Job payload")
	}
	je := ev.Job
	if je.Transition != events.JobCompleted || je.JobID != "job-1" {
		t.Errorf("Transition/JobID = %v/%q, want JobCompleted/job-1", je.Transition, je.JobID)
	}
	if je.Account != "alice" || je.AccountID != "acct-1" {
		t.Errorf("Account/AccountID = %q/%q, want alice/acct-1", je.Account, je.AccountID)
	}
	if je.Operation != "raw_exec" {
		t.Errorf("Operation = %q, want raw_exec for an ActionRawExec Action", je.Operation)
	}
	if je.RiskClass != "mutate" {
		t.Errorf("RiskClass = %q, want mutate", je.RiskClass)
	}
	if je.Nodes != 3 {
		t.Errorf("Nodes = %d, want 3", je.Nodes)
	}
	if je.Succeeded != 2 || je.Unreachable != 1 {
		t.Errorf("Succeeded/Unreachable = %d/%d, want 2/1", je.Succeeded, je.Unreachable)
	}
}

func TestJobs_OperationName_FromStructuredAction(t *testing.T) {
	bus := events.NewBus()
	sink := Jobs(bus)
	sub := bus.Subscribe([]events.Kind{events.KindJob}, "")
	defer sub.Close()

	sink.RecordJob(capability.JobEvent{
		Transition: capability.JobCreated,
		JobID:      "job-2",
		Action:     jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead},
	})

	ev := recvOrTimeout(t, sub)
	if ev.Job.Operation != "system.facts" {
		t.Errorf("Operation = %q, want system.facts", ev.Job.Operation)
	}
	if ev.Job.RiskClass != "read" {
		t.Errorf("RiskClass = %q, want read", ev.Job.RiskClass)
	}
}

// TestEnrollment_ReasonMappingIsExhaustive drives every declared
// enroll.AttemptReason through Enrollment and asserts the mapped
// events.EnrollmentReason, then proves an unrecognized reason (a value
// outside the closed set) degrades to ReasonInternal rather than being
// passed through as a fabricated string.
func TestEnrollment_ReasonMappingIsExhaustive(t *testing.T) {
	cases := []struct {
		in   enroll.AttemptReason
		want events.EnrollmentReason
	}{
		{enroll.AttemptExpired, events.ReasonExpired},
		{enroll.AttemptRevoked, events.ReasonRevoked},
		{enroll.AttemptUnknown, events.ReasonUnknown},
		{enroll.AttemptExhausted, events.ReasonExhausted},
		{enroll.AttemptMalformed, events.ReasonMalformed},
		{enroll.AttemptRateLimited, events.ReasonRateLimited},
		{enroll.AttemptAtCapacity, events.ReasonAtCapacity},
		{enroll.AttemptRevokedMidEnrollment, events.ReasonRevokedMidEnrollment},
		{enroll.AttemptInternal, events.ReasonInternal},
		{enroll.AttemptInvalidScope, events.ReasonInvalidScope},
		{enroll.AttemptReason("some-future-reason-nobody-taught-this-switch-about"), events.ReasonInternal},
	}

	for _, tc := range cases {
		t.Run(string(tc.in), func(t *testing.T) {
			bus := events.NewBus()
			obs := Enrollment(bus)
			sub := bus.Subscribe([]events.Kind{events.KindEnrollment}, "")
			defer sub.Close()

			obs.Attempt(context.Background(), enroll.AttemptEvent{Reason: tc.in, TokenID: "tok-1"})

			ev := recvOrTimeout(t, sub)
			if ev.Enrollment == nil || ev.Enrollment.Reason != tc.want {
				t.Errorf("Reason = %+v, want %q", ev.Enrollment, tc.want)
			}
			if ev.Enrollment.Outcome != events.EnrollmentRejected {
				t.Errorf("Outcome = %q, want rejected (Accepted was not set)", ev.Enrollment.Outcome)
			}
		})
	}
}

func TestEnrollment_Accepted(t *testing.T) {
	bus := events.NewBus()
	obs := Enrollment(bus)
	sub := bus.Subscribe([]events.Kind{events.KindEnrollment}, "")
	defer sub.Close()

	obs.Attempt(context.Background(), enroll.AttemptEvent{Accepted: true, NodeID: "node-1", TokenID: "tok-1", Source: "10.0.0.1"})

	ev := recvOrTimeout(t, sub)
	if ev.Enrollment.Outcome != events.EnrollmentAccepted {
		t.Errorf("Outcome = %q, want accepted", ev.Enrollment.Outcome)
	}
	if ev.Enrollment.NodeID != "node-1" || ev.Enrollment.TokenID != "tok-1" || ev.Enrollment.Source != "10.0.0.1" {
		t.Errorf("event = %+v, want NodeID/TokenID/Source copied through", ev.Enrollment)
	}
}

func TestToolCall_Publishes(t *testing.T) {
	bus := events.NewBus()
	sub := bus.Subscribe([]events.Kind{events.KindToolCall}, "")
	defer sub.Close()

	ToolCall(bus, "alice", "acct-1", mcp.ToolCallEvent{
		Tool:               "raw_exec",
		Arguments:          map[string]string{"argv": `["/bin/true"]`},
		ArgumentsTruncated: false,
	})

	ev := recvOrTimeout(t, sub)
	if ev.ToolCall == nil {
		t.Fatal("event has no ToolCall payload")
	}
	tc := ev.ToolCall
	if tc.Tool != "raw_exec" || tc.Account != "alice" || tc.AccountID != "acct-1" {
		t.Errorf("event = %+v, want Tool=raw_exec Account=alice AccountID=acct-1", tc)
	}
	if tc.Arguments["argv"] != `["/bin/true"]` {
		t.Errorf("Arguments[argv] = %q, want the argv text copied through", tc.Arguments["argv"])
	}
}
