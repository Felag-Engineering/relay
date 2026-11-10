package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/dispatch"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"google.golang.org/grpc"
)

func sendHeartbeat(t *testing.T, stream grpc.BidiStreamingClient[relayv1.DaemonMessage, relayv1.RelayMessage], unixMillis int64) {
	t.Helper()
	if err := stream.Send(&relayv1.DaemonMessage{
		Body: &relayv1.DaemonMessage_Heartbeat{Heartbeat: &relayv1.Heartbeat{UnixMillis: unixMillis}},
	}); err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}
}

// Proves NC-37.
func TestHeartbeatClockSkew(t *testing.T) {
	received := time.Date(2026, 5, 4, 3, 2, 1, 0, time.UTC)
	tests := []struct {
		name        string
		unixMillis  int64
		receivedAt  time.Time
		want        time.Duration // exact, when wantAtLeast is zero
		wantAtLeast time.Duration
		measured    bool
	}{
		{name: "node ahead", unixMillis: received.Add(5 * time.Minute).UnixMilli(), want: 5 * time.Minute, measured: true},
		{name: "node behind", unixMillis: received.Add(-3 * time.Second).UnixMilli(), want: -3 * time.Second, measured: true},
		{name: "in step is known", unixMillis: received.UnixMilli(), want: 0, measured: true},
		{name: "years out still fits", unixMillis: received.AddDate(30, 0, 0).UnixMilli(), wantAtLeast: 29 * 365 * 24 * time.Hour, measured: true},
		{name: "zero", unixMillis: 0},
		{name: "negative", unixMillis: -1},
		{name: "max int64 does not fit", unixMillis: math.MaxInt64},
		{name: "beyond 292 years ahead does not fit", unixMillis: received.AddDate(300, 0, 0).UnixMilli()},
		{name: "beyond 292 years behind does not fit", unixMillis: 1, receivedAt: time.Date(2400, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			at := received
			if !tc.receivedAt.IsZero() {
				at = tc.receivedAt
			}
			got, ok := heartbeatClockSkew(tc.unixMillis, at).Value()
			if ok != tc.measured {
				t.Fatalf("measured = %v, want %v (value %v)", ok, tc.measured, got)
			}
			if !tc.measured {
				return
			}
			if tc.wantAtLeast != 0 {
				if got < tc.wantAtLeast {
					t.Fatalf("skew = %v, want at least %v", got, tc.wantAtLeast)
				}
				return
			}
			if got != tc.want {
				t.Fatalf("skew = %v, want %v", got, tc.want)
			}
		})
	}
}

// Proves NC-37.
func TestTunnelOpen_HeartbeatFiveMinutesOutRecordsAboutThatSkew(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset time.Duration
	}{
		{"ahead", 5 * time.Minute},
		{"behind", -5 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const nodeID = "node-skew"
			reg := registry.NewInMemory()
			srv := grpc.NewServer(grpc.StreamInterceptor(injectNodeIDInterceptor(nodeID)))
			relayv1.RegisterTunnelServer(srv, &tunnelServer{reg: reg})
			conn := newBufconnConn(t, srv)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			stream := openNodeStream(ctx, t, conn, nodeID)

			sendHeartbeat(t, stream, time.Now().Add(tc.offset).UnixMilli())
			waitUntil(t, "the heartbeat's skew to be recorded", 5*time.Second, func() bool {
				n, ok := reg.Get(nodeID)
				return ok && n.ClockSkewKnown()
			})

			n, _ := reg.Get(nodeID)
			// The receive delay and the millisecond floor of the wire timestamp
			// only lower the reading, whatever its sign.
			lo, hi := tc.offset-5*time.Second, tc.offset+time.Millisecond
			if n.ClockSkew < lo || n.ClockSkew > hi {
				t.Fatalf("ClockSkew = %v, want within [%v, %v]", n.ClockSkew, lo, hi)
			}
			if !n.ClockSkewMeasuredAt.Equal(n.LastSeen) {
				t.Fatalf("ClockSkewMeasuredAt %v != LastSeen %v: one receive instant serves both", n.ClockSkewMeasuredAt, n.LastSeen)
			}
		})
	}
}

// Proves NC-37.
func TestTunnelOpen_NonPositiveHeartbeatTimestampRecordsSkewNotMeasured(t *testing.T) {
	for _, tc := range []struct {
		name       string
		unixMillis int64
	}{
		{"zero", 0},
		{"negative", -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const nodeID = "node-no-timestamp"
			reg := registry.NewInMemory()
			srv := grpc.NewServer(grpc.StreamInterceptor(injectNodeIDInterceptor(nodeID)))
			relayv1.RegisterTunnelServer(srv, &tunnelServer{reg: reg})
			conn := newBufconnConn(t, srv)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			stream := openNodeStream(ctx, t, conn, nodeID)

			seeded := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
			if err := reg.RecordHeartbeat(nodeID, seeded, registry.MeasuredClockSkew(5*time.Minute)); err != nil {
				t.Fatalf("seed skew: %v", err)
			}
			if n, _ := reg.Get(nodeID); !n.ClockSkewKnown() {
				t.Fatal("seeded skew reads as not known")
			}

			sendHeartbeat(t, stream, tc.unixMillis)
			waitUntil(t, "the heartbeat to replace the seeded skew with not measured", 5*time.Second, func() bool {
				n, ok := reg.Get(nodeID)
				return ok && n.LastSeen.After(seeded) && !n.ClockSkewKnown()
			})
		})
	}
}

// Proves NC-37.
func TestTunnelOpen_NodeYearsOutKeepsItsStreamAndAnswersATask(t *testing.T) {
	for _, tc := range []struct {
		name  string
		years int
		sign  time.Duration
	}{
		{"ahead", 30, 1},
		{"behind", -30, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const nodeID = "node-years-out"
			router := dispatch.NewRouter(nil, nil)
			sink := newRegisterSignalSink(routerSink{r: router})
			reg := registry.NewInMemory()
			srv := grpc.NewServer(grpc.StreamInterceptor(injectNodeIDInterceptor(nodeID)))
			relayv1.RegisterTunnelServer(srv, &tunnelServer{reg: reg, sink: sink})
			conn := newBufconnConn(t, srv)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			stream := openNodeStream(ctx, t, conn, nodeID)
			awaitSignal(t, "the Node to register with the router", sink.registered)

			yearsOut := time.Now().AddDate(tc.years, 0, 0).UnixMilli()
			sendHeartbeat(t, stream, yearsOut)
			waitUntil(t, "the years-out skew to be recorded", 5*time.Second, func() bool {
				n, ok := reg.Get(nodeID)
				return ok && n.ClockSkewKnown()
			})
			n, _ := reg.Get(nodeID)
			if tc.sign*n.ClockSkew < 29*365*24*time.Hour {
				t.Fatalf("ClockSkew = %v, want more than 29 years of sign %d", n.ClockSkew, tc.sign)
			}
			if !n.Connected || nodeMarkedOffline(t, reg, nodeID) {
				t.Fatal("a Node years out of step is not connected")
			}

			type dispatched struct {
				res jobs.Result
				err error
			}
			done := make(chan dispatched, 1)
			go func() {
				res, err := router.Dispatch(ctx, nodeID, jobs.Task{ID: "task-years-out", NodeID: nodeID})
				done <- dispatched{res, err}
			}()

			msg, err := stream.Recv()
			if err != nil {
				t.Fatalf("recv task: %v", err)
			}
			if got := msg.GetTask().GetTaskId(); got != "task-years-out" {
				t.Fatalf("received %T with task id %q, want the dispatched Task", msg.Body, got)
			}
			if err := stream.Send(&relayv1.DaemonMessage{
				Body: &relayv1.DaemonMessage_TaskResult{TaskResult: &relayv1.TaskResult{
					TaskId: "task-years-out", Outcome: relayv1.Outcome_OUTCOME_SUCCESS,
				}},
			}); err != nil {
				t.Fatalf("send task result: %v", err)
			}
			select {
			case d := <-done:
				if d.err != nil || d.res.Outcome != jobs.OutcomeSuccess {
					t.Fatalf("Dispatch = (%v, %v), want success", d.res.Outcome, d.err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Dispatch did not return after the Task result")
			}

			before, _ := reg.Get(nodeID)
			sendHeartbeat(t, stream, yearsOut)
			waitUntil(t, "a later years-out heartbeat to be recorded", 5*time.Second, func() bool {
				n, ok := reg.Get(nodeID)
				return ok && n.LastSeen.After(before.LastSeen)
			})
			if n, _ := reg.Get(nodeID); !n.Connected {
				t.Fatal("the stream was dropped after the years-out heartbeats")
			}
		})
	}
}

// failingHeartbeatRegistry fails the heartbeat write only, so Hello's Upsert
// and the connected flag still work.
type failingHeartbeatRegistry struct{ registry.Repository }

func (failingHeartbeatRegistry) RecordHeartbeat(string, time.Time, registry.ClockSkewReading) error {
	return errors.New("store unavailable")
}

func TestTunnelOpen_FailedHeartbeatWriteIsLoggedAndTheDeadlineStillResets(t *testing.T) {
	const nodeID = "node-failing-write"
	logs := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	inner := registry.NewInMemory()
	srv := grpc.NewServer(grpc.StreamInterceptor(injectNodeIDInterceptor(nodeID)))
	relayv1.RegisterTunnelServer(srv, &tunnelServer{
		reg:               failingHeartbeatRegistry{inner},
		heartbeatDeadline: 500 * time.Millisecond,
	})
	conn := newBufconnConn(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream := openNodeStream(ctx, t, conn, nodeID)

	recvDone := make(chan error, 1)
	go func() {
		_, err := stream.Recv()
		recvDone <- err
	}()

	// Three times the deadline, so only the resets can be keeping it open.
	end := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(end) {
		sendHeartbeat(t, stream, time.Now().UnixMilli())
		select {
		case err := <-recvDone:
			t.Fatalf("stream closed although heartbeats kept arriving: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
	}
	if n, _ := inner.Get(nodeID); !n.Connected {
		t.Fatal("node not connected although its heartbeats kept arriving")
	}

	for _, line := range strings.Split(logs.String(), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec["msg"] == "registry heartbeat write failed" && rec["node_id"] == nodeID {
			return
		}
	}
	t.Fatalf("no \"registry heartbeat write failed\" log line for %s in:\n%s", nodeID, logs.String())
}
