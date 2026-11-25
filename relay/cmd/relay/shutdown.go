package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

const (
	// shutdownDrainBound is long enough for a Task at the relay-daemon's default
	// 30 s timeout plus its outcome accounting, and short enough that, with
	// shutdownListBudget, it ends well inside the 90 s TimeoutStopSec that
	// relay.service ships, before systemd's SIGKILL. A constant, not a setting:
	// it bounds no one's reach.
	shutdownDrainBound = 60 * time.Second

	// shutdownResponseGrace is how long in-flight control-plane responses (a
	// dispatch handler writing its Job, a wait_seconds call whose Job just
	// finished) get to finish once the Jobs are done: min(this, what is left of
	// the bound). Bounded because a Console live-read stream never ends on its
	// own.
	shutdownResponseGrace = 5 * time.Second

	// shutdownListBudget is how long listing the Jobs still running may take
	// once the bound is spent.
	shutdownListBudget = 5 * time.Second
)

// notifyStop registers SIGTERM and SIGINT and returns the channel they arrive
// on and a func that unregisters them. Once the first stop signal is handled
// and the func called, a second takes the default action and ends the process
// at once: the operator's override for a drain they will not wait for.
func notifyStop() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	return ch, func() { signal.Stop(ch) }
}

// shutdownRelay stops the Relay accepting dispatches and waits, for at most
// bound, for the Jobs it already started to write their outcome (EX-11).
//
// The control-plane listener is the only one that can dispatch; it is closed
// while Execution.Drain makes Start refuse any request already inside a
// handler. The node-plane gRPC server is deliberately left alone: stopping it
// would end every Tunnel, and the Router's offline hook would then resolve each
// still-running Task as node-offline, an outcome the Node never reported for a
// Task it may still be running. Left to the process exit, the Task stays in
// flight in the store, and the next start re-sends it under its own ID for its
// result if its Node connects within ten minutes of its dispatch (EX-71,
// invariant 4). The shutdown sends, cancels and resolves
// nothing.
//
// Once the grace or the bound expires, main returns and the store closes, so a
// handler or a Job's accounting still running fails its write and logs it.
func shutdownRelay(deps *appDeps, bound time.Duration, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	defer cancel()

	log.Info("relay shutting down: accepting no new dispatch; waiting for running Jobs to write their outcome",
		"drain_bound", bound.String())

	httpDone := make(chan struct{})
	if deps.control == nil {
		close(httpDone)
	} else {
		go func() {
			defer close(httpDone)
			err := deps.control.Shutdown(ctx)
			if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
				log.Error("relay shutdown: control plane did not close cleanly", "err", err)
			}
		}()
	}

	if deps.execution != nil {
		if err := deps.execution.Drain(ctx); err != nil {
			logRunningJobs(deps, bound, log)
		}
	}

	graceCtx, graceCancel := context.WithTimeout(ctx, shutdownResponseGrace)
	defer graceCancel()
	select {
	case <-httpDone:
	case <-graceCtx.Done():
	}

	log.Info("relay stopped")
}

// logRunningJobs names, by ID, each Job the store still shows Running. The
// store's Running state is the record of what is still running: a Job whose
// Tasks all resolved but whose accounting was still writing at the bound is not
// listed, though the summary line still records that the bound was reached.
// The listing is store-wide: it can include a Job carried over from an earlier
// run that the next start re-sends (EX-71).
func logRunningJobs(deps *appDeps, bound time.Duration, log *slog.Logger) {
	if deps.store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownListBudget)
	defer cancel()

	running := jobs.JobStateRunning
	q := jobs.JobQuery{State: &running, Order: jobs.JobOrderOldestFirst}
	count, cursor := 0, ""
	for {
		page, err := deps.store.JobQueries().QueryJobs(ctx, q, 0, cursor)
		if err != nil {
			log.Error("relay shutdown: could not list the Jobs still running", "err", err)
			return
		}
		for _, j := range page.Jobs {
			count++
			log.Warn("relay shutdown: Job still running at the drain bound; nothing was cancelled, and its outcome record may be missing from the audit trail",
				"job_id", j.JobID)
		}
		if page.Next == "" {
			break
		}
		cursor = page.Next
	}
	log.Warn("relay shutdown: the drain bound passed with Jobs still running",
		"running_jobs", count, "drain_bound", bound.String())
}
