package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
)

// watchFreezeSignals is the local, host-side lever for the Relay-wide Freeze
// this milestone (v0.0.5 [6/8]/#101): SIGUSR1 engages, SIGUSR2 releases. Both
// are otherwise-unused Unix signals (the Relay imports no os/signal
// elsewhere) reserved for this purpose, chosen over a root-owned file so
// engage/release require nothing more than an operator (or a monitoring
// system's alert action) with process-signal privilege on the Relay host —
// no new config surface to write and reload.
//
// ADR-0013's asymmetric-activation decision, implemented here: engaging is
// cheap and immediate (SIGUSR1, no reason required — the priority during an
// incident is stopping dispatch, not paperwork), while releasing is
// deliberate and always carries an audited reason (SIGUSR2 +
// RELAY_FREEZE_RELEASE_REASON). Both engage and release are attributed to
// principal "local-host" and durably audited (RecordFreeze) via
// capability.Service.EngageFreeze/ReleaseFreeze. The Control API path for
// Freeze (remote engage/release, richer principals) lands in v0.0.6 — this
// is deliberately the local-only half.
func watchFreezeSignals(ctx context.Context, svc *capability.Service) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGUSR1, syscall.SIGUSR2)
	defer signal.Stop(sigCh)

	principal := capability.Principal{Account: "local-host"}

	for {
		select {
		case <-ctx.Done():
			return
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGUSR1:
				if err := svc.EngageFreeze(ctx, principal); err != nil {
					slog.Error("engage freeze failed", "err", err)
					continue
				}
				slog.Info("freeze engaged", "principal", principal.Attribution())
			case syscall.SIGUSR2:
				reason := envOr("RELAY_FREEZE_RELEASE_REASON", "released locally on relay host")
				if err := svc.ReleaseFreeze(ctx, principal, reason); err != nil {
					slog.Error("release freeze failed", "err", err)
					continue
				}
				slog.Info("freeze released", "principal", principal.Attribution(), "reason", reason)
			}
		}
	}
}
