package main

// reload_signal.go is the local, host-side lever that reloads the Relay's
// configuration file: SIGHUP. Its authority is signal privilege on the Relay's
// host, the same root as the Freeze lever (freeze_signal.go). It re-reads only
// the file root wrote, and the file check refuses any file the Relay could write
// (invariant 11, ADR-0043).

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Felag-Engineering/relay/relay/internal/auditsink"
)

// notifyReload registers for SIGHUP and returns the channel it arrives on. It
// is called before the configuration is loaded: until a handler is installed
// SIGHUP's default action ends the process, and a signal queued here is served
// once watchReload starts. The channel holds one signal, so signals arriving
// during a reload coalesce into one more reload.
func notifyReload() <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	return ch
}

// watchReload runs one reload per SIGHUP until ctx ends. A panic in a reload is
// recovered and refused like any other failure: nothing a reload does may end
// the process (RC-21).
func watchReload(ctx context.Context, hup <-chan os.Signal, r *reloader) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			runReload(ctx, r)
		}
	}
}

func runReload(ctx context.Context, r *reloader) {
	defer func() {
		if p := recover(); p != nil {
			slog.Error("configuration reload failed; the running configuration is unchanged", "panic", p)
			r.auditRefusal(ctx, auditsink.ReloadRefusedInternal, nil)
		}
	}()
	// The outcome is logged by reload itself.
	_, _ = r.reload(ctx)
}
