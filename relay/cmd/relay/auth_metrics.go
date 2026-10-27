package main

import (
	"context"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/relay/relay/internal/metrics"
)

// loginAuditCounter counts the Console's password failures on /metrics at the
// one place each is recorded: the consoleauth.Auditor seam. It reads only the
// event's Kind, and never labels or logs anything from the event.
type loginAuditCounter struct {
	next    consoleauth.Auditor
	metrics *metrics.Metrics
}

// RecordLogin counts a failure kind, then always delegates and returns next's
// answer unchanged: consoleauth fails a sign-in it cannot record, and counting
// must not swallow that.
func (c loginAuditCounter) RecordLogin(ctx context.Context, e consoleauth.LoginEvent) error {
	if f, ok := consoleAuthFailure(e.Kind); ok {
		c.metrics.IncConsoleAuthFailure(f)
	}
	return c.next.RecordLogin(ctx, e)
}

// consoleAuthFailure maps an audit kind to the failure it counts as; every
// other kind is not a failure.
func consoleAuthFailure(kind string) (metrics.ConsoleAuthFailure, bool) {
	switch kind {
	case audit.KindLoginFailed:
		return metrics.ConsoleSignInFailed, true
	case audit.KindLoginThrottled:
		return metrics.ConsoleSignInThrottled, true
	case audit.KindStepUpFailed:
		return metrics.ConsoleStepUpFailed, true
	case audit.KindStepUpThrottled:
		return metrics.ConsoleStepUpThrottled, true
	default:
		return 0, false
	}
}
