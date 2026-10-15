package mcp

import (
	"context"
	"log/slog"

	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
)

// logPrincipal records the calling Principal for attribution, as read from
// the context controlplane.Authenticator.Middleware injected (ADR-0010).
// This is observability, not the audited record.
func logPrincipal(ctx context.Context, tool string) {
	p, ok := controlplane.PrincipalFromContext(ctx)
	if !ok {
		return
	}
	slog.Debug("mcp read tool called", "tool", tool, "principal", p.Attribution())
}
