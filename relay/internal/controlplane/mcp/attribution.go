package mcp

import (
	"context"
	"log/slog"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
)

// logPrincipal records the calling Principal for attribution, as read from
// the context controlplane.Authenticator.Middleware injected (FoundingAdmin
// this milestone; every /mcp request authenticates as it — ADR-0010).
// Reads are not audited this issue (the audit trail, #102, is dispatch-only:
// it records Job/Task actions, and these tools never dispatch); this is
// observability, not the audited record.
func logPrincipal(ctx context.Context, tool string) {
	p, ok := controlplane.PrincipalFromContext(ctx)
	if !ok {
		return
	}
	slog.Debug("mcp read tool called", "tool", tool, "principal", p.Attribution())
}
