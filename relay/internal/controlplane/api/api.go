// Package api is the first REST/JSON slice of the Control API (ADR-0010):
// Enrollment Token mint/revoke, Node revoke, and Freeze engage/release,
// mounted under /api/v1 on the control-plane's existing *http.ServeMux
// (relay/internal/controlplane.Server.Mux()) behind the single
// Authenticator.Middleware already wired there — no new listener, no new
// auth path (invariant 10, ADR-0009).
//
// Every handler is a thin adapter: decode -> validate -> call existing
// enroll/revocation/capability machinery -> render. No route reimplements
// domain logic, and no route can reach Relay configuration, a blast cap, the
// CA key, or a listener (invariant 11) — Deps below intentionally carries
// none of those, and this package's import list is structurally capped by
// TestAPIImportsAreAllowlisted (api_imports_test.go).
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/enroll"
)

// TokenMinter mints a scoped, expiring Enrollment Token. *enroll.Service
// satisfies this interface.
type TokenMinter interface {
	Create(ctx context.Context, scope []string, ttl time.Duration, opts ...enroll.Option) (*enroll.Token, string, error)
}

// TokenRevoker revokes an Enrollment Token by id. *revocation.Service
// satisfies this interface (RevokeToken cascade-revokes the token's already
// -enrolled Nodes too — see tokens.go).
type TokenRevoker interface {
	RevokeToken(ctx context.Context, id string) error
}

// NodeRevoker revokes a single Node, tearing down its live Tunnel
// immediately. *revocation.Service satisfies this interface.
type NodeRevoker interface {
	RevokeNode(nodeID string)
}

// Freezer engages and releases the Relay-wide Freeze (ADR-0013).
// *capability.Service satisfies this interface.
type Freezer interface {
	EngageFreeze(ctx context.Context, p capability.Principal) error
	ReleaseFreeze(ctx context.Context, p capability.Principal, reason string) error
}

// Auditor appends a lifecycle audit.Record. audit.Repository satisfies this
// interface.
type Auditor interface {
	Append(ctx context.Context, r audit.Record) error
}

// AccountManager is the Account-store view the identity routes need
// (accounts.Repository satisfies it). Deliberately not accounts.Repository
// itself: EnsureFoundingAdmin is seeding, a startup act, and no request
// handler has any business reaching it.
type AccountManager interface {
	Create(ctx context.Context, a accounts.Account) (accounts.Account, error)
	Get(ctx context.Context, id string) (accounts.Account, error)
	List(ctx context.Context) ([]accounts.Account, error)
	SetRole(ctx context.Context, id string, role accounts.Role) error
	SetEnabled(ctx context.Context, id string, enabled bool) error
}

// APITokenService mints, revokes, and lists an Account's API Tokens.
// *accounts.TokenService satisfies it.
//
// Verify is deliberately absent: this surface *issues* credentials, the
// authenticator *checks* them, and neither needs the other's power.
type APITokenService interface {
	Mint(ctx context.Context, accountID, name string, ttl time.Duration) (accounts.APIToken, accounts.Plaintext, error)
	Revoke(ctx context.Context, id string) error
	List(ctx context.Context, accountID string) ([]accounts.APIToken, error)
}

// Deps are the collaborators Register wires into the /api/v1 route table.
// Deliberately narrow (invariant 11): no Relay Config, CA, blast cap, or
// listener field — every dependency here is a purpose-built interface over
// existing runtime-object machinery, never Relay configuration.
type Deps struct {
	Tokens       TokenMinter
	TokenRevoker TokenRevoker
	Nodes        NodeRevoker
	Freeze       Freezer
	Audit        Auditor
	// Accounts and APITokens back the identity-management routes (#297).
	// Both are admin-only at every entry point (see requireAdmin).
	Accounts  AccountManager
	APITokens APITokenService
	// Now returns the current time, used to timestamp lifecycle audit
	// Records. Defaults to time.Now().UTC() when nil.
	Now func() time.Time
}

// Register mounts the /api/v1 route table onto mux. mux is expected to be
// controlplane.Server.Mux() (or an equivalent already wrapped by
// Authenticator.Middleware in tests) — Register never constructs a listener
// or auth wrapper of its own.
func Register(mux *http.ServeMux, d Deps) {
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}

	mux.HandleFunc("POST /api/v1/enrollment-tokens", handleMintToken(d))
	mux.HandleFunc("DELETE /api/v1/enrollment-tokens/{id}", handleRevokeToken(d))
	mux.HandleFunc("POST /api/v1/nodes/{node_id}/revoke", handleRevokeNode(d))
	mux.HandleFunc("POST /api/v1/freeze/engage", handleFreezeEngage(d))
	mux.HandleFunc("POST /api/v1/freeze/release", handleFreezeRelease(d))

	// Identity management (#297). Every route below is admin-only; the gate
	// lives in each handler (requireAdmin) rather than in a wrapper here, so a
	// route added later cannot silently miss it by being registered on the
	// wrong mux.
	mux.HandleFunc("POST /api/v1/accounts", handleCreateAccount(d))
	mux.HandleFunc("GET /api/v1/accounts", handleListAccounts(d))
	mux.HandleFunc("GET /api/v1/accounts/{id}", handleGetAccount(d))
	mux.HandleFunc("POST /api/v1/accounts/{id}/role", handleSetAccountRole(d))
	mux.HandleFunc("POST /api/v1/accounts/{id}/enable", handleSetAccountEnabled(d, true))
	mux.HandleFunc("POST /api/v1/accounts/{id}/disable", handleSetAccountEnabled(d, false))
	mux.HandleFunc("POST /api/v1/accounts/{id}/tokens", handleMintAPIToken(d))
	mux.HandleFunc("GET /api/v1/accounts/{id}/tokens", handleListAPITokens(d))
	mux.HandleFunc("DELETE /api/v1/api-tokens/{token_id}", handleRevokeAPIToken(d))
}

// principal reads the Principal that Authenticator.Middleware injected into
// r's context. Every route registered by this package sits behind that
// Middleware (Register's contract), so ok is expected to always be true; the
// false path is a defensive 500, never a security decision made here.
func principal(w http.ResponseWriter, r *http.Request) (capability.Principal, bool) {
	p, ok := controlplane.PrincipalFromContext(r.Context())
	if !ok {
		writeProblem(w, http.StatusInternalServerError, "missing principal",
			"request reached the Control API without an authenticated principal")
		return capability.Principal{}, false
	}
	return p, true
}

// newAuditID mints a unique audit.Record.ID: 16 crypto/rand bytes,
// hex-encoded, "audit-" prefixed — mirroring
// relay/internal/auditsink.defaultID. audit_id is the table's PRIMARY KEY
// (store/migrations/0001_init.sql); every recordLifecycle call must set a
// fresh one or the second lifecycle insert in a session fails a UNIQUE
// constraint. A package-level var (rather than a Deps field) so it stays out
// of the deliberately narrow Deps struct while still being overridable from
// this package's own tests.
var newAuditID = defaultAuditID

func defaultAuditID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("api: generate audit record id: %w", err)
	}
	return "audit-" + hex.EncodeToString(b), nil
}

// recordLifecycle appends one lifecycle audit.Record (token mint/revoke,
// Node revoke) attributed to p. Freeze engage/release is audited intrinsically
// by capability.Service (RecordFreeze) and must never call this — doing so
// would double-audit (see freeze.go). reason must never carry an Enrollment
// Token plaintext.
//
// On an audit-write failure, this logs and returns without undoing the
// already-completed lifecycle action: the action happened; a failed audit
// write must not be papered over by rolling it back, nor may it block the
// caller from returning success for a mutation that already took effect.
func recordLifecycle(ctx context.Context, d Deps, p capability.Principal, kind, nodeID, reason string) {
	id, err := newAuditID()
	if err != nil {
		slog.Error("control api: generate lifecycle audit record id", "kind", kind, "error", err)
		return
	}
	asserted := capability.AssertionsFromContext(ctx)
	rec := audit.Record{
		ID:        id,
		Timestamp: d.Now(),
		Kind:      kind,
		Principal: p.Attribution(),
		Attribution: audit.Attribution{
			Verified: audit.Verified{
				AccountID:   p.AccountID,
				AccountName: p.Account,
				Role:        p.Role,
				TokenID:     p.TokenID,
				Method:      string(p.AuthMethod),
			},
			Asserted: audit.Asserted{
				OnBehalfOf:  asserted.OnBehalfOf,
				Traceparent: asserted.Traceparent,
				SessionRef:  asserted.SessionRef,
				ChangeRef:   asserted.ChangeRef,
			},
		},
		NodeID: nodeID,
		Reason: reason,
	}
	if err := d.Audit.Append(ctx, rec); err != nil {
		slog.Error("control api: append lifecycle audit record", "kind", kind, "error", err)
	}
}
