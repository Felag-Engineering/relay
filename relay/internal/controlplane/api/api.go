// Package api is the REST/JSON Control API (ADR-0010): Enrollment Token
// mint/revoke, Node revoke, Freeze engage/release, Account and API-Token
// management, and — since #356 — execution (run an Operation, Raw Exec, and
// plan mode), all mounted under /api/v1 on the control-plane's existing *http.ServeMux
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
//
// The execution routes hold to the same rule structurally, not just by
// convention: no_dispatch_test.go fails any file here that names
// capability.Service, capability.New, or newDispatch, so the only path to a
// dispatch is the injected Executor interface (execution.go).
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
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/revocation"
)

// TokenMinter mints a scoped, expiring Enrollment Token. *enroll.Service
// satisfies this interface.
type TokenMinter interface {
	Create(ctx context.Context, scope []string, ttl time.Duration, opts ...enroll.Option) (*enroll.Token, string, error)
}

// TokenRevoker revokes an Enrollment Token by id. *revocation.Service
// satisfies this interface (RevokeToken cascade-revokes the token's already
// -enrolled Nodes too — see tokens.go).
//
// The cascade writes one KindNodeRevoke record per cascaded Node through the
// record callback this surface supplies (#557) — revocation.Service has no
// audit sink of its own, so tokens.go's handleRevokeToken builds the closure
// that authors each record's Principal and reason and hands it in. A
// returned ErrCascadeNotRecorded means the token and every Node it enrolled
// were revoked, but the trail is incomplete for one or more of them.
type TokenRevoker interface {
	RevokeToken(ctx context.Context, id string, record revocation.RevocationRecorder) error
}

// NodeRevoker revokes a single Node, tearing down its live Tunnel
// immediately. *revocation.Service satisfies this interface.
type NodeRevoker interface {
	RevokeNode(nodeID string)
}

// Freezer engages and releases the Relay-wide Freeze (ADR-0013).
// *capability.Service satisfies this interface.
//
// Both methods are role-gated INSIDE the capability layer (#397): engage
// needs a human `operator`+, release needs `admin` and a reason, and the
// refusal is audited there. This interface deliberately does not expose
// capability.Service's EngageFreezeLocal/ReleaseFreezeLocal — the host-signal
// lever is root-on-the-box authority (ADR-0013) and must not be reachable
// from an HTTP route, so the narrow interface is what keeps it out of reach.
type Freezer interface {
	EngageFreeze(ctx context.Context, p capability.Principal) error
	ReleaseFreeze(ctx context.Context, p capability.Principal, reason string) error
}

// Auditor appends a lifecycle audit.Record. audit.Repository satisfies this
// interface.
type Auditor interface {
	Append(ctx context.Context, r audit.Record) error

	// AppendAll persists every Record in rs atomically: on a nil error all of
	// them were written, on a non-nil error none were (audit.Repository's
	// contract). Used by the token-revocation cascade to record a chunk of
	// Nodes in one commit rather than one per Node (#563).
	AppendAll(ctx context.Context, rs []audit.Record) error
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
	// Authz is the control plane's role ladder for the ADMINISTRATIVE acts
	// that never construct a jobs.Action and so never reach the capability
	// layer's dispatch pipeline: enrollment-token mint and revoke, and Node
	// revoke (#397). The composition root passes the SAME *authz.RoleGate the
	// capability layer holds, so a floor is decided in one table for every
	// surface (invariant 10) — this package consults it and renders the
	// answer, it never decides one.
	//
	// Freeze is NOT gated here: it goes through Deps.Freeze into the
	// capability layer, which consults the same object itself. The split is
	// not a preference — capability's import allowlist bars internal/enroll
	// and internal/revocation, so mint and revoke have no capability-layer
	// method to be gated inside.
	//
	// Nil refuses every route that needs it with a 500 rather than proceeding
	// ungated: an unwired gate is a composition-root bug, and #397 exists
	// because the ungated path failed open silently.
	Authz capability.ControlAuthorizer
	// Accounts and APITokens back the identity-management routes (#297).
	// Both are admin-only at every entry point (see requireAdmin).
	Accounts  AccountManager
	APITokens APITokenService
	// NodeReader is the single-Node registry view behind GET
	// /api/v1/nodes/{node_id} (#440). A read-only narrowing of
	// registry.Repository: this surface has no business holding Upsert,
	// SetRelayLabels or SetRevoked, and the revoke route reaches revocation
	// through Nodes above rather than through the registry.
	NodeReader NodeReader
	// Exec and Jobs back the execution routes (#356). Exec is the SAME
	// capability layer the MCP surface dispatches through — never a second
	// control path (invariant 10) — and Jobs is a read-only view used to render
	// per-Node results after a dispatch returns. Neither carries a blast cap or
	// any Relay configuration: the caps live inside the capability layer, above
	// this surface's reach (invariant 11).
	Exec Executor
	Jobs JobResultReader
	// Approvals backs the out-of-band decision channel (#270, ADR-0027). It is
	// the same capability layer Exec is — the composition root passes one
	// *capability.Service for both — kept as a separate interface only so this
	// package's seams stay named after what each route needs.
	Approvals ApprovalService
	// ApprovalGrants backs the batch/window grant routes (#378, ADR-0027
	// decision 12) — the same *capability.Service again, named separately for
	// the same reason Approvals is. Nil disables the routes with a 500 rather
	// than silently accepting requests that would grant nothing.
	ApprovalGrants ApprovalGrantService
	// Reads records read-access events for the Job read route (#357,
	// ADR-0025). Nil skips recording — the pre-#288 behaviour, kept so tests
	// and any unwired surface work; the composition root always supplies it.
	Reads ReadAuditor
	// Now returns the current time, used to timestamp lifecycle audit
	// Records. Defaults to time.Now().UTC() when nil.
	Now func() time.Time
	// CertExpiringWithin is the state:cert-expiring warning window
	// (ADR-0034, #414): a mirror of a root-owned startup value (invariant
	// 11) — this surface is TOLD it, and no route reads or sets it. Zero
	// (the default) means the marker never fires.
	CertExpiringWithin time.Duration
}

// Route is one /api/v1 route: its HTTP method, its path (in net/http
// ServeMux's `{name}` wildcard syntax), and the handler factory that binds it
// to a Deps.
//
// The route table is exported as DATA (see [Routes]) rather than being a list
// of mux.HandleFunc calls buried in Register, because the published OpenAPI
// spec has to be checkable against what the server actually serves. With the
// table as data, openapi_test.go compares the two mechanically and a route
// added, renamed, or removed without a matching spec edit fails CI — instead of
// the spec quietly becoming fiction, which is the normal fate of a hand-kept
// API document.
type Route struct {
	Method string
	Path   string
	// Handler builds the http.HandlerFunc for this route from d.
	Handler func(d Deps) http.HandlerFunc
}

// Pattern renders the route as a net/http ServeMux pattern ("GET /api/v1/...").
func (r Route) Pattern() string { return r.Method + " " + r.Path }

// Routes returns the complete /api/v1 route table, in registration order.
//
// This is the single source of truth for "what does the Control API serve".
// Register mounts exactly these; the OpenAPI drift gate reads exactly these.
func Routes() []Route {
	return []Route{
		// Enrollment Tokens, Node revocation, Freeze (#116). Every route
		// here has a role floor, and every floor is decided by the ONE
		// authz.RoleGate (#397): the enrollment and revocation routes consult
		// it through authorizeControl below, the Freeze routes inherit it
		// inside the capability layer. Which of the two applies to a given
		// route is asserted by TestEveryRouteIsRoleClassified, so a route
		// added to this group later cannot silently have neither.
		{"POST", "/api/v1/enrollment-tokens", handleMintToken},
		{"DELETE", "/api/v1/enrollment-tokens/{id}", handleRevokeToken},
		{"GET", "/api/v1/nodes/{node_id}", handleGetNode},
		{"POST", "/api/v1/nodes/{node_id}/revoke", handleRevokeNode},
		{"POST", "/api/v1/freeze/engage", handleFreezeEngage},
		{"POST", "/api/v1/freeze/release", handleFreezeRelease},

		// Identity management (#297). Every route here is admin-only; the gate
		// lives in each handler (requireAdmin) rather than in a wrapper, so a
		// route added later cannot silently miss it by being registered in the
		// wrong group.
		{"POST", "/api/v1/accounts", handleCreateAccount},
		{"GET", "/api/v1/accounts", handleListAccounts},
		{"GET", "/api/v1/accounts/{id}", handleGetAccount},
		{"POST", "/api/v1/accounts/{id}/role", handleSetAccountRole},
		{"POST", "/api/v1/accounts/{id}/enable", enableAccount(true)},
		{"POST", "/api/v1/accounts/{id}/disable", enableAccount(false)},
		{"POST", "/api/v1/accounts/{id}/tokens", handleMintAPIToken},
		{"GET", "/api/v1/accounts/{id}/tokens", handleListAPITokens},
		{"DELETE", "/api/v1/api-tokens/{token_id}", handleRevokeAPIToken},

		// Execution (#356). Both routes dispatch through the shared capability
		// layer (Selector -> authz -> blast-cap -> dispatch -> audit); neither
		// re-implements a role check, a Policy decision, or a cap — see
		// execution.go's header for why Raw Exec's admin gate deliberately stays
		// in authz.RoleGate rather than being repeated here.
		{"POST", "/api/v1/operations", handleRunOperation},
		{"POST", "/api/v1/raw-exec", handleRawExec},

		// Job read + cancel (#357). The read route is audited (ADR-0025): it
		// returns captured Task output, so it discloses material somebody else
		// produced. Cancel goes through the same capability layer as dispatch.
		{"GET", "/api/v1/jobs/{id}", handleGetJob},
		{"POST", "/api/v1/jobs/{id}/cancel", handleCancelJob},

		// The out-of-band approval decision channel (#270, ADR-0027). This is
		// the universal envelope: it works for a harness with zero approval
		// features and for the API-control drive mode, which has no MCP session
		// at all — and it is the only channel that is a guarantee rather than a
		// delivery convenience, because a decision here rides a credential the
		// requesting session does not hold. See approvals.go.
		{"GET", "/api/v1/approvals", handleListApprovals},
		{"GET", "/api/v1/approvals/{id}", handleGetApproval},
		{"POST", "/api/v1/approvals/{id}/decision", handleDecideApproval},

		// Batch/window approvals (#378, ADR-0027 decision 12). Note what is
		// NOT here: a route that approves a grant. Requesting one creates an
		// ordinary approval Request, answered through the decision route above
		// — so quorum, audience, requester exclusion, and channel strength are
		// the same code for a window as for a single dispatch, and cannot drift
		// apart. See approval_grants.go.
		{"POST", "/api/v1/approval-grants", handleCreateGrant},
		{"GET", "/api/v1/approval-grants", handleListGrants},
		{"GET", "/api/v1/approval-grants/{id}", handleGetGrant},
		{"POST", "/api/v1/approval-grants/{id}/revoke", handleRevokeGrant},
	}
}

// enableAccount adapts handleSetAccountEnabled's two-argument shape to the
// Route.Handler signature, so the enable/disable pair stays in the table
// alongside every other route rather than being a special case in Register.
func enableAccount(enabled bool) func(Deps) http.HandlerFunc {
	return func(d Deps) http.HandlerFunc { return handleSetAccountEnabled(d, enabled) }
}

// Register mounts the /api/v1 route table onto mux. mux is expected to be
// controlplane.Server.Mux() (or an equivalent already wrapped by
// Authenticator.Middleware in tests) — Register never constructs a listener
// or auth wrapper of its own.
func Register(mux *http.ServeMux, d Deps) {
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	for _, r := range Routes() {
		mux.HandleFunc(r.Pattern(), r.Handler(d))
	}
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

// authorizeControl is the surface-side half of #397's fix for the
// administrative routes that never reach the capability layer's dispatch
// pipeline (enrollment-token mint/revoke, Node revoke).
//
// It DECIDES NOTHING. The floor lives in one table — authz.RoleGate's
// requiredControlRole — which the capability layer consults for the Freeze
// and the composition root hands to this package as Deps.Authz, so the same
// answer reaches MCP, the Control API, and the Console (invariant 10). This
// function's whole job is to ask, audit a refusal, and render it.
//
// A nil Authz refuses with 500. That is the deliberate direction: #397 exists
// because an ungated administrative route failed open and nothing said so, so
// an unwired gate must be loud and closed rather than quiet and open.
//
// The refusal is recorded as audit.KindRefusal with the acting Principal,
// matching how the capability layer records a refused dispatch — a refusal is
// the most interesting kind of audit event, and one that only appears for
// some refusal paths is worse than none.
func authorizeControl(w http.ResponseWriter, r *http.Request, d Deps, p capability.Principal, act capability.ControlAction) bool {
	if d.Authz == nil {
		writeProblem(w, http.StatusInternalServerError, "authorization unavailable",
			"no control-plane authorizer is wired; refusing rather than proceeding ungated")
		return false
	}
	if err := d.Authz.AuthorizeControl(r.Context(), p, act); err != nil {
		recordLifecycle(r.Context(), d, p, audit.KindRefusal, "", err.Error())
		writeProblem(w, http.StatusForbidden, "forbidden", err.Error())
		return false
	}
	return true
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
// Node revoke, or a refusal of one — see authorizeControl) attributed to p.
// Freeze engage/release, and a refused Freeze, are audited intrinsically
// by capability.Service (RecordFreeze) and must never call this — doing so
// would double-audit (see freeze.go). reason must never carry an Enrollment
// Token plaintext.
//
// On an audit-write failure, this logs and returns without undoing the
// already-completed lifecycle action: the action happened; a failed audit
// write must not be papered over by rolling it back, nor may it block the
// caller from returning success for a mutation that already took effect.
func recordLifecycle(ctx context.Context, d Deps, p capability.Principal, kind, nodeID, reason string) {
	if err := recordLifecycleErr(ctx, d, p, kind, nodeID, reason); err != nil {
		// Neutral message: this covers both the id-generation and the append
		// failure, and the wrapped error says which.
		slog.Error("control api: record lifecycle audit record", "kind", kind, "error", err)
	}
}

// recordLifecycleErr is recordLifecycle's fail-closed half: it RETURNS the
// audit-write error instead of logging it, for the one caller that must not
// proceed without a record.
//
// handleRevokeNode calls this BEFORE revoking, and 500s if it fails, because
// #487's whole premise is that an irreversible act must be attributable — a
// revocation whose record was silently dropped is exactly the state the issue
// set out to end, and "the trail failed to write" is not a better excuse for it
// than "the endpoint accepted no reason". That inverts recordLifecycle's
// documented best-effort contract, which is right for the actions that keep it:
// they have already happened by the time it is called, and rolling them back is
// Revoke can invert it because RevokeNode has no error return: it cannot report
// failure to this handler, so there is no "the act failed after we recorded it"
// branch to get wrong.
//
// The honest limit of that, since a stronger claim is tempting and would be
// false: RevokeNode's DURABLE half can still fail quietly. It adds to the
// in-process denylist first and disconnects reliably, but reg.SetRevoked is
// best-effort and only logged (revocation/service.go). So a persist failure
// leaves a permanent, attributed node_revoke record beside a registry that did
// not record the revocation, and a later restart — which rehydrates the
// denylist from the registry (#133) — could let the Node reconnect. That is
// pre-existing and not this change's to fix; what this ordering guarantees is
// narrower and still worth having: no revocation is ATTEMPTED without a
// durable record of who ordered it and why.
//
// This mirrors the read lane's posture (ADR-0025: record before the seam, fail
// closed) and handleGetNode's, which already 500s when its read audit cannot be
// written — the same surface disagreeing with itself about whether an
// unrecorded act may proceed was the inconsistency worth removing.
func recordLifecycleErr(ctx context.Context, d Deps, p capability.Principal, kind, nodeID, reason string) error {
	rec, err := newLifecycleRecord(ctx, d, p, kind, nodeID, reason)
	if err != nil {
		return err
	}
	if err := d.Audit.Append(ctx, rec); err != nil {
		return fmt.Errorf("api: append lifecycle audit record: %w", err)
	}
	return nil
}

// newLifecycleRecord builds one lifecycle audit.Record attributed to p,
// carrying both the verified and asserted identity lanes and the derived
// reason — the same construction recordLifecycleErr uses for a single write
// and recordLifecycleAllErr uses for a cascaded chunk. Kept in one place so
// the attribution mapping cannot drift between the two paths: a second copy
// is what a security review would flag, and it is how a lane gets dropped on
// one path only.
func newLifecycleRecord(ctx context.Context, d Deps, p capability.Principal, kind, nodeID, reason string) (audit.Record, error) {
	id, err := newAuditID()
	if err != nil {
		return audit.Record{}, fmt.Errorf("api: generate lifecycle audit record id: %w", err)
	}
	asserted := capability.AssertionsFromContext(ctx)
	return audit.Record{
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
	}, nil
}

// recordLifecycleAllErr is the recorder-side half of RevocationRecorder's
// all-or-nothing contract (revocation/service.go): it builds one lifecycle
// audit.Record per Node in nodeIDs, attributed identically to
// recordLifecycleErr, then writes all of them through a single
// Auditor.AppendAll call.
//
// Every record is built with newLifecycleRecord before any write is
// attempted, so an ID-generation failure returns before any record for this
// chunk is persisted — keeping the all-or-nothing contract even on that path.
func recordLifecycleAllErr(ctx context.Context, d Deps, p capability.Principal, kind string, nodeIDs []string, reason string) error {
	recs := make([]audit.Record, len(nodeIDs))
	for i, nodeID := range nodeIDs {
		rec, err := newLifecycleRecord(ctx, d, p, kind, nodeID, reason)
		if err != nil {
			return err
		}
		recs[i] = rec
	}
	if err := d.Audit.AppendAll(ctx, recs); err != nil {
		return fmt.Errorf("api: append lifecycle audit records: %w", err)
	}
	return nil
}
