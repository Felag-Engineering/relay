package main

// control_surfaces.go defines the ControlSurface self-registration seam
// (#162): each control surface (MCP, the Control API) knows how to mount its
// own routes onto the shared, already-auth-wrapped mux, so newServer holds a
// list of surfaces instead of two inline mount stanzas. This must live in
// package main rather than beside mcp/api themselves: mcp/no_dispatch_test.go
// requires every non-test file in the mcp package to be classified as
// read-only or exec-strict, and api/api_imports_test.go forbids the api
// package from importing mcp — package main is the only seam both surfaces
// can be mounted from without tripping either guard.
//
// surfaceDeps is assembled exactly once per newServer call (invariant 10:
// capSvc is a single instance, delivered to every surface here — no surface
// constructs its own capability.Service or dispatcher). Mount takes
// *http.ServeMux (from controlplane.Server.Mux()), never *controlplane.Server:
// a surface can reach the routes it registers but never the listener, TLS
// config, or the Authenticator that wraps the mux.

import (
	"net/http"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/api"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/enroll"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/revocation"
)

// surfaceDeps holds every collaborator a control surface's Mount may need.
// It is assembled once in newServer's ControlEnabled block and handed to
// every surface in defaultControlSurfaces() — most fields are unused by any
// single surface (e.g. apiSurface never touches ops), which is expected: the
// struct is a shared dependency bag, not a per-surface signature.
type surfaceDeps struct {
	registry   registry.Repository
	policy     *policyview.Cache
	ops        mcp.OperationLister
	capability *capability.Service // one instance: mcp.Executor AND api.Freezer
	jobs       jobs.JobRepository
	tasks      jobs.TaskRepository
	tokens     *enroll.Service
	revocation *revocation.Service
	audit      audit.Repository
	now        func() time.Time
}

// controlSurface is a self-mounting control-plane surface: it knows how to
// register its own routes onto mux using d, and nothing else.
type controlSurface interface {
	Mount(mux *http.ServeMux, d surfaceDeps)
}

// mcpSurface mounts the MCP server (#117's read tools, #118's execution
// tools) at "/mcp" — reached only through the Authenticator.Middleware that
// already wraps mux (invariant 10: one control path).
type mcpSurface struct{}

func (mcpSurface) Mount(mux *http.ServeMux, d surfaceDeps) {
	mux.Handle("/mcp", mcp.New(d.registry, d.policy, d.ops, d.capability,
		jobResultReader{jobsRepo: d.jobs, tasksRepo: d.tasks}))
}

// apiSurface mounts the /api/v1 Control API slice (#116) onto the same mux —
// no new listener, no new auth (invariant 10). It never touches Relay Config
// or a blast cap (invariant 11).
type apiSurface struct{}

func (apiSurface) Mount(mux *http.ServeMux, d surfaceDeps) {
	api.Register(mux, api.Deps{
		Tokens:       d.tokens,
		TokenRevoker: d.revocation,
		Nodes:        d.revocation,
		Freeze:       d.capability,
		Audit:        d.audit,
		Now:          d.now,
	})
}

// defaultControlSurfaces returns every control surface newServer mounts when
// Config.ControlEnabled. An explicit slice (not init()-registration): adding
// a surface is an obvious, greppable one-line edit here, with no global
// mutable registration state.
func defaultControlSurfaces() []controlSurface {
	return []controlSurface{mcpSurface{}, apiSurface{}}
}
