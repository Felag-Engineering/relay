package api

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// openapi_test.go is the published contract's gate (#358, v0.4.0 [3/7]).
//
// A hand-kept API document drifts from the server the moment someone adds a
// route and forgets the spec — and drifts silently, because nothing checks. The
// spec then becomes actively worse than none: a generated client compiles
// against a contract the server does not honour. Since [4/7] generates the
// official CLI's transport FROM this file, that failure would land as a broken
// CLI rather than a review comment.
//
// So the spec is checked two ways, both mechanical:
//
//  1. It is a VALID OpenAPI 3.1 document (refs resolve, schemas well-formed).
//     This is the "lint" half, run in the Go toolchain rather than through a
//     Node linter — a gate that needs an uninstalled tool is a gate that never
//     runs, and this repo's Makefile already says a skipped check must not look
//     like a passed one.
//  2. Its paths and methods match api.Routes() EXACTLY, in both directions: a
//     served route missing from the spec fails, and a documented route the
//     server does not serve fails too. The second direction matters as much as
//     the first — a spec promising an endpoint that 404s is the kind of thing
//     an integrator discovers in production.

// specPath resolves docs/api/openapi.yaml from this test's own location, so it
// does not depend on the working directory `go test` was invoked from.
func specPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// .../relay/internal/controlplane/api/openapi_test.go -> repo root
	root := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..")
	return filepath.Join(root, "docs", "api", "openapi.yaml")
}

func loadSpec(t *testing.T) *openapi3.T {
	t.Helper()
	data, err := os.ReadFile(specPath(t))
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(data)
	if err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	if err := doc.Validate(loader.Context); err != nil {
		t.Fatalf("spec is not a valid OpenAPI document: %v", err)
	}
	return doc
}

// TestOpenAPISpec_IsValid is the lint half: the committed spec parses and
// validates as OpenAPI 3.1, with every $ref resolving.
func TestOpenAPISpec_IsValid(t *testing.T) {
	doc := loadSpec(t)

	if doc.Info == nil || doc.Info.Title == "" || doc.Info.Version == "" {
		t.Error("spec must carry info.title and info.version")
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.") {
		t.Errorf("openapi = %q, want a 3.x document", doc.OpenAPI)
	}
	if doc.Paths == nil || doc.Paths.Len() == 0 {
		t.Fatal("spec documents no paths")
	}
}

// specOperations returns "METHOD /path" for every operation in the spec.
func specOperations(doc *openapi3.T) []string {
	var out []string
	for path, item := range doc.Paths.Map() {
		for method := range item.Operations() {
			out = append(out, method+" "+path)
		}
	}
	sort.Strings(out)
	return out
}

// servedOperations returns "METHOD /path" for every route the server mounts.
func servedOperations() []string {
	routes := Routes()
	out := make([]string, 0, len(routes))
	for _, r := range routes {
		out = append(out, r.Pattern())
	}
	sort.Strings(out)
	return out
}

// TestOpenAPISpec_MatchesServedRoutes is the drift gate, and the reason the
// route table is exported as data. It compares both directions, because each
// failure mode is bad in its own way: an undocumented route is invisible to
// every generated client, and a documented-but-unserved route is a promise the
// server breaks with a 404.
func TestOpenAPISpec_MatchesServedRoutes(t *testing.T) {
	doc := loadSpec(t)

	spec := specOperations(doc)
	served := servedOperations()

	inSpec := map[string]bool{}
	for _, op := range spec {
		inSpec[op] = true
	}
	inServed := map[string]bool{}
	for _, op := range served {
		inServed[op] = true
	}

	for _, op := range served {
		if !inSpec[op] {
			t.Errorf("route %q is served but NOT in docs/api/openapi.yaml — every /api/v1 route must be published, or a generated client cannot reach it", op)
		}
	}
	for _, op := range spec {
		if !inServed[op] {
			t.Errorf("operation %q is in docs/api/openapi.yaml but NOT served — the spec promises an endpoint that would 404", op)
		}
	}

	if len(spec) != len(served) {
		t.Errorf("spec documents %d operations, server mounts %d", len(spec), len(served))
	}
}

// TestOpenAPISpec_EveryOperationIsDocumented holds the spec to the standard a
// published contract needs to be useful, not merely valid: a stable
// operationId (generators derive method names from it), a summary, and at least
// one documented response. Cheap to satisfy, and it stops a route from being
// added to the spec as a bare stub purely to silence the drift gate above.
func TestOpenAPISpec_EveryOperationIsDocumented(t *testing.T) {
	doc := loadSpec(t)

	seenIDs := map[string]string{}
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			where := method + " " + path

			if op.OperationID == "" {
				t.Errorf("%s: no operationId — client generators need a stable name", where)
			} else if prev, dup := seenIDs[op.OperationID]; dup {
				t.Errorf("%s: operationId %q already used by %s — ids must be unique", where, op.OperationID, prev)
			} else {
				seenIDs[op.OperationID] = where
			}

			if strings.TrimSpace(op.Summary) == "" {
				t.Errorf("%s: no summary", where)
			}
			if op.Responses == nil || op.Responses.Len() == 0 {
				t.Errorf("%s: no documented responses", where)
			}
		}
	}
}

// TestOpenAPISpec_EveryOperationDocumentsUnauthorized: every route sits behind
// the same Authenticator, so every operation can answer 401. A spec that omits
// it teaches integrators to treat an auth failure as an unexpected error.
func TestOpenAPISpec_EveryOperationDocumentsUnauthorized(t *testing.T) {
	doc := loadSpec(t)

	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			if op.Responses == nil || op.Responses.Value("401") == nil {
				t.Errorf("%s %s: no 401 response documented, but every /api/v1 route is authenticated", method, path)
			}
		}
	}
}

// TestOpenAPISpec_DeclaresBearerSecurity pins the auth scheme the CLI ([4/7])
// and any generated client depend on.
func TestOpenAPISpec_DeclaresBearerSecurity(t *testing.T) {
	doc := loadSpec(t)

	if doc.Components == nil || len(doc.Components.SecuritySchemes) == 0 {
		t.Fatal("spec declares no securitySchemes")
	}
	var bearer bool
	for _, ref := range doc.Components.SecuritySchemes {
		if ref.Value != nil && ref.Value.Type == "http" && ref.Value.Scheme == "bearer" {
			bearer = true
		}
	}
	if !bearer {
		t.Error("no HTTP bearer security scheme — /api/v1 authenticates with Account API Tokens")
	}
	if len(doc.Security) == 0 {
		t.Error("spec sets no top-level security requirement, so operations read as public")
	}
}

// TestServedRoutes_AreAllUnderAPIV1 guards the route table itself: /api/v1 is
// the versioned surface, and a route mounted outside it would be unversioned
// and outside the freeze the contract stability promise covers (ADR-0010).
func TestServedRoutes_AreAllUnderAPIV1(t *testing.T) {
	for _, r := range Routes() {
		if !strings.HasPrefix(r.Path, "/api/v1/") {
			t.Errorf("route %q is outside /api/v1 — the Control API's versioned surface", r.Pattern())
		}
		if r.Method != strings.ToUpper(r.Method) {
			t.Errorf("route %q: method must be upper-case to match the ServeMux pattern", r.Pattern())
		}
		if r.Handler == nil {
			t.Errorf("route %q has a nil handler factory", r.Pattern())
		}
	}
}
