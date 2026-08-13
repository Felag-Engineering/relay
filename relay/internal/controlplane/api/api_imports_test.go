package api

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestAPIImportsAreAllowlisted is an import-boundary AST guard (mirrors
// capability.TestCapabilityImportsOnlyRegistryAndJobs): package api's
// non-test files may only import a small stdlib allowlist plus the handful
// of internal packages this thin adapter is allowed to reuse — never
// internal/ca, internal/store, internal/transport, internal/ratelimit, or
// database/sql. This is the structural half of invariant 11 (the Control
// API manages runtime objects, never Relay configuration, and never reaches
// the CA key, a blast cap, or a listener directly).
func TestAPIImportsAreAllowlisted(t *testing.T) {
	allowed := map[string]bool{
		"context":       true,
		"crypto/rand":   true,
		"encoding/hex":  true,
		"encoding/json": true,
		"errors":        true,
		"fmt":           true,
		"io":            true,
		"log/slog":      true,
		"net/http":      true,
		"sort":          true,
		"strings":       true,
		"time":          true,
		// accounts is the proto-free identity domain (#297): the Account/Role
		// types the identity routes render, and the fail-closed Role.AtLeast
		// the admin gate reuses rather than re-deriving. It carries no SQL, no
		// HTTP, and no Relay configuration, so it does not widen what this
		// package can reach — it is the domain vocabulary of the routes.
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts":     true,
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit":        true,
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability":   true,
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane": true,
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/enroll":       true,
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/revocation":   true,
		// The three below arrived with the execution routes (#356).
		//
		// authz is imported for ONE symbol: the ErrUnauthorized sentinel, so a
		// role refusal renders as 403 instead of a generic 500. It is emphatically
		// NOT used to make an authorization decision here — RoleGate.Authorize is
		// called by the capability layer, and a surface that gated Raw Exec itself
		// would be the second control path package authz's doc warns about.
		// Importing it to *recognize* a refusal is the opposite of re-deciding one.
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/authz": true,
		// jobs is the proto-free execution domain: Action/RiskClass to build the
		// request, Task/Outcome to render the response. No SQL, no HTTP, no Relay
		// configuration — the same domain-mirror role accounts plays for identity.
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs": true,
		// opvocab is the read-only Operation vocabulary mirror. It supplies the
		// risk class and the SHARED argument-name validation both control surfaces
		// call (opvocab.ValidateArgNames), so a malformed call cannot be a clean
		// 400 on one surface and a denied_by_policy on the other (#345).
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/opvocab": true,
	}
	forbidden := map[string]bool{
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/ca":        true,
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store":     true,
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/transport": true,
		"github.com/Felag-Engineering/gleipnir-relay/relay/internal/ratelimit": true,
		"database/sql": true,
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%s): %v", dir, err)
	}

	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", path, err)
		}
		for _, imp := range file.Imports {
			importPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", imp.Path.Value, name, err)
			}
			if forbidden[importPath] {
				t.Errorf("%s imports %q — package api must never reach Relay configuration, the CA key, raw SQL, or a listener directly (invariant 11)", name, importPath)
			}
			if !allowed[importPath] {
				t.Errorf("%s imports %q, which is not in package api's import allowlist", name, importPath)
			}
		}
	}
}

// TestDeps_HasNoConfigField is a structural guard for invariant 11: Deps
// must never grow a Relay Config, CA, blast-cap, or listener field. A route
// that could read cfg.ReadBlastCap/MutateBlastCap or the CA key would let
// the Control API raise its own limits or mutate configuration, which
// ADR-0010 forbids. This walks Deps's fields via reflection so the check
// fails the moment such a field is added, without needing to import
// cmd/relay.Config (which would itself violate the import allowlist above).
func TestDeps_HasNoConfigField(t *testing.T) {
	typ := reflect.TypeOf(Deps{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if strings.Contains(strings.ToLower(f.Name), "config") {
			t.Errorf("Deps field %q looks like a Relay Config field — invariant 11 forbids the Control API from touching Relay configuration", f.Name)
		}
		fieldTypeName := f.Type.String()
		if strings.Contains(strings.ToLower(fieldTypeName), "config") {
			t.Errorf("Deps field %q has type %q, which looks like a Relay Config type — invariant 11 forbids the Control API from touching Relay configuration", f.Name, fieldTypeName)
		}
	}
}
