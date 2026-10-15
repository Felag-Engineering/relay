package mcp

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

// taskshim_guard_test.go is #376's third structural guard: **the shim may
// transform a response the SDK already produced, and may never originate one.**
//
// The other two guards constrain what the shim can reach downward
// (no_dispatch_test.go: no capability layer, so no dispatch) and sideways
// (no_decision_test.go: no approval decision). This one constrains what it can
// reach UPWARD, into the protocol surface itself.
//
// The enforcement is the strongest available and also the simplest: **the shim
// must not import the MCP SDK at all.** A file that cannot name the SDK cannot
// register a tool, add a custom method, construct a CallToolResult, or mint a
// server — so "it only reshapes what came back" stops being a property somebody
// has to keep verifying by reading, and becomes one the compiler cannot express
// a violation of.
//
// That is worth more here than anywhere else in the package. The shim sits on
// the `/mcp` path and sees every request to an RCE surface. A guard that says
// "we checked, and it only transforms" ages badly; a guard that says "it holds
// no reference capable of originating anything" does not.

// shimFile is the file this guard governs. Named explicitly rather than
// pattern-matched: if the shim is ever split across more files, adding them here
// is the deliberate act of extending the guarantee to them.
const shimFile = "taskshim.go"

// forbiddenShimImports are packages the shim must not reach.
var forbiddenShimImports = map[string]string{
	"github.com/modelcontextprotocol/go-sdk/mcp": "the MCP SDK. The shim TRANSFORMS a response the SDK produced; " +
		"it must never be able to originate one. Without this import it cannot register a tool, add a custom " +
		"method, or construct a result — the property is structural rather than reviewed",
	"github.com/Felag-Engineering/relay/relay/internal/capability": "the capability layer. " +
		"The shim rewrites JSON; it does not dispatch, decide, or resolve anything",
	"github.com/Felag-Engineering/relay/relay/internal/registry": "the Node registry. " +
		"The shim has no business knowing a Node exists",
	"database/sql": "the store. A response transformer that reached a database would be a second read path",
	"os":           "the filesystem. Nothing on the request path needs it, and on this file it would be a finding",
	"os/exec":      "process execution, on the surface whose entire purpose is gating process execution",
	"net":          "the network. The shim answers the request in front of it and calls nobody",
}

func TestTaskShimCannotOriginateAResult(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(thisFile), shimFile)

	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parser.ParseFile(%s): %v — the shim guard must be pointed at a file that exists; "+
			"if the shim moved, move this guard with it rather than deleting it", path, err)
	}

	for _, imp := range file.Imports {
		importPath, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			t.Fatalf("unquote import %s: %v", imp.Path.Value, err)
		}
		if why, bad := forbiddenShimImports[importPath]; bad {
			t.Errorf("%s imports %q — %s", shimFile, importPath, why)
		}
	}
}

// TestTaskShimGuardActuallyFires guards this guard, for the same reason
// no_decision_test.go guards its own: a structural test nobody has seen fail
// could be scanning nothing at all.
func TestTaskShimGuardActuallyFires(t *testing.T) {
	src := `package planted

import (
	"encoding/json"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

var _ = json.Marshal
var _ = sdkmcp.NewServer
`
	file, err := parser.ParseFile(token.NewFileSet(), "planted.go", src, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse planted source: %v", err)
	}

	var caught bool
	for _, imp := range file.Imports {
		importPath, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		if _, bad := forbiddenShimImports[importPath]; bad {
			caught = true
		}
	}
	if !caught {
		t.Error("the shim guard did not catch a planted MCP SDK import")
	}
}
