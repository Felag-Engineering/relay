//go:build apiclient

package apiclient

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// conformance_test.go makes this package's contract check ACTIVE rather than
// merely "it compiled".
//
// Compilation alone proves the generated code is well-formed Go. It does not
// prove the generator produced a method for every operation the spec declares —
// a spec change that silently generated nothing (an operation the generator
// skipped, a name collision resolved by dropping one side) would still compile.
// This asserts the mapping is total: every operationId in the published spec
// has a corresponding client method.
//
// It sits behind the `apiclient` build tag because the code it tests is
// generated on demand and not committed (see doc.go). `make apiclient-check`
// generates the client and runs this with the tag set; the ordinary
// `go test ./...` skips it rather than failing on absent generated code.

func specPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// .../relay/internal/apiclient/conformance_test.go -> repo root
	root := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	return filepath.Join(root, "docs", "api", "openapi.yaml")
}

func specOperationIDs(t *testing.T) []string {
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
	var ids []string
	for _, item := range doc.Paths.Map() {
		for _, op := range item.Operations() {
			if op.OperationID != "" {
				ids = append(ids, op.OperationID)
			}
		}
	}
	sort.Strings(ids)
	return ids
}

// clientMethods returns the exported method names on *Client.
func clientMethods() map[string]bool {
	out := map[string]bool{}
	typ := reflect.TypeOf(&Client{})
	for i := 0; i < typ.NumMethod(); i++ {
		out[typ.Method(i).Name] = true
	}
	return out
}

// TestClientCoversEverySpecOperation is the total-mapping assertion: for each
// operationId the spec declares, the generated client exposes a method.
//
// The generator capitalizes the operationId (runOperation -> RunOperation) and
// adds a WithBody variant for operations with a request body; matching the
// capitalized name is therefore the check, and a body-carrying operation
// satisfies it through either form.
func TestClientCoversEverySpecOperation(t *testing.T) {
	methods := clientMethods()
	if len(methods) == 0 {
		t.Fatal("*Client exposes no methods — the generated client is empty")
	}

	ids := specOperationIDs(t)
	if len(ids) == 0 {
		t.Fatal("spec declares no operationIds")
	}

	for _, id := range ids {
		name := strings.ToUpper(id[:1]) + id[1:]
		if methods[name] || methods[name+"WithBody"] {
			continue
		}
		t.Errorf("spec declares operationId %q but the generated client has no %s method — the client does not cover the published contract",
			id, name)
	}
}

// TestClientIsUsableAsAnHTTPClient pins the seam a real integration depends on:
// the client is constructible against a base URL, accepts an injected
// *http.Client, and accepts a request editor (which is how a caller attaches a
// bearer credential). A generator upgrade that changed any of these would be a
// breaking change for every consumer, so it is asserted rather than assumed.
func TestClientIsUsableAsAnHTTPClient(t *testing.T) {
	var editorCalled bool
	c, err := NewClient("https://relay.example:9443",
		WithHTTPClient(&http.Client{}),
		WithRequestEditorFn(func(_ context.Context, _ *http.Request) error {
			editorCalled = true
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c == nil {
		t.Fatal("NewClient returned nil")
	}
	_ = editorCalled // exercised on a real request; construction is what is pinned here
}
