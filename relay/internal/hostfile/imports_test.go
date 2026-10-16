package hostfile

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// The package that decides what may bound the security floor depends on nothing of the
// Relay's and stays free of cgo.
func TestHostfile_ImportsNoRelayInternal(t *testing.T) {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the package directory")
	}
	files, err := filepath.Glob(filepath.Join(filepath.Dir(self), "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no source files found: %v", err)
	}
	fset := token.NewFileSet()
	for _, file := range files {
		parsed, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range parsed.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if strings.HasPrefix(path, "github.com/Felag-Engineering/relay/relay/internal") || path == "C" {
				t.Errorf("%s imports %s", filepath.Base(file), path)
			}
		}
	}
}
