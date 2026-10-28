package accounts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log/slog"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

var temporaryNow = time.Date(2026, 10, 28, 9, 30, 0, 0, time.FixedZone("x", 3600))

func TestGenerateTemporaryPassword_LengthRandomnessAndExpiry(t *testing.T) {
	a, err := GenerateTemporaryPassword(temporaryNow)
	if err != nil {
		t.Fatalf("GenerateTemporaryPassword: %v", err)
	}
	b, err := GenerateTemporaryPassword(temporaryNow)
	if err != nil {
		t.Fatalf("GenerateTemporaryPassword: %v", err)
	}

	if got := len(a.Password.Reveal()); got != 43 {
		t.Errorf("a temporary password is %d bytes, want 43 (32 random bytes, base64url, unpadded)", got)
	}
	if err := a.Password.Validate(); err != nil {
		t.Errorf("a generated temporary password fails the length bounds it will be hashed under: %v", err)
	}
	if a.Password.Reveal() == b.Password.Reveal() {
		t.Error("two generated temporary passwords are equal")
	}
	if want := temporaryNow.UTC().Add(TemporaryPasswordLifetime); !a.ExpiresAt.Equal(want) || a.ExpiresAt.Location() != time.UTC {
		t.Errorf("ExpiresAt = %v, want %v in UTC", a.ExpiresAt, want)
	}
	if TemporaryPasswordLifetime != 72*time.Hour {
		t.Errorf("the lifetime is %v, want 72h (ADR-0045 decision 3)", TemporaryPasswordLifetime)
	}

	h, err := HashPassword(a.Password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !h.Verify(a.Password) {
		t.Error("the hash does not verify the password it was derived from")
	}
}

func TestTemporaryPassword_NeverPrintsThePassword(t *testing.T) {
	tp, err := GenerateTemporaryPassword(temporaryNow)
	if err != nil {
		t.Fatal(err)
	}
	secret := tp.Password.Reveal()

	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("issued", "tp", tp, "ptr", &tp)
	asJSON, err := json.Marshal(tp)
	if err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{
		"slog":   logged.String(),
		"%v":     fmt.Sprintf("%v", tp),
		"%+v":    fmt.Sprintf("%+v", tp),
		"%#v":    fmt.Sprintf("%#v", tp),
		"%s":     fmt.Sprintf("<%s>", tp),
		"json":   string(asJSON),
		"%v ptr": fmt.Sprintf("%v", &tp),
	} {
		if strings.Contains(out, secret) {
			t.Errorf("%s output carries the temporary password: %s", name, out)
		}
	}
}

func TestStoredPassword_TemporaryStateAndRedaction(t *testing.T) {
	h, err := HashPassword(NewPassword("a perfectly fine password"))
	if err != nil {
		t.Fatal(err)
	}
	own := StoredPassword{Hash: h}
	if own.Temporary() || own.ExpiredAt(temporaryNow.Add(1000*time.Hour)) {
		t.Error("a password with no TemporaryUntil is temporary or expired")
	}

	until := temporaryNow.Add(time.Hour)
	temp := StoredPassword{Hash: h, TemporaryUntil: until}
	if !temp.Temporary() {
		t.Error("a password with a TemporaryUntil is not temporary")
	}
	for _, tc := range []struct {
		name string
		now  time.Time
		want bool
	}{
		{"before", until.Add(-time.Nanosecond), false},
		{"at the instant", until, true},
		{"after", until.Add(time.Nanosecond), true},
	} {
		if got := temp.ExpiredAt(tc.now); got != tc.want {
			t.Errorf("ExpiredAt(%s) = %v, want %v: refused at and after the instant", tc.name, got, tc.want)
		}
	}

	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("read", "stored", temp)
	if strings.Contains(logged.String(), h.Encoded()) || strings.Contains(logged.String(), "argon2id") {
		t.Errorf("a StoredPassword logs its hash: %s", logged.String())
	}
	if !strings.Contains(logged.String(), `"temporary":true`) {
		t.Errorf("a StoredPassword does not log whether it is temporary: %s", logged.String())
	}
}

// TestGenerateTemporaryPassword_CallSitesAreEnumerated: GenerateTemporaryPassword
// mints a live credential, so where it is called is a checked fact. The
// capability layer's temporary-password acts are the only callers; a new one is
// a reviewed decision, and a stale entry fails too.
func TestGenerateTemporaryPassword_CallSitesAreEnumerated(t *testing.T) {
	permitted := map[string]bool{
		"internal/capability/temporarypasswords.go": true,
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(thisFile), "..", "..")
	const accountsPath = "github.com/Felag-Engineering/relay/relay/internal/accounts"

	found := map[string]bool{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		inAccounts := f.Name.Name == "accounts" && filepath.Base(filepath.Dir(path)) == "accounts"
		var local string
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == accountsPath {
				local = "accounts"
				if imp.Name != nil {
					local = imp.Name.Name
				}
			}
		}
		hit := false
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && local != "" && id.Name == local && x.Sel.Name == "GenerateTemporaryPassword" {
					hit = true
				}
			case *ast.CallExpr:
				// Calls inside package accounts itself, bar the definition.
				if id, ok := x.Fun.(*ast.Ident); ok && inAccounts && id.Name == "GenerateTemporaryPassword" {
					hit = true
				}
			}
			return true
		})
		if hit {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			found[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	for f := range found {
		if !permitted[f] {
			t.Errorf("%s calls accounts.GenerateTemporaryPassword, which mints a live credential; "+
				"a new call site must be a deliberate, reviewed decision added to this list", f)
		}
	}
	for f := range permitted {
		if !found[f] {
			t.Errorf("%s is permitted to call accounts.GenerateTemporaryPassword but does not; remove the stale entry", f)
		}
	}
}
