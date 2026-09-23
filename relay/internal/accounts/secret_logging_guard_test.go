package accounts

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// secret_logging_guard_test.go is a cross-package structural guard (#674)
// closing a gap the per-site redaction tests (password_test.go, tokens_test.go,
// session_test.go, enroll/token_test.go, console/accounts_write_test.go) leave
// open: none of them is an AST guard that a new secret-bearing type declares
// its redaction, or that no call site unwraps a secret directly into a log
// call. It lives here, in package accounts, because the three primary secret
// types (Password, PasswordHash, Plaintext) are already here and
// tokens_test.go already walks the module root from this directory
// (TestPlaintext_RevealCallSitesAreEnumerated). protoconv/ingress_guard_test.go
// is the precedent for a cross-package guard living in one package. It shares
// no code with no_dispatch_test.go beyond localImportAlias, which is copied
// (not imported — it is test-local in package api).
//
// Two halves, because either alone leaves a leak shape open:
//   - TestSecretTypesDeclareRedaction proves the redaction EXISTS: every
//     secret-bearing type — discovered by shape (a Reveal/Encoded wrapper, or
//     a struct with a SecretHash field) or named in explicitSecretTypes —
//     declares LogValue, and a Reveal/Encoded wrapper additionally declares
//     value-receiver LogValue, String and GoString.
//   - TestNoSecretUnwrappedIntoLogCall proves nobody BYPASSES that redaction
//     by unwrapping at the log call site: no Reveal()/Encoded() call or
//     .SecretHash selector appears inside the arguments of a slog call or a
//     logger-method call (Debug/Info/Warn/Error and their *Context, Log,
//     LogAttrs, With, WithGroup forms), by name rather than by type.
//
// It CATCHES: any Reveal(), Encoded() or .SecretHash written directly into a
// slog call or a logger-method call; any secret type — including a new
// Reveal-bearing or SecretHash-bearing type anywhere in the module — that
// lacks its redaction methods.
//
// It CANNOT catch:
//   - an unwrapped secret bound to a variable first
//     (s := p.Reveal(); slog.Info(.., s));
//   - a secret formatted into an error or string
//     (fmt.Errorf("%s", p.Reveal())) that is logged later, or passed
//     directly to fmt.Fprintf/fmt.Printf or the stdlib log package
//     (log.Printf("%s", p.Reveal())) — neither is a slog call or a
//     logger-method call by name, so logCallViolations does not inspect it;
//   - a slog.Attr{Value: ..} composite built outside the call;
//   - a new secret held as a bare string with no wrapper type, such as the
//     enrollment-token plaintext returned by enroll.Service.Create
//     (enroll/token.go);
//   - a dereferenced pointer-receiver type (slog.Any("t", *tok)) — a known
//     residual: enroll.Token and accounts.APIToken implement LogValue on a
//     POINTER receiver, so a dereferenced value passed to slog would not be a
//     slog.LogValuer and slog would reflect the struct, SecretHash included.
//     The call-site half cannot see this without type information; changing
//     those receivers is a production change outside this guard-only issue;
//   - a CONTAINER struct holding a secret and logged whole (slog.Any("req",
//     req)). With a text handler, a wrapper's String/GoString redact an
//     exported field formatted through fmt; an unexported field, or a JSON
//     handler marshalling the container, is not proven by this guard — the
//     per-site tests are the evidence there;
//   - a plain field on an EXPLICIT secret type (one in explicitSecretTypes,
//     discovered by neither a Reveal/Encoded wrapper nor a SecretHash field)
//     logged directly, such as slog.String("token", mintedView.Token):
//     TestSecretTypesDeclareRedaction proves the type declares LogValue, but
//     the call-site half only matches .Reveal()/.Encoded()/.SecretHash, none
//     of which a plain string field is;
//   - a non-slog sink reached through a method name outside logCallNames — an
//     Infof/Printf-style wrapper, or an audit-record detail-recording method
//     — is not inspected at all: the call-site half matches by name, and
//     these names are not on the list.
//
// The logger-method match is by NAME, not by type: a non-logger method
// called Error/Info/With — or http.Error(w, msg, code), or a gRPC
// status.Error(codes.X, msg) — that receives a Reveal() argument would fire.
// That is a loud false positive, never a silent miss, and none exist today.

// typeKey identifies a Go named type by its module-relative package
// directory (forward-slash, e.g. "internal/accounts") and its name.
type typeKey struct {
	dir  string
	name string
}

// explicitSecretTypes lists secret-bearing types discovery cannot find by
// shape — no Reveal/Encoded method, no SecretHash field — each with the
// reason it still carries a secret.
var explicitSecretTypes = map[typeKey]string{
	{"internal/controlplane/console", "mintedView"}: "the one view whose plain " +
		"string field holds a revealed plaintext (console/accounts_write.go); " +
		"discovery cannot find it by shape",
}

// knownSecretTypes is TestSecretTypesDeclareRedaction's presence FLOOR: the 8
// secret types known today. It does not narrow what the test checks — every
// discovered (and explicit) type must satisfy its redaction requirements
// regardless of whether it is listed here. Each of these 8 must additionally
// be FOUND, so a rename that would otherwise silently drop a type from
// discovery (Password.Reveal renamed to Unwrap, say) fails this test loudly
// instead of shrinking what it checks.
var knownSecretTypes = []typeKey{
	{"internal/accounts", "Password"},
	{"internal/accounts", "PasswordHash"},
	{"internal/accounts", "Plaintext"},
	{"internal/accounts", "APIToken"},
	{"internal/consoleauth", "SessionID"},
	{"internal/consoleauth", "CSRFToken"},
	{"internal/enroll", "Token"},
	{"internal/controlplane/console", "mintedView"},
}

// methodInfo records whether a named method is declared on a type, and
// whether its receiver is a value (as opposed to a pointer).
type methodInfo struct {
	present       bool
	valueReceiver bool
}

// secretType is what secretTypes discovers or is told about a single type.
type secretType struct {
	key            typeKey
	wrapper        bool // Reveal or Encoded is declared — the single way out
	logValue       methodInfo
	stringM        methodInfo
	goStringM      methodInfo
	explicitReason string // non-empty for an explicitSecretTypes entry
}

// satisfiesRedaction reports whether st declares everything its shape
// requires: every secret type needs LogValue; a Reveal/Encoded WRAPPER
// additionally needs LogValue, String and GoString all on VALUE receivers, so
// both T and *T redact under slog and under every fmt verb. A struct
// discovered by its SecretHash field needs only LogValue, on either receiver
// (the enroll.Token / accounts.APIToken precedent — see the guard's "cannot
// catch" list for the residual that leaves open).
func (st *secretType) satisfiesRedaction() (bool, string) {
	if !st.logValue.present {
		return false, "missing LogValue"
	}
	if !st.wrapper {
		return true, ""
	}
	if !st.logValue.valueReceiver {
		return false, "LogValue has a pointer receiver, not a value receiver"
	}
	if !st.stringM.present || !st.stringM.valueReceiver {
		return false, "String is missing or declared on a pointer receiver"
	}
	if !st.goStringM.present || !st.goStringM.valueReceiver {
		return false, "GoString is missing or declared on a pointer receiver"
	}
	return true, ""
}

// dirInfo accumulates everything secretTypes needs about one package
// directory, merged across every file in it — a type and the methods on it
// can live in different files of the same package.
type dirInfo struct {
	declaredTypes map[string]bool
	structFields  map[string]map[string]bool
	methods       map[string]map[string]methodInfo
}

func newDirInfo() *dirInfo {
	return &dirInfo{
		declaredTypes: map[string]bool{},
		structFields:  map[string]map[string]bool{},
		methods:       map[string]map[string]methodInfo{},
	}
}

// recvTypeAndPointer extracts the receiver's type name and whether it is a
// pointer receiver, unwrapping *ast.StarExpr. ok is false for a receiver this
// cannot classify (should not occur for valid Go).
func recvTypeAndPointer(recv *ast.FieldList) (name string, pointer bool, ok bool) {
	if recv == nil || len(recv.List) == 0 {
		return "", false, false
	}
	expr := recv.List[0].Type
	if star, isStar := expr.(*ast.StarExpr); isStar {
		expr = star.X
		pointer = true
	}
	id, isIdent := expr.(*ast.Ident)
	if !isIdent {
		return "", false, false
	}
	return id.Name, pointer, true
}

// parsedFile is one non-test .go file, already parsed, with its module-
// relative package directory recorded.
type parsedFile struct {
	dir  string // module-relative package dir, forward-slash
	rel  string // module-relative file path, forward-slash
	file *ast.File
}

// secretTypes discovers every secret-bearing type across files: a named type
// is SECRET if it declares Reveal or Encoded (a WRAPPER — the repo's
// documented single way out of the type), if it is a struct with a field
// named SecretHash, or if it is listed in explicitSecretTypes.
func secretTypes(files []parsedFile) map[typeKey]*secretType {
	dirs := map[string]*dirInfo{}
	dirFor := func(dir string) *dirInfo {
		di, ok := dirs[dir]
		if !ok {
			di = newDirInfo()
			dirs[dir] = di
		}
		return di
	}

	trackedMethods := map[string]bool{"Reveal": true, "Encoded": true, "LogValue": true, "String": true, "GoString": true}

	for _, pf := range files {
		di := dirFor(pf.dir)
		for _, decl := range pf.file.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				if d.Tok != token.TYPE {
					continue
				}
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok {
						continue
					}
					di.declaredTypes[ts.Name.Name] = true
					st, ok := ts.Type.(*ast.StructType)
					if !ok || st.Fields == nil {
						continue
					}
					fields := di.structFields[ts.Name.Name]
					if fields == nil {
						fields = map[string]bool{}
						di.structFields[ts.Name.Name] = fields
					}
					for _, f := range st.Fields.List {
						for _, n := range f.Names {
							fields[n.Name] = true
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv == nil || !trackedMethods[d.Name.Name] {
					continue
				}
				name, pointer, ok := recvTypeAndPointer(d.Recv)
				if !ok {
					continue
				}
				m := di.methods[name]
				if m == nil {
					m = map[string]methodInfo{}
					di.methods[name] = m
				}
				m[d.Name.Name] = methodInfo{present: true, valueReceiver: !pointer}
			}
		}
	}

	result := map[typeKey]*secretType{}
	for dir, di := range dirs {
		for name := range di.declaredTypes {
			m := di.methods[name]
			hasReveal := m["Reveal"].present
			hasEncoded := m["Encoded"].present
			hasSecretHash := di.structFields[name]["SecretHash"]
			if !hasReveal && !hasEncoded && !hasSecretHash {
				continue
			}
			key := typeKey{dir: dir, name: name}
			result[key] = &secretType{
				key:       key,
				wrapper:   hasReveal || hasEncoded,
				logValue:  m["LogValue"],
				stringM:   m["String"],
				goStringM: m["GoString"],
			}
		}
	}

	for key, reason := range explicitSecretTypes {
		if _, ok := result[key]; ok {
			continue
		}
		var m map[string]methodInfo
		if di, ok := dirs[key.dir]; ok {
			m = di.methods[key.name]
		}
		result[key] = &secretType{
			key:            key,
			wrapper:        false,
			logValue:       m["LogValue"],
			stringM:        m["String"],
			goStringM:      m["GoString"],
			explicitReason: reason,
		}
	}

	return result
}

// localImportAlias resolves the local identifier file uses for importPath,
// copied from api/no_dispatch_test.go (it is test-local there, not exported).
// See that file's doc comment for why resolving by import PATH rather than an
// assumed package name matters.
func localImportAlias(file *ast.File, importPath string) (alias string, ok bool) {
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != importPath {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name, true
		}
		return path[strings.LastIndex(path, "/")+1:], true
	}
	return "", false
}

// importNames is the set of every local identifier file's imports bind to
// (alias, or the default last path segment). Used to recognize a package-
// qualified call (http.Error, status.Error) so it is excluded from the
// non-vacuity count without needing type information.
func importNames(file *ast.File) map[string]bool {
	names := map[string]bool{}
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		if imp.Name != nil {
			if imp.Name.Name != "_" && imp.Name.Name != "." {
				names[imp.Name.Name] = true
			}
			continue
		}
		names[path[strings.LastIndex(path, "/")+1:]] = true
	}
	return names
}

// logCallNames are the slog level functions, their *Context forms, Log,
// LogAttrs, and the chaining methods With/WithGroup — every one of these, on
// ANY receiver, is treated as a log call for VIOLATION scanning: a secret
// unwrapped into a With(...) argument is exactly as real a leak as one
// unwrapped into an Info(...) argument once that logger is used.
var logCallNames = map[string]bool{
	"Debug": true, "Info": true, "Warn": true, "Error": true,
	"DebugContext": true, "InfoContext": true, "WarnContext": true, "ErrorContext": true,
	"Log": true, "LogAttrs": true, "With": true, "WithGroup": true,
}

// levelNames is the narrower set counted toward the non-vacuity floor: the
// functions that actually EMIT a record. With/WithGroup return a derived
// logger rather than emitting, so they are excluded here (they still
// participate in violation scanning above).
var levelNames = map[string]bool{
	"Debug": true, "Info": true, "Warn": true, "Error": true,
	"DebugContext": true, "InfoContext": true, "WarnContext": true, "ErrorContext": true,
	"Log": true, "LogAttrs": true,
}

// logCallStats are logCallViolations' non-vacuity counters (review item 5):
// slogFuncCalls counts calls on the slog package alias itself;
// loggerMethodCalls counts every other counted receiver (a *slog.Logger
// value, an embedded field, With's return value, ...). Split in two because a
// guard whose only evidence is slogFuncCalls would not prove the
// logger-method half of the rule is exercised at all.
type logCallStats struct {
	slogFuncCalls     int
	loggerMethodCalls int
}

// exprString renders an expression well enough for a violation message. It is
// not a formatter: it exists so a message can say "p.Reveal() inside the
// arguments of slog.Info" rather than only a line number.
func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return exprString(v.Fun) + "(...)"
	case *ast.StarExpr:
		return "*" + exprString(v.X)
	default:
		return "?"
	}
}

// isIdentNamed reports whether e is a bare identifier equal to name.
func isIdentNamed(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

// logCallViolations AST-inspects file and returns one message per Reveal(),
// Encoded() or .SecretHash written directly into the arguments of a log call,
// plus the non-vacuity counters described on logCallStats.
func logCallViolations(fset *token.FileSet, fileName string, file *ast.File) ([]string, logCallStats) {
	var violations []string
	var stats logCallStats

	slogAlias, slogImported := localImportAlias(file, "log/slog")
	imports := importNames(file)

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		isSlogCall := slogImported && isIdentNamed(sel.X, slogAlias)
		if isSlogCall || logCallNames[sel.Sel.Name] {
			for _, arg := range call.Args {
				ast.Inspect(arg, func(m ast.Node) bool {
					switch v := m.(type) {
					case *ast.CallExpr:
						s, ok := v.Fun.(*ast.SelectorExpr)
						if !ok || (s.Sel.Name != "Reveal" && s.Sel.Name != "Encoded") {
							return true
						}
						violations = append(violations, fmt.Sprintf(
							"%s:%d: %s.%s() inside the arguments of %s -- a secret unwrapped "+
								"into a log call bypasses its LogValue redaction",
							fileName, fset.Position(v.Pos()).Line, exprString(s.X), s.Sel.Name, exprString(call.Fun)))
					case *ast.SelectorExpr:
						if v.Sel.Name != "SecretHash" {
							return true
						}
						violations = append(violations, fmt.Sprintf(
							"%s:%d: %s.SecretHash inside the arguments of %s -- a secret unwrapped "+
								"into a log call bypasses its LogValue redaction",
							fileName, fset.Position(v.Pos()).Line, exprString(v.X), exprString(call.Fun)))
					}
					return true
				})
			}
		}

		if levelNames[sel.Sel.Name] && len(call.Args) >= 1 {
			switch {
			case isSlogCall:
				stats.slogFuncCalls++
			case isIdentIn(sel.X, imports):
				// A package-level call to something else named Error/Info/...
				// (http.Error, status.Error): a documented loud false
				// positive for violation-scanning, but not evidence this
				// guard is watching a real logger, so it is excluded here.
			default:
				stats.loggerMethodCalls++
			}
		}

		return true
	})

	return violations, stats
}

// isIdentIn reports whether e is a bare identifier present in names.
func isIdentIn(e ast.Expr, names map[string]bool) bool {
	id, ok := e.(*ast.Ident)
	return ok && names[id.Name]
}

// moduleRoot returns relay/, the Go module root, from this test file's own
// location (mirrors tokens_test.go).
func moduleRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// thisFile is relay/internal/accounts/secret_logging_guard_test.go.
	return filepath.Join(filepath.Dir(thisFile), "..", "..")
}

// walkProductionGoFiles parses every non-test .go file under root, skipping
// testdata and vendor directories.
func walkProductionGoFiles(t *testing.T, root string, fset *token.FileSet) []parsedFile {
	t.Helper()
	var out []parsedFile
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
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		out = append(out, parsedFile{
			dir:  filepath.ToSlash(filepath.Dir(rel)),
			rel:  rel,
			file: file,
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// TestSecretTypesDeclareRedaction is the type half: every secret type this
// guard knows about must declare LogValue, and a Reveal/Encoded wrapper must
// additionally declare value-receiver LogValue, String and GoString.
func TestSecretTypesDeclareRedaction(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	files := walkProductionGoFiles(t, root, fset)
	if len(files) == 0 {
		t.Fatal("walked 0 non-test .go files — the guard must actually inspect something")
	}

	discovered := secretTypes(files)
	if len(discovered) == 0 {
		t.Fatal("discovered 0 secret types — the guard must actually inspect something")
	}

	// Every discovered (and explicit) secret type must satisfy its redaction
	// requirements — not only the ones knownSecretTypes happens to name.
	// Checking only knownSecretTypes would leave a NEW Reveal/Encoded/
	// SecretHash-bearing type free to skip LogValue: it would be discovered,
	// but nothing would ever call satisfiesRedaction on it.
	for key, st := range discovered {
		if ok, reason := st.satisfiesRedaction(); !ok {
			t.Errorf("%s.%s does not satisfy its redaction requirements: %s", key.dir, key.name, reason)
		}
	}

	// knownSecretTypes is a presence FLOOR, not the set of types checked
	// above: each must still be found, so a rename that would otherwise
	// silently drop a type from discovery (Password.Reveal renamed to
	// Unwrap, say) fails loudly instead of shrinking what the loop above
	// inspects.
	for _, key := range knownSecretTypes {
		if _, ok := discovered[key]; !ok {
			t.Errorf("%s.%s was not discovered as a secret type — a rename of Reveal/Encoded/"+
				"SecretHash, or a dropped explicitSecretTypes entry, would silently stop this "+
				"guard from watching it", key.dir, key.name)
		}
	}
}

// TestNoSecretUnwrappedIntoLogCall is the call-site half: no Reveal(),
// Encoded() or .SecretHash may appear inside the arguments of a log call
// anywhere in the module.
func TestNoSecretUnwrappedIntoLogCall(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	files := walkProductionGoFiles(t, root, fset)

	var total logCallStats
	filesWithSlog := 0
	for _, pf := range files {
		if _, ok := localImportAlias(pf.file, "log/slog"); ok {
			filesWithSlog++
		}
		violations, stats := logCallViolations(fset, pf.rel, pf.file)
		total.slogFuncCalls += stats.slogFuncCalls
		total.loggerMethodCalls += stats.loggerMethodCalls
		for _, v := range violations {
			t.Error(v)
		}
	}

	if filesWithSlog == 0 {
		t.Fatal("no file imports log/slog — the guard must actually inspect something")
	}
	// Floors are about half the counts observed against this tree when the
	// guard was written (81 slog.<Level>(...) call sites, 20 non-slog
	// logger-method call sites once http.Error and status.Error are
	// excluded), so a rename or a refactor that dodged the vast majority of
	// real call sites still fails loudly rather than sliding under a floor
	// tuned to the exact count.
	if total.slogFuncCalls < 40 {
		t.Errorf("only %d slog.<Level>(...) call sites found across the module; want >= 40 — "+
			"this guard's non-vacuity floor exists so a change that stops it from seeing real "+
			"call sites fails loudly", total.slogFuncCalls)
	}
	if total.loggerMethodCalls < 10 {
		t.Errorf("only %d non-slog logger-method call sites found across the module; want >= 10",
			total.loggerMethodCalls)
	}
}

// parseFixture parses src as a standalone Go file for a table test.
func parseFixture(t *testing.T, src string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture.go", src, 0)
	if err != nil {
		t.Fatalf("parser.ParseFile: %v\n%s", err, src)
	}
	return fset, file
}

// TestSecretLoggingGuard_Fixtures runs logCallViolations and secretTypes
// against synthetic sources, laid out like TestDispatchViolations_Fixtures:
// proving each rule fires, that the allowed shapes in the code today do not,
// and pinning the non-vacuity counters' exclusions (review item 5).
func TestSecretLoggingGuard_Fixtures(t *testing.T) {
	t.Run("must fire", func(t *testing.T) {
		cases := []struct {
			name string
			src  string
		}{
			{
				name: "slog.Info with Reveal()",
				src: `package fixture
import "log/slog"
func f(p interface{ Reveal() string }) {
	slog.Info("x", "pw", p.Reveal())
}
`,
			},
			{
				name: "aliased slog import with Reveal()",
				src: `package fixture
import l "log/slog"
func f(p interface{ Reveal() string }) {
	l.Warn("x", "pw", p.Reveal())
}
`,
			},
			{
				name: "nested slog.Group/slog.String with Reveal()",
				src: `package fixture
import "log/slog"
func f(p interface{ Reveal() string }) {
	slog.Info("x", slog.Group("g", slog.String("pw", p.Reveal())))
}
`,
			},
			{
				name: "logger.InfoContext with Encoded()",
				src: `package fixture
func f(ctx interface{}, logger interface {
	InfoContext(ctx interface{}, msg string, args ...interface{})
}, h interface{ Encoded() string }) {
	logger.InfoContext(ctx, "x", "h", h.Encoded())
}
`,
			},
			{
				name: "d.Log.With with SecretHash",
				src: `package fixture
func f(d struct {
	Log interface{ With(args ...interface{}) interface{} }
}, t struct{ SecretHash []byte }) {
	d.Log.With("tok", t.SecretHash)
}
`,
			},
			{
				name: "slog.Default().Error with Reveal()",
				src: `package fixture
import "log/slog"
func f(s interface{ Reveal() string }) {
	slog.Default().Error("x", "sid", s.Reveal())
}
`,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				fset, file := parseFixture(t, tc.src)
				violations, _ := logCallViolations(fset, "fixture.go", file)
				if len(violations) == 0 {
					t.Fatalf("logCallViolations() found nothing, want at least one violation")
				}
			})
		}
	})

	t.Run("must not fire", func(t *testing.T) {
		cases := []struct {
			name string
			src  string
		}{
			{
				name: "slog.Any redacted by LogValue",
				src: `package fixture
import "log/slog"
func f(p interface{}) {
	slog.Any("password", p)
}
`,
			},
			{
				name: "plain token variable",
				src: `package fixture
func f(logger interface{ Info(args ...interface{}) }, tok string) {
	logger.Info("minted", "token", tok)
}
`,
			},
			{
				name: "Reveal() outside any log call (writeJSON)",
				src: `package fixture
func writeJSON(w interface{}, status int, v interface{}) {}
func f(w interface{}, p interface{ Reveal() string }) {
	writeJSON(w, 201, struct{ Token string }{Token: p.Reveal()})
}
`,
			},
			{
				name: "Reveal() outside any log call (renderScreen)",
				src: `package fixture
func renderScreen(w, pg, tmpl, view interface{}) {}
func f(w, pg, tmpl interface{}, p interface{ Reveal() string }) {
	renderScreen(w, pg, tmpl, struct{ Token string }{Token: p.Reveal()})
}
`,
			},
			{
				name: "Reveal() outside any log call (http.SetCookie)",
				src: `package fixture
import "net/http"
func f(w http.ResponseWriter, id interface{ Reveal() string }) {
	http.SetCookie(w, &http.Cookie{Value: id.Reveal()})
}
`,
			},
			{
				name: "SecretHash outside any log call (db exec)",
				src: `package fixture
func f(db interface {
	ExecContext(ctx, q interface{}, args ...interface{}) error
}, ctx interface{}, q interface{}, t struct {
	ID         string
	SecretHash []byte
}) {
	db.ExecContext(ctx, q, t.ID, t.SecretHash)
}
`,
			},
			{
				name: "err.Error() has no arguments to inspect",
				src: `package fixture
func f(err error) string {
	return err.Error()
}
`,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				fset, file := parseFixture(t, tc.src)
				violations, _ := logCallViolations(fset, "fixture.go", file)
				if len(violations) != 0 {
					t.Fatalf("logCallViolations() = %v, want none", violations)
				}
			})
		}
	})

	t.Run("type shapes", func(t *testing.T) {
		const src = `package fixture

type A struct{ secret string }

func (a A) Reveal() string { return a.secret }

type B struct{ secret string }

func (b B) Reveal() string { return b.secret }
func (b *B) LogValue() slog.Value { return slog.Value{} }

type C struct{ secret string }

func (c C) Reveal() string { return c.secret }
func (c C) LogValue() slog.Value { return slog.Value{} }

type D struct{ secret string }

func (d D) Reveal() string { return d.secret }
func (d D) LogValue() slog.Value { return slog.Value{} }
func (d D) String() string { return "x" }
func (d *D) GoString() string { return "x" }

type E struct{ SecretHash []byte }
`
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "fixture.go", src, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile: %v", err)
		}
		discovered := secretTypes([]parsedFile{{dir: "fixture", rel: "fixture.go", file: file}})

		cases := []struct {
			name       string
			wantReason string
		}{
			{"A", "missing LogValue"},
			{"B", "LogValue has a pointer receiver, not a value receiver"},
			{"C", "String is missing or declared on a pointer receiver"},
			{"D", "GoString is missing or declared on a pointer receiver"},
			{"E", "missing LogValue"},
		}
		for _, tc := range cases {
			st, ok := discovered[typeKey{dir: "fixture", name: tc.name}]
			if !ok {
				t.Fatalf("type %s was not discovered as a secret type", tc.name)
			}
			ok, reason := st.satisfiesRedaction()
			if ok {
				t.Fatalf("type %s: satisfiesRedaction() = true, want false (%s)", tc.name, tc.wantReason)
			}
			if reason != tc.wantReason {
				t.Fatalf("type %s: satisfiesRedaction() reason = %q, want %q", tc.name, reason, tc.wantReason)
			}
		}
	})

	t.Run("counter fixture", func(t *testing.T) {
		const src = `package fixture

import (
	"log/slog"
	"net/http"
)

func f(logger interface{ Warn(args ...interface{}) }, err error, w http.ResponseWriter) {
	slog.Info("a")
	logger.Warn("b")
	_ = err.Error()
	http.Error(w, "m", 500)
	_ = slog.String("k", "v")
}
`
		fset, file := parseFixture(t, src)
		_, stats := logCallViolations(fset, "fixture.go", file)
		if stats.slogFuncCalls != 1 {
			t.Errorf("slogFuncCalls = %d, want 1 (only slog.Info(\"a\"))", stats.slogFuncCalls)
		}
		if stats.loggerMethodCalls != 1 {
			t.Errorf("loggerMethodCalls = %d, want 1 (only logger.Warn(\"b\"))", stats.loggerMethodCalls)
		}
	})
}
