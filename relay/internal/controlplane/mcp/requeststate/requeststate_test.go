package requeststate

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Tests in this file swap the package's two hook seams (equalMAC,
// computeMAC) and restore them with t.Cleanup; none of them call t.Parallel,
// because a package-level var swap is not safe across concurrent subtests.

var (
	sampleRequestID = strings.Repeat("ab", 16)           // 32 hex chars, mirrors capability.defaultID
	sampleAccountID = "acct-" + strings.Repeat("cd", 16) // mirrors store.newAccountID
	samplePlanHash  = strings.Repeat("ef", 32)           // 64 hex chars, mirrors approval.HashPlan
	sampleTool      = "run_operation"
	sampleNow       = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	sampleExpiresAt = sampleNow.Add(time.Hour)
)

// sampleState returns a State built from realistic values, matching the
// shapes the MCP server's callers will actually pass.
func sampleState(t *testing.T) State {
	t.Helper()
	return State{
		AccountID:  sampleAccountID,
		RequestID:  sampleRequestID,
		PlanHash:   samplePlanHash,
		Tool:       sampleTool,
		ArgsDigest: mustDigest(t, []byte(`{"b":2,"a":1}`)),
		ExpiresAt:  sampleExpiresAt,
	}
}

func mustMint(t *testing.T) *Sealer {
	t.Helper()
	s, err := Mint()
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return s
}

// mustNewWithKnownKey mints a Sealer the same way Mint does, but — unlike
// Mint — also hands the test the raw key bytes it was built from. Sealer
// holds the key only inside a closure, so this is the one way a test can
// still get at the key it needs to check redaction against.
func mustNewWithKnownKey(t *testing.T) ([]byte, *Sealer) {
	t.Helper()
	key, err := NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	s, err := New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return key, s
}

func mustDigest(t *testing.T, raw []byte) Digest {
	t.Helper()
	d, err := DigestArgs(raw)
	if err != nil {
		t.Fatalf("DigestArgs(%q): %v", raw, err)
	}
	return d
}

func TestSeal_OpenRoundTripsEveryField(t *testing.T) {
	sealer := mustMint(t)
	st := sampleState(t)
	openNow := sampleNow.Add(30 * time.Minute)

	sealed, err := sealer.Seal(st)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	opened, err := sealer.Open(sealed, openNow)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if opened.AccountID != st.AccountID {
		t.Errorf("AccountID = %q, want %q", opened.AccountID, st.AccountID)
	}
	if opened.RequestID != st.RequestID {
		t.Errorf("RequestID = %q, want %q", opened.RequestID, st.RequestID)
	}
	if opened.PlanHash != st.PlanHash {
		t.Errorf("PlanHash = %q, want %q", opened.PlanHash, st.PlanHash)
	}
	if opened.Tool != st.Tool {
		t.Errorf("Tool = %q, want %q", opened.Tool, st.Tool)
	}
	if opened.ArgsDigest != st.ArgsDigest {
		t.Errorf("ArgsDigest = %x, want %x", opened.ArgsDigest, st.ArgsDigest)
	}
	if !opened.ExpiresAt.Equal(st.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", opened.ExpiresAt, st.ExpiresAt)
	}

	t.Run("non-UTC expiry round-trips", func(t *testing.T) {
		loc := time.FixedZone("test", 3*60*60)
		st2 := sampleState(t)
		st2.ExpiresAt = st2.ExpiresAt.In(loc)

		sealed2, err := sealer.Seal(st2)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		opened2, err := sealer.Open(sealed2, openNow)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !opened2.ExpiresAt.Equal(st2.ExpiresAt) {
			t.Errorf("ExpiresAt = %v, want %v", opened2.ExpiresAt, st2.ExpiresAt)
		}
	})

	t.Run("full field alphabet round-trips", func(t *testing.T) {
		var alphabet []byte
		for b := 0x21; b <= 0x7E; b++ {
			if fieldByteOK(byte(b)) {
				alphabet = append(alphabet, byte(b))
			}
		}
		st3 := sampleState(t)
		st3.Tool = string(alphabet)

		sealed3, err := sealer.Seal(st3)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		opened3, err := sealer.Open(sealed3, openNow)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if opened3.Tool != st3.Tool {
			t.Errorf("Tool round-trip mismatch: got %q, want %q", opened3.Tool, st3.Tool)
		}
	})
}

// decodeSealed strips the version prefix and base64-decodes the remainder,
// for tests that need to mutate the raw body/mac bytes directly.
func decodeSealed(t *testing.T, sealed string) []byte {
	t.Helper()
	rest := strings.TrimPrefix(sealed, prefix)
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(rest)
	if err != nil {
		t.Fatalf("decode sealed state: %v", err)
	}
	return decoded
}

func encodeSealed(decoded []byte) string {
	return prefix + base64.RawURLEncoding.EncodeToString(decoded)
}

func TestOpen_RefusesTamperedState(t *testing.T) {
	sealer := mustMint(t)
	openNow := sampleNow.Add(30 * time.Minute)

	sealed, err := sealer.Seal(sampleState(t))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	decoded := decodeSealed(t, sealed)

	t.Run("bit flip in body or mac", func(t *testing.T) {
		for i := range decoded {
			tampered := append([]byte(nil), decoded...)
			tampered[i] ^= 0x01
			state := encodeSealed(tampered)
			if _, err := sealer.Open(state, openNow); !errors.Is(err, ErrTampered) {
				t.Errorf("byte %d: Open() err = %v, want ErrTampered", i, err)
			}
		}
	})

	t.Run("single-character substitution", func(t *testing.T) {
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		for i := 0; i < len(sealed); i++ {
			original := sealed[i]
			for j := 0; j < len(alphabet); j++ {
				replacement := alphabet[j]
				if replacement == original {
					continue
				}
				mutated := []byte(sealed)
				mutated[i] = replacement
				_, err := sealer.Open(string(mutated), openNow)
				if err == nil {
					t.Fatalf("index %d: Open() succeeded on a mutated state, want a refusal", i)
				}
				if !errors.Is(err, ErrUnknownVersion) && !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrTampered) {
					t.Fatalf("index %d: Open() err = %v, want one of ErrUnknownVersion, ErrMalformed, ErrTampered", i, err)
				}
			}
		}
	})

	t.Run("embedded CR/LF are rejected before decoding", func(t *testing.T) {
		// base64.Encoding's decoder silently skips CR and LF rather than
		// rejecting them, so without an explicit alphabet check
		// "rs1.AB\r\nCD..." would decode to the same bytes as the canonical
		// state — two different encoded strings opening to one State.
		rest := strings.TrimPrefix(sealed, prefix)
		if len(rest) < 4 {
			t.Fatalf("test construction: sealed state too short: %q", sealed)
		}
		withCRLF := prefix + rest[:2] + "\r\n" + rest[2:]
		if _, err := sealer.Open(withCRLF, openNow); !errors.Is(err, ErrMalformed) {
			t.Errorf("Open(with embedded CRLF) err = %v, want ErrMalformed", err)
		}

		withCR := prefix + rest[:2] + "\r" + rest[2:]
		if _, err := sealer.Open(withCR, openNow); !errors.Is(err, ErrMalformed) {
			t.Errorf("Open(with embedded CR) err = %v, want ErrMalformed", err)
		}

		withLF := prefix + rest[:2] + "\n" + rest[2:]
		if _, err := sealer.Open(withLF, openNow); !errors.Is(err, ErrMalformed) {
			t.Errorf("Open(with embedded LF) err = %v, want ErrMalformed", err)
		}
	})
}

func TestOpen_RefusesStateSealedUnderAnotherKey(t *testing.T) {
	a := mustMint(t)
	b := mustMint(t)

	sealed, err := a.Seal(sampleState(t))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	opened, err := b.Open(sealed, sampleNow.Add(30*time.Minute))
	if !errors.Is(err, ErrTampered) {
		t.Fatalf("Open() err = %v, want ErrTampered", err)
	}
	if opened != (State{}) {
		t.Errorf("Open() state = %+v, want the zero State", opened)
	}
}

func TestOpen_RefusesExpiredState(t *testing.T) {
	sealer := mustMint(t)
	st := sampleState(t)
	sealed, err := sealer.Seal(st)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	cases := []struct {
		name   string
		now    time.Time
		wantOK bool
	}{
		{"now equals expiry", st.ExpiresAt, false},
		{"now is 1ns after expiry", st.ExpiresAt.Add(time.Nanosecond), false},
		{"now is 1ns before expiry", st.ExpiresAt.Add(-time.Nanosecond), true},
		{"zero now", time.Time{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sealer.Open(sealed, tc.now)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("Open() err = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrExpired) {
				t.Fatalf("Open() err = %v, want ErrExpired", err)
			}
		})
	}
}

func TestOpen_RefusesUnknownVersion(t *testing.T) {
	sealer := mustMint(t)
	openNow := sampleNow.Add(30 * time.Minute)

	sealed, err := sealer.Seal(sampleState(t))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	rest := strings.TrimPrefix(sealed, prefix)

	cases := []struct {
		name  string
		state string
	}{
		{"empty string", ""},
		{"bare base64, no prefix", rest},
		{"future version prefix", "rs2." + rest},
		{"upper-cased prefix", "RS1." + rest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := sealer.Open(tc.state, openNow); !errors.Is(err, ErrUnknownVersion) {
				t.Fatalf("Open() err = %v, want ErrUnknownVersion", err)
			}
		})
	}

	t.Run("correctly maced payload with a future version", func(t *testing.T) {
		p := payload{
			V: currentVersion + 1,
			A: sampleAccountID,
			R: sampleRequestID,
			P: samplePlanHash,
			T: sampleTool,
			D: strings.Repeat("00", 32),
			E: sampleExpiresAt.UnixNano(),
		}
		body, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		mac := sealer.mac(append([]byte(macLabel+prefix), body...))
		encoded := append(append([]byte(nil), body...), mac...)
		state := encodeSealed(encoded)

		if _, err := sealer.Open(state, openNow); !errors.Is(err, ErrUnknownVersion) {
			t.Fatalf("Open() err = %v, want ErrUnknownVersion", err)
		}
	})
}

func TestOpen_RefusesOversizedState(t *testing.T) {
	sealer := mustMint(t)
	openNow := sampleNow.Add(30 * time.Minute)

	calls := 0
	orig := computeMAC
	computeMAC = func(key, msg []byte) []byte {
		calls++
		return orig(key, msg)
	}
	t.Cleanup(func() { computeMAC = orig })

	oversized := prefix + strings.Repeat("A", MaxEncodedBytes)
	if _, err := sealer.Open(oversized, openNow); !errors.Is(err, ErrOversized) {
		t.Fatalf("Open() err = %v, want ErrOversized", err)
	}
	if calls != 0 {
		t.Errorf("computeMAC called %d times, want 0 — the size bound must be checked before any mac work", calls)
	}

	boundary := prefix + strings.Repeat("A", MaxEncodedBytes-len(prefix))
	if len(boundary) != MaxEncodedBytes {
		t.Fatalf("test construction: len(boundary) = %d, want %d", len(boundary), MaxEncodedBytes)
	}
	if _, err := sealer.Open(boundary, openNow); errors.Is(err, ErrOversized) {
		t.Errorf("Open() at exactly MaxEncodedBytes returned ErrOversized, want any other outcome")
	}
}

func TestSeal_StaysUnderClientRequestStateLimit(t *testing.T) {
	// Gleipnir's requestState limit; see docs/specs/approval.md AP-65.
	const clientRequestStateLimit = 16 * 1024

	sealer := mustMint(t)
	maxField := strings.Repeat("a", MaxFieldBytes)
	st := State{
		AccountID:  maxField,
		RequestID:  maxField,
		PlanHash:   maxField,
		Tool:       maxField,
		ArgsDigest: mustDigest(t, []byte(`{"k":"v"}`)),
		ExpiresAt:  time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	sealed, err := sealer.Seal(st)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(sealed) > MaxEncodedBytes {
		t.Errorf("len(sealed) = %d, want <= %d", len(sealed), MaxEncodedBytes)
	}
	if len(sealed) > clientRequestStateLimit/4 {
		t.Errorf("len(sealed) = %d, want <= %d (a quarter of Gleipnir's requestState limit)",
			len(sealed), clientRequestStateLimit/4)
	}

	st.Tool = strings.Repeat("a", MaxFieldBytes+1)
	if _, err := sealer.Seal(st); !errors.Is(err, ErrInvalidField) {
		t.Errorf("Seal() err = %v, want ErrInvalidField", err)
	}
}

func TestOpen_ComparesMACInConstantTime(t *testing.T) {
	sealer := mustMint(t)
	openNow := sampleNow.Add(30 * time.Minute)

	sealed, err := sealer.Seal(sampleState(t))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	decoded := decodeSealed(t, sealed)
	tampered := append([]byte(nil), decoded...)
	tampered[len(tampered)-1] ^= 0x01 // flip a bit in the mac's last byte
	tamperedState := encodeSealed(tampered)

	calls := 0
	orig := equalMAC
	equalMAC = func(a, b []byte) bool {
		calls++
		return orig(a, b)
	}
	t.Cleanup(func() { equalMAC = orig })

	if _, err := sealer.Open(sealed, openNow); err != nil {
		t.Fatalf("Open(valid) err = %v", err)
	}
	if calls != 1 {
		t.Fatalf("Open(valid) called equalMAC %d times, want 1", calls)
	}

	calls = 0
	if _, err := sealer.Open(tamperedState, openNow); !errors.Is(err, ErrTampered) {
		t.Fatalf("Open(tampered) err = %v, want ErrTampered", err)
	}
	if calls != 1 {
		t.Fatalf("Open(tampered) called equalMAC %d times, want 1", calls)
	}
}

// isSuspectMACCompareOperand reports whether e is a string(...) conversion,
// a conversion to an array type, or a composite literal of an array type —
// each a way MAC bytes could be compared with == or != instead of through
// equalMAC.
func isSuspectMACCompareOperand(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.CallExpr:
		switch fn := v.Fun.(type) {
		case *ast.Ident:
			return fn.Name == "string"
		case *ast.ArrayType:
			return true
		}
	case *ast.CompositeLit:
		_, ok := v.Type.(*ast.ArrayType)
		return ok
	}
	return false
}

// astScanNonTestFiles parses every non-test .go file in this package's
// directory, for guards that inspect the production code's shape rather
// than its behaviour.
func astScanNonTestFiles(t *testing.T) (*token.FileSet, []*ast.File, []string) {
	t.Helper()
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
	var files []*ast.File
	var names []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", name, err)
		}
		files = append(files, file)
		names = append(names, name)
	}
	if len(files) == 0 {
		t.Fatal("astScanNonTestFiles found zero non-test .go files — the guard must actually inspect something")
	}
	return fset, files, names
}

// TestConstantTimeCompare_ASTScan is the code-shape half of the
// constant-time criterion: it fails on any way the MAC comparison could be
// (or become) a non-constant-time byte or string compare, in the package's
// non-test files only.
func TestConstantTimeCompare_ASTScan(t *testing.T) {
	fset, files, names := astScanNonTestFiles(t)

	sawEqualMACInit := false
	for i, file := range files {
		name := names[i]

		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", name, err)
			}
			if path == "crypto/subtle" {
				t.Errorf("%s imports crypto/subtle — mac comparison must go through equalMAC only", name)
			}
		}

		ast.Inspect(file, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.GenDecl:
				if v.Tok != token.VAR {
					return true
				}
				for _, spec := range v.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for idx, id := range vs.Names {
						if id.Name != "equalMAC" || idx >= len(vs.Values) {
							continue
						}
						sawEqualMACInit = true
						sel, ok := vs.Values[idx].(*ast.SelectorExpr)
						if !ok {
							t.Errorf("%s: equalMAC must be initialised to hmac.Equal", name)
							continue
						}
						x, ok := sel.X.(*ast.Ident)
						if !ok || x.Name != "hmac" || sel.Sel.Name != "Equal" {
							t.Errorf("%s: equalMAC must be initialised to hmac.Equal", name)
						}
					}
				}
			case *ast.CallExpr:
				sel, ok := v.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				x, ok := sel.X.(*ast.Ident)
				if ok && x.Name == "bytes" && sel.Sel.Name == "Equal" {
					t.Errorf("%s: calls bytes.Equal — mac comparison must go through equalMAC only", name)
				}
			case *ast.BinaryExpr:
				if v.Op == token.EQL || v.Op == token.NEQ {
					if isSuspectMACCompareOperand(v.X) || isSuspectMACCompareOperand(v.Y) {
						t.Errorf("%s:%d: %s comparison with a string- or array-conversion/composite-literal operand — "+
							"mac comparison must go through equalMAC only", name, fset.Position(v.Pos()).Line, v.Op)
					}
				}
			case *ast.AssignStmt:
				for _, lhs := range v.Lhs {
					id, ok := lhs.(*ast.Ident)
					if ok && (id.Name == "equalMAC" || id.Name == "computeMAC") {
						t.Errorf("%s:%d: %s is reassigned outside its var declaration — only _test.go files may swap this seam",
							name, fset.Position(v.Pos()).Line, id.Name)
					}
				}
			}
			return true
		})
	}

	if !sawEqualMACInit {
		t.Fatal("did not find equalMAC's var declaration — the guard must actually inspect something")
	}
}

func TestSeal_RefusesInvalidFields(t *testing.T) {
	sealer := mustMint(t)
	base := sampleState(t)

	singleByteCases := []struct {
		name string
		b    byte
	}{
		{"space", ' '},
		{"double quote", '"'},
		{"backslash", '\\'},
		{"less-than", '<'},
		{"greater-than", '>'},
		{"ampersand", '&'},
		{"control byte 0x1F", 0x1F},
		{"delete 0x7F", 0x7F},
	}
	for _, tc := range singleByteCases {
		t.Run(tc.name, func(t *testing.T) {
			st := base
			st.Tool = string([]byte{tc.b})
			if _, err := sealer.Seal(st); !errors.Is(err, ErrInvalidField) {
				t.Errorf("Seal() err = %v, want ErrInvalidField", err)
			}
		})
	}

	multiByteCases := []struct {
		name string
		s    string
	}{
		{"non-ASCII rune", "café"},
		{"line separator U+2028", "a b"},
	}
	for _, tc := range multiByteCases {
		t.Run(tc.name, func(t *testing.T) {
			st := base
			st.Tool = tc.s
			if _, err := sealer.Seal(st); !errors.Is(err, ErrInvalidField) {
				t.Errorf("Seal() err = %v, want ErrInvalidField", err)
			}
		})
	}

	t.Run("invalid utf-8 byte", func(t *testing.T) {
		st := base
		st.Tool = string([]byte{'a', 0xFF, 'b'})
		if _, err := sealer.Seal(st); !errors.Is(err, ErrInvalidField) {
			t.Errorf("Seal() err = %v, want ErrInvalidField", err)
		}
	})

	t.Run("empty field", func(t *testing.T) {
		st := base
		st.AccountID = ""
		if _, err := sealer.Seal(st); !errors.Is(err, ErrInvalidField) {
			t.Errorf("Seal() err = %v, want ErrInvalidField", err)
		}
	})

	t.Run("zero digest", func(t *testing.T) {
		st := base
		st.ArgsDigest = Digest{}
		if _, err := sealer.Seal(st); !errors.Is(err, ErrInvalidField) {
			t.Errorf("Seal() err = %v, want ErrInvalidField", err)
		}
	})

	t.Run("zero expires at", func(t *testing.T) {
		st := base
		st.ExpiresAt = time.Time{}
		if _, err := sealer.Seal(st); !errors.Is(err, ErrInvalidField) {
			t.Errorf("Seal() err = %v, want ErrInvalidField", err)
		}
	})

	t.Run("expires at outside the UnixNano range (future)", func(t *testing.T) {
		st := base
		st.ExpiresAt = time.Date(2300, 1, 1, 0, 0, 0, 0, time.UTC)
		if _, err := sealer.Seal(st); !errors.Is(err, ErrInvalidField) {
			t.Errorf("Seal() err = %v, want ErrInvalidField", err)
		}
	})

	t.Run("expires at outside the UnixNano range (past)", func(t *testing.T) {
		st := base
		st.ExpiresAt = time.Date(1600, 1, 1, 0, 0, 0, 0, time.UTC)
		if _, err := sealer.Seal(st); !errors.Is(err, ErrInvalidField) {
			t.Errorf("Seal() err = %v, want ErrInvalidField", err)
		}
	})

	t.Run("New refuses a short key", func(t *testing.T) {
		if _, err := New(make([]byte, KeyBytes-1)); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("New() err = %v, want ErrInvalidKey", err)
		}
	})
	t.Run("New refuses a long key", func(t *testing.T) {
		if _, err := New(make([]byte, KeyBytes+1)); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("New() err = %v, want ErrInvalidKey", err)
		}
	})
	t.Run("New refuses an all-zero key", func(t *testing.T) {
		if _, err := New(make([]byte, KeyBytes)); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("New() err = %v, want ErrInvalidKey", err)
		}
	})
}

func TestSealer_ZeroValueRefuses(t *testing.T) {
	minted := mustMint(t)
	sealedFromMinted, err := minted.Seal(sampleState(t))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	openNow := sampleNow.Add(30 * time.Minute)

	calls := 0
	orig := computeMAC
	computeMAC = func(key, msg []byte) []byte {
		calls++
		return orig(key, msg)
	}
	t.Cleanup(func() { computeMAC = orig })

	var z Sealer
	if out, err := z.Seal(sampleState(t)); !errors.Is(err, ErrInvalidKey) || out != "" {
		t.Errorf("zero Sealer.Seal() = (%q, %v), want (\"\", ErrInvalidKey)", out, err)
	}
	if st, err := z.Open(sealedFromMinted, openNow); !errors.Is(err, ErrInvalidKey) || st != (State{}) {
		t.Errorf("zero Sealer.Open() = (%+v, %v), want (zero State, ErrInvalidKey)", st, err)
	}

	var nilSealer *Sealer
	if out, err := nilSealer.Seal(sampleState(t)); !errors.Is(err, ErrInvalidKey) || out != "" {
		t.Errorf("nil *Sealer.Seal() = (%q, %v), want (\"\", ErrInvalidKey)", out, err)
	}
	if st, err := nilSealer.Open(sealedFromMinted, openNow); !errors.Is(err, ErrInvalidKey) || st != (State{}) {
		t.Errorf("nil *Sealer.Open() = (%+v, %v), want (zero State, ErrInvalidKey)", st, err)
	}

	if calls != 0 {
		t.Errorf("computeMAC called %d times across zero/nil Sealer calls, want 0", calls)
	}
}

func TestSealer_NeverRendersKey(t *testing.T) {
	key, minted := mustNewWithKnownKey(t)

	checkRendered := func(t *testing.T, label, rendered string) {
		t.Helper()
		if !strings.Contains(rendered, "REDACTED") {
			t.Errorf("%s = %q, want it to contain REDACTED", label, rendered)
		}
		if strings.Contains(rendered, string(key)) {
			t.Errorf("%s = %q, contains the raw key", label, rendered)
		}
		if strings.Contains(rendered, hex.EncodeToString(key)) {
			t.Errorf("%s = %q, contains the hex-encoded key", label, rendered)
		}
	}

	checkAllVerbs := func(t *testing.T, label string, v any) {
		t.Helper()
		checkRendered(t, label+" %v", fmt.Sprintf("%v", v))
		checkRendered(t, label+" %+v", fmt.Sprintf("%+v", v))
		checkRendered(t, label+" %#v", fmt.Sprintf("%#v", v))
		checkRendered(t, label+" %s", fmt.Sprintf("%s", v))

		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("sealer", slog.Any("sealer", v))
		checkRendered(t, label+" slog", buf.String())
	}

	checkAllVerbs(t, "*Sealer", minted)
	checkAllVerbs(t, "Sealer", *minted)
}

// keyLeakVerbs are every fmt verb TestSealer_UnexportedFieldNeverRendersKey
// and its negative control check. %v, %+v and %#v are the verbs a struct
// naturally supports; %s, %q, %x and %d are "bad" verbs for a struct that
// doesn't implement Stringer — the ones N1 found unsafe, because fmt's
// bad-verb path (badVerb) re-renders the offending field from scratch with
// %v at depth 0, which can re-trigger the pointer-to-array auto-dereference
// fmt normally reserves for a verb's own top-level argument.
var keyLeakVerbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"}

// keyLeakFindings renders holder — typically a struct holding a Sealer or
// Sealer-shaped value in an unexported field — through every verb in
// keyLeakVerbs, through slog's Text and JSON handlers, and through
// log.Printf (which, unlike testing's own output, is a realistic sink for
// an accidentally-logged struct), and returns a description of every
// rendering that contains key in its raw, hex-encoded, base64-encoded or
// fmt-default-decimal-list form. An empty result means none of the sinks
// leaked the key.
//
// TestSealer_UnexportedFieldNeverRendersKey and its negative control both
// call this exact function: the negative control proves the checker itself
// can fail, so the real test above it is not passing vacuously.
func keyLeakFindings(key []byte, holder any) []string {
	keyHex := hex.EncodeToString(key)
	keyBase64 := base64.StdEncoding.EncodeToString(key)
	decimalList := func(b []byte) string {
		parts := make([]string, len(b))
		for i, v := range b {
			parts[i] = fmt.Sprintf("%d", v)
		}
		return "[" + strings.Join(parts, " ") + "]"
	}
	keyDecimalList := decimalList(key) // fmt's default []byte %v shape, e.g. "[1 2 3]"

	var findings []string
	check := func(sink, rendered string) {
		if strings.Contains(rendered, string(key)) {
			findings = append(findings, fmt.Sprintf("%s = %q, contains the raw key bytes", sink, rendered))
		}
		if strings.Contains(rendered, keyHex) {
			findings = append(findings, fmt.Sprintf("%s = %q, contains the hex-encoded key", sink, rendered))
		}
		if strings.Contains(rendered, keyBase64) {
			findings = append(findings, fmt.Sprintf("%s = %q, contains the base64-encoded key", sink, rendered))
		}
		if strings.Contains(rendered, keyDecimalList) {
			findings = append(findings, fmt.Sprintf("%s = %q, contains the key as a decimal byte list", sink, rendered))
		}
	}

	for _, verb := range keyLeakVerbs {
		check(verb, fmt.Sprintf(verb, holder))

		var logBuf bytes.Buffer
		log.New(&logBuf, "", 0).Printf(verb, holder)
		check("log.Printf "+verb, logBuf.String())
	}

	var textBuf, jsonBuf bytes.Buffer
	slog.New(slog.NewTextHandler(&textBuf, nil)).Info("holder", slog.Any("holder", holder))
	check("slog text", textBuf.String())

	slog.New(slog.NewJSONHandler(&jsonBuf, nil)).Info("holder", slog.Any("holder", holder))
	check("slog json", jsonBuf.String())

	return findings
}

// TestSealer_UnexportedFieldNeverRendersKey reproduces the security review's
// finding directly: fmt and slog cannot call a value's String, GoString or
// LogValue method when that value was reached through an UNEXPORTED struct
// field (reflect.Value.Interface panics on such a value, so fmt and slog
// fall back to printing the field's raw representation instead of invoking
// the method). Sealer holds the key only inside a closure, which has no
// byte-shaped raw representation for any fallback path — including a bad
// verb's — to fall back to; see Sealer's doc for why that is what redacts
// it where an earlier, pointer-based shape did not.
func TestSealer_UnexportedFieldNeverRendersKey(t *testing.T) {
	key, minted := mustNewWithKnownKey(t)

	type holder struct {
		value   Sealer
		pointer *Sealer
	}
	h := holder{value: *minted, pointer: minted}

	for _, f := range keyLeakFindings(key, h) {
		t.Error(f)
	}
}

// TestSealer_UnexportedFieldNeverRendersKey_NegativeControl proves
// keyLeakFindings actually detects a leak: leakyHolder holds the key
// exactly the way a pre-N1-fix Sealer held it (behind a single pointer,
// *[KeyBytes]byte) in an unexported field, the shape the security review
// found unsafe under a bad verb. If keyLeakFindings found nothing wrong
// with this holder, the checker — and therefore the real test above — would
// be vacuous.
func TestSealer_UnexportedFieldNeverRendersKey_NegativeControl(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	var owned [KeyBytes]byte
	copy(owned[:], key)

	type leakyHolder struct {
		key *[KeyBytes]byte
	}
	h := leakyHolder{key: &owned}

	if findings := keyLeakFindings(key, h); len(findings) == 0 {
		t.Fatal("keyLeakFindings found nothing wrong with a deliberately leaky holder — the checker is vacuous")
	}
}

func TestArgsDigest_IsCanonical(t *testing.T) {
	mustEqual := func(t *testing.T, a, b string) {
		t.Helper()
		da := mustDigest(t, []byte(a))
		db := mustDigest(t, []byte(b))
		if da != db {
			t.Errorf("DigestArgs(%q) != DigestArgs(%q), want equal", a, b)
		}
	}
	mustDiffer := func(t *testing.T, a, b string) {
		t.Helper()
		da := mustDigest(t, []byte(a))
		db := mustDigest(t, []byte(b))
		if da == db {
			t.Errorf("DigestArgs(%q) == DigestArgs(%q), want different", a, b)
		}
	}

	t.Run("key reorder at top level", func(t *testing.T) {
		mustEqual(t, `{"a":1,"b":2}`, `{"b":2,"a":1}`)
	})
	t.Run("key reorder nested", func(t *testing.T) {
		mustEqual(t, `{"outer":{"a":1,"b":2}}`, `{"outer":{"b":2,"a":1}}`)
	})
	t.Run("whitespace differences", func(t *testing.T) {
		mustEqual(t, `{"a":1,"b":2}`, "{\n  \"a\": 1,\n  \"b\": 2\n}")
	})

	t.Run("changed string value", func(t *testing.T) {
		mustDiffer(t, `{"a":"x"}`, `{"a":"y"}`)
	})
	t.Run("changed number value", func(t *testing.T) {
		mustDiffer(t, `{"a":1}`, `{"a":2}`)
	})
	t.Run("changed bool value", func(t *testing.T) {
		mustDiffer(t, `{"a":true}`, `{"a":false}`)
	})
	t.Run("changed to null", func(t *testing.T) {
		mustDiffer(t, `{"a":1}`, `{"a":null}`)
	})
	t.Run("array element order", func(t *testing.T) {
		mustDiffer(t, `[1,2,3]`, `[3,2,1]`)
	})
	t.Run("added key", func(t *testing.T) {
		mustDiffer(t, `{"a":1}`, `{"a":1,"b":2}`)
	})
	t.Run("removed key", func(t *testing.T) {
		mustDiffer(t, `{"a":1,"b":2}`, `{"a":1}`)
	})
	t.Run("nested value changed", func(t *testing.T) {
		mustDiffer(t, `{"outer":{"a":1}}`, `{"outer":{"a":2}}`)
	})
	t.Run("large integers distinguished", func(t *testing.T) {
		mustDiffer(t, `{"n":9007199254740993}`, `{"n":9007199254740992}`)
	})

	t.Run("trailing data is refused", func(t *testing.T) {
		if _, err := DigestArgs([]byte(`{}{}`)); !errors.Is(err, ErrInvalidArgs) {
			t.Errorf("DigestArgs() err = %v, want ErrInvalidArgs", err)
		}
	})
	t.Run("invalid json is refused", func(t *testing.T) {
		if _, err := DigestArgs([]byte(`{`)); !errors.Is(err, ErrInvalidArgs) {
			t.Errorf("DigestArgs() err = %v, want ErrInvalidArgs", err)
		}
	})
	t.Run("invalid utf-8 is refused", func(t *testing.T) {
		if _, err := DigestArgs([]byte{'"', 0xFF, '"'}); !errors.Is(err, ErrInvalidArgs) {
			t.Errorf("DigestArgs() err = %v, want ErrInvalidArgs", err)
		}
	})
	t.Run("empty input and null digest equal", func(t *testing.T) {
		mustEqual(t, "", "null")
	})
	// U+00A0 (NBSP) is Unicode whitespace but not JSON whitespace: DigestArgs
	// trims only " \t\r\n", so a lone NBSP, or one leading otherwise-valid
	// JSON, is invalid JSON rather than trimmed away and canonicalising as
	// though it were empty.
	t.Run("lone nbsp is refused", func(t *testing.T) {
		if _, err := DigestArgs([]byte(" ")); !errors.Is(err, ErrInvalidArgs) {
			t.Errorf("DigestArgs() err = %v, want ErrInvalidArgs", err)
		}
	})
	t.Run("nbsp followed by an object is refused", func(t *testing.T) {
		if _, err := DigestArgs([]byte(" {}")); !errors.Is(err, ErrInvalidArgs) {
			t.Errorf("DigestArgs() err = %v, want ErrInvalidArgs", err)
		}
	})
}

func TestBinding_RefusesCrossAccountCrossRequestWrongToolWrongArgs(t *testing.T) {
	sealer := mustMint(t)
	openNow := sampleNow.Add(30 * time.Minute)

	sealed, err := sealer.Seal(sampleState(t))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	opened, err := sealer.Open(sealed, openNow)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	matching := Call{
		AccountID:  opened.AccountID,
		RequestID:  opened.RequestID,
		Tool:       opened.Tool,
		ArgsDigest: opened.ArgsDigest,
	}
	if err := opened.Bind(matching); err != nil {
		t.Errorf("Bind(matching) = %v, want nil", err)
	}

	otherDigest := mustDigest(t, []byte(`{"different":true}`))
	cases := []struct {
		name     string
		mutate   func(c *Call)
		wantWord string
	}{
		{"cross-account", func(c *Call) { c.AccountID = "acct-" + strings.Repeat("11", 16) }, "account id"},
		{"cross-request", func(c *Call) { c.RequestID = strings.Repeat("22", 16) }, "request id"},
		{"wrong tool", func(c *Call) { c.Tool = "raw_exec" }, "tool"},
		{"wrong args", func(c *Call) { c.ArgsDigest = otherDigest }, "args digest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := matching
			tc.mutate(&c)
			err := opened.Bind(c)
			if !errors.Is(err, ErrBindingMismatch) {
				t.Fatalf("Bind() err = %v, want ErrBindingMismatch", err)
			}
			if !strings.Contains(err.Error(), tc.wantWord) {
				t.Errorf("Bind() err = %q, want it to name %q", err.Error(), tc.wantWord)
			}
		})
	}
}

// TestOpenFor_IsOpenThenBind proves OpenFor is the answer-path verifier: it
// refuses on the same single-field mismatches Bind refuses on its own, and
// returns the zero State on any of them, so a caller cannot forget to bind.
func TestOpenFor_IsOpenThenBind(t *testing.T) {
	sealer := mustMint(t)
	openNow := sampleNow.Add(30 * time.Minute)

	sealed, err := sealer.Seal(sampleState(t))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	opened, err := sealer.Open(sealed, openNow)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	matching := Call{
		AccountID:  opened.AccountID,
		RequestID:  opened.RequestID,
		Tool:       opened.Tool,
		ArgsDigest: opened.ArgsDigest,
	}

	t.Run("matching call succeeds", func(t *testing.T) {
		st, err := sealer.OpenFor(sealed, openNow, matching)
		if err != nil {
			t.Fatalf("OpenFor() err = %v, want nil", err)
		}
		if st != opened {
			t.Errorf("OpenFor() = %+v, want %+v", st, opened)
		}
	})

	otherDigest := mustDigest(t, []byte(`{"different":true}`))
	cases := []struct {
		name     string
		mutate   func(c *Call)
		wantWord string
	}{
		{"cross-account", func(c *Call) { c.AccountID = "acct-" + strings.Repeat("11", 16) }, "account id"},
		{"cross-request", func(c *Call) { c.RequestID = strings.Repeat("22", 16) }, "request id"},
		{"wrong tool", func(c *Call) { c.Tool = "raw_exec" }, "tool"},
		{"wrong args", func(c *Call) { c.ArgsDigest = otherDigest }, "args digest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := matching
			tc.mutate(&c)
			st, err := sealer.OpenFor(sealed, openNow, c)
			if !errors.Is(err, ErrBindingMismatch) {
				t.Fatalf("OpenFor() err = %v, want ErrBindingMismatch", err)
			}
			if !strings.Contains(err.Error(), tc.wantWord) {
				t.Errorf("OpenFor() err = %q, want it to name %q", err.Error(), tc.wantWord)
			}
			if st != (State{}) {
				t.Errorf("OpenFor() State = %+v, want the zero State", st)
			}
		})
	}
}
