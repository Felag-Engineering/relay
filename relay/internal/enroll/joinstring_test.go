package enroll

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
)

type joinOKRow struct {
	name, encoded, address, fingerprintHex, token string
}

type joinRefuseRow struct {
	name, reason, input string
}

var joinRefuseReasons = map[string]error{
	"missing_prefix":   ErrJoinStringPrefix,
	"invalid_encoding": ErrJoinStringEncoding,
	"invalid_message":  ErrJoinStringMessage,
	"unknown_version":  ErrJoinStringVersion,
	"empty_field":      ErrJoinStringEmptyField,
	"bad_fingerprint":  ErrJoinStringFingerprint,
}

func loadJoinVectors(t *testing.T) ([]joinOKRow, []joinRefuseRow) {
	t.Helper()
	data, err := os.ReadFile("../../../proto/testdata/join_string_vectors.tsv")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var oks []joinOKRow
	var refuses []joinRefuseRow
	covered := map[string]bool{}
	for i, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		switch {
		case cols[0] == "ok" && len(cols) == 6:
			oks = append(oks, joinOKRow{cols[1], cols[2], cols[3], cols[4], cols[5]})
		case cols[0] == "refuse" && len(cols) == 4:
			if _, known := joinRefuseReasons[cols[2]]; !known {
				t.Fatalf("line %d: unknown reason %q", i+1, cols[2])
			}
			covered[cols[2]] = true
			refuses = append(refuses, joinRefuseRow{cols[1], cols[2], cols[3]})
		default:
			t.Fatalf("line %d: malformed vectors line", i+1)
		}
	}
	if len(oks) < 4 {
		t.Fatalf("want at least 4 ok rows, got %d", len(oks))
	}
	for reason := range joinRefuseReasons {
		if !covered[reason] {
			t.Fatalf("no refuse row for reason %s", reason)
		}
	}
	return oks, refuses
}

func fingerprintFromHex(t *testing.T, s string) [sha256.Size]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != sha256.Size {
		t.Fatalf("bad fingerprint hex %q", s)
	}
	var fp [sha256.Size]byte
	copy(fp[:], b)
	return fp
}

func TestJoinString_RoundTripsSharedVectors(t *testing.T) {
	oks, _ := loadJoinVectors(t)
	sawDash, sawUnderscore := false, false
	for _, row := range oks {
		t.Run(row.name, func(t *testing.T) {
			fp := fingerprintFromHex(t, row.fingerprintHex)
			got, err := DecodeJoinString(row.encoded)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got.RelayAddress() != row.address || got.CAFingerprint() != fp || got.EnrollmentToken() != row.token {
				t.Fatalf("decoded parts differ from the vector columns")
			}
			built, err := NewJoinString(row.address, fp, row.token).Encode()
			if err != nil || built != row.encoded {
				t.Fatalf("encode of the columns differs from the vector (err=%v)", err)
			}
			again, err := got.Encode()
			if err != nil || again != row.encoded {
				t.Fatalf("decode then encode differs from the vector (err=%v)", err)
			}
		})
		sawDash = sawDash || strings.Contains(row.encoded, "-")
		sawUnderscore = sawUnderscore || strings.Contains(row.encoded, "_")
	}
	if !sawDash || !sawUnderscore {
		t.Fatalf("ok rows must cover '-' and '_' (dash=%v underscore=%v)", sawDash, sawUnderscore)
	}
}

func TestJoinString_RefusesMalformed(t *testing.T) {
	oks, refuses := loadJoinVectors(t)
	for _, row := range refuses {
		t.Run(row.name, func(t *testing.T) {
			got, err := DecodeJoinString(row.input)
			if !errors.Is(err, joinRefuseReasons[row.reason]) {
				t.Fatalf("want %v, got %v", joinRefuseReasons[row.reason], err)
			}
			if got != (JoinString{}) {
				t.Fatalf("a refused decode must return the zero value")
			}
			if row.reason == "empty_field" {
				want := map[string]string{
					"relay_address_missing":    "relay_address",
					"ca_fingerprint_missing":   "ca_fingerprint_sha256",
					"enrollment_token_missing": "enrollment_token",
				}[row.name]
				if want == "" {
					t.Fatalf("unmapped empty_field row %s", row.name)
				}
				if !strings.HasSuffix(err.Error(), ": "+want) {
					t.Fatalf("empty_field error must name %q, got %v", want, err)
				}
			}
		})
	}

	valid := oks[0].encoded
	mid := len(JoinStringPrefix) + 10
	local := []struct {
		name  string
		input string
		want  error
	}{
		{"empty", "", ErrJoinStringPrefix},
		{"leading_space", " " + valid, ErrJoinStringPrefix},
		{"leading_tab", "\t" + valid, ErrJoinStringPrefix},
		{"lf_mid_payload", valid[:mid] + "\n" + valid[mid:], ErrJoinStringEncoding},
		{"crlf_appended", valid + "\r\n", ErrJoinStringEncoding},
		{"trailing_space", valid + " ", ErrJoinStringEncoding},
		{"trailing_tab", valid + "\t", ErrJoinStringEncoding},
		{"space_mid_payload", valid[:mid] + " " + valid[mid:], ErrJoinStringEncoding},
	}
	for _, c := range local {
		t.Run(c.name, func(t *testing.T) {
			got, err := DecodeJoinString(c.input)
			if !errors.Is(err, c.want) {
				t.Fatalf("want %v, got %v", c.want, err)
			}
			if got != (JoinString{}) {
				t.Fatalf("a refused decode must return the zero value")
			}
		})
	}

	var fp [sha256.Size]byte
	if _, err := NewJoinString("", fp, "tok").Encode(); !errors.Is(err, ErrJoinStringEmptyField) {
		t.Fatalf("empty address: got %v", err)
	}
	if _, err := NewJoinString("host:1", fp, "").Encode(); !errors.Is(err, ErrJoinStringEmptyField) {
		t.Fatalf("empty token: got %v", err)
	}
}

func TestJoinString_NeverRendersInputOrToken(t *testing.T) {
	oks, refuses := loadJoinVectors(t)

	var inputs []string
	for _, row := range oks {
		inputs = append(inputs, row.encoded)
	}
	for _, row := range refuses {
		inputs = append(inputs, row.input)
	}
	var tokens []string
	for _, row := range oks {
		tokens = append(tokens, row.token)
	}
	for _, in := range inputs {
		_, err := DecodeJoinString(in)
		if err == nil {
			continue
		}
		msg := err.Error()
		if strings.Contains(msg, in) {
			t.Fatalf("error text contains its input: %q", msg)
		}
		if payload := strings.TrimPrefix(in, JoinStringPrefix); payload != "" && strings.Contains(msg, payload) {
			t.Fatalf("error text contains its payload: %q", msg)
		}
		for _, tok := range tokens {
			if strings.Contains(msg, tok) {
				t.Fatalf("error text contains a token: %q", msg)
			}
		}
	}

	for _, row := range oks {
		t.Run(row.name, func(t *testing.T) {
			v, err := DecodeJoinString(row.encoded)
			if err != nil {
				t.Fatal(err)
			}
			check := func(label, out string) {
				t.Helper()
				if strings.Contains(out, row.token) || strings.Contains(out, row.encoded) {
					t.Fatalf("%s leaks the token or encoded text: %q", label, out)
				}
			}
			for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d", "%t"} {
				check(verb, fmt.Sprintf(verb, v))
				check(verb+" pointer", fmt.Sprintf(verb, &v))
			}
			var tb, jb bytes.Buffer
			slog.New(slog.NewTextHandler(&tb, nil)).Info("m", slog.Any("j", v))
			slog.New(slog.NewJSONHandler(&jb, nil)).Info("m", slog.Any("j", v))
			check("slog text", tb.String())
			check("slog json", jb.String())
			// Nested in an unexported field, fmt and slog cannot call Format or LogValue
			// and walk the fields instead.
			type holder struct{ j JoinString }
			for _, outer := range []any{holder{v}, &holder{v}} {
				for _, verb := range []string{"%v", "%+v", "%#v"} {
					check(verb+" nested", fmt.Sprintf(verb, outer))
				}
				tb.Reset()
				jb.Reset()
				slog.New(slog.NewTextHandler(&tb, nil)).Info("m", slog.Any("o", outer))
				slog.New(slog.NewJSONHandler(&jb, nil)).Info("m", slog.Any("o", outer))
				check("slog text nested", tb.String())
				check("slog json nested", jb.String())
			}
			j, err := json.Marshal(map[string]any{"j": v})
			if err != nil {
				t.Fatal(err)
			}
			check("json", string(j))
		})
	}
}

func TestJoinString_StringQuotesAddress(t *testing.T) {
	var fp [sha256.Size]byte
	out := NewJoinString("host:1\nFORGED level=ERROR", fp, "tok").String()
	if strings.ContainsAny(out, "\n\r") {
		t.Fatalf("String must escape control characters: %q", out)
	}
	if !strings.Contains(out, `relay_address="host:1\nFORGED level=ERROR"`) {
		t.Fatalf("String must quote the address: %q", out)
	}
}
