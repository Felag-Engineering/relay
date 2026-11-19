package visibletext

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// bs is one backslash. Expected escape text is built from it so no source line
// holds a backslash-u sequence a tool layer or reader could mistake for the
// character it names.
const bs = "\\"

func char(c rune) string { return string(rune(c)) }

func TestEscape_WritesEveryHiddenClassAsAnEscape(t *testing.T) {
	cases := []struct {
		name string
		in   rune
		want string
	}{
		{"NUL", 0x00, bs + "u0000"},
		{"TAB", 0x09, bs + "u0009"},
		{"LF", 0x0a, bs + "u000a"},
		{"CR", 0x0d, bs + "u000d"},
		{"ESC", 0x1b, bs + "u001b"},
		{"DEL", 0x7f, bs + "u007f"},
		{"NEL", 0x85, bs + "u0085"},
		{"CSI", 0x9b, bs + "u009b"},
		{"ZWSP", 0x200b, bs + "u200b"},
		{"ZWNJ", 0x200c, bs + "u200c"},
		{"ZWJ", 0x200d, bs + "u200d"},
		{"WJ", 0x2060, bs + "u2060"},
		{"BOM", 0xfeff, bs + "ufeff"},
		{"soft hyphen", 0xad, bs + "u00ad"},
		{"CGJ", 0x34f, bs + "u034f"},
		{"Hangul choseong filler", 0x115f, bs + "u115f"},
		{"Hangul filler", 0x3164, bs + "u3164"},
		{"halfwidth Hangul filler", 0xffa0, bs + "uffa0"},
		{"Braille blank", 0x2800, bs + "u2800"},
		{"variation selector", 0xfe0f, bs + "ufe0f"},
		{"tag letter", 0xe0041, bs + "U000e0041"},
		{"NBSP", 0xa0, bs + "u00a0"},
		{"ogham space", 0x1680, bs + "u1680"},
		{"en quad", 0x2000, bs + "u2000"},
		{"figure space", 0x2007, bs + "u2007"},
		{"narrow NBSP", 0x202f, bs + "u202f"},
		{"ideographic space", 0x3000, bs + "u3000"},
		{"line separator", 0x2028, bs + "u2028"},
		{"paragraph separator", 0x2029, bs + "u2029"},
		{"ALM", 0x61c, bs + "u061c"},
		{"LRM", 0x200e, bs + "u200e"},
		{"RLM", 0x200f, bs + "u200f"},
		{"LRE", 0x202a, bs + "u202a"},
		{"RLE", 0x202b, bs + "u202b"},
		{"PDF", 0x202c, bs + "u202c"},
		{"LRO", 0x202d, bs + "u202d"},
		{"RLO", 0x202e, bs + "u202e"},
		{"LRI", 0x2066, bs + "u2066"},
		{"RLI", 0x2067, bs + "u2067"},
		{"FSI", 0x2068, bs + "u2068"},
		{"PDI", 0x2069, bs + "u2069"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := "app" + char(c.in) + ".log"
			want := "app" + c.want + ".log"
			if got := Escape(in); got != want {
				t.Errorf("Escape(%q) = %q, want %q", in, got, want)
			}
			if got := Quote(in); got != `"`+want+`"` {
				t.Errorf("Quote(%q) = %q, want %q", in, got, `"`+want+`"`)
			}
			if got := Prose(in); got != want {
				t.Errorf("Prose(%q) = %q, want %q", in, got, want)
			}
			if got := Escape("app.log"); got == Escape(in) {
				t.Errorf("hostile and plain lookalike render the same: %q", got)
			}
		})
	}
}

func TestEscape_LeavesVisibleTextAlone(t *testing.T) {
	for _, in := range []string{
		"",
		"plain ascii with spaces",
		"caf" + char(0xe9),
		char(0x65e5) + char(0x672c) + char(0x8a9e),
		char(0x20ac) + "5",
		"real " + char(0xfffd) + " replacement",
		`^/usr/bin/systemctl` + bs + `s+status`,
		`^/usr/bin/foo` + bs + `d+` + bs + `.log$`,
		"trailing" + bs,
	} {
		if got := Escape(in); got != in {
			t.Errorf("Escape(%q) = %q, want it unchanged", in, got)
		}
		if got := Block(in); got != in {
			t.Errorf("Block(%q) = %q, want it unchanged", in, got)
		}
		if got := Prose(in); got != in {
			t.Errorf("Prose(%q) = %q, want it unchanged", in, got)
		}
	}
}

func TestEscape_BackslashRule(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"literal escape text", bs + "u202e", bs + "u005cu202e"},
		{"real RLO", char(0x202e), bs + "u202e"},
		{"backslash then real RLO", bs + char(0x202e), bs + "u005c" + bs + "u202e"},
		{"literal long escape text", bs + "U0001f600", bs + "u005cU0001f600"},
		{"backslash before backslash", bs + bs, bs + "u005c" + bs},
		{"backslash before x", bs + "xff", bs + "u005cxff"},
		{"backslash before U", bs + "U", bs + "u005cU"},
		{"backslash before quote", bs + `"`, bs + "u005c" + `"`},
		{"backslash before invalid byte", bs + string([]byte{0xff}), bs + "u005c" + bs + "xff"},
		{"invalid byte", string([]byte{0xff}), bs + "xff"},
		{"other invalid byte", string([]byte{0xfe}), bs + "xfe"},
		{"policy regex", `^/usr/bin/systemctl` + bs + `s+status`, `^/usr/bin/systemctl` + bs + `s+status`},
		{"regex literal backslash then dot", bs + bs + bs + ".", bs + "u005c" + bs + "u005c" + bs + "."},
		{"real replacement rune", char(0xfffd), char(0xfffd)},
	}
	for _, c := range cases {
		if got := Escape(c.in); got != c.want {
			t.Errorf("%s: Escape(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
	distinct := map[string]string{}
	for _, in := range []string{char(0x202e), bs + "u202e", bs + char(0x202e), bs + "U0001f600"} {
		out := Escape(in)
		if prev, dup := distinct[out]; dup {
			t.Errorf("%q and %q both render %q", prev, in, out)
		}
		distinct[out] = in
	}
}

func TestQuote_ATrailingBackslashCannotForgeAnArgumentBoundary(t *testing.T) {
	twoArgs := Quote("x"+bs) + " " + Quote("y")
	oneArg := Quote(`x" "y`)
	if want := `"x` + bs + `u005c" "y"`; twoArgs != want {
		t.Errorf("two argv elements = %s, want %s", twoArgs, want)
	}
	if want := `"x` + bs + `u0022 ` + bs + `u0022y"`; oneArg != want {
		t.Errorf("one value = %s, want %s", oneArg, want)
	}
	if twoArgs == oneArg {
		t.Errorf("distinct values render the same: %s", twoArgs)
	}
	for _, out := range []string{twoArgs, oneArg} {
		if strings.Contains(out, bs+`"`) {
			t.Errorf("%s holds a backslash directly before a double quote", out)
		}
	}
	if got := Quote(""); got != `""` {
		t.Errorf("Quote(empty) = %s, want two double quotes", got)
	}
}

func TestEscape_InvalidBytesAreHexEscapes(t *testing.T) {
	if got, want := Escape(string([]byte{0xff})), bs+"xff"; got != want {
		t.Errorf("0xff = %q, want %q", got, want)
	}
	if got, want := Escape("a"+string([]byte{0xfe})+"b"), "a"+bs+"xfeb"; got != want {
		t.Errorf("0xfe = %q, want %q", got, want)
	}
	if got := Escape(char(0xfffd)); got != char(0xfffd) {
		t.Errorf("a real U+FFFD changed to %q", got)
	}
	truncated := string([]byte{0xe2, 0x82})
	if got, want := Escape(truncated), bs+"xe2"+bs+"x82"; got != want {
		t.Errorf("truncated sequence = %q, want %q", got, want)
	}
}

func TestBlock_KeepsOnlyLineFeeds(t *testing.T) {
	if got, want := Block("a\nb"), "a\nb"; got != want {
		t.Errorf("LF = %q, want %q", got, want)
	}
	if got, want := Block("a\r\n\tb"), "a"+bs+"u000d\n"+bs+"u0009b"; got != want {
		t.Errorf("CR and TAB = %q, want %q", got, want)
	}
	if got, want := Block("a"+bs+"\nb"), "a"+bs+"\nb"; got != want {
		t.Errorf("backslash before LF = %q, want %q", got, want)
	}
}

func TestProse_EscapesHiddenRunesAndLeavesQuotingAlone(t *testing.T) {
	quoted := strconv.Quote("a" + char(0x3164) + "b")
	want := strings.Replace(quoted, char(0x3164), bs+"u3164", 1)
	if got := Prose(quoted); got != want {
		t.Errorf("Prose(%%q of U+3164) = %q, want %q", got, want)
	}
	already := strconv.Quote("a" + char(0x202e) + `"b`)
	if got := Prose(already); got != already {
		t.Errorf("Prose changed %%q's own escapes: %q -> %q", already, got)
	}
	for _, c := range []rune{0x85, 0x200b, 0x202e, 0x2066, 0xa0} {
		in := "app" + char(c) + ".log"
		out := Prose(in)
		if strings.ContainsRune(out, c) {
			t.Errorf("Prose(%q) still holds U+%04X", in, c)
		}
		if out == Prose("app.log") {
			t.Errorf("Prose(%q) reads as the lookalike", in)
		}
	}
}

// decode inverts Escape, Block and Quote: it reads each escape as its own
// unit and every other character literally.
func decode(t *testing.T, s string) string {
	t.Helper()
	var out []byte
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+1 < len(s) {
			var width int
			switch s[i+1] {
			case 'u':
				width = 4
			case 'U':
				width = 8
			case 'x':
				width = 2
			}
			if width > 0 {
				if i+2+width > len(s) {
					t.Fatalf("truncated escape in %q at %d", s, i)
				}
				v, err := strconv.ParseUint(s[i+2:i+2+width], 16, 32)
				if err != nil {
					t.Fatalf("bad escape in %q at %d", s, i)
				}
				if s[i+1] == 'x' {
					out = append(out, byte(v))
				} else {
					out = utf8.AppendRune(out, rune(v))
				}
				i += 2 + width
				continue
			}
		}
		out = append(out, s[i])
		i++
	}
	return string(out)
}

func FuzzEscape_RoundTripsAndLeavesNothingHidden(f *testing.F) {
	for _, seed := range []string{
		"app" + char(0x85) + ".log", "app" + char(0x200b) + ".log", char(0x202e) + "gol.ppa",
		char(0x2066) + "app.log" + char(0x2069), "app" + char(0xa0) + ".log",
		"x" + bs, `x" "y`, bs + "u202e", bs + char(0x202e), bs + "xff", bs + bs, bs + `"`,
		string([]byte{0xff}), "a\nb", char(0xfffd),
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		s := string(in)
		for name, got := range map[string]string{"Escape": Escape(s), "Block": Block(s), "Quote": Quote(s)} {
			if !utf8.ValidString(got) {
				t.Fatalf("%s(%q) is not valid UTF-8", name, s)
			}
			body := got
			if name == "Quote" {
				body = got[1 : len(got)-1]
			}
			if dec := decode(t, body); dec != s {
				t.Fatalf("%s(%q) = %q decodes to %q", name, s, got, dec)
			}
			for _, c := range body {
				if hidden(c) && (name != "Block" || c != '\n') {
					t.Fatalf("%s(%q) holds hidden %U", name, s, c)
				}
			}
			// No escape holds a backslash or a double quote after its first
			// character, so these pairs can only be a raw backslash that
			// would begin an escape or escape a quote.
			if strings.Contains(body, bs+bs) || strings.Contains(body, bs+`"`) {
				t.Fatalf("%s(%q) = %q: raw backslash before a backslash or quote", name, s, got)
			}
			if name == "Quote" && strings.HasSuffix(body, bs) {
				t.Fatalf("%s(%q) = %q: backslash precedes the closing quote", name, s, got)
			}
		}
		p := Prose(s)
		if !utf8.ValidString(p) {
			t.Fatalf("Prose(%q) is not valid UTF-8", s)
		}
		for _, c := range p {
			if hidden(c) {
				t.Fatalf("Prose(%q) holds hidden %U", s, c)
			}
		}
	})
}

func TestEscape_FastPathDoesNotAllocate(t *testing.T) {
	in := "an ordinary value"
	if got := fmt.Sprint(testing.AllocsPerRun(10, func() { _ = Escape(in) })); got != "0" {
		t.Errorf("Escape allocated %s times on an ordinary value", got)
	}
}
