package relayconfig

import (
	"regexp"
	"strings"
	"testing"
)

// Every name the schema tree holds is lower-case ASCII, numerals and underscore:
// the case-variant check and the refusal text rely on it.
func TestSchemaTree_NamesAreLowerCaseASCII(t *testing.T) {
	valid := regexp.MustCompile(`^[a-z0-9_]+$`)
	var walk func(path string, n schemaNode)
	walk = func(path string, n schemaNode) {
		for name, child := range n {
			if !valid.MatchString(name) {
				t.Errorf("schema name %q under %q is not lower-case ASCII, digits or underscore", name, path)
			}
			walk(path+"."+name, child)
		}
	}
	walk("", schemaTree)
}

func upperFirst(s string) string { return strings.ToUpper(s[:1]) + s[1:] }

// A key spelled in another case than the schema's is refused wherever it is
// written, naming the key as written and never its value.
//
// Proves RC-54.
func TestLoad_CaseVariantKeyRefusedInEverySection(t *testing.T) {
	want := func(t *testing.T, src string, wants ...string) {
		t.Helper()
		got := loadErr(t, src)
		for _, w := range wants {
			if !strings.Contains(got, w) {
				t.Errorf("error %q does not contain %q", got, w)
			}
		}
		notContains(t, got, "CANARY", "unrecognised")
	}

	t.Run("every key", func(t *testing.T) {
		for _, k := range schemaKeys() {
			section, key, _ := strings.Cut(k, ".")
			src := minimal + "[" + section + "]\n" + upperFirst(key) + " = \"CANARY\"\n"
			want(t, src, k+" (line 8): "+reasonSpelling+"; it is written "+section+"."+upperFirst(key))
		}
	})
	t.Run("every section", func(t *testing.T) {
		for section := range sections {
			want(t, minimal+"["+strings.ToUpper(section)+"]\n", section+" (line 7): "+reasonSpelling)
		}
	})
	t.Run("every rule field", func(t *testing.T) {
		for f := range ruleFields {
			src := minimal + "[[approval.rules]]\n" + upperFirst(f) + " = \"CANARY\"\n"
			want(t, src, "approval.rules."+f+" (line 8): "+reasonSpelling+"; it is written approval.rules."+upperFirst(f))
		}
	})
	t.Run("a root dotted key", func(t *testing.T) {
		want(t, "TLS.hostname = \"CANARY\"\n"+minimal, "tls.hostname (line 1)", "it is written TLS.hostname")
	})
	t.Run("an inline table", func(t *testing.T) {
		src := "tls = { Hostname = \"CANARY\" }\n[ca]\ndir = \"/var/lib/relay/ca\"\n[store]\npath = \"/var/lib/relay/relay.db\"\n"
		want(t, src, "tls.hostname (line 1)")
	})
	t.Run("a variant header with exact keys under it", func(t *testing.T) {
		got := loadErr(t, minimal+"[REACH]\nread_blast_cap = 1\nmutate_blast_cap = 1\n")
		if n := strings.Count(got, reasonSpelling); n != 1 {
			t.Errorf("error %q refuses the spelling %d times, want 1", got, n)
		}
	})
	t.Run("non-ASCII folds", func(t *testing.T) {
		want(t, minimal+"[tls]\n\"hoſtname\" = \"CANARY\"\n", "tls.hostname")
		want(t, minimal+"[approval]\n\"webhooK_url_file\" = \"CANARY\"\n", "approval.webhook_url_file")
	})
}

// A file that spells one key two ways is refused, each spelling named.
//
// Proves RC-54.
func TestLoad_KeySpelledTwoWaysRefused(t *testing.T) {
	t.Run("exact then variant", func(t *testing.T) {
		got := loadErr(t, minimal+"[reach]\nmutate_blast_cap = 1\nMutate_Blast_Cap = 2\n")
		for _, w := range []string{"reach.mutate_blast_cap (line 9)", "it is written reach.Mutate_Blast_Cap"} {
			if !strings.Contains(got, w) {
				t.Errorf("error %q does not contain %q", got, w)
			}
		}
	})
	t.Run("variant then exact", func(t *testing.T) {
		got := loadErr(t, minimal+"[reach]\nMutate_Blast_Cap = 2\nmutate_blast_cap = 1\n")
		if w := "reach.mutate_blast_cap (line 8)"; !strings.Contains(got, w) {
			t.Errorf("error %q does not contain %q", got, w)
		}
	})
	t.Run("two variants", func(t *testing.T) {
		got := loadErr(t, minimal+"[reach]\nMutate_blast_cap = 1\nMUTATE_BLAST_CAP = 2\n")
		for _, w := range []string{"it is written reach.Mutate_blast_cap", "it is written reach.MUTATE_BLAST_CAP"} {
			if !strings.Contains(got, w) {
				t.Errorf("error %q does not contain %q", got, w)
			}
		}
	})
	t.Run("one section in two cases", func(t *testing.T) {
		got := loadErr(t, minimal+"[reach]\nread_blast_cap = 1\n[Reach]\nmutate_blast_cap = 2\n")
		if w := "reach (line 9)"; !strings.Contains(got, w) {
			t.Errorf("error %q does not contain %q", got, w)
		}
	})
	t.Run("the same variant twice is named once", func(t *testing.T) {
		got := loadErr(t, minimal+"[Reach]\nread_blast_cap = 1\n[Reach]\n")
		if n := strings.Count(got, reasonSpelling); n != 1 {
			t.Errorf("error %q refuses the spelling %d times, want 1", got, n)
		}
	})
}

// A key that matches no schema name in any case is not a case variant and keeps
// the refusal it had.
func TestLoad_KeyThatIsNotACaseVariantKeepsItsRefusal(t *testing.T) {
	for _, tc := range []struct{ name, src, want string }{
		{"a misspelt key", minimal + "[reach]\nMutate_Blast_Caps = 1\n", "an unrecognised key in [reach]"},
		{"an unknown section", minimal + "[Listen]\naddr = 1\n", "an unrecognised key is"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := loadErr(t, tc.src)
			if !strings.Contains(got, tc.want) {
				t.Errorf("error %q does not contain %q", got, tc.want)
			}
			notContains(t, got, reasonSpelling)
		})
	}
	// A removed key in another case is not an accepted key's variant.
	notContains(t, loadErr(t, minimal+"[log]\nFormat = \"json\"\n"), reasonSpelling)
	if got := loadErr(t, minimal+"[log]\nformat = \"json\"\n"); !strings.Contains(got, "log.format") {
		t.Errorf("error %q does not name log.format", got)
	}
}

// Exact spellings are untouched by the check.
func TestLoad_ExactSpellingsLoad(t *testing.T) {
	mustLoad(t, minimal)
	mustLoad(t, minimal+"[reach]\nmutate_blast_cap = 5\n[[approval.rules]]\nname = \"a\"\nrisk_class = \"mutate\"\n")
}
