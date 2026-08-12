package store

import (
	"reflect"
	"testing"
)

// The regression this exists for: a semicolon inside a migration comment used
// to split the file mid-sentence, handing the remaining prose to SQLite as a
// statement. It failed with a syntax error pointing at an English word, which
// is a long way from "your comment has a semicolon in it".
//
// Migration comments are where the reasoning for a schema change lives, so
// they are precisely where ordinary punctuation turns up.
func TestSplitStatements_SemicolonInACommentIsNotAStatement(t *testing.T) {
	sql := `
-- Two lanes, kept distinct in the schema; blurring them is how an audit trail
-- becomes fiction.
ALTER TABLE audit ADD COLUMN account_id TEXT;

-- A second comment; also with a semicolon.
ALTER TABLE audit ADD COLUMN token_id TEXT;
`
	want := []string{
		"ALTER TABLE audit ADD COLUMN account_id TEXT",
		"ALTER TABLE audit ADD COLUMN token_id TEXT",
	}
	if got := splitStatements(sql); !reflect.DeepEqual(got, want) {
		t.Errorf("splitStatements =\n  %q\nwant\n  %q", got, want)
	}
}

func TestSplitStatements_OrdinaryCases(t *testing.T) {
	cases := []struct {
		label string
		sql   string
		want  []string
	}{
		{"empty", "", nil},
		{"comments only", "-- nothing but prose;\n-- more prose\n", nil},
		{"no trailing semicolon", "SELECT 1", []string{"SELECT 1"}},
		{"blank statements collapse", "SELECT 1;;;\n\n;SELECT 2;", []string{"SELECT 1", "SELECT 2"}},
		{
			"indented comment",
			"    -- indented; still a comment\nSELECT 1;",
			[]string{"SELECT 1"},
		},
		{
			"multi-line statement keeps its shape",
			"CREATE INDEX idx\n    ON audit (account_id) WHERE account_id IS NOT NULL;",
			[]string{"CREATE INDEX idx\n    ON audit (account_id) WHERE account_id IS NOT NULL"},
		},
	}
	for _, c := range cases {
		got := splitStatements(c.sql)
		if len(got) == 0 && len(c.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("[%s] splitStatements = %q, want %q", c.label, got, c.want)
		}
	}
}

// The documented remaining limitation, pinned so it stays a known constraint
// rather than becoming a surprise: a trailing comment on the same line as SQL
// is NOT stripped, because telling it apart from a "--" inside a string
// literal needs a tokenizer. Dropping a line that is unambiguously a comment
// cannot corrupt a statement; guessing at one that might be a literal can.
func TestSplitStatements_TrailingCommentsAreNotStripped(t *testing.T) {
	got := splitStatements("SELECT 1; -- a trailing note\n")
	want := []string{"SELECT 1", "-- a trailing note"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("splitStatements = %q, want %q — the trailing-comment limitation is documented on splitStatements", got, want)
	}
}

// Every shipped migration must still split into statements SQLite accepts.
// openTestStore runs the whole set, so this is really an assertion that the
// stripping did not eat anything load-bearing.
func TestMigrations_AllApplyCleanly(t *testing.T) {
	st, _ := openTestStore(t)
	if st == nil {
		t.Fatal("openTestStore returned nil")
	}
}
