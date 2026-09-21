package store

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// orderRecord builds a Record that EVERY by-key reader matches, so one
// fixture can be read back through all seven of them.
func orderRecord(id string, ts time.Time) audit.Record {
	return audit.Record{
		ID:        id,
		Timestamp: ts,
		Kind:      audit.KindDispatch,
		Principal: "gleipnir:operator",
		Attribution: audit.Attribution{
			Verified: audit.Verified{AccountID: "acct-1", AccountName: "gleipnir", Role: "operator"},
			Asserted: audit.Asserted{OnBehalfOf: "ops-team"},
		},
		Selector:      "relay:env=prod",
		JobID:         "job-1",
		NodeID:        "node-1",
		ActionKind:    "operation",
		OperationName: "service.restart",
		Outcome:       jobs.OutcomeSuccess,
		ApprovalID:    "appr-1",
		GrantID:       "grant-1",
	}
}

// auditReaders is every by-key reader on audit.Repository, each called with
// the key orderRecord sets, so a tie-break added to six of seven fails here.
func auditReaders(repo audit.Repository) []struct {
	name string
	read func(context.Context) ([]audit.Record, error)
} {
	return []struct {
		name string
		read func(context.Context) ([]audit.Record, error)
	}{
		{"List", repo.List},
		{"ByJob", func(ctx context.Context) ([]audit.Record, error) { return repo.ByJob(ctx, "job-1") }},
		{"ByNode", func(ctx context.Context) ([]audit.Record, error) { return repo.ByNode(ctx, "node-1") }},
		{"ByAccount", func(ctx context.Context) ([]audit.Record, error) { return repo.ByAccount(ctx, "acct-1") }},
		{"ByApproval", func(ctx context.Context) ([]audit.Record, error) { return repo.ByApproval(ctx, "appr-1") }},
		{"ByGrant", func(ctx context.Context) ([]audit.Record, error) { return repo.ByGrant(ctx, "grant-1") }},
		{"ByOnBehalfOf", func(ctx context.Context) ([]audit.Record, error) { return repo.ByOnBehalfOf(ctx, "ops-team") }},
	}
}

func recordIDs(records []audit.Record) []string {
	ids := make([]string, len(records))
	for i, r := range records {
		ids[i] = r.ID
	}
	return ids
}

// TestAudit_SameTimestampRowsComeBackInIDOrder is #656 defect 1, against the
// real repository: rows sharing a ts must come back in audit_id order, the
// same order on every read, through every by-key reader.
//
// A dispatch fan-out makes this the common case, not a corner one: every
// per-Node Record copies one clock reading, so an entire fan-out shares a ts.
func TestAudit_SameTimestampRowsComeBackInIDOrder(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	repo := st.Audit()

	ts := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	appended := []string{"zzz", "aaa", "mmm"}
	for _, id := range appended {
		if err := repo.Append(ctx, orderRecord(id, ts)); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}
	want := []string{"aaa", "mmm", "zzz"}

	for _, reader := range auditReaders(repo) {
		t.Run(reader.name, func(t *testing.T) {
			records, err := reader.read(ctx)
			if err != nil {
				t.Fatalf("%s: %v", reader.name, err)
			}
			got := recordIDs(records)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s returned %v, want %v — ORDER BY ts has no audit_id tie-break, so rows sharing a timestamp come back in arbitrary order (#656)", reader.name, got, want)
			}
		})
	}
}

// TestAudit_ChronologicalOrderAcrossFractionalWidths is #656 defect 2: ts is
// TEXT, so ORDER BY on it is a byte comparison, and RFC3339Nano trims
// trailing zeros — which put a whole-second row AFTER the .5 row in the same
// second. Appended scrambled, read back chronologically.
func TestAudit_ChronologicalOrderAcrossFractionalWidths(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	repo := st.Audit()

	base := time.Date(2026, 9, 21, 12, 0, 1, 0, time.UTC)
	fixtures := []struct {
		id     string
		offset time.Duration
	}{
		{"half", 500 * time.Millisecond},
		{"whole", 0},
		{"halfish", 500100 * time.Microsecond},
		{"nano", 1 * time.Nanosecond},
		{"ninedigits", 123456789 * time.Nanosecond},
	}
	// Appended in the order above, which is deliberately not chronological.
	for _, f := range fixtures {
		if err := repo.Append(ctx, orderRecord(f.id, base.Add(f.offset))); err != nil {
			t.Fatalf("append %s: %v", f.id, err)
		}
	}
	want := []string{"whole", "nano", "ninedigits", "half", "halfish"}

	for _, reader := range auditReaders(repo) {
		t.Run(reader.name, func(t *testing.T) {
			records, err := reader.read(ctx)
			if err != nil {
				t.Fatalf("%s: %v", reader.name, err)
			}
			got := recordIDs(records)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s returned %v, want %v — ts is TEXT and RFC3339Nano trims trailing zeros, so a shorter fraction sorts after a longer one (#656)", reader.name, got, want)
			}
		})
	}
}

// TestAuditSQL_EveryOrderByTsCarriesTheTieBreak is the structural guard: no
// audit ORDER BY in this package may be spelled any way but the two the trail
// depends on.
//
// WHAT IT COVERS, EXACTLY: a literal "ORDER BY ts" appearing in a Go string
// constant in a NON-TEST file of package store — every such file, found by
// reading the package directory, not a list of file names. A new by-key
// reader added later most plausibly lives in a NEW FILE, which is precisely
// what a two-file scan would miss.
//
// WHAT IT DOES NOT COVER, said plainly so nobody reads more into it. It sees
// only the literal "ORDER BY ts", SPELLED EXACTLY, case and spacing included:
// a lowercase "order by ts", a double space, "ORDER BY audit_id" alone or an
// "ORDER BY rowid" all pass green, because each is either not this clause or
// not this spelling of it. Nor does it see an ORDER BY assembled by
// concatenating across literals ("ORDER BY ts" + dir); a reader that calls
// db.QueryContext with NO ORDER BY at all, which is invisible to both this
// scan and sqliteAudit.query's refactor; or an audit reader added in a
// different package. sqliteAudit.query does not make a bare clause
// unspellable either — a caller passing its own ORDER BY gets a RUNTIME SQL
// syntax error, not a compile error.
//
// What it does cover is the mistake that actually happened here twice: a
// hand-written audit ORDER BY, in this package, missing the tie-break or
// spelling it with the directions mismatched.
//
// _test.go files are skipped BECAUSE THEY MUST BE: this file holds both
// accepted spellings as its own expectations, and audit_ts_migration_test.go
// writes legacy fixture rows with raw SQL. Scanning tests would make the
// guard assert against itself.
func TestAuditSQL_EveryOrderByTsCarriesTheTieBreak(t *testing.T) {
	// Held here, NOT read from auditOrderAsc/auditOrderDesc: a guard that
	// took its expectations from the code it guards moves whenever that code
	// does. The drift assertion at the end is what ties the two together.
	const (
		needle   = "ORDER BY ts"
		wantAsc  = "ORDER BY ts, audit_id"
		wantDesc = "ORDER BY ts DESC, audit_id DESC"
	)

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
	scanned, occurrences := 0, 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		// Parsed rather than grepped so only STRING LITERALS are examined.
		// Prose mentioning "ORDER BY ts" — 0021's migration comment does, and
		// so do two comments in auditquery.go — is not a BasicLit and cannot
		// false-positive.
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parser.ParseFile(%s): %v", path, err)
		}
		scanned++

		ast.Inspect(file, func(n ast.Node) bool {
			lit, isLit := n.(*ast.BasicLit)
			if !isLit || lit.Kind != token.STRING {
				return true
			}
			v, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			for i := 0; i < len(v); {
				j := strings.Index(v[i:], needle)
				if j < 0 {
					break
				}
				i += j
				occurrences++

				clause := v[i:]
				if k := strings.Index(clause, " LIMIT"); k >= 0 {
					clause = clause[:k]
				}
				clause = strings.TrimSpace(clause)
				// EQUALITY against exactly two alternatives, never a prefix
				// or a regex with independent optional DESCs. The mixed
				// "ORDER BY ts DESC, audit_id" must be as red as a bare
				// "ORDER BY ts": auditquery.go's keyset predicate presumes
				// audit_id DESC, and a mismatch there is a variant of #656
				// rather than a cosmetic one.
				if clause != wantAsc && clause != wantDesc {
					t.Errorf("%s:%d: audit ORDER BY clause is %q — it must be exactly %q or %q. A bare ts sorts rows sharing a timestamp arbitrarily; a mixed ASC/DESC pair breaks auditquery.go's keyset predicate (ts < ? OR (ts = ? AND audit_id < ?)), which skips or repeats every row sharing a timestamp with a page boundary (#656). Use auditOrderAsc/auditOrderDesc.",
						name, fset.Position(lit.Pos()).Line, clause, wantAsc, wantDesc)
				}
				i += len(needle)
			}
			return true
		})
	}

	// Liveness. A directory scan that finds nothing passes vacuously, which is
	// the same failure class as scanning the wrong files one level up.
	if occurrences < 2 {
		t.Errorf("scanned %d non-test .go files in %s and found %d %q occurrences, want at least 2 — the two audit order constants are in this package; if the audit readers moved out of it, move this guard with them rather than letting it pass vacuously (#656)",
			scanned, dir, occurrences, needle)
	}

	// Drift. The production constants must be the two spellings this guard
	// accepts — otherwise editing one silently redefines what is allowed.
	if auditOrderAsc != wantAsc {
		t.Errorf("auditOrderAsc = %q, want %q — this guard holds its own literal alternatives on purpose; changing the production constant must not redefine what the guard accepts (#656)", auditOrderAsc, wantAsc)
	}
	if auditOrderDesc != wantDesc {
		t.Errorf("auditOrderDesc = %q, want %q — this guard holds its own literal alternatives on purpose; changing the production constant must not redefine what the guard accepts (#656)", auditOrderDesc, wantDesc)
	}
}

// TestAudit_StoredTimestampIsFixedWidth asserts the WRITE path against the
// database, using the same canonical GLOB migration 0024's skip gate uses —
// so the writer and the migration cannot disagree about what "already
// converted" means.
//
// ts is read back through CAST(...AS TEXT) on purpose: a direct scan of the
// TIMESTAMP-declared column goes through the driver's text -> time.Time ->
// trimmed RFC3339Nano round trip and would report 20 characters for a
// perfectly stored 30-character value (#656 finding 4).
func TestAudit_StoredTimestampIsFixedWidth(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()

	for _, ts := range []time.Time{
		time.Date(2026, 9, 21, 12, 0, 1, 0, time.UTC),
		time.Date(2026, 9, 21, 12, 0, 2, 1, time.UTC),
		time.Date(2026, 9, 21, 12, 0, 3, 123456789, time.UTC),
		time.Date(2026, 9, 21, 12, 0, 4, 999999999, time.UTC),
	} {
		id := ts.Format("id-150405.000000000")
		if err := st.Audit().Append(ctx, orderRecord(id, ts)); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}

		var stored string
		var length, canonical int
		if err := st.db.QueryRowContext(ctx,
			`SELECT CAST(ts AS TEXT), length(ts), ts GLOB ? FROM audit WHERE audit_id = ?`,
			auditTSCanonicalGlob, id).Scan(&stored, &length, &canonical); err != nil {
			t.Fatalf("read back %s: %v", id, err)
		}
		if length != 30 || canonical != 1 {
			t.Errorf("stored ts is %q (len %d, canonical-GLOB match %v) — migration 0024's ordering holds only if every written ts is exactly 30 chars, 9 fractional digits, UTC Z", stored, length, canonical == 1)
		}
	}
}

// TestAudit_TimestampRoundTripsUnchanged pins that the representation change
// is invisible above the store: Record.Timestamp in equals Record.Timestamp
// out, at every fractional width.
func TestAudit_TimestampRoundTripsUnchanged(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()

	cases := []struct {
		id string
		ts time.Time
	}{
		{"whole", time.Date(2026, 9, 21, 12, 0, 1, 0, time.UTC)},
		{"one-nano", time.Date(2026, 9, 21, 12, 0, 2, 1, time.UTC)},
		{"nine-digits", time.Date(2026, 9, 21, 12, 0, 3, 123456789, time.UTC)},
		{"all-nines", time.Date(2026, 9, 21, 12, 0, 4, 999999999, time.UTC)},
	}
	for _, c := range cases {
		if err := st.Audit().Append(ctx, orderRecord(c.id, c.ts)); err != nil {
			t.Fatalf("append %s: %v", c.id, err)
		}
	}

	records, err := st.Audit().List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got := map[string]time.Time{}
	for _, r := range records {
		got[r.ID] = r.Timestamp
	}
	for _, c := range cases {
		if !got[c.id].Equal(c.ts) {
			t.Errorf("Timestamp round-tripped %v -> %v — the representation change must be invisible above the store", c.ts, got[c.id])
		}
	}
}
