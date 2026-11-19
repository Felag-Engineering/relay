package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

var denyRuleRef = jobs.PolicyRuleRef{Pass: "deny", RuleSection: "raw_exec_deny", RuleIndex: 2, RuleLine: 14}

func deniedRecord(i int, rule jobs.PolicyRuleRef) audit.Record {
	r := chainTestRecord(i)
	r.Outcome = jobs.OutcomeDeniedByPolicy
	r.PolicyRule = rule
	return r
}

// insertPreChangeChainedRow writes a chained row the way a binary built before
// the policy columns did: the 31-column list, hashed over a record with no
// rule reference. It is the only way to build that state once the columns are
// part of insertAuditSQL.
func insertPreChangeChainedRow(t *testing.T, db *sql.DB, rec audit.Record, head audit.ChainHead) audit.ChainHead {
	t.Helper()
	p, err := prepareAudit(rec)
	if err != nil {
		t.Fatalf("prepareAudit: %v", err)
	}
	seq := head.Seq + 1
	hash := audit.ComputeChainHash(seq, head.Hash, p.canon)
	args := append([]any{}, p.args[:31]...)
	args = append(args, int64(seq), head.Hash.Hex(), hash.Hex())
	execRaw(t, db, `INSERT INTO audit (`+auditRecordColumnsV1+`, seq, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, args...)
	return audit.ChainHead{Seq: seq, Hash: hash}
}

func openAtSchema37(t *testing.T, name string) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	seedMigrations(t, db, 38)
	return db, path
}

// A trail holding rows written before the policy columns and rows written
// after, with and without a rule reference, verifies end to end.
// Proves EX-70.
func TestVerifyAuditChain_ATrailMixingRowsWrittenBeforeAndAfterThePolicyRuleVerifies(t *testing.T) {
	db, path := openAtSchema37(t, "mixed.db")
	head := audit.ChainHead{Hash: audit.GenesisPrevHash}
	head = insertPreChangeChainedRow(t, db, chainTestRecord(1), head)
	insertPreChangeChainedRow(t, db, deniedRecord(2, jobs.PolicyRuleRef{}), head)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	for _, r := range []audit.Record{deniedRecord(3, denyRuleRef), chainTestRecord(4), deniedRecord(5, jobs.PolicyRuleRef{Pass: "default"})} {
		if err := st.Audit().Append(ctx, r); err != nil {
			t.Fatalf("Append %s: %v", r.ID, err)
		}
	}

	v := verify(t, path)
	if !v.Intact() || v.Head.Seq != 5 || v.Unchained != 0 {
		t.Errorf("verdict = %+v, want an intact chain of 5 rows", v)
	}
}

// Editing a rule reference, or adding one to a row written without, is named.
// Proves EX-70.
func TestVerifyAuditChain_AnEditedRuleReferenceIsNamed(t *testing.T) {
	cases := []struct{ name, id, set string }{
		{"a recorded reference edited", "row01", `policy_rule_line = 99`},
		{"a reference added to a row written without", "row02", `policy_pass = 'deny'`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, path := openTestStore(t)
			ctx := context.Background()
			for _, r := range []audit.Record{deniedRecord(1, denyRuleRef), chainTestRecord(2), chainTestRecord(3)} {
				if err := st.Audit().Append(ctx, r); err != nil {
					t.Fatalf("Append: %v", err)
				}
			}
			withoutAppendOnlyTriggers(t, st.db, func() {
				execRaw(t, st.db, `UPDATE audit SET `+c.set+` WHERE audit_id = ?`, c.id)
			})
			v := verify(t, path)
			if v.Break == nil || v.Break.Reason != audit.BreakHashMismatch || v.Break.AuditID != c.id {
				t.Errorf("break = %+v, want hash_mismatch naming %s", v.Break, c.id)
			}
		})
	}
}

// A verifier run on a store that has the chain but not yet the policy columns
// (right after a package upgrade, before the Relay restarts) still verifies.
// Proves EX-70.
func TestVerifyAuditChain_AStoreWithoutThePolicyRuleColumnsVerifies(t *testing.T) {
	db, path := openAtSchema37(t, "schema37.db")
	head := audit.ChainHead{Hash: audit.GenesisPrevHash}
	head = insertPreChangeChainedRow(t, db, chainTestRecord(1), head)
	insertPreChangeChainedRow(t, db, chainTestRecord(2), head)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	if v := verify(t, path); !v.Intact() || v.Head.Seq != 2 {
		t.Errorf("verdict = %+v, want an intact chain of 2 rows", v)
	}
}

// A store upgrading from before the chain back-fills it before the policy
// columns exist, so the back-fill must not select them. The row appended after
// the upgrade carries a reference and chains onto the back-filled head.
func TestMigration0028_BackfillRunsBeforeThePolicyColumnsExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pre28.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	seedMigrations(t, db, 28, 38)
	insertLegacyAuditRow(t, db, "old-a", "2026-09-21T12:00:01.000000000Z")
	insertLegacyAuditRow(t, db, "old-b", "2026-09-21T12:00:02.000000000Z")
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if v := verify(t, path); !v.Intact() || v.Head.Seq != 2 {
		t.Fatalf("after the upgrade: %+v", v)
	}
	if err := st.Audit().Append(context.Background(), deniedRecord(3, denyRuleRef)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if v := verify(t, path); !v.Intact() || v.Head.Seq != 3 {
		t.Errorf("after a row carrying a reference: %+v", v)
	}
}

// The reference reads back as written through the record reader and the read
// lane, and the absent group reads back as the zero value.
// Proves EX-70.
func TestAudit_PolicyRuleRoundTrips(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	want := map[string]jobs.PolicyRuleRef{
		"none":    {},
		"full":    denyRuleRef,
		"default": {Pass: "default"},
		"zeroes":  {Pass: "deny", RuleSection: "deny"},
	}
	i := 0
	for id, rule := range want {
		r := queryRecord(id, base.Add(time.Duration(i)*time.Second))
		r.Outcome = jobs.OutcomeDeniedByPolicy
		r.PolicyRule = rule
		if err := st.Audit().Append(ctx, r); err != nil {
			t.Fatalf("Append %s: %v", id, err)
		}
		i++
	}

	recs, err := st.Audit().List(ctx)
	if err != nil || len(recs) != len(want) {
		t.Fatalf("List: %v (%d records)", err, len(recs))
	}
	for _, r := range recs {
		if r.PolicyRule != want[r.ID] {
			t.Errorf("List %s: PolicyRule = %+v, want %+v", r.ID, r.PolicyRule, want[r.ID])
		}
	}
	page, err := st.AuditQueries().Query(ctx, audit.Query{}, 0, "")
	if err != nil || len(page.Rows) != len(want) {
		t.Fatalf("Query: %v (%d rows)", err, len(page.Rows))
	}
	for _, r := range page.Rows {
		if r.PolicyRule != want[r.ID] {
			t.Errorf("Query %s: PolicyRule = %+v, want %+v", r.ID, r.PolicyRule, want[r.ID])
		}
	}
}
