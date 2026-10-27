package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/enroll"
)

// legacyFleet seeds the schema at version 32 (everything but migration 33) with
// the accounts, tokens, Nodes and labels the upgrade tests share, and returns
// the database path. Two Accounts minted tokens: alice (human) and bot
// (machine). "ghost" names no Account.
//
//	tok-human    alice  scope env=prod, role=web, node-id=x, tier=pci/1, plus a non-relay: entry; live
//	tok-clean    alice  scope env=prod, role=web; live, enrolled nothing
//	tok-garbled  alice  scope that is not JSON
//	tok-machine  bot    scope env=prod; live
//	tok-ghost    ghost  scope env=x; live
//
//	node-h1  tok-human  relay env=prod role=web tier=pci/1 node-id=node-h1
//	node-h2  tok-human  relay env=prod node-id=other; already tag env=staging
//	node-m   tok-machine relay env=prod
//	node-g   tok-ghost   relay env=x
func legacyFleet(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "schema32.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(1)
	seedMigrations(t, db, 33)

	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("seed %q: %v", query, err)
		}
	}
	at := formatTime(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	for _, a := range [][]string{
		{"acct-alice", "alice", "human"},
		{"acct-bot", "bot", "machine"},
	} {
		exec(`INSERT INTO accounts (id, name, name_normalized, kind, role, created_at) VALUES (?, ?, ?, ?, 'admin', ?)`,
			a[0], a[1], a[1], a[2], at)
	}

	future := formatTime(time.Now().Add(24 * time.Hour))
	hash := sha256.Sum256([]byte("known-secret"))
	for _, tok := range [][]string{
		{"tok-human", `["relay:env=prod","relay:role=web","relay:node-id=x","relay:tier=pci/1","node:secret=hunter2"]`, "alice:admin"},
		{"tok-clean", `["relay:env=prod","relay:role=web"]`, "alice:admin"},
		{"tok-garbled", `not json`, "alice:admin"},
		{"tok-machine", `["relay:env=prod"]`, "bot:admin"},
		{"tok-ghost", `["relay:env=x"]`, "ghost:admin"},
	} {
		exec(`INSERT INTO tokens (token_id, secret_hash, scope, expires_at, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?)`,
			tok[0], hash[:], tok[1], future, at, tok[2])
	}

	for _, n := range [][]string{
		{"node-h1", "tok-human"}, {"node-h2", "tok-human"}, {"node-m", "tok-machine"}, {"node-g", "tok-ghost"},
	} {
		exec(`INSERT INTO nodes (node_id, cert_fingerprint, hostname, os, kernel, arch, enrolling_token_id, policy_fingerprint, last_seen)
			VALUES (?, 'fp', 'h', 'linux', 'k', 'amd64', ?, '', ?)`, n[0], n[1], at)
	}
	for _, l := range [][]string{
		{"node-h1", "env", "prod"}, {"node-h1", "role", "web"}, {"node-h1", "tier", "pci/1"}, {"node-h1", "node-id", "node-h1"},
		{"node-h2", "env", "prod"}, {"node-h2", "node-id", "other"},
		{"node-m", "env", "prod"},
		{"node-g", "env", "x"},
	} {
		exec(`INSERT INTO relay_labels (node_id, key, value) VALUES (?, ?, ?)`, l[0], l[1], l[2])
	}
	exec(`INSERT INTO tag_labels (node_id, key, value) VALUES ('node-h2', 'env', 'staging')`)

	// A few chained audit rows already on the trail, written the way the Relay
	// writes them, so the migration must append onto a live chain.
	var prepared []preparedAudit
	for _, id := range []string{"audit-pre-1", "audit-pre-2"} {
		p, err := prepareAudit(audit.Record{
			ID: id, Timestamp: time.Date(2026, 9, 1, 0, 0, 1, 0, time.UTC),
			Kind: audit.KindTokenMint, Principal: "alice:admin", Reason: "token_id=tok-human",
		})
		if err != nil {
			t.Fatalf("prepareAudit: %v", err)
		}
		prepared = append(prepared, p)
	}
	if err := insertChained(ctx, db, prepared); err != nil {
		t.Fatalf("insertChained: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close seed db: %v", err)
	}
	return path
}

// logLines decodes a JSON log buffer into one map per line.
func logLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// tagsOf reads a Node's tags straight from the table.
func tagsOnNode(t *testing.T, st *Store, nodeID string) map[string]string {
	t.Helper()
	rows, err := st.db.QueryContext(context.Background(), `SELECT key, value FROM tag_labels WHERE node_id = ?`, nodeID)
	if err != nil {
		t.Fatalf("read tags: %v", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			t.Fatalf("scan tag: %v", err)
		}
		out[k] = v
	}
	return out
}

// TestMigration0033_ScopeLabelsBecomeTagsAndTheAuditChainVerifies drives the real
// upgrade: a database at schema 32 holds relay: labels an earlier release
// stamped from token scopes. Opening it copies those a human Account's token
// stamped to tags, attributed to that Account, lists every Node it could not
// copy and why, deletes nothing, and leaves the audit chain intact.
//
// Proves EN-45.
func TestMigration0033_ScopeLabelsBecomeTagsAndTheAuditChainVerifies(t *testing.T) {
	ctx := context.Background()
	path := legacyFleet(t)

	var logBuf bytes.Buffer
	st, err := Open(path, WithLogger(slog.New(slog.NewJSONHandler(&logBuf, nil))))
	if err != nil {
		t.Fatalf("Open on a schema-32 database: %v", err)
	}

	// node-h1: env and role copied; tier declined by the tag predicate;
	// node-id naming the Node itself is skipped silently.
	if got := tagsOnNode(t, st, "node-h1"); len(got) != 2 || got["env"] != "prod" || got["role"] != "web" {
		t.Errorf("node-h1 tags = %v, want env=prod role=web", got)
	}
	// node-h2: the existing tag is never overwritten.
	if got := tagsOnNode(t, st, "node-h2"); len(got) != 1 || got["env"] != "staging" {
		t.Errorf("node-h2 tags = %v, want its own env=staging untouched", got)
	}
	// A machine Account's token, and one from no Account, copy nothing.
	for _, id := range []string{"node-m", "node-g"} {
		if got := tagsOnNode(t, st, id); len(got) != 0 {
			t.Errorf("%s tags = %v, want none", id, got)
		}
	}

	// relay_labels is copied from, never changed.
	var relayRows int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM relay_labels`).Scan(&relayRows); err != nil {
		t.Fatal(err)
	}
	if relayRows != 8 {
		t.Errorf("relay_labels rows = %d, want the 8 seeded, none deleted", relayRows)
	}

	// Every copy is one tag_write record attributed to the minting Account.
	rows, err := st.db.QueryContext(ctx,
		`SELECT node_id, principal, account_id, account_name, account_role, reason FROM audit WHERE kind = 'tag_write' ORDER BY node_id, reason`)
	if err != nil {
		t.Fatalf("read tag_write records: %v", err)
	}
	type rec struct{ node, principal, id, name, role, reason string }
	var recs []rec
	for rows.Next() {
		var r rec
		if err := rows.Scan(&r.node, &r.principal, &r.id, &r.name, &r.role, &r.reason); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	rows.Close()
	if len(recs) != 2 {
		t.Fatalf("tag_write records = %+v, want exactly the two copies", recs)
	}
	for _, r := range recs {
		if r.node != "node-h1" || r.principal != "alice:admin" || r.id != "acct-alice" || r.name != "alice" || r.role != "admin" {
			t.Errorf("record %+v is not the minting Account's act on node-h1", r)
		}
		if !strings.Contains(r.reason, "upgrade") || !strings.Contains(r.reason, "tok-human") || !strings.Contains(r.reason, "old=(none)") {
			t.Errorf("record reason %q does not carry the upgrade provenance", r.reason)
		}
	}

	// The token rows carry the minting Account and the converted tags.
	tok, err := st.Tokens().ByID(ctx, "tok-human")
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if !tok.CreatedByHuman || tok.CreatedByAccountID != "acct-alice" {
		t.Errorf("tok-human minter = %q human=%v", tok.CreatedByAccountID, tok.CreatedByHuman)
	}
	if got := strings.Join(tok.InitialTags, ","); got != "tag:env=prod,tag:role=web" {
		t.Errorf("tok-human initial tags = %q, want its convertible scope entries sorted", got)
	}
	machine, err := st.Tokens().ByID(ctx, "tok-machine")
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if machine.CreatedByHuman || machine.CreatedByAccountID != "acct-bot" || len(machine.InitialTags) != 0 {
		t.Errorf("tok-machine = %+v, want a machine minter and no initial tags", machine)
	}

	// The log lists what a person must tag by hand, and why.
	listed := map[string]string{}
	var sawUnreadable, sawDropped, sawRemint bool
	for _, l := range logLines(t, &logBuf) {
		msg, _ := l["msg"].(string)
		switch {
		case strings.Contains(msg, "were not copied to tags"):
			listed[l["node_id"].(string)+"/"+l["reason"].(string)] = "x"
		case strings.Contains(msg, "scope could not be read"):
			sawUnreadable = l["token_id"] == "tok-garbled"
		case strings.Contains(msg, "scope entries were not converted"):
			sawDropped = l["token_id"] == "tok-human"
		case strings.Contains(msg, "re-mint it from a human Account"):
			if l["token_id"] == "tok-machine" || l["token_id"] == "tok-ghost" {
				sawRemint = true
			}
		}
	}
	for _, want := range []string{
		"node-h1/declined",
		"node-h2/tag_exists",
		"node-h2/node_id_mismatch",
		"node-m/minted_by_machine_or_unknown_account",
		"node-g/minted_by_machine_or_unknown_account",
	} {
		if _, ok := listed[want]; !ok {
			t.Errorf("upgrade log does not list %s; listed: %v", want, listed)
		}
	}
	if !sawUnreadable || !sawDropped || !sawRemint {
		t.Errorf("per-token warnings: unreadable=%v dropped=%v re-mint=%v, want all", sawUnreadable, sawDropped, sawRemint)
	}
	if strings.Contains(logBuf.String(), "pci/1") {
		t.Error("the upgrade log carries a label value")
	}
	if strings.Contains(logBuf.String(), "hunter2") {
		t.Error("the upgrade log carries the value of a dropped non-relay: scope entry")
	}

	// The chain verifies across the migration: the copies append onto it.
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	verdict, err := VerifyAuditChain(ctx, path, nil)
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if verdict.Break != nil || verdict.Unchained != 0 {
		t.Errorf("audit chain after the migration: break=%+v unchained=%d", verdict.Break, verdict.Unchained)
	}
	if verdict.Rows != 4 {
		t.Errorf("chained rows = %d, want the 2 earlier plus the 2 copies", verdict.Rows)
	}
}

// TestMigration0033_UnusedHumanTokenEnrollsWithItsScopeAsTags checks that a token
// a human Account minted and nothing has used yet hands enrollment its scope as
// initial tags, attributed to that Account, and that a machine Account's token
// hands none.
//
// Proves EN-45.
func TestMigration0033_UnusedHumanTokenEnrollsWithItsScopeAsTags(t *testing.T) {
	ctx := context.Background()
	st, err := Open(legacyFleet(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := enroll.NewService(st.Tokens())

	grant, err := svc.Validate(ctx, "tok-clean.known-secret")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := strings.Join(grant.InitialTags, ","); got != "tag:env=prod,tag:role=web" {
		t.Errorf("initial tags = %q, want the scope as tags", got)
	}
	want := enroll.MintedBy{AccountID: "acct-alice", Account: "alice", Role: "admin", Human: true}
	if grant.MintedBy != want {
		t.Errorf("MintedBy = %+v, want %+v", grant.MintedBy, want)
	}

	machineGrant, err := svc.Validate(ctx, "tok-machine.known-secret")
	if err != nil {
		t.Fatalf("Validate machine token: %v", err)
	}
	if len(machineGrant.InitialTags) != 0 || machineGrant.MintedBy.Human {
		t.Errorf("machine token grant = %+v, want no tags and no human minter", machineGrant)
	}
}

// TestMigration0033_UsedHumanTokenIsNotConvertedAndIsListed checks that a token a
// human Account minted and that has already enrolled a Node keeps its legacy
// scope unconverted, and that the upgrade says so for one that could still
// enroll, naming the token and never a label value. An unused token beside it
// still converts.
//
// Proves EN-45.
func TestMigration0033_UsedHumanTokenIsNotConvertedAndIsListed(t *testing.T) {
	ctx := context.Background()
	path := legacyFleet(t)

	seed, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	seed.SetMaxOpenConns(1)
	at := formatTime(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	hash := sha256.Sum256([]byte("known-secret"))
	for _, tok := range []struct {
		id      string
		expires any
		revoked int
		maxUses int
		uses    int
	}{
		{"tok-used", formatTime(time.Now().Add(24 * time.Hour)), 0, 0, 3},
		{"tok-used-exhausted", formatTime(time.Now().Add(24 * time.Hour)), 0, 1, 1},
		{"tok-used-expired", formatTime(time.Now().Add(-time.Hour)), 0, 0, 1},
		{"tok-used-revoked", formatTime(time.Now().Add(24 * time.Hour)), 1, 0, 1},
	} {
		if _, err := seed.ExecContext(ctx,
			`INSERT INTO tokens (token_id, secret_hash, scope, expires_at, created_at, created_by, revoked, max_uses, uses)
			VALUES (?, ?, '["relay:env=hunter2"]', ?, ?, 'alice:admin', ?, ?, ?)`,
			tok.id, hash[:], tok.expires, at, tok.revoked, tok.maxUses, tok.uses); err != nil {
			t.Fatalf("seed %s: %v", tok.id, err)
		}
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("close seed db: %v", err)
	}

	var logBuf bytes.Buffer
	st, err := Open(path, WithLogger(slog.New(slog.NewJSONHandler(&logBuf, nil))))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	for _, id := range []string{"tok-used", "tok-used-exhausted", "tok-used-expired", "tok-used-revoked"} {
		tok, err := st.Tokens().ByID(ctx, id)
		if err != nil {
			t.Fatalf("ByID %s: %v", id, err)
		}
		if len(tok.InitialTags) != 0 {
			t.Errorf("%s initial tags = %v, want none: a used token is not converted", id, tok.InitialTags)
		}
	}
	clean, err := st.Tokens().ByID(ctx, "tok-clean")
	if err != nil {
		t.Fatalf("ByID tok-clean: %v", err)
	}
	if got := strings.Join(clean.InitialTags, ","); got != "tag:env=prod,tag:role=web" {
		t.Errorf("tok-clean initial tags = %q, want the unused token still converted", got)
	}

	warned := map[string]bool{}
	for _, l := range logLines(t, &logBuf) {
		if msg, _ := l["msg"].(string); strings.Contains(msg, "a used Enrollment Token keeps a scope") {
			id, _ := l["token_id"].(string)
			warned[id] = true
		}
	}
	if len(warned) != 1 || !warned["tok-used"] {
		t.Errorf("used-token warnings for %v, want exactly tok-used", warned)
	}
	if strings.Contains(logBuf.String(), "hunter2") {
		t.Error("the upgrade log carries a scope value")
	}
}
