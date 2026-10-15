package main

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

type fakeEnv struct {
	euid, owner int
}

func (f *fakeEnv) Geteuid() int { return f.euid }
func (f *fakeEnv) FileOwner(path string) (int, bool, error) {
	if _, err := os.Stat(path); err != nil {
		return 0, false, err
	}
	return f.owner, true, nil
}

// seeded builds a store of n rows and returns its path and the head after row
// anchorAt. The Store is closed, so the file is quiescent.
func seeded(t *testing.T, n, anchorAt int) (path string, anchor audit.ChainHead) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "relay.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= n; i++ {
		r := audit.Record{ID: fmt.Sprintf("row%02d", i), Timestamp: time.Date(2026, 10, 7, 12, 0, i, 0, time.UTC), Kind: audit.KindDispatch, Reason: "r"}
		if err := st.Audit().Append(context.Background(), r); err != nil {
			t.Fatal(err)
		}
		if i == anchorAt {
			if anchor, err = st.AuditChain().ChainHead(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	return path, anchor
}

func rawExec(t *testing.T, path string, stmts ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
}

func runCLI(t *testing.T, env *fakeEnv, args ...string) (code int, out, errOut string) {
	t.Helper()
	var o, e bytes.Buffer
	code = run(args, &o, &e, env)
	return code, o.String(), e.String()
}

var ownerEnv = func() *fakeEnv { return &fakeEnv{euid: 1000, owner: 1000} }

func TestRun_IntactChain(t *testing.T) {
	path, _ := seeded(t, 3, 0)
	code, out, _ := runCLI(t, ownerEnv(), "-store", path)
	if code != 0 || !strings.Contains(out, "audit chain intact: rows=3 head_seq=3") || !strings.Contains(out, "anchors_checked=0") {
		t.Errorf("code=%d out=%q", code, out)
	}
}

func TestRun_CorrectAnchor(t *testing.T) {
	path, a := seeded(t, 4, 2)
	code, out, _ := runCLI(t, ownerEnv(), "-store", path, "-expect", fmt.Sprintf("%d:%s", a.Seq, a.Hash.Hex()))
	if code != 0 || !strings.Contains(out, "anchors_checked=1") {
		t.Errorf("code=%d out=%q", code, out)
	}
}

func TestRun_TamperedRowIsNamed(t *testing.T) {
	path, _ := seeded(t, 3, 0)
	rawExec(t, path, `DROP TRIGGER audit_append_only_no_update`, `UPDATE audit SET reason = 'x' WHERE audit_id = 'row02'`)
	code, out, _ := runCLI(t, ownerEnv(), "-store", path)
	if code != 1 || !strings.Contains(out, `audit_id="row02"`) || !strings.Contains(out, "seq=2") {
		t.Errorf("code=%d out=%q", code, out)
	}
}

func TestRun_EscapesDatabaseText(t *testing.T) {
	path, _ := seeded(t, 3, 0)
	evil := "x\x1b[2J\x1b]0;pwned\x07\rspoof"
	rawExec(t, path, `DROP TRIGGER audit_append_only_no_update`,
		`UPDATE audit SET audit_id = '`+evil+`' WHERE audit_id = 'row02'`)
	code, out, _ := runCLI(t, ownerEnv(), "-store", path)
	if code != 1 {
		t.Fatalf("code=%d out=%q", code, out)
	}
	if strings.ContainsAny(out, "\x1b\x07\r") {
		t.Errorf("raw control bytes reached the output: %q", out)
	}
	if !strings.Contains(out, `\x1b[2J`) {
		t.Errorf("escaped audit_id missing from output: %q", out)
	}
}

func TestRun_TailTruncationPastAnchor(t *testing.T) {
	path, a := seeded(t, 4, 3)
	rawExec(t, path, `DROP TRIGGER audit_append_only_no_delete`, `DELETE FROM audit WHERE seq >= 3`)
	code, out, _ := runCLI(t, ownerEnv(), "-store", path, "-expect", fmt.Sprintf("%d:%s", a.Seq, a.Hash.Hex()))
	if code != 1 || !strings.Contains(out, string(audit.BreakAnchorBeyondHead)) {
		t.Errorf("code=%d out=%q", code, out)
	}
}

func TestRun_UnchainedOnlyIsExit3(t *testing.T) {
	path, _ := seeded(t, 2, 0)
	rawExec(t, path, `INSERT INTO audit (audit_id, ts, kind, principal, selector, job_id, action_kind, outcome)
		VALUES ('stray', '2026-10-07T12:00:00.000000000Z', 'dispatch', 'p', 's', 'j', 'operation', 0)`)
	code, out, _ := runCLI(t, ownerEnv(), "-store", path)
	if code != 3 || !strings.Contains(out, `first audit_id="stray"`) {
		t.Errorf("code=%d out=%q", code, out)
	}
}

func TestRun_UsageAndOpenErrorsAreExit2(t *testing.T) {
	path, _ := seeded(t, 1, 0)
	h := strings.Repeat("a", 64)
	for name, args := range map[string][]string{
		"no -store":         {},
		"missing file":      {"-store", filepath.Join(t.TempDir(), "absent.db")},
		"malformed -expect": {"-store", path, "-expect", "nonsense"},
		"stray argument":    {"-store", path, "extra"},
		"zero seq":          {"-store", path, "-expect", "0:" + h},
	} {
		if code, _, _ := runCLI(t, ownerEnv(), args...); code != 2 {
			t.Errorf("%s: code = %d, want 2", name, code)
		}
	}
}

func TestRun_RefusesToOpenAsAnotherUser(t *testing.T) {
	path, _ := seeded(t, 1, 0)
	dir := filepath.Dir(path)
	before, _ := os.ReadDir(dir)

	code, _, errOut := runCLI(t, &fakeEnv{euid: 0, owner: 10001}, "-store", path)
	if code != 2 || !strings.Contains(errOut, "refusing to open") || !strings.Contains(errOut, "owned by uid 10001") {
		t.Errorf("code=%d stderr=%q", code, errOut)
	}
	after, _ := os.ReadDir(dir)
	if len(after) != len(before) {
		t.Errorf("the refused run changed the directory: %d files before, %d after", len(before), len(after))
	}
	if _, err := os.Stat(path + "-shm"); err == nil {
		if _, err := os.Stat(path + "-wal"); err != nil {
			t.Error("a -shm exists without -wal after a refused run")
		}
	}
}
