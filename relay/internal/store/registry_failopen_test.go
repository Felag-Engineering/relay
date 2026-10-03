package store

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/revocation"
)

// These tests are G-E0: the SQLite registry used to hide store errors —
// List() returned nil on a failed ID scan and silently skipped Nodes that
// failed to read — so the Enrollment-Token revocation cascade, which lists
// the registry to find the Nodes a token enrolled, revoked zero (or too few)
// Nodes on a store fault and still reported success. Nodes enrolled with a
// leaked token stayed trusted (invariant 6). They drive the real
// revocation.Service over the real store-backed registry, so the fault is a
// genuine database error rather than a double's say-so.

// quietLogs discards slog output for the test: the paths under test log at
// Error by design, which is noise here, not signal.
func quietLogs(t *testing.T) {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
}

// cascadeOver builds a revocation.Service over reg with an always-succeeding
// token store and recorder, so the registry read is the only fault in play.
func cascadeOver(reg revocation.Registry) (*revocation.Service, *revocation.Denylist) {
	d := revocation.NewDenylist()
	svc := revocation.NewService(d, revocation.NewConnections(), reg, okTokenRevoker{})
	return svc, d
}

type okTokenRevoker struct{}

func (okTokenRevoker) Revoke(context.Context, string) error { return nil }

func okRecorder([]string) error { return nil }

// corruptLastSeen makes nodeID unreadable by getNode (its last_seen no longer
// parses), while leaving it visible to the ID scan — the "one Node fails to
// read" fault List() used to skip silently.
func corruptLastSeen(t *testing.T, st *Store, nodeID string) {
	t.Helper()
	res, err := st.db.Exec(`UPDATE nodes SET last_seen = 'not-a-time' WHERE node_id = ?`, nodeID)
	if err != nil {
		t.Fatalf("corrupt last_seen: %v", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("corrupt last_seen: %d rows affected, want 1", n)
	}
}

func TestRevokeToken_UnreadableRegistryDoesNotReportSuccess(t *testing.T) {
	quietLogs(t)
	st, _ := openTestStore(t)
	reg := st.Registry()
	if _, err := reg.Upsert(registry.Report{NodeID: "node-a", EnrollingTokenID: "tok-leaked"}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	// Every registry read now fails.
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	svc, d := cascadeOver(reg)
	err := svc.RevokeToken(context.Background(), "tok-leaked", okRecorder)
	if err == nil {
		t.Fatal("RevokeToken reported success over an unreadable registry: node-a, enrolled " +
			"under the revoked token, was never seen and is still trusted")
	}
	if !errors.Is(err, revocation.ErrCascadeIncomplete) {
		t.Errorf("RevokeToken error = %v, want errors.Is(err, ErrCascadeIncomplete)", err)
	}
	if errors.Is(err, revocation.ErrCascadeNotRecorded) {
		t.Errorf("RevokeToken error = %v must not claim ErrCascadeNotRecorded (every Node revoked)", err)
	}
	var ic *revocation.IncompleteCascade
	if errors.As(err, &ic) && ic.UnreadableCount != 0 {
		t.Errorf("UnreadableCount = %d, want 0: a failed ID scan cannot name any Node", ic.UnreadableCount)
	}
	if d.IsRevoked("node-a") {
		t.Error("node-a denylisted although the registry could not be read — the test's fault did not take")
	}
}

func TestRevokeToken_UnreadableNodeDoesNotReportSuccess(t *testing.T) {
	quietLogs(t)
	st, _ := openTestStore(t)
	reg := st.Registry()
	for _, id := range []string{"node-a", "node-bad", "node-c"} {
		if _, err := reg.Upsert(registry.Report{NodeID: id, EnrollingTokenID: "tok-leaked"}); err != nil {
			t.Fatalf("upsert %s: %v", id, err)
		}
	}
	corruptLastSeen(t, st, "node-bad")

	svc, d := cascadeOver(reg)
	err := svc.RevokeToken(context.Background(), "tok-leaked", okRecorder)
	if !errors.Is(err, revocation.ErrCascadeIncomplete) {
		t.Fatalf("RevokeToken error = %v, want errors.Is(err, ErrCascadeIncomplete): node-bad "+
			"could not be read, so the cascade cannot claim it revoked every Node", err)
	}
	var ic *revocation.IncompleteCascade
	if !errors.As(err, &ic) {
		t.Fatalf("RevokeToken error = %v, want an *IncompleteCascade", err)
	}
	if ic.UnreadableCount != 1 || len(ic.UnreadableNodeIDs) != 1 || ic.UnreadableNodeIDs[0] != "node-bad" {
		t.Errorf("unreadable = %v (count %d), want exactly [node-bad]: the Nodes that may "+
			"still be trusted must be named", ic.UnreadableNodeIDs, ic.UnreadableCount)
	}
	// Over-denying beats under-denying: the Nodes that were readable are revoked.
	for _, id := range []string{"node-a", "node-c"} {
		if !d.IsRevoked(id) {
			t.Errorf("%s was readable but not denylisted", id)
		}
	}
}

func TestSqliteRegistry_ListChecked_ReportsWhatListHides(t *testing.T) {
	quietLogs(t)

	t.Run("unreadable node", func(t *testing.T) {
		st, _ := openTestStore(t)
		reg := st.Registry()
		for _, id := range []string{"node-a", "node-bad", "node-c"} {
			if _, err := reg.Upsert(registry.Report{NodeID: id}); err != nil {
				t.Fatalf("upsert %s: %v", id, err)
			}
		}
		corruptLastSeen(t, st, "node-bad")

		got, err := reg.ListChecked()
		var une *registry.UnreadableNodesError
		if !errors.As(err, &une) {
			t.Fatalf("ListChecked error = %v, want a *registry.UnreadableNodesError", err)
		}
		if len(une.NodeIDs) != 1 || une.NodeIDs[0] != "node-bad" || une.Scanned != 3 {
			t.Errorf("UnreadableNodesError = {NodeIDs:%v Scanned:%d}, want {[node-bad] 3}", une.NodeIDs, une.Scanned)
		}
		if ids := nodeIDs(got); len(ids) != 2 || ids[0] != "node-a" || ids[1] != "node-c" {
			t.Errorf("ListChecked nodes = %v, want [node-a node-c] (the readable ones)", ids)
		}
		// List's contract is unchanged: it still returns the readable Nodes.
		if ids := nodeIDs(reg.List()); len(ids) != 2 {
			t.Errorf("List nodes = %v, want the 2 readable ones", ids)
		}
	})

	t.Run("closed store", func(t *testing.T) {
		st, _ := openTestStore(t)
		reg := st.Registry()
		if _, err := reg.Upsert(registry.Report{NodeID: "node-a"}); err != nil {
			t.Fatalf("upsert: %v", err)
		}
		if err := st.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		got, err := reg.ListChecked()
		if err == nil {
			t.Fatal("ListChecked on a closed store: want error, got nil")
		}
		if len(got) != 0 {
			t.Errorf("ListChecked nodes = %v, want none", nodeIDs(got))
		}
	})
}

func nodeIDs(ns []registry.Node) []string {
	out := make([]string, 0, len(ns))
	for _, n := range ns {
		out = append(out, n.NodeID)
	}
	return out
}
