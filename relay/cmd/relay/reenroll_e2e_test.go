// Package main: reenroll_e2e_test.go proves EN-16 through the real composition root and the
// SQLite store: a second enrollment is a new Node, never a merge with an earlier record.
// bootServer, persistTestConfig and dialTLS are shared with revocation_persist_e2e_test.go.
package main

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/registry"
	"google.golang.org/grpc/test/bufconn"
)

// TestEnroll_SecondEnrollmentIsANewNode: enrolling again, under a token that is valid, gives a
// new Node ID and a second record, and leaves the earlier record exactly as it was. Both
// enrollments use the same hostname on purpose: nothing matches by host.
//
// Proves EN-16, NC-31.
func TestEnroll_SecondEnrollmentIsANewNode(t *testing.T) {
	boot := func(t *testing.T) (context.Context, *bufconn.Listener, *appDeps) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		t.Cleanup(cancel)
		lis, deps, srv := bootServer(t, persistTestConfig(t))
		t.Cleanup(func() { deps.store.Close() })
		t.Cleanup(srv.Stop)
		return ctx, lis, deps
	}

	// requireNewNode holds the shared assertions after the second enrollment.
	requireNewNode := func(t *testing.T, deps *appDeps, oldID, newID, tokenID string, old registry.Node, wantOldRevoked bool) {
		t.Helper()
		if newID == "" || newID == oldID {
			t.Fatalf("new Node ID = %q, old = %q; want a new, non-empty ID", newID, oldID)
		}
		var ids []string
		for _, n := range deps.registry.List() {
			ids = append(ids, n.NodeID)
		}
		slices.Sort(ids)
		if want := []string{oldID, newID}; !slices.Equal(ids, slices.Sorted(slices.Values(want))) {
			t.Fatalf("registry holds %v, want exactly %v", ids, want)
		}
		got, ok := deps.registry.Get(oldID)
		if !ok || !reflect.DeepEqual(got, old) {
			t.Errorf("old record changed:\n got  %+v\n want %+v", got, old)
		}
		fresh, ok := deps.registry.Get(newID)
		if !ok {
			t.Fatalf("new record %s is absent", newID)
		}
		if !fresh.RevokedAt.IsZero() {
			t.Errorf("new record is revoked: %v", fresh.RevokedAt)
		}
		if fresh.EnrollingTokenID != tokenID {
			t.Errorf("new record EnrollingTokenID = %q, want %q", fresh.EnrollingTokenID, tokenID)
		}
		if wantOldRevoked {
			if !deps.denylist.IsRevoked(oldID) {
				t.Errorf("old Node %s is not on the denylist", oldID)
			}
			if deps.denylist.IsRevoked(newID) {
				t.Errorf("new Node %s is on the denylist", newID)
			}
		}
	}

	t.Run("after the Node is revoked", func(t *testing.T) {
		ctx, lis, deps := boot(t)
		tok, plaintext := seedToken(ctx, t, deps, nil)
		oldID := enrollNode(ctx, t, lis, deps, plaintext, "host-reenroll").ID
		deps.revocation.RevokeNode(oldID)
		old, ok := deps.registry.Get(oldID)
		if !ok || old.RevokedAt.IsZero() {
			t.Fatalf("old record present = %v, RevokedAt = %v; want present and revoked", ok, old.RevokedAt)
		}
		newID := enrollNode(ctx, t, lis, deps, plaintext, "host-reenroll").ID
		requireNewNode(t, deps, oldID, newID, tok.ID, old, true)
	})

	t.Run("after its token is revoked, under a fresh token", func(t *testing.T) {
		ctx, lis, deps := boot(t)
		tokA, plaintextA := seedToken(ctx, t, deps, nil)
		oldID := enrollNode(ctx, t, lis, deps, plaintextA, "host-reenroll").ID
		if err := deps.revocation.RevokeToken(ctx, tokA.ID, func([]string) error { return nil }); err != nil {
			t.Fatalf("RevokeToken: %v", err)
		}
		old, ok := deps.registry.Get(oldID)
		if !ok || old.RevokedAt.IsZero() {
			t.Fatalf("old record present = %v, RevokedAt = %v; want present and revoked", ok, old.RevokedAt)
		}
		tokB, plaintextB := seedToken(ctx, t, deps, nil)
		newID := enrollNode(ctx, t, lis, deps, plaintextB, "host-reenroll").ID
		requireNewNode(t, deps, oldID, newID, tokB.ID, old, true)
	})

	// Nothing about the old Node is consulted at enrollment, so this also stands in for the
	// expired-certificate case.
	t.Run("while the old Node is still active", func(t *testing.T) {
		ctx, lis, deps := boot(t)
		tok, plaintext := seedToken(ctx, t, deps, nil)
		oldID := enrollNode(ctx, t, lis, deps, plaintext, "host-reenroll").ID
		old, ok := deps.registry.Get(oldID)
		if !ok || !old.RevokedAt.IsZero() {
			t.Fatalf("old record present = %v, RevokedAt = %v; want present and active", ok, old.RevokedAt)
		}
		newID := enrollNode(ctx, t, lis, deps, plaintext, "host-reenroll").ID
		requireNewNode(t, deps, oldID, newID, tok.ID, old, false)
	})
}
