// Package accountstest holds the shared conformance suite for
// accounts.Repository, run against both the accounts package's own
// in-memory implementation and internal/store's sqliteAccounts.
//
// It exists because both implementations carry the last-enabled-admin rule
// by hand (accounts.Repository's doc comment requires it, but cannot enforce
// it): a shared, table-driven harness is what stops the two from drifting —
// a case added here is proven against both at once. It is a regular package,
// not a _test.go file, on the relaytest precedent: memoryStore is unexported
// in accounts' own _test.go files and unreachable from package store, so the
// harness has to live somewhere both test packages can import it from,
// taking a fresh accounts.Repository from each caller rather than
// constructing one itself.
package accountstest

import (
	"context"
	"errors"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
)

// RunRepositoryConformance exercises the last-enabled-admin guard against a
// fresh accounts.Repository per subtest, built by newRepo.
func RunRepositoryConformance(t *testing.T, newRepo func(t *testing.T) accounts.Repository) {
	t.Helper()
	ctx := context.Background()

	create := func(t *testing.T, repo accounts.Repository, name string, role accounts.Role, enabled bool) accounts.Account {
		t.Helper()
		a, err := repo.Create(ctx, accounts.Account{
			Name: name, Kind: accounts.KindHuman, Role: role, Enabled: enabled,
		})
		if err != nil {
			t.Fatalf("create %q: %v", name, err)
		}
		return a
	}

	t.Run("last enabled admin cannot be demoted", func(t *testing.T) {
		repo := newRepo(t)
		admin := create(t, repo, "sole-admin", accounts.RoleAdmin, true)

		if err := repo.SetRole(ctx, admin.ID, accounts.RoleAdmin, accounts.RoleViewer); !errors.Is(err, accounts.ErrLastAdmin) {
			t.Fatalf("SetRole(only enabled admin, viewer) = %v, want ErrLastAdmin", err)
		}
		got, err := repo.Get(ctx, admin.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Role != accounts.RoleAdmin {
			t.Errorf("role after refused demote = %q, want admin unchanged", got.Role)
		}
	})

	t.Run("last enabled admin cannot be disabled", func(t *testing.T) {
		repo := newRepo(t)
		admin := create(t, repo, "sole-admin", accounts.RoleAdmin, true)

		if err := repo.SetEnabled(ctx, admin.ID, false); !errors.Is(err, accounts.ErrLastAdmin) {
			t.Fatalf("SetEnabled(only enabled admin, false) = %v, want ErrLastAdmin", err)
		}
		got, err := repo.Get(ctx, admin.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if !got.Enabled {
			t.Error("enabled after refused disable = false, want unchanged true")
		}
	})

	t.Run("a disabled admin does not count toward the last admin", func(t *testing.T) {
		repo := newRepo(t)
		enabledAdmin := create(t, repo, "enabled-admin", accounts.RoleAdmin, true)
		create(t, repo, "disabled-admin", accounts.RoleAdmin, false)

		// The disabled admin does not count, so enabledAdmin is still the
		// only ENABLED admin — demoting or disabling it must be refused.
		if err := repo.SetRole(ctx, enabledAdmin.ID, accounts.RoleAdmin, accounts.RoleViewer); !errors.Is(err, accounts.ErrLastAdmin) {
			t.Fatalf("SetRole(last enabled admin, viewer), with a disabled admin also present, = %v, want ErrLastAdmin", err)
		}
		if err := repo.SetEnabled(ctx, enabledAdmin.ID, false); !errors.Is(err, accounts.ErrLastAdmin) {
			t.Fatalf("SetEnabled(last enabled admin, false), with a disabled admin also present, = %v, want ErrLastAdmin", err)
		}
	})

	t.Run("demoting or disabling an admin is fine with another enabled admin present", func(t *testing.T) {
		repo := newRepo(t)
		a := create(t, repo, "admin-a", accounts.RoleAdmin, true)
		create(t, repo, "admin-b", accounts.RoleAdmin, true)

		if err := repo.SetRole(ctx, a.ID, accounts.RoleAdmin, accounts.RoleViewer); err != nil {
			t.Fatalf("SetRole(admin-a, viewer) with admin-b still enabled = %v, want nil", err)
		}
	})

	t.Run("promoting to admin is never blocked", func(t *testing.T) {
		repo := newRepo(t)
		admin := create(t, repo, "sole-admin", accounts.RoleAdmin, true)
		viewer := create(t, repo, "a-viewer", accounts.RoleViewer, true)
		_ = admin

		if err := repo.SetRole(ctx, viewer.ID, accounts.RoleViewer, accounts.RoleAdmin); err != nil {
			t.Fatalf("SetRole(viewer, admin) = %v, want nil", err)
		}
	})

	t.Run("enabling is never blocked", func(t *testing.T) {
		repo := newRepo(t)
		admin := create(t, repo, "sole-admin", accounts.RoleAdmin, false)

		if err := repo.SetEnabled(ctx, admin.ID, true); err != nil {
			t.Fatalf("SetEnabled(disabled admin, true) = %v, want nil", err)
		}
	})

	t.Run("demoting a non-admin is unaffected", func(t *testing.T) {
		repo := newRepo(t)
		create(t, repo, "sole-admin", accounts.RoleAdmin, true)
		op := create(t, repo, "an-operator", accounts.RoleOperator, true)

		if err := repo.SetRole(ctx, op.ID, accounts.RoleOperator, accounts.RoleViewer); err != nil {
			t.Fatalf("SetRole(operator, viewer) = %v, want nil", err)
		}
	})

	t.Run("ErrNotFound beats ErrLastAdmin for an unknown id", func(t *testing.T) {
		repo := newRepo(t)
		create(t, repo, "sole-admin", accounts.RoleAdmin, true)

		if err := repo.SetRole(ctx, "does-not-exist", accounts.RoleAdmin, accounts.RoleViewer); !errors.Is(err, accounts.ErrNotFound) {
			t.Errorf("SetRole(unknown id, viewer) = %v, want ErrNotFound", err)
		}
		if err := repo.SetEnabled(ctx, "does-not-exist", false); !errors.Is(err, accounts.ErrNotFound) {
			t.Errorf("SetEnabled(unknown id, false) = %v, want ErrNotFound", err)
		}
	})

	roleOf := func(t *testing.T, repo accounts.Repository, id string) accounts.Role {
		t.Helper()
		got, err := repo.Get(ctx, id)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		return got.Role
	}

	t.Run("a stale from is refused with ErrRoleChanged and writes nothing", func(t *testing.T) {
		repo := newRepo(t)
		a := create(t, repo, "admin-a", accounts.RoleAdmin, true)
		create(t, repo, "admin-b", accounts.RoleAdmin, true)

		// The concurrent demotion lands first.
		if err := repo.SetRole(ctx, a.ID, accounts.RoleAdmin, accounts.RoleViewer); err != nil {
			t.Fatalf("demote: %v", err)
		}
		// The stale writer still believes a is an admin.
		if err := repo.SetRole(ctx, a.ID, accounts.RoleAdmin, accounts.RoleOperator); !errors.Is(err, accounts.ErrRoleChanged) {
			t.Fatalf("SetRole(stale from=admin) = %v, want ErrRoleChanged", err)
		}
		if got := roleOf(t, repo, a.ID); got != accounts.RoleViewer {
			t.Errorf("role after refused stale write = %q, want viewer unchanged", got)
		}
	})

	t.Run("role mismatch wins over last-admin", func(t *testing.T) {
		repo := newRepo(t)
		a := create(t, repo, "sole-admin", accounts.RoleAdmin, true)

		if err := repo.SetRole(ctx, a.ID, accounts.RoleOperator, accounts.RoleViewer); !errors.Is(err, accounts.ErrRoleChanged) {
			t.Fatalf("SetRole(sole admin, from=operator) = %v, want ErrRoleChanged", err)
		}
		if got := roleOf(t, repo, a.ID); got != accounts.RoleAdmin {
			t.Errorf("role after refused write = %q, want admin unchanged", got)
		}
	})

	t.Run("an invalid from is ErrInvalidRole", func(t *testing.T) {
		repo := newRepo(t)
		a := create(t, repo, "sole-admin", accounts.RoleAdmin, true)

		if err := repo.SetRole(ctx, a.ID, accounts.Role("root"), accounts.RoleViewer); !errors.Is(err, accounts.ErrInvalidRole) {
			t.Fatalf("SetRole(from=root) = %v, want ErrInvalidRole", err)
		}
		if got := roleOf(t, repo, a.ID); got != accounts.RoleAdmin {
			t.Errorf("role after refused write = %q, want admin unchanged", got)
		}
	})

	t.Run("a matching from writes", func(t *testing.T) {
		repo := newRepo(t)
		create(t, repo, "sole-admin", accounts.RoleAdmin, true)
		v := create(t, repo, "a-viewer", accounts.RoleViewer, true)

		if err := repo.SetRole(ctx, v.ID, accounts.RoleViewer, accounts.RoleOperator); err != nil {
			t.Fatalf("SetRole(viewer->operator) = %v, want nil", err)
		}
		if got := roleOf(t, repo, v.ID); got != accounts.RoleOperator {
			t.Errorf("role = %q, want operator", got)
		}
	})
}
