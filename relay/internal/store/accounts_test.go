package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
)

func machine(name string, role accounts.Role) accounts.Account {
	return accounts.Account{Name: name, Kind: accounts.KindMachine, Role: role, Enabled: true}
}

func TestAccounts_CreateGetList(t *testing.T) {
	st, _ := openTestStore(t)
	repo := st.Accounts()
	ctx := context.Background()

	created, err := repo.Create(ctx, machine("gleipnir", accounts.RoleOperator))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.ID == "" {
		t.Error("create: empty ID, want an assigned identifier")
	}
	if created.CreatedAt.IsZero() {
		t.Error("create: zero CreatedAt")
	}
	if !created.LastSeenAt.IsZero() {
		t.Error("create: LastSeenAt must be zero until the Account authenticates")
	}

	byID, err := repo.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if byID.Name != "gleipnir" || byID.Kind != accounts.KindMachine || byID.Role != accounts.RoleOperator || !byID.Enabled {
		t.Errorf("get: %+v, want the created Account", byID)
	}

	// Name lookup is normalized: an audit reader must never face two Accounts
	// distinguishable only by case.
	byName, err := repo.GetByName(ctx, "GLEIPNIR")
	if err != nil {
		t.Fatalf("get by name (different case): %v", err)
	}
	if byName.ID != created.ID {
		t.Errorf("get by name: ID = %q, want %q", byName.ID, created.ID)
	}

	if _, err := repo.Get(ctx, "acct-nope"); !errors.Is(err, accounts.ErrNotFound) {
		t.Errorf("get unknown: %v, want ErrNotFound", err)
	}
	if _, err := repo.GetByName(ctx, "nobody"); !errors.Is(err, accounts.ErrNotFound) {
		t.Errorf("get unknown by name: %v, want ErrNotFound", err)
	}

	if _, err := repo.Create(ctx, machine("Gleipnir", accounts.RoleViewer)); !errors.Is(err, accounts.ErrNameTaken) {
		t.Errorf("create duplicate (different case): %v, want ErrNameTaken", err)
	}

	if _, err := repo.Create(ctx, machine("alice", accounts.RoleAdmin)); err != nil {
		t.Fatalf("create second: %v", err)
	}
	list, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 || list[0].Name != "alice" || list[1].Name != "gleipnir" {
		t.Errorf("list = %+v, want [alice gleipnir] in name order", list)
	}
}

// Malformed input is refused at the repository, not merely by the schema's
// CHECK constraints — this is the single write path every surface funnels
// through, so it is where the rules have to hold.
func TestAccounts_CreateRejectsMalformed(t *testing.T) {
	st, _ := openTestStore(t)
	repo := st.Accounts()
	ctx := context.Background()

	cases := []struct {
		label string
		in    accounts.Account
		want  error
	}{
		{"empty name", accounts.Account{Name: "", Kind: accounts.KindHuman, Role: accounts.RoleViewer}, accounts.ErrInvalidName},
		{"name with space", accounts.Account{Name: "bad name", Kind: accounts.KindHuman, Role: accounts.RoleViewer}, accounts.ErrInvalidName},
		{"name with newline", accounts.Account{Name: "a\nb", Kind: accounts.KindHuman, Role: accounts.RoleViewer}, accounts.ErrInvalidName},
		{"leading punctuation", accounts.Account{Name: "-alice", Kind: accounts.KindHuman, Role: accounts.RoleViewer}, accounts.ErrInvalidName},
		{"unknown kind", accounts.Account{Name: "alice", Kind: accounts.Kind("robot"), Role: accounts.RoleViewer}, accounts.ErrInvalidKind},
		{"unknown role", accounts.Account{Name: "alice", Kind: accounts.KindHuman, Role: accounts.Role("root")}, accounts.ErrInvalidRole},
		{"reserved name", accounts.Account{Name: accounts.FoundingAdminName, Kind: accounts.KindHuman, Role: accounts.RoleAdmin}, accounts.ErrReservedName},
	}
	for _, c := range cases {
		if _, err := repo.Create(ctx, c.in); !errors.Is(err, c.want) {
			t.Errorf("[%s] create: %v, want %v", c.label, err, c.want)
		}
	}
}

// Acceptance: "Role changes take effect without restart" — the stored role is
// the authority, read fresh on every lookup rather than cached at creation.
func TestAccounts_SetRoleAndEnabled(t *testing.T) {
	st, _ := openTestStore(t)
	repo := st.Accounts()
	ctx := context.Background()

	a, err := repo.Create(ctx, machine("ci", accounts.RoleViewer))
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := repo.SetRole(ctx, a.ID, accounts.RoleAdmin); err != nil {
		t.Fatalf("set role: %v", err)
	}
	got, _ := repo.Get(ctx, a.ID)
	if got.Role != accounts.RoleAdmin {
		t.Errorf("role after SetRole = %q, want admin", got.Role)
	}

	if err := repo.SetRole(ctx, a.ID, accounts.Role("root")); !errors.Is(err, accounts.ErrInvalidRole) {
		t.Errorf("set invalid role: %v, want ErrInvalidRole", err)
	}
	if err := repo.SetRole(ctx, "acct-nope", accounts.RoleViewer); !errors.Is(err, accounts.ErrNotFound) {
		t.Errorf("set role on unknown: %v, want ErrNotFound", err)
	}

	if err := repo.SetEnabled(ctx, a.ID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	got, _ = repo.Get(ctx, a.ID)
	if got.Enabled {
		t.Error("Enabled = true after SetEnabled(false)")
	}
	if err := repo.SetEnabled(ctx, "acct-nope", true); !errors.Is(err, accounts.ErrNotFound) {
		t.Errorf("enable unknown: %v, want ErrNotFound", err)
	}
}

func TestAccounts_TouchLastSeen(t *testing.T) {
	st, _ := openTestStore(t)
	repo := st.Accounts()
	ctx := context.Background()

	a, err := repo.Create(ctx, machine("gleipnir", accounts.RoleOperator))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	when := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	if err := repo.TouchLastSeen(ctx, a.ID, when); err != nil {
		t.Fatalf("touch: %v", err)
	}
	got, _ := repo.Get(ctx, a.ID)
	if !got.LastSeenAt.Equal(when) {
		t.Errorf("LastSeenAt = %v, want %v", got.LastSeenAt, when)
	}
}

// Acceptance: "The seeded credential resolves to the founding admin Account" —
// seeding is deterministic and idempotent, and never repairs an existing row.
func TestAccounts_EnsureFoundingAdminIsIdempotent(t *testing.T) {
	st, _ := openTestStore(t)
	repo := st.Accounts()
	ctx := context.Background()

	first, err := repo.EnsureFoundingAdmin(ctx)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if first.Name != accounts.FoundingAdminName || first.Role != accounts.RoleAdmin || !first.Enabled {
		t.Errorf("founding admin = %+v, want an enabled admin named %q", first, accounts.FoundingAdminName)
	}
	if !first.IsFoundingAdmin() {
		t.Error("IsFoundingAdmin() = false for the seeded Account")
	}

	second, err := repo.EnsureFoundingAdmin(ctx)
	if err != nil {
		t.Fatalf("ensure (second call): %v", err)
	}
	if second.ID != first.ID {
		t.Errorf("second ensure created a new Account (%q != %q); seeding must be idempotent", second.ID, first.ID)
	}
	list, _ := repo.List(ctx)
	if len(list) != 1 {
		t.Errorf("list = %+v, want exactly one Account after two ensures", list)
	}

	// An operator disabling or demoting the founding admin is a deliberate
	// security act — retiring the seeded credential's authority. Seeding must
	// never quietly undo it on the next boot.
	if err := repo.SetEnabled(ctx, first.ID, false); err != nil {
		t.Fatalf("disable founding admin: %v", err)
	}
	if err := repo.SetRole(ctx, first.ID, accounts.RoleViewer); err != nil {
		t.Fatalf("demote founding admin: %v", err)
	}
	after, err := repo.EnsureFoundingAdmin(ctx)
	if err != nil {
		t.Fatalf("ensure after operator changes: %v", err)
	}
	if after.Enabled || after.Role != accounts.RoleViewer {
		t.Errorf("ensure repaired an operator-modified founding admin: %+v", after)
	}
}

// Acceptance: "Accounts persist across Relay restarts."
func TestAccounts_PersistAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.db")
	ctx := context.Background()

	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	seeded, err := st.Accounts().EnsureFoundingAdmin(ctx)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	created, err := st.Accounts().Create(ctx, machine("gleipnir", accounts.RoleOperator))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.Accounts().SetEnabled(ctx, created.ID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	st.Close() //nolint:errcheck

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { reopened.Close() }) //nolint:errcheck

	again, err := reopened.Accounts().EnsureFoundingAdmin(ctx)
	if err != nil {
		t.Fatalf("ensure after reopen: %v", err)
	}
	if again.ID != seeded.ID {
		t.Errorf("founding admin ID changed across restart: %q → %q", seeded.ID, again.ID)
	}

	got, err := reopened.Accounts().Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("get after reopen: %v", err)
	}
	if got.Enabled {
		t.Error("a disabled Account came back enabled after a restart — the off-switch must be durable")
	}
	if got.Role != accounts.RoleOperator || got.Kind != accounts.KindMachine {
		t.Errorf("Account after reopen = %+v, want role/kind preserved", got)
	}
}
