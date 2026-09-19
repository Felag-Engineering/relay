package store

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts/accountstest"
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
	// A second enabled admin, so promoting/disabling "ci" below does not trip
	// the last-enabled-admin guard (#653) this test is not about.
	if _, err := repo.Create(ctx, machine("other-admin", accounts.RoleAdmin)); err != nil {
		t.Fatalf("create other admin: %v", err)
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

	// A second enabled admin, so disabling/demoting the founding admin below
	// does not trip the last-enabled-admin guard (#653) this test is not
	// about.
	if _, err := repo.Create(ctx, machine("other-admin", accounts.RoleAdmin)); err != nil {
		t.Fatalf("create other admin: %v", err)
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

// TestSQLiteAccountsConformance runs the shared last-enabled-admin
// conformance suite (#653) against sqliteAccounts — the same suite
// accounts.TestRepositoryConformance runs against the package's own
// in-memory Repository, proving both implementations carry the rule
// identically.
func TestSQLiteAccountsConformance(t *testing.T) {
	accountstest.RunRepositoryConformance(t, func(t *testing.T) accounts.Repository {
		st, _ := openTestStore(t)
		return st.Accounts()
	})
}

// -----------------------------------------------------------------------
// The last-admin guard: structural proof of atomicity, plus an end-state
// concurrency test and the chaining case the plan reviewer executed by hand.
// -----------------------------------------------------------------------

// TestSQLiteAccounts_LastAdminGuardIsASingleStatement is the REAL atomicity
// proof (#653) — not the concurrency test below it. Under
// SetMaxOpenConns(1) (store.go:171), one connection serialises STATEMENTS,
// not the read-then-write SEQUENCE a layer-level check-then-write would
// need, so a goroutine race would pass against a check-then-write just as
// readily as against a single guarded UPDATE. What actually proves atomicity
// is a SOURCE-LEVEL fact: SetRole and SetEnabled's disable path each issue
// exactly one guarded UPDATE, whose SQL text carries the EXISTS-based
// last-admin guard, with no separate read before it.
func TestSQLiteAccounts_LastAdminGuardIsASingleStatement(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(thisFile), "accounts.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parser.ParseFile(%s): %v", path, err)
	}

	funcs := map[string]*ast.FuncDecl{}
	consts := map[string]string{}
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Body != nil {
				funcs[d.Name.Name] = d
			}
		case *ast.GenDecl:
			if d.Tok != token.CONST {
				continue
			}
			for _, spec := range d.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
					continue
				}
				lit, ok := vs.Values[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				val, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("unquote const %s: %v", vs.Names[0].Name, err)
				}
				consts[vs.Names[0].Name] = val
			}
		}
	}

	checked := 0

	// guardedCall is one call this test expects to find directly in a
	// FuncDecl's body: `r.<method>(ctx, <query>, ...)`, where query is the
	// identifier naming the SQL constant passed (empty means "any").
	type guardedCall struct {
		method string
		query  string
	}
	findCalls := func(fd *ast.FuncDecl) []guardedCall {
		var calls []guardedCall
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name != "updateGuarded" && sel.Sel.Name != "update" {
				return true
			}
			query := ""
			if len(call.Args) >= 2 {
				if id, ok := call.Args[1].(*ast.Ident); ok {
					query = id.Name
				}
			}
			calls = append(calls, guardedCall{method: sel.Sel.Name, query: query})
			return true
		})
		return calls
	}

	// SetRole must reach the single guarded UPDATE, and nothing else that
	// mutates a row.
	setRole := funcs["SetRole"]
	if setRole == nil {
		t.Fatal("SetRole not found in accounts.go")
	}
	gotSetRole := findCalls(setRole)
	wantSetRole := []guardedCall{{"updateGuarded", "setRoleGuardSQL"}}
	if len(gotSetRole) != len(wantSetRole) || gotSetRole[0] != wantSetRole[0] {
		t.Errorf("SetRole issues %+v, want exactly %+v — the guard must be a single statement", gotSetRole, wantSetRole)
	}
	checked++

	// SetEnabled must reach the UNGUARDED update for enable=true (enabling is
	// never blocked) and the GUARDED update for enable=false — both, since
	// the AST cannot see which branch a test happens to exercise.
	setEnabled := funcs["SetEnabled"]
	if setEnabled == nil {
		t.Fatal("SetEnabled not found in accounts.go")
	}
	gotSetEnabled := findCalls(setEnabled)
	wantSetEnabled := map[guardedCall]bool{
		{"update", ""}:                          true,
		{"updateGuarded", "setDisabledGuardSQL"}: true,
	}
	if len(gotSetEnabled) != len(wantSetEnabled) {
		t.Errorf("SetEnabled issues %+v, want exactly one unguarded update (enable) and one guarded updateGuarded (disable)", gotSetEnabled)
	}
	for _, c := range gotSetEnabled {
		if !wantSetEnabled[c] {
			t.Errorf("SetEnabled issues unexpected call %+v", c)
		}
	}
	checked++

	// updateGuarded itself must issue exactly one ExecContext — the single
	// statement the guard clause lives inside. A later Get (disambiguation
	// only, on the zero-rows path) is fine; a read BEFORE the write is not,
	// and would show up as a second call here since it too would need
	// ExecContext or QueryContext/QueryRowContext.
	updateGuarded := funcs["updateGuarded"]
	if updateGuarded == nil {
		t.Fatal("updateGuarded not found in accounts.go")
	}
	execCalls := 0
	ast.Inspect(updateGuarded.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "ExecContext" {
			execCalls++
		}
		return true
	})
	if execCalls != 1 {
		t.Errorf("updateGuarded issues %d ExecContext calls, want exactly 1", execCalls)
	}
	checked++

	// The guard clause itself must actually be in the executed SQL text —
	// without this, the two checks above would pass for a query that changed
	// role/enabled unconditionally.
	for _, name := range []string{"setRoleGuardSQL", "setDisabledGuardSQL"} {
		sqlText, ok := consts[name]
		if !ok {
			t.Fatalf("const %s not found in accounts.go", name)
		}
		if !strings.Contains(sqlText, "EXISTS (SELECT 1 FROM accounts") {
			t.Errorf("%s = %q, want it to contain the EXISTS(SELECT 1 FROM accounts ...) last-admin guard", name, sqlText)
		}
		if !strings.Contains(sqlText, "o.id <> :id") {
			t.Errorf("%s = %q, want the EXISTS subquery to exclude the row being changed (o.id <> :id)", name, sqlText)
		}
		checked++
	}

	if checked == 0 {
		t.Fatal("checked 0 facts — the guard must actually inspect something")
	}
}

// TestSQLiteAccounts_ConcurrentDemotionsLeaveOneEnabledAdmin is an END-STATE
// assertion, NOT an atomicity proof (see
// TestSQLiteAccounts_LastAdminGuardIsASingleStatement for that): under
// SetMaxOpenConns(1), the pool serialises this race regardless of whether the
// guard is a single statement or a check-then-write, so this test alone would
// pass against either shape. What it DOES prove is the end state a caller
// actually observes: racing two demotions of the same last enabled admin
// leaves exactly one enabled admin standing, never zero.
func TestSQLiteAccounts_ConcurrentDemotionsLeaveOneEnabledAdmin(t *testing.T) {
	st, _ := openTestStore(t)
	repo := st.Accounts()
	ctx := context.Background()

	a, err := repo.Create(ctx, accounts.Account{Name: "a", Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true})
	if err != nil {
		t.Fatalf("create a: %v", err)
	}
	b, err := repo.Create(ctx, accounts.Account{Name: "b", Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true})
	if err != nil {
		t.Fatalf("create b: %v", err)
	}

	// Race demoting BOTH admins concurrently. Exactly one of the two writers
	// must win — the loser gets ErrLastAdmin — leaving one enabled admin, not
	// zero.
	var wg sync.WaitGroup
	results := make([]error, 2)
	ids := []string{a.ID, b.ID}
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = repo.SetRole(ctx, ids[i], accounts.RoleViewer)
		}(i)
	}
	wg.Wait()

	wins, refusals := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, accounts.ErrLastAdmin):
			refusals++
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if wins != 1 || refusals != 1 {
		t.Fatalf("wins=%d refusals=%d, want exactly one winner and one refusal", wins, refusals)
	}

	list, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	enabledAdmins := 0
	for _, acct := range list {
		if acct.Role == accounts.RoleAdmin && acct.Enabled {
			enabledAdmins++
		}
	}
	if enabledAdmins != 1 {
		t.Fatalf("enabled admins after the race = %d, want exactly 1", enabledAdmins)
	}
}

// TestSQLiteAccounts_ChainedDisableDemoteDisableIsRefused pins the chaining
// attack the plan reviewer executed by hand against a real store: disable A,
// demote the now-disabled A (never blocked — A no longer counts), then
// disable B — which IS refused, because B is now the last enabled admin.
func TestSQLiteAccounts_ChainedDisableDemoteDisableIsRefused(t *testing.T) {
	st, _ := openTestStore(t)
	repo := st.Accounts()
	ctx := context.Background()

	a, err := repo.Create(ctx, accounts.Account{Name: "a", Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true})
	if err != nil {
		t.Fatalf("create a: %v", err)
	}
	b, err := repo.Create(ctx, accounts.Account{Name: "b", Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true})
	if err != nil {
		t.Fatalf("create b: %v", err)
	}

	if err := repo.SetEnabled(ctx, a.ID, false); err != nil {
		t.Fatalf("disable a (b still enabled): %v", err)
	}
	if err := repo.SetRole(ctx, a.ID, accounts.RoleViewer); err != nil {
		t.Fatalf("demote the now-disabled a: %v, want nil — a disabled admin does not count", err)
	}
	if err := repo.SetEnabled(ctx, b.ID, false); !errors.Is(err, accounts.ErrLastAdmin) {
		t.Fatalf("disable b, the last enabled admin: %v, want ErrLastAdmin", err)
	}

	got, err := repo.Get(ctx, b.ID)
	if err != nil {
		t.Fatalf("get b: %v", err)
	}
	if !got.Enabled {
		t.Error("b.Enabled = false after a refused disable, want unchanged true")
	}
}
