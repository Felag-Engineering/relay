package accounts

import (
	"context"
	"sort"
	"sync"
	"time"
)

// memoryStore is an in-memory Repository + TokenRepository, mirroring
// enroll.MemoryRepository's precedent.
//
// It exists so this package's own tests can exercise TokenService here rather
// than only through internal/store. Those store tests are valuable and stay —
// they prove the SQLite implementation — but they left the service's logic
// covered from a different package, which reported internal/accounts at 27%
// and understated the real state. A coverage number that misleads is worse
// than a low one: it either invites someone to "fix" a non-problem, or hides a
// real gap behind a figure everyone has learned to ignore.
type memoryStore struct {
	mu       sync.Mutex
	accounts map[string]Account
	tokens   map[string]APIToken
	seq      int
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		accounts: make(map[string]Account),
		tokens:   make(map[string]APIToken),
	}
}

func (m *memoryStore) nextID(prefix string) string {
	m.seq++
	return prefix + string(rune('a'+m.seq%26)) + time.Now().Format("150405.000000000")
}

// --- Repository ---

func (m *memoryStore) Create(_ context.Context, a Account) (Account, error) {
	if err := ValidateName(a.Name); err != nil {
		return Account{}, err
	}
	if NormalizeName(a.Name) == FoundingAdminName {
		return Account{}, ErrReservedName
	}
	if !a.Kind.Valid() {
		return Account{}, ErrInvalidKind
	}
	if !a.Role.Valid() {
		return Account{}, ErrInvalidRole
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.accounts {
		if NormalizeName(existing.Name) == NormalizeName(a.Name) {
			return Account{}, ErrNameTaken
		}
	}
	a.ID = m.nextID("acct-")
	a.CreatedAt = time.Now().UTC()
	m.accounts[a.ID] = a
	return a, nil
}

func (m *memoryStore) Get(_ context.Context, id string) (Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.accounts[id]
	if !ok {
		return Account{}, ErrNotFound
	}
	return a, nil
}

func (m *memoryStore) GetByName(_ context.Context, name string) (Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.accounts {
		if NormalizeName(a.Name) == NormalizeName(name) {
			return a, nil
		}
	}
	return Account{}, ErrNotFound
}

func (m *memoryStore) List(_ context.Context) ([]Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Account, 0, len(m.accounts))
	for _, a := range m.accounts {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// anotherEnabledAdminExistsLocked reports whether an enabled admin other than
// excludeID exists. Callers must hold m.mu — this is the memoryStore
// counterpart of sqliteAccounts' single-statement EXISTS guard, made safe by
// the SAME lock covering both the read and the write, which is exactly what
// a SQL statement's atomicity gives the store implementation and a
// check-then-write above it would not.
func (m *memoryStore) anotherEnabledAdminExistsLocked(excludeID string) bool {
	for id, a := range m.accounts {
		if id != excludeID && a.Role == RoleAdmin && a.Enabled {
			return true
		}
	}
	return false
}

func (m *memoryStore) SetRole(_ context.Context, id string, role Role) error {
	if !role.Valid() {
		return ErrInvalidRole
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.accounts[id]
	if !ok {
		return ErrNotFound
	}
	// The last-admin guard (#653): demoting an enabled admin away from
	// "admin" is refused unless another enabled admin exists. Promoting TO
	// admin, and any change to a disabled or non-admin row, is unaffected.
	if a.Role == RoleAdmin && a.Enabled && role != RoleAdmin && !m.anotherEnabledAdminExistsLocked(id) {
		return ErrLastAdmin
	}
	a.Role = role
	m.accounts[id] = a
	return nil
}

func (m *memoryStore) SetEnabled(_ context.Context, id string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.accounts[id]
	if !ok {
		return ErrNotFound
	}
	// The last-admin guard (#653): disabling an enabled admin is refused
	// unless another enabled admin exists. Enabling is never blocked.
	if !enabled && a.Role == RoleAdmin && a.Enabled && !m.anotherEnabledAdminExistsLocked(id) {
		return ErrLastAdmin
	}
	a.Enabled = enabled
	m.accounts[id] = a
	return nil
}

func (m *memoryStore) TouchLastSeen(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.accounts[id]
	if !ok {
		return ErrNotFound
	}
	a.LastSeenAt = at
	m.accounts[id] = a
	return nil
}

func (m *memoryStore) EnsureFoundingAdmin(ctx context.Context) (Account, error) {
	if a, err := m.GetByName(ctx, FoundingAdminName); err == nil {
		return a, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	a := Account{
		ID:        m.nextID("acct-"),
		Name:      FoundingAdminName,
		Kind:      KindHuman,
		Role:      RoleAdmin,
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
	}
	m.accounts[a.ID] = a
	return a, nil
}

// --- TokenRepository ---

func (m *memoryStore) CreateToken(_ context.Context, t APIToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[t.ID] = t
	return nil
}

func (m *memoryStore) TokenByID(_ context.Context, id string) (APIToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[id]
	if !ok {
		return APIToken{}, ErrTokenNotFound
	}
	return t, nil
}

func (m *memoryStore) TokensByAccount(_ context.Context, accountID string) ([]APIToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]APIToken, 0)
	for _, t := range m.tokens {
		if t.AccountID == accountID {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *memoryStore) RevokeToken(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[id]
	if !ok {
		return ErrTokenNotFound
	}
	if t.RevokedAt.IsZero() {
		t.RevokedAt = at
		m.tokens[id] = t
	}
	return nil
}

func (m *memoryStore) TouchTokenLastUsed(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[id]
	if !ok {
		return ErrTokenNotFound
	}
	t.LastUsedAt = at
	m.tokens[id] = t
	return nil
}

var (
	_ Repository      = (*memoryStore)(nil)
	_ TokenRepository = (*memoryStore)(nil)
)

// NewMemoryRepositoryForConformanceTest returns a fresh in-memory Repository.
// Exported (test-only — this file never builds into production) so the
// shared conformance suite (accountstest.RunRepositoryConformance) can run
// against it from an external test package without this package's own
// _test.go files importing accountstest back, which would be an import
// cycle: memoryStore itself must stay unexported, since it exists only to
// give this package's own tests real coverage of TokenService, not as a
// second production Repository.
func NewMemoryRepositoryForConformanceTest() Repository {
	return newMemoryStore()
}
