// Package accounts is the Relay's identity substrate (ADR-0010, roadmap
// v0.3.0): who is asking, and with what authority.
//
// An **Account** is the unit of identity on the control plane. It is either
// **human** (an operator, later logging into the Console) or **machine** (an
// orchestrator — Gleipnir, a CI job, any headless driver). Every action on
// every surface attributes to exactly one Account, and every authorization
// question is answered from that Account's **role**.
//
// This package is the domain model only: no proto dependency, no HTTP, no
// token handling, no persistence. The store implements [Repository]
// (internal/store), the API Token lifecycle that binds credentials to Accounts
// is issue #296, and role-gating the MCP surface is #298. Keeping those apart
// is deliberate — an Account is a *durable identity*, a token is a *revocable
// credential for one*, and conflating them is how "revoke the token" and
// "disable the human" become the same button by accident.
//
// # The founding admin
//
// The Relay's config-seeded control-plane credential (ADR-0010's staged authz)
// predates Accounts. It does not disappear: on first start it resolves to the
// **founding admin Account** — a real, stored, listable Account like any other,
// so audit attributes it as that Account rather than as a special case, and so
// the eventual removal of the seeded credential is a token change and not an
// identity change. See [FoundingAdminName] and the store's idempotent seeding.
package accounts

import (
	"context"
	"errors"
	"strings"
	"time"
)

// FoundingAdminName is the reserved Account name the config-seeded
// control-plane credential resolves to. Reserved: no other Account may be
// created with it, so the founding identity can never be shadowed by a
// later-created Account that would then inherit its audit history.
const FoundingAdminName = "founding-admin"

var (
	// ErrNotFound is returned when an Account does not exist.
	ErrNotFound = errors.New("accounts: account not found")

	// ErrNameTaken is returned when creating an Account whose name is already
	// in use. Names are the human-facing handle and appear in audit, so they
	// are unique — an ambiguous attribution is worse than a rejected create.
	ErrNameTaken = errors.New("accounts: account name already in use")

	// ErrInvalidName is returned for an empty or malformed Account name.
	ErrInvalidName = errors.New("accounts: invalid account name")

	// ErrInvalidRole is returned for a role outside the closed set.
	ErrInvalidRole = errors.New("accounts: invalid role")

	// ErrInvalidKind is returned for a kind outside the closed set.
	ErrInvalidKind = errors.New("accounts: invalid account kind")

	// ErrReservedName is returned when a caller tries to create an Account
	// using a reserved name (today: FoundingAdminName). The founding admin is
	// created by seeding, never by the API.
	ErrReservedName = errors.New("accounts: reserved account name")

	// ErrLastAdmin is returned by SetRole and SetEnabled when the change
	// would leave zero enabled admin rows (#653): demoting the last enabled
	// admin, or disabling it. A disabled admin does not count toward "last
	// admin" — see SetRole/SetEnabled below for why an implementation MUST
	// refuse this in one statement rather than a check-then-write.
	ErrLastAdmin = errors.New("accounts: the last enabled admin cannot be demoted or disabled")
)

// Kind distinguishes a human operator from a machine driver. It is not an
// authorization input on its own — role decides that — but it is recorded and
// displayed, because "which of my machine identities did this" is a question
// an operator asks during an incident, and because approvals (v0.5.0) need it:
// a machine Account can never satisfy a gate that requires a human.
type Kind string

const (
	// KindHuman is a person: an operator who will log into the Console
	// (v0.6.0) or authenticate through OAuth (#299).
	KindHuman Kind = "human"

	// KindMachine is a headless driver: the AI-agent, CI, a script. Machine
	// Accounts are how orchestrators get identities (ADR-0010).
	KindMachine Kind = "machine"
)

// Valid reports whether k is one of the two defined kinds.
func (k Kind) Valid() bool { return k == KindHuman || k == KindMachine }

// Role is an Account's authority level — a closed, ordered set (ADR-0010).
// Ordering is the point: authorization asks "at least operator?", never
// "exactly operator", so a new role can be inserted without rewriting every
// call site.
type Role string

const (
	// RoleViewer may read: list Nodes, describe them, read Jobs and audit.
	// It may never dispatch anything.
	RoleViewer Role = "viewer"

	// RoleOperator may additionally run structured Operations — the typed
	// path (ADR-0001) — but never Raw Exec.
	RoleOperator Role = "operator"

	// RoleAdmin may additionally use Raw Exec and manage the control plane
	// (Accounts, tokens, enrollment, revocation, the Freeze).
	//
	// Raw Exec being admin-only is the centrally-enforced half of ADR-0001's
	// safety model: Node Policy still gates every command, but the Relay
	// decides who may even ask for the arbitrary-command path.
	RoleAdmin Role = "admin"
)

// Valid reports whether r is one of the three defined roles.
func (r Role) Valid() bool {
	return r == RoleViewer || r == RoleOperator || r == RoleAdmin
}

// rank orders the roles for [Role.AtLeast]. An unknown role ranks below
// everything — fail closed: a corrupted or future role read from the store
// authorizes nothing rather than accidentally out-ranking admin.
func (r Role) rank() int {
	switch r {
	case RoleViewer:
		return 1
	case RoleOperator:
		return 2
	case RoleAdmin:
		return 3
	default:
		return 0
	}
}

// AtLeast reports whether r carries at least the authority of want.
//
// Fail-closed in both directions: an unknown r never satisfies anything, and
// an unknown want is never satisfiable (a typo'd requirement denies rather
// than silently permitting everyone).
func (r Role) AtLeast(want Role) bool {
	if !r.Valid() || !want.Valid() {
		return false
	}
	return r.rank() >= want.rank()
}

// Account is a stored identity on the control plane.
//
// Enabled is the durable off-switch, distinct from revoking a credential: a
// disabled Account authenticates nowhere, immediately, regardless of how many
// valid tokens exist for it (#296). Disabling the identity and revoking a
// token are deliberately different acts.
type Account struct {
	// ID is the Relay-assigned stable identifier. It never changes, so audit
	// records stay attributable even if the Account is renamed.
	ID string

	// Name is the unique human-facing handle shown in audit and the Console.
	Name string

	Kind Kind
	Role Role

	// Enabled is the durable off-switch (#296). A disabled Account
	// authenticates nowhere and authorizes nothing.
	Enabled bool

	CreatedAt time.Time

	// LastSeenAt is the most recent successful authentication, zero if the
	// Account has never authenticated. Advisory: it answers "is this machine
	// Account still in use?" before someone deletes it.
	LastSeenAt time.Time
}

// IsFoundingAdmin reports whether a is the seeded founding admin Account.
func (a Account) IsFoundingAdmin() bool { return a.Name == FoundingAdminName }

// Attribution is the string form recorded on audit entries: "name:role".
//
// Name rather than ID because an audit trail is read by humans during an
// incident, and role alongside it because "what could this Account do at the
// time" is the second question every reader asks. The ID is carried separately
// on records that need to survive a rename.
func (a Account) Attribution() string {
	if a.Role == "" {
		return a.Name
	}
	return a.Name + ":" + string(a.Role)
}

// ValidateName checks an Account name: 1–64 characters of [A-Za-z0-9._-],
// starting alphanumeric.
//
// Deliberately narrow. Names appear in audit lines, log lines, and (later) the
// Console; a name containing whitespace, quotes, or control characters is a
// log-forging and display-spoofing vector, and no legitimate Account needs one.
func ValidateName(name string) error {
	if len(name) == 0 || len(name) > 64 {
		return ErrInvalidName
	}
	for i, c := range name {
		alnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if i == 0 {
			if !alnum {
				return ErrInvalidName
			}
			continue
		}
		if !alnum && c != '.' && c != '_' && c != '-' {
			return ErrInvalidName
		}
	}
	return nil
}

// NormalizeName lowercases and trims a name for uniqueness comparison, so
// "Alice" and "alice" cannot both exist and be mistaken for each other in an
// audit trail.
func NormalizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// Repository persists Accounts. Implemented by internal/store (SQLite) behind
// the same repository seam as the registry and Job engine, so the Postgres
// swap named in the roadmap's Deferred section stays a store-only change.
type Repository interface {
	// Create stores a new Account and returns it as stored (with its assigned
	// ID and CreatedAt). Returns ErrNameTaken if the normalized name exists,
	// ErrReservedName for a reserved name, and ErrInvalidName/Role/Kind for a
	// malformed input — validated here rather than trusted from the caller,
	// because this is the write path every surface funnels through.
	Create(ctx context.Context, a Account) (Account, error)

	// Get returns the Account with the given ID, or ErrNotFound.
	Get(ctx context.Context, id string) (Account, error)

	// GetByName returns the Account with the given name (normalized), or
	// ErrNotFound. This is the lookup the authenticator uses to resolve a
	// credential to its Account.
	GetByName(ctx context.Context, name string) (Account, error)

	// List returns every Account, ordered by name.
	List(ctx context.Context) ([]Account, error)

	// SetRole changes an Account's role. Returns ErrNotFound if it does not
	// exist, ErrInvalidRole for a role outside the closed set, and
	// ErrLastAdmin if the change would demote the last enabled admin (#653).
	//
	// Takes effect immediately: authorization reads the stored role at each
	// request rather than caching it at authentication time, so a demotion
	// does not wait for a restart or a token expiry.
	//
	// An implementation MUST refuse, IN ONE STATEMENT, any change that would
	// leave zero enabled admin rows. The rule is a COUNT over the whole
	// table, not a property of the one row being changed, so a
	// check-then-write above the store races another writer between the
	// check and the write — the same reason ErrNameTaken is enforced by a
	// UNIQUE index rather than a pre-check (see internal/store/accounts.go's
	// insert, which cites exactly this precedent for its own collision
	// guard).
	//
	// Two scope limits, so a caller does not read more into this than it
	// promises:
	//
	//   - It guarantees ONE ENABLED ADMIN ROW, not one admin that can
	//     AUTHENTICATE. Revoking that admin's last API Token locks the
	//     control plane out just as effectively as demoting or disabling the
	//     Account would have — this rule does not see tokens at all.
	//     Recovery in that case is `relay bootstrap-token` on the host,
	//     exactly as docs/specs/accounts-and-access.md accepts. Do not read
	//     this rule as "lockout is now impossible".
	//   - There is no Delete on this interface, so spec 15's "removed" is
	//     SetEnabled(false), not a deletion.
	SetRole(ctx context.Context, id string, role Role) error

	// SetEnabled enables or disables an Account. A disabled Account
	// authenticates nowhere, immediately.
	//
	// Enabling is never blocked. Disabling is refused with ErrLastAdmin
	// under exactly the same single-statement rule as SetRole above: it
	// would leave zero enabled admin rows. A disabled admin does not count
	// toward "the last admin" in either direction — demoting or disabling
	// one that is already disabled is never refused by this rule.
	SetEnabled(ctx context.Context, id string, enabled bool) error

	// TouchLastSeen records a successful authentication. Best-effort: a
	// failure here must never fail the request it accompanies, since
	// last-seen is advisory and the caller has already authenticated.
	TouchLastSeen(ctx context.Context, id string, at time.Time) error

	// EnsureFoundingAdmin creates the founding admin Account if it does not
	// exist and returns it either way — the idempotent, deterministic seeding
	// the acceptance criteria require. Never modifies an existing founding
	// admin: if an operator has since disabled it or changed its role, that
	// decision survives every restart.
	EnsureFoundingAdmin(ctx context.Context) (Account, error)
}
