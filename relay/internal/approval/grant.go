package approval

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// grant.go is ADR-0027 decision 12: a batch or window approval — one human
// decision covering a bounded set of future dispatches instead of one.
//
// It exists because fatigue is a security property. "The ops team is doing a
// bunch of work" must not mean forty elicitations, because a mechanism that
// produces forty prompts produces forty rubber stamps — and a rubber-stamped
// approval is WORSE than no approval: it manufactures evidence that a human
// considered something they did not. So this is not a throughput feature. It
// is the feature that stops the audit trail becoming fiction.
//
// # What a Grant gives up, stated plainly
//
// A normal approval binds to one content-addressed Plan, and that binding IS
// the anti-drift property: a changed fan-out is a changed hash, the approval is
// not found, the dispatch re-parks. There is no drift detector to get wrong
// because there is nothing to detect.
//
// A Grant covers Plans that do not exist yet, so it cannot bind that way. What
// replaces the hash is a SCOPE plus a WINDOW — and the honest accounting is
// that a Grant trades exactness for reach. A single-plan approval says "this
// exact thing, once". A Grant says "anything inside these walls, until this
// time". The walls are therefore the whole security argument, which is why
// Scope below is explicit-by-default and why every bound is mandatory.
//
// # The inversion that makes this dangerous, and how it is handled
//
// A Gate [Match] and a Grant [Scope] look like the same grammar, and reusing
// one for the other would be a plausible-looking, security-inverting mistake:
//
//	Match  — an omitted field matches ANYTHING, which gates MORE dispatches.
//	         Omission is the SAFE direction. MinFanOut is a FLOOR ("at least
//	         this big needs a human").
//
//	Scope  — an omitted field would cover ANYTHING, which pre-approves MORE
//	         dispatches. Omission is the UNSAFE direction. MaxFanOut is a
//	         CEILING ("at most this big is already approved").
//
// They are duals, not the same type, and a Scope built by copying a Match
// would silently convert "anything touching 10+ Nodes needs approval" into
// "anything touching 10+ Nodes is pre-approved". So Scope is a separate type,
// every bound is required, and Validate refuses anything unbounded.

// Errors returned by the Grant lifecycle.
var (
	// ErrGrantNotFound is returned when a Grant ID does not exist.
	ErrGrantNotFound = errors.New("approval: grant not found")

	// ErrGrantNotActive is returned when a Grant exists but may not cover
	// anything: revoked, expired, not yet started, or exhausted.
	ErrGrantNotActive = errors.New("approval: grant is not active")

	// ErrGrantUnbounded is returned by Validate for a Scope or window that does
	// not close. An unbounded grant is a standing authorization, which is the
	// one thing this mechanism must never become.
	ErrGrantUnbounded = errors.New("approval: grant is not bounded")
)

// Scope is the wall around a Grant: which dispatches it may cover.
//
// EVERY field here is mandatory (see Validate). That is the opposite of
// [Match], and deliberately so — see this file's header. An operator who wants
// a broad grant must say so in each dimension explicitly; there is no field
// whose omission quietly widens the grant.
type Scope struct {
	// Account is the requesting Account this Grant covers. Required: a Grant
	// that covered every requester would be a standing authorization for the
	// whole control plane rather than for one operator's batch of work.
	Account string

	// RiskClass is the class covered. Required, and never "any": read and
	// mutate are not interchangeable, and a grant written for a read sweep
	// must not silently cover a mutate.
	RiskClass jobs.RiskClass

	// MaxFanOut is the CEILING on a covered dispatch's resolved Node count —
	// the mirror image of Match.MinFanOut's floor. Required and positive.
	//
	// This is what stops a grant described to a human as covering a handful of
	// Nodes from covering the fleet after the registry grows. A dispatch that
	// resolves wider than this parks normally, which is the correct outcome:
	// the approver bounded what they were agreeing to.
	MaxFanOut int

	// Operations is the allow-list of Operation names covered. Required and
	// non-empty unless RawExec is set (below); an empty list covers nothing
	// rather than everything.
	//
	// A grant naming its Operations is one an approver can actually read.
	// "Any mutate for two hours" is exactly the kind of approval that gets
	// rubber-stamped, so the grammar does not offer it.
	Operations []string

	// RawExec covers the Raw Exec path. It is a SEPARATE opt-in rather than an
	// entry in Operations because Raw Exec has no Operation name to enumerate
	// and no argument shape to bound — a grant covering it is the broadest
	// thing this type can express, and it should read that way at the call
	// site and in the audit trail.
	RawExec bool

	// SelectorNamespace optionally narrows to dispatches whose Selector used
	// this namespace. Empty means "any namespace", which is the ONE permitted
	// widening default in this type: a namespace is a targeting mechanism
	// rather than a capability, and the real bounds are the ones above.
	SelectorNamespace string
}

// MaxGrantWindow bounds how long any Grant may last, whatever its config says.
// A ceiling in code as well as in configuration, because the difference
// between a two-hour batch approval and a standing grant is only ever a number
// somebody typed.
const MaxGrantWindow = 24 * time.Hour

// MaxGrantUses bounds how many dispatches one Grant may cover. Like the window,
// it exists so that "a batch of work" cannot quietly become "everything this
// account does today".
const MaxGrantUses = 1000

// Grant is one approved, bounded, time-boxed authorization covering multiple
// future dispatches (ADR-0027 decision 12).
//
// It reuses Request's decision machinery rather than inventing a second one:
// creating a Grant IS an approval Request whose subject is a Scope instead of a
// Plan, so the gate rule's count, audience, requester_allowed, and channel all
// apply unchanged. A deployment that requires two approvers for a single
// mutate does not get single-approver grants covering a hundred of them.
type Grant struct {
	ID string

	// RequestID is the approval Request that authorized this Grant. The
	// Requirement, the decisions, and the approvers all live there — this type
	// deliberately does not duplicate them, so there is exactly one place
	// quorum is evaluated.
	RequestID string

	// Scope and the window are what the approver agreed to.
	Scope     Scope
	StartsAt  time.Time
	ExpiresAt time.Time

	// MaxUses caps how many dispatches this Grant may release. Required.
	MaxUses int
	// Uses is how many it has released so far.
	Uses int

	// Summary is the Relay-authored description of the Scope, stored rather
	// than recomputed for the same reason Request.Summary is: what the human
	// was shown is a fact about the past, and re-rendering it from today's
	// config would quietly rewrite history.
	Summary string

	CreatedAt time.Time

	// RevokedAt is set when an operator ends the Grant early. A window is a
	// period of reduced friction, and reduced friction against a compromised
	// requester is exactly when someone needs to close it without reaching for
	// the fleet-wide Freeze.
	RevokedAt time.Time
	// RevokedBy and RevokeReason attribute the revocation.
	RevokedBy    string
	RevokeReason string
}

// Validate refuses a Grant that is not bounded in every dimension.
//
// It is called at creation, not at use: an unbounded Grant must be impossible
// to store, not merely ineffective. Every branch here is a wall that ADR-0027's
// "bounded in scope and time" depends on.
func (g Grant) Validate() error {
	if strings.TrimSpace(g.ID) == "" {
		return fmt.Errorf("approval: grant has no id")
	}
	if strings.TrimSpace(g.RequestID) == "" {
		return fmt.Errorf("approval: grant %q has no approval request; a grant is never self-authorizing", g.ID)
	}
	if err := g.Scope.Validate(); err != nil {
		return fmt.Errorf("approval: grant %q: %w", g.ID, err)
	}

	if g.ExpiresAt.IsZero() || !g.ExpiresAt.After(g.StartsAt) {
		return fmt.Errorf("%w: grant %q has no window", ErrGrantUnbounded, g.ID)
	}
	if window := g.ExpiresAt.Sub(g.StartsAt); window > MaxGrantWindow {
		return fmt.Errorf("%w: grant %q spans %s, above the %s maximum",
			ErrGrantUnbounded, g.ID, window, MaxGrantWindow)
	}
	if g.MaxUses < 1 {
		return fmt.Errorf("%w: grant %q has no use limit", ErrGrantUnbounded, g.ID)
	}
	if g.MaxUses > MaxGrantUses {
		return fmt.Errorf("%w: grant %q allows %d uses, above the %d maximum",
			ErrGrantUnbounded, g.ID, g.MaxUses, MaxGrantUses)
	}
	return nil
}

// Validate refuses an unbounded Scope. See the type doc: omission is the unsafe
// direction here, so every bound is required.
func (s Scope) Validate() error {
	if strings.TrimSpace(s.Account) == "" {
		return fmt.Errorf("%w: scope names no requesting account", ErrGrantUnbounded)
	}
	if s.RiskClass == jobs.RiskClassUnspecified {
		return fmt.Errorf("%w: scope names no risk class (read and mutate are never interchangeable)", ErrGrantUnbounded)
	}
	if s.MaxFanOut < 1 {
		return fmt.Errorf("%w: scope has no max_fan_out ceiling", ErrGrantUnbounded)
	}
	if len(s.Operations) == 0 && !s.RawExec {
		return fmt.Errorf("%w: scope covers no operations; an empty list covers nothing, not everything", ErrGrantUnbounded)
	}
	for _, op := range s.Operations {
		if strings.TrimSpace(op) == "" {
			return fmt.Errorf("%w: scope contains an empty operation name", ErrGrantUnbounded)
		}
	}
	switch s.SelectorNamespace {
	case "", "node", "relay", "tag":
	default:
		return fmt.Errorf("approval: scope has unknown selector namespace %q (want node, relay, or tag)", s.SelectorNamespace)
	}
	return nil
}

// Active reports whether g may cover anything at now: not revoked, inside its
// window, and not exhausted.
func (g Grant) Active(now time.Time) bool {
	if !g.RevokedAt.IsZero() {
		return false
	}
	if now.Before(g.StartsAt) || !now.Before(g.ExpiresAt) {
		return false
	}
	return g.Uses < g.MaxUses
}

// Covers reports whether g covers dispatch d at now.
//
// It is deliberately a pure predicate over stored state: a Grant covers a
// dispatch or it does not, and nothing about the caller, the clock source, or
// the registry can make a borderline case go the permissive way. Every check is
// a conjunction, and the fan-out check is the ceiling that stops a grant
// written for a handful of Nodes covering the fleet after the registry grows.
func (g Grant) Covers(d Dispatch, now time.Time) bool {
	if !g.Active(now) {
		return false
	}
	if !strings.EqualFold(g.Scope.Account, d.Account) {
		return false
	}
	if g.Scope.RiskClass != d.RiskClass {
		return false
	}
	if d.FanOut > g.Scope.MaxFanOut {
		return false
	}
	if g.Scope.SelectorNamespace != "" && !hasNamespace(d.Namespaces, g.Scope.SelectorNamespace) {
		return false
	}
	if d.RawExec {
		return g.Scope.RawExec
	}
	for _, op := range g.Scope.Operations {
		if strings.EqualFold(op, d.Operation) {
			return true
		}
	}
	return false
}

// Revoked reports whether g was ended early.
func (g Grant) Revoked() bool { return !g.RevokedAt.IsZero() }

// Remaining reports how many more dispatches g may cover.
func (g Grant) Remaining() int {
	if g.Uses >= g.MaxUses {
		return 0
	}
	return g.MaxUses - g.Uses
}

// Progress renders use against limit for a human ("3 of 20 used").
func (g Grant) Progress() string {
	return fmt.Sprintf("%d of %d used", g.Uses, g.MaxUses)
}

// SummarizeScope renders the Relay-authored description of what a Grant covers
// — the text an approver reads before agreeing to it.
//
// Like Summarize for a single Plan, this is written HERE from the Relay's own
// state and never from anything the requester supplied as prose. The agent
// proposes the scope; it does not get to choose the words describing it, so it
// cannot make a broad grant read as a narrow one (ADR-0027).
func SummarizeScope(s Scope, startsAt, expiresAt time.Time, maxUses int) string {
	what := "raw exec"
	if len(s.Operations) > 0 {
		ops := append([]string(nil), s.Operations...)
		sort.Strings(ops)
		what = strings.Join(ops, ", ")
		if s.RawExec {
			what += ", and raw exec"
		}
	}

	where := "any Selector"
	if s.SelectorNamespace != "" {
		where = "Selectors using " + s.SelectorNamespace + ":"
	}

	return fmt.Sprintf(
		"%s [%s] requested by %s, %s, up to %d node(s) per dispatch, at most %d dispatch(es), from %s until %s",
		what, RiskClassName(s.RiskClass), s.Account, where, s.MaxFanOut, maxUses,
		startsAt.UTC().Format(time.RFC3339), expiresAt.UTC().Format(time.RFC3339),
	)
}
