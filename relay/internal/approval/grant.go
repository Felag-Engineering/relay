package approval

import (
	"crypto/sha256"
	"encoding/hex"
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

	// ErrGrantInvalid is returned by Validate for a Scope that is malformed
	// rather than unbounded — a name the storage encoding cannot represent, or
	// a retired namespace pin. Kept distinct from ErrGrantUnbounded so a
	// surface can tell "you did not close this wall" from "this is not a thing
	// you can write", which are different mistakes to an operator.
	ErrGrantInvalid = errors.New("approval: grant is malformed")
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

	// LegacyNamespacePin is the Selector namespace a Grant stored before #482
	// was pinned to. Only the store's read path sets it. Validate refuses it,
	// so a new Grant can never carry one. A pinned Grant was PRICED over that
	// one namespace but COVERED any dispatch whose Selector merely used it, so
	// it may have been approved more cheaply than work it could release.
	// Ignoring the pin would widen it further, so a Grant carrying one covers
	// nothing (see Active).
	LegacyNamespacePin string

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
	if g.LegacyNamespacePin != "" {
		return fmt.Errorf("%w: grant %q pins selector namespace %q, and namespace pinning is not part of a Scope",
			ErrGrantInvalid, g.ID, g.LegacyNamespacePin)
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
		// The store encodes this list comma-separated (migration 0014). A comma
		// inside a name would split one Operation into two on read-back, which
		// on an allow-list means covering something nobody approved. Refused
		// here rather than escaped there, so the encoding cannot be the thing
		// that decides what a grant covers.
		if strings.Contains(op, ",") {
			return fmt.Errorf("%w: operation name %q contains a comma, which the grant encoding reserves as a separator", ErrGrantInvalid, op)
		}
	}
	return nil
}

// Active reports whether g may cover anything at now: not revoked, inside its
// window, not exhausted, and not a pre-#482 namespace-pinned Grant (fail
// closed, see LegacyNamespacePin).
func (g Grant) Active(now time.Time) bool {
	if g.LegacyNamespacePin != "" {
		return false
	}
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
//
// A Scope has no namespace term, so no dispatch is covered or refused
// because of the label namespaces its Selector used. That is why
// RequirementForScope prices every Grant over all of them.
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
// state and never from anything the requester supplied as prose. The AI-agent
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

	return fmt.Sprintf(
		"%s [%s] requested by %s, %s, up to %d node(s) per dispatch, at most %d dispatch(es), from %s until %s",
		what, jobs.RiskClassName(s.RiskClass), s.Account, where, s.MaxFanOut, maxUses,
		startsAt.UTC().Format(time.RFC3339), expiresAt.UTC().Format(time.RFC3339),
	)
}

// HashScope content-addresses what a Grant's approver is agreeing to: the
// Scope and its bounds, together.
//
// A grant request is an approval Request like any other, so it carries a plan
// hash and a decision must cite it. Hashing the SCOPE gives that binding real
// meaning here: an approver's answer cannot be replayed onto a grant whose
// walls have moved. Widening the fan-out ceiling, adding an Operation, or
// extending the window all change the hash, so the old approval simply is not
// an approval of the new thing.
//
// The encoding is length-prefixed for the same reason HashPlan's is: a
// separator-joined encoding is ambiguous when the values are caller-influenced,
// and Operation names are.
func HashScope(s Scope, startsAt, expiresAt time.Time, maxUses int) string {
	h := sha256.New()

	writeField(h, "kind", "grant")
	writeField(h, "account", s.Account)
	writeField(h, "risk", jobs.RiskClassName(s.RiskClass))
	// Retained as an always-empty field so the digest of every unpinned Scope
	// (the only kind that can now exist) is byte-identical to what
	// approval_requests.plan_hash already stores.
	writeField(h, "namespace", "")
	writeCount(h, "max_fan_out", s.MaxFanOut)
	// raw_exec is a bool, not an int; writeCount takes an int and there is no
	// bool primitive, so this stays a direct Fprintf.
	fmt.Fprintf(h, "raw_exec=%t\n", s.RawExec)
	writeCount(h, "max_uses", maxUses)

	ops := append([]string(nil), s.Operations...)
	sort.Strings(ops)
	writeCount(h, "ops", len(ops))
	for _, op := range ops {
		writeField(h, "op", op)
	}

	writeField(h, "starts", startsAt.UTC().Format(time.RFC3339Nano))
	writeField(h, "expires", expiresAt.UTC().Format(time.RFC3339Nano))

	return hex.EncodeToString(h.Sum(nil))
}

// ShapeKey is the Grant's shape key: a hash over its Scope minus the bounds
// that are scale (the window, the use limit, and the fan-out ceiling — see
// HashGrantShape).
//
// DERIVED, not stored. Every input is already a scope_* column on
// approval_grants, so it is always exactly recomputable and can never go stale
// against the Scope it describes — which is why migration 0022 adds a shape_key
// column to approval_requests and deliberately none here.
//
// A legacy pinned Grant (LegacyNamespacePin) keeps the key it was stored
// under, so the shape-key backfill still recomputes it exactly and the diff
// callout never shows a dead pinned Grant as "same shape" as a live unpinned
// one.
func (g Grant) ShapeKey() string { return hashGrantShape(g.Scope, g.LegacyNamespacePin) }

// knownNamespaces are the label namespaces a Selector may use (ADR-0006,
// ADR-0020, ADR-0034). RequirementForScope ALWAYS walks every one. A Scope has
// no namespace term, so a Grant can cover a dispatch whose Selector
// uses any of them, and in any combination. Probing each namespace on its own
// is exactly that worst case, because a gate Match names at most one namespace
// and a multi-namespace dispatch matches the union of what its single-namespace
// probes match. The probes are merged with mergeStricter, which is strictest
// for count, channel, requester exclusion and decision deadline (TTL), and a
// union for audience (owner-accepted residual risk, ADR-0027 amendment
// 2026-09-16).
//
// Before #482 a pinned Scope was priced over its one namespace while Covers
// admitted any dispatch CONTAINING it, so a Grant could release work needing a
// stronger approval than it was issued under. That class of defect is removed
// by removing the pin, not by patching either side.
//
// This list is now load-bearing: dropping a namespace a gate rule can name
// would let a Grant be priced below a rule in that namespace. Rule.Validate
// (gate.go) accepts a Match.SelectorNamespace by consulting THIS list rather
// than a second hardcoded set, so the two vocabularies cannot drift apart —
// there is only one to widen or narrow, and widening it here is exactly what
// widens what a rule may name (TestRequirementForScopeProbesEveryKnownNamespace,
// TestKnownNamespacesMatchGateRuleNamespaces).
var knownNamespaces = []string{"node", "relay", "tag", "state"}

// RequirementForScope derives what a Grant over s must satisfy: the
// Requirement priced at the strictest count, channel, requester exclusion and
// decision deadline (TTL) any dispatch the Grant could cover would itself have
// faced, with an approver audience that is the UNION of those dispatches'
// audiences (a rule with no audience makes it unrestricted).
//
// This is the property that stops a grant being a way around the gate for
// count, channel, requester exclusion and decision deadline. If "mutate on
// 10+ Nodes needs two people" and a grant would cover exactly that, the grant
// needs two people. Deriving it — rather than letting the requester or a
// separate config say what a grant costs — means a grant is never priced more
// cheaply on those four dimensions than the dispatches it replaces. The
// audience is not priced the same way: it is the union across matched rules,
// so a Grant's approver set can be wider than a covered dispatch's own
// (owner-accepted residual risk, ADR-0027 amendment 2026-09-16).
//
// It evaluates the gate at the Scope's WORST CASE: the fan-out ceiling (the
// widest dispatch the grant admits), every Operation in the allow-list, Raw
// Exec if opted in, and every namespace a Selector could use (a Scope never
// narrows by namespace). Merging those is the same mergeStricter the Gate
// itself uses for overlapping rules.
//
// gated is false when nothing the Grant could cover would have parked at all.
// A caller should refuse that rather than create the Grant: a grant covering
// only ungated work grants nothing, and storing one would put a live
// authorization in the table for no reason.
func RequirementForScope(s Scope, evaluate func(Dispatch) (Requirement, []string, bool)) (Requirement, []string, bool) {
	// Each probe is the widest dispatch this Scope admits for one
	// (operation, namespace) pair — the fan-out ceiling, not some typical size.
	var probes []Dispatch
	for _, ns := range knownNamespaces {
		for _, op := range s.Operations {
			probes = append(probes, Dispatch{
				RiskClass:  s.RiskClass,
				FanOut:     s.MaxFanOut,
				Namespaces: []string{ns},
				Account:    s.Account,
				Operation:  op,
			})
		}
		if s.RawExec {
			probes = append(probes, Dispatch{
				RiskClass:  s.RiskClass,
				FanOut:     s.MaxFanOut,
				Namespaces: []string{ns},
				Account:    s.Account,
				RawExec:    true,
			})
		}
	}

	var (
		merged  Requirement
		names   []string
		matched bool
		seen    = map[string]struct{}{}
	)
	for _, d := range probes {
		req, rules, gated := evaluate(d)
		if !gated {
			continue
		}
		if !matched {
			merged, matched = req, true
		} else {
			merged = mergeStricter(merged, req)
		}
		for _, r := range rules {
			if _, dup := seen[r]; dup {
				continue
			}
			seen[r] = struct{}{}
			names = append(names, r)
		}
	}
	if !matched {
		return Requirement{}, nil, false
	}
	sort.Strings(names)
	return merged.normalized(), names, true
}

// ActionKind reports the Action kind a Grant's approval should be authorized
// against: Raw Exec when the Scope covers it, otherwise a structured Operation.
//
// The stricter of the two wins, because the role floor on approving a grant
// must be the floor for the most powerful thing it can release. A grant
// covering Raw Exec needs an admin to approve it even if it also covers
// ordinary Operations.
func (s Scope) ActionKind() jobs.ActionKind {
	if s.RawExec {
		return jobs.ActionRawExec
	}
	return jobs.ActionOperation
}

// NewGrantRequest builds the pending approval Request that authorizes g.
//
// Creating a Grant is not a separate kind of act with its own rules: it IS an
// approval Request, whose subject happens to be a Scope rather than a Plan. So
// everything that makes a single approval trustworthy applies unchanged — the
// quorum, the audience, the requester exclusion, the machine-cannot-self-decide
// rule, and the channel floor all come from the same Requirement machinery.
//
// It takes the whole Grant rather than the parts because the Request's
// PlanHash, its Summary, and its deadline must all describe THAT grant. Passing
// them separately would make "the approver read one thing and authorized
// another" a call-site mistake; taking the Grant makes it unrepresentable.
//
// The Request never carries a JobID, for a stronger reason than the single-Plan
// case: a Grant releases MANY Jobs, so there is no one Job to bind. The join
// from an authorization to the executions it released runs the other way, from
// the audit trail's grant_id.
func NewGrantRequest(g Grant, requestedByID, requestedBy string, rules []string, req Requirement, now time.Time) Request {
	req = req.normalized()

	// The human has until the window closes, and no longer. An approval that
	// lands after the Grant's own expiry authorizes nothing anyway, and a
	// Request that outlives its subject is a queue entry whose only possible
	// outcome is a no-op.
	expires := now.Add(req.TTL)
	if !g.ExpiresAt.IsZero() && g.ExpiresAt.Before(expires) {
		expires = g.ExpiresAt
	}

	return Request{
		ID:       g.RequestID,
		PlanHash: HashScope(g.Scope, g.StartsAt, g.ExpiresAt, g.MaxUses),
		// The same key the Grant itself carries, so a grant's queue card groups
		// and diffs against the Grant it authorizes rather than against a
		// separately-derived approximation of it.
		ShapeKey:      g.ShapeKey(),
		RequestedByID: requestedByID,
		RequestedBy:   requestedBy,
		Summary:       g.Summary,
		MatchedRules:  rules,
		// The role floor for deciding this Request is the floor for the most
		// powerful thing the Grant can release (Scope.ActionKind), not for some
		// nominal one: releasing a Raw-Exec-covering window is at least as
		// consequential as releasing one Raw Exec.
		ActionKind: g.Scope.ActionKind(),
		RiskClass:  g.Scope.RiskClass,
		Require:    req,
		State:      StatePending,
		CreatedAt:  now,
		ExpiresAt:  expires,
	}
}
