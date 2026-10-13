package capability

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Control is the Relay-wide Freeze and the role floor on it (ADR-0013):
// engaging and releasing the emergency stop, from a surface or from root on the
// host. Construct it with NewControl. It also carries the Authorizer that
// AccountAdmin shares, so one role floor and one trail govern every
// control-plane act.
type Control struct {
	rec    *Recorder
	authz  Authorizer
	freeze FreezeStore
}

// NewControl returns a Control over rec, authz and freeze. All three are
// required: a nil Recorder cannot record a Freeze, a nil Authorizer cannot
// gate one, and a nil FreezeStore has nothing to engage — a composition-root
// bug, so each panics rather than degrading.
func NewControl(rec *Recorder, authz Authorizer, freeze FreezeStore) *Control {
	if rec == nil {
		panic("capability: NewControl: recorder must not be nil")
	}
	if authz == nil {
		panic("capability: NewControl: authorizer must not be nil")
	}
	if freeze == nil {
		panic("capability: NewControl: freezeStore must not be nil")
	}
	return newControl(rec, authz, freeze)
}

// newControl assembles a Control with no checks. Only NewControl and _test.go
// files call it; it is the only route to a Control holding the no-op
// FreezeStore.
func newControl(rec *Recorder, authz Authorizer, freeze FreezeStore) *Control {
	return &Control{rec: rec, authz: authz, freeze: freeze}
}

// ErrFreezeReasonRequired is returned by ReleaseFreeze when reason is empty
// or whitespace. ADR-0013's asymmetric activation is not decoration: engaging
// the emergency stop is cheap and reason-free, and releasing it is the
// deliberate act that must say why, because the reason is what a later reader
// has to reconstruct the incident from. Enforced here rather than per surface
// so a Console or a future CLI cannot release without one.
var ErrFreezeReasonRequired = errors.New("capability: releasing the Freeze requires a non-empty reason (ADR-0013)")

// localHostPrincipal attributes an engage/release performed by root on the
// Relay host itself (the signal lever, cmd/relay/freeze_signal.go). It is
// deliberately role-less and kind-less: it is not an Account, it holds no
// credential, and its authority is process-signal privilege on the box —
// which is strictly greater than any API credential's.
//
// Defined here, once, so the attribution string recorded for the host lever
// cannot drift from the two methods allowed to use it.
func localHostPrincipal() Principal { return Principal{Account: "local-host"} }

// EngageFreeze sets the Relay-wide Freeze (ADR-0013), attributed to p:
// authorized first, then persisted (so a crash after the store call still
// leaves the Freeze engaged), then recorded via AuditSink.RecordFreeze. If
// persistence fails, the audit call is skipped — there is nothing true to
// record — and the persistence error is returned.
//
// The floor is `operator`, AND the Principal must be a human Account (#397).
// The role half is ADR-0013's "engage cheap": anyone who may run anything may
// also pull the cord. The human half is the amendment #397 records, and it is
// not a role question at all — a machine Account at `operator` freezing the
// fleet is a jailbroken AI-agent switching off its own overseers, a denial of
// service the fire-alarm argument does not cover. Authority is still the Role
// (principal.go); Kind answers only the question authority cannot.
//
// A refusal is audited as a refusal, with the Principal, exactly like a
// refused dispatch — see refuseControl.
func (c *Control) EngageFreeze(ctx context.Context, p Principal) error {
	if err := c.authz.AuthorizeControl(ctx, p, ControlFreezeEngage); err != nil {
		return c.rec.refuseControl(ctx, p, err)
	}
	return c.engageFreeze(ctx, p)
}

// EngageFreezeLocal engages the Freeze on behalf of root on the Relay host —
// ADR-0013's second activation path ("or locally on the Relay host"), which
// exists precisely for the case where the distrusted thing IS the API
// credential.
//
// It is a separate method rather than a Principal the role gate happens to
// wave through, because the two are different roots of authority and that
// difference should be visible at the call site. Authority-by-call-site is
// also what keeps it unreachable from any surface: the Control API holds a
// Freezer interface carrying only the gated pair (api.Freezer), so no route
// can reach this even by accident.
func (c *Control) EngageFreezeLocal(ctx context.Context) error {
	return c.engageFreeze(ctx, localHostPrincipal())
}

func (c *Control) engageFreeze(ctx context.Context, p Principal) error {
	if err := c.freeze.Engage(ctx, p.Attribution()); err != nil {
		return fmt.Errorf("capability: engage freeze: %w", err)
	}
	return c.rec.audit.RecordFreeze(ctx, FreezeEvent{Principal: p, Engage: true, Asserted: AssertionsFromContext(ctx)})
}

// ReleaseFreeze clears the Relay-wide Freeze (ADR-0013), attributed to p with
// reason recorded for why: authorized first, then persisted, then recorded
// via AuditSink.RecordFreeze, mirroring EngageFreeze.
//
// The floor is `admin` and the reason is mandatory (#397, ADR-0013): the
// fire-alarm asymmetry is that anyone may pull the handle and the chief
// clears re-entry. Both refusals are audited with the Principal.
func (c *Control) ReleaseFreeze(ctx context.Context, p Principal, reason string) error {
	if err := c.authz.AuthorizeControl(ctx, p, ControlFreezeRelease); err != nil {
		return c.rec.refuseControl(ctx, p, err)
	}
	if strings.TrimSpace(reason) == "" {
		return c.rec.refuseControl(ctx, p, ErrFreezeReasonRequired)
	}
	return c.releaseFreeze(ctx, p, reason)
}

// ReleaseFreezeLocal is EngageFreezeLocal's counterpart: release by root on
// the Relay host. The reason stays mandatory — the local lever is a different
// root of authority, not an exemption from saying why the fleet is running
// again.
func (c *Control) ReleaseFreezeLocal(ctx context.Context, reason string) error {
	if strings.TrimSpace(reason) == "" {
		return ErrFreezeReasonRequired
	}
	return c.releaseFreeze(ctx, localHostPrincipal(), reason)
}

func (c *Control) releaseFreeze(ctx context.Context, p Principal, reason string) error {
	if err := c.freeze.Release(ctx, p.Attribution(), reason); err != nil {
		return fmt.Errorf("capability: release freeze: %w", err)
	}
	return c.rec.audit.RecordFreeze(ctx, FreezeEvent{Principal: p, Engage: false, Reason: reason, Asserted: AssertionsFromContext(ctx)})
}
