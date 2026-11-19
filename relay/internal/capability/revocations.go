package capability

import (
	"context"
	"errors"
	"time"
)

// Node and Enrollment Token revocation authorize, act and record here, never
// per interface (invariant 10, EX-7, EN-19, EN-20).

var (
	// ErrRevokeCascadeIncomplete reports that the Enrollment Token was revoked
	// but the registry could not be read completely.
	ErrRevokeCascadeIncomplete = errors.New("capability: the Enrollment Token was revoked, but the registry could not be read completely; Nodes enrolled under it may still be trusted")
	// ErrRevokeCascadeNotRecorded reports that the token and its Nodes were
	// revoked but one or more Node revocation records were not written.
	ErrRevokeCascadeNotRecorded = errors.New("capability: the Enrollment Token and its Nodes were revoked, but one or more Node revocation records were not written")
)

// cascadeAuditBudget bounds the detached cascade record writes on the single
// store connection. A chunk that misses it is counted unrecorded (R12). The
// registry half is deliberately not bounded by it: stopping those writes would
// leave Nodes denylisted in memory only, and a restart would un-revoke them.
const cascadeAuditBudget = 2 * time.Minute

// Revocations revokes Nodes and Enrollment Tokens for the Control API: an
// admin, a validated reason, the act and its records. Construct it with
// NewRevocations.
type Revocations struct {
	control *Control
	revoker Revoker
	rec     RevokeRecorder
}

// NewRevocations returns a Revocations over control and revoker. It requires a
// real Authorizer and an AuditSink that is also a RevokeRecorder, read through
// control, so there is one Recorder and one trail: an un-floored or unrecorded
// revoke is a composition-root bug and panics.
func NewRevocations(control *Control, revoker Revoker) *Revocations {
	if control == nil {
		panic("capability: NewRevocations: control must not be nil")
	}
	if revoker == nil {
		panic("capability: NewRevocations: revoker must not be nil")
	}
	if _, ok := control.authz.(allowAllAuthorizer); ok {
		panic("capability: NewRevocations: requires a real Authorizer (NewControl); allowAllAuthorizer would fail open on every revoke")
	}
	if _, ok := control.rec.audit.(noopAuditSink); ok {
		panic("capability: NewRevocations: requires a real AuditSink (NewRecorder); noopAuditSink would record no revoke")
	}
	rec, ok := control.rec.audit.(RevokeRecorder)
	if !ok {
		panic("capability: NewRevocations: the AuditSink must also be a RevokeRecorder; without it a revoke cannot be recorded")
	}
	return newRevocations(control, revoker, rec)
}

// newRevocations assembles a Revocations with no checks. Only NewRevocations
// and _test.go files call it.
func newRevocations(control *Control, revoker Revoker, rec RevokeRecorder) *Revocations {
	return &Revocations{control: control, revoker: revoker, rec: rec}
}

// RevokeNodeWithReason revokes one Node, tearing down its live Tunnel. It asks
// the ControlRevokeNode floor first, so a refused caller learns nothing about
// the reason rule; the refusal is audited. An unusable reason is refused
// unaudited, before any act. The node_revoke record precedes the act, under the
// Node's lock: an error means the Node was not revoked. Revoking an unknown or
// already-revoked Node succeeds.
func (r *Revocations) RevokeNodeWithReason(ctx context.Context, p Principal, nodeID, reason string) error {
	if err := r.control.authorizeAct(ctx, p, ControlRevokeNode); err != nil {
		return err
	}
	trimmed, err := ValidateRevokeReason(reason)
	if err != nil {
		return err
	}
	asserted := AssertionsFromContext(ctx)
	record := func(nodeIDs []string) error {
		return r.rec.RecordNodeRevokes(ctx, NodeRevokeEvent{Principal: p, Asserted: asserted, NodeIDs: nodeIDs, Reason: trimmed})
	}
	// The request ctx, not WithoutCancel: the record precedes the act, so a
	// cancelled wait has caused nothing.
	return r.revoker.RevokeNodeRecorded(ctx, nodeID, record)
}

// RevokeEnrollmentToken revokes a token and cascades to every Node it
// enrolled (EN-19), recording one node_revoke per cascaded Node and one
// token_revoke. The floor is asked before the token id is rendered into the
// cascade's reason, so a refused caller is refused whatever the id.
//
// The cascade performs irreversible acts, so its records are written on a
// context detached from the request, under cascadeAuditBudget. The budget
// starts before the act, so a second revoke of the same token waiting on the
// first spends it too; expiry is reported as a shortfall, never a silent
// success.
//
// token_revoke is written after the act and is best-effort: the act can fail,
// so recording first could leave a record of a revoke that never happened, and
// a failed record never undoes a revoke that took effect.
func (r *Revocations) RevokeEnrollmentToken(ctx context.Context, p Principal, tokenID string) error {
	if err := r.control.authorizeAct(ctx, p, ControlRevokeEnrollmentToken); err != nil {
		return err
	}
	// tokenID is raw caller input, not a store-validated value: without this, a
	// control character in it would be persisted into every cascade record.
	reason, err := ValidateRevokeReason(CascadeRevokeReason(tokenID))
	if err != nil {
		return err
	}
	asserted := AssertionsFromContext(ctx)
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cascadeAuditBudget)
	defer cancel()
	record := func(nodeIDs []string) error {
		return r.rec.RecordNodeRevokes(auditCtx, NodeRevokeEvent{Principal: p, Asserted: asserted, NodeIDs: nodeIDs, Reason: reason})
	}

	err = r.revoker.RevokeToken(ctx, tokenID, record)
	switch {
	case errors.Is(err, ErrRevokeCascadeIncomplete):
		// The token was revoked: the cascade only reads the registry after the
		// token barrier. Recorded, marked incomplete.
		r.recordTokenRevoke(ctx, p, asserted, tokenID, true)
	case err != nil && !errors.Is(err, ErrRevokeCascadeNotRecorded):
		return err
	default:
		r.recordTokenRevoke(ctx, p, asserted, tokenID, false)
	}
	return err
}

func (r *Revocations) recordTokenRevoke(ctx context.Context, p Principal, asserted Assertions, tokenID string, incomplete bool) {
	err := r.rec.RecordEnrollmentTokenRevoke(ctx, EnrollmentTokenRevokeEvent{
		Principal: p, Asserted: asserted, TokenID: tokenID, CascadeIncomplete: incomplete,
	})
	if err != nil {
		r.control.rec.logger().ErrorContext(ctx, "capability: enrollment token revoke not recorded", "token_id", tokenID, "error", err)
	}
}
