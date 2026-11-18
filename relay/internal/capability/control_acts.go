package capability

import "context"

// The authorization of the Control API's Enrollment Token and Node revocation
// acts. The acts themselves run outside this layer; who may perform them, and
// the record of a refusal, are decided here and never per interface
// (invariant 10, EX-7).

// AuthorizeEnrollmentTokenMint asks the ControlMintEnrollmentToken floor that
// EnrollmentTokens' mint asks again. A surface asks it first so a refused
// caller is refused before its request body is read (EN-1).
func (c *Control) AuthorizeEnrollmentTokenMint(ctx context.Context, p Principal) error {
	return c.authorizeAct(ctx, p, ControlMintEnrollmentToken)
}

// AuthorizeEnrollmentTokenRevoke authorizes an Enrollment Token revoke, which
// cascades to every Node the token enrolled (EN-19).
func (c *Control) AuthorizeEnrollmentTokenRevoke(ctx context.Context, p Principal) error {
	return c.authorizeAct(ctx, p, ControlRevokeEnrollmentToken)
}

// AuthorizeNodeRevoke authorizes a Node revoke.
func (c *Control) AuthorizeNodeRevoke(ctx context.Context, p Principal) error {
	return c.authorizeAct(ctx, p, ControlRevokeNode)
}

// authorizeAct hides caller-asserted attribution from the Authorizer (EX-7).
// The refusal record keeps it, because refuseControl is handed the unmasked
// ctx. An allowed act records nothing: its own record belongs to whoever
// performs it.
func (c *Control) authorizeAct(ctx context.Context, p Principal, act ControlAction) error {
	if err := c.authz.AuthorizeControl(withoutAssertions(ctx), p, act); err != nil {
		return c.rec.refuseControl(ctx, p, err)
	}
	return nil
}
