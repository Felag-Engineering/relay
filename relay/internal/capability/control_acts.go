package capability

import "context"

// Early asks for the routes that read a request body before they can call the
// layer. The act itself (EnrollmentTokens' mint, Revocations' Node revoke)
// authorizes again, so the floor and the refusal's record are decided here and
// never per interface (invariant 10, EX-7).

// AuthorizeEnrollmentTokenMint asks the ControlMintEnrollmentToken floor that
// EnrollmentTokens' mint asks again. A surface asks it first so a refused
// caller is refused before its request body is read (EN-1).
func (c *Control) AuthorizeEnrollmentTokenMint(ctx context.Context, p Principal) error {
	return c.authorizeAct(ctx, p, ControlMintEnrollmentToken)
}

// AuthorizeNodeRevoke asks the ControlRevokeNode floor that Revocations' Node
// revoke asks again. A surface asks it first so a refused caller is refused
// before its request body is read.
func (c *Control) AuthorizeNodeRevoke(ctx context.Context, p Principal) error {
	return c.authorizeAct(ctx, p, ControlRevokeNode)
}

// authorizeAct hides caller-asserted attribution from the Authorizer (EX-7).
// The refusal record keeps it, because refuseControl is handed the unmasked
// ctx. An allowed ask records nothing: the act's own record belongs to the
// entry point that performs it.
func (c *Control) authorizeAct(ctx context.Context, p Principal, act ControlAction) error {
	if err := c.authz.AuthorizeControl(withoutAssertions(ctx), p, act); err != nil {
		return c.rec.refuseControl(ctx, p, err)
	}
	return nil
}
