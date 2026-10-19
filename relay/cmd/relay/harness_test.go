package main

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// serveControlPlane starts deps.control's HTTPS listener on a real TCP
// 127.0.0.1:0 address (the control plane needs a real net.Listener; bufconn
// only wraps gRPC's dialer) and registers its Shutdown as a t.Cleanup. It
// returns the control-plane base URL and a cert pool trusting deps.ca — the
// verbatim listener+pool setup every appDeps-bound control-plane e2e starter
// needs (startControlAPIServer, startSurfaceHarness, mcp_execution's harness).
func serveControlPlane(t *testing.T, deps *appDeps) (base string, pool *x509.CertPool) {
	t.Helper()

	controlLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen (control-plane): %v", err)
	}
	go func() { _ = deps.control.Serve(controlLis) }()
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = deps.control.Shutdown(shutdownCtx)
	})

	pool = relaytest.CertPool(t, deps.ca.Bundle())
	return "https://" + controlLis.Addr().String(), pool
}

// testAdminName names the founding admin the in-process fixtures create. No
// name is reserved, so it is an ordinary name.
const testAdminName = "first-admin"

// testAdmin is the founding admin's Principal shape: the name, role and kind
// principalFromAccount projects from the Account bootstrapCredential creates.
func testAdmin() capability.Principal {
	return capability.Principal{
		Account: testAdminName,
		Role:    string(accounts.RoleAdmin),
		Kind:    string(accounts.KindHuman),
	}
}

// bootstrapCredential creates the founding admin Account in deps' store if it
// is absent, mints it an API Token and returns the plaintext — the in-process
// stand-in for `relay init`, which is how a real operator obtains the first
// credential (ADR-0030). init's own path is proven over the shippable binary
// in init_e2e_test.go.
//
// It mints through the real accounts.TokenService against the real store, so a
// test using it authenticates over exactly the production path.
func bootstrapCredential(t *testing.T, deps *appDeps) string {
	t.Helper()
	ctx := context.Background()

	admin, err := deps.store.Accounts().GetByName(ctx, testAdminName)
	if errors.Is(err, accounts.ErrNotFound) {
		admin, err = deps.store.Accounts().Create(ctx, accounts.Account{
			Name: testAdminName, Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true,
		})
	}
	if err != nil {
		t.Fatalf("create the founding admin: %v", err)
	}
	svc := accounts.NewTokenService(deps.store.APITokens(), deps.store.Accounts(), nil)
	_, plaintext, err := svc.Mint(ctx, admin.ID, "test-bootstrap", time.Hour)
	if err != nil {
		t.Fatalf("mint bootstrap token: %v", err)
	}
	return plaintext.Reveal()
}

// staticVerifier is a controlplane.TokenVerifier accepting exactly one
// credential, as the founding admin Account. For tests whose subject is a
// route or a surface rather than the credential path itself; tests that care
// about authentication use bootstrapCredential above and the real
// accounts.TokenService.
type staticVerifier struct{ credential string }

func (v staticVerifier) Verify(_ context.Context, credential string) (accounts.Account, accounts.APIToken, error) {
	if credential != v.credential {
		return accounts.Account{}, accounts.APIToken{}, accounts.ErrTokenInvalid
	}
	return accounts.Account{
		ID:      "acct-test-founding",
		Name:    testAdminName,
		Kind:    accounts.KindHuman,
		Role:    accounts.RoleAdmin,
		Enabled: true,
	}, accounts.APIToken{ID: "tok-test"}, nil
}
