// Package relaytest holds e2e/integration test helpers shared across
// cmd/relay's integration test files and internal/controlplane/mcp's tests.
//
// Everything here is appDeps-independent: pure crypto, wire-level MCP
// client calls against an address/*http.Client, or bare os/testing
// fixtures. Helpers that need Config/appDeps/newServer (unexported in
// package main) cannot live here and stay in cmd/relay.
//
// relaytest links into no production binary: only _test.go files import it.
package relaytest
