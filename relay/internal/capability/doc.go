// Package capability is the Relay's single capability layer: the pipeline
// every control-path surface (MCP, the Control API, the Admin Console, any
// future CLI) must go through to act on Nodes — Selector -> authz ->
// blast-cap -> dispatch -> audit (ADR-0009/0010, invariant 10). It is one
// package of bounded services over one Recorder: Execution, Approvals,
// ReadLane, AccountAdmin and Control.
//
// No surface may build a parallel path to a Node: every surface reaches Nodes
// only through Execution.Run and Start. The dispatch type and its constructor
// are unexported, so a surface that tries to dispatch without going through
// them fails to compile (dispatch.go, dispatch_construction_test.go).
//
// capability imports registry and jobs only — no database/sql, no audit, no
// relayv1 proto — preserving the store-swap and contract boundaries the rest
// of the Relay relies on.
package capability
