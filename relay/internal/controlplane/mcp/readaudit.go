package mcp

import (
	"context"
	"fmt"
)

// Read auditing.
//
// The audit trail was dispatch-only: it recorded Job/Task actions, so the four
// tools that never reach a Node — list_nodes, describe_node, list_operations,
// get_job — left no record at all beyond a debug log line that is normally
// switched off.
//
// That is a real hole, because **`read` means "cannot change Node state", not
// "safe to see"**. These tools disclose the fleet's shape: Node names, all
// three Label namespaces, Facts, and a Node's Policy — what is and is not
// permitted to run there. `get_job` goes further and returns the captured
// stdout of a previously-dispatched Task, so a caller can read back command
// output somebody else produced. After an incident, "who enumerated the fleet,
// and what did they read back" was unanswerable.
//
// **Metadata only, never content.** A read record says who read, which tool
// they used, what they aimed it at, and when — never what came back. Recording
// the result would copy the very material this decision is worried about into
// a trail that outlives the Job (ADR-0025).
//
// list_nodes, describe_node and list_operations go through the capability
// read lane (ReadLane, mcp.go): the record and the read are the same call,
// made there rather than through this seam. This file's
// ReadAuditor/auditRead serve only get_job (tools_jobs.go) and an
// answered retry's Job-bound re-attach (run_operation/raw_exec, tools_execution.go),
// which reads back a previously-dispatched Job's Task rows exactly as
// get_job does: the tools that read back a previously-dispatched Job's own
// Task rows rather than the registry or a display-only cache.

// ReadEvent is one non-dispatching read-tool call.
//
// Every field is either the tool or a pointer to what it was aimed at. There
// is deliberately no result field — see the note above.
type ReadEvent struct {
	// Tool is the MCP tool name, e.g. "get_job". Set by auditRead.
	Tool string

	// JobID is the Job a get_job call read back.
	JobID string
}

// ReadAuditor records a read-tool call. The composition root supplies an
// adapter that resolves the acting Account from ctx and appends to the audit
// trail.
//
// Narrow and **write-only**: the read surface can append its own access
// records and cannot read, amend, or delete anything, including its own. An
// append-only trail whose writer can also edit it is not append-only.
//
// It takes only a context and an event — no Principal — so this package never
// names a capability type on its read path, keeping the read files within the
// narrow surface no_dispatch_test.go enforces.
type ReadAuditor interface {
	RecordRead(ctx context.Context, e ReadEvent) error
}

// auditRead records one read-tool call. A non-nil return fails the tool call.
//
// **Fail closed.** An unauditable read must not silently happen — that is the
// entire point of auditing reads, and it matches the precedent the capability
// layer already sets for Plan, whose audit-write failure fails the Plan. The
// cost is real and worth stating plainly: a Relay that cannot write its audit
// trail stops answering read tools rather than answering them invisibly. On
// this side of the system that is the right way round (AGENTS.md: prefer the
// more restrictive option).
//
// A nil auditor logs at debug only, and exists so
// tests and any surface that has not been wired yet keep working rather than
// failing shut on a missing dependency.
func auditRead(ctx context.Context, a ReadAuditor, tool string, e ReadEvent) error {
	logPrincipal(ctx, tool)
	if a == nil {
		return nil
	}
	e.Tool = tool
	if err := a.RecordRead(ctx, e); err != nil {
		return fmt.Errorf("mcp: record read audit for %s: %w", tool, err)
	}
	return nil
}
