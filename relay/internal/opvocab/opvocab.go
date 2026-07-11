// Package opvocab is a Relay-side, READ-ONLY mirror of /proto's Operation
// vocabulary (OperationDescriptor, gleipnir.proto:142-145): the fixed set of
// structured Operations, each with its risk class. /proto remains the single
// source of truth for the wire vocabulary (invariant 8) — this list MUST be
// kept in sync with it by hand; opvocab carries no proto or dispatch
// dependency, following the registry.Facts / jobs domain-mirror precedent so
// the MCP surface ([internal/controlplane/mcp]) can list Operations without
// importing the dispatch path.
//
// Raw Exec is deliberately NOT listed here: it is not an Operation
// (ADR-0003, CONTEXT.md) and has no OperationDescriptor on the wire. It is
// always risk class mutate by definition (arbitrary commands are
// unclassifiable) and surfaces through its own tool (#118), never this one.
package opvocab

import "github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"

// Descriptor mirrors gleipnirv1.OperationDescriptor's Name and Risk (the wire
// contract, invariant 8/ADR-0012), plus model-facing legibility PROSE that
// has no proto counterpart (#120, central decision: NO /proto change).
// Purpose, ArgConstraints, and Example are ADVISORY — they exist so a model
// reader (list_operations, MCP) can pick the right Operation and build valid
// args without trial-and-error (ADR-0001's typed-path-by-default safety
// assumption). They are NOT the enforcement: the daemon's own validate_*
// functions (daemon/src/operations/*.rs) are the real gate (ADR-0002,
// invariant 2), and this prose is kept in sync with them BY HAND — a mismatch
// here is a legibility bug, not a security hole, but it is exactly the
// failure this issue exists to prevent, so treat any daemon validator change
// as requiring a matching edit here.
type Descriptor struct {
	Name    string
	Risk    jobs.RiskClass
	Purpose string
	// ArgConstraints maps each documented argument name to
	// "type, required/optional. constraint prose." A zero-arg Operation
	// (system.facts) legitimately has an empty-but-non-nil map — that is
	// INTENTIONAL, not a placeholder still to be filled (see
	// TestOperations_Legible / TestOperations_DocumentedArgKeys in
	// opvocab_test.go).
	ArgConstraints map[string]string
	// Example is a concrete, runnable-shaped usage sample for
	// list_operations/run_operation's tool description.
	Example string
}

// Operations returns the fixed v1 Operation vocabulary, per
// gleipnir.proto:142-145:
//
//	system.facts     -> read    (self-reported Node facts; no state change)
//	file.read        -> read    (reads file contents; no state change)
//	service.restart  -> mutate  (changes Node state)
//	pkg.install      -> mutate  (installs a package; changes Node state)
//
// Ordering is fixed (not alphabetical) to match the proto comment; callers
// that need a stable display order should sort explicitly.
//
// Every ArgConstraints charset below is copied from the daemon's own
// validators — daemon/src/operations/service_restart.rs (validate_unit_name)
// and daemon/src/operations/pkg_install.rs (validate_pkg_name/
// validate_pkg_version) — and every documented arg key is copied from
// daemon/src/dispatch.rs's OP_ARG_* constants. Keep both in sync by hand if
// either side changes.
func Operations() []Descriptor {
	return []Descriptor{
		{
			Name:    "system.facts",
			Risk:    jobs.RiskClassRead,
			Purpose: "Collect the Node's self-reported Facts (OS, kernel, hostname, arch, IPs). Read-only; fans out fleet-wide under the read-cap.",
			// Empty ArgConstraints is INTENTIONAL: system.facts takes no
			// arguments at all, not "not yet documented".
			ArgConstraints: map[string]string{},
			Example:        "run_operation operation=system.facts (no args)",
		},
		{
			Name:    "file.read",
			Risk:    jobs.RiskClassRead,
			Purpose: "Read the contents of a single file on the Node (size-capped). Read-only.",
			ArgConstraints: map[string]string{
				"path": "string, required. Filesystem path to read. DATA, never a shell — the daemon opens it " +
					"directly. Which paths are readable is decided by the Node's Policy, not this argument.",
			},
			Example: `run_operation operation=file.read args={"path":"/etc/os-release"}`,
		},
		{
			Name:    "service.restart",
			Risk:    jobs.RiskClassMutate,
			Purpose: "Restart a systemd unit on the Node. Mutates state — mutate-cap.",
			ArgConstraints: map[string]string{
				"unit": "string, required. systemd unit name; charset [A-Za-z0-9@._-], no leading '-'. A single " +
					"validated argv element, never a shell string.",
			},
			Example: `run_operation operation=service.restart args={"unit":"nginx"}`,
		},
		{
			Name:    "pkg.install",
			Risk:    jobs.RiskClassMutate,
			Purpose: "Install a package via the Node's package manager. Mutates state — mutate-cap.",
			ArgConstraints: map[string]string{
				"name": "string, required. Package name; charset [A-Za-z0-9+._-], must start and end alphanumeric. " +
					"Validated before argv is built; never a shell string.",
				"version": "string, optional. Charset [A-Za-z0-9+._:~-], must start and end alphanumeric. " +
					"Empty/absent installs the latest.",
			},
			Example: `run_operation operation=pkg.install args={"name":"nginx","version":"1.24.0"}`,
		},
	}
}
