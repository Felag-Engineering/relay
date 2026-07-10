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

// Descriptor mirrors gleipnirv1.OperationDescriptor: an Operation's name and
// risk class. ArgConstraints is an empty placeholder in this issue — #120
// fills in the per-argument legibility content list_operations renders.
type Descriptor struct {
	Name           string
	Risk           jobs.RiskClass
	ArgConstraints map[string]string
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
func Operations() []Descriptor {
	return []Descriptor{
		{Name: "system.facts", Risk: jobs.RiskClassRead, ArgConstraints: map[string]string{}},
		{Name: "file.read", Risk: jobs.RiskClassRead, ArgConstraints: map[string]string{}},
		{Name: "service.restart", Risk: jobs.RiskClassMutate, ArgConstraints: map[string]string{}},
		{Name: "pkg.install", Risk: jobs.RiskClassMutate, ArgConstraints: map[string]string{}},
	}
}
