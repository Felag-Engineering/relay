// Package opvocab is a Relay-side, READ-ONLY mirror of /proto's Operation
// vocabulary (OperationDescriptor, relay.proto:142-145): the fixed set of
// structured Operations, each with its risk class. /proto remains the single
// source of truth for the wire vocabulary (invariant 8) — this list is
// hand-authored, but opvocab_test.go's TestOperations_MatchesGoldenSchema
// hermetically cross-checks it against the daemon's own golden Operation
// schema (testdata/operations.schema.json, ADR-0015), so a hand-authoring
// mistake fails a test instead of silently drifting. opvocab carries no
// proto or dispatch dependency, following the registry.Facts / jobs
// domain-mirror precedent so the MCP surface
// ([internal/controlplane/mcp]) can list Operations without importing the
// dispatch path.
//
// Raw Exec is deliberately NOT listed here: it is not an Operation
// (ADR-0003, GLOSSARY.md) and has no OperationDescriptor on the wire. It is
// always risk class mutate by definition (arbitrary commands are
// unclassifiable) and surfaces through its own tool, never this one.
package opvocab

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// Descriptor mirrors relayv1.OperationDescriptor's Name and Risk (the wire
// contract, invariant 8/ADR-0012), plus model-facing legibility PROSE that
// has no proto counterpart (central decision: NO /proto change).
// Purpose, ArgConstraints, and Example are ADVISORY — they exist so a model
// reader (list_operations, MCP) can pick the right Operation and build valid
// args without trial-and-error (ADR-0001's typed-path-by-default safety
// assumption). They are NOT the enforcement: the daemon's own validate_*
// functions (daemon/src/operations/*.rs) are the real gate (ADR-0002,
// invariant 2). This prose is still hand-authored, but
// TestOperations_MatchesGoldenSchema (opvocab_test.go) hermetically proves it
// agrees with the daemon's golden Operation schema — a mismatch here is a
// legibility bug, not a security hole, but it is exactly the failure ADR-0015
// exists to catch mechanically rather than by hand-review.
type Descriptor struct {
	Name    string
	Risk    jobs.RiskClass
	Purpose string
	// ArgConstraints maps each documented argument name to
	// "type, required/optional. constraint prose." A zero-arg Operation
	// (system.facts) legitimately has an empty-but-non-nil map — that is
	// INTENTIONAL, not a placeholder still to be filled (see
	// TestOperations_Legible / TestOperations_MatchesGoldenSchema in
	// opvocab_test.go).
	ArgConstraints map[string]string
	// ArgClasses declares, per argument, whether it is part of an action's
	// SHAPE or its SCALE (D10). Every key in ArgConstraints must appear
	// here — TestArgClasses_CoverEveryDocumentedArg is the mechanical check —
	// so adding an argument without deciding which it is fails a test rather
	// than quietly landing on a default.
	ArgClasses map[string]ArgClass
	// Example is a concrete, runnable-shaped usage sample for
	// list_operations/run_operation's tool description.
	Example string
}

// ArgClass declares whether one argument is part of an Operation's SHAPE —
// WHAT is being done — or its SCALE — how much of it (D10). It is what
// the approval shape key filters on, so "the last approved action of the same
// shape" can find a prior record that differs only in a value expected to vary.
//
// It is DECLARED here, never inferred from a value: inferring would make the
// approval queue's grouping depend on what somebody happened to type, and the
// failure mode is exactly the one D10 names — a materially different action
// reading as routine.
type ArgClass int

const (
	// ArgClassUnspecified is the zero value and is never a valid declaration.
	// It is deliberately NOT an alias for scale: an argument nobody classified
	// must not silently drop out of the shape key, which is why ShapeArgs
	// treats anything that is not explicitly scale as shape, and why
	// TestArgClasses_AreNeverUnspecified refuses the zero value outright.
	ArgClassUnspecified ArgClass = iota
	ArgClassShape
	ArgClassScale
)

func (c ArgClass) String() string {
	switch c {
	case ArgClassShape:
		return "shape"
	case ArgClassScale:
		return "scale"
	default:
		return "unspecified"
	}
}

// Operations returns the fixed v1 Operation vocabulary, per
// relay.proto:142-145:
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
// daemon/src/operations/schema.rs's OP_ARG_* constants (relocated there from
// dispatch.rs, ADR-0015). Keep both in sync by hand if either side changes;
// TestOperations_MatchesGoldenSchema (opvocab_test.go) is the mechanical
// check that catches it if you forget.
func Operations() []Descriptor {
	return []Descriptor{
		{
			Name:    "system.facts",
			Risk:    jobs.RiskClassRead,
			Purpose: "Collect the Node's self-reported Facts (OS, kernel, hostname, arch, IPs). Read-only; fans out fleet-wide under the read-cap.",
			// Empty ArgConstraints is INTENTIONAL: system.facts takes no
			// arguments at all, not "not yet documented".
			ArgConstraints: map[string]string{},
			// Empty for the same reason ArgConstraints is: no arguments to
			// classify, not "not yet classified".
			ArgClasses: map[string]ArgClass{},
			Example:    "run_operation operation=system.facts (no args)",
		},
		{
			Name:    "file.read",
			Risk:    jobs.RiskClassRead,
			Purpose: "Read the contents of a single file on the Node (size-capped). Read-only.",
			ArgConstraints: map[string]string{
				"path": "string, required. Filesystem path to read. DATA, never a shell — the daemon opens it " +
					"directly. Which paths are readable is decided by the Node's Policy, not this argument.",
			},
			// Reading /etc/shadow and reading /etc/motd are materially
			// different acts, so the path is the shape of a file.read.
			ArgClasses: map[string]ArgClass{"path": ArgClassShape},
			Example:    `run_operation operation=file.read args={"path":"/etc/os-release"}`,
		},
		{
			Name:    "service.restart",
			Risk:    jobs.RiskClassMutate,
			Purpose: "Restart a systemd unit on the Node. Mutates state — mutate-cap.",
			ArgConstraints: map[string]string{
				"unit": "string, required. systemd unit name; charset [A-Za-z0-9@._-], no leading '-'. A single " +
					"validated argv element, never a shell string.",
			},
			// Which unit is restarted is the whole act.
			ArgClasses: map[string]ArgClass{"unit": ArgClassShape},
			Example:    `run_operation operation=service.restart args={"unit":"nginx"}`,
		},
		{
			Name:    "pkg.install",
			Risk:    jobs.RiskClassMutate,
			Purpose: "Install a package via the Node's package manager. Mutates state — mutate-cap.",
			ArgConstraints: map[string]string{
				"name": "string, required. Package name; charset [A-Za-z0-9+._-], must start and end alphanumeric. " +
					"Validated before argv is built; never a shell string.",
				"version": "string, optional. Charset [A-Za-z0-9+.:~_-], must start and end alphanumeric. " +
					"Empty/absent installs the latest.",
			},
			// The package is the shape. The version is D10's canonical
			// "argument expected to vary": classifying it as shape would make
			// every step of a rollout look novel, which is the too-strict half
			// of the failure D10 names. Excluding it is safe because the shape
			// key only chooses WHAT TO DIFF AGAINST — the diff then shows the
			// version change loudly rather than hiding it.
			ArgClasses: map[string]ArgClass{"name": ArgClassShape, "version": ArgClassScale},
			Example:    `run_operation operation=pkg.install args={"name":"nginx","version":"1.24.0"}`,
		},
	}
}

// Lookup returns the Descriptor for name, or ok=false when name is not in the
// native vocabulary. It is the shared name resolution both control surfaces
// use before building an Action, so "unknown operation" reads identically on
// MCP and the Control API.
//
// Native vocabulary only (frozen at four, ADR-0021): a Template Operation is
// per-Node and is NOT resolvable here — a surface that supports templates must
// treat !ok as "not native", not as "does not exist".
func Lookup(name string) (Descriptor, bool) {
	for _, d := range Operations() {
		if d.Name == name {
			return d, true
		}
	}
	return Descriptor{}, false
}

// ShapeArgs returns the subset of args that is part of the SHAPE of a call to
// operation — what the approval shape key is computed over (D10).
//
// The default is STRICT in both directions where a declaration is missing. An
// Operation this package does not know is a Template Operation (ADR-0021),
// which has declared nothing, so nothing may be dropped: every argument is
// treated as shape. Same for a documented argument carrying no class — absence
// is never read as "scale", because reading it that way would let a forgotten
// declaration quietly make two different actions share a shape key.
//
// It returns a fresh map and never mutates args.
func ShapeArgs(operation string, args map[string]string) map[string]string {
	out := make(map[string]string, len(args))
	d, known := Lookup(operation)
	for k, v := range args {
		if known && d.ArgClasses[k] == ArgClassScale {
			continue
		}
		out[k] = v
	}
	return out
}

// ValidateArgNames checks a caller's argument NAMES against d's published
// ArgConstraints: every provided name must be one d declares, and every
// declared required name must be provided.
//
// It exists here — beside the ArgConstraints convention it reads — because
// **every** control surface needs it and a per-surface copy would drift
// (ADR-0042). Without it, an unknown arg name is silently dropped and a
// misspelled REQUIRED name defaults to empty, so the daemon's refusal surfaces
// as `denied_by_policy` rather than a validation error — sending the AI-agent into a
// describe_node/narrow/retry loop it could never exit, because the request was
// malformed rather than forbidden. A second surface re-implementing this would
// reopen the same trap on its own schedule.
//
// **Names only — never values.** This is a fail-fast legibility pre-check, not
// a second Policy decision (ADR-0002/0011, invariant 12): argument *values* are
// the daemon's live engine's call, and forwarding an unrecognized value stays
// its refusal to make. Errors name the offending argument and list the valid
// ones, because the single most useful correction hint is the exact set of
// names to choose from.
func ValidateArgNames(d Descriptor, args map[string]string) error {
	valid := make([]string, 0, len(d.ArgConstraints))
	for k := range d.ArgConstraints {
		valid = append(valid, k)
	}
	sort.Strings(valid)

	// Unknown names first: a misspelled required arg lands here, and it is the
	// more actionable message ("you wrote X; valid names are ...").
	var unknown []string
	for k := range args {
		if _, ok := d.ArgConstraints[k]; !ok {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf(
			"operation %q got unknown argument(s) %v; valid arguments: %v "+
				"(see list_operations for each argument's type and constraints)",
			d.Name, unknown, valid,
		)
	}

	// Then missing required names (an omitted required arg, as opposed to a
	// misspelled one, which the unknown-name check above already caught).
	var missing []string
	for name, constraint := range d.ArgConstraints {
		if !argIsRequired(constraint) {
			continue
		}
		if _, ok := args[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf(
			"operation %q is missing required argument(s) %v; valid arguments: %v "+
				"(see list_operations)",
			d.Name, missing, valid,
		)
	}
	return nil
}

// argIsRequired reports whether an ArgConstraints value marks the argument as
// required. Every constraint follows this package's own convention
// "<type>, required. ..." or "<type>, optional. ..." (see Descriptor), so the
// ", required" marker is the signal. TestArgConstraintsAreClassifiable guards
// the convention mechanically, so this string match cannot silently rot if the
// prose is reworded.
func argIsRequired(constraint string) bool {
	return strings.Contains(constraint, ", required")
}
