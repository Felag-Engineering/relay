//go:build !devharness

package main

// installDevHarness is the production no-op. The entire dev-harness
// dispatch/control surface (cmd/relay/devharness.go) is compiled only under
// the `devharness` build tag; every other build — including the default,
// shippable one — gets this empty stub instead. This is the ONLY production
// footprint of the feature: a single call site that does nothing.
//
// cfg is accepted (but unused) so the signature matches the devharness-tagged
// build, which needs it to read the file-configured blast caps when
// constructing its own capability.Execution.
func installDevHarness(cfg Config, deps *appDeps) (func(), error) {
	return func() {}, nil
}
