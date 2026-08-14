// Package apiclient is a typed Go client for the Control API, GENERATED from
// docs/api/openapi.yaml (`make gen-apiclient`) and DELIBERATELY NOT COMMITTED.
//
// # What lives here
//
// Only the inputs and the check: the generator config, this doc, and a
// build-tagged conformance suite. The generated client itself
// (client.gen.go, several thousand lines) is gitignored and produced on
// demand. Nothing in the product imports it, so committing it would add
// repository weight and review surface for code with no consumer.
//
// # Why generate it at all
//
// It is the published contract's CONFORMANCE TEST. The spec's own gate
// (internal/controlplane/api/openapi_test.go) proves the document is valid
// OpenAPI 3.1 and matches the route table the server mounts. That is necessary
// but not sufficient: a spec can be valid, match every route, and still be
// unusable by a real client generator — schema names that shadow generated
// wrapper types, request bodies a generator cannot express, response shapes
// that do not compile. Exactly that happened when this was first generated
// (#359): five schema names collided with oapi-codegen's own
// `<OperationId>Response` types, which no amount of spec validation would have
// caught.
//
// Generating and compiling a client in CI closes that gap. A spec that no
// client can consume fails there rather than failing the first integrator who
// tries.
//
// An operator CLI was built on this package and then deliberately removed: the
// Admin Console (ADR-0009, v0.6.0/v0.7.0) owns the human surface, and the
// signing workflow that once seemed to require a CLI is better served by
// standard tooling the operator already has key custody for (cosign,
// ssh-keygen -Y) — the Relay never holds the signing key either way, so nothing
// bespoke is needed. What remains is the contract check.
//
// # Working with it
//
// `make apiclient-check` (run by CI and by `make verify`) generates the client,
// compiles it, and runs the conformance suite. The generated file is left on
// disk afterwards — gitignored, so it cannot be committed by accident, and
// useful to read when debugging a spec change.
//
// The conformance suite sits behind the `apiclient` build tag so the ordinary
// inner loop never requires a code-generation step: with no generated file
// present, `go build ./...` and `go test ./...` see an empty package and pass.
// With one present they simply compile it, which is why a stale file is
// harmless — `make gen-apiclient` deletes it before regenerating, so it can
// never stand in for a generation that failed.
package apiclient
