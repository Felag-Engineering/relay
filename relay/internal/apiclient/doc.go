// Package apiclient is a typed Go client for the Control API, GENERATED from
// docs/api/openapi.yaml (`make gen-apiclient`) and DELIBERATELY NOT COMMITTED.
//
// Only the inputs and the check live here: the generator config, this doc, and
// a build-tagged conformance suite. The generated client (client.gen.go) is
// gitignored, and nothing in the product imports it, so committing it would add
// review surface for code with no consumer.
//
// # Why generate it at all
//
// It is the published contract's CONFORMANCE TEST. The spec's own gate
// (internal/controlplane/api/openapi_test.go) proves the document is valid
// OpenAPI 3.1 and matches the mounted route table, but a spec can pass both and
// still be unusable by a real client generator. That happened when this was
// first generated (#359): five schema names collided with oapi-codegen's own
// `<OperationId>Response` types. Generating and compiling a client in CI makes
// such a spec fail there rather than for the first integrator.
//
// An operator CLI was built on this package and then deliberately removed: the
// Admin Console (ADR-0009) owns the human surface, and signing is better served
// by standard tooling the operator already holds keys for (cosign,
// ssh-keygen -Y). What remains is the contract check.
//
// # Working with it
//
// `make apiclient-check` (run by CI and `make verify`) generates the client,
// compiles it, and runs the conformance suite, leaving the gitignored file on
// disk for debugging.
//
// The suite sits behind the `apiclient` build tag so the inner loop needs no
// code generation: with no generated file, `go build ./...` and `go test ./...`
// see an empty package. A stale file is harmless, since `make gen-apiclient`
// deletes it before regenerating.
package apiclient
