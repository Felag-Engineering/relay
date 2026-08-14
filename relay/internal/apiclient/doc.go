// Package apiclient is a typed Go client for the Control API, GENERATED from
// docs/api/openapi.yaml (`make gen-apiclient`).
//
// # Why it exists with no CLI consuming it
//
// It is the published contract's CONFORMANCE TEST. The spec's own gate
// (internal/controlplane/api/openapi_test.go) proves the document is valid
// OpenAPI 3.1 and matches the route table the server mounts. That is necessary
// but not sufficient: a spec can be valid, match every route, and still be
// unusable by a real client generator — schema names that shadow generated
// wrapper types, request bodies a generator cannot express, response shapes
// that do not compile. Exactly that happened when this package was first
// generated (#359): five schema names collided with oapi-codegen's own
// `<OperationId>Response` types, which no amount of spec validation would have
// caught.
//
// Generating and compiling a client on every build closes that gap. A spec that
// no client can consume fails CI here rather than failing the first integrator
// who tries.
//
// An operator CLI was built on this package and then deliberately removed: the
// Admin Console (ADR-0009, v0.6.0/v0.7.0) owns the human surface, and the
// signing workflow that once seemed to require a CLI is better served by
// standard tooling the operator already has key custody for (cosign,
// ssh-keygen -Y) — the Relay never holds the signing key either way, so nothing
// bespoke is needed. What remains is this: the contract check, plus a ready
// starting point for any future Go integration that wants a typed client rather
// than hand-rolled HTTP.
//
// # Do not hand-edit
//
// client.gen.go is generated. `make apiclient-check` regenerates it and fails on
// any difference, so a hand-edit is reverted by CI rather than silently kept.
// Change docs/api/openapi.yaml and regenerate.
package apiclient
