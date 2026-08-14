//go:build apiclient

package apiclient

// The generated client imports oapi-codegen's runtime helpers. Because
// client.gen.go is not committed, no checked-in file would otherwise reference
// that module, and `go mod tidy` would drop it from go.mod — leaving
// `make apiclient-check` to fail on a missing dependency long after the change
// that caused it.
//
// This blank import is that reference. `go mod tidy` considers files under all
// build tags, so the requirement survives; the ordinary build does not compile
// this file at all.
import _ "github.com/oapi-codegen/runtime"
