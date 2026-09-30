//go:build apiclient

package apiclient

// The generated client imports oapi-codegen's runtime helpers. Because
// client.gen.go is not committed, nothing else references that module and
// `go mod tidy` would drop it from go.mod, breaking `make apiclient-check`
// later. This blank import keeps the requirement: `go mod tidy` considers all
// build tags, and the ordinary build never compiles this file.
import _ "github.com/oapi-codegen/runtime"
