// Package main is the compile-fail fixture for
// dispatch_construction_test.go: it is a foreign package (not
// internal/capability itself) that attempts both forbidden constructions —
// building a dispatch value directly, and calling newDispatch. Neither
// symbol is exported, so this file must NOT compile. It lives under
// testdata/ so `go build ./...` and `make build` never build it; only the
// structural test invokes `go build` on it explicitly.
package main

import "github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"

func main() {
	_ = capability.dispatch{}
	_ = capability.newDispatch
}
