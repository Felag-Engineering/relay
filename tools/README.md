# tools/

One Go module per pinned dev tool: `buf`, `golangci-lint`, `govulncheck`, `actionlint`, `gitleaks` and
`nfpm`. Each directory holds only a `go.mod` (with a `tool` directive) and a `go.sum`.
Makefile targets run a tool as `go -C tools/<name> tool -n <name>`, which builds it into the
content-addressed Go build cache and prints the path. So every checkout runs the pins its own
`go.sum` names, nothing reads the shared `GOPATH/bin`, and nothing needs installing first (#891,
after #710).

**Why not `relay/go.mod`.** Putting `buf`, `golangci-lint` or `govulncheck` there moves modules
that are linked into the shipped binary (`x/net`, `segmentio/asm`, `genproto`), so a lint-tool
bump would silently change production dependencies. The proto generators (`protoc-gen-go`,
`protoc-gen-go-grpc`) stay in `relay/go.mod` as `tool` directives (#926): they share the
protobuf runtime with the generated code on purpose.

**Why not one shared module.** `gitleaks` does not compile against the
`charmbracelet/x/ansi` version `golangci-lint` selects. One module per tool also keeps each
tool's build list identical to upstream's own `go install` build.

**Bumping a pin.** `cd tools/<name> && go get -tool <package>@<version> && go mod tidy`, with
the Makefile's toolchain (`make` exports it). Never edit these files by hand.

**Dependabot.** `go mod tidy` records a tool's own require as `// indirect`, so
`.github/dependabot.yml` lists each tool explicitly. Dependabot *security* updates ignore that
list: an advisory in a tool's transitive dependency can open a PR that bumps just that
dependency. Such a PR lands only if the tool still builds and every gate is green (CI rebuilds
the tool from the changed module). If the tool fails to build, close the PR and bump the tool
itself instead. A green CI on a PR that changes `tools/<name>` was produced by that PR's own
tool, so it does not vouch for the change: the reviewer reads the `go.mod` diff — no `replace`,
the upstream module path, a released version. These modules are never linked into the `relay` binary, so an advisory here is
not a shipped vulnerability.

**The `protoc (unknown)` stamp** in generated code cannot be set: buf passes no compiler version
to local plugins, and editing generated code is forbidden (invariant 8).
