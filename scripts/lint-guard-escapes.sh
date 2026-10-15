#!/usr/bin/env bash
# The adapter-boundary and import guards are golangci-lint rules (depguard, forbidigo), and
# golangci-lint only sees what it analyses. Three things inside a Go file change that, and
# each would silence invariant 10's guards from the file they guard:
#   - a `Code generated … DO NOT EDIT.` header: such a file is skipped entirely, so only
#     the real codegen output (relay/internal/relay/v1/) may carry one;
#   - a `//go:build` constraint: the lint run is untagged, so a tagged file is never
#     analysed; under relay/internal/ only the files listed below may carry one;
#   - a `nolint` directive naming depguard or forbidigo.
#
# Exit 1 with file:line for each finding; exit 0 when clean.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

generated_ok='^relay/internal/relay/v1/'
# Each entry is reviewed: it is not an adapter, capability or domain package.
build_tag_ok='^relay/internal/apiclient/deps\.go$'

findings=$(
  git ls-files --cached --others --exclude-standard -- 'relay/*.go' | while IFS= read -r f; do
    if ! [[ $f =~ $generated_ok ]]; then
      grep -nH -E '^// Code generated .* DO NOT EDIT\.$' "$f" || true
    fi
    if [[ $f == relay/internal/* && $f != *_test.go ]] && ! [[ $f =~ $build_tag_ok ]]; then
      grep -nH -E '^//go:build' "$f" || true
    fi
    grep -nH -E '//[[:space:]]*nolint:[^[:space:]]*(depguard|forbidigo)' "$f" || true
  done
)

if [ -n "$findings" ]; then
  printf '%s\n' "$findings"
  echo "lint-guard-escapes: a generated header, build tag or nolint directive would hide this file from the boundary guards." >&2
  exit 1
fi
echo "lint-guard-escapes: ok"
