#!/usr/bin/env bash
# Proves scripts/install-matrix-platforms.sh holds the install matrix's platform list equal to
# DI-33's: it passes on the real files and on DI-33 in either claim shape, wrapped at any
# column, and fails on a dropped, added, duplicated or excluded row, on a changed architecture
# set on either side, on a platform with no Dockerfile, on a workflow without its markers, and
# on a spec whose DI-33 is missing or reworded. A parser that passed vacuously would let the
# matrix and the specification drift apart unseen, so every failing case also names the
# message it must fail with.
#
# Hermetic: bash, awk, sed and fixtures copied from the real files under a `mktemp -d`. Touches
# nothing in this working tree.
#
# NOT `set -e`: every case must run and be reported, not stop at the first failure.
set -uo pipefail

# The same safety preamble as ci-changed-paths-test.sh: the only destructive operation is the
# trap's `rm -rf "$WORKDIR"`, which refuses anything but an absolute path.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
WORKDIR="$(mktemp -d)" || { echo "FAIL: mktemp -d failed" >&2; exit 1; }
trap 'case "${WORKDIR:-}" in /*) rm -rf "$WORKDIR" ;; esac' EXIT
case "$WORKDIR" in
  /*) ;;
  *) echo "FAIL: mktemp returned a non-absolute path: '$WORKDIR'" >&2; exit 1 ;;
esac

SCRIPT="$REPO_ROOT/scripts/install-matrix-platforms.sh"
REAL_SPEC="$REPO_ROOT/docs/specs/daemon-installation.md"
REAL_WORKFLOW="$REPO_ROOT/.github/workflows/install-matrix.yml"
REAL_DOCKERFILES="$REPO_ROOT/docker/install-matrix"
fail=0

OUT=""
RC=0

# run <spec> <workflow> <dockerfile-dir>
run() {
  OUT="$(bash "$SCRIPT" "$1" "$2" "$3" 2>&1)"
  RC=$?
}

# expect_pass <case>
expect_pass() {
  if [ "$RC" -ne 0 ]; then
    echo "FAIL: $1: wanted exit 0, got $RC: $OUT" >&2
    fail=$((fail + 1))
  fi
}

# expect_fail <case> <message the failure must contain>
expect_fail() {
  if [ "$RC" -ne 1 ]; then
    echo "FAIL: $1: wanted exit 1, got $RC: $OUT" >&2
    fail=$((fail + 1))
  elif [[ $OUT != *"$2"* ]]; then
    echo "FAIL: $1: failed, but not with '$2': $OUT" >&2
    fail=$((fail + 1))
  fi
}

# changed <case> <original> <fixture>: the fixture must differ from the original, so a case
# whose edit silently did nothing cannot pass for the wrong reason.
changed() {
  if cmp -s "$2" "$3"; then
    echo "FAIL: $1: the fixture is identical to the real file; the edit did not apply" >&2
    fail=$((fail + 1))
  fi
}

for f in "$SCRIPT" "$REAL_SPEC" "$REAL_WORKFLOW"; do
  [ -f "$f" ] || { echo "FAIL: missing $f" >&2; exit 1; }
done

# --- 1. the real files pass ------------------------------------------------------------------
run "$REAL_SPEC" "$REAL_WORKFLOW" "$REAL_DOCKERFILES"
expect_pass "1: the real spec, workflow and Dockerfiles"

# --- 2. DI-33 as a promoted bullet, re-wrapped through an anchor and a platform name ---------
cat >"$WORKDIR/spec-promoted.md" <<'EOF'
# Fixture

- **DI-33** A platform is supported only where CI installs the package, upgrades it over the
  operator's edited configuration and finds the edit intact, and removes
  it: Ubuntu 24.04 LTS and 26.04 LTS; Debian 13; RHEL-compatible 10, tested on Rocky
  Linux 10; Amazon Linux 2023. Each is
  supported on `x86_64` and `aarch64`. A platform whose package manager refuses an unsigned
  local package by default is not supported.
- **DI-34** The next claim, which the bullet above must not read into.
EOF
run "$WORKDIR/spec-promoted.md" "$REAL_WORKFLOW" "$REAL_DOCKERFILES"
expect_pass "2: DI-33 as a promoted bullet, wrapped inside an anchor and a platform name"

# --- workflow fixtures --------------------------------------------------------------------------
# 3. a workflow missing one platform
grep -v 'id: debian-13' "$REAL_WORKFLOW" >"$WORKDIR/wf-missing.yml"
changed "3 fixture" "$REAL_WORKFLOW" "$WORKDIR/wf-missing.yml"
run "$REAL_SPEC" "$WORKDIR/wf-missing.yml" "$REAL_DOCKERFILES"
expect_fail "3: a workflow missing a platform" "platform lists differ"

# 4. a workflow with an extra platform (it has a Dockerfile, so only the sets differ)
mkdir -p "$WORKDIR/dockerfiles-extra"
cp "$REAL_DOCKERFILES"/*.Dockerfile "$WORKDIR/dockerfiles-extra/"
cp "$REAL_DOCKERFILES/debian-13.Dockerfile" "$WORKDIR/dockerfiles-extra/fedora-43.Dockerfile"
awk '
  { print }
  /id: debian-13/ {
    line = $0
    sub(/id: debian-13/, "id: fedora-43", line)
    sub(/distribution: "Debian"/, "distribution: \"Fedora\"", line)
    sub(/release: "13"/, "release: \"43\"", line)
    print line
  }
' "$REAL_WORKFLOW" >"$WORKDIR/wf-extra.yml"
changed "4 fixture" "$REAL_WORKFLOW" "$WORKDIR/wf-extra.yml"
run "$REAL_SPEC" "$WORKDIR/wf-extra.yml" "$WORKDIR/dockerfiles-extra"
expect_fail "4: a workflow with an extra platform" "platform lists differ"

# 5. a spec that adds a platform
sed 's/Amazon Linux 2023\. Each/Amazon Linux 2023; Fedora 43. Each/' "$REAL_SPEC" >"$WORKDIR/spec-extra.md"
changed "5 fixture" "$REAL_SPEC" "$WORKDIR/spec-extra.md"
run "$WORKDIR/spec-extra.md" "$REAL_WORKFLOW" "$REAL_DOCKERFILES"
expect_fail "5: a spec that adds a platform" "platform lists differ"

# 6. a workflow arch line missing one architecture
sed 's/arch: \[x86_64, aarch64\]/arch: [x86_64]/' "$REAL_WORKFLOW" >"$WORKDIR/wf-arch.yml"
changed "6 fixture" "$REAL_WORKFLOW" "$WORKDIR/wf-arch.yml"
run "$REAL_SPEC" "$WORKDIR/wf-arch.yml" "$REAL_DOCKERFILES"
expect_fail "6: a workflow arch line [x86_64]" "architecture lists differ"

# 7. a workflow without the markers
grep -v 'DI-33 platforms' "$REAL_WORKFLOW" >"$WORKDIR/wf-nomarkers.yml"
changed "7 fixture" "$REAL_WORKFLOW" "$WORKDIR/wf-nomarkers.yml"
run "$REAL_SPEC" "$WORKDIR/wf-nomarkers.yml" "$REAL_DOCKERFILES"
expect_fail "7: a workflow without the BEGIN/END markers" "marker"

# 8. a workflow containing an exclusion
{ cat "$REAL_WORKFLOW"; printf '        %s []\n' "exclude:"; } >"$WORKDIR/wf-exclude.yml"
changed "8 fixture" "$REAL_WORKFLOW" "$WORKDIR/wf-exclude.yml"
run "$REAL_SPEC" "$WORKDIR/wf-exclude.yml" "$REAL_DOCKERFILES"
expect_fail "8: a workflow containing an exclusion" "drops a row"

# 9. a spec whose DI-33 lost the `removes it:` anchor
sed 's/removes it:/removes it,/' "$REAL_SPEC" >"$WORKDIR/spec-anchor.md"
changed "9 fixture" "$REAL_SPEC" "$WORKDIR/spec-anchor.md"
run "$WORKDIR/spec-anchor.md" "$REAL_WORKFLOW" "$REAL_DOCKERFILES"
expect_fail "9: a spec whose DI-33 lost the 'removes it:' anchor" "wording changed"

# 10. a missing Dockerfile for one id
mkdir -p "$WORKDIR/dockerfiles-missing"
cp "$REAL_DOCKERFILES"/*.Dockerfile "$WORKDIR/dockerfiles-missing/"
rm -f "$WORKDIR/dockerfiles-missing/rocky-10.Dockerfile"
run "$REAL_SPEC" "$REAL_WORKFLOW" "$WORKDIR/dockerfiles-missing"
expect_fail "10: a missing Dockerfile for one id" "rocky-10"

# 11. a duplicate id
awk '{ print } /id: debian-13/ { print }' "$REAL_WORKFLOW" >"$WORKDIR/wf-duplicate.yml"
changed "11 fixture" "$REAL_WORKFLOW" "$WORKDIR/wf-duplicate.yml"
run "$REAL_SPEC" "$WORKDIR/wf-duplicate.yml" "$REAL_DOCKERFILES"
expect_fail "11: a duplicate id" "duplicate platform id"

# 12. a spec with no DI-33
sed 's/DI-33/DI-99/g' "$REAL_SPEC" >"$WORKDIR/spec-none.md"
changed "12 fixture" "$REAL_SPEC" "$WORKDIR/spec-none.md"
run "$WORKDIR/spec-none.md" "$REAL_WORKFLOW" "$REAL_DOCKERFILES"
expect_fail "12: a spec with no DI-33" "DI-33 not found"

# 13. a spec whose DI-33 adds an architecture
sed 's/`aarch64`\. A platform/`aarch64` and `riscv64`. A platform/' "$REAL_SPEC" >"$WORKDIR/spec-riscv.md"
changed "13 fixture" "$REAL_SPEC" "$WORKDIR/spec-riscv.md"
run "$WORKDIR/spec-riscv.md" "$REAL_WORKFLOW" "$REAL_DOCKERFILES"
expect_fail "13: a spec whose DI-33 adds an architecture" "architecture lists differ"

# 14. the same distribution and release under a second id
awk '{ print } /id: debian-13,/ { sub(/id: debian-13,/, "id: debian-13b,"); print }' "$REAL_WORKFLOW" >"$WORKDIR/wf-same-platform.yml"
changed "14 fixture" "$REAL_WORKFLOW" "$WORKDIR/wf-same-platform.yml"
run "$REAL_SPEC" "$WORKDIR/wf-same-platform.yml" "$REAL_DOCKERFILES"
expect_fail "14: one platform under two ids" "duplicate platform (distribution release)"

if [ "$fail" -ne 0 ]; then
  echo "FAIL: $fail case(s) failed" >&2
  exit 1
fi

echo "PASS: install-matrix-platforms.sh holds the workflow's platform list equal to DI-33's in both claim shapes and across a re-wrap, and fails on a dropped, added, duplicated or excluded row, a changed architecture set, a missing Dockerfile, missing markers, and a missing or reworded DI-33."
