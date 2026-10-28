#!/usr/bin/env bash
# Proves scripts/ci-release-matrix.sh, CI OK's evidence for an install matrix that only the
# release dry run ran, passes only on a completed newest run whose every install-matrix row
# succeeded, and fails closed on everything else: no run, a run that never completes, a failed,
# skipped or cancelled row, a run with no rows, an older pass under a newer failure, an API
# that never answers, and malformed input. It waits through a run in progress, and the job
# name it looks for is the one release.yml gives its install-matrix job.
#
# Hermetic: a stub `gh` under a throwaway WORKDIR applying the script's own --jq filters to
# fixture JSON with real jq; no network, no token. Writes nothing outside its own `mktemp -d`.
#
# NOT `set -e`: every case must run and be reported (security-surface-test.sh:12).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
WORKDIR="$(mktemp -d)" || { echo "FAIL: mktemp -d failed" >&2; exit 1; }
trap 'case "${WORKDIR:-}" in /*) rm -rf "$WORKDIR" ;; esac' EXIT
case "$WORKDIR" in
  /*) ;;
  *) echo "FAIL: mktemp returned a non-absolute path: '$WORKDIR'" >&2; exit 1 ;;
esac

if ! command -v jq >/dev/null 2>&1; then
  echo "FAIL: jq is required" >&2
  exit 1
fi

SCRIPT="$REPO_ROOT/scripts/ci-release-matrix.sh"
BIN="$WORKDIR/bin"
mkdir -p "$BIN"
fail=0
SHA=0123456789abcdef0123456789abcdef01234567
JOB="Install matrix (the release's packages and role)"

# The stub answers only GET api calls for the release.yml runs listing and a run's jobs.
# Fixtures under $STUB_DIR: runs-<n>.json is the listing on the n-th poll (the highest one
# present answers every later poll); runs-error makes every listing fail; jobs-<id>.json is a
# run's jobs. Anything else is UNEXPECTED, logged, and fails the call.
cat >"$BIN/gh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$STUB_DIR/gh.log"
[ "${1:-}" = api ] || { echo UNEXPECTED >>"$STUB_DIR/gh.log"; exit 1; }
shift
path="" jqx=""
while [ $# -gt 0 ]; do
  case "$1" in
    --paginate) ;;
    --jq) shift; jqx=$1 ;;
    -*) echo UNEXPECTED >>"$STUB_DIR/gh.log"; exit 1 ;;
    *) path=$1 ;;
  esac
  shift
done
case "$path" in
  repos/acme/relay/actions/workflows/release.yml/runs\?head_sha=*)
    [ -e "$STUB_DIR/runs-error" ] && { echo "gh: HTTP 502" >&2; exit 1; }
    n=$(($(cat "$STUB_DIR/polls" 2>/dev/null || echo 0) + 1))
    echo "$n" >"$STUB_DIR/polls"
    f=""
    for i in $(seq "$n" -1 1); do
      [ -f "$STUB_DIR/runs-$i.json" ] && { f="$STUB_DIR/runs-$i.json"; break; }
    done
    [ -n "$f" ] || { echo "gh: no fixture" >&2; exit 1; }
    jq -r "$jqx" "$f" ;;
  repos/acme/relay/actions/runs/*/jobs\?filter=latest\&per_page=100)
    id=${path#repos/acme/relay/actions/runs/}
    id=${id%%/*}
    [ -f "$STUB_DIR/jobs-$id.json" ] || { echo "gh: HTTP 404" >&2; exit 1; }
    jq -r "$jqx" "$STUB_DIR/jobs-$id.json" ;;
  *) echo UNEXPECTED >>"$STUB_DIR/gh.log"; exit 1 ;;
esac
STUB
chmod +x "$BIN/gh"

# Fixture builders.
# run_json <id> <status> [<sha>]: one workflow_runs entry.
run_json() { printf '{"id":%s,"status":"%s","head_sha":"%s"}' "$1" "$2" "${3:-$SHA}"; }
# runs <case dir> <poll n> <entry...>: the listing on poll n.
runs() {
  local dir=$1 n=$2
  shift 2
  local IFS=,
  printf '{"workflow_runs":[%s]}' "$*" >"$dir/runs-$n.json"
}
# jobs <case dir> <run id> <conclusion=name>...: a run's jobs.
jobs() {
  local dir=$1 id=$2 entries=() c n
  shift 2
  for pair in "$@"; do
    c=${pair%%=*}
    n=${pair#*=}
    if [ "$c" = null ]; then
      entries+=("$(jq -cn --arg n "$n" '{name:$n,status:"completed",conclusion:null}')")
    else
      entries+=("$(jq -cn --arg n "$n" --arg c "$c" '{name:$n,status:"completed",conclusion:$c}')")
    fi
  done
  local IFS=,
  printf '{"jobs":[%s]}' "${entries[*]}" >"$dir/jobs-$id.json"
}

GOOD_ROWS=("success=Build x86_64 (primary)" "success=$JOB / Build packages (x86_64)"
  "success=$JOB / Install debian-13 (x86_64)" "success=$JOB / Ansible role (debian-13 x86_64)"
  "skipped=Sign and push")

new_case() {
  CASE="$WORKDIR/case-$1"
  mkdir -p "$CASE"
}

# check <case name> <want rc> [<sha>]: runs the real script against $CASE with short windows.
check() {
  local out rc
  out=$(PATH="$BIN:$PATH" STUB_DIR="$CASE" GITHUB_REPOSITORY=acme/relay \
    RELEASE_MATRIX_TIMEOUT="${TIMEOUT:-2}" RELEASE_MATRIX_APPEAR="${APPEAR:-0}" \
    RELEASE_MATRIX_INTERVAL=0 bash "$SCRIPT" "${3-$SHA}" 2>&1)
  rc=$?
  if [ "$rc" -ne "$2" ]; then
    echo "FAIL: $1: rc=$rc, want $2. Output:" >&2
    printf '%s\n' "$out" | sed 's/^/    /' >&2
    fail=$((fail + 1))
  fi
  if grep -q UNEXPECTED "$CASE/gh.log" 2>/dev/null; then
    echo "FAIL: $1: the script made a gh call the stub does not allow:" >&2
    sed 's/^/    /' "$CASE/gh.log" >&2
    fail=$((fail + 1))
  fi
}

# --- 1. A completed newest run whose every row passed is the one pass.
new_case pass
runs "$CASE" 1 "$(run_json 7 completed)"
jobs "$CASE" 7 "${GOOD_ROWS[@]}"
check "completed run, every row passed" 0

# --- 2. It waits through a run in progress and decides on the completed result.
new_case wait-pass
runs "$CASE" 1 "$(run_json 7 queued)"
runs "$CASE" 2 "$(run_json 7 in_progress)"
runs "$CASE" 3 "$(run_json 7 completed)"
jobs "$CASE" 7 "${GOOD_ROWS[@]}"
TIMEOUT=30 check "run in progress, then passed" 0

new_case wait-fail
runs "$CASE" 1 "$(run_json 7 in_progress)"
runs "$CASE" 2 "$(run_json 7 completed)"
jobs "$CASE" 7 "${GOOD_ROWS[@]}" "failure=$JOB / Install rocky-10 (aarch64)"
TIMEOUT=30 check "run in progress, then a row failed" 1

# --- 3. Any row that is not success fails: failed, skipped, cancelled, unfinished.
for c in failure skipped cancelled null; do
  new_case "row-$c"
  runs "$CASE" 1 "$(run_json 7 completed)"
  jobs "$CASE" 7 "${GOOD_ROWS[@]}" "$c=$JOB / Install ubuntu-24.04 (aarch64)"
  check "a $c row" 1
done

# The caller job itself skipped (the build it needs failed): no rows, and it is not success.
new_case caller-skipped
runs "$CASE" 1 "$(run_json 7 completed)"
jobs "$CASE" 7 "failure=Build x86_64 (primary)" "skipped=$JOB"
check "install-matrix job skipped, no rows" 1

# A completed run with no install-matrix jobs at all (a release.yml without the job).
new_case no-rows
runs "$CASE" 1 "$(run_json 7 completed)"
jobs "$CASE" 7 "success=Build x86_64 (primary)" "success=Rebuild matches, SBOMs"
check "completed run with no install-matrix rows" 1

# A job merely sharing the prefix without the reusable-workflow separator is not a row.
new_case lookalike
runs "$CASE" 1 "$(run_json 7 completed)"
jobs "$CASE" 7 "success=$JOB extra"
check "a lookalike job name is not a row" 1

# --- 4. The newest run decides.
new_case newest-fails
runs "$CASE" 1 "$(run_json 7 completed)" "$(run_json 9 completed)"
jobs "$CASE" 7 "${GOOD_ROWS[@]}"
jobs "$CASE" 9 "${GOOD_ROWS[@]}" "failure=$JOB / Install debian-13 (aarch64)"
check "older run passed, newer run failed" 1

new_case newest-passes
runs "$CASE" 1 "$(run_json 9 completed)" "$(run_json 7 completed)"
jobs "$CASE" 7 "${GOOD_ROWS[@]}" "failure=$JOB / Install debian-13 (aarch64)"
jobs "$CASE" 9 "${GOOD_ROWS[@]}"
check "older run failed, newer run passed" 0

new_case newest-running
runs "$CASE" 1 "$(run_json 7 completed)" "$(run_json 9 in_progress)"
jobs "$CASE" 7 "${GOOD_ROWS[@]}"
TIMEOUT=0 check "older run passed, newer run still going at the deadline" 1

# A run for another commit in the listing is never evidence.
new_case other-sha
runs "$CASE" 1 "$(run_json 7 completed fedcba9876543210fedcba9876543210fedcba98)"
jobs "$CASE" 7 "${GOOD_ROWS[@]}"
check "only a run for another commit" 1

# --- 5. Fails closed when nothing can be learnt.
new_case no-run
runs "$CASE" 1
check "no release run" 1

new_case no-run-then-run
runs "$CASE" 1
runs "$CASE" 2 "$(run_json 7 completed)"
jobs "$CASE" 7 "${GOOD_ROWS[@]}"
APPEAR=30 TIMEOUT=30 check "no release run yet, then one inside the appearance window" 0

new_case never-completes
runs "$CASE" 1 "$(run_json 7 in_progress)"
TIMEOUT=0 check "a run that never completes" 1

new_case api-down
touch "$CASE/runs-error"
TIMEOUT=0 check "a runs listing that always errors" 1

new_case jobs-down
runs "$CASE" 1 "$(run_json 7 completed)"
TIMEOUT=0 check "a jobs listing that always errors" 1

# --- 6. Malformed input is refused before any call.
new_case bad-input
runs "$CASE" 1 "$(run_json 7 completed)"
jobs "$CASE" 7 "${GOOD_ROWS[@]}"
for bad in "" 0123 "$SHA\"" "${SHA^^}"; do
  check "malformed SHA '$bad'" 1 "$bad"
done
if [ -e "$CASE/gh.log" ]; then
  echo "FAIL: a malformed SHA reached gh" >&2
  fail=$((fail + 1))
fi

# --- 7. Drift guard: the job name the script reads is the name release.yml gives the job that
# calls install-matrix.yml.
want=$(sed -n 's/^MATRIX_JOB="\(.*\)"$/\1/p' "$SCRIPT")
got=$(awk '/^  install-matrix:/ { j = 1; next } j && /^  [^ ]/ { exit } j && /^    name: / { sub(/^    name: /, ""); print }' \
  "$REPO_ROOT/.github/workflows/release.yml")
if [ "$want" != "$JOB" ] || [ "$got" != "$JOB" ]; then
  echo "FAIL: install-matrix job name drift: script '$want', release.yml '$got', test '$JOB'" >&2
  fail=$((fail + 1))
fi
if ! awk '/^  install-matrix:/ { j = 1; next } j && /^  [^ ]/ { exit } j' "$REPO_ROOT/.github/workflows/release.yml" \
  | grep -q '^    uses: ./.github/workflows/install-matrix.yml$'; then
  echo "FAIL: release.yml's install-matrix job no longer calls install-matrix.yml" >&2
  fail=$((fail + 1))
fi

if [ "$fail" -ne 0 ]; then
  echo "FAIL: $fail case(s) failed" >&2
  exit 1
fi

echo "PASS: ci-release-matrix.sh passes only on a completed newest release run whose every install-matrix row succeeded, waits through a run in progress, and fails closed on a missing, unfinished, failed, skipped or row-less run, an unreachable API and a malformed SHA."
