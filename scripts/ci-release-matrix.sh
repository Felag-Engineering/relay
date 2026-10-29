#!/usr/bin/env bash
# CI OK's evidence that the release dry run's install matrix passed for a pull request's head
# commit. ci.yml skips its own install matrix when scripts/ci-changed-paths.sh says release.yml's
# dry run carries it (release=true); this script is what stops that skip reading as a pass.
#
# It waits for the newest release.yml run whose head is <head-sha> to complete, then passes only
# if that run's install-matrix jobs (named "Install matrix (the release's packages and role)",
# and every job of the reusable workflow under it) all concluded success, and there was at least
# one. Fails CLOSED: no run within the appearance window, a run still going at the deadline, a
# skipped, cancelled or failed row, or an API that never answers is a failure, never a pass. The
# newest run decides: an older pass does not outvote a newer failure.
#
# Usage: ci-release-matrix.sh <head-sha>
# Env:   GITHUB_REPOSITORY (owner/repo) and GH_TOKEN, for gh; the token needs actions: read.
#        RELEASE_MATRIX_TIMEOUT  seconds to wait for the run to complete (default 4800)
#        RELEASE_MATRIX_APPEAR   seconds to wait for a run to exist at all (default 600)
#        RELEASE_MATRIX_INTERVAL seconds between polls (default 60)
set -uo pipefail

# The release workflow's install-matrix job. scripts/ci-release-matrix-test.sh holds this
# equal to the job's name in release.yml.
MATRIX_JOB="Install matrix (the release's packages and role)"

sha=${1:-}
repo=${GITHUB_REPOSITORY:-}
timeout=${RELEASE_MATRIX_TIMEOUT:-4800}
appear=${RELEASE_MATRIX_APPEAR:-600}
interval=${RELEASE_MATRIX_INTERVAL:-60}

die() {
  echo "::error::release install matrix: $*"
  exit 1
}

[[ $sha =~ ^[0-9a-f]{40}$ ]] || die "not a commit SHA: '$sha'"
[[ $repo =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "GITHUB_REPOSITORY is not owner/repo: '$repo'"
for n in "$timeout" "$appear" "$interval"; do
  [[ $n =~ ^[0-9]+$ ]] || die "a RELEASE_MATRIX_* setting is not a whole number of seconds: '$n'"
done

start=$SECONDS
while :; do
  elapsed=$((SECONDS - start))
  # The newest run of release.yml for this head commit, as "<id> <status>". The SHA is
  # validated hex above, so interpolating it into the filter is safe.
  if newest=$(gh api "repos/$repo/actions/workflows/release.yml/runs?head_sha=$sha&per_page=100" \
    --jq "[.workflow_runs[] | select(.head_sha == \"$sha\")] | max_by(.id) // empty | \"\\(.id) \\(.status)\""); then
    if [ -z "$newest" ]; then
      if [ "$elapsed" -ge "$appear" ]; then
        die "no release.yml run for $sha after ${elapsed}s. CI skipped its own matrix because release.yml's pull_request path filter matches this change; if that dry run did not start, dispatch the Release workflow on this branch, then re-run CI's failed jobs."
      fi
      echo "release install matrix: no release.yml run for $sha yet (${elapsed}s)"
    else
      read -r run status <<<"$newest"
      if [ "$status" = completed ]; then
        if rows=$(gh api --paginate "repos/$repo/actions/runs/$run/jobs?filter=latest&per_page=100" \
          --jq '.jobs[] | "\(.conclusion // "none")\t\(.name)"'); then
          matched=0 rowsseen=0 bad=""
          while IFS=$'\t' read -r conclusion name; do
            case "$name" in
              "$MATRIX_JOB / "*) rowsseen=$((rowsseen + 1)) ;;
              "$MATRIX_JOB") ;;
              *) continue ;;
            esac
            matched=$((matched + 1))
            [ "$conclusion" = success ] || bad+="  $conclusion: $name"$'\n'
          done <<<"$rows"
          if [ -n "$bad" ]; then
            printf '%s' "$bad"
            die "run $run for $sha did not pass every row (listed above)"
          fi
          if [ "$rowsseen" -eq 0 ]; then
            die "run $run for $sha completed with no install-matrix rows ($matched job(s) named '$MATRIX_JOB')"
          fi
          echo "release install matrix: run $run for $sha passed all $rowsseen row(s)"
          exit 0
        fi
        echo "release install matrix: cannot list the jobs of run $run yet (${elapsed}s)"
      else
        echo "release install matrix: run $run for $sha is $status (${elapsed}s)"
      fi
    fi
  else
    echo "release install matrix: cannot list release.yml runs yet (${elapsed}s)"
  fi
  if [ "$elapsed" -ge "$timeout" ]; then
    die "gave up after ${elapsed}s without a completed release.yml run for $sha"
  fi
  sleep "$interval"
done
