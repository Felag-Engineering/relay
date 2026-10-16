#!/usr/bin/env bash
# Release gate for the BSL Change Date. Each release converts to the Change License on the
# Change Date in LICENSE, so a release must carry a date three years after it ships; one left
# over from an earlier release converts the new code early. The BSL also converts a version on
# the fourth anniversary of its first public distribution, so a date past four years is a typo.
#
# usage: license-change-date.sh [--warn] RELEASE_DATE [LICENSE]
#   RELEASE_DATE  YYYY-MM-DD the release is cut (the tagged commit's date in the workflow).
#   --warn        report a stale date as a warning and exit 0 (dry runs); a malformed or
#                 missing date still fails.
# Exit 0 when the Change Date is within [RELEASE_DATE + 3 years - 7 days, RELEASE_DATE + 4 years].
set -euo pipefail

warn=0
if [ "${1:-}" = "--warn" ]; then warn=1; shift; fi
release=${1:?usage: license-change-date.sh [--warn] RELEASE_DATE [LICENSE]}
license=${2:-"$(git rev-parse --show-toplevel)/LICENSE"}

is_date() { [[ $1 =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] && date -u -d "$1" +%F >/dev/null 2>&1; }

is_date "$release" || { echo "license-change-date: release date '$release' is not YYYY-MM-DD" >&2; exit 2; }
[ -r "$license" ] || { echo "license-change-date: cannot read $license" >&2; exit 2; }

change=$(sed -n 's/^Change Date:[[:space:]]*//p' "$license" | head -n1 | tr -d '[:space:]')
is_date "$change" || { echo "license-change-date: no YYYY-MM-DD 'Change Date:' line in $license (found '$change')" >&2; exit 2; }

earliest=$(date -u -d "$release +3 years -7 days" +%F)
latest=$(date -u -d "$release +4 years" +%F)

problem=""
if [[ $change < $earliest ]]; then
  problem="Change Date $change is less than three years after the release date $release; set it to $(date -u -d "$release +3 years" +%F)"
elif [[ $change > $latest ]]; then
  problem="Change Date $change is past the BSL's four-year limit ($latest) for a release on $release; set it to $(date -u -d "$release +3 years" +%F)"
fi

if [ -z "$problem" ]; then
  echo "license-change-date: ok (Change Date $change for a release on $release)"
  exit 0
fi
if [ "$warn" = 1 ]; then
  echo "::warning::license-change-date: $problem"
  exit 0
fi
echo "::error::license-change-date: $problem" >&2
exit 1
