#!/usr/bin/env bash
# DI-33: the install matrix's platform list equals the capability specification's.
#
#   install-matrix-platforms.sh [spec] [workflow] [dockerfile-dir]
#
# DI-33 names the supported platforms and architectures in prose. The matrix is the only proof
# that a platform is supported, so a platform the workflow runs and the spec does not name is
# an unsupported claim, and one the spec names and the workflow does not run is an unproven
# one. This script reads DI-33's own words and the workflow's marked platform block and fails
# unless the two sets are equal, platform for platform and architecture for architecture.
#
# It anchors on DI-33's wording and fails closed: any rewording sends its author here rather
# than passing vacuously. It reads DI-33 in either shape the spec may hold it in (the Designed
# table row, or the promoted bullet with indented continuation lines), at any line wrap.
#
# Defaults: docs/specs/daemon-installation.md, .github/workflows/install-matrix.yml and
# docker/install-matrix, resolved from the repository root. Needs bash, awk, sed, grep and
# sort only.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
cd "$REPO_ROOT" || exit 1
SPEC="${1:-docs/specs/daemon-installation.md}"
WORKFLOW="${2:-.github/workflows/install-matrix.yml}"
DOCKERFILES="${3:-docker/install-matrix}"

die() { echo "install-matrix-platforms: $*" >&2; exit 1; }

[ -f "$SPEC" ] || die "no spec at $SPEC"
[ -f "$WORKFLOW" ] || die "no workflow at $WORKFLOW"
[ -d "$DOCKERFILES" ] || die "no Dockerfile directory at $DOCKERFILES"

# --- DI-33's text -------------------------------------------------------------------------

# The Designed shape: the second cell of the `| DI-33 |` table row.
claim="$(awk -F'|' '$2 ~ /^[[:space:]]*DI-33[[:space:]]*$/ { print $3; exit }' "$SPEC")"
if [ -z "$claim" ]; then
  # The promoted shape: the `- **DI-33**` bullet and its indented continuation lines, up to
  # the next bullet, a blank line or a heading.
  claim="$(awk '
    found && ($0 ~ /^- \*\*/ || $0 ~ /^[[:space:]]*$/ || $0 ~ /^#/) { exit }
    $0 ~ /^- \*\*DI-33\*\*/ { found = 1 }
    found { print }
  ' "$SPEC")"
fi
[ -n "$claim" ] || die "DI-33 not found in $SPEC"

# A re-wrap anywhere, inside an anchor or a platform name included, parses the same.
claim="$(printf '%s' "$claim" | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')"

reword() { die "DI-33's wording changed; update this parser with it ($1)"; }

case "$claim" in *"removes it:"*) ;; *) reword "no 'removes it:'" ;; esac
case "$claim" in *". Each is supported on"*) ;; *) reword "no '. Each is supported on'" ;; esac

# --- the spec's platforms and architectures ---------------------------------------------------

after="${claim#*removes it:}"
platform_text="${after%%. Each is supported on*}"
arch_text="${claim#*Each is supported on}"
arch_text="${arch_text%%.*}"

# "Ubuntu 24.04 LTS and 26.04 LTS" is two platforms; "Debian 13" is one.
two_releases='^(.+) ([0-9.]+)( LTS)? and ([0-9.]+)( LTS)?$'
one_release='^(.+) ([0-9.]+)( LTS)?$'
spec_platforms=""
IFS=';' read -ra items <<<"$platform_text"
for item in "${items[@]}"; do
  item="$(printf '%s' "$item" | sed -E 's/^ +//; s/ +$//')"
  [ -n "$item" ] || continue
  case "$item" in *"tested on "*) item="${item#*tested on }" ;; esac
  if [[ $item =~ $two_releases ]]; then
    spec_platforms+="${BASH_REMATCH[1]} ${BASH_REMATCH[2]}"$'\n'
    spec_platforms+="${BASH_REMATCH[1]} ${BASH_REMATCH[4]}"$'\n'
  elif [[ $item =~ $one_release ]]; then
    spec_platforms+="${BASH_REMATCH[1]} ${BASH_REMATCH[2]}"$'\n'
  else
    reword "cannot read the platform '$item'"
  fi
done
spec_platforms="$(printf '%s' "$spec_platforms" | sort -u)"
[ -n "$spec_platforms" ] || reword "no platforms between 'removes it:' and 'Each is supported on'"

spec_arches="$(printf '%s' "$arch_text" | grep -oE '`[^`]+`' | tr -d '`' | sort -u)"
[ -n "$spec_arches" ] || reword "no backticked architectures after 'Each is supported on'"

# --- the workflow's platforms and architectures --------------------------------------------------

begin_count="$(grep -c '# BEGIN DI-33 platforms' "$WORKFLOW")"
end_count="$(grep -c '# END DI-33 platforms' "$WORKFLOW")"
[ "$begin_count" -eq 1 ] && [ "$end_count" -eq 1 ] \
  || die "$WORKFLOW must hold exactly one '# BEGIN DI-33 platforms' and one '# END DI-33 platforms' marker (found $begin_count and $end_count)"
if grep -q 'exclude:' "$WORKFLOW"; then
  die "$WORKFLOW uses 'exclude:', which drops a row the list names"
fi

block="$(awk '
  /# END DI-33 platforms/ { inside = 0 }
  inside { print }
  /# BEGIN DI-33 platforms/ { inside = 1 }
' "$WORKFLOW")"
[ -n "$block" ] || die "$WORKFLOW's DI-33 platform block is empty or its markers are out of order"

platform_line='^[[:space:]]*-[[:space:]]*\{.*[[:space:],{]id:'
id_re='(^|[[:space:],{])id: *([A-Za-z0-9.-]+)'
distribution_re='distribution: *"([^"]+)"'
release_re='release: *"([^"]+)"'
wf_platforms=""
ids=""
while IFS= read -r line; do
  [[ $line =~ $platform_line ]] || continue
  [[ $line =~ $id_re ]] || die "no id in '$line'"
  id="${BASH_REMATCH[2]}"
  [[ $line =~ $distribution_re ]] || die "no distribution in '$line'"
  distribution="${BASH_REMATCH[1]}"
  [[ $line =~ $release_re ]] || die "no release in '$line'"
  release="${BASH_REMATCH[1]}"
  wf_platforms+="$distribution $release"$'\n'
  ids+="$id"$'\n'
done <<<"$block"
duplicate_platforms="$(printf '%s' "$wf_platforms" | sort | uniq -d)"
wf_platforms="$(printf '%s' "$wf_platforms" | sort -u)"
[ -n "$wf_platforms" ] || die "$WORKFLOW's DI-33 block holds no platform lines"

duplicates="$(printf '%s' "$ids" | sort | uniq -d)"
[ -z "$duplicates" ] || die "duplicate platform id: $(printf '%s' "$duplicates" | tr '\n' ' ')"
[ -z "$duplicate_platforms" ] || die "duplicate platform (distribution release): $(printf '%s' "$duplicate_platforms" | tr '\n' ';')"
while IFS= read -r id; do
  [ -n "$id" ] || continue
  [ -f "$DOCKERFILES/$id.Dockerfile" ] || die "platform id '$id' has no $DOCKERFILES/$id.Dockerfile"
done <<<"$ids"

arch_line="$(grep -E '^[[:space:]]*arch: *\[' <<<"$block")"
[ "$(grep -c . <<<"$arch_line")" -eq 1 ] || die "the DI-33 block must hold exactly one 'arch: [...]' line"
wf_arches="$(printf '%s' "$arch_line" | sed -E 's/.*\[(.*)\].*/\1/' | tr ',' '\n' | sed -E 's/^ +//; s/ +$//' | grep . | sort -u)"

# --- compare --------------------------------------------------------------------------------------

status=0
if [ "$spec_platforms" != "$wf_platforms" ]; then
  echo "install-matrix-platforms: platform lists differ" >&2
  echo "--- DI-33 ($SPEC)" >&2
  printf '%s\n' "$spec_platforms" >&2
  echo "--- workflow ($WORKFLOW)" >&2
  printf '%s\n' "$wf_platforms" >&2
  echo "--- only in DI-33:" >&2
  comm -23 <(printf '%s\n' "$spec_platforms") <(printf '%s\n' "$wf_platforms") >&2
  echo "--- only in the workflow:" >&2
  comm -13 <(printf '%s\n' "$spec_platforms") <(printf '%s\n' "$wf_platforms") >&2
  status=1
fi
if [ "$spec_arches" != "$wf_arches" ]; then
  echo "install-matrix-platforms: architecture lists differ: DI-33 says $(tr '\n' ' ' <<<"$spec_arches"), the workflow says $(tr '\n' ' ' <<<"$wf_arches")" >&2
  status=1
fi
[ "$status" -eq 0 ] || exit 1

echo "install-matrix-platforms: PASS — $(grep -c . <<<"$spec_platforms") platforms × $(grep -c . <<<"$spec_arches") architectures equal DI-33"
