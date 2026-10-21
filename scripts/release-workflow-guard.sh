#!/usr/bin/env bash
# A regression guard over the committed shapes of release.yml's image, sign-push and latest jobs,
# for the part of RC-7 that no run can show on a pull request: the release pushes the archive its
# image guard checked BY DIGEST, signs that digest keylessly, verifies the signature against this
# workflow's identity, and writes a version tag or :latest only from that verified digest and only
# after the verify.
#
#   release-workflow-guard.sh [<release.yml>]     (default: .github/workflows/release.yml)
#
# It keeps the committed sign -> verify -> tag shape from drifting silently. It is NOT a proof
# against a hostile workflow author: anyone who can edit release.yml can edit this guard, and both
# are human-reviewed security surface. It is a text guard, not a YAML parser, and it refuses what
# it can cheaply recognise as a departure: a job header that is not the bare `  name:` form, a
# quoted, spaced or merge key, a folded job-level `if:`, a block-list `needs:`, a repeated verify
# command, a `||` on a sign or verify line, and any registry reference in sign-push or latest that
# is not one of the committed lines. A harmless restyle of release.yml can therefore fail it, and
# the fix is a deliberate update here. Comment lines and blank lines are never matched, so a
# commented-out directive proves nothing.
#
# It deliberately does not cover: a registry credential other than GITHUB_TOKEN used in another job
# (`docker login ghcr.io` with a secret); a failure masked other than by `||` (`!`, `set +e`,
# `if cmd; then`); a registry write that names neither IMAGE nor ghcr.io; YAML anchors and
# aliases other than merge keys; any job other than image, sign-push and latest, apart from its
# header and `packages: write`; and what a run does, such as whether the sign succeeds.
#
# Needs bash and nothing else: no Docker, no network, no yq. Each refusal prints one line to
# stderr, `::error::release-workflow-guard: <id>: <detail>`, and exits 1; <id> is one of a
# closed list that scripts/release-image-guard-test.sh asserts case by case. The assertions run
# in a fixed order, and that order is part of the contract with the self-test.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
FILE="${1:-$REPO_ROOT/.github/workflows/release.yml}"

refuse() { # <id> <detail>
  echo "::error::release-workflow-guard: $1: $2; update this guard deliberately if the release path changed (RC-7)" >&2
  exit 1
}

if [ ! -f "$FILE" ] || [ ! -r "$FILE" ]; then
  echo "::error::release-workflow-guard: $FILE is not a readable file" >&2
  exit 1
fi
mapfile -t LINES <"$FILE"
N=${#LINES[@]}

# A code line is neither blank nor a full-line comment. A trailing ` # ...` is NOT stripped, so
# a directive with a trailing comment still matches.
RE_COMMENT='^[[:space:]]*#'
RE_JOBS='^jobs:[[:space:]]*$'
RE_HEADER='^  ([A-Za-z0-9_-]+):[[:space:]]*$'
RE_TOPLEVEL='^[^[:space:]#]'
RE_JOB_KEY='^  [^[:space:]]'
RE_PKG_WRITE='packages:[[:space:]]*["'"'"']?write'
KEY_NAMES='(packages|id-token|if|needs|permissions|continue-on-error|IMAGE|DIGEST)'
RE_QUOTED_KEY="[\"']${KEY_NAMES}[\"'][[:space:]]*:"
RE_SPACED_KEY="^[[:space:]-]*${KEY_NAMES}[[:space:]]+:"
RE_MERGE_KEY='^[[:space:]-]*<<[[:space:]]*:'
RE_TOP_PERMISSIONS_KEY='^permissions[[:space:]]*:'
RE_TOP_PERMISSIONS='^permissions: \{\}[[:space:]]*(#.*)?$'
RE_DIGEST_KEY='^[[:space:]]*(-[[:space:]]+)?DIGEST[[:space:]]*:'
RE_STATUS_FN='(always|failure|cancelled)[[:space:]]*\('
RE_NEEDS_FLOW='^\[[[:space:]]*[A-Za-z0-9_-]+([[:space:]]*,[[:space:]]*[A-Za-z0-9_-]+)*[[:space:]]*\]$'
RE_NEEDS_BARE='^[A-Za-z0-9_-]+$'
RE_ID_TOKEN='^[[:space:]]+id-token:[[:space:]]*["'"'"']?write["'"'"']?([[:space:]]|$)'
RE_IMAGE_KEY='^[[:space:]]+IMAGE:'
RE_STEP_IF='^[[:space:]]{6,}(-[[:space:]]+)?if:'
RE_STEP_ITEM='^      -[[:space:]]'
RE_SIGNING_KEY_FLAG='(^|[[:space:]"'"'"'])--(key|sk)([=[:space:]"'"'"']|$)'
# What the allowlist lets a registry-touching line be: no shell operator, no substitution, and
# flags are plain words.
RE_SIGN_LINE='^(run: )?cosign sign [^|;&`<>()"$]*"\$\{IMAGE\}@\$\{DIGEST\}"$'
RE_TAG_LINE='^skopeo copy [^|;&`<>()"$]*"docker://\$\{IMAGE\}@\$\{DIGEST\}" "docker://\$\{IMAGE\}:\$\{version\}"$'
RE_VERIFY_FIRST='^(run: )?cosign verify "\$\{IMAGE\}@\$\{DIGEST\}"( [^|;&`<>()]*)?$'
RE_VERIFY_CONT='^--[a-z-]+ [^|;&`<>()]*$'
RE_ECHO='^echo "[^"`]*"$'
RE_CHECK_ECHO='^\[ "\$\{[a-z]+\}" = "\$\{DIGEST\}" \] \|\| \{ echo "[^"`]*"; exit 1; \}$'
RE_PKG_LINE='^packages:[[:space:]]*write[[:space:]]*(#.*)?$'
RE_DIGEST_ASSIGN='(^|[^A-Za-z0-9_])digest='
LOGIN_LINE='run: echo "${GH_TOKEN}" | docker login ghcr.io -u "${GITHUB_ACTOR}" --password-stdin'
LOGOUT_LINE='run: docker logout ghcr.io || true'
LATEST_COPY='skopeo copy --all --preserve-digests "docker://${IMAGE}@${digest}" "docker://${IMAGE}:latest"'
LATEST_DIGEST='digest="$(cat image/relay-image.digest)"'
RE_IMAGE_VALUE='^[[:space:]]+IMAGE:[[:space:]]*ghcr\.io/felag-engineering/relay[[:space:]]*$'

declare -a CODE
for ((i = 0; i < N; i++)); do
  if [[ -z "${LINES[i]//[[:space:]]/}" || ${LINES[i]} =~ $RE_COMMENT ]]; then CODE[i]=0; else CODE[i]=1; fi
done

at_line() { echo "line $(($1 + 1))"; }

trim() { # <string>
  local s=$1
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

# --- structure -------------------------------------------------------------------------------

jobs_idx=-1
jobs_count=0
for ((i = 0; i < N; i++)); do
  if [[ ${LINES[i]} =~ $RE_JOBS ]]; then
    jobs_idx=$i
    jobs_count=$((jobs_count + 1))
  fi
done
[ "$jobs_count" -eq 1 ] || refuse no-jobs-key "found $jobs_count 'jobs:' lines, want exactly one"

# OWNER[i] is the job whose block holds line i. A block runs from the line after the job's header
# to the next job header or column-0 code line, so a top-level key inserted after a job ends its
# block instead of hiding inside it.
declare -a OWNER
declare -A HEADERS
cur=""
for ((i = jobs_idx + 1; i < N; i++)); do
  if [[ ${LINES[i]} =~ $RE_HEADER ]]; then
    cur=${BASH_REMATCH[1]}
    HEADERS[$cur]=$(( ${HEADERS[$cur]:-0} + 1 ))
    OWNER[i]=""
  elif [ "${CODE[i]}" -eq 1 ] && [[ ${LINES[i]} =~ $RE_TOPLEVEL ]]; then
    cur=""
    OWNER[i]=""
  elif [ "${CODE[i]}" -eq 1 ] && [[ ${LINES[i]} =~ $RE_JOB_KEY ]]; then
    refuse job-header-malformed "$(at_line "$i") starts a job-level key that is not a bare 'name:' header, so the lines below it would be attributed to the job above"
  else
    OWNER[i]=$cur
  fi
done

JOBS=(image sign-push latest)
for j in "${JOBS[@]}"; do
  [ "${HEADERS[$j]:-0}" -eq 1 ] || refuse missing-job "job '$j' has ${HEADERS[$j]:-0} headers, want exactly one"
done

# BLOCK is the code lines of a job's block (as indexes into LINES).
block() { # <job>
  BLOCK=()
  local i
  for ((i = 0; i < N; i++)); do
    if [ "${CODE[i]}" -eq 1 ] && [ "${OWNER[i]:-}" = "$1" ]; then BLOCK+=("$i"); fi
  done
}

# HITS is the BLOCK lines containing a fixed string.
lines_with() { # <literal>
  HITS=()
  local i
  for i in ${BLOCK[@]+"${BLOCK[@]}"}; do
    if [[ ${LINES[i]} == *"$1"* ]]; then HITS+=("$i"); fi
  done
}

# HITS is the BLOCK lines matching a regular expression.
lines_matching() { # <regex>
  HITS=()
  local i
  for i in ${BLOCK[@]+"${BLOCK[@]}"}; do
    if [[ ${LINES[i]} =~ $1 ]]; then HITS+=("$i"); fi
  done
}

# KEYS is the BLOCK lines that are the job-level key <key>: exactly four spaces of indent, so a
# step-level key of the same name (eight or more) never matches.
key_lines() { # <key>
  lines_matching "^    $1:"
  KEYS=(${HITS[@]+"${HITS[@]}"})
}

# write-all grants the registry write without naming it.
for ((i = 0; i < N; i++)); do
  if [ "${CODE[i]}" -eq 1 ] && [[ ${LINES[i]} == *'write-all'* ]]; then
    refuse write-all "$(at_line "$i") grants write-all"
  fi
done

# Without the empty top-level permissions every job lacking its own inherits the repository default.
top_perm_lines=0
top_perm_ok=0
for ((i = 0; i < N; i++)); do
  if [ "${CODE[i]}" -eq 1 ] && [[ ${LINES[i]} =~ $RE_TOP_PERMISSIONS_KEY ]]; then
    top_perm_lines=$((top_perm_lines + 1))
    if [[ ${LINES[i]} =~ $RE_TOP_PERMISSIONS ]]; then top_perm_ok=$((top_perm_ok + 1)); fi
  fi
done
{ [ "$top_perm_lines" -eq 1 ] && [ "$top_perm_ok" -eq 1 ]; } ||
  refuse top-level-permissions "found $top_perm_lines top-level permissions: lines ($top_perm_ok of them 'permissions: {}'), want exactly one 'permissions: {}'"

# The guard reads these keys in their plain form; a quoted or spaced key, or a merge key that
# imports a mapping, would hide one from it.
for ((i = 0; i < N; i++)); do
  [ "${CODE[i]}" -eq 1 ] || continue
  if [[ ${LINES[i]} =~ $RE_QUOTED_KEY || ${LINES[i]} =~ $RE_SPACED_KEY || ${LINES[i]} =~ $RE_MERGE_KEY ]]; then
    refuse yaml-key-form "$(at_line "$i") writes a key the guard reads as a quoted or spaced key or a merge key"
  fi
done

# Only the two publishing jobs may write to the registry, and both are ordered after signing.
for ((i = 0; i < N; i++)); do
  if [ "${CODE[i]}" -eq 1 ] && [[ ${LINES[i]} =~ $RE_PKG_WRITE ]]; then
    owner=${OWNER[i]:-}
    if [ "$owner" != sign-push ] && [ "$owner" != latest ]; then
      refuse packages-write-outside-publish-jobs "$(at_line "$i") holds packages write outside sign-push and latest (job '${owner:-none}')"
    fi
  fi
done
# The vacuity guard for the match above.
for j in sign-push latest; do
  block "$j"
  lines_matching "$RE_PKG_WRITE"
  [ "${#HITS[@]}" -gt 0 ] || refuse packages-write-absent "job '$j' does not hold packages write, so the registry-write check matched nothing"
done

# --- job conditions --------------------------------------------------------------------------

for j in "${JOBS[@]}"; do
  block "$j"
  key_lines if
  if [ "${#KEYS[@]}" -gt 1 ]; then
    refuse job-if-not-single-line "job '$j' has ${#KEYS[@]} job-level if: lines"
  fi
  if [ "${#KEYS[@]}" -eq 1 ]; then
    v="$(trim "${LINES[KEYS[0]]#    if:}")"
    if [ -z "$v" ] || [[ $v == '>'* || $v == '|'* ]]; then
      refuse job-if-not-single-line "job '$j' $(at_line "${KEYS[0]}") has a folded or empty job-level if:; a status function could hide in it"
    fi
    # release.yml's own rule: a publishing job never gets always() or !cancelled(), or it would
    # run after a failed sign or verify.
    if [[ ${LINES[KEYS[0]]} =~ $RE_STATUS_FN ]]; then
      refuse job-if-status-function "job '$j' $(at_line "${KEYS[0]}") has a status function in its job-level if:"
    fi
  fi
  lines_with 'continue-on-error'
  if [ "${#HITS[@]}" -gt 0 ]; then
    refuse continue-on-error "job '$j' $(at_line "${HITS[0]}") sets continue-on-error"
  fi
done

# --- image: the guarded archive and its digest -----------------------------------------------

block image
lines_with 'bash scripts/release-image-guard.sh relay-image.oci.tar'
[ "${#HITS[@]}" -gt 0 ] || refuse image-guard-not-run "job 'image' does not run the image guard on relay-image.oci.tar"
lines_with 'tar -xOf relay-image.oci.tar index.json'
read_index=${#HITS[@]}
lines_with '> relay-image.digest'
[ "$read_index" -gt 0 ] && [ "${#HITS[@]}" -gt 0 ] ||
  refuse image-digest-not-recorded "job 'image' does not read the archive's index into relay-image.digest"
# A step-level condition on any image step could skip the guard and still upload the archive.
lines_matching "$RE_STEP_IF"
[ "${#HITS[@]}" -eq 0 ] || refuse image-step-condition "job 'image' $(at_line "${HITS[0]}") has a step-level if:, so a step could be skipped"

# --- sign-push: push by digest, sign, verify, tag --------------------------------------------

# NEEDS is the names a job lists in its single job-level needs: line, in the one-line flow form
# or the bare form; any other shape is refused.
parse_needs() { # <job>
  block "$1"
  key_lines needs
  NEEDS=()
  [ "${#KEYS[@]}" -gt 0 ] || return 0
  if [ "${#KEYS[@]}" -gt 1 ]; then
    refuse needs-not-flow-form "job '$1' has ${#KEYS[@]} job-level needs: lines"
  fi
  local v name
  v="$(trim "${LINES[KEYS[0]]#    needs:}")"
  if [[ $v =~ $RE_NEEDS_FLOW ]]; then
    v=${v#\[}
    v=${v%\]}
    local -a parts
    IFS=',' read -r -a parts <<<"$v"
    for name in "${parts[@]}"; do NEEDS+=("$(trim "$name")"); done
  elif [[ $v =~ $RE_NEEDS_BARE ]]; then
    NEEDS=("$v")
  else
    refuse needs-not-flow-form "job '$1' $(at_line "${KEYS[0]}") has a needs: that is neither a one-line list nor a single name"
  fi
}
in_needs() { # <name>
  local n
  for n in ${NEEDS[@]+"${NEEDS[@]}"}; do
    if [ "$n" = "$1" ]; then return 0; fi
  done
  return 1
}

parse_needs sign-push
in_needs image || refuse sign-push-needs-image "job 'sign-push' does not need 'image', so it could run before the guarded archive exists"

block sign-push
# Keyless signing needs the workflow's OIDC identity.
lines_matching "$RE_ID_TOKEN"
[ "${#HITS[@]}" -gt 0 ] || refuse sign-push-id-token "job 'sign-push' does not grant id-token: write"

lines_matching "$RE_IMAGE_KEY"
if [ "${#HITS[@]}" -ne 1 ] || [[ ! ${LINES[HITS[0]]} =~ $RE_IMAGE_VALUE ]]; then
  refuse sign-push-image-name "job 'sign-push' does not set IMAGE exactly once to ghcr.io/felag-engineering/relay"
fi

lit='oci-archive:image/relay-image.oci.tar "docker://${IMAGE}@${DIGEST}"'
lines_with "$lit"
[ "${#HITS[@]}" -gt 0 ] || refuse push-by-digest "job 'sign-push' does not push the guarded archive to \${IMAGE}@\${DIGEST}"
push_line=${HITS[0]}

# `cosign sign ` with the trailing space: this job also runs `cosign sign-blob` over SHA256SUMS,
# which must not count as signing the image.
lines_with 'cosign sign '
SIGNS=(${HITS[@]+"${HITS[@]}"})
digest_ref='"${IMAGE}@${DIGEST}"'
[ "${#SIGNS[@]}" -gt 0 ] || refuse sign-by-digest "job 'sign-push' does not sign the image"
for i in "${SIGNS[@]}"; do
  [[ ${LINES[i]} == *"$digest_ref"* ]] || refuse sign-by-digest "job 'sign-push' $(at_line "$i") signs something other than \${IMAGE}@\${DIGEST}"
done

# A flag is matched as a whole token, so an unrelated `--keyring-...` or `--skip-...` is not a key.
lines_matching "$RE_SIGNING_KEY_FLAG"
[ "${#HITS[@]}" -eq 0 ] || refuse sign-not-keyless "job 'sign-push' $(at_line "${HITS[0]}") names a signing key flag"
for lit in 'COSIGN_KEY' 'COSIGN_PRIVATE_KEY'; do
  lines_with "$lit"
  [ "${#HITS[@]}" -eq 0 ] || refuse sign-not-keyless "job 'sign-push' $(at_line "${HITS[0]}") names a signing key ($lit)"
done

lit='cosign verify "${IMAGE}@${DIGEST}"'
lines_with "$lit"
[ "${#HITS[@]}" -eq 1 ] || refuse verify-by-digest "job 'sign-push' has ${#HITS[@]} 'cosign verify' commands on \${IMAGE}@\${DIGEST}, want exactly one"
verify_first=${HITS[0]}
# The verify command and its continuation lines: the identity and issuer must belong to it, not
# to the verify-blob command elsewhere in the job.
verify_last=$verify_first
while (( verify_last + 1 < N )); do
  prev=${LINES[verify_last]}
  prev=${prev%"${prev##*[![:space:]]}"}
  [[ $prev == *'\' ]] || break
  verify_last=$((verify_last + 1))
done
span_has() { # <literal>
  local i
  for ((i = verify_first; i <= verify_last; i++)); do
    if [[ ${LINES[i]} == *"$1"* ]]; then return 0; fi
  done
  return 1
}
span_has '--certificate-identity "https://github.com/${GITHUB_REPOSITORY}/.github/workflows/release.yml@${GITHUB_REF}"' ||
  refuse verify-identity "the 'cosign verify' at $(at_line "$verify_first") does not pin the release workflow's identity"
span_has '--certificate-oidc-issuer https://token.actions.githubusercontent.com' ||
  refuse verify-oidc-issuer "the 'cosign verify' at $(at_line "$verify_first") does not pin the GitHub Actions OIDC issuer"

# The verify must stay strict: no ignored transparency log, no regexp identity or issuer.
for ((i = verify_first; i <= verify_last; i++)); do
  if [[ ${LINES[i]} == *'--insecure'* || ${LINES[i]} == *'-regexp'* ]]; then
    refuse verify-weakened "the 'cosign verify' span weakens verification at $(at_line "$i")"
  fi
done

# `|| true` (or any `||`) on a sign or verify line would let a failed signature pass.
for i in "${SIGNS[@]}"; do
  [[ ${LINES[i]} != *'||'* ]] || refuse failure-masked "job 'sign-push' $(at_line "$i") has || on a sign command"
done
for ((i = verify_first; i <= verify_last; i++)); do
  [[ ${LINES[i]} != *'||'* ]] || refuse failure-masked "the 'cosign verify' span has || at $(at_line "$i")"
done

# The vacuity guard for the tag-order check below.
tag_write=0
for i in "${BLOCK[@]}"; do
  if [[ ${LINES[i]} == *'skopeo copy'* && ${LINES[i]} == *'"docker://${IMAGE}:${version}"'* ]]; then tag_write=1; fi
done
[ "$tag_write" -eq 1 ] || refuse tag-write-missing "job 'sign-push' does not write the version tag, so the tag-order check would match nothing"

# What a version tag points at: every tag write in this job copies the pushed, signed digest.
for i in "${BLOCK[@]}"; do
  if [[ ${LINES[i]} == *'"docker://${IMAGE}:'* && ${LINES[i]} != *'skopeo inspect'* ]]; then
    [[ ${LINES[i]} == *'"docker://${IMAGE}@${DIGEST}" "docker://${IMAGE}:${version}"' ]] ||
      refuse tag-source-not-pushed-digest "job 'sign-push' $(at_line "$i") writes a tag from something other than \"docker://\${IMAGE}@\${DIGEST}\" to \"docker://\${IMAGE}:\${version}\""
  fi
done

# DIGEST, which the push, sign, verify and tag all name, is the digest the image job recorded.
for i in "${BLOCK[@]}"; do
  if [[ ${LINES[i]} =~ $RE_DIGEST_KEY ]]; then
    [ "$(trim "${LINES[i]#*:}")" = '${{ steps.digest.outputs.digest }}' ] ||
      refuse digest-env-not-pushed "job 'sign-push' $(at_line "$i") sets DIGEST to something other than the digest step's output"
  fi
  if [[ ${LINES[i]} == *'DIGEST='* ]]; then
    refuse digest-env-not-pushed "job 'sign-push' $(at_line "$i") assigns DIGEST in a script"
  fi
done

sign_min=${SIGNS[0]}
sign_max=${SIGNS[0]}
for i in "${SIGNS[@]}"; do
  if (( i < sign_min )); then sign_min=$i; fi
  if (( i > sign_max )); then sign_max=$i; fi
done
(( sign_min > push_line )) || refuse order-push-sign "job 'sign-push' signs at $(at_line "$sign_min"), at or before the push at $(at_line "$push_line")"
(( sign_max < verify_first )) || refuse order-sign-verify "job 'sign-push' signs at $(at_line "$sign_max"), at or after the verify at $(at_line "$verify_first")"

# Any reference to the image by tag that is not an inspect, in this job, comes after the verify.
tag_last=-1
for i in "${BLOCK[@]}"; do
  if [[ ${LINES[i]} == *'"docker://${IMAGE}:'* && ${LINES[i]} != *'skopeo inspect'* ]]; then
    if (( i <= verify_last )); then
      refuse order-verify-tag "job 'sign-push' references the image by tag at $(at_line "$i"), at or before the verify ending at $(at_line "$verify_last")"
    fi
    if (( i > tag_last )); then tag_last=$i; fi
  fi
done

# No step-level if: may sit in a step that runs up to the last tag reference: an `always()`, `!cancelled()`
# or `false` there could write a tag after a failed or skipped sign or verify. The steps from the
# next step item on (the registry log-out) may carry one. An unrecognised step layout leaves no
# such steps, so every if: is refused.
steps_end=$N
for i in "${BLOCK[@]}"; do
  if (( i > tag_last )) && [[ ${LINES[i]} =~ $RE_STEP_ITEM ]]; then steps_end=$i; break; fi
done
for i in "${BLOCK[@]}"; do
  if (( i < steps_end )) && [[ ${LINES[i]} =~ $RE_STEP_IF ]]; then
    refuse sign-push-step-condition "job 'sign-push' $(at_line "$i") has a step-level if: in a step at or before the last tag write at $(at_line "$tag_last")"
  fi
done

# Any line that names the image or the registry is one of the committed lines. This is what
# refuses a registry write the patterns above do not name: an unquoted ref, crane, docker push,
# cosign copy, oras.
ref_allowed() { # <job> <index>
  local t
  t="$(trim "${LINES[$2]}")"
  if [[ ${LINES[$2]} =~ $RE_IMAGE_VALUE || $t == "$LOGIN_LINE" || $t == "$LOGOUT_LINE" ]]; then return 0; fi
  if [[ $t =~ $RE_ECHO && $t != *'$('* ]]; then return 0; fi
  if [ "$1" = latest ]; then
    [ "$t" = "$LATEST_COPY" ]
    return
  fi
  if [[ $t =~ $RE_PKG_LINE || $t =~ $RE_SIGN_LINE || $t =~ $RE_TAG_LINE ]]; then return 0; fi
  if [[ $t =~ $RE_CHECK_ECHO && $t != *'$('* ]]; then return 0; fi
  case "$t" in
    'err="$(skopeo inspect --raw "docker://${IMAGE}:${version}" 2>&1 >existing.json)"' | \
      'oci-archive:image/relay-image.oci.tar "docker://${IMAGE}@${DIGEST}"' | \
      'skopeo inspect --raw "docker://${IMAGE}@${DIGEST}" > pushed.json' | \
      'skopeo inspect --raw "docker://${IMAGE}:${version}" > tagged.json' | \
      'subject-name: ${{ env.IMAGE }}') return 0 ;;
  esac
  if (( $2 == verify_first )); then [[ $t =~ $RE_VERIFY_FIRST ]]; return; fi
  if (( $2 > verify_first && $2 <= verify_last )); then [[ $t =~ $RE_VERIFY_CONT ]]; return; fi
  return 1
}
refs_allowed() { # <job>
  local i
  block "$1"
  for i in "${BLOCK[@]}"; do
    if [[ ${LINES[i]} == *IMAGE* || ${LINES[i]} == *ghcr.io* ]] && ! ref_allowed "$1" "$i"; then
      refuse registry-ref-not-allowlisted "job '$1' $(at_line "$i") names the image or the registry in a line that is not one of the committed ones"
    fi
  done
}
refs_allowed sign-push

# --- latest: after sign-push -----------------------------------------------------------------

parse_needs latest
in_needs sign-push || refuse latest-needs-sign-push "job 'latest' does not need 'sign-push', so :latest could move before the digest is signed and tagged"

# :latest is moved by one copy of the digest recorded by the image job, and nothing else.
block latest
copies=()
digest_assigns=()
for i in "${BLOCK[@]}"; do
  if [[ ${LINES[i]} == *'skopeo copy'* ]]; then copies+=("$i"); fi
  if [[ ${LINES[i]} =~ $RE_DIGEST_ASSIGN ]]; then digest_assigns+=("$i"); fi
done
{ [ "${#copies[@]}" -eq 1 ] && [ "$(trim "${LINES[copies[0]]}")" = "$LATEST_COPY" ]; } ||
  refuse latest-copy-source "job 'latest' does not have exactly one skopeo copy, of the form: $LATEST_COPY"
{ [ "${#digest_assigns[@]}" -eq 1 ] && [ "$(trim "${LINES[digest_assigns[0]]}")" = "$LATEST_DIGEST" ]; } ||
  refuse latest-digest-source "job 'latest' does not take digest from image/relay-image.digest exactly once"
refs_allowed latest

echo "ok: release-workflow-guard: $FILE: the image, sign-push and latest jobs still have their committed shapes: pushed by digest, signed and verified keylessly, tagged from that digest only after (a regression guard, not a proof)"
