#!/usr/bin/env bash
# Proves scripts/release-image-guard.sh refuses what its header says it refuses, against tiny
# OCI archives built here from tar, jq and sha256sum (#892). Hermetic: bash and coreutils, no
# Docker, no network, no writes outside its own `mktemp -d`. The guard's --version step needs
# Docker and is exercised by the release workflow's dry run instead.
#
# It also proves scripts/release-workflow-guard.sh (RC-7), case by case, against mutated copies of
# the committed release.yml (the "Release workflow guard" section below).
#
# Every refusal case asserts the REASON as well as the exit status, so a fixture that breaks
# for an unrelated reason cannot pass as a proof.
#
# NOT `set -e`: every case must run and be reported, not stop at the first failure.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
GUARD="$REPO_ROOT/scripts/release-image-guard.sh"
WORKDIR="$(mktemp -d)" || { echo "FAIL: mktemp -d failed" >&2; exit 1; }
trap 'case "${WORKDIR:-}" in /*) rm -rf "$WORKDIR" ;; esac' EXIT
case "$WORKDIR" in
  /*) ;;
  *) echo "FAIL: mktemp returned a non-absolute path: '$WORKDIR'" >&2; exit 1 ;;
esac

fail=0
n=0

BIN_CONTENT="the released relay binary"
BIN_SHA="$(printf '%s' "$BIN_CONTENT" | sha256sum | awk '{print $1}')"

# layer_dir <dir> <name> [gzip]: tar a directory into a layer blob under $L and print its
# path. Entries are owned 0/0, as a real layer's are.
L="$WORKDIR/layers"
mkdir -p "$L"
layer_tar() {
  local dir="$1" name="$2" mode="${3:-plain}"
  local -a entries; mapfile -t entries < <(cd "$dir" && ls -A)
  tar --sort=name --owner=0 --group=0 --numeric-owner -cf "$L/$name.tar" -C "$dir" "${entries[@]}"
  if [ "$mode" = gzip ]; then
    gzip -n -c "$L/$name.tar" >"$L/$name.blob"
  else
    cp "$L/$name.tar" "$L/$name.blob"
  fi
  echo "$L/$name.blob"
}

# mk_base_with <name> <uid|none> <mode>: a lower layer holding /etc/os-release and, unless <uid>
# is "none", the state directory var/lib/relay owned <uid>/<uid> with <mode>.
mk_base_with() {
  local name="$1" uid="$2" mode="$3" d="$WORKDIR/src/$1"
  rm -rf "$d"; mkdir -p "$d/etc" "$d/var/lib/relay"; echo alpine >"$d/etc/os-release"
  chmod "$mode" "$d/var/lib/relay"
  tar --sort=name --owner=0 --group=0 --numeric-owner -cf "$L/$name.tar" -C "$d" etc
  if [ "$uid" != none ]; then
    tar --owner="$uid" --group="$uid" --numeric-owner -rf "$L/$name.tar" -C "$d" var/lib/relay
  fi
  cp "$L/$name.tar" "$L/$name.blob"
  echo "$L/$name.blob"
}
mk_base() { mk_base_with base 10001 0700; }
mk_top() { # name, mode, content: a top layer holding the binary
  local d="$WORKDIR/src/$1"; rm -rf "$d"; mkdir -p "$d/usr/local/bin"
  printf '%s' "$3" >"$d/usr/local/bin/relay"; chmod "$2" "$d/usr/local/bin/relay"
  layer_tar "$d" "$1" gzip
}

sha_of() { sha256sum "$1" | awk '{print $1}'; }

# assemble <out.tar> <user> <platform-arch> <manifest-jq> <layer-blob>...
# Builds an OCI layout whose index.json -> image index -> {a real manifest for <arch>, an
# attestation-style unknown/unknown manifest}. <manifest-jq> edits the manifest BEFORE it is
# hashed, so the index still names it correctly and only the edited field is wrong.
assemble() {
  local out="$1" user="$2" arch="$3" mjq="$4"; shift 4
  local lay="$WORKDIR/layout"; rm -rf "$lay"; mkdir -p "$lay/blobs/sha256"
  echo '{"imageLayoutVersion":"1.0.0"}' >"$lay/oci-layout"
  put() { local h; h="$(sha_of "$1")"; cp "$1" "$lay/blobs/sha256/$h"; echo "$h"; }

  local layers='[]' diffids='[]' f h sz mt
  for f in "$@"; do
    h="$(put "$f")"; sz="$(stat -c %s "$f")"
    case "$f" in
      *.blob) if gzip -t "$f" 2>/dev/null; then mt=application/vnd.oci.image.layer.v1.tar+gzip
              else mt=application/vnd.oci.image.layer.v1.tar; fi ;;
    esac
    layers="$(jq -c --arg d "sha256:$h" --argjson s "$sz" --arg m "$mt" '. + [{mediaType:$m,digest:$d,size:$s}]' <<<"$layers")"
    diffids="$(jq -c --arg d "sha256:$h" '. + [$d]' <<<"$diffids")"
  done

  local cfg="$WORKDIR/config.json" mf="$WORKDIR/manifest.json" ix="$WORKDIR/image-index.json"
  jq -nc --arg u "$user" --arg a "$arch" --argjson ids "$diffids" \
    '{architecture:$a, os:"linux", config:{User:$u, Entrypoint:["/usr/local/bin/relay"]}, rootfs:{type:"layers",diff_ids:$ids}}
     | if env.CONFIG_ENV then .config.Env = (env.CONFIG_ENV | fromjson) else . end' >"$cfg"
  local ch; ch="$(put "$cfg")"
  jq -nc --arg c "sha256:$ch" --argjson l "$layers" \
    '{schemaVersion:2, mediaType:"application/vnd.oci.image.manifest.v1+json", config:{mediaType:"application/vnd.oci.image.config.v1+json",digest:$c,size:1}, layers:$l}' \
    | jq -c "$mjq" >"$mf"
  local mh; mh="$(put "$mf")"
  # PLATFORMS (space-separated goarch list) is what the image index advertises.
  local plist='[]' pa
  for pa in ${PLATFORMS:-amd64 arm64}; do
    plist="$(jq -c --arg m "sha256:$mh" --arg a "$pa" '. + [{mediaType:"application/vnd.oci.image.manifest.v1+json",digest:$m,size:1,platform:{os:"linux",architecture:$a}}]' <<<"$plist")"
  done
  jq -nc --argjson l "$plist" '{schemaVersion:2, mediaType:"application/vnd.oci.image.index.v1+json", manifests:$l}' >"$ix"
  local ih; ih="$(put "$ix")"
  jq -nc --arg i "sha256:$ih" \
    '{schemaVersion:2, manifests:[{mediaType:"application/vnd.oci.image.index.v1+json",digest:$i,size:1}]}' >"$lay/index.json"
  tar -cf "$out" -C "$lay" .
}

# run_guard <expect: ok|fail> <reason-substring> <name> <archive> <platform> <sha>
check() {
  local expect="$1" reason="$2" name="$3"; shift 3
  n=$((n + 1))
  local out rc
  out="$(bash "$GUARD" "$@" 2>&1)"; rc=$?
  if [ "$expect" = ok ]; then
    if [ "$rc" -eq 0 ]; then echo "PASS: $name"; else echo "FAIL: $name: want success, got rc=$rc: $out"; fail=1; fi
    return
  fi
  if [ "$rc" -ne 0 ] && grep -qF -- "$reason" <<<"$out"; then
    echo "PASS: $name (refused: $reason)"
  else
    echo "FAIL: $name: want refusal containing '$reason', got rc=$rc: $out"; fail=1
  fi
}

BASE="$(mk_base)"
GOOD_TOP="$(mk_top good 0755 "$BIN_CONTENT")"
ID='.'

# 1. The good archive passes (gzip top layer over a plain base).
assemble "$WORKDIR/good.tar" 10001:10001 amd64 "$ID" "$BASE" "$GOOD_TOP"
check ok "" "good archive passes" "$WORKDIR/good.tar" linux/amd64 "$BIN_SHA"

# 2. A wrong expected binary digest.
check fail "SHA256SUMS says" "wrong binary digest" "$WORKDIR/good.tar" linux/amd64 "$(printf 'other' | sha256sum | awk '{print $1}')"

# 3. A platform set that is not exactly amd64 + arm64.
PLATFORMS="amd64" assemble "$WORKDIR/onlyamd.tar" 10001:10001 amd64 "$ID" "$BASE" "$GOOD_TOP"
check fail "want exactly linux/amd64,linux/arm64" "only one platform" "$WORKDIR/onlyamd.tar" linux/amd64 "$BIN_SHA"
PLATFORMS="amd64 arm64 riscv64" assemble "$WORKDIR/extraplat.tar" 10001:10001 amd64 "$ID" "$BASE" "$GOOD_TOP"
check fail "want exactly linux/amd64,linux/arm64" "an extra platform" "$WORKDIR/extraplat.tar" linux/amd64 "$BIN_SHA"

# 4. A root User, and an unset one.
assemble "$WORKDIR/root.tar" 0 amd64 "$ID" "$BASE" "$GOOD_TOP"
check fail "want 10001:10001" "root User" "$WORKDIR/root.tar" linux/amd64 "$BIN_SHA"
assemble "$WORKDIR/nouser.tar" "" amd64 "$ID" "$BASE" "$GOOD_TOP"
check fail "want 10001:10001" "unset User" "$WORKDIR/nouser.tar" linux/amd64 "$BIN_SHA"

# 5. A tampered blob: the layer's bytes change after the manifest named its digest.
rm -rf "$WORKDIR/x"; mkdir -p "$WORKDIR/x"; tar -xf "$WORKDIR/good.tar" -C "$WORKDIR/x"
lh="$(sha_of "$GOOD_TOP")"
printf 'tampered' >>"$WORKDIR/x/blobs/sha256/$lh"
tar -cf "$WORKDIR/tampered.tar" -C "$WORKDIR/x" .
check fail "is tampered" "tampered blob" "$WORKDIR/tampered.tar" linux/amd64 "$BIN_SHA"

# 6. A symlink at the binary's path, and a non-0755 binary.
d="$WORKDIR/src/sym"; rm -rf "$d"; mkdir -p "$d/usr/local/bin"; ln -s /bin/busybox "$d/usr/local/bin/relay"
SYM_TOP="$(layer_tar "$d" sym gzip)"
assemble "$WORKDIR/symlink.tar" 10001:10001 amd64 "$ID" "$BASE" "$SYM_TOP"
check fail "not a regular file" "symlink member" "$WORKDIR/symlink.tar" linux/amd64 "$BIN_SHA"
d="$WORKDIR/src/hard"; rm -rf "$d"; mkdir -p "$d/usr/local/bin"
printf '%s' "$BIN_CONTENT" >"$d/usr/local/bin/other"; chmod 0755 "$d/usr/local/bin/other"
ln "$d/usr/local/bin/other" "$d/usr/local/bin/relay"
HARD_TOP="$(layer_tar "$d" hard gzip)"
assemble "$WORKDIR/hardlink.tar" 10001:10001 amd64 "$ID" "$BASE" "$HARD_TOP"
# layer_tar sorts by name, so `other` is stored first and `relay` is the hardlink member.
check fail "not a regular file" "hardlink member" "$WORKDIR/hardlink.tar" linux/amd64 "$BIN_SHA"
WRONGMODE_TOP="$(mk_top wrongmode 0777 "$BIN_CONTENT")"
assemble "$WORKDIR/mode.tar" 10001:10001 amd64 "$ID" "$BASE" "$WRONGMODE_TOP"
check fail "want rwxr-xr-x" "binary mode 0777" "$WORKDIR/mode.tar" linux/amd64 "$BIN_SHA"

# 7. A malformed digest in the manifest (path traversal shaped), before any blob path is built.
assemble "$WORKDIR/baddigest.tar" 10001:10001 amd64 \
  '.layers[1].digest = "sha256:../../../../etc/passwd"' "$BASE" "$GOOD_TOP"
check fail "malformed digest" "malformed layer digest" "$WORKDIR/baddigest.tar" linux/amd64 "$BIN_SHA"
assemble "$WORKDIR/shortdigest.tar" 10001:10001 amd64 \
  '.layers[1].digest = "sha256:abc123"' "$BASE" "$GOOD_TOP"
check fail "malformed digest" "short layer digest" "$WORKDIR/shortdigest.tar" linux/amd64 "$BIN_SHA"

# 8. The right binary exists, but only in a LOWER layer, under an opaque whiteout in the top one.
LOWER="$(mk_top lower 0755 "$BIN_CONTENT")"
d="$WORKDIR/src/opq"; rm -rf "$d"; mkdir -p "$d/usr/local/bin"; : >"$d/usr/local/bin/.wh..wh..opq"
OPQ_TOP="$(layer_tar "$d" opq gzip)"
assemble "$WORKDIR/opaque.tar" 10001:10001 amd64 "$ID" "$LOWER" "$OPQ_TOP"
check fail "opaque whiteout" "lower-layer binary under an opaque whiteout" "$WORKDIR/opaque.tar" linux/amd64 "$BIN_SHA"
# ...and with no whiteout at all: still not in the topmost layer.
assemble "$WORKDIR/loweronly.tar" 10001:10001 amd64 "$ID" "$LOWER" "$BASE"
check fail "not in the topmost layer" "binary only in a lower layer" "$WORKDIR/loweronly.tar" linux/amd64 "$BIN_SHA"
# A named whiteout of the binary in the same layer that ships it is refused too.
d="$WORKDIR/src/wh"; rm -rf "$d"; mkdir -p "$d/usr/local/bin"
printf '%s' "$BIN_CONTENT" >"$d/usr/local/bin/relay"; chmod 0755 "$d/usr/local/bin/relay"; : >"$d/usr/local/bin/.wh.relay"
WH_TOP="$(layer_tar "$d" wh gzip)"
assemble "$WORKDIR/whiteout.tar" 10001:10001 amd64 "$ID" "$BASE" "$WH_TOP"
check fail "whiteout '" "named whiteout of the binary" "$WORKDIR/whiteout.tar" linux/amd64 "$BIN_SHA"

# 8b. Non-canonical spellings of the binary's path, and a symlinked ancestor. A layer is built
# from a staging tree and its names rewritten with --transform, since the filesystem cannot
# hold them.
layer_renamed() { # <name> <staging-dir> <sed-expr>
  local -a entries; mapfile -t entries < <(cd "$2" && ls -A)
  tar --sort=name --owner=0 --group=0 --numeric-owner --transform "$3" -cf "$L/$1.tar" -C "$2" "${entries[@]}"
  gzip -n -c "$L/$1.tar" >"$L/$1.blob"
  echo "$L/$1.blob"
}
d="$WORKDIR/src/dot"; rm -rf "$d"; mkdir -p "$d/stage"
printf '%s' "$BIN_CONTENT" >"$d/stage/relay"; chmod 0755 "$d/stage/relay"
DOT_TOP="$(layer_renamed dot "$d" 's,^stage/relay$,usr/local/bin/./relay,')"
assemble "$WORKDIR/dotname.tar" 10001:10001 amd64 "$ID" "$BASE" "$DOT_TOP"
check fail "non-canonical member name" "usr/local/bin/./relay" "$WORKDIR/dotname.tar" linux/amd64 "$BIN_SHA"
SLASH_TOP="$(layer_renamed slash "$d" 's,^stage/relay$,usr/local//bin/relay,')"
assemble "$WORKDIR/slashname.tar" 10001:10001 amd64 "$ID" "$BASE" "$SLASH_TOP"
check fail "non-canonical member name" "usr/local//bin/relay" "$WORKDIR/slashname.tar" linux/amd64 "$BIN_SHA"
d="$WORKDIR/src/anc"; rm -rf "$d"; mkdir -p "$d/usr/local" "$d/stage"
ln -s /opt/evil "$d/usr/local/bin"
printf '%s' "$BIN_CONTENT" >"$d/stage/relay"; chmod 0755 "$d/stage/relay"
ANC_TOP="$(layer_renamed anc "$d" 's,^stage/relay$,usr/local/bin/relay,')"
assemble "$WORKDIR/ancestor.tar" 10001:10001 amd64 "$ID" "$BASE" "$ANC_TOP"
check fail "ancestor /usr/local/bin is not a directory" "symlinked ancestor directory" "$WORKDIR/ancestor.tar" linux/amd64 "$BIN_SHA"
# ...and the same symlink planted in a LOWER layer under a well-formed top layer.
d="$WORKDIR/src/lowanc"; rm -rf "$d"; mkdir -p "$d/usr/local"; ln -s /opt/evil "$d/usr/local/bin"
LOWANC="$(layer_tar "$d" lowanc gzip)"
assemble "$WORKDIR/lowancestor.tar" 10001:10001 amd64 "$ID" "$LOWANC" "$GOOD_TOP"
check fail "ancestor /usr/local/bin is not a directory" "symlinked ancestor in a lower layer" "$WORKDIR/lowancestor.tar" linux/amd64 "$BIN_SHA"

# 8c. The config's Env: no RELAY_* name, and a refused value is never echoed.
CONFIG_ENV='["PATH=/usr/bin"]' assemble "$WORKDIR/envok.tar" 10001:10001 amd64 "$ID" "$BASE" "$GOOD_TOP"
check ok "" "Env without a RELAY_ name passes" "$WORKDIR/envok.tar" linux/amd64 "$BIN_SHA"
CONFIG_ENV='["PATH=/usr/bin","RELAY_HOSTNAME=secret-x"]' assemble "$WORKDIR/envrelay.tar" 10001:10001 amd64 "$ID" "$BASE" "$GOOD_TOP"
check fail "config Env sets RELAY_HOSTNAME" "Env names RELAY_HOSTNAME" "$WORKDIR/envrelay.tar" linux/amd64 "$BIN_SHA"
n=$((n + 1))
if bash "$GUARD" "$WORKDIR/envrelay.tar" linux/amd64 "$BIN_SHA" 2>&1 | grep -qF secret-x; then
  echo "FAIL: the guard echoed an Env value"; fail=1
else
  echo "PASS: the guard prints Env names, never values"
fi

# 8d. The state directory: 10001/10001 0700 after every layer.
assemble "$WORKDIR/state-root.tar" 10001:10001 amd64 "$ID" "$(mk_base_with stroot 0 0700)" "$GOOD_TOP"
check fail "want a directory 'd rwx------ 10001/10001'" "state directory owned by root" "$WORKDIR/state-root.tar" linux/amd64 "$BIN_SHA"
assemble "$WORKDIR/state-mode.tar" 10001:10001 amd64 "$ID" "$(mk_base_with stmode 10001 0755)" "$GOOD_TOP"
check fail "want a directory 'd rwx------ 10001/10001'" "state directory mode 0755" "$WORKDIR/state-mode.tar" linux/amd64 "$BIN_SHA"
assemble "$WORKDIR/state-none.tar" 10001:10001 amd64 "$ID" "$(mk_base_with stnone none 0700)" "$GOOD_TOP"
check fail "/var/lib/relay is 'absent'" "no state directory" "$WORKDIR/state-none.tar" linux/amd64 "$BIN_SHA"
d="$WORKDIR/src/stwh"; rm -rf "$d"; mkdir -p "$d/var/lib"; : >"$d/var/lib/.wh.relay"
STWH="$(layer_tar "$d" stwh gzip)"
assemble "$WORKDIR/state-whiteout.tar" 10001:10001 amd64 "$ID" "$BASE" "$STWH" "$GOOD_TOP"
check fail "/var/lib/relay is 'absent'" "state directory whited out by a later layer" "$WORKDIR/state-whiteout.tar" linux/amd64 "$BIN_SHA"

# A later layer that replaces var/lib with a symlink is refused like a symlinked usr/local/bin.
d="$WORKDIR/src/stlink"; rm -rf "$d"; mkdir -p "$d/var"; ln -s /opt/evil "$d/var/lib"
STLINK="$(layer_tar "$d" stlink gzip)"
assemble "$WORKDIR/state-symlink.tar" 10001:10001 amd64 "$ID" "$BASE" "$STLINK" "$GOOD_TOP"
check fail "ancestor /var/lib is not a directory" "var/lib replaced by a symlink in a later layer" "$WORKDIR/state-symlink.tar" linux/amd64 "$BIN_SHA"
# A layer that recreates the state directory with an opaque marker inside it still has the directory.
d="$WORKDIR/src/stopq"; rm -rf "$d"; mkdir -p "$d/var/lib/relay"; chmod 0700 "$d/var/lib/relay"; : >"$d/var/lib/relay/.wh..wh..opq"
tar --owner=10001 --group=10001 --numeric-owner --sort=name -cf "$L/stopq.tar" -C "$d" var
gzip -n -c "$L/stopq.tar" >"$L/stopq.blob"
assemble "$WORKDIR/state-opq.tar" 10001:10001 amd64 "$ID" "$BASE" "$L/stopq.blob" "$GOOD_TOP"
check ok "" "opaque marker inside the state directory does not remove the directory" "$WORKDIR/state-opq.tar" linux/amd64 "$BIN_SHA"

# 9. Arguments are validated.
check fail "not 64 lowercase hex" "malformed expected sha" "$WORKDIR/good.tar" linux/amd64 "XYZ"
check fail "unsupported platform" "unsupported platform" "$WORKDIR/good.tar" linux/riscv64 "$BIN_SHA"

# Release workflow guard. scripts/release-workflow-guard.sh reads release.yml as text, so each
# case below mutates ONE addressed line of a copy of the committed workflow and asserts the
# guard refuses it with that case's reason ID. The helper fails a case that trips any other ID,
# or whose mutation changed nothing, so a case cannot pass for the wrong reason.
WF_GUARD="$REPO_ROOT/scripts/release-workflow-guard.sh"
WF_SRC="$REPO_ROOT/.github/workflows/release.yml"
# Keeps `inb` at 1 while awk is inside <job>'s block, by the guard's own block rule: from the
# job's header to the next job header or column-0 code line. <job> "-" matches no block.
WF_PRELUDE='/^jobs:[[:space:]]*$/ { injobs = 1 }
injobs && (/^  [A-Za-z0-9_-]+:[[:space:]]*$/ || /^[^[:space:]#]/) { inb = (job != "-" && $0 ~ ("^  " job ":[[:space:]]*$")) }
'

# wf_mut <case> <job|-> <awk-program>: write $WORKDIR/wf-<case>.yml, the committed workflow
# with the program applied; every line it does not drop or replace is printed unchanged. The
# program is kept beside it, so a case whose mutation matched nothing can name what it looked for.
wf_mut() {
  printf '%s' "$3" >"$WORKDIR/wf-$1.prog"
  awk -v job="$2" "$WF_PRELUDE""$3"' { print }' "$WF_SRC" >"$WORKDIR/wf-$1.yml"
}

wf_count() { grep -cF -- "$2" "$1"; }

# check_wf <ok|fail> <id> <name> <file> [<guard-arg>]: run the guard on <file> (or on <guard-arg>
# when given; the word "default" runs it with no argument at all).
check_wf() {
  local expect="$1" id="$2" name="$3" file="$4"
  local -a arg=("$file")
  if [ "$#" -ge 5 ]; then
    if [ "$5" = default ]; then arg=(); else arg=("$5"); fi
  fi
  n=$((n + 1))
  local out rc
  out="$(bash "$WF_GUARD" ${arg[@]+"${arg[@]}"} 2>&1)"; rc=$?
  if [ "$expect" = ok ]; then
    if [ "$rc" -eq 0 ] && grep -qF -- "ok: release-workflow-guard" <<<"$out"; then
      echo "PASS: $name"
    else
      echo "FAIL: $name: want success, got rc=$rc: $out"; fail=1
    fi
    return
  fi
  if cmp -s "$WF_SRC" "$file"; then
    echo "FAIL: $name: mutation had no effect; release.yml no longer has the line this awk program looks for, update the case: $(cat "${file%.yml}.prog")"; fail=1
    return
  fi
  if [ "$rc" -ne 0 ] && [ "$(grep -c '::error::' <<<"$out")" -eq 1 ] &&
    grep -qF -- "release-workflow-guard: $id:" <<<"$out"; then
    echo "PASS: $name (refused: $id)"
  else
    echo "FAIL: $name: want a refusal with id '$id', got rc=$rc: $out"; fail=1
  fi
}

# wf_expect_count <file> <fixed> <want> <name>: a mutation hit only its line, where the
# literal occurs on several.
wf_expect_count() {
  n=$((n + 1))
  local got; got="$(wf_count "$1" "$2")"
  if [ "$got" -eq "$3" ]; then
    echo "PASS: $4 (precision: '$2' on $got lines)"
  else
    echo "FAIL: $4: '$2' is on $got lines, want $3"; fail=1
  fi
}

# w1. The committed workflow passes. This also proves that the comment lines that mention
# packages:write, the step-level `if: always()` log-out steps and the verify-blob command trip
# nothing.
check_wf ok "" "w1 committed release.yml passes" "$WF_SRC"
check_wf ok "" "w1b default path passes" "$WF_SRC" default

# Structure and whole file.
wf_mut w2 - '/^jobs:/ { print "jobz:"; next }'
check_wf fail no-jobs-key "w2 no jobs key" "$WORKDIR/wf-w2.yml"
wf_mut w3 - '$0 == "  latest:" { print "  latest-move:"; next }'
check_wf fail missing-job "w3 latest job renamed" "$WORKDIR/wf-w3.yml"
wf_mut w4 - '$0 == "permissions: {}" { print "permissions: write-all"; next }'
check_wf fail write-all "w4 top-level write-all" "$WORKDIR/wf-w4.yml"
wf_mut w5 image 'inb && /^    permissions:[[:space:]]*$/ { print; print "      packages: write"; next }'
check_wf fail packages-write-outside-publish-jobs "w5 packages: write in image (block form)" "$WORKDIR/wf-w5.yml"
wf_mut w6 image 'inb && /^    permissions:[[:space:]]*$/ { print "    permissions: { contents: read, packages: write }"; skip = 1; next } skip { skip = 0; next }'
check_wf fail packages-write-outside-publish-jobs "w6 packages: write in image (flow form)" "$WORKDIR/wf-w6.yml"
wf_mut w7 latest 'inb && /^      packages: write[[:space:]]*$/ { next }'
check_wf fail packages-write-absent "w7 latest loses packages: write" "$WORKDIR/wf-w7.yml"

# Job conditions.
wf_mut w8 latest 'inb && /^    if:/ { print "    if: >-"; print "      always()"; next }'
check_wf fail job-if-not-single-line "w8 a folded job if hides always()" "$WORKDIR/wf-w8.yml"
wf_mut w9 latest 'inb && /^    if:/ { print "    if: always() && " substr($0, 9); next }'
check_wf fail job-if-status-function "w9 job-level always() on latest" "$WORKDIR/wf-w9.yml"
wf_mut w10 sign-push 'inb && index($0, "- name: Verify the image signature") { print; print "        continue-on-error: true"; next }'
check_wf fail continue-on-error "w10 continue-on-error on the verify step" "$WORKDIR/wf-w10.yml"

# image.
wf_mut w11 image 'inb && index($0, "bash scripts/release-image-guard.sh relay-image.oci.tar") { next }'
check_wf fail image-guard-not-run "w11 image guard step removed" "$WORKDIR/wf-w11.yml"
wf_mut w12 image 'inb && index($0, "> relay-image.digest") { next }'
check_wf fail image-digest-not-recorded "w12 digest file not written" "$WORKDIR/wf-w12.yml"

# sign-push.
wf_mut w13 sign-push 'inb && /^    needs:/ { print "    needs: [reproducible]"; next }'
check_wf fail sign-push-needs-image "w13 sign-push no longer needs image" "$WORKDIR/wf-w13.yml"
wf_mut w14 sign-push 'inb && /^      id-token:/ { next }'
check_wf fail sign-push-id-token "w14 id-token removed" "$WORKDIR/wf-w14.yml"
wf_mut w15 sign-push 'inb && /^      id-token:/ { print "      # " substr($0, 7); next }'
check_wf fail sign-push-id-token "w15 id-token commented out" "$WORKDIR/wf-w15.yml"
wf_mut w16 sign-push 'inb && index($0, "IMAGE: ghcr.io/felag-engineering/relay") { print $0 "-dev"; next }'
check_wf fail sign-push-image-name "w16 IMAGE renamed" "$WORKDIR/wf-w16.yml"
wf_expect_count "$WORKDIR/wf-w16.yml" 'IMAGE: ghcr.io/felag-engineering/relay-dev' 1 "w16 latest's IMAGE untouched"
wf_mut w17 sign-push 'inb && index($0, "oci-archive:image/relay-image.oci.tar") { print "            oci-archive:image/relay-image.oci.tar \"docker://${IMAGE}:latest\""; next }'
check_wf fail push-by-digest "w17 push by tag" "$WORKDIR/wf-w17.yml"
wf_expect_count "$WORKDIR/wf-w17.yml" '"docker://${IMAGE}@${DIGEST}"' 2 "w17 only the push line changed"
wf_mut w18 sign-push 'inb && index($0, "run: cosign sign --yes") { print "        run: cosign sign --yes --recursive \"${IMAGE}:${GITHUB_REF_NAME}\""; next }'
check_wf fail sign-by-digest "w18 sign by tag" "$WORKDIR/wf-w18.yml"
wf_expect_count "$WORKDIR/wf-w18.yml" '"${IMAGE}@${DIGEST}"' 1 "w18 only the sign line changed"
wf_mut w19 sign-push 'inb && index($0, "run: cosign sign --yes") { print "        run: cosign sign --yes --key cosign.key --recursive \"${IMAGE}@${DIGEST}\""; next }'
check_wf fail sign-not-keyless "w19 sign with a key" "$WORKDIR/wf-w19.yml"
# A flag that only starts with --key or --sk is not a signing key.
wf_mut w19b sign-push 'inb && index($0, "run: cosign sign --yes") { print "        run: cosign sign --yes --keyring-example --skip-example --recursive \"${IMAGE}@${DIGEST}\""; next }'
check_wf ok "" "w19b --keyring-example and --skip-example are not signing keys" "$WORKDIR/wf-w19b.yml"
# A quoted flag is still a flag.
wf_mut w19c sign-push 'inb && index($0, "run: cosign sign --yes") { print "        run: cosign sign --yes \"--key\" cosign.key --recursive \"${IMAGE}@${DIGEST}\""; next }'
check_wf fail sign-not-keyless "w19c sign with a double-quoted --key" "$WORKDIR/wf-w19c.yml"
wf_mut w19d sign-push 'inb && index($0, "run: cosign sign --yes") { print "        run: cosign sign --yes \047--sk\047 --recursive \"${IMAGE}@${DIGEST}\""; next }'
check_wf fail sign-not-keyless "w19d sign with a single-quoted --sk" "$WORKDIR/wf-w19d.yml"
wf_mut w20 sign-push 'inb && index($0, "cosign verify \"${IMAGE}@${DIGEST}\"") { print "          cosign verify \"${IMAGE}:${GITHUB_REF_NAME}\" \\"; next }'
check_wf fail verify-by-digest "w20 verify by tag" "$WORKDIR/wf-w20.yml"
wf_mut w21 sign-push 'inb && index($0, "cosign verify \"${IMAGE}@${DIGEST}\"") { span = 1 } span && index($0, "--certificate-identity") { span = 0; next }'
check_wf fail verify-identity "w21 the image verify loses its identity" "$WORKDIR/wf-w21.yml"
wf_expect_count "$WORKDIR/wf-w21.yml" '--certificate-identity' 1 "w21 the verify-blob identity survives"
# The issuer case is what binds the check to the image verify command and not to the job: the
# verify-blob command in the same job keeps its own issuer.
wf_mut w22 sign-push 'inb && index($0, "cosign verify \"${IMAGE}@${DIGEST}\"") { span = 1 } span && index($0, "--certificate-oidc-issuer") { span = 0; next }'
check_wf fail verify-oidc-issuer "w22 the image verify loses its issuer" "$WORKDIR/wf-w22.yml"
wf_expect_count "$WORKDIR/wf-w22.yml" '--certificate-oidc-issuer' 1 "w22 the verify-blob issuer survives"
wf_mut w23 sign-push 'inb && index($0, "skopeo copy") && index($0, "\"docker://${IMAGE}:${version}\"") { next }'
check_wf fail tag-write-missing "w23 version tag write removed" "$WORKDIR/wf-w23.yml"
wf_mut w24 sign-push 'inb && index($0, "oci-archive:image/relay-image.oci.tar") { print "          cosign sign --yes --recursive \"${IMAGE}@${DIGEST}\"" }'
check_wf fail order-push-sign "w24 a sign before the push" "$WORKDIR/wf-w24.yml"
wf_mut w25 sign-push 'inb && index($0, "- name: Tag the verified digest") { print "          cosign sign --yes --recursive \"${IMAGE}@${DIGEST}\"" }'
check_wf fail order-sign-verify "w25 a sign after the verify" "$WORKDIR/wf-w25.yml"
# The original tag write stays after the verify, so this passes only if the order check takes
# the earliest tag reference and not the last.
wf_mut w26 sign-push 'inb && index($0, "run: cosign sign --yes") { print "          skopeo copy --all --preserve-digests \"docker://${IMAGE}@${DIGEST}\" \"docker://${IMAGE}:${version}\"" }'
check_wf fail order-verify-tag "w26 a version tag before the sign" "$WORKDIR/wf-w26.yml"

# latest.
wf_mut w27 latest 'inb && /^    needs:/ { print "    needs:"; print "      - sign-push"; print "      - image"; next }'
check_wf fail needs-not-flow-form "w27 latest needs as a block list" "$WORKDIR/wf-w27.yml"
wf_mut w28 latest 'inb && /^    needs:/ { print "    needs: [image]"; next }'
check_wf fail latest-needs-sign-push "w28 latest no longer needs sign-push" "$WORKDIR/wf-w28.yml"

# || would let a failed signature pass. The second case ends the verify span with it.
wf_mut w29 sign-push 'inb && index($0, "run: cosign sign --yes") { print $0 " || true"; next }'
check_wf fail failure-masked "w29 || true on the sign command" "$WORKDIR/wf-w29.yml"
wf_mut w30 sign-push 'inb && index($0, "cosign verify \"${IMAGE}@${DIGEST}\"") { span = 1 } span && index($0, "--certificate-oidc-issuer") { print $0 " || true"; span = 0; next }'
check_wf fail failure-masked "w30 || true on the last line of the verify span" "$WORKDIR/wf-w30.yml"

# A step-level if: in a step up to the last tag write could tag after a failed or skipped sign or
# verify. The log-out step after it keeps its `if: always()` (w1).
wf_mut w31 sign-push 'inb && index($0, "- name: Tag the verified digest") { print; print "        if: always()"; next }'
check_wf fail sign-push-step-condition "w31 if: always() at the top of the tag step" "$WORKDIR/wf-w31.yml"
wf_mut w32 sign-push 'inb && index($0, "# The credential must not outlive") { print "        if: always()" }'
check_wf fail sign-push-step-condition "w32 if: always() after the tag step's run block" "$WORKDIR/wf-w32.yml"
wf_mut w33 sign-push 'inb && index($0, "- name: Sign the image (keyless)") { print; print "        if: false"; next }'
check_wf fail sign-push-step-condition "w33 if: false on the sign step" "$WORKDIR/wf-w33.yml"
wf_mut w34 image 'inb && index($0, "- name: Guard - image binary, user, entrypoint and version") { print; print "        if: false"; next }'
check_wf fail image-step-condition "w34 if: false on the image guard step" "$WORKDIR/wf-w34.yml"

# What a tag or :latest points at. Each mutation keeps the line's shape but changes its source.
wf_mut w35 sign-push 'inb && index($0, "skopeo copy --all --preserve-digests \"docker://${IMAGE}@${DIGEST}\"") { print "          skopeo copy --all oci-archive:other.oci.tar \"docker://${IMAGE}:${version}\""; next }'
check_wf fail tag-source-not-pushed-digest "w35 the version tag is copied from another archive" "$WORKDIR/wf-w35.yml"
wf_mut w36 latest 'inb && index($0, "\"docker://${IMAGE}:latest\"") { print "          skopeo copy --all oci-archive:other.tar \"docker://${IMAGE}:latest\""; next }'
check_wf fail latest-copy-source "w36 :latest is copied from another archive" "$WORKDIR/wf-w36.yml"
wf_mut w37 latest 'inb && index($0, "digest=\"$(cat image/relay-image.digest)\"") { print "          digest=\"sha256:0000000000000000000000000000000000000000000000000000000000000000\""; next }'
check_wf fail latest-digest-source "w37 :latest takes a digest that is not the recorded one" "$WORKDIR/wf-w37.yml"
wf_mut w38 sign-push 'inb && index($0, "- name: Verify the image signature") { v = 1 } v && index($0, "DIGEST:") { print "          DIGEST: sha256:0000000000000000000000000000000000000000000000000000000000000000"; v = 0; next }'
check_wf fail digest-env-not-pushed "w38 the verify step names another digest" "$WORKDIR/wf-w38.yml"

# Any other line that names the image or the registry is refused, whatever tool writes it.
wf_mut w39 sign-push 'inb && index($0, "oci-archive:image/relay-image.oci.tar") { print; print "          skopeo copy --all docker://${IMAGE}@${DIGEST} docker://${IMAGE}:${version}"; next }'
check_wf fail registry-ref-not-allowlisted "w39 an unquoted version tag before the sign" "$WORKDIR/wf-w39.yml"
wf_mut w40 sign-push 'inb && index($0, "oci-archive:image/relay-image.oci.tar") { print; print "          crane tag \"${IMAGE}@${DIGEST}\" 1.2.3"; next }'
check_wf fail registry-ref-not-allowlisted "w40 a crane tag in sign-push" "$WORKDIR/wf-w40.yml"
wf_mut w41 latest 'inb && index($0, "\"docker://${IMAGE}:latest\"") { print; print "          crane tag \"${IMAGE}@${digest}\" edge"; next }'
check_wf fail registry-ref-not-allowlisted "w41 a crane tag in latest" "$WORKDIR/wf-w41.yml"
wf_mut w42 latest 'inb && index($0, "IMAGE: ghcr.io/felag-engineering/relay") { print $0 "-dev"; next }'
check_wf fail registry-ref-not-allowlisted "w42 latest's IMAGE renamed" "$WORKDIR/wf-w42.yml"

# A job header that is not the bare form would hand its lines to the job above it.
wf_mut w43 - '$0 == "  github-release:" { print "  github-release: # x"; next }'
check_wf fail job-header-malformed "w43 a job header with a trailing comment" "$WORKDIR/wf-w43.yml"
wf_mut w44 - '$0 == "  github-release:" { print "  \"github-release\":"; next }'
check_wf fail job-header-malformed "w44 a quoted job header" "$WORKDIR/wf-w44.yml"

# Without the empty top-level permissions every job inherits the repository default.
wf_mut w45 - '$0 == "permissions: {}" { next }'
check_wf fail top-level-permissions "w45 the top-level permissions removed" "$WORKDIR/wf-w45.yml"

# Keys the guard reads in their plain form.
wf_mut w46 image 'inb && /^    permissions:[[:space:]]*$/ { print; print "      \"packages\": write"; next }'
check_wf fail yaml-key-form "w46 a quoted packages key" "$WORKDIR/wf-w46.yml"
wf_mut w47 latest 'inb && /^    if:/ { print "    \"if\": " substr($0, 9); next }'
check_wf fail yaml-key-form "w47 a quoted job-level if key" "$WORKDIR/wf-w47.yml"
wf_mut w48 latest 'inb && /^    if:/ { print "    if : " substr($0, 9); next }'
check_wf fail yaml-key-form "w48 a job-level if key with a space before the colon" "$WORKDIR/wf-w48.yml"
wf_mut w49 image 'inb && /^    permissions:[[:space:]]*$/ { print; print "      <<: *x"; next }'
check_wf fail yaml-key-form "w49 a merge key" "$WORKDIR/wf-w49.yml"

# The verify must stay strict.
wf_mut w50 sign-push 'inb && index($0, "cosign verify \"${IMAGE}@${DIGEST}\"") { span = 1 } span && index($0, "--certificate-oidc-issuer") { print $0 " --insecure-ignore-tlog"; span = 0; next }'
check_wf fail verify-weakened "w50 the verify ignores the transparency log" "$WORKDIR/wf-w50.yml"
wf_mut w51 sign-push 'inb && index($0, "cosign verify \"${IMAGE}@${DIGEST}\"") { span = 1 } span && index($0, "--certificate-oidc-issuer") { print $0 " --certificate-identity-regexp \".*\""; span = 0; next }'
check_wf fail verify-weakened "w51 the verify accepts an identity by regexp" "$WORKDIR/wf-w51.yml"

if [ "$fail" -eq 0 ]; then
  echo "PASS: scripts/release-image-guard.sh accepts a well-formed archive and refuses a wrong binary digest, a root or unset User, a RELAY_* name in Env (never echoing its value), a state directory that is not 10001/10001 0700 once every layer is applied, a tampered blob, a symlink or hardlink or wrong-mode binary, a malformed digest, a binary only in a lower layer (with or without an opaque whiteout), a named whiteout, a platform set other than amd64+arm64, non-canonical spellings of the binary's path, a symlinked ancestor directory and bad arguments (#892), and scripts/release-workflow-guard.sh, a regression guard over the committed shapes of the image, sign-push and latest jobs, accepts the committed release.yml and refuses each departure it names: an image pushed by tag, signed with a key or by tag, left unverified or verified weakly, a version tag or :latest written from anything but the verified digest or before the verify, a registry line that is not a committed one, a job published after a failure, a step condition or a ||-fallback, a job header, permissions or key written in a form it cannot read ($n cases)."
  exit 0
fi
echo "FAIL: scripts/release-image-guard.sh self-test" >&2
exit 1
