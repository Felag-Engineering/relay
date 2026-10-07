#!/usr/bin/env bash
# Proves scripts/release-image-guard.sh refuses what its header says it refuses, against tiny
# OCI archives built here from tar, jq and sha256sum (#892). Hermetic: bash and coreutils, no
# Docker, no network, no writes outside its own `mktemp -d`. The guard's --version step needs
# Docker and is exercised by the release workflow's dry run instead.
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

mk_base() { # a lower layer holding only /etc/os-release
  local d="$WORKDIR/src/base"; rm -rf "$d"; mkdir -p "$d/etc"; echo alpine >"$d/etc/os-release"
  layer_tar "$d" base
}
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
    '{architecture:$a, os:"linux", config:{User:$u, Entrypoint:["/usr/local/bin/relay"]}, rootfs:{type:"layers",diff_ids:$ids}}' >"$cfg"
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

# 9. Arguments are validated.
check fail "not 64 lowercase hex" "malformed expected sha" "$WORKDIR/good.tar" linux/amd64 "XYZ"
check fail "unsupported platform" "unsupported platform" "$WORKDIR/good.tar" linux/riscv64 "$BIN_SHA"

if [ "$fail" -eq 0 ]; then
  echo "PASS: scripts/release-image-guard.sh accepts a well-formed archive and refuses a wrong binary digest, a root or unset User, a tampered blob, a symlink or hardlink or wrong-mode binary, a malformed digest, a binary only in a lower layer (with or without an opaque whiteout), a named whiteout, a platform set other than amd64+arm64, non-canonical spellings of the binary's path, a symlinked ancestor directory and bad arguments ($n cases) (#892)."
  exit 0
fi
echo "FAIL: scripts/release-image-guard.sh self-test" >&2
exit 1
