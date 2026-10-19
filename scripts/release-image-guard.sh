#!/usr/bin/env bash
# Guards the release image by inspecting THE BYTES OF THE OCI ARCHIVE that release.yml will
# push — never a separately built or loaded image — for one platform (#892).
#
#   release-image-guard.sh <oci-archive> <linux/amd64|linux/arm64> <binary-sha256> [<version>]
#
# <binary-sha256> is the released binary's line in SHA256SUMS. Asserts, for that platform's
# manifest in the archive:
#   - every blob it touches hashes to the digest that names it (nothing is trusted by filename);
#   - the config says User 10001:10001, no RELAY_* in Env, and Entrypoint
#     ["/usr/local/bin/relay"], for the right os/architecture;
#   - var/lib/relay, the state directory, is a directory owned 10001/10001 with mode 0700 once
#     every layer is applied, so a fresh volume mounted there inherits both;
#   - usr/local/bin/relay is a single regular file, 0755 root:root, in the TOPMOST layer, with no
#     whiteout or opaque marker in that layer covering it, and its sha256 is <binary-sha256>;
#   - with <version> (the stamp without its leading v), the image loaded from the archive itself
#     reports that version. Needs docker and skopeo; the archive's own image is proven by id.
#
# The archive is attacker-shaped input as far as this script is concerned, so: the outer tar is
# unpacked with GNU tar defaults (no -P: absolute names and `..` are refused) into a mktemp -d;
# every digest is validated against ^sha256:[0-9a-f]{64}$ before it is used to build a path;
# a blob must be a regular file; and layers are NEVER extracted to disk — they are listed with
# `tar -tv` and the one member we need is streamed out with `tar -xO`.
#
# Exits non-zero, with an ::error:: line, on the first failed assertion.
set -euo pipefail

die() { echo "::error::release-image-guard: $*" >&2; exit 1; }

[ "$#" -eq 3 ] || [ "$#" -eq 4 ] || die "usage: $0 <oci-archive> <linux/amd64|linux/arm64> <binary-sha256> [<version>]"
archive="$1"; platform="$2"; want_sha="$3"; want_version="${4:-}"

[ -f "$archive" ] || die "no such archive: $archive"
case "$platform" in
  linux/amd64 | linux/arm64) ;;
  *) die "unsupported platform '$platform'" ;;
esac
[[ "$want_sha" =~ ^[0-9a-f]{64}$ ]] || die "binary sha256 '$want_sha' is not 64 lowercase hex digits"
os="${platform%/*}"; arch="${platform#*/}"

work="$(mktemp -d)" || die "mktemp -d failed"
case "$work" in /*) ;; *) die "mktemp returned a non-absolute path" ;; esac
loaded=""
cleanup() {
  [ -z "$loaded" ] || docker rmi "$loaded" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

tar -xf "$archive" -C "$work" || die "cannot unpack $archive"
[ -f "$work/index.json" ] && [ ! -L "$work/index.json" ] || die "archive has no regular index.json"

digest_re='^sha256:[0-9a-f]{64}$'

# blob <digest>: print the path of a verified blob. The digest is validated BEFORE it is used
# to build a path, and the content is re-hashed: the name is a claim, not a fact.
blob() {
  local d="$1" hex path got
  [[ "$d" =~ $digest_re ]] || die "malformed digest '$d'"
  hex="${d#sha256:}"
  path="$work/blobs/sha256/$hex"
  [ -f "$path" ] && [ ! -L "$path" ] || die "blob $d is missing or not a regular file"
  got="$(sha256sum "$path" | awk '{print $1}')"
  [ "$got" = "$hex" ] || die "blob $d is tampered: content hashes to sha256:$got"
  printf '%s\n' "$path"
}

index_type='application/vnd.oci.image.index.v1+json'
list_type='application/vnd.docker.distribution.manifest.list.v2+json'

# Descriptors of index.json's entries, expanding image indexes one level (what buildx emits).
descriptors="$(jq -c '.manifests[]' "$work/index.json")" || die "index.json is not a manifest list"
candidates=""
while IFS= read -r desc; do
  [ -n "$desc" ] || continue
  mt="$(jq -r '.mediaType // ""' <<<"$desc")"
  dg="$(jq -r '.digest // ""' <<<"$desc")"
  if [ "$mt" = "$index_type" ] || [ "$mt" = "$list_type" ]; then
    candidates+="$(jq -c '.manifests[]' "$(blob "$dg")")"$'\n'
  else
    candidates+="$desc"$'\n'
  fi
done <<<"$descriptors"

# The release image is exactly these two platforms: an extra or missing entry is not what the
# release job built, whatever else checks out.
platforms="$(jq -r '.platform.os + "/" + .platform.architecture' <<<"$candidates" | sort | paste -sd, -)"
[ "$platforms" = "linux/amd64,linux/arm64" ] \
  || die "the archive's platforms are '$platforms', want exactly linux/amd64,linux/arm64"

matches="$(jq -c --arg os "$os" --arg arch "$arch" \
  'select(.platform.os == $os and .platform.architecture == $arch)' <<<"$candidates")"
[ -n "$matches" ] || die "no manifest for $platform in the archive"
[ "$(wc -l <<<"$matches")" -eq 1 ] || die "more than one manifest for $platform in the archive"
manifest_digest="$(jq -r '.digest' <<<"$matches")"
manifest="$(blob "$manifest_digest")"

config_digest="$(jq -er '.config.digest' "$manifest")" || die "manifest has no config"
config="$(blob "$config_digest")"

# ---- config --------------------------------------------------------------------
[ "$(jq -r '.config.User // ""' "$config")" = "10001:10001" ] \
  || die "config User is '$(jq -r '.config.User // ""' "$config")', want 10001:10001"
relay_env="$(jq -r '[.config.Env[]? | split("=")[0] | select(startswith("RELAY_"))] | join(", ")' "$config")" \
  || die "config Env is malformed"
[ -z "$relay_env" ] || die "config Env sets $relay_env: the image carries no configuration (RC-27, ADR-0043)"
[ "$(jq -c '.config.Entrypoint // null' "$config")" = '["/usr/local/bin/relay"]' ] \
  || die "config Entrypoint is $(jq -c '.config.Entrypoint // null' "$config"), want [\"/usr/local/bin/relay\"]"
[ "$(jq -r '.os + "/" + .architecture' "$config")" = "$platform" ] \
  || die "config says $(jq -r '.os + "/" + .architecture' "$config"), want $platform"

# ---- the binary, in the topmost layer ------------------------------------------
bin_path="usr/local/bin/relay"
layer_count="$(jq -er '.layers | length' "$manifest")" || die "manifest has no layers"
[ "$layer_count" -ge 1 ] || die "manifest has no layers"

# A layer's decompressor comes from its mediaType, never from sniffing its bytes.
decompressor() { # <mediaType>: sets the array `decompress`
  case "$1" in
    *+gzip | *.gzip) decompress=(gzip -dc) ;;
    *+zstd) decompress=(zstd -dc) ;;
    application/vnd.oci.image.layer.v1.tar | application/vnd.docker.image.rootfs.diff.tar)
      decompress=(cat) ;;
    *) die "layer has unsupported mediaType '$1'" ;;
  esac
}

member_re='^(.)([rwxsStT-]{9}) ([0-9]+)/([0-9]+) +[0-9]+ [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2} (.*)$'
ancestors=("usr" "usr/local" "usr/local/bin" "var" "var/lib")
state_path="var/lib/relay"
state_entry=""   # "<kind> <perms> <uid>/<gid>" of the state directory as the layers leave it

# scan_layer <blob> <top|lower>: list the layer (never extracting it) and enforce the path
# rules. Names are canonicalised before they are compared with anything: a member that spells
# the binary or one of its ancestors in a non-canonical way (usr/local/bin/./relay,
# usr/local//bin/relay, a leading ./) is refused outright, because the runtime resolves it to
# the binary while a literal comparison would not. Sets `found` and `stored_name` (top only).
scan_layer() {
  local blobpath="$1" which="$2" listing line kind perms uid gid name base dir hidden anc canon c
  local -a parts
  listing="$("${decompress[@]}" <"$blobpath" | tar --numeric-owner -tvf -)" \
    || die "cannot list a layer"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    [[ "$line" =~ $member_re ]] || die "unparseable layer listing line: $line"
    kind="${BASH_REMATCH[1]}"; perms="${BASH_REMATCH[2]}"
    uid="${BASH_REMATCH[3]}"; gid="${BASH_REMATCH[4]}"; name="${BASH_REMATCH[5]}"
    # Symlinks and hardlinks print "name -> target" / "name link to target"; keep the name.
    name="${name%% -> *}"; name="${name%% link to *}"

    # Canonical form: no empty, "." or ".." component. ".." anywhere is refused.
    canon=""
    IFS=/ read -r -a parts <<<"$name"
    for c in "${parts[@]}"; do
      case "$c" in
        "" | ".") ;;
        "..") die "member name '$name' contains '..'" ;;
        *) canon="${canon:+$canon/}$c" ;;
      esac
    done
    base="${canon##*/}"

    case "$base" in
      .wh.*)
        # Whiteout (.wh.<x>) or opaque marker (.wh..wh..opq): in the directory ${canon%/*} it
        # hides <x> / everything below, so refuse any that sits on the binary's path.
        dir=""; [ "$canon" = "$base" ] || dir="${canon%/*}"
        hidden="${dir:+$dir/}${base#.wh.}"
        if [ "$base" = ".wh..wh..opq" ]; then
          case "$bin_path/" in "${dir:+$dir/}"*) die "opaque whiteout in '${dir:-/}' covers /$bin_path" ;; esac
          # The marker hides what is below $dir, not $dir itself, so only a strict ancestor clears.
          [ "$dir" = "$state_path" ] || case "$state_path/" in "${dir:+$dir/}"*) state_entry="" ;; esac
        elif [ "$hidden" = "$bin_path" ] || [[ "$bin_path" == "$hidden/"* ]]; then
          die "whiteout '$canon' covers /$bin_path"
        elif [ "$hidden" = "$state_path" ] || [[ "$state_path" == "$hidden/"* ]]; then
          state_entry=""
        fi
        continue ;;
    esac

    # An ancestor of the binary must be a real directory, in any layer: a symlink there
    # redirects where the binary lands. Any spelling that canonicalises to it counts.
    for anc in "${ancestors[@]}"; do
      [ "$canon" = "$anc" ] || continue
      [ "$kind" = "d" ] || die "ancestor /$anc is not a directory (tar type '$kind')"
    done

    # The latest layer to mention the state directory decides, as it does at run time.
    [ "$canon" != "$state_path" ] || state_entry="$kind $perms $uid/$gid"

    [ "$canon" = "$bin_path" ] || continue
    [ "$which" = top ] || continue   # a lower copy is shadowed or whited out; the top layer decides
    [ "$name" = "$bin_path" ] || die "non-canonical member name '$name' for /$bin_path"
    found=$((found + 1))
    stored_name="$name"
    [ "$kind" = "-" ] || die "/$bin_path is not a regular file (tar type '$kind'); symlinks and hardlinks are refused"
    [ "$perms" = "rwxr-xr-x" ] || die "/$bin_path mode is $perms, want rwxr-xr-x (0755)"
    [ "$uid/$gid" = "0/0" ] || die "/$bin_path owner is $uid/$gid, want 0/0"
  done <<<"$listing"
}

found=0
stored_name=""
top_blob=""
for ((i = 0; i < layer_count; i++)); do
  desc="$(jq -c ".layers[$i]" "$manifest")"
  lblob="$(blob "$(jq -r '.digest' <<<"$desc")")"
  decompressor "$(jq -r '.mediaType // ""' <<<"$desc")"
  if [ "$i" -eq $((layer_count - 1)) ]; then
    top_blob="$lblob"; top_decompress=("${decompress[@]}")
    scan_layer "$lblob" top
  else
    # Lower layers are scanned for a symlinked or non-canonical ancestor only.
    scan_layer "$lblob" lower
  fi
done

[ "$state_entry" = "d rwx------ 10001/10001" ] \
  || die "/$state_path is '${state_entry:-absent}' after every layer, want a directory 'd rwx------ 10001/10001'"
[ "$found" -ne 0 ] || die "/$bin_path is not in the topmost layer (a binary only in a lower layer is not what the image runs)"
[ "$found" -eq 1 ] || die "/$bin_path appears $found times in the topmost layer"

got_sha="$("${top_decompress[@]}" <"$top_blob" | tar -xOf - "$stored_name" | sha256sum | awk '{print $1}')"
[ "$got_sha" = "$want_sha" ] \
  || die "/$bin_path in the $platform image hashes to $got_sha; SHA256SUMS says $want_sha"
echo "ok: $platform: config, topmost-layer /$bin_path (sha256 $got_sha), manifest $manifest_digest"

# ---- --version, on the archive's own image --------------------------------------
[ -n "$want_version" ] || exit 0
command -v docker >/dev/null || die "docker is required to run --version"
command -v skopeo >/dev/null || die "skopeo is required to load the archive"
# Through a docker-archive file, not skopeo's docker-daemon: transport: skopeo 1.13 speaks
# Docker API 1.22, which Docker 25+ refuses. Writing the file needs no daemon.
tag="relay-guard:$arch"
skopeo copy --override-os "$os" --override-arch "$arch" "oci-archive:$archive" "docker-archive:$work/loaded.tar:$tag" \
  || die "skopeo could not extract $platform from the archive"
docker load -i "$work/loaded.tar" >/dev/null || die "docker could not load the extracted image"
loaded="$tag"
id="$(docker image inspect --format '{{.Id}}' "$tag")"
# Identity with the archive's image: the classic store reports the config digest, the
# containerd store a manifest digest it synthesised from the docker-archive. Where the id is
# not the config digest, the loaded layer chain must equal the archive config's, which is the
# content the binary check above was made on.
if [ "$id" != "$config_digest" ]; then
  want_layers="$(jq -c '.rootfs.diff_ids' "$config")"
  got_layers="$(docker image inspect --format '{{json .RootFS.Layers}}' "$tag")"
  [ "$want_layers" = "$got_layers" ] \
    || die "loaded image id $id is not the archive's config $config_digest and its layers differ"
fi
out="$(docker run --rm --platform "$platform" "$tag" --version)" || die "$tag --version failed"
got_version="$(awk '{print $2}' <<<"$out")"
[ "$got_version" = "$want_version" ] || die "image reports version '$got_version' ($out), want '$want_version'"
echo "ok: $platform: loaded from the archive (id $id), --version = $got_version"
