#!/usr/bin/env bash
# Release gate for the shipped read catalog's ledger (ADR-0021, amendment 2026-10-15). The ledger
# binds each released catalog Template name to its body digest and risk class. A released entry
# never changes, a withdrawn name never comes back, and every catalog name has an active entry.
# The body digest itself is checked against the catalog by the daemon test
# catalog_names_match_ledger; this script checks what a test inside one commit cannot: that the
# ledger only grew since every release.
#
# usage: catalog-ledger.sh compare BASE HEAD [LABEL]
#          append-only rule between two ledger files; BASE may be /dev/null (empty baseline).
#        catalog-ledger.sh names TEMPLATES_DIR LEDGER
#          every Template name in the catalog has an active ledger entry. Fails closed on any
#          catalog layout it does not understand, and on any other .toml under TEMPLATES_DIR.
#        catalog-ledger.sh check [LEDGER] [TEMPLATES_DIR]
#          the gate: compare against the ledger at every visible v* tag, then names. Paths are
#          relative to the repository top level and default to the shipped locations.
# Exit codes: 0 ok, 1 refused, 2 malformed input or a layout not understood, 3 no release tag
# visible. Findings are printed as "::error::catalog-ledger: ...".
set -euo pipefail

DEFAULT_LEDGER=daemon/packaging/relay-read-catalog.ledger
DEFAULT_TEMPLATES=daemon/packaging/templates.d
# Tags version-sorted at or before this one predate the ledger and get an empty baseline. A later
# tag whose tree lacks the ledger is refused, so moving the ledger cannot unfreeze every entry.
# Deliberately not overridable from the environment: an override would be a bypass.
LAST_LEDGERLESS_TAG=v0.0.9

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

err() { echo "::error::catalog-ledger: $*" >&2; }

# parse_ledger FILE: prints "NAME CLASS DIGEST STATUS" per entry. Returns 2 on a malformed
# file: a CR, a line off the grammar, or a duplicate name.
parse_ledger() {
  local file=$1
  if [ ! -r "$file" ]; then err "cannot read $file"; return 2; fi
  if grep -q $'\r' "$file"; then err "$file contains a carriage return; LF line endings only"; return 2; fi
  awk -v file="$file" '
    /^#/ || $0 == "" { next }
    $0 !~ /^[a-z][a-z0-9_.]* (read|mutate) [0-9a-f]+ (active|withdrawn)$/ || length($3) != 64 {
      printf "::error::catalog-ledger: %s line %d is not NAME CLASS DIGEST STATUS\n", file, NR > "/dev/stderr"
      bad = 1; next
    }
    seen[$1]++ {
      printf "::error::catalog-ledger: %s line %d repeats name %s\n", file, NR, $1 > "/dev/stderr"
      bad = 1; next
    }
    { print }
    END { exit bad ? 2 : 0 }
  ' "$file"
}

# cmd_compare BASE HEAD [LABEL]
cmd_compare() {
  local base=$1 head=$2 label=${3:-$1}
  parse_ledger "$base" >"$TMP/base.n" || return 2
  parse_ledger "$head" >"$TMP/head.n" || return 2
  local -a B H
  mapfile -t B <"$TMP/base.n"
  mapfile -t H <"$TMP/head.n"
  local nb=${#B[@]} nh=${#H[@]} bad=0 i
  local bn bc bd bs hn hc hd hs
  local -A base_status=()

  if [ "$nh" -lt "$nb" ]; then
    err "against $label: the ledger has $nh entries, $label has $nb; an entry was dropped"
    bad=1
  fi
  for ((i = 0; i < nb; i++)); do
    read -r bn bc bd bs <<<"${B[i]}"
    base_status[$bn]=$bs
    if [ "$i" -ge "$nh" ]; then continue; fi
    read -r hn hc hd hs <<<"${H[i]}"
    if [ "$bn" != "$hn" ]; then
      err "against $label: entry $((i + 1)) is $hn, was $bn; entries are never reordered or replaced"
      bad=1
    elif [ "$bc" != "$hc" ]; then
      err "against $label: risk class of $bn changed from $bc to $hc"
      bad=1
    elif [ "$bd" != "$hd" ]; then
      err "against $label: body digest of $bn changed"
      bad=1
    elif [ "$bs" != "$hs" ]; then
      if [ "$bs" = withdrawn ]; then
        err "against $label: re-adding withdrawn name $bn"
        bad=1
      fi
    fi
  done
  for ((i = nb; i < nh; i++)); do
    read -r hn hc hd hs <<<"${H[i]}"
    # Unreachable while both files parse (a repeated name is refused there); kept as a backstop.
    if [ -n "${base_status[$hn]:-}" ]; then
      if [ "${base_status[$hn]}" = withdrawn ]; then
        err "against $label: re-adding withdrawn name $hn"
      else
        err "against $label: $hn is already in $label"
      fi
      bad=1
    fi
  done
  if [ "$bad" -ne 0 ]; then return 1; fi

  local withdrawn
  withdrawn=$(grep -c ' withdrawn$' "$TMP/head.n" || true)
  echo "catalog-ledger: ok against $label ($nb entries bound, $((nh - nb)) appended, $withdrawn withdrawn)"
}

# catalog_names FILE: prints each [[template]] name, one per line. Returns 2 on any layout
# outside the allow-list: the shipped catalog's own, which is column-0 headers and key lines with
# single-line basic-string or array values.
catalog_names() {
  local file=$1
  if grep -q $'\r' "$file"; then err "$file contains a carriage return"; return 2; fi
  awk -v file="$file" '
    function fail(msg) {
      printf "::error::catalog-ledger: %s line %d: %s\n", file, NR, msg > "/dev/stderr"
      rc = 2; exit rc
    }
    function close_template() {
      if (intable != "" && nname != 1) fail("a [[template]] table needs exactly one name key")
    }
    $0 == "" || /^#/ { next }
    /^\[\[template\]\]( +#.*)?$/ {
      close_template(); tables++; nname = 0; intable = "template"; next
    }
    /^\[\[template\.slots\]\]( +#.*)?$/ {
      if (intable == "") fail("[[template.slots]] before any [[template]]")
      intable = "slots"; next
    }
    match($0, /^[a-z_]+ = /) {
      if (intable == "") fail("a key before the first [[template]] header")
      key = substr($0, 1, RLENGTH - 3)
      val = substr($0, RLENGTH + 1)
      if (val ~ /^"/ && val !~ /^"""/ && length(val) >= 2 && val ~ /"$/) {
        # single-line basic string
      } else if (val ~ /^\[/ && val ~ /\]$/) {
        # single-line array
      } else {
        fail("value of " key " is not a single-line basic string or array")
      }
      if (intable == "template" && key == "name") {
        nname++
        content = substr(val, 2, length(val) - 2)
        if (val !~ /^"/ || content !~ /^[a-z][a-z0-9_.]*$/) fail("template name is not a plain name")
        print content
      }
      next
    }
    { fail("line outside the layout this check reads") }
    END {
      if (rc) exit rc
      close_template()
      if (rc) exit rc
      if (tables == 0) { printf "::error::catalog-ledger: %s holds no [[template]] table\n", file > "/dev/stderr"; exit 2 }
    }
  ' "$file"
}

# cmd_names TEMPLATES_DIR LEDGER
cmd_names() {
  local dir=${1%/} ledger=$2 path
  local catalog="$dir/relay-read/catalog.toml"
  local -a extra=()
  if [ ! -d "$dir" ]; then err "$dir is not a directory"; return 2; fi
  while IFS= read -r path; do
    [ "$path" = "$catalog" ] || extra+=("$path")
  done < <(find "$dir" ! -type d -name '*.toml' | sort)
  if [ "${#extra[@]}" -gt 0 ]; then
    err "templates.d holds a pack file this check does not read: ${extra[0]}"
    return 2
  fi
  if [ ! -f "$catalog" ] || [ -L "$catalog" ]; then err "$catalog is missing or not a regular file"; return 2; fi

  parse_ledger "$ledger" >"$TMP/names.ledger" || return 2
  catalog_names "$catalog" >"$TMP/names.catalog" || return 2

  local name bad=0
  while IFS= read -r name; do
    # Exact field compare: a name holds "." and must not be read as a regex.
    if ! awk -v n="$name" '$1 == n && $4 == "active" { found = 1 } END { exit !found }' "$TMP/names.ledger"; then
      err "catalog Template $name has no active ledger entry in $ledger"
      bad=1
    fi
  done <"$TMP/names.catalog"
  if [ "$bad" -ne 0 ]; then return 1; fi
  echo "catalog-ledger: every catalog Template name has an active ledger entry ($(wc -l <"$TMP/names.catalog") names)"
}

# predates_ledger TAG: true when TAG sorts, as a version, at or before LAST_LEDGERLESS_TAG.
predates_ledger() {
  [ "$(printf '%s\n%s\n' "$1" "$LAST_LEDGERLESS_TAG" | sort -V | head -n1)" = "$1" ]
}

# cmd_check [LEDGER] [TEMPLATES_DIR]
cmd_check() {
  local top ledger tags_raw tag listing worst=0 r n=0
  top=$(git rev-parse --show-toplevel) || return 2
  cd "$top"
  ledger=${1:-$DEFAULT_LEDGER}
  local dir=${2:-$DEFAULT_TEMPLATES}
  local -a tags=() compared=()

  tags_raw=$(git for-each-ref --sort=version:refname --format='%(refname)' 'refs/tags/v*')
  while IFS= read -r tag; do
    tag=${tag#refs/tags/}
    [[ $tag =~ ^v[0-9] ]] && tags+=("$tag")
  done <<<"$tags_raw"
  if [ "${#tags[@]}" -eq 0 ]; then
    err "no release tag visible; fetch tags"
    return 3
  fi

  # Every tag is a baseline, not only the newest: a tag from a failed release must not launder
  # a changed entry past an older release that froze it. A tag on HEAD compares HEAD with itself.
  for tag in "${tags[@]}"; do
    n=$((n + 1))
    compared+=("$tag")
    if ! git rev-parse -q --verify "refs/tags/$tag^{tree}" >/dev/null; then
      err "cannot read the tree of $tag"
      return 2
    fi
    listing=$(git ls-tree --name-only "refs/tags/$tag" -- "$ledger") || { err "cannot list the tree of $tag"; return 2; }
    if [ -n "$listing" ]; then
      git show "refs/tags/$tag:$ledger" >"$TMP/tag.ledger" || { err "cannot read $ledger at $tag"; return 2; }
    elif predates_ledger "$tag"; then
      echo "::notice::catalog-ledger: $tag predates the ledger; using an empty baseline"
      : >"$TMP/tag.ledger"
    else
      err "$tag has no ledger at $ledger, and only tags up to $LAST_LEDGERLESS_TAG predate it"
      [ "$worst" -lt 1 ] && worst=1
      continue
    fi
    r=0
    cmd_compare "$TMP/tag.ledger" "$ledger" "$tag" || r=$?
    [ "$r" -gt "$worst" ] && worst=$r
  done

  r=0
  cmd_names "$dir" "$ledger" || r=$?
  [ "$r" -gt "$worst" ] && worst=$r

  echo "catalog-ledger: compared against $n tags: ${compared[*]}"
  return "$worst"
}

usage() {
  sed -n '2,/^set -e/p' "$0" | sed '$d' >&2
  exit 2
}

cmd=${1:-}
[ -n "$cmd" ] && shift
rc=0
case "$cmd" in
  compare) [ $# -ge 2 ] && [ $# -le 3 ] || usage; cmd_compare "$@" || rc=$? ;;
  names) [ $# -eq 2 ] || usage; cmd_names "$@" || rc=$? ;;
  check) [ $# -le 2 ] || usage; cmd_check "$@" || rc=$? ;;
  *) usage ;;
esac
exit "$rc"
