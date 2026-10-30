#!/usr/bin/env bash
# Writes a release version into a copy of the relay_daemon role: stamp-role.sh VERSION ROLE-DIR
# OUT-DIR leaves OUT-DIR/relay_daemon, and changes nothing in ROLE-DIR. Called by the release
# workflow and by the install matrix's ansible-role script, so both run the same stamping (DI-45).
set -euo pipefail

for tool in cp awk grep; do
  command -v "$tool" >/dev/null 2>&1 || { echo "stamp-role: $tool is required" >&2; exit 2; }
done

if [ "$#" -ne 3 ]; then
  echo "usage: stamp-role.sh VERSION ROLE-DIR OUT-DIR" >&2
  exit 2
fi
version=$1
role_dir=$2
out_dir=$3

if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?(\+[0-9A-Za-z.]+)?$ ]]; then
  echo "stamp-role: '$version' is not a release version" >&2
  exit 2
fi

placeholder='relay_daemon_release_version: "@RELEASE_VERSION@"'
stamped="relay_daemon_release_version: \"$version\""
vars_file="$role_dir/vars/main.yml"

count=$(grep -cxF -- "$placeholder" "$vars_file" 2>/dev/null || true)
if [ "$count" != 1 ]; then
  echo "stamp-role: $vars_file must hold the placeholder line exactly once" >&2
  exit 2
fi
if [ ! -d "$out_dir" ]; then
  echo "stamp-role: $out_dir is not a directory" >&2
  exit 2
fi
if [ -e "$out_dir/relay_daemon" ]; then
  echo "stamp-role: $out_dir/relay_daemon already exists" >&2
  exit 2
fi

cp -R "$role_dir" "$out_dir/relay_daemon"
out_vars="$out_dir/relay_daemon/vars/main.yml"
awk -v from="$placeholder" -v to="$stamped" '$0 == from { print to; next } { print }' \
  "$vars_file" >"$out_vars"

other=$(grep -rlE '^[[:space:]]*relay_daemon_release_version[[:space:]]*:' "$out_dir/relay_daemon" || true)
if [ "$other" != "$out_vars" ]; then
  echo "stamp-role: the release version must be set in vars/main.yml only: $other" >&2
  exit 1
fi
vers_lines=$(grep -cE '^relay_daemon_release_version:' "$out_vars" || true)
if [ "$vers_lines" != 1 ]; then
  echo "stamp-role: vars/main.yml must hold one relay_daemon_release_version line" >&2
  exit 1
fi

stamped_count=$(grep -cxF -- "$stamped" "$out_vars" || true)
if [ "$stamped_count" != 1 ] || grep -qF -- '@RELEASE_VERSION@' "$out_vars"; then
  echo "stamp-role: the stamped role does not carry $version exactly once" >&2
  exit 1
fi
