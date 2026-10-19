#!/usr/bin/env bash
# Proves scripts/build-packages.sh and scripts/package-guard.sh, the release's package build and
# guards (DI-24, DI-32): two builds of the same inputs from different paths, umasks and source
# mtimes are byte-identical; the payload binary is the input binary byte for byte; the guards
# refuse a different binary, a missing or wrong SHA256SUMS line, and a package that declares
# configuration files; the content guard accepts the real packages and refuses, each by the
# check meant to catch it, a changed maintainer script, a setuid or non-root entry, an extra
# payload file, a changed default Policy or LICENSE, an extra relationship and an added trigger
# or scriptlet; and the build refuses a missing SOURCE_DATE_EPOCH, a malformed version
# and an unknown architecture.
#
# Builds the pinned nfpm with `go tool` and packages a stand-in binary; touches nothing in this
# working tree. Needs dpkg-deb, rpm, rpm2cpio and cpio: a missing one is a recorded skip under
# `make verify` and a failure anywhere else, the convention for a missing tool.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
build="$root/scripts/build-packages.sh"
guard="$root/scripts/package-guard.sh"

for t in dpkg-deb rpm rpm2cpio cpio go; do
  if ! command -v "$t" >/dev/null 2>&1; then
    if [ -n "${RELAY_VERIFY_SKIPS:-}" ]; then
      echo "verify: SKIPPING test-packages - $t not installed (CI runs it)"
      echo "test-packages ($t not installed)" >> "$RELAY_VERIFY_SKIPS"
      exit 0
    fi
    echo "package-guard-test: $t is required" >&2
    exit 1
  fi
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export SOURCE_DATE_EPOCH=1700000000
version="1.2.3-0.dev+gdeadbeef"

pass=0 fail=0
ok() { echo "ok   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; fail=$((fail + 1)); }
expect_ok() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
expect_refused() {
  local name="$1" want="$2"; shift 2
  local rc=0
  "$@" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -eq "$want" ]; then ok "$name"; else bad "$name (exit $rc, want $want)"; fi
}

# A stand-in for the guarded release binary: arbitrary bytes, which the package must carry as is.
mkdir -p "$work/one" "$work/two/a/b/c"
head -c 65536 /dev/urandom > "$work/one/relay-daemon"
chmod 0755 "$work/one/relay-daemon"
cp "$work/one/relay-daemon" "$work/two/a/b/c/other-name"
touch -d '2001-02-03' "$work/two/a/b/c/other-name"

if ! bash "$build" "$version" x86_64 "$work/one/relay-daemon" "$work/out1" --catalog >"$work/log1" 2>&1; then
  cat "$work/log1"; bad "first build"; echo "package-guard-test: $pass passed, $fail failed"; exit 1
fi
(umask 077; bash "$build" "$version" x86_64 "$work/two/a/b/c/other-name" "$work/out2" --catalog >"$work/log2" 2>&1) \
  || { cat "$work/log2"; bad "second build"; }

shopt -s nullglob
pkgs=("$work"/out1/*.deb "$work"/out1/*.rpm)
if [ "${#pkgs[@]}" -eq 4 ]; then ok "four packages built"; else bad "four packages built (got ${#pkgs[@]})"; fi
for p in "${pkgs[@]}"; do
  n="$(basename "$p")"
  if cmp -s "$p" "$work/out2/$n"; then ok "reproducible: $n"; else bad "reproducible: $n"; fi
done

deb="$(echo "$work"/out1/relay-daemon_*_amd64.deb)"
rpmf="$(echo "$work"/out1/relay-daemon-*.x86_64.rpm)"
read_deb="$(echo "$work"/out1/relay-read_*_all.deb)"
read_rpm="$(echo "$work"/out1/relay-read-*.noarch.rpm)"

# DI-24: the payload binary is the input binary, byte for byte.
expect_ok "deb payload equals the input binary" bash "$guard" same "$deb" /usr/bin/relay-daemon "$work/one/relay-daemon"
expect_ok "rpm payload equals the input binary" bash "$guard" same "$rpmf" /usr/bin/relay-daemon "$work/one/relay-daemon"
cp "$work/one/relay-daemon" "$work/tampered"
printf '\001' | dd of="$work/tampered" bs=1 seek=100 conv=notrunc status=none
expect_refused "deb payload against a one-byte-different binary is refused" 1 bash "$guard" same "$deb" /usr/bin/relay-daemon "$work/tampered"
expect_refused "rpm payload against a one-byte-different binary is refused" 1 bash "$guard" same "$rpmf" /usr/bin/relay-daemon "$work/tampered"
expect_refused "a member the package lacks is refused" 1 bash "$guard" same "$deb" /usr/bin/not-there "$work/one/relay-daemon"
expect_refused "an rpm member the package lacks is refused" 1 bash "$guard" same "$rpmf" /usr/bin/not-there "$work/one/relay-daemon"

# DI-32: the packaged unit and environment example are the standalone files.
for p in "$deb" "$rpmf"; do
  expect_ok "$(basename "$p"): unit equals the standalone unit" \
    bash "$guard" same "$p" /usr/lib/systemd/system/relay-daemon.service "$root/daemon/packaging/relay-daemon.service"
  expect_ok "$(basename "$p"): env example equals the standalone example" \
    bash "$guard" same "$p" /usr/share/relay-daemon/relay-daemon.env.example "$root/daemon/packaging/relay-daemon.env.example"
done
expect_ok "catalog deb carries the shipped catalog" \
  bash "$guard" same "$read_deb" /etc/relay-daemon/templates.d/relay-read/catalog.toml "$root/daemon/packaging/templates.d/relay-read/catalog.toml"
expect_ok "catalog rpm carries the shipped catalog" \
  bash "$guard" same "$read_rpm" /etc/relay-daemon/templates.d/relay-read/catalog.toml "$root/daemon/packaging/templates.d/relay-read/catalog.toml"

# Every package listed in a sums file, and a missing or wrong line refused.
(cd "$work/out1" && sha256sum -- *.deb *.rpm > "$work/SUMS")
expect_ok "every package is listed" bash "$guard" listed "$work/SUMS" "${pkgs[@]}"
grep -v relay-read_ "$work/SUMS" > "$work/SUMS.missing"
expect_refused "a package missing from the sums file is refused" 1 bash "$guard" listed "$work/SUMS.missing" "${pkgs[@]}"
sed "s/^[0-9a-f]\{8\}/00000000/" "$work/SUMS" > "$work/SUMS.wrong"
expect_refused "a wrong digest is refused" 1 bash "$guard" listed "$work/SUMS.wrong" "$deb"

# No package declares configuration the package manager would preserve (ADR-0033, DI-29).
for p in "${pkgs[@]}"; do
  expect_ok "$(basename "$p") declares no configuration files" bash "$guard" no-config "$p"
done
nfpm="$(GOWORK=off go -C "$root/tools/nfpm" tool -n nfpm)"
mkdir -p "$work/conf"
printf 'x\n' > "$work/conf/f"
cat > "$work/conf/nfpm.yaml" <<EOF
name: conf-fixture
arch: all
version: 1.0.0
maintainer: test
mtime: "2023-11-14T22:13:20Z"
contents:
  - src: $work/conf/f
    dst: /etc/conf-fixture/f
    type: config|noreplace
EOF
(cd "$work/conf" && "$nfpm" package -f nfpm.yaml -p deb -t "$work/conf/" >/dev/null 2>&1 \
  && "$nfpm" package -f nfpm.yaml -p rpm -t "$work/conf/" >/dev/null 2>&1) || bad "config fixture builds"
expect_refused "a deb with conffiles is refused" 1 bash "$guard" no-config "$(echo "$work"/conf/*.deb)"
expect_refused "an rpm with %config is refused" 1 bash "$guard" no-config "$(echo "$work"/conf/*.rpm)"

# Fixed modes and owners, whatever the source files' modes.
check() { local name="$1"; shift; if "$@"; then ok "$name"; else bad "$name"; fi; }
lists() { grep -Eq "$1" <<<"$2"; }
lacks() { ! grep -Eq "$1" <<<"$2"; }
listing="$(dpkg-deb -c "$deb")"
check "deb binary root 0755" lists '^-rwxr-xr-x root/root .* \./usr/bin/relay-daemon$' "$listing"
check "deb unit root 0644" lists '^-rw-r--r-- root/root .* \./usr/lib/systemd/system/relay-daemon.service$' "$listing"
check "daemon deb owns nothing under /etc" lacks '\./etc/' "$listing"
rlisting="$(rpm -qlvp "$rpmf" 2>/dev/null)"
check "rpm binary root 0755" lists '^-rwxr-xr-x +1 root +root .* /usr/bin/relay-daemon$' "$rlisting"
check "daemon rpm owns nothing under /etc" lacks ' /etc/' "$rlisting"
check "catalog rpm requires relay-daemon" lists '^relay-daemon$' "$(rpm -qpR "$read_rpm" 2>/dev/null)"
check "catalog deb depends on relay-daemon" lists '^relay-daemon$' "$(dpkg-deb -f "$read_deb" Depends)"

# The content guard reads every package with dpkg-deb and rpm, never nfpm, against the
# repository's expected listings, scripts and relationships.
for p in "$deb" "$rpmf"; do
  expect_ok "$(basename "$p"): content as expected" bash "$guard" content "$p" relay-daemon
done
for p in "$read_deb" "$read_rpm"; do
  expect_ok "$(basename "$p"): content as expected" bash "$guard" content "$p" relay-read
done
expect_refused "a daemon package checked as the catalog is refused" 1 bash "$guard" content "$deb" relay-read

# Tampered packages: each is built from a copy of the packaging inputs with one thing changed,
# and the real guard, which compares against this repository, must refuse it. A file
# capability cannot be expressed in an nfpm manifest, so it has no tampered case here; the
# payload listing would show it as a changed caps= field, refused like any other difference.
fake="$work/fake"
mkdir -p "$fake/docs/operations" "$fake/daemon" "$fake/tools"
cp -r "$root/scripts" "$fake/scripts"
cp -r "$root/daemon/packaging" "$fake/daemon/packaging"
cp "$root/daemon/policy.default.toml" "$fake/daemon/"
cp "$root/docs/operations/daemon-privilege-posture.md" "$fake/docs/operations/"
cp "$root/LICENSE" "$fake/"
cp -r "$root/tools/nfpm" "$fake/tools/nfpm"

# tampered NAME EDIT...: builds the daemon packages from the fake tree after running EDIT in it,
# then restores the tree. Prints the output directory.
tampered() {
  local name="$1"; shift
  local out="$work/t-$name"
  rm -rf "$fake.bak"; cp -r "$fake" "$fake.bak"
  (cd "$fake" && "$@") || { bad "tamper $name: edit failed"; return 1; }
  bash "$fake/scripts/build-packages.sh" "$version" x86_64 "$work/one/relay-daemon" "$out" >/dev/null 2>&1 \
    || bad "tamper $name: build failed"
  rm -rf "$fake"; mv "$fake.bak" "$fake"
  printf '%s\n' "$out"
}
# refuses_both WHAT DEB-REASON RPM-REASON OUTDIR: the content guard refuses both packages, exit 1,
# and its refusal names the check expected to catch the tampering, so a case cannot pass by
# being refused for some other reason.
refused_for() {
  local name="$1" reason="$2" pkg="$3" rc=0 err
  err="$(bash "$guard" content "$pkg" relay-daemon 2>&1 >/dev/null)" || rc=$?
  if [ "$rc" -eq 1 ] && grep -Eq "REFUSED: .*($reason)" <<<"$err"; then ok "$name"
  else bad "$name (exit $rc: $(grep REFUSED <<<"$err" | head -1))"; fi
}
refuses_both() {
  local what="$1" deb_reason="$2" rpm_reason="$3" out="$4"
  refused_for "deb with $what is refused" "$deb_reason" "$(echo "$out"/*.deb)"
  refused_for "rpm with $what is refused" "$rpm_reason" "$(echo "$out"/*.rpm)"
}
manifest=daemon/packaging/nfpm/relay-daemon.yaml
refuses_both "a changed maintainer script" "postinst differs" "scriptlets and triggers differs" \
  "$(tampered script sh -c 'echo "touch /tmp/x" >> daemon/packaging/scripts/postinst.sh')"
refuses_both "a setuid binary" "payload listing differs" "payload listing differs" \
  "$(tampered setuid sed -i 's/file_info: {mode: 0o755, owner: root, group: root}/file_info: {mode: 0o4755, owner: root, group: root}/' "$manifest")"
refuses_both "an extra payload file" "payload listing differs" "payload listing differs" \
  "$(tampered extra sed -i 's|^contents:|contents:\n  - src: "@SRC@/LICENSE"\n    dst: /usr/bin/extra\n    file_info: {mode: 0o755, owner: root, group: root}|' "$manifest")"
refuses_both "a non-root owner" "payload listing differs" "payload listing differs" \
  "$(tampered owner sed -i '0,/owner: root, group: root/s//owner: nobody, group: root/' "$manifest")"
refuses_both "a changed default Policy" "policy.default.toml differs" "policy.default.toml differs" \
  "$(tampered policy sh -c 'echo "# changed" >> daemon/policy.default.toml')"
refuses_both "a changed LICENSE" "LICENSE differs" "LICENSE differs" \
  "$(tampered license sh -c 'echo "changed" >> LICENSE')"
refuses_both "an extra relationship" "relationships differs" "relationships differs" \
  "$(tampered relation sed -i 's|^mtime:|replaces:\n  - other-daemon\nconflicts:\n  - other-daemon\nprovides:\n  - other-daemon\nmtime:|' "$manifest")"
refuses_both "an added trigger or scriptlet" "control archive members differs" "scriptlets and triggers differs" \
  "$(tampered trigger sed -i 's|^deb:|deb:\n  triggers:\n    interest:\n      - /usr/lib/x|; s|^rpm:|rpm:\n  scripts:\n    posttrans: "@SRC@/daemon/packaging/scripts/prerm.sh"|' "$manifest")"

# postrm's purge and removal listing, run unprivileged on a copy whose fixed paths are moved
# under a temporary root (and whose systemd probe is off). Only the four path constants and the
# probe are rewritten; every line of logic runs as shipped.
relocated_postrm() {
  local t="$1" copy="$1/postrm.sh"
  sed -e "s|^MARKER_DIR=/var/lib/relay-daemon-package\$|MARKER_DIR=$t/var/lib/relay-daemon-package|" \
      -e "s|^ETC=/etc/relay-daemon\$|ETC=$t/etc/relay-daemon|" \
      -e "s|^STATE=/var/lib/relay-daemon\$|STATE=$t/var/lib/relay-daemon|" \
      -e 's|^systemd_running() { \[ -d /run/systemd/system \]; }$|systemd_running() { false; }|' \
      "$root/daemon/packaging/scripts/postrm.sh" > "$copy"
  [ "$(grep -c "$t" "$copy")" -eq 3 ] && grep -q '^systemd_running() { false; }$' "$copy"
}
purge_fixture() {
  local t="$1"
  rm -rf "$t"; mkdir -p "$t/var/lib/relay-daemon-package" "$t/var/lib/relay-daemon" "$t/operator"
  printf 'created etc\ncreated policy\ncreated policy-dir\ncreated env\ncreated state\n' \
    > "$t/var/lib/relay-daemon-package/marker"
  echo id > "$t/var/lib/relay-daemon/node_id"
  relocated_postrm "$t"
}
pt="$work/postrm"
if purge_fixture "$pt"; then
  mkdir -p "$pt/etc/relay-daemon/policy.d"
  echo p > "$pt/etc/relay-daemon/policy.toml"; echo e > "$pt/etc/relay-daemon/relay-daemon.env"
  sh "$pt/postrm.sh" purge >/dev/null 2>&1
  check "purge deletes what the package created, state included" \
    test ! -e "$pt/etc/relay-daemon" -a ! -e "$pt/var/lib/relay-daemon" -a ! -e "$pt/var/lib/relay-daemon-package"
else bad "postrm relocates for the test"; fi

# A symlinked /etc/relay-daemon: purge deletes nothing through it, and names it.
if purge_fixture "$pt"; then
  echo p > "$pt/operator/policy.toml"; echo e > "$pt/operator/relay-daemon.env"
  ln -s "$pt/operator" "$pt/etc-link"; mkdir -p "$pt/etc"; mv "$pt/etc-link" "$pt/etc/relay-daemon"
  out="$(sh "$pt/postrm.sh" purge 2>&1)"
  check "purge through a symlinked /etc/relay-daemon deletes nothing there" \
    test -f "$pt/operator/policy.toml" -a -f "$pt/operator/relay-daemon.env"
  check "purge names a symlinked /etc/relay-daemon" lists "$pt/etc/relay-daemon is not a plain directory" "$out"
else bad "postrm relocates for the test"; fi

# /etc/relay-daemon as a regular file: purge neither fails nor deletes it, and names it.
if purge_fixture "$pt"; then
  mkdir -p "$pt/etc"; echo x > "$pt/etc/relay-daemon"
  rc=0; out="$(sh "$pt/postrm.sh" purge 2>&1)" || rc=$?
  check "purge over a non-directory /etc/relay-daemon succeeds and keeps it" test "$rc" -eq 0 -a -f "$pt/etc/relay-daemon"
  check "purge names a non-directory /etc/relay-daemon" lists "not a plain directory" "$out"
else bad "postrm relocates for the test"; fi

# .rpm removal prints what remains, the catalog's Template root included, and deletes nothing.
if purge_fixture "$pt"; then
  mkdir -p "$pt/etc/relay-daemon/policy.d" "$pt/etc/relay-daemon/templates.d"
  echo p > "$pt/etc/relay-daemon/policy.toml"
  out="$(sh "$pt/postrm.sh" 0 2>&1)"
  check "rpm removal names the leftover templates.d" lists "$pt/etc/relay-daemon/templates.d\$" "$out"
  check "rpm removal names the state directory" lists "$pt/var/lib/relay-daemon\$" "$out"
  check "rpm removal deletes no configuration or state" \
    test -f "$pt/etc/relay-daemon/policy.toml" -a -f "$pt/var/lib/relay-daemon/node_id"
else bad "postrm relocates for the test"; fi

# The build refuses what it cannot make reproducible or does not recognise.
expect_refused "no SOURCE_DATE_EPOCH is refused" 2 env -u SOURCE_DATE_EPOCH bash "$build" "$version" x86_64 "$work/one/relay-daemon" "$work/x"
expect_refused "a non-integer SOURCE_DATE_EPOCH is refused" 2 env SOURCE_DATE_EPOCH=yesterday bash "$build" "$version" x86_64 "$work/one/relay-daemon" "$work/x"
expect_refused "a malformed version is refused" 2 bash "$build" '1.2.3"; evil: x' x86_64 "$work/one/relay-daemon" "$work/x"
expect_refused "an unknown architecture is refused" 2 bash "$build" "$version" riscv64 "$work/one/relay-daemon" "$work/x"

echo "package-guard-test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
