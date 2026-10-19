#!/usr/bin/env bash
# Proves scripts/build-packages.sh and scripts/package-guard.sh, the release's package build and
# guards (DI-24, DI-32): two builds of the same inputs from different paths, umasks and source
# mtimes are byte-identical; the payload binary is the input binary byte for byte; the guards
# refuse a different binary, a missing or wrong SHA256SUMS line, and a package that declares
# configuration files; and the build refuses a missing SOURCE_DATE_EPOCH, a malformed version
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
[ "${#pkgs[@]}" -eq 4 ] && ok "four packages built" || bad "four packages built (got ${#pkgs[@]})"
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
listing="$(dpkg-deb -c "$deb")"
grep -Eq '^-rwxr-xr-x root/root .* \./usr/bin/relay-daemon$' <<<"$listing" && ok "deb binary root 0755" || bad "deb binary root 0755"
grep -Eq '^-rw-r--r-- root/root .* \./usr/lib/systemd/system/relay-daemon.service$' <<<"$listing" && ok "deb unit root 0644" || bad "deb unit root 0644"
if grep -Eq '\./etc/' <<<"$listing"; then bad "daemon deb owns nothing under /etc"; else ok "daemon deb owns nothing under /etc"; fi
rlisting="$(rpm -qlvp "$rpmf" 2>/dev/null)"
grep -Eq '^-rwxr-xr-x +1 root +root .* /usr/bin/relay-daemon$' <<<"$rlisting" && ok "rpm binary root 0755" || bad "rpm binary root 0755"
if grep -Eq ' /etc/' <<<"$rlisting"; then bad "daemon rpm owns nothing under /etc"; else ok "daemon rpm owns nothing under /etc"; fi
[ "$(rpm -qpR "$read_rpm" 2>/dev/null | grep -cx 'relay-daemon')" -eq 1 ] && ok "catalog rpm requires relay-daemon" || bad "catalog rpm requires relay-daemon"
dpkg-deb -f "$read_deb" Depends | grep -qx 'relay-daemon' && ok "catalog deb depends on relay-daemon" || bad "catalog deb depends on relay-daemon"

# The build refuses what it cannot make reproducible or does not recognise.
expect_refused "no SOURCE_DATE_EPOCH is refused" 2 env -u SOURCE_DATE_EPOCH bash "$build" "$version" x86_64 "$work/one/relay-daemon" "$work/x"
expect_refused "a non-integer SOURCE_DATE_EPOCH is refused" 2 env SOURCE_DATE_EPOCH=yesterday bash "$build" "$version" x86_64 "$work/one/relay-daemon" "$work/x"
expect_refused "a malformed version is refused" 2 bash "$build" '1.2.3"; evil: x' x86_64 "$work/one/relay-daemon" "$work/x"
expect_refused "an unknown architecture is refused" 2 bash "$build" "$version" riscv64 "$work/one/relay-daemon" "$work/x"

echo "package-guard-test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
