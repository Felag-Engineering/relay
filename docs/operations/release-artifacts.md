# Release artifacts: naming, pinning, and verify-then-install

The relay-daemon is never upgraded by the Relay. It reaches a fleet only through the
customer's own config management, which pulls a published artifact and installs it —
ADR-0014, and CLAUDE.md invariant #14: *the daemon never self-upgrades and the Relay never
pushes binaries.* That makes the release artifact the sole supported upgrade path, and its
name and its digest the interface config management codes against. This document is that
interface.

## What a tag publishes

Pushing a `v*` tag runs [`.github/workflows/release.yml`](../../.github/workflows/release.yml),
which builds both binaries stamped (see [version-stamping.md](version-stamping.md)), verifies
them, and creates a GitHub Release carrying three assets:

| Asset | What it is |
|---|---|
| `relay-daemon-<version>-x86_64-unknown-linux-musl` | the Node daemon: static, no libc dependency (ADR-0007) |
| `relay-<version>-linux-amd64` | the Relay control-plane server: static (`CGO_ENABLED=0`) |
| `SHA256SUMS` | `sha256sum` output over exactly those two names |

Release notes are generated from the commit range. **Pre-1.0 tags publish as pre-releases** —
`0.y.z` promises no compatibility — as does any tag with a semver prerelease suffix
(`v0.1.0-beta`).

## Naming and pinning

The convention is the contract. Config management pins against it, so it changes only with a
deliberate, documented break.

```
<binary>-<version>-<platform>
```

- **`<binary>`** — `relay-daemon` or `relay`. The same name the binary has on disk.
- **`<version>`** — bare semver, **no leading `v`**: `0.0.9`, `0.1.0-beta`. This is exactly
  what the binary prints for `--version`, so a pinned version string can be compared to a
  running daemon's self-report with no stripping on either side. The `v` belongs to the git
  tag (`v0.0.9`) and to the release, never to the artifact.
- **`<platform>`** — the build target *as its own toolchain names it*:
  `x86_64-unknown-linux-musl` is the literal `cargo --target` triple for the daemon;
  `linux-amd64` is Go's `GOOS-GOARCH` for the Relay. The two vocabularies are deliberately
  not unified into one invented token: each string is a claim an operator can check against
  the way the binary was actually produced, and a shared token would have to be false about
  one of them. The daemon's `musl` is the operationally load-bearing half — it is what makes
  one binary run on every Node in a heterogeneous fleet regardless of libc.

Only `x86_64` is published today. A second architecture adds artifacts under the same
grammar (`relay-daemon-0.1.0-aarch64-unknown-linux-musl`); it does not change existing names.

> **Caveat on prerelease version tokens (`0.1.0-beta`, `0.1.0-rc.1`) — see
> [#261](https://github.com/Felag-Engineering/gleipnir-relay/issues/261).** A prerelease tag
> builds, verifies, and publishes correctly through everything described here. What is *not*
> yet settled is what it does to the `min-daemon-version` gate: once `Cargo.toml` names a
> prerelease target, dev builds stamp `0.1.0-beta-dev`, which sorts **above** `0.1.0-beta`
> under semver — inverting the fail-closed direction the gate depends on, so a Relay
> configured with `min-daemon-version = 0.1.0-beta` would dispatch to unreleased dev daemons.
> Until #261 is decided: publishing a prerelease tag is fine; setting `min-daemon-version` to
> a prerelease version is not.

The download URL follows from the tag and the asset name, which is all an IaC role needs:

```
https://github.com/Felag-Engineering/gleipnir-relay/releases/download/v<version>/<asset>
```

## Verify then install

**Verification is not optional and not a post-install audit step.** The relay-daemon runs as
root on every Node in the fleet; an unverified binary landing there is precisely the
supply-chain compromise this system is built to make hard. Check the digest *before* the file
reaches a privileged path.

### By hand

```bash
VERSION=0.0.9
BASE=https://github.com/Felag-Engineering/gleipnir-relay/releases/download/v${VERSION}
ASSET=relay-daemon-${VERSION}-x86_64-unknown-linux-musl

cd "$(mktemp -d)"
curl -fsSL -O "${BASE}/${ASSET}"
curl -fsSL -O "${BASE}/SHA256SUMS"

# Verify first. SHA256SUMS covers both assets, so select the line for the one
# you downloaded and check that. --strict rejects a malformed SHA256SUMS
# instead of skipping the bad lines; if nothing is selected (a typo in the
# asset name) sha256sum gets empty input and exits non-zero with "no properly
# formatted checksum lines found" — it fails, it does not silently pass.
awk -v a="$ASSET" '$2 == a' SHA256SUMS | sha256sum --check --strict -

# Only now does it become a privileged binary.
sudo install -o root -g root -m 0755 "$ASSET" /usr/local/bin/relay-daemon
/usr/local/bin/relay-daemon --version     # must print exactly ${VERSION}
sudo systemctl restart relay-daemon
```

The `--version` line is the second half of the check: the digest proves you got the bytes
that were published, and `--version` proves those bytes are the release you meant to pin. A
daemon reporting a `-dev` suffix in production means something bypassed this path.

Two details in that one line are deliberate. `awk … | sha256sum -c -` rather than
`sha256sum --check --ignore-missing`, because `--ignore-missing` — the more obvious
spelling, and one that also fails closed — needs coreutils ≥ 8.25, while RHEL 7, CentOS 7 and
Amazon Linux 2 ship 8.22. Those are exactly the machines this daemon targets musl *for*, and
an operator who hits `unrecognized option '--ignore-missing'` on one is an operator about to
drop the flag or skip verification altogether. And `awk '$2 == a'` rather than
`grep " $ASSET$"`, because grep would treat the asset name as a *pattern*: the dots in
`relay-daemon-0.0.9-…` are wildcards, so the line for a `relay-daemon-0a0b9-…` asset would
match it. Harmless against a `SHA256SUMS` we generate ourselves with two lines in it, but
this is the snippet operators copy, and it is the same regex-as-data mistake the build
tooling was hardened against (`grep -qxF` in `scripts/build-version.sh`). `awk`'s `==` is a
string comparison on the exact filename field.

### From config management

Pin the version **and** the digest in the role's own reviewed variables, taken once from a
release's `SHA256SUMS`. Ansible's `get_url` verifies the checksum before the file lands, so
the ordering property above is structural rather than a habit:

```yaml
# group_vars — reviewed in the IaC repo, changed only by a deliberate upgrade commit.
relay_daemon_version: "0.0.9"
relay_daemon_sha256: "<the line for relay-daemon-0.0.9-x86_64-unknown-linux-musl>"

- name: Install the pinned relay-daemon
  ansible.builtin.get_url:
    url: >-
      https://github.com/Felag-Engineering/gleipnir-relay/releases/download/v{{ relay_daemon_version }}/relay-daemon-{{ relay_daemon_version }}-x86_64-unknown-linux-musl
    dest: /usr/local/bin/relay-daemon
    checksum: "sha256:{{ relay_daemon_sha256 }}"
    owner: root
    group: root
    mode: "0755"
  notify: restart relay-daemon
```

Pinning the digest in the role is stronger than fetching `SHA256SUMS` at run time: the
checksum file is served from the same origin as the binary, so fetching both together proves
the download was not corrupted or truncated, but not that the origin is honest. A digest that
was reviewed into the IaC repo once, by a human, and is thereafter enforced on every run is
the property worth having. Closing the origin-trust gap itself needs artifact signing — see
*Not in scope* below.

The daemon's stamped version is fleet-visible, so upgrade progress is observable without
touching the Nodes: `list_nodes` and the Console report each Node's `daemon_version`, and the
ADR-0014 `min-daemon-version` gate flags anything below the configured floor as `outdated`
(it keeps heartbeating; the Job engine simply refuses to dispatch to it). See
[version-stamping.md](version-stamping.md).

## What the release job refuses to publish

Every guard below lives in [`scripts/release-artifacts.sh`](../../scripts/release-artifacts.sh)
and runs *before* `gh release create`. A tripped guard fails the run and publishes nothing —
a release that does not happen costs a re-tag, while a release that publishes a mislabelled
binary is discovered on the fleet.

1. **The tag is semver.** `on.push.tags: v*` also matches `vnext`; the version token is
   embedded in every artifact name, so it must be `v<major>.<minor>.<patch>[-prerelease]`.
2. **The stamped version equals the tag.** Not merely "contains no `-dev`". Equality catches
   the whole family at once: an untagged or dirty or shallowly-checked-out build (which stamps
   `-dev`), a `Cargo.toml` bumped ahead of the tag (which would publish `0.0.10-dev+g…` under
   a `v0.0.9` release), and the case a `-dev` check misses entirely — a commit carrying
   several `v*` tags, where the stamp is a clean but *wrong* version. Asserted for both
   binaries.
3. **Both binaries are static.** Checked with `readelf`, not `ldd`: a static-PIE still has a
   `.dynamic` section for self-relocation, so what must be absent is any `PT_INTERP` and any
   `DT_NEEDED`. `ldd` is asserted too, since it is what an operator reaches for — it prints
   `statically linked` for the musl daemon and `not a dynamic executable` for the
   `CGO_ENABLED=0` Relay, and both phrasings are accepted. A missing `readelf` is a hard
   failure, not a skip.
4. **`SHA256SUMS` verifies against the staged files.** Close to the operator's check above,
   but not identical: this one verifies *every* listed asset (`sha256sum --check --strict`
   over the whole file), because the release job is the one party that must have all of them.

**What the guards do not check is correctness.** They establish identity, linkage, and
digests — nothing more. The release job runs no tests: a `v*` tag pushed at any commit
publishes, and nothing verifies that CI ever passed there. Cut tags only from a commit on
`main` whose CI is green.

The release is created as a **draft**, has its assets uploaded, and is only then un-drafted.
`gh release create` with assets would publish first and upload afterwards, so a failure
part-way through would leave a *public* release carrying only some of its assets — a binary
with no `SHA256SUMS`, or a `SHA256SUMS` naming an asset that is not there. A failed run
instead leaves a draft, which is invisible to consumers and to `gh release download`.

**A failed run must be cleaned up before it is retried.** The publish step refuses to start
if any release already exists for the tag, and says which case it hit:

- *a draft from a previous run* — delete it (`gh release delete <tag> --yes`) and re-run.
  Simply re-running would not fail: `gh release create` only performs its own duplicate-tag
  check when it is given assets and is not a draft, and a draft's tag is not bound
  server-side until it is published, so a re-run would create a *second* draft — and the
  by-tag lookup that `gh release upload`/`edit` use picks one of them with no defined
  selection and no warning, which could publish the earlier, partial draft.
- *an already-published release* — nothing is overwritten. `--clobber` is never passed and
  no release is ever deleted by the workflow, because artifacts may already be pinned by
  digest. Ship a corrected build under a new tag.

Locally, `make release-artifacts TAG=v0.0.9` runs the build and every one of those guards.
It is the same command the workflow runs, so the verification path can be rehearsed on a
developer machine; only the publishing steps are exclusive to CI.

## Reproducibility

Rebuild a tag, get the same digests. Three things make that hold, and all three are
necessary:

- **`SOURCE_DATE_EPOCH`**, pinned by the workflow to the tag commit's commit date. The build
  date is compiled into both binaries, and unpinned it is the wall-clock UTC day, so
  rebuilding tomorrow would change every digest.
- **`-trimpath`** on the Go build, so the Relay carries no absolute build paths.
- **`--remap-path-prefix`** on the daemon build (`RELEASE_RUSTFLAGS` in the `Makefile`),
  mapping the checkout to `/build` and the cargo registry to `/cargo`. Without it two clones
  of the same tag at different paths produce different daemon binaries — the generated proto
  module's path is embedded, along with several hundred registry paths from dependency panic
  locations — so the digest would only reproduce on the original builder's machine, at the
  original checkout path. It also stops the published binary from carrying the builder's home
  directory and checkout layout to every customer who runs `strings` on it.

Downloads verify without any of this — the published `SHA256SUMS` is unaffected — but
rebuild-and-compare verification is what turns "GitHub served me these bytes" into something
a third party can check, and it is what artifact signing will assume.

This is still a reproducibility *effort*, not a *guarantee*: the toolchain is `stable`
rather than a pinned version, so a rebuild after a Rust or Go release may legitimately
differ. Match the toolchain versions before treating a mismatch as a finding.

## Not in scope (the next tier)

Deliberately deferred, not forgotten:

- **Container images.** The `docker/` tree is the local dev fleet only
  (`docs/dev-fleet.md`); `docker/daemon.Dockerfile` is deliberately *unstamped* so the dev
  fleet exercises the no-stamp fallback, and it is explicitly **not** the release recipe.
  A published image is separate work.
- **SBOM generation.** No dependency manifest is published with the release yet.
- **Artifact signing (cosign / sigstore).** This is the gap that keeps the trust root at
  "GitHub Releases served the bytes". It should be taken up **alongside v0.8.0's
  operator-signing work**, because it is the same key-custody question — who holds the
  signing key, where, and what happens when it is rotated — and answering it twice, in two
  places, would be the wrong shape.
