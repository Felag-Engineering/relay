# Expected package contents

The reviewed baseline `scripts/package-guard.sh content` checks every release package against.
The guard reads each package with `dpkg-deb` or `rpm`, never with nfpm, so it does not trust the
tool that built the package.

- `<package>.<deb|rpm>.files`: the payload listing, one entry per line: mode string, owner,
  path. On rpm there is also `caps=`, where `(none)` means no file capability.
- `<package>.<deb|rpm>.relations`: every relationship the package declares. On .deb this also
  includes the set of control field names. The package's own version-release is written as
  `@VR@`, and the rpm architecture tag as `@ISA@`.

The maintainer scripts are compared byte for byte with `../scripts/*.sh`, so nothing here
repeats them.

Change a file here only in the same change that changes the manifests under `../nfpm/`. A diff
to this directory is a diff to what lands on every Node, and it is reviewed as one.
