# Expected package contents

This directory is the reviewed baseline that `scripts/package-guard.sh content` checks every
release package against. The guard reads each package with `dpkg-deb` or `rpm`, never with nfpm.
It is told the release version and architecture, and computes the package's identity from them.
It never takes the identity from the package.

What it checks, and nothing more:

- **Identity.**
  - On .deb, the whole control file (`dpkg-deb -f`) must equal `<package>.deb.control`. Only three
    fields are filled in:
    - `Version` is `<base>[~<pre>][+<meta>]-1`, with no epoch.
    - `Architecture` is `amd64` or `arm64`, or `all` for `relay-read`.
    - `Installed-Size` is read from the package and must be a number.
    Every other field must match exactly, the package name included.
  - On .rpm, `NAME EPOCHNUM VERSION-RELEASE ARCH` must equal the package name, `0`, the same
    version, and `x86_64` or `aarch64` (`noarch` for `relay-read`).
- **Payload listing.** It must equal `<package>.<deb|rpm>.files`, one entry per line: mode string
  (which gives the type), owner, path. On rpm each entry also has `caps=`, where `(none)` means no
  file capability. No entry may be setuid, setgid or sticky, and no rpm entry may carry a
  capability.
- **Maintainer scripts and triggers.**
  - On .deb, the control archive must hold exactly `control`, `md5sums` and, for
    `relay-daemon`, the four scripts. Each script must be byte-equal to `../scripts/<name>.sh`.
  - On .rpm, `rpm -qp --scripts --triggers --filetriggers` must equal the source scripts. The
    only allowance is the header line and trailing newline rpm prints around each scriptlet.
- **Relationships.** They must equal `<package>.<deb|rpm>.relations`.
  - On .deb these are the control field names and the nine relationship fields.
  - On rpm these are Provides, Requires, Conflicts, Obsoletes, Recommends, Suggests,
    Supplements and Enhances.
  - The expected version-release is written as `@VR@`, and the expected rpm architecture tag as
    `@ISA@`.
- **Files carried from the repository.** These must be byte-equal to their sources:
  - for `relay-daemon`: the default Policy, LICENSE, the privilege posture document, the unit and
    the environment example;
  - for `relay-read`: the catalog.

The guard does not check the bytes of the binary; the release compares those with the release
binary in its own step. It also does not check file timestamps, or the deb `md5sums` member
beyond its presence.

Change a file here only in the same change that changes the manifests under `../nfpm/`. A diff
to this directory is a diff to what lands on every Node, and it is reviewed as one.
