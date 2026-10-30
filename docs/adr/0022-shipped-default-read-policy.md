# The shipped default Policy pre-allows the read class, with a confidentiality deny-list

**Status:** Accepted.

Rewritten 2026-10-30 to say what is true now; the earlier text, which ADR-0033 amended, is in
git. Amended once, below: the amendment changes the decision, so it is not folded into the
rewrite.

## Decision

The Policy file Relay ships for each Node lets an AI-agent read the Node with no local
setup, and keeps it from reading secrets. Every read-only action the daemon ships with is
allowed, including reading any file. A fixed list of secret files is denied, and the deny wins
over the allow. The same list is denied to the file-checksum action, since a digest confirms a
guessed file. Of the daemon's own files, only those that hold a secret are on the list, plus its
environment file as a precaution. Nothing that changes a Node is allowed, and neither are
arbitrary commands (Raw Exec), until the operator turns them on. Once installed, the operator may
narrow or replace it.

## Why

An AI-agent's main work on a fleet is observation (ADR-0012). A default that denies reads
pushes every evaluation into Policy authoring or, worse, toward a broad Raw Exec allow, the most
dangerous path absorbing demand the typed read path should serve. A read result reaches the
model provider (ADR-0021: `read` is not "safe for the AI to see"), so the files whose contents
are themselves a credential are denied by name.

The deny-list exists for confidentiality, so it holds only files that carry a secret. The
daemon's binary and unit are public release artifacts; its Policy is reported whole in the
Policy view (`query.md`); its CA bundle is the Relay's own CA certificate, and its identity
certificate is presented on every connection; the shipped catalog's Template files are a public
package. Denying them would hide nothing, and a default that cannot deny the Template directory
exactly would fail its own strict check, which trains operators to ignore the check.

The default adds no engine semantics. Deny-by-default and deny-beats-allow stand as ADR-0002
defines them, and the default is expressed entirely as ordinary allow and deny rules
(invariant 3).

## What changes

**The allow side.** The shipped file allows each `read` Operation by name: the native reads
`system.facts` and `file.read`, the latter on any canonical path, and the `read` Templates of the
catalog that ships with the daemon (ADR-0021, ADR-0053), `file.checksum` among them, each scoped
by what it makes reachable. On a Node without the catalog, those rules are inert and dispatch
reports `unsupported`; a Policy rule never creates vocabulary. It carries no `mutate` allow and no
`[raw_exec]` pattern (ADR-0002). Nothing in the Relay assumes the file's presence or shape.

**The deny-list**, in ADR-0018 canonical form, each path denied to `file.read` and
`file.checksum` alike:

- local credential databases: `/etc/shadow`, `/etc/shadow-`, `/etc/gshadow`, `/etc/gshadow-`;
- host key material: `/etc/ssh/ssh_host_{rsa,ecdsa,ed25519,dsa}_key` and `/etc/krb5.keytab`;
- root's default SSH private keys: `/root/.ssh/id_{rsa,ecdsa,ed25519,dsa}`;
- distribution-default TLS private keys at a fixed path: `/etc/ssl/private/ssl-cert-snakeoil.key`
  (Debian and Ubuntu's `ssl-cert`) and `/etc/pki/tls/private/localhost.key` (the RHEL family's
  `mod_ssl`);
- the daemon's own files: the Node's identity private key `/var/lib/relay-daemon/key.pem`, and the
  environment file `/etc/relay-daemon/relay-daemon.env`, which holds no secret (DI-43) and stays
  denied as defence in depth;
- kernel and process memory and environment oracles: `/proc/kcore`, `/dev/mem`, `/dev/kmem`,
  `/proc/self/mem`, `/proc/self/environ`.

What the default does not deny, and how its strict check runs, is `daemon-installation.md` DI-28.
The self-reference lint's read probes follow this list; ADR-0021 decision 14 and DI-39 hold the
probe set.

**What stays open.** Path denies are exact strings, and Policy has no subtree deny (ADR-0018), so
the list cannot cover secrets without a fixed path: a site's own TLS keys, per-process `/proc`
aliases, shell histories, or a secret that lands in a log the catalog's bounded tail reaches (threat model R46). The
remedy is to deny such a path exactly, or to narrow `file.read`'s `"*"` to an explicit path
allow-list (`docs/operations/policy-as-code.md`). An operator-authored Template body is readable
under the wildcard (threat model R37); the lint's write probes do not prove a path unreachable
(R38). Neither a subtree deny nor output classification in Policy (ADR-0021) is built.

## Alternatives

- **Ship no default, denying everything.** Rejected: every deployment starts with authoring
  friction on the safe class, and operators reach for broad Raw Exec patterns instead.
- **Allow reads by risk class in the engine** (`class = "read"`). Rejected: it touches invariant 3
  and ADR-0012's boundary, where risk class sizes blast radius and never grants trust, and it
  hides the allowance from the exact-rule attribution a Decision carries. The file names each
  Operation instead.
- **A narrow `file.read` allow-list instead of `"*"` and a deny-list.** More restrictive, but a
  default allow-list either blocks the interrogation it exists for or grows into a
  distribution-specific catalog nobody can maintain. It stays the operator's hardening move.
- **Deny the daemon's whole trust root, not only its secrets.** Rejected on 2026-10-16: it hides
  nothing of value and leaves the shipped file failing its own strict check.

## Amendment (2026-10-30): the temporary identity key

Owner decision 2026-10-29, recorded here and on issue #1056. The daemon writes a new identity
private key to `/var/lib/relay-daemon/key.pem.tmp` before renaming it into place, so for that
moment the key is readable at a path the list above does not name. The list above gains that
path, for `file.read` and `file.checksum` alike, and the lint's read probes target it, once
`daemon-installation.md` DI-48 and DI-49 are built; until then the list above is what ships.
Writing the key where no rule can reach it, as an unnamed `O_TMPFILE` linked into place, was
weighed and not taken, as the larger change to the key-writing path. A Node whose live Policy
predates the deny keeps its old list until its operator updates it: the package never rewrites a
live Policy (DI-26). Both residuals are threat model R50.
