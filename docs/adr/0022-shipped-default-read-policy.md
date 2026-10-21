# The shipped default Policy pre-allows the read class, with a confidentiality deny-list

**Status:** Accepted; amended by ADR-0033; amended 2026-10-16 (of its own files the default hides
only secrets; the lint's read probes stop at secrets).

A freshly enrolled Node should be fully interrogable with zero Policy authoring: the
AI-agent's dominant workload is observation (ADR-0012), and a default that denies
`system.facts` pushes every evaluation toward authoring friction or, worse, toward widening
Raw Exec. This ADR records the posture of the **shipped default Policy file**
(`daemon/policy.default.toml`), the companion decision ADR-0021 deferred to issue #294.

**Engine semantics are unchanged.** Deny-by-default and deny-beats-allow stand as ADR-0002
defines them; only the *file we ship* changes, an ordinary locally-rooted Policy the operator
owns once it lands on the Node. It does not touch invariant #3: the default is expressed
entirely as ordinary allow and deny rules.

## Decisions

- **`read`-class Operations are pre-allowed out of the box.** The shipped file carries an
  allow rule for every `read`-class name in the shipped vocabulary: at the time, the two native
  reads, `system.facts` (no args) and `file.read` (any canonical path). The shipped catalog's
  (ADR-0021) `read`-class template names join this file, scoped by what they make *reachable*
  (paths/units/journals).
- **A confidentiality deny-list is authoritative over the read pre-allowance.**
  Deny-beats-allow makes the list win even against `file.read "*"`. Because a read result flows
  to the model provider (ADR-0021: `read` is **not** "safe for the AI to see"), the shipped file
  denies, in ADR-0018 canonical form:
  - **local credential databases**: `/etc/shadow`, `/etc/gshadow`, and their
    shadow-utility backups `/etc/shadow-`, `/etc/gshadow-`;
  - **host key material**: the standard SSH host private keys
    (`/etc/ssh/ssh_host_{rsa,ecdsa,ed25519,dsa}_key`) and `/etc/krb5.keytab`;
  - **root's default SSH private keys**: `/root/.ssh/id_{rsa,ecdsa,ed25519,dsa}`;
  - **the daemon's own config and credentials** (consistent with the #287
    self-reference lint): `/etc/relay-daemon/policy.toml`,
    `/etc/relay-daemon/relay-daemon.env` (carries the Enrollment Token),
    `/etc/relay-daemon/ca-bundle.pem`, and the Node's identity private key
    `/var/lib/relay-daemon/key.pem`;
  - **kernel/process memory and environment oracles**: `/proc/kcore`, `/dev/mem`,
    `/dev/kmem`, `/proc/self/mem`, `/proc/self/environ` (the daemon's environment
    carries the Enrollment Token on first boot).
- **`mutate` and Raw Exec stay opt-in.** The shipped file carries no `mutate` allow rules and
  no `[raw_exec]` allow patterns, so every state change stays behind a deliberate, local,
  human widening act (ADR-0002).
- **The default is a starting point, not a floor.** It is the operator's file once
  installed: locally-rooted, remotely-immutable, replaced or narrowed through the same IaC
  pipeline as any Policy (docs/operations/policy-as-code.md). Nothing in the Relay assumes its
  presence or shape.

## Recorded residuals (why this list cannot be complete)

Path denies are exact canonical strings (ADR-0018); there is no subtree or wildcard deny.
The list therefore cannot cover unenumerable secrets: `/etc/ssl/private/*` and other
site-specific key files, per-pid `/proc/<pid>/{mem,environ}` aliases, shell histories, or
secrets that land in logs (reachable through the catalog's bounded log tail). Two directions
are named, both deferred beyond v0.2.0: the **typed prefix/subtree path matcher** ADR-0018
deferred, and **output classification in Policy** (ADR-0021). Until then, the egress-conscious
operator narrows `file.read`'s allow from `"*"` to an explicit path set; the default
deliberately chooses interrogability with a curated deny-list over a read posture nobody
enables.

## Considered options

- **Ship deny-everything (no default file).** Rejected: every deployment starts with
  authoring friction on the safe class, and operators reach for broad Raw Exec regexes
  instead, the most dangerous path absorbing demand the typed read path should serve.
- **Pre-allow reads by risk class in the engine** (a `class = "read"` allow rule). Rejected:
  that *would* touch invariant #3 and ADR-0012's boundary (risk class is a blast-radius
  classification, never a trust classification), and would hide the pre-allowance from the
  exact-rule attribution in `Decision`. The file enumerates names instead.
- **A narrower `file.read` allow-list instead of `"*"` + deny-list.** More restrictive, but a
  default allow-list either blocks the interrogation it exists for or grows into a
  distro-specific catalog we cannot maintain. Chosen: wildcard read + authoritative
  confidentiality deny-list, with allow-list narrowing documented as the operator's
  egress-hardening move.

## Consequences

- A Node enrolled with the shipped default answers `system.facts` and any
  non-deny-listed `file.read` with zero local authoring; every deny-listed path is
  refused; any `mutate` Operation or Raw Exec is refused until explicitly allowed.
- The file is validated in CI against the real engine: it must parse with the fail-closed
  loader, lint clean (`policy check` semantics), allow the read cases, and deny every
  deny-listed path, all `mutate` natives, and Raw Exec (tests in
  `daemon/crates/relay-policy/src/lib.rs` and `daemon/tests/default_policy_strict.rs`).
- `#288` (read auditing / output-retention) is the interlock ADR-0021 named: this posture
  makes reads ubiquitous, so the audit decision governs what they leave behind.
- The default Policy file is Policy surface: changes to it, including the catalog's template
  allowances, are always reviewed by a person.

## Amendment (2026-08-10, issue #293): the shipped read catalog, and three more denied paths

The shipped file also allows the seven `read` Template Operations of the first-party catalog
(ADR-0021, #293) and mirrors the confidentiality deny-list onto `file.checksum`: a digest is a
content oracle, so every path denied to `file.read` is denied to it. A Policy rule never
creates vocabulary: on a Node without the pack these rules are inert and dispatch reports
`unsupported`.

Pointing the self-reference lint (#287) at this file surfaced three paths the original list
missed, now denied: `/var/lib/relay-daemon/cert.pem`, `/usr/local/bin/relay-daemon`, and
`/etc/systemd/system/relay-daemon.service`.

**Recorded residual, unchanged in kind:** the template files under
`/etc/relay-daemon/templates.d/` cannot be denied by exact path (their names are whatever the
installed packs use, and Policy has no subtree deny). With `file.read`'s `"*"` allow, the
AI-agent can read a Node's template files, disclosing its vocabulary but never changing them
(ADR-0002/0021). `policy check --strict` reports this rather than the file being tuned to
silence its own linter; the remedy is an explicit `file.read` path allow-list.

## Amendment (2026-10-15): amended by ADR-0033 — the self-reference denies follow the packaged paths

Owner decision, 2026-10-15, recorded in ADR-0033's amendment of that date. The relay-daemon
installs from an OS package, and packaged and hand-built installs share one binary path,
`/usr/bin/relay-daemon`, with the packaged unit under `/usr/lib/systemd/system/`. The shipped
default's self-reference denies, and the lint that checks a Policy against them, cover the
binary and unit at those paths, and keep covering `/etc/systemd/system/relay-daemon.service`
and the drop-in `systemctl edit` writes,
`/etc/systemd/system/relay-daemon.service.d/override.conf`, by exact path: an override of the
packaged unit lives there, and writing one removes the hardening as surely as editing the unit.
A drop-in under any other name is the same recorded residual as the Template directory's files.

A Node moved from a hand-built install onto the package keeps its live Policy, which the package
never rewrites, so its denies still name `/usr/local/bin`. The documented migration removes the
old binary and the old unit under `/etc/systemd/system/` (which would otherwise shadow the
packaged one) and says to update the Policy's self-reference denies by hand. Everything else
this ADR decides is unchanged.

## Amendment (2026-10-16): the default hides secrets; the lint's read probes stop at secrets

Owner decision, 2026-10-16. Recorded on ADR-0021's page the same day, since ADR-0021 owns the
self-reference lint's probe set. This amendment supersedes four things above: the Decision's
deny of the daemon's own Policy file and CA bundle "consistent with the self-reference lint";
the 2026-08-10 amendment's denies of the identity certificate, the binary at `/usr/local/bin` and
the unit under `/etc/systemd/system/`; the 2026-08-10 stance that
`policy check --strict` must keep reporting the template root as a residual; and the
2026-10-15 amendment's rule that the shipped default denies reading the binary, the unit and
the unit's override files. The Decision's posture — read pre-allowed, a confidentiality
deny-list authoritative over it, `mutate` and Raw Exec opt-in — is unchanged, and so is the
deny of every non-daemon secret the Decision lists.

**What changed in the reasoning.** The deny-list's purpose is confidentiality (ADR-0021). That
argument carries no weight for a file whose reader already holds it, and little for one that
holds no secret. The daemon's binary and unit are public release artifacts, reproducible and
listed in `SHA256SUMS`; its Policy is reported whole to the Relay in the Policy view
(`query.md`); its CA bundle is the Relay's own CA certificate and its identity certificate is
presented on every connection; the shipped catalog's Template files are a public package. The
override unit and a drop-in are operator-authored and not reported, but they hold a privilege
posture, not a secret. Denying these reads hid nothing of value, and the one path the default
could never deny exactly — the template root — left the shipped file permanently failing its
own strict check.

**Decisions.**

- **Of the daemon's own files, the shipped default denies reading only those that carry a
  secret:** the Node's identity private key and the environment file (the Enrollment Token or
  join string), with the daemon's environment oracle (`/proc/self/environ`) beside them. Every
  path so denied for `file.read` is denied for `file.checksum` (the 2026-08-10 rule stands).
  The daemon's Policy, CA bundle, identity certificate, binary, unit, override unit, drop-ins
  and the shipped catalog's Template files are not denied.
- **The self-reference lint separates reading from writing, and reads stop at secrets** —
  the ADR-0021 amendment of this date holds the probe set. Reading a file that holds no secret
  is never a finding.
- **`policy check --strict` passes on the shipped default**, with the shipped catalog loaded.
  The file is still not tuned to silence its linter: the template root stopped being a finding
  because the lint does not object to reading a Template, not because a probe was bent around
  it. A shipped default that fails its own strict check trains operators to ignore the check.
  Without `--templates`, the catalog's names are unknown-name findings that `--strict` fails
  (ADR-0021, 2026-08-10, *Also decided*), so the check runs with the catalog's template root.
- **Operator-authored Template bodies are a recorded residual, not a secret.** They never
  travel as Template metadata: no RPC carries a body, and drift visibility stays
  fingerprint-only (ADR-0021). Whether a `file.read` Task may return one is a Policy question
  the operator answers, and the shipped default's wildcard answers yes. That is
  `docs/security/threat-model.md` **R37**; the remedy is the one this ADR has always named,
  an explicit `file.read` allow-list in place of the wildcard.

**Residuals.** The lint's write probes are concrete actions against named paths, and absence of
a finding is not proof of unreachability (ADR-0021). A drop-in under any name but
`override.conf`, a Policy fragment in the Policy directory, or a Template or state-directory
file under a name the probes do not try, is reachable by a Raw Exec allow the lint does not
flag: **R38**. The operator's control is a Raw Exec deny pattern over those directories
(ADR-0019). The hardened unit's mount namespace refuses writes under `/etc` and `/usr` unless an
operator drop-in relaxes it (`daemon-installation.md`, DI-3, DI-5), but not writes to the state
directory, which the daemon owns. The state-directory files the probes name (identity key and
certificate, CA bundle, persisted address) are named because a Raw Exec allow is the only thing
between them and an overwrite that changes the Node's identity or trust root. The lint is
defense-in-depth under that boundary. One change to the 2026-10-15 migration paragraph: the
hand update to a migrated Node's Policy removes the denies for the old binary and unit paths,
which the shipped default no longer carries, rather than re-pointing them.

**Consumers.** `daemon-installation.md` (DI-28, DI-39, DI-40; DI-4 and DI-41 retired);
`query.md` QRY-10; `docs/security/threat-model.md` R37 and R38; the v0.6.5 design plan, step
S12; `policy-as-code.md` and `template-packs.md` where they describe what the lint probes; the
shipped `daemon/policy.default.toml` and its comments.

## Amendment (2026-10-21): distribution-default TLS private keys

Owner decision, 2026-10-21, made while reviewing what the first release freezes. The
confidentiality deny-list adds the two TLS private keys that sit at a fixed path on a stock
install: `/etc/ssl/private/ssl-cert-snakeoil.key`, which Debian and Ubuntu's `ssl-cert` package
generates, and `/etc/pki/tls/private/localhost.key`, which the RHEL family's `mod_ssl` generates.
Both are denied for `file.read` and, under the 2026-08-10 rule, for `file.checksum`. The
Decision's posture is unchanged.

**Residual, unchanged in kind.** A site's own keys (`/etc/letsencrypt/live/<name>/privkey.pem`,
other files under `/etc/ssl/private/` or `/etc/pki/tls/private/`) have no fixed path, and Policy
has no subtree deny, so the shipped default still cannot deny them. The remedies are the ones
this ADR has always named: deny them by exact path, or narrow `file.read`'s `"*"` to an explicit
path allow-list. A subtree deny is tracked as its own change.

**Consumers.** The shipped `daemon/policy.default.toml` and the deny-list test in
`relay-policy` that pins it to this ADR. No spec or threat-model row enumerates the list.

