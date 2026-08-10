# The shipped default Policy pre-allows the read class, with a confidentiality deny-list

A freshly enrolled Node should be fully interrogable with zero Policy authoring: the
AI-agent's dominant workload is observation (ADR-0012), and a default that denies
`system.facts` pushes every evaluation toward authoring friction or — worse — toward
widening Raw Exec. This ADR records the posture of the **shipped default Policy file**
(`daemon/policy.default.toml`), the companion decision ADR-0021 deferred to issue #294.

**Engine semantics are unchanged.** Deny-by-default and deny-beats-allow stand exactly as
ADR-0002 defines them; this decision changes only the *file we ship*, which is an ordinary
locally-rooted Policy the operator owns from the moment it lands on the Node. It *looks*
like it touches invariant #3; it does not — the default is expressed entirely as ordinary
allow and deny rules the engine already evaluates.

## Decisions

- **`read`-class Operations are pre-allowed out of the box.** The shipped file carries an
  allow rule for every `read`-class name in the shipped vocabulary — today the two native
  reads, `system.facts` (no args) and `file.read` (any canonical path). When the v0.2.0
  shipped catalog (ADR-0021) lands, its `read`-class template names join this same file,
  scoped by what they make *reachable* (paths/units/journals), per ADR-0021's data-egress
  governance.
- **A confidentiality deny-list is authoritative over the read pre-allowance.**
  Deny-beats-allow makes the list win even against `file.read "*"`. Applying ADR-0021's
  governance section — `read` means "cannot change Node state", **not** "safe for the AI
  to see"; a read result flows to the model provider, so reading is exfiltration by
  construction — the shipped file denies, in ADR-0018 canonical form:
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
- **`mutate` and Raw Exec stay opt-in.** The shipped file carries no `mutate` allow rules
  and no `[raw_exec]` allow patterns: deny-by-default leaves every state change exactly
  where it was — behind a deliberate, local, human widening act (ADR-0002).
- **The default is a starting point, not a floor.** It is the operator's file the moment
  it is installed: locally-rooted, remotely-immutable, replaced or narrowed through the
  same IaC pipeline as any Policy (docs/operations/policy-as-code.md). Nothing in the
  Relay assumes its presence or shape.

## Recorded residuals (why this list cannot be complete)

Path denies are exact canonical strings (ADR-0018); there is no subtree or wildcard deny.
The list therefore cannot cover unenumerable secrets: `/etc/ssl/private/*` and other
site-specific key files, per-pid `/proc/<pid>/{mem,environ}` aliases, shell histories, or
secrets that land in logs (reachable once the catalog's bounded log tail ships). Two
directions are named, both deferred beyond v0.2.0: the **typed prefix/subtree path
matcher** ADR-0018 already deferred, and **output classification in Policy** — rules
about what results may contain, not only what may run (ADR-0021). Until then, the
egress-conscious operator narrows `file.read`'s allow from `"*"` to an explicit path set;
the default deliberately chooses interrogability with a curated deny-list over shipping a
read posture nobody enables.

## Considered options

- **Ship deny-everything (status quo: no default file).** Rejected: every deployment
  starts with authoring friction on the safe class, and the observed failure mode is
  operators reaching for broad Raw Exec regexes instead — the most dangerous path
  absorbing demand the typed read path should serve.
- **Pre-allow reads by risk class in the engine** (a `class = "read"` allow rule).
  Rejected: that *would* touch invariant #3 and ADR-0012's boundary (risk class is
  blast-radius classification, never a trust classification), and it would make the
  pre-allowance invisible to the exact-rule attribution in `Decision`. The file
  enumerates names instead; the engine stays unchanged.
- **A narrower `file.read` allow-list instead of `"*"` + deny-list.** More restrictive,
  but a default allow-list either blocks the interrogation use case it exists for or
  grows into a distro-specific curated catalog we cannot maintain. Chosen shape:
  wildcard read + authoritative confidentiality deny-list, with the allow-list narrowing
  documented as the operator's egress-hardening move.

## Consequences

- A Node enrolled with the shipped default answers `system.facts` and any
  non-deny-listed `file.read` with zero local authoring; every deny-listed path is
  refused; any `mutate` Operation or Raw Exec is refused until explicitly allowed.
- The file is validated in CI against the real engine: it must parse with the fail-closed
  loader, lint clean (`policy check` semantics), allow the read cases, and deny every
  deny-listed path, all `mutate` natives, and Raw Exec (`daemon/src/policy.rs` tests).
- `#288` (read auditing / output-retention) remains the interlock ADR-0021 named: this
  posture makes reads ubiquitous, so the audit decision governs what those reads leave
  behind.
- The shipped catalog's template allowances (ADR-0021) land in this file with the
  catalog, in the human-merge lane — the default Policy file is Policy surface, always
  reviewed by a person.
