# A local Template tier, a shipped read catalog, and a frozen native vocabulary

**Status:** Accepted; amended by ADR-0042; amended 2026-10-14 (slot values as positional
parameters, #974); amended 2026-10-15 (slots only at the top level; a narrower `path`, #977);
amended by ADR-0033; amended 2026-10-16 (the self-reference lint's read probes stop at secrets).

Template **execution** is separable from template **distribution** (owner decision
2026-08-03, issue #266). ADR-0001 defined tier 2, **Template Operations** (operator-authored
shell templates with typed parameters), but sequenced it behind operator-signed distribution.
That coupling was unnecessary: a template loaded from a local, root-owned file beside
`policy.toml` shares Policy's trust root (ADR-0002, unchanged), and a catalog shipped **inside
the daemon package** is trusted the way the binary is: you installed it. This ADR realizes
tier 2 without signing; signing and courier distribution of the same objects come later. The
default read Policy that makes the shipped catalog usable out of the box is a **companion
decision** (#294, ADR-0022).

## Decisions

- **Template tier semantics (realizes ADR-0001 tier 2).** A Template Operation is an
  operator-authored shell template with **named, typed-validated parameter slots**. The
  trusted author fixes the command structure; the caller supplies only parameter values.
  **Substitution can never alter command structure**: each parameter is validated against its
  slot's declared type and fills exactly the lexical position the author wrote, never adding
  words, operators, redirections, or expansions. A **`risk_class` (`read` | `mutate`) is
  mandatory** (ADR-0012); a template without one fails to load. **Policy governs templates
  exactly like Native Operations**: deny-by-default, deny-beats-allow, argument-level
  constraints, with the template's name in the same Policy vocabulary. **The shell boundary
  is treated as hostile**: per-parameter validation and quoting mitigate the tier's residual
  risk (parameter injection, per ADR-0001), and a **red-team suite** of parameter-injection
  attempts against the substitution boundary is an **acceptance criterion of the milestone,
  not a follow-up**. Findings become regression tests.
- **Local loading, same trust root.** Templates load from root-owned files beside
  `policy.toml`; changing them requires local or out-of-band access (config management, SSH),
  never the wire. ADR-0002 applies verbatim: the Relay can query but never modify a Node's
  template set. A directory of templates installed and versioned as a unit is a **template
  pack**.
- **Fingerprint and discovery.** The daemon reports a **template-set fingerprint** beside the
  Policy fingerprint (in `Hello` and every snapshot), and the registry records it: fleet-wide
  drift visibility without the templates traveling. Because the vocabulary is now
  **per-Node**, `list_operations`/`describe_node` expose each Node's effective vocabulary, and
  dispatching a template a Node has not loaded yields a **distinct `unsupported` per-Node
  outcome**: not a failure, not a Policy deny, since the Node was never asked to decide.
- **Shipped read catalog.** A first-party template pack installed with the daemon package:
  **process list, service status, disk/mount usage, listening ports, package inventory,
  bounded log tail, file checksum**, all `read` class. It replaces a planned batch of native
  read Operations: the catalog is the tier's first customer, so its safety machinery is proven
  on templates we ship before operators author their own.
- **Native-vocabulary freeze.** The Native Operation vocabulary is **frozen at the current
  four**. `system.facts` and `file.read` stay native as platform intrinsics (facts feeds
  the registry; `file.read` carries the ADR-0018 canonical-path matching and
  resolved-target re-check, which needs executor-level descriptor access no template has).
  `service.restart` and `pkg.install` are grandfathered. **New vocabulary = templates.**
- **Prerequisite: one registry lookup (#289).** The vocabulary goes behind a single
  **name → (handler, arg-shape, risk-class)** lookup, so the template tier **registers**
  Operations instead of adding dispatch match arms, and validation, Policy evaluation, and
  discovery read one source of truth. The ADR-0015 golden schema pins the frozen native
  vocabulary; per-Node template vocabularies are discovered live.
- **Data-egress governance (owner review 2026-08-04).** `read` means "cannot change Node
  state", **not** "safe for the AI to see". A read result flows to the model provider, so
  reading is exfiltration by construction (PII in logs, secrets in configs). The shipped
  catalog is governed by what it makes **reachable**, not by an `/etc/shadow` deny-list alone:
  the log tail reads whatever secrets land in logs, and the file checksum is a content oracle
  over any path Policy lets it touch. The shipped default Policy (#294) must scope these, and
  **output classification in Policy** (rules about what results may contain, not only what may
  run) is the long-term direction, deferred beyond v0.2.0.
- **Default read Policy posture is #294's companion ADR:** read pre-allowed with a
  confidentiality deny-list; `mutate` and Raw Exec stay opt-in; engine semantics unchanged.

## Considered Options

- **Keep the tier coupled to signing.** Rejected: the trust argument for a local root-owned
  file is ADR-0002's, already made; signing adds distribution reach, not execution trust.
  Waiting keeps Raw Exec as the only extensibility valve for two more milestones.
- **Keep growing the native vocabulary instead.** Rejected: every addition is Rust in the
  privileged exec path plus a fleet-wide daemon release (ADR-0014), so the vocabulary grows at
  release cadence, centrally chosen, while the fleet-specific long tail stays on Raw Exec, the
  most dangerous path.
- **Templates as centrally-expanded Raw Exec** (the Relay substitutes parameters and sends
  Raw Exec). Rejected: the daemon would see only a command string, with no typed validation
  at the enforcement boundary, no argument-level Policy, and the trusted-author property
  enforced by the untrusted side. It collapses tier 2 into tier 3.
- **Argv-only templates (no shell).** Safest boundary, but the gap templates exist to close
  *is* shell composition (pipes, filters, redirection); argv-only is a native Operation
  authored in TOML. Rejected in favour of a hostile-shell posture: validation, quoting,
  red-team.

## Consequences

- ADR-0001's tier 2 gets its promised ADR; tiers 1 and 3 are unchanged, and the ordering by
  trust holds: a template is safer than Raw Exec *because* a trusted local author fixed the
  structure. ADR-0002 is unchanged.
- The template loader and substitution engine are exec-path security surface: human-merge
  lane, always, and the red-team suite gates the milestone.
- The Operation vocabulary stops being fleet-uniform. Surfaces and the AI-agent treat it as
  per-Node (`list_operations`/`describe_node`), and the Job engine gains the `unsupported`
  outcome (a `/proto` change, contract-first).
- The registry, `describe_node`, and the Console carry the template-set fingerprint beside
  the Policy fingerprint; a template rollout is confirmed like a Policy rollout (ADR-0002).
- `policy check` grows template linting, and the self-reference lint (#287) warns when an
  allow rule's reach includes the daemon's own config, binary, or unit, now including the
  template files (a rule that can rewrite templates is self-modifying Policy).
- The AI-agent may *draft* templates, but nothing loads until a root-owned file lands on the
  Node out-of-band (and, once signing exists, until an operator signs the bundle). The
  widening act stays human, as for Policy.
- #288 (read auditing / output-retention) must be decided before the catalog makes reads
  ubiquitous; the data-egress section above is its motivation.
- GLOSSARY.md gains **Template Operation** and **template pack** in the same change.

## Amendment (2026-08-10, issue #292 / #287): the self-reference lint, and no daemon-side floor

#287 proposed two defenses against an allow rule whose reach includes the daemon's own trust
root ("letting the wire rewrite the wire's own gate"). This records the outcome.

**Adopted — the lint.** `relay-daemon policy check` always runs a self-reference lint. It does
**not** parse allow patterns or reason about what a regex "means": it builds concrete probe
actions against the daemon's own paths (Policy file, template root, state dir with identity
key and cert, binary, systemd unit) and evaluates each through the **real** Policy engine
(`Policy::evaluate` / `evaluate_raw_exec`). A finding is proof that the exact probed action
would be allowed on that Node, deny-beats-allow is honoured for free, and there is no second
matcher to drift (ADR-0011). Findings are `Warning`s; `--strict` fails on them. Absence of
findings is **not** proof of unreachability: the probes cover the plausible shapes
(edit-in-place, overwrite, copy/move over, delete, redirect, chmod, symlink, read), not every
command.

**Rejected — the hardcoded daemon-side deny floor.** #287's second half proposed that the
daemon always deny operations targeting its own config directory, regardless of Policy.
Rejected because:

1. **It is the mechanism we already know is bypassable.** ADR-0018 and ADR-0019 each had to
   harden a path-string match after a bypass; a third path-matching surface in the privileged
   exec path buys more confidence than strength.
2. **It cannot distinguish read from rewrite.** The daemon sees an argv, not an intent. A
   floor wide enough to stop `sed -i` also blocks a legitimate `file.read` of `policy.toml`
   for audit, which the shipped read catalog and the dev fleet both do.
3. **It would silently override an explicit operator allow.** A hidden rule that beats an
   explicit allow is a surprise in the one place surprises are least acceptable, with no
   expression in the Policy file an operator reads.
4. **The real boundary is the filesystem, and it already holds.** Root-owned files plus
   `ProtectSystem=strict` make `/etc` read-only inside the daemon's mount namespace
   (`docs/operations/daemon-privilege-posture.md`). The floor adds nothing on a hardened Node,
   and on an unhardened one is a bypassable veneer over a deployment problem the lint names.

The lint is defense-in-depth **under** the mount-namespace protection, placed where the
foot-gun is created (the IaC pipeline) rather than in the privileged exec path. If a
deployment mode weakens the filesystem boundary, revisit the floor in its own ADR, with a
mechanism that is not path-string matching.

**Also decided here:** with a per-Node vocabulary, `policy check` cannot tell a Template
Operation from a typo unaided. An unrecognized Operation name is an `Error` only when the
caller supplied a template root (`--templates`); otherwise it is a `Warning` that names the
fix. `--strict` fails on it either way.

## Amendment (2026-10-02): amended by ADR-0042 — how the Relay calls a Template

This ADR made the vocabulary per-Node and built the daemon half, but never said how the Relay
dispatches a Template. ADR-0042 settles it: a Template is dispatched by name through the
capability layer on every execution surface. Nodes that do not report it, or for which the Relay
holds no report, are excluded as `unsupported` before the class, cap and approval gate are
decided; the class is the most restrictive the remaining Nodes report; argument names are
checked against every remaining Node's slots. The per-Node vocabulary cache becomes a dispatch
input. Template loading, rendering, quoting and Policy parity are unchanged.

## Amendment (2026-10-14, #974): slot values travel as positional parameters, never as shell text

The property this ADR decided is unchanged: **substitution can never alter command
structure**. The mechanism changes, because "validation + quoting" was shown not to hold.

**What failed.** A slot value was validated, single-quoted, spliced into the body, and run as
`/bin/sh -c <text>`. Single quotes protect a value only where the shell reads them as quotes,
and inside a here-document, a backquoted or `$( … )` substitution, or after an escaped space,
it does not. #974 reproduced each against dash: a value of `/tmp/$(cmd)` ran `cmd` from inside
a here-document. `/bin/sh` differs per distribution (dash, bash, busybox), and #975's attempt
to refuse every unsafe construct at load was found incomplete by three review passes in turn
(`$'…'`, `alias`, `BASH_ALIASES`, `((`, `name[…]`). A denylist checked against a shell grammar
cannot be shown complete, so the defect is the mechanism, not a missing entry.

**The threat this answers.** A prompt-injected AI-agent chooses every slot value. Policy, the
blast cap and approval bound *which* Template it may call and where; the mechanism below bounds
what a value can do once the call is allowed.

### Decisions

1. **A slot value is never shell text.** Where a Template body runs through a shell, the text
   the shell parses is the author's body with each placeholder replaced by a fixed, quoted
   reference to a positional parameter (`{{path}}` becomes `"$1"`), and the slot values are
   passed as separate arguments after it. A placeholder still stands alone as a
   whitespace-delimited token outside any quotes, so a value is never glued to the author's
   text. The parsed text is a function of the Template definition alone, identical for every
   call, and a value enters only at expansion, after the shell has fixed the command's
   structure. A shell never re-parses an expanded parameter for syntax, and the quotes stop
   field splitting and globbing, so a value is exactly one word, byte for byte, in every POSIX
   shell. This holds inside here-documents, substitutions and conditionals alike, so **authors
   keep the full shell**: no construct is refused for being near a slot, beyond the
   standalone-token rule. The single-quoting path and #975's construct denylist are not
   adopted.
2. **A slot fills only a data position.** No mechanism can stop a command the author chose
   from deliberately turning its argument back into code. A Template is therefore a **Policy
   error** (the whole Policy is then `invalid` and the Node denies every Task; `policy check`
   reports it before deploy) where a placeholder stands in a position, decidable from the body
   alone, that executes its value: the command-name position of a simple command; the operand
   of `eval`, `.` or `source`; the argument after `-c` (or an interpreter's equivalent program
   flag) of a recognised shell or interpreter; and arithmetic contexts (`(( … ))`, `$(( … ))`,
   `let`), which some bash versions re-evaluate. Code positions not reliably decidable from the
   body (an `awk` or `sed` program, `find -exec`, `xargs` feeding a shell, an option that takes
   a program such as `tar -I` or `rsync -e`) are a `policy check` **warning**, which `--strict`
   fails. The two lists live in `operations-and-templates.md` and grow there.
3. **No value is an option.** No well-formed value of a daemon-owned slot type can begin with
   `-` (an `identifier` begins alphanumeric, a `path` begins `/`, an `integer` is digits), and
   an `enum` value is a literal the author chose. A slot type added later keeps that property
   or its spec says why not. With decision 1, a value can neither become an option nor be
   glued onto one.
4. **The `path` type is not narrowed further** (owner decision, 2026-10-14). It refuses C0
   controls and DEL, but may carry characters a human cannot see or a terminal interprets (C1
   controls, zero-width and invisible characters, Unicode whitespace, bidirectional controls).
   Decision 1 makes them inert to the shell; what remains is deceiving a reader. So wherever a
   slot value or any Node-derived string is shown to a human (the Console, approval prompts,
   audit views, log lines), those characters are made visible, never raw. The specs of those
   surfaces own that (#979).
5. **Raw Exec gets a tool, not a floor.** `relay-daemon policy check` gains a probe-based
   interpreter lint like the self-reference lint above: interpreter- and wrapper-shaped argvs
   (`sh -c`, `env`, `xargs`, `nice`, `timeout`, `sudo`, `setsid`, `nohup`, `python -c`,
   `perl -e`, `find -exec`, …) are evaluated through the real Policy engine, and an Allow is a
   `Warning` that `--strict` fails. It never changes what the daemon runs. Threat model R4
   stays accepted, now tooled (#978).
6. **Node output is an injection source, and is a separate track.** Everything above stops a
   compromised AI-agent doing more than it was allowed. Node output reaching the AI-agent (a
   log line, a file, a package description) is how one *becomes* compromised. That is decided
   separately (#980: an untrusted-data envelope on every result an AI-agent receives, beside
   the output-classification direction named above).

### Considered options

- **Keep single-quoting and refuse unsafe constructs (#975).** Rejected: shown incomplete by
  three consecutive reviews, breaks safe author Templates, and needs a new entry whenever a
  shell grows a construct.
- **Allow only a restricted grammar in bodies that have slots.** Provable, but removes the shell
  composition this tier exists to provide (the reason "argv-only templates" was rejected above).
- **Pin the shell** (always dash, or a vendored one). Narrows the grammar to defend but keeps a
  denylist, and dash is not installed by default on every supported distribution.
- **Positional parameters** (chosen): the attacker contributes no bytes to the parsed text, so
  the defence does not depend on knowing any shell's grammar.

### Consequences

- **Invariant 1 is amended** to state the property decision 1 guarantees outright, "no slot
  value ever part of the text the Template's shell parses", rather than a mechanism ("with
  every slot single-quoted" is retired). Decision 2 is deliberately **not** in the invariant:
  it can only be partly enforced, so it is defence in depth stated here and in the spec, and
  the invariant stays a claim the code can fully meet.
- #975 is closed unmerged; its reproduced cases become the red-team suite of the implementing
  change (#977).
- The rendered command changes shape (`sh -c <body> relay-template <v1> <v2> …`). Policy is
  unaffected, since it already matches the raw slot values, and the audit record carries the
  values beside the body rather than inside it.
- A property becomes testable outright: the parsed text is identical for all values of a call.
  A `template_render` fuzz target (#897) is to assert exactly that.
- **Residual risk**, accepted: an author who passes a slot to a code-running position that
  decision 2 cannot detect; a program's own parsing of a well-formed argument (as ever, out of
  scope); and Node output steering the AI-agent until decision 6's track lands.

## Amendment (2026-10-15, #977): slots stand only at the top level, and `path` is narrower

Owner decisions, 2026-10-15, taken while implementing the 2026-10-14 amendment. They narrow two
of its decisions; decision 1's mechanism, positional parameters, is unchanged.

**What was found.** Three adversarial review passes on the implementing change each reproduced
bodies the load-time lexer accepted while the shell read them differently: a `case` pattern
closing a substitution early, `$((` that is a command substitution, bash's `$[ ]`, backquote
backslash rules, keyword-splitting line continuations, and a placeholder one substitution deep
inside arithmetic or a parameter expansion. Positional parameters kept every value out of the
parsed text, but a value in a nested context can still be re-split by an unquoted outer
substitution or re-evaluated by bash's arithmetic, and a `path` value carrying spaces, `$`, `[`
and `(` was the payload each time. Modelling more shell grammar is the rejected denylist again,
in a new place.

### Decisions

1. **A slot stands only at the top level** (narrows the 2026-10-14 decision 1's "authors keep
   the full shell around a slot"). A placeholder is accepted only as a standalone word of a
   command in the body's top-level list — a simple command, a pipeline, or an `&&` / `||` / `;`
   list. A placeholder inside a command or process substitution, a parameter expansion, any
   arithmetic context, a here-document or here-string, quotes, `[[ ]]` or a `case` pattern is a
   Template compile error. Authors keep the full shell elsewhere in the body; only where a slot
   may stand is restricted. The load-time refusals that keep the lexer's frame tracking honest
   (backquote substitutions, joining line continuations, unterminated constructs, constructs it
   cannot analyse) stay, and apply when the body carries a placeholder.
2. **`path` refuses whitespace and shell metacharacters** (reverses the 2026-10-14 decision 4's
   "not narrowed further"). Beyond starting with `/` and refusing C0 controls and DEL, a `path`
   value refuses any whitespace and each of these characters: `$`, `` ` ``, `\`, `"`, `'`,
   `;`, `|`, `&`, `<`, `>`, `(`, `)`, `{`, `}`, `[`, `]`, `*`, `?`, `!`, `#`, `~`, `=`. A path
   a Template cannot address is reached by a Native Operation or Raw Exec, where Policy
   governs it as before. Decision 4's rendering obligation for invisible and bidirectional
   characters (#979) is unchanged.
3. **How decision 2's refusals and warnings land** (completes the 2026-10-14 decision 2):
   - A placeholder in a decidable code-running position is a Template compile error like every
     other: the Node's template set becomes `unloadable`, Native Operations keep running, and
     `policy check` exits 1. It does not invalidate the Policy or deny every Task.
   - The operand of `exec`, `command` or `builtin` is a command-name position.
   - A body whose own text routes slot values into code (the author's `$1`… `$@` `shift`
     `set --`, a placeholder inside a function body, alias definitions, a placeholder among
     `trap`'s operands, or `.`/`source` passing positional parameters on) is a `policy check`
     **warning**, which `--strict` fails. An operator who deliberately writes a script that
     turns an argument back into code is exercising their own authority over the Node.

### Consequences

- Two layers now hold the one-word property independently: where a slot may stand, and what a
  `path` value may contain. A lexer miss leaves a value that carries no metacharacters, and a
  metacharacter-free value cannot split, become an option, or carry a subscript.
- Templates that placed a slot in a nested context, or relied on paths containing spaces or the
  refused characters, stop loading or refuse those values after upgrade.
- Invariant 1 is unchanged: these decisions strengthen how it holds, not what it states.

## Amendment (2026-10-15): amended by ADR-0033 — the shipped read catalog is its own package

Owner decision, 2026-10-15, recorded in ADR-0033's amendment of that date. The **Shipped read
catalog** decision said the catalog is "installed with the daemon package". It now ships as its
own optional package, which depends on the daemon package.

**Why.** A Template changes what may run on a Node. Installing the daemon should give a Node
its engine and its default Policy; offering the catalog's Templates is a choice the operator
makes, not a side effect.

**What is kept.** The catalog is first-party content trusted the way the binary is, so its
files are **package-owned**: replaced on upgrade, removed with the package, never the
operator's to edit. An operator who wants a variant defines their own Template under another
name. Its contents, `read` class and role as the tier's first customer are unchanged.

**What is added.** Because the shipped default allows the catalog by name, a package-owned file
replaced on upgrade could change what an already-allowed name does on every Node at once, the
unauthored fleet-wide change ADR-0033 decision 4 exists to prevent. So a released catalog
Template's name is bound to its body and risk class: a change to either ships under a new name,
and CI refuses a release that changes a released one. Withdrawing a released name is allowed,
because it only reduces what may run; that is how an unsafe Template is retired.

## Amendment (2026-10-16): the self-reference lint's read probes stop at secrets

Owner decision, 2026-10-16, taken with ADR-0022's amendment of the same date, which records
why. This amends the 2026-08-10 amendment's probe set; everything else there stands.

**The probe set is split by what a finding would mean.**

- **Read probes** (`file.read`, `file.checksum`, and any supplied path-taking Template
  Operation) target only the daemon's secret-bearing files: the identity private key and the
  environment file. A read of the Policy file, the template root, the identity certificate,
  the CA bundle, the binary or the unit is never a finding: those files hold no secret, and
  most are already in the Relay's hands or public. The running binary at the path the check
  runs from gets a write probe only, so the check answers the same from a CI checkout as from
  `/usr/bin`.
- **Write probes** (the Raw Exec shapes: edit-in-place, overwrite, copy or move over, delete,
  redirect, chmod, symlink) target the daemon's whole trust root at the packaged paths, each
  by exact path: the Policy file and the Policy directory; the environment file; the state
  directory's identity key and certificate, CA bundle and persisted address; the template
  root; the binary at `/usr/bin/relay-daemon`; the unit at
  `/usr/lib/systemd/system/relay-daemon.service`; the override unit at
  `/etc/systemd/system/relay-daemon.service` and the `override.conf` drop-in `systemctl edit`
  writes. That is the case the lint exists for: a rule that lets the wire rewrite the wire's
  own gate.

**Template bodies and the wire.** "Drift visibility without the templates traveling" is
unchanged: no RPC carries a Template body; the Relay learns names, risk classes and a
fingerprint. A `file.read` Task returning a Template file is a read result like any other,
governed by Policy. The shipped default's wildcard permits it, recorded as
`docs/security/threat-model.md` **R37** rather than as a lint finding the shipped file could
never clear. The remedy is ADR-0022's: narrow the wildcard.

**Residual.** The write probes are concrete actions against named paths, and absence of a
finding is not proof of unreachability, as the 2026-08-10 amendment says; names the probes do
not try are **R38** (ADR-0022, this date), and a Raw Exec deny pattern over a directory is the
operator's control (ADR-0019).
