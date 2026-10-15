# A local Template tier, a shipped read catalog, and a frozen native vocabulary

**Status:** Accepted; amended by ADR-0042; amended 2026-10-14 (slot values as positional
parameters, #974); amended 2026-10-15 (slots only at the top level; a narrower `path`, #977);
amended by ADR-0033.

Template **execution** is separable from template **distribution** (owner decision
2026-08-03, issue #266). ADR-0001 defined tier 2 — **Template Operations**, operator-authored
shell templates with typed parameters — but sequenced it behind operator-signed distribution
(v0.8.0). That coupling was unnecessary: a template loaded from a local, root-owned file
beside `policy.toml` shares Policy's trust root (ADR-0002 unchanged — locally-rooted,
remotely-immutable), and a catalog shipped **inside the daemon package** is trusted the way
the binary is: you installed it. This ADR realizes tier 2 without signing; v0.8.0 shrinks to
signing + courier distribution of the same objects. The default read Policy posture that
makes the shipped catalog usable out of the box is a **companion decision** (#294, its own
short ADR), referenced but not specified here.

## Decisions

- **Template tier semantics (realizes ADR-0001 tier 2).** A Template Operation is an
  operator-authored shell template with **named, typed-validated parameter slots**. The
  trusted author fixes the command structure; the caller supplies only parameter values.
  **Substitution can never alter command structure**: each parameter is validated against
  its slot's declared type/constraints and then substituted such that it fills exactly the
  lexical position the author wrote — a value can never add words, operators, redirections,
  or expansions. A **`risk_class` (`read` | `mutate`) is mandatory** on every template
  (ADR-0012); a template without one fails to load. **Policy governs templates exactly like
  Native Operations**: deny-by-default, deny-beats-allow, argument-level constraints on
  parameters — the template's name enters the same Policy vocabulary, and a Policy rule for
  it is written no differently. **The shell boundary is treated as hostile**: per-parameter
  validation and quoting are the mitigation for the tier's residual risk (parameter
  injection, per ADR-0001), and a **red-team suite** — adversarial parameter-injection
  attempts against the substitution boundary, in the tradition of the v0.0.8 Raw Exec
  red-team — is an **acceptance criterion of the milestone, not a follow-up**. Findings
  become regression tests.
- **Local loading, same trust root.** Templates load from root-owned files beside
  `policy.toml`; changing them requires local or out-of-band access (config management,
  SSH), never the wire — ADR-0002's model applies verbatim, and the Relay can query but
  never modify a Node's template set. A directory of templates installed and versioned as a
  unit is a **template pack** (the convention the shipped catalog and future first- or
  third-party packs follow).
- **Fingerprint and discovery.** The daemon reports a **template-set fingerprint** beside
  the Policy fingerprint (in `Hello` and every snapshot); the registry records it —
  fleet-wide template drift visibility without the templates traveling, the exact
  Policy-fingerprint mechanism reused. Because the vocabulary is now **per-Node**,
  `list_operations`/`describe_node` expose each Node's effective vocabulary, and dispatching
  a template a Node has not loaded yields a **distinct `unsupported` per-Node outcome** —
  not a failure, not a Policy deny: the Node was never asked to decide.
- **Shipped read catalog.** A first-party template pack installed with the daemon package:
  **process list, service status, disk/mount usage, listening ports, package inventory,
  bounded log tail, file checksum** — all `read` class. This absorbs the old v0.7.0 native
  read-Op batch: the catalog is the tier's own first customer, so its safety machinery is
  proven on templates we ship before operators author their own.
- **Native-vocabulary freeze.** The Native Operation vocabulary is **frozen at the current
  four**. `system.facts` and `file.read` stay native as platform intrinsics (facts feeds
  the registry; `file.read` carries the ADR-0018 canonical-path matching and
  resolved-target re-check, which needs executor-level descriptor access no template has).
  `service.restart` and `pkg.install` are grandfathered. **New vocabulary = templates.**
- **Prerequisite: one registry lookup (#289, in flight in parallel).** The vocabulary goes
  behind a single **name → (handler, arg-shape, risk-class)** lookup (architecture review
  2026-07-07, candidate 3), so the template tier **registers** Operations instead of adding
  dispatch match arms, and validation, Policy evaluation, and discovery read one source of
  truth. The ADR-0015 golden schema continues to pin the (frozen) native vocabulary;
  per-Node template vocabularies are discovered live, not golden-pinned.
- **Data-egress governance (owner review 2026-08-04).** `read` means "cannot change Node
  state" — it does **not** mean "safe for the AI to see". A read result flows to the model
  provider: reading is exfiltration by construction (PII in logs, secrets in configs). The
  shipped catalog is therefore governed by what it makes **reachable**, not by an
  `/etc/shadow` deny-list alone: the bounded log tail reads whatever secrets land in logs,
  and the file checksum is a content oracle over any path Policy lets it touch. The shipped
  default Policy (#294) must scope these accordingly (paths/units/journals reachable by
  default), and **output classification in Policy** — rules about what results may contain,
  not only what may run — is named as the long-term direction, deferred beyond v0.2.0.
- **Default read Policy posture is #294's companion ADR.** Read pre-allowed out of the box
  with a confidentiality deny-list; `mutate` + Raw Exec stay opt-in whitelist; engine
  semantics unchanged. Recorded and specified there, not here.

## Considered Options

- **Keep the tier coupled to signing (status quo sequencing, old v0.8.0).** Rejected: the
  trust argument for a local root-owned file is ADR-0002's, already made — signing adds
  distribution reach, not execution trust. Waiting keeps Raw Exec as the only extensibility
  valve for another two milestones, against ADR-0001's own intent.
- **Keep growing the native vocabulary instead.** Rejected: every addition is Rust in the
  privileged exec path plus a daemon release for the whole fleet (ADR-0014: IaC-only
  upgrades), so the vocabulary would grow at release cadence, centrally chosen, while the
  fleet-specific long tail stays on Raw Exec — the most dangerous path absorbing the demand
  the typed path exists to serve.
- **Templates as centrally-expanded Raw Exec** (Relay substitutes parameters, sends the
  result as Raw Exec). Rejected: the daemon would see only a command string — no typed
  parameter validation at the enforcement boundary, no argument-level Policy, and the
  trusted-author property enforced by the untrusted side. Collapses tier 2 into tier 3.
- **Argv-only templates (no shell).** Safest boundary, but the vocabulary gap templates
  exist to close *is* shell composition (pipes, filters, redirection) — argv-only is just a
  native Operation authored in TOML. Rejected in favor of a hostile-shell posture:
  validation + quoting + red-team, per ADR-0001's stated residual risk.

## Consequences

- ADR-0001's tier 2 gets its promised ADR (this one); tiers 1 and 3 are unchanged, and the
  tier ordering by trust still holds — a template is safer than Raw Exec *because* a
  trusted local author fixed the structure. ADR-0002 is unchanged; its v0.8.0 rewrite
  ("operator-rooted") will cover Policy and template bundles alike.
- The template loader and substitution engine are exec-path security surface: human-merge
  lane, always, and the red-team suite gates the milestone.
- The Operation vocabulary stops being fleet-uniform. Surfaces and the AI-agent must treat
  vocabulary as per-Node (`list_operations`/`describe_node`), and the Job engine gains the
  `unsupported` outcome (`/proto` change — contract-first, both sides regenerated).
- The registry, `describe_node`, and the Console (v0.6.0 views) carry the template-set
  fingerprint beside the Policy fingerprint; a template rollout is confirmed the same way a
  Policy rollout is (ADR-0002).
- `policy check` grows template linting, and the self-reference lint (#287) warns when an
  allow rule's reach includes the daemon's own config, binary, or unit — which now includes
  the template files themselves (a template or Policy rule that can rewrite templates is
  self-modifying Policy).
- The AI-agent may *draft* templates, but nothing loads until a root-owned file lands on
  the Node out-of-band — and, after v0.8.0, until an operator signs the bundle. The
  widening act stays human, exactly as for Policy.
- #288 (read auditing / output-retention) must be decided before the catalog makes reads
  ubiquitous; the data-egress section above is its motivation.
- GLOSSARY.md gains **Template Operation** and **template pack** in the same change.

## Amendment (2026-08-10, issue #292 / #287): the self-reference lint, and no daemon-side floor

#287 proposed two defenses against an operator authoring an allow rule whose reach includes
the daemon's own trust root ("letting the wire rewrite the wire's own gate"). Both were to be
decided in the `policy check` tooling pass; this records the outcome.

**Adopted — the lint.** `relay-daemon policy check` now always runs a self-reference lint. It
does **not** parse allow patterns or reason about what a regex "means": it builds concrete
probe actions against this daemon's own paths — Policy file, template root, state dir
(identity key and cert), binary, systemd unit — and evaluates each through the **real** Policy
engine (`Policy::evaluate` / `evaluate_raw_exec`). A finding is therefore proof that the exact
probed action would be allowed on that Node, deny-beats-allow is honored for free, and there
is no second matcher to drift (ADR-0011). Findings are `Warning`s; `--strict` makes them fail
the pipeline. Absence of findings is explicitly **not** a proof of unreachability — the probe
set covers the plausible shapes (edit-in-place, overwrite, copy/move over, delete, redirect,
chmod, symlink, read), not every possible command.

**Rejected — the hardcoded daemon-side deny floor.** #287's second half proposed that the
daemon always deny operations targeting its own config directory, regardless of Policy. Not
implemented, because:

1. **It is the mechanism we already know is bypassable.** A path-string floor is exactly what
   ADR-0018 and ADR-0019 each had to harden after a bypass; adding a third path-matching
   surface in the privileged exec path buys confidence disproportionate to its strength.
2. **It cannot distinguish read from rewrite.** The dangerous act is *writing* the gate, but
   the daemon sees an argv, not an intent. A floor wide enough to stop `sed -i` also blocks a
   legitimate `file.read` of `policy.toml` for audit — which the shipped read catalog and the
   dev fleet both do.
3. **It would silently override an explicit operator allow.** Policy is the operator's
   deliberate statement about their own Node. A hidden rule that beats an explicit allow is a
   surprise in the one place surprises are least acceptable, and it has no expression in the
   Policy file an operator reads.
4. **The real boundary is the filesystem, and it already holds.** Root-owned files plus
   `ProtectSystem=strict` make `/etc` read-only inside the daemon's mount namespace
   (`docs/operations/daemon-privilege-posture.md`). The floor would add nothing on a hardened
   Node, and on an unhardened one it would be a bypassable veneer over a deployment problem
   the lint now names at authoring time.

The lint is therefore defense-in-depth **under** the mount-namespace protection, positioned
where the foot-gun is created (the IaC pipeline) rather than where it is hardest to enforce
(the privileged exec path). If a future deployment mode weakens the filesystem boundary, the
floor should be revisited in its own ADR — with a mechanism that is not path-string matching.

**Also decided here:** with a per-Node vocabulary, `policy check` can no longer tell a
Template Operation from a typo without being told. An unrecognized Operation name is an
`Error` only when the caller supplied a template root (`--templates`, so the whole vocabulary
is knowable); otherwise it is a `Warning` that names the fix. `--strict` fails on it either
way, so the IaC gate loses nothing.

## Amendment (2026-10-02): amended by ADR-0042 — how the Relay calls a Template

This ADR made the vocabulary per-Node and built the daemon half; it never said how the Relay
dispatches a Template, and until #626 no surface could. ADR-0042 settles it: a Template is
dispatched by name through the capability layer on every execution surface. Nodes that do not
report it — or that the Relay holds no report for — are excluded as `unsupported` before the
class, cap and approval gate are decided; the class is the most restrictive the remaining Nodes
report; argument names are checked against every remaining Node's slots. The per-Node vocabulary
cache becomes a dispatch input. Template loading, rendering, quoting and Policy parity are
unchanged.

## Amendment (2026-10-14, #974): slot values travel as positional parameters, never as shell text

The property this ADR decided is unchanged: **substitution can never alter command
structure**. What changes is the mechanism that holds it, because the one this ADR named —
"validation + quoting" — was shown not to hold.

**What failed.** A slot value was validated, single-quoted, and spliced into the body, and the
result was run as `/bin/sh -c <text>`. Single quotes protect a value only where the shell reads
them as quotes, and the body is author-written shell: inside a here-document, a backquoted or
`$( … )` substitution, or after an escaped space, they do not. #974 reproduced each against
dash, and a value of `/tmp/$(cmd)` ran `cmd` from inside a here-document. `/bin/sh` is a
different shell per distribution — dash, bash, busybox — and #975's attempt to refuse every
unsafe construct at load was found incomplete by each of three review passes in turn (`$'…'`,
`alias`, `BASH_ALIASES`, `((`, `name[…]`). A denylist checked against a shell grammar cannot be
shown complete, so the defect is the mechanism, not a missing entry.

**The threat this answers.** A prompt-injected AI-agent chooses every slot value. Policy, the
blast cap and approval bound *which* Template it may call and where; the mechanism below bounds
what a value can do once the call is allowed.

### Decisions

1. **A slot value is never shell text.** Where a Template body is run through a shell, the text
   the shell parses is the author's body with each placeholder replaced by a fixed, quoted
   reference to a positional parameter (`{{path}}` becomes `"$1"`), and the slot values are
   handed to the shell as separate arguments after it. The existing rule that a placeholder
   stands alone as a whitespace-delimited token outside any quotes is kept, so a value is never
   glued to the author's text. The parsed text is therefore a function
   of the Template definition alone — identical for every call, whatever the caller sent — and a
   value enters only at expansion, after the shell has fixed the command's structure. A shell
   never re-parses an expanded parameter for syntax, and the quotes stop field splitting and
   globbing, so a value is exactly one word, byte for byte, in every POSIX shell. This holds
   inside here-documents, substitutions and conditionals alike, so **authors keep the full
   shell**: no construct is refused for being near a slot, beyond the standalone-token rule. The single-quoting path and #975's
   construct denylist are not adopted.
2. **A slot fills only a data position.** No mechanism can stop a command the author chose from
   deliberately turning its argument back into code. A Template is therefore a **Policy error** —
   under the existing rule, the whole Policy is then `invalid` and the Node denies every Task;
   `policy check` reports it before deploy — where a placeholder stands in a position that is
   decidable from the body alone and executes its value: the command-name position of a simple
   command; the operand of `eval`, `.` or `source`; the argument immediately after `-c` (or an
   interpreter's equivalent program flag) of a recognised shell or interpreter; and arithmetic
   contexts (`(( … ))`, `$(( … ))`, `let`), which some bash versions re-evaluate. Code positions
   that cannot be decided reliably from the body — an `awk` or `sed` program, `find -exec`,
   `xargs` feeding a shell, an option that takes a program (`tar -I`, `rsync -e`) — are a
   `policy check` **warning**, which `--strict` fails. The two lists live in
   `operations-and-templates.md`, not here, and grow there.
3. **No value is an option.** The well-formed values of every daemon-owned slot type can never
   begin with `-` — an `identifier` begins alphanumeric, a `path` begins `/`, an `integer` is
   digits — and an `enum` value is a literal the author chose. A slot type added later keeps
   that property or the spec that adds it says why not. Combined with decision 1, a value can
   neither become an option nor be glued onto one.
4. **The `path` type is not narrowed further** (owner decision, 2026-10-14). It already refuses
   C0 controls and DEL, but may carry characters a human cannot see or that a terminal
   interprets — C1 controls, zero-width and other invisible characters, Unicode whitespace and
   bidirectional controls. Decision 1 makes them inert to the shell; what remains is deception of a reader.
   So wherever a slot value or any Node-derived string is shown to a human — the Console,
   approval prompts, audit views, log lines — it is rendered with those characters made visible,
   never raw. That is owned by the specs of those surfaces (#979).
5. **Raw Exec gets a tool, not a floor.** `relay-daemon policy check` gains a probe-based
   interpreter lint in the manner of the self-reference lint above: concrete interpreter- and
   wrapper-shaped argvs (`sh -c`, `env`, `xargs`, `nice`, `timeout`, `sudo`, `setsid`, `nohup`,
   `python -c`, `perl -e`, `find -exec`, …) are evaluated through the real Policy engine, and an
   Allow is a `Warning` that `--strict` fails. It never changes what the daemon runs. Threat
   model R4 stays accepted, now tooled (#978).
6. **Node output is an injection source, and is a separate track.** Everything above stops a
   compromised AI-agent from doing more than it was allowed. Node output reaching the AI-agent —
   a log line, a file, a package description — is how one *becomes* compromised. That is decided
   on its own (#980: an untrusted-data envelope on every result an AI-agent receives, beside the
   output-classification direction already named in this ADR), not in this amendment.

### Considered options

- **Keep single-quoting and refuse unsafe constructs (#975).** Rejected: shown incomplete by
  three consecutive reviews; breaks author Templates that are safe; would need a new entry each
  time a shell grows a construct.
- **Allow only a restricted grammar in bodies that have slots.** Provable, but removes the shell
  composition this tier exists to provide (the reason "argv-only templates" was rejected above).
- **Pin the shell** (always dash, or a vendored one). Narrows the grammar to defend but keeps a
  denylist, and dash is not installed by default on every supported distribution.
- **Positional parameters** — chosen: the attacker contributes no bytes to the parsed text, so
  the defence does not depend on knowing any shell's grammar.

### Consequences

- **Invariant 1 is amended** to state the property decision 1 guarantees outright — "no slot
  value ever part of the text the Template's shell parses" — rather than a mechanism ("with every slot single-quoted"
  is retired). Decision 2 is deliberately **not** part of the invariant: it can only ever be
  partly enforced, so it is defence in depth stated here and in the spec, and the invariant stays
  a claim the code can fully meet. Until the implementing change lands, the gap table in `AGENTS.md`
  carries the Template clause against #974.
- #975 is closed unmerged; its reproduced cases become the red-team suite of the implementing
  change (#977), and #974 stays open as the bug it fixes.
- The rendered command changes shape (`sh -c <body> relay-template <v1> <v2> …`). Policy is
  unaffected — it already matches the raw slot values, per this ADR's "Policy governs templates
  exactly like Native Operations" — and the audit record carries the
  values beside the body rather than inside it.
- A property becomes testable outright: the parsed text is identical for all values of a call.
  The `template_render` fuzz target (#897) asserts exactly that.
- **Residual risk**, accepted: an author who passes a slot to a code-running position that
  decision 2 cannot detect; a program's own parsing of a well-formed argument (as ever, out of
  scope); and Node output steering the AI-agent until decision 6's track lands.

## Amendment (2026-10-15, #977): slots stand only at the top level, and `path` is narrower

Owner decisions, 2026-10-15, taken while implementing the 2026-10-14 amendment. They narrow two
of its decisions; decision 1's mechanism — positional parameters — is unchanged.

**What was found.** Three adversarial review passes on the implementing change each reproduced
bodies the load-time lexer accepted while the shell read them differently: a `case` pattern
closing a substitution early, `$((` that is a command substitution, bash's `$[ ]`, backquote
backslash rules, keyword-splitting line continuations, and a placeholder one substitution deep
inside arithmetic or a parameter expansion. Positional parameters kept every value out of the
text the shell parses, as decided. But a value that lands in a nested context can still be
re-split by an unquoted outer substitution or re-evaluated by bash's arithmetic, and a `path`
value carrying spaces, `$`, `[` and `(` was the payload in each case. Modelling more of each
shell's grammar is the denylist this amendment's predecessor rejected, in a new place.

### Decisions

1. **A slot stands only at the top level** (narrows the 2026-10-14 decision 1's "authors keep
   the full shell around a slot"). A placeholder is accepted only as a standalone word of a
   command in the body's top-level list — a simple command, a pipeline, or an `&&` / `||` / `;`
   list. A placeholder inside a command or process substitution, a parameter expansion, any
   arithmetic context, a here-document or here-string, quotes, `[[ ]]` or a `case` pattern is a
   Template compile error. Authors keep the full shell everywhere else in the body; only where a
   slot may stand is restricted. The load-time refusals that keep the lexer's frame tracking
   honest — backquote substitutions, joining line continuations, unterminated constructs, and
   constructs it cannot analyse — stay, and apply when the body carries a placeholder.
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
   - A body whose own text routes slot values into code — the author's `$1`… `$@` `shift`
     `set --`, a placeholder inside a function body, alias definitions, a placeholder among
     `trap`'s operands, or `.`/`source` passing positional parameters on — is a `policy check`
     **warning**, which `--strict` fails. An operator who deliberately writes a script that turns
     an argument back into code is exercising their own authority over the Node; the product
     does not try to prevent every such script.

### Consequences

- Two layers now hold the one-word property independently: where a slot may stand, and what a
  `path` value may contain. A lexer miss leaves a value that carries no metacharacters, and a
  metacharacter-free value cannot split, become an option, or carry a subscript.
- Templates that placed a slot in a nested context, or relied on paths containing spaces or the
  refused characters, stop loading or refuse those values after upgrade. The implementing PR
  lists both for operators.
- Invariant 1 is unchanged: these decisions strengthen how it holds, not what it states.


## Amendment (2026-10-15): amended by ADR-0033 — the shipped read catalog is its own package

Owner decision, 2026-10-15, recorded in ADR-0033's amendment of that date. The **Shipped read
catalog** decision said the catalog is "installed with the daemon package". It now ships as its
own optional package, which depends on the daemon package.

**Why.** A Template changes what may run on a Node. Installing the daemon should give a Node
its engine and its default Policy; offering the catalog's Templates is a choice the operator
makes, not a side effect.

**What is kept.** The catalog's trust argument stands unchanged: it is first-party content
trusted the way the binary is, so its files are **package-owned** — replaced on upgrade, removed
with the package, never the operator's to edit. An operator who wants a variant defines their
own Template under another name. Its contents, its `read` class and its role as the tier's
first customer are unchanged.

**What is added.** Because the shipped default allows the catalog by name, a package-owned file
replaced on upgrade could change what an already-allowed name does on every Node at once — the
unauthored, fleet-wide change ADR-0033 decision 4 exists to prevent. So a released catalog
Template's name is bound to its body and its risk class: any change to either ships under a new
name, and CI refuses a release that changes a released one.
