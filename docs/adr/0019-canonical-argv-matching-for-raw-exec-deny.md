# Raw Exec deny patterns are matched against canonical argv elements, and `argv[0]` may not contain whitespace

**Status:** Accepted.

`evaluate_raw_exec` matches deny patterns against `argv.join(" ")` **or** each individual
`argv[i]`, and allow patterns against the joined string only. Finding **#227** (v0.0.8
red-team, carried as residual **R1** in the #225 register) showed that an element-anchored
deny is defeated by merging the denied token into a neighbouring argv element: the joined
string is unchanged, so the allow still fires, but no individual element equals the denied
token any more.

```toml
[raw_exec]
allow = ["^systemctl restart nginx --force x$"]
deny  = ["^--force$"]
```

`["systemctl","restart","nginx","--force x"]` → **Allow** (evaded); the honest
`[…,"--force","x"]` → **Deny**. Argv element boundaries are caller-controlled, and the daemon
is the last line of defense against a compromised Relay or a jailbroken AI-agent. Unlike the
unanchored-allow footgun, this is **not** fixable by operator anchoring discipline: the
operator wrote the most precise rule available and still lost.

## Decision

**Canonicalize argv before the deny pass**, mirroring ADR-0018's canonical-form precedent for
`file.read` paths. Derive **canonical elements** by splitting the joined command on whitespace
and run the per-element deny pass over those *in addition to* the existing forms. The deny
pass becomes the union of three disjuncts; **the allow pass is untouched**:

```
canonical = argv.join(" ").split_whitespace()
deny if:  re.is_match(joined)
       || argv.iter().any(|a| re.is_match(a))        // kept — see below
       || canonical.iter().any(|c| re.is_match(c))   // new
```

On the reproduction the canonical elements are `[systemctl, restart, nginx, --force, x]`, so
`^--force$` matches and the command is **denied**. Whitespace is the Unicode notion
(`split_whitespace`), so tab, LF, CR and NBSP separators, padding, and repeated runs all
collapse onto the same normal form; empty argv elements produce no empty canonical elements.

**The raw-element pass is kept, deliberately.** A deny written against a *merged* element
(`^--force x$`) matches that raw element and no canonical one, so replacing the pass instead
of adding to it would *lose* a deny path.

**Monotonicity makes this reviewable.** Adding a disjunct to a deny pass can only turn Allows
into Denies. Nothing that was denied stops being denied, and no allow is widened, so the worst
case is "some previously-allowed Raw Exec is now refused", the safe direction on the privileged
side.

**Companion guard: `argv[0]` must be exactly one non-empty program token.** The joined form
is a lossy projection of argv (`["systemctl restart","nginx"]` joins identically to the
three-element form), so an allow pattern can approve a joined string whose `argv[0]` is not
the program that will run; an empty `argv[0]` is no program at all. Invariant #1 says an
argument must never change *which* command runs; for Raw Exec that is `argv[0]`. The guard is
pure, lexical, fails closed (`Deny`, `rule: None`), and monotonic. It is **defense-in-depth
and legibility, not a plugged exploit**: `argv[0]` goes straight to `Command::new`, so
`"systemctl restart"` was already `ENOENT` unless a file of that name was planted on `PATH`.
What it removes is a Policy saying *allow* to a command whose real program the gate never saw.

**Ordering: deny pass, then the guard, then the allow pass.** The guard runs after the deny
pass so an argv that a deny pattern claims keeps the specific attribution
(`rule: Some(RawExecDeny)`) instead of the guard's `rule: None`, and before the allow pass so no
allow pattern can approve a non-token `argv[0]`. Both orders Deny; this is for audit legibility.

**Deny reasons name the matched form.** A canonical element need not appear anywhere in argv,
so the reason reads `raw exec denied by pattern "^--force$" (matched canonical element
"--force")`, distinguishing joined command / argv element / canonical element. It is
`PolicyVerdict.deciding_rule` verbatim, so `PolicyQuery`, the Policy preflight and
`policy check --would-allow` all inherit it.

Every caller-controlled fragment quoted into a reason (the matched text, and `argv[0]` in the
guard reason) is truncated to a fixed character budget on a character boundary. A reason is an
audit record on the wire, so the Policy engine, not the caller, chooses its size; the guard
reason fires with **no allow and no deny pattern loaded**, making it the cheapest reason on the
daemon to provoke.

Daemon-side only: no `/proto`, Relay or Policy file-format change, so Policy fingerprints are
unaffected and no fleet re-rollout is implied. Policy is still evaluated by the one live engine
(ADR-0011, invariant #12): `policy check --would-allow` reaches the same `evaluate_raw_exec`
through `evaluate_policy_query`.

## What this does not close (recorded residual)

Canonicalization closes the **deny-evasion**. It does not make the joined form faithful to
argv: a caller can still shift element boundaries while keeping the joined string constant
(`["systemctl","restart nginx"]` is indistinguishable from the three-element form). The
`argv[0]` guard removes the part that touches *which program runs*; boundaries below `argv[0]`
stay invisible to the gate. A **token-form** deny (`^--force$`) now holds, but a deny written
against a multi-token whole-command string (`^systemctl restart nginx --force$`) is still
whitespace-fragile: it matches only the joined form, so tab-separated tokens miss it while a
loose `\s`-based allow still matches. That is the same authoring-mismatch family as the
unanchored-allow footgun, not a new evasion class; the guidance is to deny tokens and allow
whole commands. Fully closing it would mean **rejecting ambiguous argv outright** or
**joining on a separator that cannot appear in an element**; both break Policy authoring
(every deployed pattern is written against the space-joined form) and are declined here. This
is a known limit of regex-gated Raw Exec, and what Template Operations exist to make
unnecessary.

## Consequences

- An element-anchored Raw Exec deny (`^--force$`) holds against merged, padded, and
  tab/LF/CR/NBSP-separated spellings. `policy.example.toml` tells operators to write the deny
  against the **token**, not a merged spelling.
- A Raw Exec whose `argv[0]` is empty or contains whitespace is a **policy Deny**. This is a
  real, small capability loss: a program whose path contains a space (`/opt/Some App/bin/tool`)
  cannot run via Raw Exec, with no override. Accepted as the more restrictive option; the
  workaround is a space-free path (e.g. a symlink in `/usr/local/bin`) or an Operation, and the
  deny reason names `argv[0]` so the failure is diagnosable. Recorded in `policy.example.toml`.
- Every Deny reason on this path names the form that matched, visible in `deciding_rule`,
  `policy check` output and daemon stderr.
- The finding-#227 test in `daemon/crates/relay-policy/src/lib.rs` pins the fix, with the
  neighbouring shapes as red-team table rows (Axis 7).
- The #225 residual-risk register records R1 (#227) as **fixed**, with the joined-form
  lossiness above carried as its narrowed remainder.

## Amendment (2026-09-16): allow patterns match the whole command, and no argv element carries whitespace

**This reverses part of the residual section above,** which declined both ways to close the
joined form's lossiness. The owner took the first, rejecting ambiguous argv, on 2026-09-16 while
working through `docs/specs/policy.md`, together with a second change the July red-team (#214)
had recorded as "by design".

### What changed

1. **An allow pattern must match the whole joined command.** The daemon enforces the full match
   rather than relying on the author writing `^…$`; an anchored pattern behaves as before. A
   pattern that relied on substring semantics (`/usr/bin/systemctl (status|restart) nginx`) now
   matches only a command that *is* that text, so
   `/bin/rm -rf /var/log && /usr/bin/systemctl restart nginx` is denied by default. #214's
   "intended, anchor it yourself" is withdrawn: a safety property of the exceptional tier should
   not depend on every operator remembering two characters.
2. **Every argv element is refused if it carries whitespace, not only `argv[0]`.** The
   `argv[0]` guard (`char::is_whitespace`) extends to every element; an empty `argv[0]` stays
   refused, and an empty later element is allowed (it carries no boundary ambiguity). With no
   whitespace inside any element, joining on a space and re-splitting is lossless: the joined
   line the allow pattern sees is exactly the argv that runs.

Deny semantics are unchanged: deny still runs first, over the joined command, each raw element
and each canonical element, and still beats allow.

### What it closes

- **R10** in `docs/security/threat-model.md`, the argument-boundary lossiness, is closed rather
  than accepted: `["systemctl","restart nginx"]` is refused, so no two distinct argvs share a
  joined form, and a multi-token whole-command deny is no longer whitespace-fragile.
- The unanchored-allow footgun, which the red-team table carried as intended, becomes a denial
  those rows assert (`unanchored_allow_full_match_denies_foreign_argv0`,
  `interp_unanchored_allow_full_match_denies_shell_argv0`).

### What is given up, and accepted

- **Raw Exec cannot pass an argument containing whitespace**, with no override: a commit
  message, a path with a space, a quoted search term. The remedy is a Template, whose slots are
  typed by the author (ADR-0021). Raw Exec is the conspicuous exception to a typed vocabulary
  (invariant 1), and a command needing rich arguments should not be regex-gated.
- **A deployed unanchored allow pattern stops matching on upgrade.** The failure is closed
  (denial, never widening) with the ordinary deny-by-default reason, so
  `relay-daemon policy check` must warn on an allow pattern without `^` and `$` so an operator
  finds it before the upgrade. Both in-tree patterns (`policy.example.toml`, the dev-fleet
  fixture) already anchor.

### Consumers

`docs/specs/policy.md` (states both claims), `docs/security/threat-model.md` R10 and invariant
#1's row, `daemon/policy.example.toml` guidance, and the `raw_exec_redteam` rows named above.
