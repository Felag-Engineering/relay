# Raw Exec deny patterns are matched against canonical argv elements, and `argv[0]` may not contain whitespace

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
unanchored-allow footgun, this is **not** fixable by operator anchoring discipline — the
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

**Monotonicity — the property that makes this reviewable.** Adding a disjunct to a deny pass
can only turn Allows into Denies, never the reverse. No Policy that denies something today
stops denying it, and no allow is widened (the allow pass is unchanged). That bounds the
blast radius of this change to "some previously-allowed Raw Exec is now refused", which is
the safe direction on the privileged side.

**Companion guard: `argv[0]` must be exactly one non-empty program token.** The joined form
is a lossy projection of argv — `["systemctl restart","nginx"]` joins identically to the
legitimate three-element form — so an allow pattern can approve a joined string whose `argv[0]`
is not the program that will actually execute; an empty `argv[0]` is not a program at all.
Invariant #1 is that an argument must never change *which* command runs; for Raw Exec that is
`argv[0]`. The guard is a pure lexical test and fails closed (`Deny`, `rule: None`); it is also
monotonic in the deny direction. It is **defense-in-depth and legibility, not a plugged
exploit**: the executor passes `argv[0]` straight to `Command::new`, so `"systemctl restart"`
was already `ENOENT` unless an attacker had planted a file of exactly that name on `PATH`. What
the guard removes is a Policy that says *allow* to a command whose real program the gate never
saw.

**Ordering: deny pass, then the guard, then the allow pass.** The guard runs after the deny
pass so an argv that a deny pattern claims keeps the specific attribution
(`rule: Some(RawExecDeny)`) instead of collapsing into the guard's `rule: None`; it runs before
the allow pass so no allow pattern can approve a non-token `argv[0]`. Both orders Deny, so this
is an audit-legibility choice, not a semantic one.

**Deny reasons name the matched form.** A canonical element need not appear anywhere in argv,
so `denied by pattern "^--force$"` alone is not reconcilable against the argv a caller sent.
The reason now reads `raw exec denied by pattern "^--force$" (matched canonical element
"--force")`, distinguishing joined command / argv element / canonical element. This string is
`PolicyVerdict.deciding_rule` verbatim, so `PolicyQuery`, plan mode and
`policy check --would-allow` all inherit it.

Every caller-controlled fragment quoted into a reason — the matched text, and `argv[0]` in the
guard reason — is truncated to a fixed character budget, on a character boundary. A reason is
an audit record on the wire, and its size must be chosen by the Policy engine, not by the
caller: the guard reason in particular fires with **no allow and no deny pattern loaded**, so
it is the cheapest reason on the daemon to provoke and is quoted at bounded width for that
reason.

Daemon-side only: no `/proto` change, no Relay change, no Policy file-format change — so
Policy fingerprints are unaffected and no fleet re-rollout is implied. Policy is still
evaluated by the one live engine (ADR-0011/invariant #12): `policy check --would-allow` reaches
the same `evaluate_raw_exec` through `evaluate_policy_query` and inherits both rules for free.

## What this does not close (recorded residual)

Canonicalization closes the **deny-evasion**. It does not make the joined form a faithful
representation of argv: matching a whitespace-joined projection is inherently approximate, and
a caller retains freedom to shift element boundaries in ways that keep the joined string
constant (e.g. `["systemctl","restart nginx"]`, which the joined-form allow cannot distinguish
from the three-element form). The `argv[0]` guard removes the part of it that touches *which
program runs*; the argument boundaries below `argv[0]` remain invisible to the gate. Concretely:
a **token-form** deny (`^--force$`) now holds, but a deny written against a multi-token
whole-command string (`^systemctl restart nginx --force$`) is still whitespace-fragile — it
matches only the joined form, so an argv whose tokens are separated by a tab misses it while a
loosely-written `\s`-based allow still matches. That is the same family as the documented
unanchored-allow footgun (an authoring mismatch, pre-existing and unchanged here), not a new
evasion class, and the authoring guidance is the mitigation: deny tokens, allow whole
commands. Fully closing it would mean **rejecting ambiguous argv outright** or
**joining on a separator that cannot appear in an element**: both are breaking changes to
Policy authoring (every deployed pattern is written against the space-joined form), and both
are declined here. This is a known limit of regex-gated Raw Exec, and it is the argument
v0.8.0's Template Operations exist to make unnecessary.

## Consequences

- An element-anchored Raw Exec deny (`^--force$`) now holds against merged, padded, and
  tab/LF/CR/NBSP-separated spellings. Operator guidance in `policy.example.toml` is corrected
  accordingly: write the deny against the **token**, not against a merged spelling.
- A Raw Exec whose `argv[0]` is empty or contains whitespace is a **policy Deny**, where some
  such commands were previously allowed. This is a real (small) capability loss, not a no-op: a
  program whose own path contains a space — `/opt/Some App/bin/tool` — is no longer runnable via
  Raw Exec at all, with no override. Accepted as the more restrictive option on the privileged
  side; the workaround is a space-free path (e.g. a symlink in `/usr/local/bin`) or promotion to
  an Operation, and the deny reason names `argv[0]` explicitly so the failure is diagnosable in
  the field. Recorded in `policy.example.toml` where operators read it.
- Deny attribution is preserved across the guard (deny pass first), and every Deny reason on
  this path names the form that matched — a behaviour change visible in `deciding_rule`,
  `policy check` output and daemon stderr, though no format is machine-parsed today.
- The `#[ignore]`d finding-#227 test in `daemon/src/policy.rs` is enabled and now pins the fix;
  the neighbouring shapes land as red-team table rows (Axis 7) alongside it.
- The #225 residual-risk register records R1 (#227) as **fixed**, with the joined-form
  lossiness above carried as its narrowed remainder.
