# A local Template tier, a shipped read catalog, and a frozen native vocabulary

**Status:** Accepted.

Behaviour: `operations-and-templates.md`, `policy.md`. Numbers are stable; code cites them.

## Decision

New things a Node can do are added as **Templates**: shell snippets an operator writes in a
root-owned file on the Node, with typed slots the AI-agent fills. The author fixes what runs; a
caller supplies only values, and no value ever becomes part of the text the shell parses, so no
argument can change the command. The four built-in Native Operations are frozen. A first-party
catalog of read-only Templates ships as an optional package. The daemon's own files are
protected by the filesystem and by a lint the operator runs, never by a hidden deny rule.

## The decisions

**The tier**

1. **A Template is an author-fixed command with typed slots** (ADR-0001's tier 2). Each value is
   validated against its slot's type. A mandatory `risk_class`, `read` or `mutate` (ADR-0012),
   or the Template fails to load. Policy governs it exactly as a Native Operation: by name,
   deny-by-default, deny-beats-allow, argument by argument, matching the raw slot values. The
   loader and renderer are exec-path security surface and always take the human-merge lane.
2. **Local loading, same trust root.** Templates load from root-owned files beside the Policy,
   changed only by local or out-of-band access, never the wire (ADR-0002); a directory installed
   and versioned as a unit is a **template pack**. The AI-agent may draft one; nothing loads
   until a root-owned file lands out of band and, once signing exists, an operator signs it. The
   widening act stays human.
3. **The vocabulary is per-Node.** In `Hello` and every snapshot the daemon reports names, risk
   classes and a template-set fingerprint beside the Policy fingerprint; no RPC carries a body.
   The registry, `list_operations`, `describe_node` and the Console show each Node's own, and a
   Template rollout is confirmed like a Policy rollout. Dispatch is by name through the
   capability layer (ADR-0042): Nodes not reporting it, or with no report, are `unsupported`
   before class, cap and approval are decided. A daemon asked for a Template it has not loaded
   answers `unsupported` too: not a failure and not a deny, since it was never asked to decide.
4. **The Native vocabulary is frozen at four.** `system.facts` and `file.read` are platform
   intrinsics; `file.read` keeps the canonical-path checks no Template can do (ADR-0018).
   `service.restart` and `pkg.install` are grandfathered. New vocabulary is Templates. One
   lookup, name to handler, argument shape and risk class, is the source validation, Policy and
   discovery all read. The golden schema pins the Natives (ADR-0015).

**How a slot value is kept out of the shell**

5. **A slot value is never shell text.** The shell parses the author's body with each
   placeholder replaced by a quoted positional parameter (`{{path}}` becomes `"$1"`), and the
   values follow as separate arguments; the audit record carries them beside the body. The
   parsed text depends on the Template alone, so a value is exactly one word in every POSIX
   shell. Invariant 1 states this property.
6. **A slot stands only at the top level**, as a standalone word of a simple command, a
   pipeline or an `&&`, `||` or `;` list. A placeholder inside a substitution, a parameter
   expansion, arithmetic, a here-document or here-string, quotes, `[[ ]]` or a `case` pattern
   fails to compile. Elsewhere authors keep the full shell. In a body that carries a
   placeholder, the lexer also refuses backquotes, joining line continuations, unterminated
   constructs and anything it cannot analyse.
7. **A slot fills only a data position.** A placeholder where the body alone shows it would be
   executed fails to compile: the command name, including the operand of `exec`, `command` or
   `builtin`; the operand of `eval`, `.` or `source`; the argument after `-c`, or an
   interpreter's equivalent program flag, of a recognised shell or interpreter; and arithmetic,
   `(( ))`, `$(( ))` and `let`. The template set is then `unloadable`, Natives keep running, and
   `policy check` exits 1. A `policy check` warning, which `--strict` fails, covers code
   positions the body cannot decide (an `awk` or `sed` program, `find -exec`, `xargs` into a
   shell, `tar -I`, `rsync -e`) and bodies whose own text routes values into code: the author's
   `$1` to `$@`, `shift`, `set --`, a placeholder in a function body or among `trap`'s
   operands, alias definitions, and `.` or `source` passing parameters on. The lists live in
   `operations-and-templates.md` and grow there. This decision is defence in depth and
   deliberately not in invariant 1, which the code can fully meet.
8. **No value is an option.** No well-formed value of a daemon-owned slot type begins with `-`:
   an `identifier` begins alphanumeric, a `path` begins `/`, an `integer` is digits, an `enum`
   is the author's literal. A new slot type keeps that property or its spec says why not.
9. **`path` is narrow.** It begins with `/` and refuses C0 controls, DEL, whitespace and each of
   `` $ ` \ " ' ; | & < > ( ) { } [ ] * ? ! # ~ = ``. A path a Template cannot address is
   reached by a Native Operation or Raw Exec, under Policy. Invisible, bidirectional and C1
   characters are inert to the shell but can deceive a reader, so wherever a slot value or a
   Node-derived string is shown to a human, in the Console, an approval prompt, an audit view
   or a log line, they must be made visible, never raw. Those surfaces' specs own it.
10. **The boundary is tested as hostile.** A red-team suite against substitution is an
    acceptance criterion of the tier, its findings regression tests. That the parsed text is the
    same for every value is to be asserted by a fuzz target as well as property tests.

**The shipped catalog**

11. **A first-party read catalog ships** (superseded in part by ADR-0053, 2026-10-23: inside the
    `relay-daemon` package, all of it allowed by default): process list, service status, disk
    and mount usage, listening ports, package inventory, bounded log tail, file checksum, all
    `read`. Its files are package-owned: replaced on upgrade, removed with the package, never
    the operator's to edit. A variant is the operator's own Template under another name.
12. **A released catalog name is bound to its body and risk class.** A change ships under a new
    name and CI refuses one that changes a released name, since the default Policy allows the
    catalog by name. Withdrawing a name is allowed: it only reduces what may run.
13. **`read` means it cannot change the Node, not that it is safe to see.** A read result flows
    to the model provider, so reading is exfiltration by construction. The catalog is governed
    by what it makes reachable: the log tail reads whatever secrets reach logs, and the file
    checksum is a content oracle over any path Policy lets it touch. The default Policy must
    scope both (ADR-0022), and classifying output in Policy is the long-term direction. Node
    output reaching the AI-agent is how an AI-agent becomes compromised; that is to be decided
    on its own track (#980).

**Protecting the daemon's own files**

14. **A lint, not a floor.** `relay-daemon policy check` runs a self-reference lint: concrete probe
    actions against the daemon's own paths, each evaluated by the real Policy engine, so a finding
    proves that exact action is allowed and no second matcher can drift (ADR-0011). Read probes
    (`file.read`, `file.checksum`, path-taking Templates) target only the secret-bearing files, the
    identity private key and the environment file. Write probes, the Raw Exec shapes from
    edit-in-place to symlink, target the whole trust root by exact path: the Policy file and
    directory, the environment file, the state directory's key, certificate, CA bundle and address,
    the template root, `/usr/bin/relay-daemon`, `/usr/lib/systemd/system/relay-daemon.service`, the
    override at `/etc/systemd/system/relay-daemon.service`, and the `override.conf` drop-in. The
    binary at the path the check runs from gets a write probe only, so a CI checkout answers as
    `/usr/bin` does. Findings are warnings that `--strict` fails; absence of one is not proof of
    unreachability (R38), and a Raw Exec deny pattern over a directory is the operator's control
    (ADR-0019). A Template body read by `file.read` under the default wildcard is R37.
15. **No daemon-side deny floor** over the daemon's own paths: path matching is what ADR-0018
    and ADR-0019 each hardened after a bypass, it cannot tell an audit read from a rewrite, it
    would silently beat an operator's explicit allow, and root-owned files under
    `ProtectSystem=strict` hold the boundary. A mode that weakens that boundary reopens this in
    its own ADR, with a mechanism other than path matching.
16. **Raw Exec gets a tool, not a floor.** `policy check` is to probe interpreter- and
    wrapper-shaped argvs (`sh -c`, `env`, `xargs`, `sudo`, `python -c`, `perl -e`,
    `find -exec` and the like) through the real engine; an allow is a warning that `--strict`
    fails, and never changes what runs. R4 stays accepted. An unrecognised Operation name in
    `policy check` is an error when a template root is supplied and otherwise a warning that
    names the fix; `--strict` fails on both.

**Accepted residual risk:** an undetectable code position, a program's own argument parsing,
and Node output steering the AI-agent.

## Alternatives

- **Signing first** adds reach, not execution trust. **More Natives** cost privileged Rust and a
  fleet release each. **Relay-side expansion into Raw Exec** collapses tier 2 into tier 3.
  **Argv-only** loses the composition the tier exists for. **A pinned shell** keeps a denylist.
- **Single-quote values and refuse unsafe constructs** (a denylist). Built, then broken: quotes
  do not protect inside here-documents or substitutions, and three reviews each found a
  construct it missed. A denylist over a shell grammar cannot be shown complete.

## Where the amendments went

| Cited as | Now |
|---|---|
| the original bullets: tier, loading, fingerprint, catalog, freeze, lookup, egress | 1 and 10, 2, 3, 11, 4, 4, 13 |
| 2026-08-10: the self-reference lint, no floor, *Also decided* | 14, 15, 16 |
| 2026-10-02, ADR-0042: dispatching a Template | 3 |
| 2026-10-14, decisions 1 to 6; its red-team and fuzz consequences | 5, 7, 8, 9, 16, 13; 10 |
| 2026-10-15 (#977), decisions 1 to 3 | 6, 9, 7 |
| 2026-10-15, ADR-0033: the catalog's own package | 11, 12 |
| 2026-10-16: read probes stop at secrets; no RPC carries a body | 14, 3 |

## Amendment (2026-10-30): once DI-49 is built, read probes also target the temporary identity key
