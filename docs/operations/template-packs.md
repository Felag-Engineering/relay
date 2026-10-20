# Template packs: authoring, distribution, and verification

How Template Operations are authored, installed, and confirmed on a fleet: as code, in the
customer's IaC repo, **never over the wire** (ADR-0002, ADR-0021). See also
[policy-as-code.md](policy-as-code.md) (the same workflow for Policy, which still decides
whether a template may run), [relay-daemon-install.md](relay-daemon-install.md), and the
annotated example [`daemon/templates.example.toml`](../../daemon/templates.example.toml).

## What a Template Operation is

An operator-authored shell template with named, type-validated **parameter slots** (ADR-0021,
ADR-0001's tier 2). The author fixes the command structure; a caller supplies only parameter
*values*, and a value can never alter that structure. Each value is validated against its
slot's type and passed to the shell as a positional parameter: each `{{slot}}` in the body
becomes a quoted reference (`"$1"`, `"$2"`, … in slot declaration order), so the script
`/bin/sh -c` parses is the same text on every call. A value is data beside the script, never
part of it.

Templates let the typed path grow at *your* cadence rather than the daemon's release cadence,
keeping fleet-specific work off Raw Exec, the most dangerous path (ADR-0001). They are **not**:

- **A Policy bypass.** A template's name enters the Node's Policy vocabulary like any Native
  Operation: deny-by-default, deny-beats-allow, argument-level constraints. Installing a
  template allows nothing by itself.
- **Remotely installable.** The Relay may read a Node's template set and can never author or
  modify one. Widening a Node's vocabulary goes through reviewed config management, exactly
  like widening its Policy.
- **Fleet-uniform.** Vocabulary is per-Node. A Node without a given template reports the
  distinct `unsupported` outcome (below).

## The layout, and what a "pack" is

```
/etc/relay-daemon/
  policy.toml                   # the Node's Policy (ADR-0002)
  templates.d/                  # the template root (RELAY_TEMPLATE_DIR)
    local.toml                  # a loose, operator-authored file
    relay-read/                 # a PACK — installed and versioned as a unit
      catalog.toml
      README.md                 # ignored by the loader (only *.toml loads)
```

A **template pack** is one immediate subdirectory of the template root, installed and
versioned as a unit; the shipped read catalog and any first- or third-party pack follow this
convention. Loose `*.toml` files in the root are equally valid; use a pack when templates
travel together (one source, one version, one uninstall).

Nesting stops there. A directory inside a pack is skipped with a warning, so what loads is
always what two levels of `ls` show.

## 1. Author

[`daemon/templates.example.toml`](../../daemon/templates.example.toml) is the annotated
reference. In brief:

```toml
[[template]]
name       = "log.tail"     # enters the Policy vocabulary; ^[a-z][a-z0-9_.]*$
risk_class = "read"         # MANDATORY (ADR-0012): "read" | "mutate"
body       = "tail -n {{lines}} -- {{path}}"

[[template.slots]]
name = "lines"
type = "integer"            # ^[0-9]+$, unsigned, ≤19 digits

[[template.slots]]
name = "path"
type = "path"               # absolute + canonical, ≤4096 bytes, plain filenames only
```

Slot types: `identifier`, `integer`, `path`, `enum` (with `values`). Prefer `enum` whenever
the value space is finite: it is the only type whose accept-set you control completely.

The loader enforces these rules; each is a refusal at load time:

- **A slot is a plain word of the top-level command list, and nowhere else.** It may stand as
  an argument of a simple command, in a pipeline, in a `;`/`&&`/`||`/newline list, or inside a
  `{ …; }` group or function body. It is refused inside `$( )`, `( )`, backquotes, `${ }`, any
  arithmetic (`$(( ))`, `(( ))`, `$[ ]`, `for ((`), a here-document or here-string, quotes,
  `$'…'`, `[[ ]]`, a process substitution or array literal, a comment, and beside a `case`
  command. This makes "one slot fills exactly one word" true by construction and keeps a value
  away from every place a shell evaluates text. Move the slot out to a plain argument, or
  compute the rest in the body and pass the value as an argument of the command that needs it.
- **A slot must be a whole word.** `--file={{path}}` and `'{{path}}'` fail to load. Only space,
  tab and newline are blanks: a slot glued to an operator (`>{{path}}`, `;{{path}}`), after an
  escaped space (`a\ {{path}}`), or next to a form feed or carriage return is refused. Keep
  bodies on LF line endings: a CRLF-saved file puts a carriage return after the slot.
- **Some constructs are refused when the body holds a slot**, because the daemon cannot read
  them the way every shell does: backquote substitutions (write `$( )`), a `$((` that is not
  arithmetic, an unterminated construct, `case`, and a backslash-newline inside a nested
  construct or in the middle of a word. A backslash-newline between words, after a blank, is
  allowed. Bodies without a slot are not affected.
- **A `path` slot admits plain filenames only.** The value must be an absolute canonical path
  with no whitespace (ASCII or Unicode), no control character, and none of
  `` $ ` \ " ' ; | & < > ( ) { } [ ] * ? ! # ~ = ``. Letters of any script, digits and
  `- _ . , + @ % : ^` are fine (`/home/josé/notes`, `/srv/app-1.2_x/data@2026,v2+final.txt`).
  A caller's value with a space or a quote is refused with a validation failure, not run. This
  is narrower than the Native `file.read` path check. For a path the type refuses, list the
  allowed values in an `enum` slot.
- **One bad template makes the whole set `unloadable`.** Run `policy check --templates` before
  deploying.
- **A slot never stands where its value would be executed.** Positional parameters keep a
  value out of the parsed text, but a command you wrote can still turn its argument back into
  code. Where that is decidable from the body, the template fails to load (and `policy check`
  exits 1):
  - the command-name position of a simple command: the start of the body, after a newline,
    `;`, `&&`, `||`, `|`, `&`, `{`, `!`, a `then`/`do`/`else`/`elif`/`if`/`while`/`until`/
    `time` (also `time -p`)/`coproc`, and after leading `NAME=value` assignments and
    redirections (`2>&1`, `{fd}>file`);
  - the operand of `exec`, `command` or `builtin` (`exec > {{path}}` with no command, and
    `command -v {{name}}` / `command -V`, which only look a name up, are not command
    positions), and the applet of `busybox`;
  - an operand of `eval`, the file operand of `.` or `source`, an operand of `let`;
  - the program of a shell run with `-c` (`sh`, `bash`, `dash`, `zsh`, `ksh`, `mksh`, `ash`,
    `rbash`, `fish`, `csh`, `tcsh`): its first operand after all options, so
    `sh -c -e {{path}}` and `sh -c -- {{path}}` count too;
  - the argument after `python -c` (also `python3`, `pypy3`, versioned names such as
    `python3.11`), `perl -e`/`-E`, `ruby -e`, `node -e`/`-p`/`--eval`/`--print`, `php -r`,
    `lua -e`, when the flag comes before the script operand;
  - any of the above behind a wrapper (`env sh -c {{path}}`).

  A slot as a *data* argument of those programs is fine (`python3 -c '…' {{path}}`);
  `sh -c 'script "$1"' relay {{path}}` loads, with the warning below for a program that reads
  its positional parameters.
- **Warnings** do not stop a template from loading. `policy check` reports each with the
  template, the byte offset in the body and the reason, and `--strict` fails the pipeline on
  them. They cover positions the daemon cannot decide, and bodies that route slot values into
  code themselves:
  - a slot as the program of `awk`/`sed`, after `find -exec`/`-execdir`/`-ok`, anywhere after
    `xargs`, or as an argument of a wrapper that runs a command (such as `env`, `sudo`,
    `timeout`, `nohup`, `nice`, `chroot`, `nsenter`, `strace`, `systemd-run`,
    `/usr/bin/time`);
  - a slot as the value of an option that runs a command (such as `tar -I`, `rsync -e`,
    `git -c`, `su -c`, `script -c`, `mapfile -C`, `complete -C`, `enable -f`) or part of an
    `ssh` remote command;
  - a slot as the script operand of a shell or interpreter without `-c` (`sh {{path}}`,
    `python3 {{path}}`) or an argument of a command whose name is computed (`$cmd {{path}}`);
  - a shell program that reads its own positional parameters with a slot after it
    (`sh -c 'echo "$1"' relay {{path}}`): where the value lands is then that program's choice;
  - the body's own `$1`…`$9`, `${N}`, `$@`, `$*`, `shift`, `set --` or `getopts` (the
    positional parameters carry the slot values), a slot inside a function body, an `alias`, a
    slot among `trap`'s operands, any `.` or `source` (the sourced file receives the slot
    values), and a slot in a `compgen`/`complete -W` word list.

  These lists name the main members; the daemon's tables are the full set. Neither is a
  complete hazard list: a program that interprets its own argument as code is the author's
  responsibility. The wrapper and option tables are conservative: a slot that is only an
  argument of the wrapped command (`timeout 5 du {{path}}`) is also reported, because the
  daemon does not model each wrapper's options.
- **`risk_class` is mandatory**, and a template may not shadow a Native Operation
  (`system.facts`, `file.read`, `service.restart`, `pkg.install`) or `raw_exec`. The Native
  vocabulary is frozen (ADR-0021) and always wins.

## 2. Validate

`relay-daemon policy check <policy.toml> --templates <dir>` lints the Policy and the template
root together, before anything is deployed:

```console
$ relay-daemon policy check policy.toml --templates templates.d/ --strict
error: relay-read/catalog.toml: [[template]] #2 (name="log.tail") — a placeholder near byte 12 \
       is not a standalone whitespace-delimited word …
```

It reports:

- **Errors per template**: a malformed body (a placeholder that is not a standalone word,
  unbalanced quoting, a slot in a code-running position), an invalid or missing `risk_class`,
  bad slot names or types, an empty `enum`, a name that shadows a Native Operation, and a
  duplicate name across the set. Each is an error because each makes the whole set fail to
  load on the Node.
- **Warnings per template**: the undecidable positions and author hazards listed under Author.
  They never block loading; `--strict` makes them fail the check.
- **Across Policy and templates**: an Operation name in a Policy rule that is neither native
  nor in the supplied template root is an **error**. Without `--templates` the linter cannot
  know the Node's vocabulary, so the same name is a **warning** that names the fix; `--strict`
  still fails on it.
- **`--would-allow`** resolves names through that vocabulary: a template name answers
  `ALLOW`/`DENY` on a Node that has it and `UNSUPPORTED` where it is absent, the same answer a
  real dispatch gives (ADR-0011).

The linter does not apply the runtime loader's ownership and mode checks, because it runs on a
non-root IaC checkout; the Node re-applies them. Symlinks are still refused.

### The self-reference lint

`policy check` always asks, with or without `--templates`: **does this Policy reach the
daemon's own trust root?** The two halves differ on purpose:

- **Reads** (`file.read`, `file.checksum`, any path-taking Template Operation) are probed only
  against the files that hold a secret: the Node's identity private key and the environment
  file. Reading any other file, the Template files included, is never a finding: they disclose
  vocabulary, never a secret (residual R37 in `docs/security/threat-model.md`; the control is
  narrowing `file.read`'s wildcard to an explicit path list).
- **Writes** (Raw Exec edit in place, overwrite, copy or move over, delete, redirect, chmod,
  symlink) are probed by exact path at the packaged locations: the Policy file and directory,
  the environment file, the state directory's `key.pem`, `cert.pem`, `ca_bundle.pem` and
  persisted address, the template root, `/usr/bin/relay-daemon`, the unit under
  `/usr/lib/systemd/system/`, and the override unit and `override.conf` drop-in under
  `/etc/systemd/system/`. A rule that lets a Task rewrite `policy.toml` lets the wire rewrite
  its own gate. The probes name exact paths, so a drop-in or Policy fragment under another
  name is not flagged (residual R38; the control is a Raw Exec deny over the directory,
  ADR-0019).

It **probes the real Policy engine** with concrete actions against those paths, evaluated as a
dispatch would evaluate them. A finding is proof, not a guess, and an explicit `[[deny]]`
silences it because the engine applies deny-beats-allow:

```console
$ relay-daemon policy check policy.toml
warning: [raw_exec].allow — self-reference: Policy allows the Raw Exec \
  ["/usr/bin/sed", "-i", "s/a/b/", "/etc/relay-daemon/policy.toml"] — this daemon's own \
  Policy file … Narrow the allow regex, or add a [raw_exec] deny for this path.
```

Findings are warnings; `--strict` makes them failures. No findings is **not** proof of
unreachability: the probes cover the plausible shapes, not every command. This is
defense-in-depth under the real boundary (root-owned files + `ProtectSystem=strict`); the
ADR-0021 amendment explains why there is deliberately no hardcoded daemon-side deny floor.

## 3. Distribute

Config management copies the files and restarts the daemon, exactly as for `policy.toml`:

```yaml
- name: Install the read template pack
  ansible.builtin.copy:
    src: "packs/relay-read/"          # from the IaC repo
    dest: /etc/relay-daemon/templates.d/relay-read/
    owner: root
    group: root
    mode: "0644"                      # never group/world-writable
    directory_mode: "0755"
  notify: restart relay-daemon
```

The daemon's loader refuses anything it cannot trust, and refuses it **for the whole set**:

| Refusal | Why |
|---|---|
| A symlinked file, pack directory, or template root | Whoever controls the link target would choose the vocabulary (`O_NOFOLLOW`, `lstat`-typed directory entries) |
| Not a regular file (FIFO, device, socket) | Same descriptor that is validated is the one read — no TOCTOU gap |
| Group- or world-writable (`mode & 0o022`) | Anyone who can write it can choose what runs |
| Not owned by root (or the daemon's euid) | Same |
| A parse error, a bad template, a duplicate name, a native-name collision | A *partial* vocabulary is the dangerous outcome: it silently changes what a Node answers while looking healthy |

A set that fails to load leaves the Node with **no** Template Operations, and its
template-set fingerprint reads `unloadable`: a deliberately non-hex sentinel, so the failure
is visible fleet-wide instead of hiding as a plausible hash. A Node with no templates reports
an empty fingerprint. Both fail closed: every template dispatch reports `unsupported`.

## 4. Verify the rollout landed

The same mechanism as Policy, one field over:

- `list_nodes` / `describe_node` report `template_set_fingerprint` beside
  `policy_fingerprint`. A uniform fingerprint across a cohort means the pack landed
  byte-identically; an outlier is drift; `unloadable` is a broken set; empty means nothing is
  installed.
- `describe_node` reports the Node's full `template_vocabulary`: every loaded template with
  its risk class and typed slots. `reported: false` means *no snapshot captured yet* (the Node
  has not reconnected since the Relay restarted), never "this Node has no templates".
- `list_operations` with a `node_id` returns that Node's complete vocabulary: the four Native
  Operations (`source: "native"`) plus its Template Operations (`source: "template"`), each
  with slot constraints and an example. Without a `node_id` it returns the native part only,
  the only fleet-uniform part.

The fingerprint covers the raw bytes of every file in the set, path-prefixed and
length-delimited in sorted order, under a domain-separation prefix. A cosmetic edit, a rename
or a moved file all change it, and it can never collide with a Policy fingerprint.

## The `unsupported` outcome

Dispatching a template to a Node that has not loaded it reports `unsupported`: **not**
`failure`, and **not** `denied_by_policy`. Nothing executed and Policy was never consulted,
because the Node has no such Operation. A Policy preflight reports the same for the same Node
(`verdict: "unsupported"`), so a Plan never promises a run a dispatch will refuse.

`unsupported` across a cohort means the pack did not land there: check the fingerprint, then
config management. It never means Policy is too tight.

## What is not here yet

- **Signed, centrally distributed bundles**: v0.8.0 (ADR-0002's rewrite to
  "operator-rooted"). Until then, local files are the only path.

## The shipped read catalog

The daemon package installs a first-party pack at `/etc/relay-daemon/templates.d/relay-read/`:
seven `read`-class templates, trusted the way the binary is (you installed it).

| Operation | Parameters | Notes |
|---|---|---|
| `proc.list` | — | Full process table incl. command lines (which routinely carry secrets). |
| `disk.usage` | — | `df -P -T`. |
| `net.listening` | — | Listening TCP/UDP sockets and their processes. |
| `pkg.inventory` | — | dpkg, then rpm; a Node with neither errors rather than returning an empty list. |
| `service.status` | `unit` (identifier) | Fixed property list via `systemctl show` — parseable, and no spliced log lines. |
| `log.tail` | `unit` (identifier) | **Bounded at 200 lines by the template**, never by the caller. The catalog's widest egress surface. |
| `file.checksum` | `path` (path) | A digest is a content oracle; the shipped Policy denies it the same paths as `file.read`. |

The shipped default Policy (ADR-0022) allows exactly these names, so a freshly enrolled Node
answers the whole catalog with no local authoring. Narrowing `service.status`/`log.tail` from
`"*"` to your real unit list is the highest-value edit you can make to it.

## Security notes before you author

- `read` means "cannot change Node state". It does **not** mean "safe for the AI to see": a
  read result leaves the fleet for the model provider. Scope what a read template can reach in
  Policy (ADR-0021's data-egress section).
- A template, or a Policy rule, that can rewrite the daemon's config, binary, unit, or these
  template files is self-modifying Policy. Do not write one.
- The shell boundary is treated as hostile by design; validation and positional-parameter
  passing are the mitigation. Do not pass attacker-controlled values into a `path` slot and
  assume they are harmless: constrain values in Policy too, where review can see them.
