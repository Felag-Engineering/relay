# Template packs: authoring, distribution, and verification

How Template Operations are authored, installed, and confirmed on a fleet — as
code, in the customer's IaC repo, **never over the wire** (ADR-0002, ADR-0021).
Companion documents: [policy-as-code.md](policy-as-code.md) (the identical
workflow for Policy, which still decides whether a template may run),
[relay-daemon-install.md](relay-daemon-install.md),
[`daemon/templates.example.toml`](../../daemon/templates.example.toml) (the
annotated example).

## What a Template Operation is

An operator-authored shell template with named, typed-validated **parameter
slots** (ADR-0021, realizing ADR-0001's tier 2). The trusted author fixes the
command structure; a caller supplies only parameter *values*, and substitution
can never alter that structure — each value is validated against its slot's
declared type and then POSIX single-quoted before it is placed in the exact
lexical position the author wrote.

Templates exist so the typed path can grow at *your* cadence instead of the
daemon's release cadence, keeping fleet-specific work off Raw Exec — the most
dangerous path (ADR-0001). Three things they are **not**:

- **Not a Policy bypass.** A template's name enters the Node's Policy
  vocabulary like any Native Operation: deny-by-default, deny-beats-allow,
  argument-level constraints. Installing a template allows nothing by itself.
- **Not remotely installable.** The Relay may read a Node's template set; it can
  never author or modify one. Widening a Node's vocabulary is an out-of-band act
  through the reviewed config-management path, exactly like widening its Policy.
- **Not fleet-uniform.** Vocabulary is per-Node from here on. A Node without a
  given template reports the distinct `unsupported` outcome — see below.

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

A **template pack** is one immediate subdirectory of the template root,
installed and versioned as a unit — the convention the shipped read catalog and
any first- or third-party pack follow. Loose `*.toml` files directly in the root
are equally valid for your own templates; use packs when a set of templates
travels together (one source, one version, one uninstall).

Nesting stops there. A directory inside a pack is skipped with a warning rather
than silently traversed, so what loads is always exactly what you can see in two
levels of `ls`.

## 1. Author

See [`daemon/templates.example.toml`](../../daemon/templates.example.toml) for
the annotated reference. In brief:

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
type = "path"               # absolute + canonical, ≤4096 bytes, no control chars
```

Slot types: `identifier`, `integer`, `path`, `enum` (with `values`). Prefer
`enum` whenever the value space is genuinely finite — it is the only type whose
accept-set you control completely.

Two authoring rules the loader enforces, both refusals at load time:

- **Every `{{slot}}` must be a standalone, whitespace-delimited token in an
  unquoted context.** `--file={{path}}` and `'{{path}}'` fail to load. That rule
  is what makes "one slot fills exactly one word" true by construction.
- **`risk_class` is mandatory**, and a template may not shadow a Native
  Operation (`system.facts`, `file.read`, `service.restart`, `pkg.install`) or
  `raw_exec`. The native vocabulary is frozen (ADR-0021) and always wins.

## 2. Validate

The whole set is validated at daemon start. `relay-daemon policy check` answers
`--would-allow` against the same live evaluator, resolving names through the
same per-Node vocabulary a real dispatch would (so on a Node with the pack
installed, a template name answers `ALLOW`/`DENY`; elsewhere it answers
`UNSUPPORTED`). Dedicated template *linting* — structure, slot hygiene, and the
self-reference lint — lands with issue #292.

## 3. Distribute

Config management copies the files and restarts the daemon, exactly as for
`policy.toml`:

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

The daemon's loader refuses anything it cannot trust, and refuses it **for the
whole set**:

| Refusal | Why |
|---|---|
| A symlinked file, pack directory, or template root | Whoever controls the link target would choose the vocabulary (`O_NOFOLLOW`, `lstat`-typed directory entries) |
| Not a regular file (FIFO, device, socket) | Same descriptor that is validated is the one read — no TOCTOU gap |
| Group- or world-writable (`mode & 0o022`) | Anyone who can write it can choose what runs |
| Not owned by root (or the daemon's euid) | Same |
| A parse error, a bad template, a duplicate name, a native-name collision | A *partial* vocabulary is the dangerous outcome: it silently changes what a Node answers while looking healthy |

A set that fails to load leaves the Node with **no** Template Operations, and
its reported template-set fingerprint reads `unloadable` — a deliberately
non-hex sentinel so the failure is visible fleet-wide instead of hiding as a
plausible-looking hash. A Node with no templates installed reports an empty
fingerprint. Both cases are fail-closed: every template dispatch reports
`unsupported`.

## 4. Verify the rollout landed

Same mechanism as Policy, one field over:

- `list_nodes` / `describe_node` report `template_set_fingerprint` beside
  `policy_fingerprint`. A uniform fingerprint across a cohort means the pack
  landed byte-identically; an outlier is drift; `unloadable` is a broken set;
  empty is "nothing installed".
- `describe_node` reports the Node's full `template_vocabulary`: every loaded
  template with its risk class and typed slots. `reported: false` means *no
  snapshot captured yet* (the Node has not reconnected since the Relay
  restarted) — never "this Node has no templates".
- `list_operations` with a `node_id` returns that Node's complete vocabulary:
  the four native Operations (`source: "native"`) plus its Template Operations
  (`source: "template"`), each with slot constraints and an example. Without a
  `node_id` you get the native part only, because that is the only part that is
  fleet-uniform.

The fingerprint is over the raw bytes of every file in the set, path-prefixed
and length-delimited in sorted order, under a domain-separation prefix — so a
cosmetic edit, a rename, or a moved file all change it (the drift signal you
want), and it can never collide with a Policy fingerprint.

## The `unsupported` outcome

Dispatching a template to a Node that has not loaded it reports
`unsupported` — **not** `failure`, and **not** `denied_by_policy`. Nothing
executed and the Node's Policy was never consulted: it has no such Operation to
decide about. Plan mode reports the same conclusion for the same Node
(`verdict: "unsupported"`), so a Plan never promises a run that a dispatch will
refuse.

Practically: `unsupported` across a cohort means the pack did not land there —
check the fingerprint, then config management. It never means Policy is too
tight.

## What is not here yet

- **Signed, centrally distributed bundles** — v0.8.0 (ADR-0002's rewrite to
  "operator-rooted"). Until then, local files are the only path, and this
  workflow is the whole story.
- **Template linting in `policy check`**, including the self-reference lint that
  warns when a rule's reach includes the daemon's own config, binary, unit, or
  these template files — issue #292.
- **The shipped first-party read catalog** — issue #293.

## Security notes worth re-reading before you author

- `read` means "cannot change Node state". It does **not** mean "safe for the AI
  to see": a read result leaves the fleet for the model provider. Scope what a
  read template can reach in Policy (ADR-0021's data-egress section).
- A template — or a Policy rule — that can rewrite the daemon's config, binary,
  unit, or these template files is self-modifying Policy. Do not write one.
- The shell boundary is treated as hostile by design, and the daemon's
  validation and quoting are its mitigation. That is not a licence to pass
  attacker-controlled values into a `path` slot and assume they are harmless:
  constrain values in Policy too, where you can see them in review.
