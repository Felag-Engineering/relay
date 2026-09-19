# 06 — Policy Catalog

**Artboard 10** (drawn as Policy Author; the layout below supersedes it). Arrange first-party
catalog fragments into cohorts and take the files away. **Milestone v0.7.0.**

*(The file keeps its `06-policy-author.md` name so existing links hold. The screen was the
per-Operation Policy Author until 2026-09-18.)*

**Capability:** `docs/specs/policy-catalog.md` — the claims live there (`PC-n`); this file is the
screen. If the two disagree, the capability spec wins.
**Governing:** ADR-0002, ADR-0011, ADR-0021, ADR-0022, ADR-0026, ADR-0033, invariants #2, #3, #9,
#12.
**Backend:** the catalog embedded in the Relay binary, byte-identical to the release artifact; daemon versions from the registry through
the capability layer's read lane. **No write path of any kind.**

## What this screen is for

"Let the web Nodes restart nginx" should be one fragment name added to one Ansible group, not a
hand-edited Policy file. This screen is where an operator finds that fragment, sees exactly what
it grants, groups it with others for each cohort, and leaves with the files and the
group-variables block.

It is the **proactive** half of a pair. Spec 07 is the reactive half — one rule, born from a
specific deny, for what the catalog does not cover.

## The hard boundary

**The Relay does not transmit Policy and has no code path that could.** This screen ends at the
operator's clipboard and says so on the screen (PC-15). Any future "apply to these Nodes" button
needs a new ADR and a threat model.

The Relay also **remembers nothing** about an arrangement (PC-9). The IaC repo is the only record
of what a cohort runs; the screen is a calculator, not a registry.

## Layout

Three columns.

**Left — the catalog.** Every catalog fragment, sectioned by highest risk class, all captioned
*opt-in; nothing here is live until config management installs it*. The shipped default Policy is
not listed: it is already on every Node and is not a catalog fragment.

Each row: the fragment name in mono, its one-line purpose, its risk badge, its required daemon
release, and its SHA-256 (PC-16). Expanding a row shows the full fragment text and **what this grants** in plain words
(PC-13). A fragment newer than some Nodes' daemons carries the count and the consequence on each
(PC-14): a daemon that predates the Policy directory silently ignores the fragment; a later
daemon that cannot load it refuses everything.

**Middle — cohorts.** Named columns (default names suggested from `node:` label values; editable)
that fragments are dragged into. Each cohort also has a **Narrow** control that adds deny rules —
never allows — emitted as that cohort's own deny fragment (PC-11). A "paste group_vars" control
reopens an arrangement from a previous export (PC-10).

**Right — output, per selected cohort.**

1. The group-variables block:
   ```yaml
   relay_policy_fragments: [nginx-restart, php-fpm-restart]
   ```
2. The files: each catalog fragment with its SHA-256, plus the cohort's deny fragment if it has
   one, labelled *generated here — review it; it has no release digest*.
3. The install task, below.

## The install task

```yaml
- name: check catalog fragments against the release SHA256SUMS
  ansible.builtin.stat:
    path: "{{ relay_catalog_dir }}/{{ item }}.toml"
    checksum_algorithm: sha256
  delegate_to: localhost
  loop: "{{ relay_policy_fragments }}"
  register: relay_catalog_stat

- ansible.builtin.assert:
    that: item.stat.checksum == relay_catalog_sha256[item.item]   # from the release, not the Relay
  loop: "{{ relay_catalog_stat.results }}"

- name: install Relay Policy fragments
  ansible.builtin.copy:
    src: "{{ relay_catalog_dir }}/{{ item }}.toml"
    dest: "/etc/relay-daemon/policy.d/{{ item }}.toml"
    owner: root
    group: root
    mode: "0644"
    validate: relay-daemon policy check %s --strict
  loop: "{{ relay_policy_fragments }}"
  notify: restart relay-daemon
```

Paths, variable names and the check's mechanism are illustrative. Four properties are
load-bearing and none may be dropped: the digest comes from the release, never from this screen
(PC-16), and this task itself is Relay-rendered text the operator reviews once and commits (Open
question 2); `validate:` runs the
daemon's own checker before the file is placed; the mode is fixed because the daemon refuses a
group- or world-writable fragment; and a copy, never a symlink, because the Policy directory
refuses symlinks. The daemon applies Policy on restart (`daemon-installation.md`).

## Guidance the screen must carry

1. **Narrowing `log.tail` is the highest-value narrowing.** A journal carries whatever a service
   chooses to log; the Narrow control offers it first.
2. **`read` does not mean safe to see.** It means *cannot change Node state*. A read result flows
   onward to the model provider (ADR-0021).

## Must not appear

- Any control that writes, pushes, distributes or applies Policy to a Node.
- Any claim that the Relay will roll this out, or that a Task *would* be allowed.
- Any allow-rule editor. Allows come from catalog fragments or from spec 07.
- Any saved or shared cohort, or a comparison of Nodes against one.

## Acceptance

The capability spec's `PC-n` claims, verbatim. This screen adds:

- [ ] The catalog is rendered from the embedded catalog, never hand-listed in a template.
- [ ] Copying a file yields it whole; any on-screen collapse is presentational.
- [ ] No route on this screen writes anything anywhere.
