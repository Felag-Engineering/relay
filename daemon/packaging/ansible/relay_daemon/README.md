# relay_daemon

An Ansible role that installs the `relay-daemon` package on a Node and joins it to a Relay
with a join string from your vault. Your config management runs it; the Relay never does
([daemon packaging](../../README.md), [enrollment](../../../../docs/operations/enrollment.md)).

On a Node with no identity it:

1. installs the `relay-daemon` package from a directory on the controller, unless
   `/usr/bin/relay-daemon` already exists. The role checks that path, not the package database;
2. runs `relay-daemon join` with the join string on **standard input**, so the string reaches
   no file, no command line and no log on the Node. `join` enables and starts the unit.

It also:

- fails, installing nothing and not joining, on a Node with some but not all of its identity
  files;
- refuses, without joining, a Node where sudo records standard input, because the string would
  then be recorded (see Limits);
- changes nothing on an enrolled Node;
- places no Policy fragment. Policy is yours to deliver (ADR-0002);
- never upgrades or downgrades an installed daemon, whatever its version: it joins the daemon
  it finds as it is. Upgrades are your config management's (ADR-0014).

## Variables

| Variable | |
|---|---|
| `relay_daemon_join_string` | Required, no default. The join string from your vault. |
| `relay_daemon_package_dir` | Required. A directory on the controller holding the verified `relay-daemon` package for the Node's architecture, as downloaded beside `SHA256SUMS`. |

Put the join string in the vault with
`ansible-vault encrypt_string --stdin-name relay_daemon_join_string`. The play must set
`become: true`.

```yaml
- hosts: nodes
  become: true
  roles:
    - role: relay_daemon
      vars:
        relay_daemon_package_dir: /srv/relay-daemon-package
```

## Limits

- Only Debian 13 on x86_64 is proven in CI. The rpm (dnf) branch is untested.
- The join task forces pipelining and refuses to stage anything on the Node. Become via `su`,
  `keep_remote_files`, or a connection without pipelining makes that task fail (unreachable)
  before it writes anything.
- The join string passes through the become method, so the role supports two ways to be root:
  sudo, or a connection that is already root with no become. Any other become method fails
  before the join task. Under sudo the role reads the sudo configuration as root and refuses,
  without joining, when sudo records standard input: a `log_input` default or a `LOG_INPUT:`
  tag in `sudo -ll -U` for the connecting user, or an un-negated `log_input` on any
  non-comment line of `/etc/sudoers` or `/etc/sudoers.d`. It errs towards refusing: a
  `log_input` that a later entry negates still refuses, and so does a file in `sudoers.d`
  that sudo itself ignores. It also refuses when `sudo -ll` fails.
- Recording the role cannot detect is outside it: a session recorder or terminal auditing on the
  Node (for example tlog or auditd TTY auditing), or a shell-level recorder, records whatever
  is piped to a privileged command, the join string included. `sudoers` files the role does not
  read (an `@include` of another path) are seen only through the `sudo -ll` listing.
- `requiretty` in sudoers breaks pipelining, and the task then fails.
- When the join task fails unreachable, Ansible skips the cleanup, so the temporary directory
  holding the package stays on the Node. It holds no secret.
- The apt module needs `python3-apt` on the Node, and installs it if it is missing.
- The join task's guard rests on `ansible_remote_tmp`, `ansible_system_tmpdirs`,
  `ansible_become_user` and `ansible_sudo_user`. The role stops before the join task if you
  have set any of them to something else, by an extra-var, `set_fact`, `include_vars` or a role
  parameter. Leave them unset for this role.
- The join string is an argument of the join task, so a controller callback plugin receives it
  in plain text. `no_log` is honoured by Ansible's own output, not necessarily by third-party
  callbacks such as ARA. Do not enable one that records task arguments.
- The enrolled check reads the packaged state directory, `/var/lib/relay-daemon`, only. A
  `RELAY_STATE_DIR` override in the environment file is not seen. The role installs nothing
  there, because the daemon is already installed, and `join` itself still changes nothing.

The release attaches the role as `relay_daemon-<version>.tar.gz`, listed in the signed
`SHA256SUMS`, and the install matrix runs that tarball before the release publishes. Verify the
tarball as in [release-artifacts.md](../../../../docs/operations/release-artifacts.md), extract it
(`tar -xzf`) into your roles path, and point `relay_daemon_package_dir` at the directory holding
the verified package of the same release.
