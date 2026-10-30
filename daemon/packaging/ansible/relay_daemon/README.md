# relay_daemon

An Ansible role that installs the `relay-daemon` package on a Node and joins it to a Relay
with a join string from your vault. Your config management runs it; the Relay never does
([daemon packaging](../../README.md), [enrollment](../../../../docs/operations/enrollment.md)).

On a Node with no identity it:

1. installs the `relay-daemon` package from a directory on the controller, unless
   `/usr/bin/relay-daemon` already exists. The role checks that path, not the package database.
   It installs the package only if it is the package of the role's own release. The version
   read from the package's metadata on the controller, not the file name, is the package's
   release;
2. runs `relay-daemon join` with the join string on **standard input**, so the string reaches
   no file, no command line and no log on the Node. `join` enables and starts the unit.

It also:

- fails, installing nothing and not joining, on a Node with some but not all of its identity
  files;
- refuses, without joining, a Node where sudo records standard input, because the string would
  then be recorded (see Limits);
- refuses, changing nothing on the Node, a package whose version is not the role's release.
  The refusal names the package's version, the role's release and the directory:

      refusing a relay-daemon package from another release:
      relay-daemon_0.2.0-1_amd64.deb in /srv/relay-daemon-package is version 0.2.0-1, and
      this role is from release 0.3.0, which installs package version 0.3.0-1. Put release
      0.3.0's relay-daemon package in /srv/relay-daemon-package. The role changed nothing
      on the Node

  The fix is to put that release's package in the directory and run again;
- refuses a directory holding more than one package for the Node's platform, and never picks
  one;
- changes nothing on an enrolled Node;
- places no Policy fragment. Policy is yours to deliver (ADR-0002);
- carries a handler, `relay_daemon : Restart relay-daemon`, that restarts the daemon. Notify it
  from your own task that writes a Policy fragment, because the daemon loads Policy only at
  start. The handler does not validate: check the composed Policy first, the Policy file and
  the Policy directory together:
  `relay-daemon policy check /etc/relay-daemon/policy.toml --policy-dir /etc/relay-daemon/policy.d --strict`
  ([policy-as-code.md](../../../../docs/operations/policy-as-code.md));
- never upgrades or downgrades an installed daemon, whatever its version: it joins the daemon
  it finds as it is. Upgrades are your config management's (ADR-0014);
- carries no release version when copied from the repository rather than a release tarball, and
  then installs nothing. It still joins a Node whose daemon is installed.

## Variables

| Variable | |
|---|---|
| `relay_daemon_join_string` | Required, no default. The join string from your vault. |
| `relay_daemon_package_dir` | Required. A directory on the controller holding this release's verified `relay-daemon` package for the Node's architecture, as downloaded beside `SHA256SUMS`. A package of any other version is refused. |

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
  tasks:
    - name: Place a Policy fragment
      ansible.builtin.copy:
        src: policies/10-nginx.toml
        dest: /etc/relay-daemon/policy.d/10-nginx.toml
        owner: root
        group: root
        mode: "0644"
      notify: "relay_daemon : Restart relay-daemon"
```

## Limits

- Only Debian 13 on x86_64 is proven in CI. The rpm (dnf) branch is untested.
- The controller needs `dpkg-deb` to install on apt Nodes and `rpm` on dnf Nodes, because the
  package's version is read there. The version check runs only when the role installs: an
  installed daemon, of any version, is joined as found and never upgraded or downgraded. The
  rpm branch's version read is untested, like the rest of that branch.
- Only the package's version is read, not its name or architecture, and the controller parses
  the candidate with `dpkg-deb` or `rpm` as the controller user, the trust it would have as
  root on the Node. Verify the package against `SHA256SUMS` first.
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
- The release check guards against the wrong package, not against an operator who deliberately
  overrides the role's internal variables with extra-vars. Ansible's extra-vars outrank
  everything a role holds, registered results included, so no role can refuse that.
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
the verified package of the same release; the role refuses any other version.
