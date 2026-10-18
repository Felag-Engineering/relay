//! The second sanctioned spawn site in the daemon (invariant 1): `relay-daemon join`
//! enabling and starting the unit. The argv is a compile-time constant with an
//! absolute path, nothing in it comes from input, no shell runs, the child's
//! environment is cleared and its stdin is null. `clippy_write_ban.rs` pins the
//! suppression below to the exact text of `command`.

use std::io;
use std::process::{Command, ExitStatus, Stdio};

/// The program `join` runs. Absolute, so `PATH` plays no part.
pub const SYSTEMCTL: &str = "/usr/bin/systemctl";

/// Its arguments: enable the packaged unit and start it now.
pub const SYSTEMCTL_ARGS: [&str; 3] = ["enable", "--now", "relay-daemon.service"];

#[allow(
    clippy::disallowed_methods,
    reason = "the join spawn: literal argv, cleared environment, null stdin (invariant 1)"
)]
fn command() -> Command {
    let mut cmd = Command::new(SYSTEMCTL);
    cmd.args(SYSTEMCTL_ARGS).env_clear().stdin(Stdio::null());
    cmd
}

/// Runs `systemctl enable --now relay-daemon.service` and waits for it. Its output
/// goes to the operator's terminal.
pub fn enable_and_start() -> io::Result<ExitStatus> {
    command().status()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn join_spawn_argv_is_the_literal_constant() {
        let cmd = command();
        assert_eq!(cmd.get_program(), OsStr::new("/usr/bin/systemctl"));
        assert!(
            SYSTEMCTL.starts_with('/'),
            "the program path must be absolute"
        );
        let args: Vec<&OsStr> = cmd.get_args().collect();
        assert_eq!(
            args,
            [
                OsStr::new("enable"),
                OsStr::new("--now"),
                OsStr::new("relay-daemon.service")
            ]
        );
        assert_eq!(
            cmd.get_envs().count(),
            0,
            "no variable is set for the child: its environment is cleared, never extended"
        );
        assert_eq!(cmd.get_current_dir(), None);
    }
}
