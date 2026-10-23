//! The second sanctioned spawn site in the daemon (invariant 1): `relay-daemon join`
//! enabling and starting the unit. The argv is a compile-time constant with an
//! absolute path, nothing in it comes from input, no shell runs, the child's
//! environment is cleared and its stdin is null. The whole spawn is the one
//! function below, and `clippy_write_ban.rs` pins its suppression to that
//! function's exact text.

use std::io;
use std::process::{Command, ExitStatus, Stdio};

/// The program `join` runs. Absolute, so `PATH` plays no part.
pub const SYSTEMCTL: &str = "/usr/bin/systemctl";

/// Its arguments: enable the packaged unit and start it now.
pub const SYSTEMCTL_ARGS: [&str; 3] = ["enable", "--now", "relay-daemon.service"];

/// Runs `systemctl enable --now relay-daemon.service` and waits for it. Its output
/// goes to the operator's terminal.
#[allow(
    clippy::disallowed_methods,
    reason = "the join spawn: literal argv, cleared environment, null stdin (invariant 1)"
)]
pub fn enable_and_start() -> io::Result<ExitStatus> {
    Command::new(SYSTEMCTL)
        .args(SYSTEMCTL_ARGS)
        .env_clear()
        .stdin(Stdio::null())
        .status()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The spawn is `Command::new(SYSTEMCTL).args(SYSTEMCTL_ARGS)` and nothing else
    /// (pinned by `clippy_write_ban.rs`), so these two constants are its whole argv.
    // Proves DI-37.
    #[test]
    fn join_spawn_argv_is_the_literal_constant() {
        assert_eq!(SYSTEMCTL, "/usr/bin/systemctl");
        assert!(
            SYSTEMCTL.starts_with('/'),
            "the program path must be absolute"
        );
        assert_eq!(SYSTEMCTL_ARGS, ["enable", "--now", "relay-daemon.service"]);
    }
}
