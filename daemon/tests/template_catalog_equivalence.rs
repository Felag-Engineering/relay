//! The shipped `relay-read` catalog produces the same output under the
//! positional-parameter rendering as it did under the retired single-quote
//! splicing, for the same inputs (ADR-0021 amendment of 2026-10-14).
//!
//! Each catalog program (`ps`, `systemctl`, `df`, `ss`, `dpkg-query`, `rpm`,
//! `journalctl`, `sha256sum`) is a stub on a fixed `PATH` that prints its name and
//! arguments NUL-separated, so the comparison is hermetic and byte-exact: the
//! two renderings must hand every program the same arguments.

mod common;
#[path = "common/shell_runner.rs"]
mod shell_runner;

use std::os::unix::fs::PermissionsExt;

use common::TempDir;
use relay_ops::operations::template::{SlotType, TemplateDef};
use shell_runner::{invoke, retired_splice, run_sh_argv, shells, stderr, stdout, ShellRunner};

const CATALOG: &str = include_str!("../packaging/templates.d/relay-read/catalog.toml");

#[derive(serde::Deserialize)]
struct CatalogFile {
    template: Vec<TemplateDef>,
}

const UNITS: [&str; 3] = ["nginx", "ssh.service", "user@1000.service"];
const PATHS: [&str; 4] = [
    "/etc/hostname",
    "/var/log/syslog",
    "/srv/app-1.2_x/data@2026,v2+final.txt",
    "/home/josé/notes",
];

/// Stubs that print their own name and arguments, NUL-terminated. They use only
/// shell builtins, since the `PATH` holds nothing else.
fn stub_dir() -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new("catalog-stubs");
    let path = dir.path().to_path_buf();
    std::fs::create_dir_all(&path).expect("create stub dir");
    for program in [
        "ps",
        "systemctl",
        "df",
        "ss",
        "dpkg-query",
        "rpm",
        "journalctl",
        "sha256sum",
    ] {
        let file = path.join(program);
        std::fs::write(&file, "#!/bin/sh\nprintf '%s\\000' \"${0##*/}\" \"$@\"\n")
            .expect("write stub");
        // Explicit mode: a strict umask must not leave a stub unexecutable.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755))
            .expect("chmod stub");
    }
    (dir, path)
}

fn inputs(def: &TemplateDef) -> Vec<Vec<(&'static str, &'static str)>> {
    match def.slots.first().map(|s| &s.ty) {
        None => vec![vec![]],
        Some(SlotType::Identifier) => UNITS.iter().map(|u| vec![("unit", *u)]).collect(),
        Some(SlotType::Path) => PATHS.iter().map(|p| vec![("path", *p)]).collect(),
        Some(other) => panic!("catalog slot type {other:?} has no inputs here"),
    }
}

#[tokio::test]
async fn catalog_output_is_unchanged_by_the_new_rendering() {
    let defs = toml::from_str::<CatalogFile>(CATALOG)
        .expect("the shipped catalog parses")
        .template;
    assert_eq!(defs.len(), 7);
    let (_guard, stubs) = stub_dir();

    let mut compared = 0;
    for shell in shells() {
        let runner = ShellRunner::with_path(&shell, &stubs);
        for def in &defs {
            for args in inputs(def) {
                let new = invoke(def, &args, &runner).await;
                let retired = run_sh_argv(
                    &runner,
                    vec![
                        "/bin/sh".to_string(),
                        "-c".to_string(),
                        retired_splice(&def.body, &args),
                    ],
                )
                .await;

                let label = format!("{} {} {args:?}", shell.label, def.name);
                assert_eq!(new.exit_code, 0, "{label}: stderr {:?}", stderr(&new));
                assert!(!new.stdout.is_empty(), "{label}: the stub printed nothing");
                assert_eq!(new.stdout, retired.stdout, "{label}: stdout");
                assert_eq!(new.stderr, retired.stderr, "{label}: stderr");
                assert_eq!(new.exit_code, retired.exit_code, "{label}: exit code");
                compared += 1;
            }
        }
    }
    // 3 shells x (4 slot-free + 3 units x 2 + 4 paths x 1) templates-with-inputs.
    assert_eq!(compared, 3 * (4 + 3 * 2 + 4));

    // Spot-check that the stubs really received the value as one argument.
    let shell = &shells()[0];
    let runner = ShellRunner::with_path(shell, &stubs);
    let def = defs.iter().find(|d| d.name == "file.checksum").unwrap();
    let r = invoke(def, &[("path", "/home/josé/notes")], &runner).await;
    assert_eq!(stdout(&r), "sha256sum\0--\0/home/josé/notes\0");
}
