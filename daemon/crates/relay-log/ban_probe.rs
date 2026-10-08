//! Proves every `std::` entry of this crate's clippy.toml fires.
//!
//! Compiled only with `--features ban-probe`, so never part of a normal build.
//! `scripts/clippy-ban-probe.sh` lints the workspace with that feature and
//! requires clippy to report `disallowed_methods` on EXACTLY the lines ending in
//! the marker below. The `libc::` and `tokio::` entries of the shared clippy.toml
//! name crates this one does not depend on, so they are proven in `relay-policy`.
//! The probe lives outside `src/` so no source-text guard reads it as production.
#![allow(unused, deprecated)]

fn probe_fs_write() {
    let _ = std::fs::write("", ""); // PROBE
}

fn probe_fs_rename() {
    let _ = std::fs::rename("", ""); // PROBE
}

fn probe_fs_copy() {
    let _ = std::fs::copy("", ""); // PROBE
}

fn probe_fs_remove_file() {
    let _ = std::fs::remove_file(""); // PROBE
}

fn probe_fs_remove_dir() {
    let _ = std::fs::remove_dir(""); // PROBE
}

fn probe_fs_remove_dir_all() {
    let _ = std::fs::remove_dir_all(""); // PROBE
}

fn probe_fs_create_dir() {
    let _ = std::fs::create_dir(""); // PROBE
}

fn probe_fs_create_dir_all() {
    let _ = std::fs::create_dir_all(""); // PROBE
}

fn probe_fs_set_permissions() {
    let p = std::fs::metadata("").unwrap().permissions();
    let _ = std::fs::set_permissions("", p); // PROBE
}

fn probe_fs_hard_link() {
    let _ = std::fs::hard_link("", ""); // PROBE
}

fn probe_fs_soft_link() {
    let _ = std::fs::soft_link("", ""); // PROBE
}

fn probe_file_create() {
    let _ = std::fs::File::create(""); // PROBE
}

fn probe_file_create_new() {
    let _ = std::fs::File::create_new(""); // PROBE
}

fn probe_file_set_len() {
    let _ = std::fs::File::open("").unwrap().set_len(0); // PROBE
}

fn probe_file_set_permissions() {
    let f = std::fs::File::open("").unwrap();
    let p = std::fs::metadata("").unwrap().permissions();
    let _ = f.set_permissions(p); // PROBE
}

fn probe_openoptions_write() {
    let _ = std::fs::OpenOptions::new().write(true); // PROBE
}

fn probe_openoptions_append() {
    let _ = std::fs::OpenOptions::new().append(true); // PROBE
}

fn probe_openoptions_create() {
    let _ = std::fs::OpenOptions::new().create(true); // PROBE
}

fn probe_openoptions_create_new() {
    let _ = std::fs::OpenOptions::new().create_new(true); // PROBE
}

fn probe_openoptions_truncate() {
    let _ = std::fs::OpenOptions::new().truncate(true); // PROBE
}

fn probe_dirbuilder_new() {
    let _ = std::fs::DirBuilder::new(); // PROBE
}

fn probe_unix_symlink() {
    let _ = std::os::unix::fs::symlink("", ""); // PROBE
}

fn probe_unix_chown() {
    let _ = std::os::unix::fs::chown("", None, None); // PROBE
}

fn probe_unix_lchown() {
    let _ = std::os::unix::fs::lchown("", None, None); // PROBE
}

fn probe_unix_fchown() {
    let f = std::fs::File::open("").unwrap();
    let _ = std::os::unix::fs::fchown(f, None, None); // PROBE
}

fn probe_openoptionsext_custom_flags() {
    let mut o = std::fs::OpenOptions::new();
    let _ = std::os::unix::fs::OpenOptionsExt::custom_flags(&mut o, 0); // PROBE
}

fn probe_process_command_new() {
    let _ = std::process::Command::new(""); // PROBE
}

fn probe_file_set_times() {
    let f = std::fs::File::open("").unwrap();
    let _ = f.set_times(std::fs::FileTimes::new()); // PROBE
}

fn probe_file_set_modified() {
    let f = std::fs::File::open("").unwrap();
    let _ = f.set_modified(std::time::SystemTime::UNIX_EPOCH); // PROBE
}

fn probe_unix_listener_bind() {
    let _ = std::os::unix::net::UnixListener::bind(""); // PROBE
}

fn probe_unix_datagram_bind() {
    let _ = std::os::unix::net::UnixDatagram::bind(""); // PROBE
}
