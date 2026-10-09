//! Proves every `disallowed-methods` entry of this crate's clippy.toml fires.
//!
//! Compiled only with `--features ban-probe` (see `lib.rs`), so it is never part
//! of a normal build. `scripts/clippy-ban-probe.sh` lints this crate with that
//! feature and requires clippy to report `disallowed_methods` on EXACTLY the
//! lines ending in the marker below: a missing line is a ban entry that does not
//! fire (a typo'd path), an extra line is a hit outside this file.
//!
//! The probe lives outside `src/` so no source-text guard reads it as production.
//! Entries whose first path segment is not a dependency of this crate (`tokio::*`)
//! are skipped by clippy and cannot be probed here (the `tokio::*` entries are
//! probed in relay-exec and relay-ops). `forbid(unsafe_code)` holds
//! in the real crate, so the libc entries are probed as function-item references,
//! never calls.
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

fn probe_libc_open() {
    let _ = libc::open; // PROBE
}

fn probe_libc_open64() {
    let _ = libc::open64; // PROBE
}

fn probe_libc_openat() {
    let _ = libc::openat; // PROBE
}

fn probe_libc_openat64() {
    let _ = libc::openat64; // PROBE
}

fn probe_libc_creat() {
    let _ = libc::creat; // PROBE
}

fn probe_libc_creat64() {
    let _ = libc::creat64; // PROBE
}

fn probe_libc_write() {
    let _ = libc::write; // PROBE
}

fn probe_libc_pwrite() {
    let _ = libc::pwrite; // PROBE
}

fn probe_libc_pwrite64() {
    let _ = libc::pwrite64; // PROBE
}

fn probe_libc_writev() {
    let _ = libc::writev; // PROBE
}

fn probe_libc_unlink() {
    let _ = libc::unlink; // PROBE
}

fn probe_libc_unlinkat() {
    let _ = libc::unlinkat; // PROBE
}

fn probe_libc_rename() {
    let _ = libc::rename; // PROBE
}

fn probe_libc_renameat() {
    let _ = libc::renameat; // PROBE
}

fn probe_libc_renameat2() {
    let _ = libc::renameat2; // PROBE
}

fn probe_libc_mkdir() {
    let _ = libc::mkdir; // PROBE
}

fn probe_libc_mkdirat() {
    let _ = libc::mkdirat; // PROBE
}

fn probe_libc_mkfifo() {
    let _ = libc::mkfifo; // PROBE
}

fn probe_libc_mkfifoat() {
    let _ = libc::mkfifoat; // PROBE
}

fn probe_libc_mknod() {
    let _ = libc::mknod; // PROBE
}

fn probe_libc_mknodat() {
    let _ = libc::mknodat; // PROBE
}

fn probe_libc_chmod() {
    let _ = libc::chmod; // PROBE
}

fn probe_libc_fchmod() {
    let _ = libc::fchmod; // PROBE
}

fn probe_libc_fchmodat() {
    let _ = libc::fchmodat; // PROBE
}

fn probe_libc_chown() {
    let _ = libc::chown; // PROBE
}

fn probe_libc_fchown() {
    let _ = libc::fchown; // PROBE
}

fn probe_libc_lchown() {
    let _ = libc::lchown; // PROBE
}

fn probe_libc_fchownat() {
    let _ = libc::fchownat; // PROBE
}

fn probe_libc_truncate() {
    let _ = libc::truncate; // PROBE
}

fn probe_libc_truncate64() {
    let _ = libc::truncate64; // PROBE
}

fn probe_libc_ftruncate() {
    let _ = libc::ftruncate; // PROBE
}

fn probe_libc_ftruncate64() {
    let _ = libc::ftruncate64; // PROBE
}

fn probe_libc_link() {
    let _ = libc::link; // PROBE
}

fn probe_libc_linkat() {
    let _ = libc::linkat; // PROBE
}

fn probe_libc_symlink() {
    let _ = libc::symlink; // PROBE
}

fn probe_libc_symlinkat() {
    let _ = libc::symlinkat; // PROBE
}

fn probe_libc_remove() {
    let _ = libc::remove; // PROBE
}

fn probe_libc_rmdir() {
    let _ = libc::rmdir; // PROBE
}

fn probe_libc_fallocate() {
    let _ = libc::fallocate; // PROBE
}

fn probe_libc_fallocate64() {
    let _ = libc::fallocate64; // PROBE
}

fn probe_libc_posix_fallocate() {
    let _ = libc::posix_fallocate; // PROBE
}

fn probe_libc_fopen() {
    let _ = libc::fopen; // PROBE
}

fn probe_libc_fopen64() {
    let _ = libc::fopen64; // PROBE
}

fn probe_libc_freopen() {
    let _ = libc::freopen; // PROBE
}

fn probe_libc_mkstemp() {
    let _ = libc::mkstemp; // PROBE
}

fn probe_libc_syscall() {
    let _ = libc::syscall; // PROBE
}

fn probe_libc_execv() {
    let _ = libc::execv; // PROBE
}

fn probe_libc_execve() {
    let _ = libc::execve; // PROBE
}

fn probe_libc_execvp() {
    let _ = libc::execvp; // PROBE
}

fn probe_libc_execvpe() {
    let _ = libc::execvpe; // PROBE
}

fn probe_libc_execl() {
    let _ = libc::execl; // PROBE
}

fn probe_libc_execle() {
    let _ = libc::execle; // PROBE
}

fn probe_libc_execlp() {
    let _ = libc::execlp; // PROBE
}

fn probe_libc_fexecve() {
    let _ = libc::fexecve; // PROBE
}

fn probe_libc_fork() {
    let _ = libc::fork; // PROBE
}

fn probe_libc_vfork() {
    let _ = libc::vfork; // PROBE
}

fn probe_libc_posix_spawn() {
    let _ = libc::posix_spawn; // PROBE
}

fn probe_libc_posix_spawnp() {
    let _ = libc::posix_spawnp; // PROBE
}

fn probe_libc_system() {
    let _ = libc::system; // PROBE
}

fn probe_libc_execveat() {
    let _ = libc::execveat; // PROBE
}

fn probe_libc_clone() {
    let _ = libc::clone; // PROBE
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

fn probe_libc_pwritev() {
    let _ = libc::pwritev; // PROBE
}

fn probe_libc_pwritev2() {
    let _ = libc::pwritev2; // PROBE
}

fn probe_libc_copy_file_range() {
    let _ = libc::copy_file_range; // PROBE
}

fn probe_libc_splice() {
    let _ = libc::splice; // PROBE
}

fn probe_libc_sendfile() {
    let _ = libc::sendfile; // PROBE
}

fn probe_libc_utimensat() {
    let _ = libc::utimensat; // PROBE
}

fn probe_libc_futimens() {
    let _ = libc::futimens; // PROBE
}

fn probe_libc_setxattr() {
    let _ = libc::setxattr; // PROBE
}

fn probe_libc_fsetxattr() {
    let _ = libc::fsetxattr; // PROBE
}

fn probe_libc_lsetxattr() {
    let _ = libc::lsetxattr; // PROBE
}

fn probe_libc_removexattr() {
    let _ = libc::removexattr; // PROBE
}

fn probe_libc_fremovexattr() {
    let _ = libc::fremovexattr; // PROBE
}

fn probe_libc_lremovexattr() {
    let _ = libc::lremovexattr; // PROBE
}

fn probe_libc_open_by_handle_at() {
    let _ = libc::open_by_handle_at; // PROBE
}
