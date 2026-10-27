//! The daemon's single environment/config surface, read once at startup and
//! threaded down. Startup follows one plan with two outcomes (ADR-0031
//! decision 4; DI-25's exit rule): a complete identity is used, and no identity
//! is the one clean exit; anything in between refuses. The daemon reads no join
//! string: `relay-daemon join` enrolls, in the process that read it (DI-42), and
//! a set `RELAY_JOIN` is refused by name (DI-43). The Relay address resolves from
//! `RELAY_ADDRESS` or `--relay` first, then from the address persisted at
//! enrollment, with no default. Also centralizes RELAY_SERVER_NAME and the
//! http→https scheme normalization.
//!
//! Also hosts the one place `join`'s enrollment settings are named
//! ([`JOIN_SETTINGS`], [`join_enroll_config`]), and daemon-local hard limits
//! (e.g. [`MAX_OUTPUT_BYTES`]) that are compile-time constants, not env-derived
//! — kept here as the daemon's single neutral config-adjacent home rather than
//! scattered per call site. The spawned-child `setrlimit` bounds
//! (`ResourceLimits`) live in relay-exec's `limits` module.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::enroll::{node_labels_from_env, parse_node_labels, state_dir_from_env};
use crate::enroll::{EnrollConfig, EnrollError};
use crate::gen::Facts;
use crate::identity::{self, load_relay_addr, validate_endpoint_scheme, IdentityError};
use relay_transport::join_string::{JoinString, JoinStringError};

/// The longest join string `relay-daemon join` reads. A real join string is well
/// under 1 KiB; the cap bounds what reaches the decoder.
pub const MAX_JOIN_STRING_LEN: usize = 4096;

/// Settings the daemon refuses to start with, each paired with what to do
/// instead. A retired setting is refused by name, never silently ignored, so a
/// stale line in an existing environment file is noticed.
pub const RETIRED_SETTINGS: [(&str, &str); 1] = [(
    "RELAY_JOIN",
    "if this Node is not yet enrolled, give the join string to relay-daemon join on standard input",
)];

/// The only settings `relay-daemon join` reads: the state directory, the two
/// addresses, the SNI name and the labels. `join` takes no CA bundle path and no
/// bare token from any setting (EN-30).
pub const JOIN_SETTINGS: [&str; 5] = [
    "RELAY_STATE_DIR",
    "RELAY_ADDRESS",
    "RELAY_ENROLL_ADDRESS",
    "RELAY_SERVER_NAME",
    "RELAY_NODE_LABELS",
];

/// The four files a persisted identity is made of. `relay_addr` is not one of
/// them: it is written before the identity and is optional for an enrolled Node.
pub const IDENTITY_FILES: [&str; 4] = ["key.pem", "cert.pem", "ca_bundle.pem", "node_id"];

/// Why the daemon could not be configured. No variant carries the join string or
/// any part of it.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error(
        "no Relay address: set RELAY_ADDRESS (none was persisted at enrollment in {}); \
         there is no default address",
        state_dir.display()
    )]
    NoRelayAddr { state_dir: PathBuf },
    #[error("cannot read the persisted Relay address: {0}")]
    PersistedAddr(#[from] IdentityError),
    #[error("the join string is malformed: {0}")]
    MalformedJoin(JoinStringError),
    #[error("the join string is malformed: not valid UTF-8")]
    JoinNotUnicode,
    #[error("the join string is malformed: longer than {MAX_JOIN_STRING_LEN} bytes")]
    JoinTooLong,
    #[error("the join string is malformed: its Relay address {0}")]
    BadJoinAddress(&'static str),
    /// A retired setting is present. Only its name is printed, never its value.
    #[error(
        "{name} is set in the daemon's environment; it is not a setting and the daemon \
         refuses to start while it is set: remove it from the environment file; {instead}"
    )]
    RetiredSetting {
        name: &'static str,
        instead: &'static str,
    },
    #[error(
        "partial identity in {}: missing {}; restore the files or empty the directory \
         and enroll again",
        state_dir.display(),
        missing.join(", ")
    )]
    PartialIdentity {
        state_dir: PathBuf,
        missing: Vec<&'static str>,
    },
    #[error("cannot inspect the identity in {}: {source}", state_dir.display())]
    IdentityUnreadable {
        state_dir: PathBuf,
        source: std::io::Error,
    },
    #[error("refusing to read the state directory {}: it {reason}", state_dir.display())]
    UntrustedStateDir { state_dir: PathBuf, reason: String },
}

/// What a start does, decided before any network or Config read.
pub enum StartupPlan {
    /// No identity file: nothing to connect with (the one clean exit).
    Unconfigured,
    /// A complete identity: use it.
    Enrolled,
}

/// How much of a persisted identity is present.
#[derive(Debug, PartialEq, Eq)]
pub enum IdentityState {
    Absent,
    Partial { missing: Vec<&'static str> },
    Complete,
}

/// Refuses an existing `state_dir` that is a symlink, not a directory,
/// group- or world-writable, or owned by neither root nor `euid`. An absent one
/// holds no identity, and `join` creates it.
fn check_state_dir(state_dir: &Path, euid: u32) -> Result<(), ConfigError> {
    // A trailing slash makes lstat follow a final symlink, so look at the path
    // rebuilt from its components, which drops it.
    let probe: std::path::PathBuf = state_dir.components().collect();
    let meta = match std::fs::symlink_metadata(&probe) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(ConfigError::IdentityUnreadable {
                state_dir: state_dir.to_path_buf(),
                source,
            })
        }
    };
    match identity::untrusted_reason(&meta, identity::StateEntry::Dir, euid) {
        Some(reason) => Err(ConfigError::UntrustedStateDir {
            state_dir: state_dir.to_path_buf(),
            reason,
        }),
        None => Ok(()),
    }
}

/// Reports which of the four identity files exist in `state_dir`. A directory
/// that does not exist holds no identity. An existing state directory that is a
/// symlink, not a directory, group- or world-writable, or owned by neither root
/// nor the daemon's user is refused before anything in it is read: this is the
/// first look into the directory for both `join` and the unit start.
pub fn identity_state(state_dir: &Path) -> Result<IdentityState, ConfigError> {
    check_state_dir(state_dir, rustix::process::geteuid().as_raw())?;
    let mut missing = Vec::new();
    for name in IDENTITY_FILES {
        match std::fs::symlink_metadata(state_dir.join(name)) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => missing.push(name),
            Err(source) => {
                return Err(ConfigError::IdentityUnreadable {
                    state_dir: state_dir.to_path_buf(),
                    source,
                })
            }
        }
    }
    Ok(match missing.len() {
        0 => IdentityState::Complete,
        n if n == IDENTITY_FILES.len() => IdentityState::Absent,
        _ => IdentityState::Partial { missing },
    })
}

/// Refuses to start while a retired setting is present. Any presence refuses,
/// an empty or non-UTF-8 value included, so a stale line cannot hide. The
/// message names the setting and never its value.
pub fn refuse_retired_settings(get: impl Fn(&str) -> Option<OsString>) -> Result<(), ConfigError> {
    for (name, instead) in RETIRED_SETTINGS {
        if get(name).is_some() {
            return Err(ConfigError::RetiredSetting { name, instead });
        }
    }
    Ok(())
}

/// Decides what this start does (DI-25). Only a Node with no identity file at
/// all is `Unconfigured`; a partial identity or an untrusted state directory is
/// an error, so a broken Node shows as failed rather than idle.
pub fn plan_startup(state_dir: &Path) -> Result<StartupPlan, ConfigError> {
    match identity_state(state_dir)? {
        IdentityState::Complete => Ok(StartupPlan::Enrolled),
        IdentityState::Partial { missing } => Err(ConfigError::PartialIdentity {
            state_dir: state_dir.to_path_buf(),
            missing,
        }),
        IdentityState::Absent => Ok(StartupPlan::Unconfigured),
    }
}

/// Decodes a join string: empty is `None`; anything else must be at most
/// [`MAX_JOIN_STRING_LEN`] bytes, decode, and carry a dialable address. Borrowed,
/// so the caller wipes its own copy of the text.
pub fn decode_join_str(raw: &str) -> Result<Option<JoinString>, ConfigError> {
    if raw.is_empty() {
        return Ok(None);
    }
    if raw.len() > MAX_JOIN_STRING_LEN {
        return Err(ConfigError::JoinTooLong);
    }
    let join = JoinString::decode(raw).map_err(ConfigError::MalformedJoin)?;
    validate_join_address(join.relay_address())?;
    Ok(Some(join))
}

/// Accepts only a bare `host:port`: a DNS name or IPv4 literal, or a bracketed
/// IPv6 literal, and a non-zero port. No scheme, path, user info, whitespace or
/// control character, so the address can neither redirect the dial nor inject a
/// log line. The error never echoes the value.
pub fn validate_join_address(addr: &str) -> Result<(), ConfigError> {
    if addr.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(ConfigError::BadJoinAddress(
            "contains whitespace or a control character",
        ));
    }
    let (host, port) = addr
        .rsplit_once(':')
        .ok_or(ConfigError::BadJoinAddress("is not host:port"))?;
    match port.parse::<u16>() {
        Ok(p) if p != 0 && port.bytes().all(|b| b.is_ascii_digit()) => {}
        _ => return Err(ConfigError::BadJoinAddress("has no valid port")),
    }
    let host_ok = if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        !inner.is_empty()
            && inner.contains(':')
            && inner
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
    } else {
        !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    };
    if !host_ok {
        return Err(ConfigError::BadJoinAddress("has an invalid host"));
    }
    Ok(())
}

/// All daemon configuration derived from environment variables (and `--relay`
/// CLI arg). Constructed exactly once in `main` and threaded down to callers. No
/// env-var is read elsewhere for these fields.
pub struct Config {
    /// Resolved Relay address: `--relay`/`RELAY_ADDRESS` when set, else the one
    /// persisted at enrollment (may be `http://` when from the environment).
    pub relay_addr: String,
    /// `relay_addr` normalized to `https://` — the gRPC dial target.
    pub endpoint: String,
    /// `RELAY_SERVER_NAME` TLS SNI override (optional).
    pub tls_server_name: Option<String>,
    /// `RELAY_STATE_DIR` — where identity files are persisted.
    pub state_dir: PathBuf,
    /// `RELAY_POLICY_PATH` — path to the Node's Policy TOML file.
    ///
    /// Defaults to `/etc/relay-daemon/policy.toml` when the env var is absent.
    /// The daemon loads the Policy at startup via `policy::load_policy`, which
    /// also reads the Policy directory ([`Config::policy_dir`]). An unreadable
    /// file, or an absent one with no fragment → warn and fall back to deny-all
    /// (fail-closed for dispatch); an absent file beside fragments → warn and
    /// compose the fragments alone (DI-20). A refused fragment or Policy
    /// directory stops the daemon from starting.
    pub policy_path: PathBuf,
    /// The Policy directory: `policy.d` beside the Policy file (DI-36). It has
    /// no setting of its own, so it follows `RELAY_POLICY_PATH`.
    pub policy_dir: PathBuf,
    /// `RELAY_TEMPLATE_DIR` — the root of this Node's Template Operation files
    /// (ADR-0021).
    ///
    /// Defaults to `/etc/relay-daemon/templates.d` — beside `policy.toml`, the
    /// same root-owned local trust root (ADR-0002); the Relay can read the
    /// resulting vocabulary but never write it. An absent directory simply
    /// means "no templates installed"; anything else that goes wrong leaves the
    /// Node with NO Template Operations (fail closed, `templates::TemplateSet`).
    pub template_dir: PathBuf,
    /// `RELAY_NODE_LABELS` as bare `(key, value)` pairs; `node:` prefix is
    /// added at send time by `enroll::node_labels_to_proto` (ADR-0006 §7).
    pub node_labels: Vec<(String, String)>,
    /// Facts advertised to the Relay on Hello. Built once here, from the shared
    /// [`crate::operations::system_facts::gather_facts`] collector — the same
    /// single source used by the live `system.facts` Operation — so neither
    /// `EnrollConfig` nor `main` re-reads `HOSTNAME` / `OS` / `ARCH` and the
    /// Relay's registry never sees a Hello with a different (poorer) Facts set
    /// than a live `system.facts` run.
    pub facts: Facts,
}

impl Config {
    /// Reads all shared daemon configuration from the environment for an
    /// enrolled Node: the address is the override, else the persisted one.
    ///
    /// Fails only when no Relay address source exists or the persisted address
    /// is unreadable or malformed. Defaults are applied for every other missing
    /// or unparsable env var; an empty `RELAY_SERVER_NAME` counts as unset.
    pub fn from_env() -> Result<Config, ConfigError> {
        let state_dir = state_dir_from_env();
        let relay_addr = resolve_relay_addr(relay_addr_override_from_args_env(), &state_dir)?;
        let endpoint = normalize_scheme(&relay_addr);
        let tls_server_name = std::env::var("RELAY_SERVER_NAME")
            .ok()
            .filter(|v| !v.is_empty());
        let node_labels = node_labels_from_env();

        // Facts.hostname is the human-readable descriptor, not the
        // Relay-assigned identity UUID (see node_id on Hello, ADR-0006). Gathered
        // via the shared collector so kernel/IPs are populated and the hostname
        // policy (kernel hostname first, $HOSTNAME an explicit fallback) matches
        // the live `system.facts` Operation exactly — see system_facts.rs.
        let facts = crate::operations::system_facts::gather_facts();

        let policy_path = std::env::var("RELAY_POLICY_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/etc/relay-daemon/policy.toml"));
        let policy_dir = policy_dir_beside(&policy_path);

        Ok(Config {
            relay_addr,
            endpoint,
            tls_server_name,
            state_dir,
            policy_path,
            policy_dir,
            template_dir: template_dir_from_env(),
            node_labels,
            facts,
        })
    }
}

/// The Policy directory for the Policy file at `policy_path`: `policy.d` in the
/// same directory (DI-36). Standalone for the same reason as
/// [`template_dir_from_env`]: the self-reference lint resolves it without
/// building a full [`Config`].
pub fn policy_dir_beside(policy_path: &Path) -> PathBuf {
    policy_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(crate::policy::POLICY_DIR_NAME)
}

/// Reads `RELAY_TEMPLATE_DIR`, defaulting to `/etc/relay-daemon/templates.d`.
///
/// Standalone (not only a [`Config`] field) because `relay-daemon policy check`
/// resolves the same root without building a full [`Config`]: its
/// `--would-allow` answers come from the live evaluator, which resolves names
/// against the same per-Node vocabulary a real dispatch would (ADR-0011).
pub fn template_dir_from_env() -> PathBuf {
    std::env::var("RELAY_TEMPLATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/relay-daemon/templates.d"))
}

/// Per-stream output byte cap for stdout and stderr independently. Daemon-local
/// and wire-immutable: the Relay can never raise it over the wire (invariant 11
/// analog for the daemon; ADR-0004). Bytes past the cap are drained but discarded
/// and `truncated` is set. Sane default; a Policy/env-tunable value is future work.
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024; // 1 MiB

/// Builds the enrollment configuration `relay-daemon join` enrolls with, from the
/// decoded join string, the state directory it resolved, and `setting`, which
/// answers for the names in [`JOIN_SETTINGS`] only (an empty value is unset):
///
/// - the Node-plane address persisted for the Tunnel is `RELAY_ADDRESS`, else the
///   join string's, normalized to `https://`;
/// - `RELAY_ENROLL_ADDRESS` overrides only the enrollment dial target. The CA
///   pin applies to whichever endpoint is dialled;
/// - `RELAY_SERVER_NAME` and `RELAY_NODE_LABELS` are the SNI name and the labels.
///
/// It reads no other setting: no CA bundle path and no bare token (EN-30), and
/// no argv.
pub fn join_enroll_config(
    join: JoinString,
    state_dir: PathBuf,
    setting: &dyn Fn(&str) -> Option<String>,
) -> Result<EnrollConfig, EnrollError> {
    let relay_addr = normalize_scheme(
        &setting("RELAY_ADDRESS").unwrap_or_else(|| format!("https://{}", join.relay_address())),
    );
    // The enroll override is used raw so operators can specify a distinct
    // enrollment endpoint if needed.
    let endpoint = setting("RELAY_ENROLL_ADDRESS").unwrap_or_else(|| relay_addr.clone());

    // Fail closed: an "http://" endpoint would skip TLS, and with it the CA
    // pin, exposing the Enrollment Token. `IdentityError` auto-converts into
    // `EnrollError::Identity` via the existing `#[from]` impl.
    validate_endpoint_scheme(&endpoint)?;

    Ok(EnrollConfig {
        join,
        endpoint,
        relay_addr,
        tls_server_name: setting("RELAY_SERVER_NAME"),
        state_dir,
        node_labels: setting("RELAY_NODE_LABELS")
            .map(|v| parse_node_labels(&v))
            .unwrap_or_default(),
        facts: crate::operations::system_facts::gather_facts(),
    })
}

/// Normalizes `http://` to `https://` in a Relay address.
///
/// `https://` passes through unchanged; any other scheme (including bare
/// hostnames and `grpc://`) is also returned as-is. This is a convenience
/// transformation for operators who supply plain `http://` addresses; the
/// authoritative fail-closed guard remains `validate_endpoint_scheme` /
/// `build_channel` (ADR-0005, invariant 6).
pub(crate) fn normalize_scheme(addr: &str) -> String {
    addr.replacen("http://", "https://", 1)
}

/// Returns the Relay address override: the first `--relay <val>` in argv, else
/// `RELAY_ADDRESS`. An empty value from either source counts as unset.
fn relay_addr_override_from_args_env() -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    let from_args = args
        .windows(2)
        .find(|w| w[0] == "--relay")
        .map(|w| w[1].clone());
    from_args
        .or_else(|| std::env::var("RELAY_ADDRESS").ok())
        .filter(|v| !v.is_empty())
}

/// Resolves the Relay address: the override when set (without reading the
/// persisted file, so config management can always repoint a Node), else the
/// address persisted at enrollment. With none, refuses; there is no default.
pub(crate) fn resolve_relay_addr(
    override_addr: Option<String>,
    state_dir: &Path,
) -> Result<String, ConfigError> {
    if let Some(addr) = override_addr {
        return Ok(addr);
    }
    load_relay_addr(state_dir)?.ok_or_else(|| ConfigError::NoRelayAddr {
        state_dir: state_dir.to_path_buf(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::{BTreeSet, HashMap};
    use std::sync::Mutex;

    // Serialize all env-touching tests within this module so they don't race.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    // --- normalize_scheme (pure, no lock needed) ----------------------------

    #[test]
    fn normalize_scheme_http_becomes_https() {
        assert_eq!(normalize_scheme("http://relay:8080"), "https://relay:8080");
    }

    #[test]
    fn normalize_scheme_https_passthrough() {
        assert_eq!(normalize_scheme("https://relay:8080"), "https://relay:8080");
    }

    #[test]
    fn normalize_scheme_no_scheme_unchanged() {
        assert_eq!(normalize_scheme("relay:8080"), "relay:8080");
    }

    #[test]
    fn normalize_scheme_grpc_unchanged() {
        assert_eq!(normalize_scheme("grpc://relay:8080"), "grpc://relay:8080");
    }

    /// Points RELAY_STATE_DIR at a fresh empty directory so no test reads the
    /// host's default state directory.
    fn isolated_state_dir(tag: &str) -> IsolatedStateDir {
        let dir = crate::test_support::TempDir::created(tag);
        std::env::set_var("RELAY_STATE_DIR", dir.path());
        IsolatedStateDir(dir)
    }

    /// Removes RELAY_STATE_DIR on drop so no later test sees a deleted directory.
    struct IsolatedStateDir(crate::test_support::TempDir);

    impl std::ops::Deref for IsolatedStateDir {
        type Target = crate::test_support::TempDir;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl Drop for IsolatedStateDir {
        fn drop(&mut self) {
            std::env::remove_var("RELAY_STATE_DIR");
        }
    }

    // --- Config::from_env defaults ------------------------------------------

    #[test]
    fn config_from_env_defaults() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _dir = isolated_state_dir("cfg-defaults");
        std::env::set_var("RELAY_ADDRESS", "https://relay:7654");
        std::env::remove_var("RELAY_SERVER_NAME");
        // CI shells commonly set HOSTNAME; remove it so the default fires.
        std::env::remove_var("HOSTNAME");
        std::env::remove_var("RELAY_NODE_LABELS");
        std::env::remove_var("RELAY_POLICY_PATH");

        let cfg = Config::from_env().expect("from_env");
        assert_eq!(cfg.tls_server_name, None);
        assert_eq!(
            cfg.policy_path,
            PathBuf::from("/etc/relay-daemon/policy.toml")
        );
        assert!(cfg.node_labels.is_empty());

        std::env::remove_var("RELAY_ADDRESS");
        std::env::remove_var("RELAY_STATE_DIR");
        assert_eq!(state_dir_from_env(), PathBuf::from("/var/lib/relay-daemon"));
    }

    #[test]
    fn policy_dir_is_beside_the_policy_file() {
        assert_eq!(
            policy_dir_beside(Path::new("/etc/relay-daemon/policy.toml")),
            PathBuf::from("/etc/relay-daemon/policy.d")
        );
        assert_eq!(
            policy_dir_beside(Path::new("/custom/policy.toml")),
            PathBuf::from("/custom/policy.d")
        );
        assert_eq!(
            policy_dir_beside(Path::new("policy.toml")),
            PathBuf::from("policy.d"),
            "a bare relative name sits in the working directory"
        );
    }

    #[test]
    fn config_policy_path_override() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _dir = isolated_state_dir("cfg-policy");
        std::env::set_var("RELAY_ADDRESS", "https://relay:7654");
        std::env::set_var("RELAY_POLICY_PATH", "/custom/policy.toml");

        let cfg = Config::from_env().expect("from_env");
        assert_eq!(cfg.policy_path, PathBuf::from("/custom/policy.toml"));
        assert_eq!(cfg.policy_dir, PathBuf::from("/custom/policy.d"));

        std::env::remove_var("RELAY_POLICY_PATH");
        std::env::remove_var("RELAY_ADDRESS");
    }

    // --- Relay address resolution -------------------------------------------

    // Proves DI-44.
    #[test]
    fn relay_addr_overrides_persisted_address() {
        let _lock = ENV_LOCK.lock().unwrap();
        let dir = isolated_state_dir("cfg-override");
        std::fs::write(
            dir.path().join(crate::identity::PERSISTED_ADDR_FILE),
            "https://persisted:7654\n",
        )
        .unwrap();

        std::env::set_var("RELAY_ADDRESS", "https://override:9000");
        let cfg = Config::from_env().expect("from_env");
        assert_eq!(cfg.relay_addr, "https://override:9000");
        assert_eq!(cfg.endpoint, "https://override:9000");

        std::env::remove_var("RELAY_ADDRESS");
        let cfg = Config::from_env().expect("from_env");
        assert_eq!(cfg.relay_addr, "https://persisted:7654");
        assert_eq!(cfg.endpoint, "https://persisted:7654");
    }

    #[test]
    fn no_address_source_refuses_naming_relay_addr() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _dir = isolated_state_dir("cfg-no-addr");

        std::env::remove_var("RELAY_ADDRESS");
        let err = Config::from_env().err().expect("must refuse");
        assert!(matches!(err, ConfigError::NoRelayAddr { .. }), "{err:?}");
        assert!(err.to_string().contains("RELAY_ADDRESS"), "{err}");

        // An empty RELAY_ADDRESS counts as unset.
        std::env::set_var("RELAY_ADDRESS", "");
        let err = Config::from_env().err().expect("must refuse");
        assert!(matches!(err, ConfigError::NoRelayAddr { .. }), "{err:?}");

        std::env::remove_var("RELAY_ADDRESS");
    }

    #[test]
    fn no_localhost_default_address() {
        let dir = crate::test_support::TempDir::created("cfg-no-default");
        assert!(resolve_relay_addr(None, dir.path()).is_err());

        // Guard against a reintroduced literal default in production code. The
        // test module below legitimately names addresses, so only the part of
        // the file before it is scanned.
        let src = include_str!("config.rs");
        let production = src.split("#[cfg(test)]").next().unwrap();
        assert!(
            !production.contains("127.0.0.1"),
            "config.rs production code (before its #[cfg(test)] module) must not \
             contain a localhost default address"
        );
    }

    // --- Config::from_env overrides -----------------------------------------

    #[test]
    fn config_from_env_overrides() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _dir = isolated_state_dir("cfg-overrides");
        std::env::set_var("RELAY_ADDRESS", "https://relay:9000");
        std::env::set_var("RELAY_SERVER_NAME", "relay.internal");

        let cfg = Config::from_env().expect("from_env");
        assert_eq!(cfg.relay_addr, "https://relay:9000");
        // https:// passes through normalize_scheme unchanged.
        assert_eq!(cfg.endpoint, "https://relay:9000");
        assert_eq!(cfg.tls_server_name, Some("relay.internal".to_string()));

        std::env::remove_var("RELAY_ADDRESS");
        std::env::remove_var("RELAY_SERVER_NAME");
    }

    #[test]
    fn config_from_env_facts_match_gather_facts() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _dir = isolated_state_dir("cfg-facts");
        std::env::set_var("RELAY_ADDRESS", "https://relay:7654");

        let cfg = Config::from_env().expect("from_env");
        let facts = crate::operations::system_facts::gather_facts();

        // Proves the single-source wiring: Config::from_env no longer builds a
        // second, partial Facts by hand — it draws from the same collector as
        // the live `system.facts` Operation. ip_addresses is intentionally not
        // compared: two independent getifaddrs() calls can race real interface
        // changes on a live box.
        assert_eq!(cfg.facts.os, facts.os);
        assert_eq!(cfg.facts.arch, facts.arch);
        assert_eq!(cfg.facts.hostname, facts.hostname);
        assert_eq!(cfg.facts.kernel, facts.kernel);

        std::env::remove_var("RELAY_ADDRESS");
    }

    // --- Config::from_env scheme normalization ------------------------------

    #[test]
    fn config_from_env_scheme_normalization() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _dir = isolated_state_dir("cfg-scheme");
        std::env::set_var("RELAY_ADDRESS", "http://relay:8080");

        let cfg = Config::from_env().expect("from_env");
        // relay_addr retains the raw value; endpoint is normalized.
        assert_eq!(cfg.relay_addr, "http://relay:8080");
        assert_eq!(cfg.endpoint, "https://relay:8080");

        std::env::remove_var("RELAY_ADDRESS");
    }

    // --- join_enroll_config ---------------------------------------------------

    fn join_for(addr: &str) -> String {
        JoinString::new(addr.to_string(), [7u8; 32], "tok-test".to_string())
            .encode()
            .expect("encode")
    }

    fn decoded(addr: &str) -> JoinString {
        decode_join_str(&join_for(addr))
            .expect("decode")
            .expect("some")
    }

    /// A setting lookup over a fixed table, with empty values counting as unset,
    /// as `relay-daemon join`'s own lookup treats them.
    fn lookup(pairs: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        let table: HashMap<&'static str, &'static str> = pairs.iter().copied().collect();
        move |name| {
            table
                .get(name)
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string())
        }
    }

    fn enroll_config(
        join: JoinString,
        pairs: &[(&'static str, &'static str)],
    ) -> Result<EnrollConfig, EnrollError> {
        join_enroll_config(join, PathBuf::from("/state"), &lookup(pairs))
    }

    #[test]
    fn join_address_is_the_enrollment_address_by_default() {
        let ec = enroll_config(decoded("relay.example:7654"), &[]).expect("config");
        assert_eq!(ec.relay_addr, "https://relay.example:7654");
        assert_eq!(ec.endpoint, "https://relay.example:7654");
        assert_eq!(ec.state_dir, PathBuf::from("/state"));
        assert_eq!(ec.join.enrollment_token(), "tok-test");
        assert_eq!(ec.tls_server_name, None);
        assert!(ec.node_labels.is_empty());
    }

    #[test]
    fn relay_address_overrides_the_join_address() {
        let ec = enroll_config(
            decoded("relay.example:7654"),
            &[("RELAY_ADDRESS", "http://override:9000")],
        )
        .expect("config");
        // Normalized to https, and both the persisted address and the dial target.
        assert_eq!(ec.relay_addr, "https://override:9000");
        assert_eq!(ec.endpoint, "https://override:9000");
    }

    #[test]
    fn enroll_address_overrides_only_the_enrollment_endpoint() {
        let ec = enroll_config(
            decoded("relay:7654"),
            &[("RELAY_ENROLL_ADDRESS", "https://override:9000")],
        )
        .expect("config");
        assert_eq!(ec.endpoint, "https://override:9000");
        // The persisted (Tunnel) address stays the Node-plane one.
        assert_eq!(ec.relay_addr, "https://relay:7654");
    }

    #[test]
    fn http_enroll_endpoint_is_refused() {
        let result = enroll_config(
            decoded("relay:7654"),
            &[("RELAY_ENROLL_ADDRESS", "http://relay:7654")],
        );
        assert!(result.is_err());
    }

    #[test]
    fn labels_and_server_name_come_from_the_settings() {
        let ec = enroll_config(
            decoded("relay:7654"),
            &[
                ("RELAY_NODE_LABELS", "role=web,node:env=prod"),
                ("RELAY_SERVER_NAME", "relay.internal"),
            ],
        )
        .expect("config");
        assert_eq!(
            ec.node_labels,
            vec![
                ("role".to_string(), "web".to_string()),
                ("env".to_string(), "prod".to_string())
            ]
        );
        assert_eq!(ec.tls_server_name.as_deref(), Some("relay.internal"));
        assert_eq!(ec.facts.hostname, gather_hostname());
    }

    fn gather_hostname() -> String {
        crate::operations::system_facts::gather_facts().hostname
    }

    // Proves EN-30.
    #[test]
    fn join_enroll_config_never_reads_a_ca_path_or_a_bare_token() {
        let asked = RefCell::new(BTreeSet::new());
        let recording = |name: &str| {
            asked.borrow_mut().insert(name.to_string());
            None
        };
        join_enroll_config(decoded("relay:7654"), PathBuf::from("/state"), &recording)
            .expect("config");
        let asked = asked.into_inner();

        for name in &asked {
            assert!(
                JOIN_SETTINGS.contains(&name.as_str()),
                "join_enroll_config looked up {name}, which is not one of JOIN_SETTINGS"
            );
        }
        // Spelled in two pieces so the packaging drift scan, which reads every
        // whole RELAY_ name in the source, does not mistake these for settings.
        for never in [
            concat!("RELAY_", "CA_BUNDLE_PATH"),
            concat!("RELAY_", "ENROLLMENT_TOKEN"),
        ] {
            assert!(!asked.contains(never), "{never} must never be consulted");
        }
    }

    // --- refuse_retired_settings ----------------------------------------------

    // Proves DI-43.
    #[test]
    fn retired_settings_refused_by_name() {
        use std::os::unix::ffi::OsStringExt;

        let valid = join_for("relay:7654");
        let values: Vec<OsString> = vec![
            OsString::new(),
            OsString::from(valid.clone()),
            OsString::from("glp_join_not!valid tok-should-not-print"),
            OsString::from_vec(b"glp_join_\xff\xfe".to_vec()),
        ];
        for value in values {
            let shown = value.to_string_lossy().into_owned();
            let err = refuse_retired_settings(|name| (name == "RELAY_JOIN").then(|| value.clone()))
                .expect_err("a set RELAY_JOIN is refused, whatever it holds");
            assert!(
                matches!(
                    err,
                    ConfigError::RetiredSetting {
                        name: "RELAY_JOIN",
                        ..
                    }
                ),
                "{err:?}"
            );
            let text = format!("{err} {err:?}");
            assert!(text.contains("RELAY_JOIN"), "{text}");
            assert!(text.contains("relay-daemon join"), "{text}");
            for secret in ["tok-should-not-print", "tok-test", valid.as_str()] {
                assert!(!text.contains(secret), "{text}");
            }
            if !shown.is_empty() {
                assert!(!text.contains(&shown), "the value is never printed: {text}");
            }
        }
        assert!(refuse_retired_settings(|_| None).is_ok());
    }

    #[test]
    fn empty_state_dir_and_server_name_count_as_unset() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var("RELAY_STATE_DIR", "");
        assert_eq!(state_dir_from_env(), PathBuf::from("/var/lib/relay-daemon"));
        std::env::remove_var("RELAY_STATE_DIR");

        let _dir = isolated_state_dir("cfg-empty-name");
        std::env::set_var("RELAY_ADDRESS", "https://relay:7654");
        std::env::set_var("RELAY_SERVER_NAME", "");
        let cfg = Config::from_env().expect("from_env");
        assert_eq!(cfg.tls_server_name, None);
        std::env::remove_var("RELAY_SERVER_NAME");
        std::env::remove_var("RELAY_ADDRESS");
    }

    // --- the join string and the address it carries ---------------------------

    #[test]
    fn empty_join_is_none() {
        assert!(decode_join_str("").unwrap().is_none());
    }

    #[test]
    fn overlong_join_is_refused_before_decoding() {
        let long = format!("glp_join_{}", "A".repeat(MAX_JOIN_STRING_LEN));
        assert!(matches!(
            decode_join_str(&long),
            Err(ConfigError::JoinTooLong)
        ));
    }

    #[test]
    fn malformed_join_is_refused_without_echoing_it() {
        let input = "glp_join_not!base64 tok-secret";
        let err = decode_join_str(input).expect_err("refused");
        assert!(matches!(err, ConfigError::MalformedJoin(_)), "{err:?}");
        let text = format!("{err} {err:?}");
        assert!(!text.contains("tok-secret"), "{text}");
        assert!(!text.contains(input), "{text}");
    }

    #[test]
    fn join_address_must_be_bare_host_port() {
        for ok in [
            "relay:7654",
            "relay.example.internal:7654",
            "10.0.0.5:7654",
            "[::1]:7654",
            "[fd00::5]:443",
        ] {
            assert!(validate_join_address(ok).is_ok(), "{ok} must be accepted");
        }
        for bad in [
            "relay",
            "relay:",
            "relay:0",
            "relay:99999",
            "relay:76a4",
            ":7654",
            "https://relay:7654",
            "relay/path:7654",
            "user@relay:7654",
            "relay :7654",
            "relay\n:7654",
            "relay\u{7}:7654",
            "[]:7654",
            "[relay]:7654",
            "::1:7654",
        ] {
            let err = validate_join_address(bad).err();
            assert!(err.is_some(), "{bad:?} must be refused");
            assert!(
                !err.unwrap().to_string().contains(bad),
                "error must not echo {bad:?}"
            );
        }
    }

    #[test]
    fn join_with_bad_address_is_malformed() {
        let err = decode_join_str(&join_for("https://relay:7654")).expect_err("refused");
        assert!(matches!(err, ConfigError::BadJoinAddress(_)), "{err:?}");
    }

    // --- plan_startup (the exit rule) ---------------------------------------

    fn seed(dir: &Path, names: &[&str]) {
        std::fs::create_dir_all(dir).unwrap();
        for n in names {
            std::fs::write(dir.join(n), "x").unwrap();
        }
    }

    // Proves EN-32.
    #[test]
    fn plan_has_two_outcomes() {
        let dir = crate::test_support::TempDir::created("plan-two-outcomes");
        assert!(matches!(
            plan_startup(dir.path()),
            Ok(StartupPlan::Unconfigured)
        ));
        // A state directory that does not exist yet holds no identity either.
        assert!(matches!(
            plan_startup(&dir.path().join("absent")),
            Ok(StartupPlan::Unconfigured)
        ));
        seed(dir.path(), &IDENTITY_FILES);
        assert!(matches!(
            plan_startup(dir.path()),
            Ok(StartupPlan::Enrolled)
        ));
    }

    #[test]
    fn plan_refuses_every_partial_identity() {
        let dir = crate::test_support::TempDir::created("plan-partial");
        for present in 1..IDENTITY_FILES.len() {
            let sub = dir.path().join(format!("p{present}"));
            seed(&sub, &IDENTITY_FILES[..present]);
            let err = plan_startup(&sub)
                .err()
                .expect("partial identity must refuse");
            match err {
                ConfigError::PartialIdentity { missing, .. } => {
                    assert_eq!(missing, IDENTITY_FILES[present..].to_vec())
                }
                other => panic!("want PartialIdentity, got {other:?}"),
            }
        }
    }

    // --- the state directory is checked before it is read -------------------

    fn mode_dir(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn an_untrusted_state_dir_is_refused_naming_it() {
        use std::os::unix::fs::MetadataExt;

        let base = crate::test_support::TempDir::created("state-dir-untrusted");
        let euid = rustix::process::geteuid().as_raw();

        let real = base.path().join("real");
        mode_dir(&real, 0o700);
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let group = base.path().join("group-writable");
        mode_dir(&group, 0o720);
        let world = base.path().join("world-writable");
        mode_dir(&world, 0o702);
        let file = base.path().join("a-file");
        std::fs::write(&file, "x").unwrap();
        // Owned by someone who is neither root nor the running user.
        let foreign = base.path().join("foreign");
        mode_dir(&foreign, 0o700);
        let foreign_euid = if std::fs::metadata(&foreign).unwrap().uid() == 0 {
            std::os::unix::fs::chown(&foreign, Some(65534), Some(65534)).unwrap();
            0
        } else {
            euid + 1
        };

        for (path, as_euid, reason) in [
            (&link, euid, "symlink"),
            (&group, euid, "group- or world-writable"),
            (&world, euid, "group- or world-writable"),
            (&file, euid, "not a directory"),
            (&foreign, foreign_euid, "neither root nor"),
        ] {
            let err = check_state_dir(path, as_euid).expect_err("refused");
            assert!(
                matches!(&err, ConfigError::UntrustedStateDir { state_dir, .. } if state_dir == path),
                "{err:?}"
            );
            let message = err.to_string();
            assert!(message.contains(&path.display().to_string()), "{message}");
            assert!(message.contains(reason), "{message}");
        }

        // A trailing slash must not let lstat follow the symlink.
        let slashed = std::path::PathBuf::from(format!("{}/", link.display()));
        let err = check_state_dir(&slashed, euid)
            .expect_err("a symlink with a trailing slash is refused");
        assert!(err.to_string().contains("symlink"), "{err}");

        let ok = base.path().join("ok");
        mode_dir(&ok, 0o755);
        check_state_dir(&real, euid).expect("0700 is accepted");
        check_state_dir(&ok, euid).expect("0755 is accepted");
        check_state_dir(&base.path().join("absent"), euid).expect("absent holds no identity");
    }

    #[test]
    fn plan_startup_refuses_an_untrusted_state_dir_before_reading_it() {
        let base = crate::test_support::TempDir::created("plan-untrusted");
        let dir = base.path().join("state");
        // A partial identity would be PartialIdentity if the directory were read.
        seed(&dir, &["key.pem"]);
        mode_dir(&dir, 0o777);

        let err = plan_startup(&dir).err().expect("refused");
        assert!(
            matches!(err, ConfigError::UntrustedStateDir { .. }),
            "{err:?}"
        );
    }
}
