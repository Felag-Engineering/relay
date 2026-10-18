//! The daemon's single environment/config surface, read once at startup and
//! threaded down. Startup follows one plan (ADR-0031 decision 4; DI-25's exit
//! rule): a complete identity is used and the join string is never read; no
//! identity and no `RELAY_JOIN` is the one clean exit; anything in between
//! refuses. The Relay address resolves from `RELAY_ADDR` or `--relay` first, then
//! from the join string while enrolling, then from the address persisted at
//! enrollment, with no default. Also centralizes RELAY_DOMAIN and the http→https
//! scheme normalization.
//!
//! Also hosts daemon-local hard limits (e.g. [`MAX_OUTPUT_BYTES`]) that are
//! compile-time constants, not env-derived — kept here as the daemon's single
//! neutral config-adjacent home rather than scattered per call site.
//! The spawned-child `setrlimit` bounds (`ResourceLimits`) live in relay-exec's
//! `limits` module.

use std::path::{Path, PathBuf};

use crate::enroll::{node_labels_from_env, state_dir_from_env, EnrollConfig, EnrollError};
use crate::gen::Facts;
use crate::identity::{load_relay_addr, validate_endpoint_scheme, IdentityError};
use relay_transport::join_string::{JoinString, JoinStringError};

/// The longest `RELAY_JOIN` value read. A real join string is well under 1 KiB;
/// the cap bounds what reaches the decoder.
pub const MAX_JOIN_STRING_LEN: usize = 4096;

/// The four files a persisted identity is made of. `relay_addr` is not one of
/// them: it is written before the identity and is optional for an enrolled Node.
pub const IDENTITY_FILES: [&str; 4] = ["key.pem", "cert.pem", "ca_bundle.pem", "node_id"];

/// Why the daemon could not be configured. No variant carries the join string or
/// any part of it.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error(
        "no Relay address: set RELAY_ADDR (none was persisted at enrollment in {}); \
         there is no default address",
        state_dir.display()
    )]
    NoRelayAddr { state_dir: PathBuf },
    #[error("cannot read the persisted Relay address: {0}")]
    PersistedAddr(#[from] IdentityError),
    #[error("RELAY_JOIN is malformed: {0}")]
    MalformedJoin(JoinStringError),
    #[error("RELAY_JOIN is malformed: not valid UTF-8")]
    JoinNotUnicode,
    #[error("RELAY_JOIN is malformed: longer than {MAX_JOIN_STRING_LEN} bytes")]
    JoinTooLong,
    #[error("RELAY_JOIN is malformed: its Relay address {0}")]
    BadJoinAddress(&'static str),
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
}

/// What a start does, decided before any network or Config read.
pub enum StartupPlan {
    /// No identity file and no join string: nothing to do (the one clean exit).
    Unconfigured,
    /// No identity file and a valid join string: enroll with it.
    Enroll(JoinString),
    /// A complete identity: use it. The join string is inert and not read.
    Enrolled,
}

/// How much of a persisted identity is present.
#[derive(Debug, PartialEq, Eq)]
pub enum IdentityState {
    Absent,
    Partial { missing: Vec<&'static str> },
    Complete,
}

/// Reports which of the four identity files exist in `state_dir`. A directory
/// that does not exist holds no identity.
pub fn identity_state(state_dir: &Path) -> Result<IdentityState, ConfigError> {
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

/// Reads `RELAY_JOIN` as the raw value [`plan_startup`] takes: unset is `None`,
/// and a value that is not UTF-8 is an error rather than unset.
pub fn relay_join_from_env() -> Result<Option<String>, ConfigError> {
    match std::env::var("RELAY_JOIN") {
        Ok(v) => Ok(Some(v)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(ConfigError::JoinNotUnicode),
    }
}

/// Decides what this start does (DI-25). Only a fully unconfigured Node —
/// no identity file at all and `RELAY_JOIN` unset or empty — is `Unconfigured`;
/// a partial identity or a malformed join string is an error, so a broken Node
/// shows as failed rather than idle.
///
/// `read_join` is called only when no identity file exists, so an enrolled
/// Node never reads its join string at all, however malformed (DI-38: inert).
pub fn plan_startup(
    state_dir: &Path,
    read_join: impl FnOnce() -> Result<Option<String>, ConfigError>,
) -> Result<StartupPlan, ConfigError> {
    match identity_state(state_dir)? {
        IdentityState::Complete => Ok(StartupPlan::Enrolled),
        IdentityState::Partial { missing } => Err(ConfigError::PartialIdentity {
            state_dir: state_dir.to_path_buf(),
            missing,
        }),
        IdentityState::Absent => match decode_join(read_join()?)? {
            None => Ok(StartupPlan::Unconfigured),
            Some(join) => Ok(StartupPlan::Enroll(join)),
        },
    }
}

/// Decodes a `RELAY_JOIN` value: unset or empty is `None`; anything else must be
/// at most [`MAX_JOIN_STRING_LEN`] bytes, decode, and carry a dialable address.
pub fn decode_join(raw: Option<String>) -> Result<Option<JoinString>, ConfigError> {
    let Some(raw) = raw.filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    if raw.len() > MAX_JOIN_STRING_LEN {
        return Err(ConfigError::JoinTooLong);
    }
    let join = JoinString::decode(&raw).map_err(ConfigError::MalformedJoin)?;
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
    /// Resolved Relay address: `--relay`/`RELAY_ADDR` when set, else (enrolling)
    /// the join string's, else the one persisted at enrollment (may be `http://`
    /// when from the environment).
    pub relay_addr: String,
    /// `relay_addr` normalized to `https://` — the gRPC dial target.
    pub endpoint: String,
    /// `RELAY_DOMAIN` TLS SNI override (optional).
    pub relay_domain: Option<String>,
    /// `RELAY_STATE_DIR` — where identity files are persisted.
    pub state_dir: PathBuf,
    /// `RELAY_POLICY_PATH` — path to the Node's Policy TOML file.
    ///
    /// Defaults to `/etc/relay-daemon/policy.toml` when the env var is absent.
    /// The daemon loads the Policy at startup via `policy::load_policy`. Absent or
    /// unreadable file → warn and fall back to deny-all (fail-closed for dispatch).
    pub policy_path: PathBuf,
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
    pub fn from_env() -> Result<Config, ConfigError> {
        Self::from_env_for(None)
    }

    /// As [`Config::from_env`], with `join` the join string being enrolled with:
    /// its address stands in for the persisted one, which a Node without an
    /// identity does not have.
    ///
    /// Fails only when no Relay address source exists or the persisted address
    /// is unreadable or malformed. Defaults are applied for every other missing
    /// or unparsable env var. Enroll endpoint scheme validation lives in
    /// [`enroll_config`] and returns a typed `EnrollError`.
    pub fn from_env_for(join: Option<&JoinString>) -> Result<Config, ConfigError> {
        let state_dir = state_dir_from_env();
        let join_addr = join.map(|j| format!("https://{}", j.relay_address()));
        let relay_addr =
            resolve_relay_addr(relay_addr_override_from_args_env(), join_addr, &state_dir)?;
        let endpoint = normalize_scheme(&relay_addr);
        let relay_domain = std::env::var("RELAY_DOMAIN").ok();
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

        Ok(Config {
            relay_addr,
            endpoint,
            relay_domain,
            state_dir,
            policy_path,
            template_dir: template_dir_from_env(),
            node_labels,
            facts,
        })
    }
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

/// Builds enrollment configuration from the shared `Config`, the decoded join
/// string, and the one enroll-only env var:
///
/// - `RELAY_ENROLL_ENDPOINT` — overrides `cfg.endpoint` as the enrollment dial
///   target only; the address persisted for the Tunnel is `cfg.endpoint`. The
///   CA pin applies to whichever endpoint is dialled.
///
/// All other values (`relay_domain`, `state_dir`, `node_labels`, `facts`)
/// are taken from `cfg` — they are not re-read from the environment.
pub fn enroll_config(cfg: &Config, join: JoinString) -> Result<EnrollConfig, EnrollError> {
    // cfg.endpoint is already normalized (http→https); the override is used
    // raw so operators can specify a distinct enrollment endpoint if needed.
    let endpoint = std::env::var("RELAY_ENROLL_ENDPOINT")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| cfg.endpoint.clone());

    // Fail closed: an "http://" endpoint would skip TLS, and with it the CA
    // pin, exposing the Enrollment Token. `IdentityError` auto-converts into
    // `EnrollError::Identity` via the existing `#[from]` impl.
    validate_endpoint_scheme(&endpoint)?;

    Ok(EnrollConfig {
        join,
        endpoint,
        relay_addr: cfg.endpoint.clone(),
        relay_domain: cfg.relay_domain.clone(),
        state_dir: cfg.state_dir.clone(),
        node_labels: cfg.node_labels.clone(),
        facts: cfg.facts.clone(),
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
/// `RELAY_ADDR`. An empty value from either source counts as unset.
fn relay_addr_override_from_args_env() -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    let from_args = args
        .windows(2)
        .find(|w| w[0] == "--relay")
        .map(|w| w[1].clone());
    from_args
        .or_else(|| std::env::var("RELAY_ADDR").ok())
        .filter(|v| !v.is_empty())
}

/// Resolves the Relay address: the override when set (without reading the
/// persisted file, so config management can always repoint a Node), else the
/// join string's address while enrolling, else the address persisted at
/// enrollment. With none, refuses; there is no default.
pub(crate) fn resolve_relay_addr(
    override_addr: Option<String>,
    join_addr: Option<String>,
    state_dir: &Path,
) -> Result<String, ConfigError> {
    if let Some(addr) = override_addr.or(join_addr) {
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
        std::env::set_var("RELAY_ADDR", "https://relay:7654");
        std::env::remove_var("RELAY_DOMAIN");
        // CI shells commonly set HOSTNAME; remove it so the default fires.
        std::env::remove_var("HOSTNAME");
        std::env::remove_var("RELAY_NODE_LABELS");
        std::env::remove_var("RELAY_POLICY_PATH");

        let cfg = Config::from_env().expect("from_env");
        assert_eq!(cfg.relay_domain, None);
        assert_eq!(
            cfg.policy_path,
            PathBuf::from("/etc/relay-daemon/policy.toml")
        );
        assert!(cfg.node_labels.is_empty());

        std::env::remove_var("RELAY_ADDR");
        std::env::remove_var("RELAY_STATE_DIR");
        assert_eq!(state_dir_from_env(), PathBuf::from("/var/lib/relay-daemon"));
    }

    #[test]
    fn config_policy_path_override() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _dir = isolated_state_dir("cfg-policy");
        std::env::set_var("RELAY_ADDR", "https://relay:7654");
        std::env::set_var("RELAY_POLICY_PATH", "/custom/policy.toml");

        let cfg = Config::from_env().expect("from_env");
        assert_eq!(cfg.policy_path, PathBuf::from("/custom/policy.toml"));

        std::env::remove_var("RELAY_POLICY_PATH");
        std::env::remove_var("RELAY_ADDR");
    }

    // --- Relay address resolution -------------------------------------------

    #[test]
    fn relay_addr_overrides_persisted_address() {
        let _lock = ENV_LOCK.lock().unwrap();
        let dir = isolated_state_dir("cfg-override");
        std::fs::write(
            dir.path().join(crate::identity::PERSISTED_ADDR_FILE),
            "https://persisted:7654\n",
        )
        .unwrap();

        std::env::set_var("RELAY_ADDR", "https://override:9000");
        let cfg = Config::from_env().expect("from_env");
        assert_eq!(cfg.relay_addr, "https://override:9000");
        assert_eq!(cfg.endpoint, "https://override:9000");

        std::env::remove_var("RELAY_ADDR");
        let cfg = Config::from_env().expect("from_env");
        assert_eq!(cfg.relay_addr, "https://persisted:7654");
        assert_eq!(cfg.endpoint, "https://persisted:7654");
    }

    #[test]
    fn no_address_source_refuses_naming_relay_addr() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _dir = isolated_state_dir("cfg-no-addr");

        std::env::remove_var("RELAY_ADDR");
        let err = Config::from_env().err().expect("must refuse");
        assert!(matches!(err, ConfigError::NoRelayAddr { .. }), "{err:?}");
        assert!(err.to_string().contains("RELAY_ADDR"), "{err}");

        // An empty RELAY_ADDR counts as unset.
        std::env::set_var("RELAY_ADDR", "");
        let err = Config::from_env().err().expect("must refuse");
        assert!(matches!(err, ConfigError::NoRelayAddr { .. }), "{err:?}");

        std::env::remove_var("RELAY_ADDR");
    }

    #[test]
    fn no_localhost_default_address() {
        let dir = crate::test_support::TempDir::created("cfg-no-default");
        assert!(resolve_relay_addr(None, None, dir.path()).is_err());

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
        std::env::set_var("RELAY_ADDR", "https://relay:9000");
        std::env::set_var("RELAY_DOMAIN", "relay.internal");

        let cfg = Config::from_env().expect("from_env");
        assert_eq!(cfg.relay_addr, "https://relay:9000");
        // https:// passes through normalize_scheme unchanged.
        assert_eq!(cfg.endpoint, "https://relay:9000");
        assert_eq!(cfg.relay_domain, Some("relay.internal".to_string()));

        std::env::remove_var("RELAY_ADDR");
        std::env::remove_var("RELAY_DOMAIN");
    }

    #[test]
    fn config_from_env_facts_match_gather_facts() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _dir = isolated_state_dir("cfg-facts");
        std::env::set_var("RELAY_ADDR", "https://relay:7654");

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

        std::env::remove_var("RELAY_ADDR");
    }

    // --- Config::from_env scheme normalization ------------------------------

    #[test]
    fn config_from_env_scheme_normalization() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _dir = isolated_state_dir("cfg-scheme");
        std::env::set_var("RELAY_ADDR", "http://relay:8080");

        let cfg = Config::from_env().expect("from_env");
        // relay_addr retains the raw value; endpoint is normalized.
        assert_eq!(cfg.relay_addr, "http://relay:8080");
        assert_eq!(cfg.endpoint, "https://relay:8080");

        std::env::remove_var("RELAY_ADDR");
    }

    // --- enroll_config ------------------------------------------------------

    /// Constructs a minimal fake Config for use in enroll_config tests.
    /// No env vars are read — fields are set directly.
    fn fake_config() -> Config {
        Config {
            template_dir: std::path::PathBuf::from("/nonexistent/templates.d"),
            relay_addr: "http://relay:7654".to_string(),
            endpoint: "https://relay:7654".to_string(),
            relay_domain: None,
            state_dir: PathBuf::from("/var/lib/relay-daemon"),
            policy_path: PathBuf::from("/etc/relay-daemon/policy.toml"),
            node_labels: vec![],
            facts: Facts {
                hostname: "test-node".to_string(),
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
                kernel: String::new(),
                ip_addresses: vec![],
            },
        }
    }

    fn join_for(addr: &str) -> String {
        JoinString::new(addr.to_string(), [7u8; 32], "tok-test".to_string())
            .encode()
            .expect("encode")
    }

    fn decoded(addr: &str) -> JoinString {
        decode_join(Some(join_for(addr)))
            .expect("decode")
            .expect("some")
    }

    #[test]
    fn enroll_endpoint_override_does_not_change_persisted_address() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var("RELAY_ENROLL_ENDPOINT", "https://override:9000");

        let cfg = fake_config();
        let ec = enroll_config(&cfg, decoded("relay:7654")).expect("enroll_config");

        assert_eq!(
            ec.endpoint, "https://override:9000",
            "RELAY_ENROLL_ENDPOINT must take precedence over cfg.endpoint"
        );
        // The persisted (Tunnel) address stays the Node-plane one.
        assert_eq!(ec.relay_addr, cfg.endpoint);
        assert_eq!(ec.join.enrollment_token(), "tok-test");

        std::env::remove_var("RELAY_ENROLL_ENDPOINT");
    }

    #[test]
    fn enroll_endpoint_defaults_to_config_endpoint() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::remove_var("RELAY_ENROLL_ENDPOINT");
        let cfg = fake_config();
        let ec = enroll_config(&cfg, decoded("relay:7654")).expect("enroll_config");
        assert_eq!(ec.endpoint, cfg.endpoint);
    }

    #[test]
    fn http_enroll_endpoint_is_refused() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var("RELAY_ENROLL_ENDPOINT", "http://relay:7654");
        let cfg = fake_config();
        assert!(enroll_config(&cfg, decoded("relay:7654")).is_err());
        std::env::remove_var("RELAY_ENROLL_ENDPOINT");
    }

    // --- the join string and the address it carries ---------------------------

    #[test]
    fn join_address_is_the_enrollment_address_unless_overridden() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _dir = isolated_state_dir("cfg-join-addr");
        std::env::remove_var("RELAY_ADDR");
        let join = decoded("relay.example:7654");

        let cfg = Config::from_env_for(Some(&join)).expect("from_env_for");
        assert_eq!(cfg.relay_addr, "https://relay.example:7654");
        assert_eq!(cfg.endpoint, "https://relay.example:7654");

        std::env::set_var("RELAY_ADDR", "https://override:9000");
        let cfg = Config::from_env_for(Some(&join)).expect("from_env_for");
        assert_eq!(cfg.relay_addr, "https://override:9000");
        std::env::remove_var("RELAY_ADDR");
    }

    #[test]
    fn unset_or_empty_join_is_none() {
        assert!(decode_join(None).unwrap().is_none());
        assert!(decode_join(Some(String::new())).unwrap().is_none());
    }

    #[test]
    fn overlong_join_is_refused_before_decoding() {
        let long = format!("glp_join_{}", "A".repeat(MAX_JOIN_STRING_LEN));
        assert!(matches!(
            decode_join(Some(long)),
            Err(ConfigError::JoinTooLong)
        ));
    }

    #[test]
    fn malformed_join_is_refused_without_echoing_it() {
        let input = "glp_join_not!base64 tok-secret".to_string();
        let err = decode_join(Some(input.clone())).expect_err("refused");
        assert!(matches!(err, ConfigError::MalformedJoin(_)), "{err:?}");
        let text = format!("{err} {err:?}");
        assert!(!text.contains("tok-secret"), "{text}");
        assert!(!text.contains(&input), "{text}");
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
        let err = decode_join(Some(join_for("https://relay:7654"))).expect_err("refused");
        assert!(matches!(err, ConfigError::BadJoinAddress(_)), "{err:?}");
    }

    // --- plan_startup (the exit rule) ---------------------------------------

    fn seed(dir: &Path, names: &[&str]) {
        std::fs::create_dir_all(dir).unwrap();
        for n in names {
            std::fs::write(dir.join(n), "x").unwrap();
        }
    }

    #[test]
    fn plan_unconfigured_only_without_identity_or_join() {
        let dir = crate::test_support::TempDir::created("plan-unconfigured");
        assert!(matches!(
            plan_startup(dir.path(), || Ok(None)),
            Ok(StartupPlan::Unconfigured)
        ));
        assert!(matches!(
            plan_startup(dir.path(), || Ok(Some(String::new()))),
            Ok(StartupPlan::Unconfigured)
        ));
        // A state directory that does not exist yet holds no identity either.
        assert!(matches!(
            plan_startup(&dir.path().join("absent"), || Ok(None)),
            Ok(StartupPlan::Unconfigured)
        ));
    }

    #[test]
    fn plan_enrolls_with_a_valid_join() {
        let dir = crate::test_support::TempDir::created("plan-enroll");
        match plan_startup(dir.path(), || Ok(Some(join_for("relay:7654")))) {
            Ok(StartupPlan::Enroll(j)) => assert_eq!(j.relay_address(), "relay:7654"),
            _ => panic!("want Enroll"),
        }
    }

    #[test]
    fn plan_refuses_a_malformed_join() {
        let dir = crate::test_support::TempDir::created("plan-malformed");
        assert!(plan_startup(dir.path(), || Ok(Some("not-a-join-string".into()))).is_err());
    }

    #[test]
    fn plan_refuses_every_partial_identity() {
        let dir = crate::test_support::TempDir::created("plan-partial");
        for present in 1..IDENTITY_FILES.len() {
            let sub = dir.path().join(format!("p{present}"));
            seed(&sub, &IDENTITY_FILES[..present]);
            let err = plan_startup(&sub, || Ok(Some(join_for("relay:7654"))))
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

    #[test]
    fn plan_never_reads_the_join_once_enrolled() {
        let dir = crate::test_support::TempDir::created("plan-enrolled-unread");
        seed(dir.path(), &IDENTITY_FILES);
        assert!(matches!(
            plan_startup(dir.path(), || panic!(
                "an enrolled Node must not read RELAY_JOIN"
            )),
            Ok(StartupPlan::Enrolled)
        ));
        // A join string that could not even be read (not UTF-8) does not matter.
        assert!(matches!(
            plan_startup(dir.path(), || Err(ConfigError::JoinNotUnicode)),
            Ok(StartupPlan::Enrolled)
        ));
    }

    #[test]
    fn plan_ignores_the_join_once_enrolled() {
        let dir = crate::test_support::TempDir::created("plan-enrolled");
        seed(dir.path(), &IDENTITY_FILES);
        // Inert: even a malformed join string is never read.
        assert!(matches!(
            plan_startup(dir.path(), || Ok(Some("not-a-join-string".into()))),
            Ok(StartupPlan::Enrolled)
        ));
        assert!(matches!(
            plan_startup(dir.path(), || Ok(None)),
            Ok(StartupPlan::Enrolled)
        ));
    }
}
