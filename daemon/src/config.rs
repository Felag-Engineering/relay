//! The daemon's single environment/config surface, read once at startup and
//! threaded down. Centralizes the previously double-read RELAY_ADDR /
//! RELAY_DOMAIN and the http→https scheme normalization.
//!
//! Also hosts daemon-local hard limits (e.g. [`MAX_OUTPUT_BYTES`]) that are
//! compile-time constants, not env-derived — kept here as the daemon's single
//! neutral config-adjacent home rather than scattered per call site.
//! The spawned-child `setrlimit` bounds (`ResourceLimits`) live in relay-exec's
//! `limits` module (#889).

use std::path::PathBuf;

use crate::enroll::{node_labels_from_env, state_dir_from_env, EnrollConfig, EnrollError};
use crate::gen::Facts;
use crate::identity::validate_endpoint_scheme;

/// All daemon configuration derived from environment variables (and `--relay`
/// CLI arg). Constructed exactly once in `main` via `Config::from_env()` and
/// threaded down to callers. No env-var is read elsewhere for these fields.
pub struct Config {
    /// Raw `--relay` / `RELAY_ADDR` value (may still be `http://`).
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
    /// (ADR-0021, issue #291).
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
    /// Reads all shared daemon configuration from the environment.
    ///
    /// Infallible: defaults are applied for every missing or unparsable env
    /// var. The only fallible config step — enroll endpoint scheme validation —
    /// lives in [`enroll_config`] and returns a typed `EnrollError`.
    pub fn from_env() -> Config {
        let relay_addr = relay_addr_from_args_env();
        let endpoint = normalize_scheme(&relay_addr);
        let relay_domain = std::env::var("RELAY_DOMAIN").ok();
        let state_dir = state_dir_from_env();
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

        Config {
            relay_addr,
            endpoint,
            relay_domain,
            state_dir,
            policy_path,
            template_dir: template_dir_from_env(),
            node_labels,
            facts,
        }
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
/// and wire-immutable: the Relay can never raise it over the wire (invariant #11
/// analog for the daemon; ADR-0004). Bytes past the cap are drained but discarded
/// and `truncated` is set. Sane default; a Policy/env-tunable value is future work.
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024; // 1 MiB

/// Builds enrollment configuration from the shared `Config` plus the
/// enroll-only env vars.
///
/// Returns `Ok(None)` when `RELAY_ENROLLMENT_TOKEN` or
/// `RELAY_CA_BUNDLE_PATH` are absent or empty, so callers can skip the
/// enrollment step and fall through to the existing Tunnel path.
///
/// Environment keys read here (enroll-only):
/// - `RELAY_ENROLLMENT_TOKEN` — required; never logged
/// - `RELAY_CA_BUNDLE_PATH`   — required; path to pinned bootstrap CA
/// - `RELAY_ENROLL_ENDPOINT`  — overrides `cfg.endpoint` when set
///
/// All other values (`relay_domain`, `state_dir`, `node_labels`, `facts`)
/// are taken from `cfg` — they are not re-read from the environment.
pub fn enroll_config(cfg: &Config) -> Result<Option<EnrollConfig>, EnrollError> {
    let token = match std::env::var("RELAY_ENROLLMENT_TOKEN") {
        Ok(v) if !v.is_empty() => v,
        _ => return Ok(None),
    };
    let ca_bundle_str = match std::env::var("RELAY_CA_BUNDLE_PATH") {
        Ok(v) if !v.is_empty() => v,
        _ => return Ok(None),
    };

    // cfg.endpoint is already normalized (http→https); the override is used
    // raw so operators can specify a distinct enrollment endpoint if needed.
    let endpoint = std::env::var("RELAY_ENROLL_ENDPOINT").unwrap_or_else(|_| cfg.endpoint.clone());

    // Fail closed: TLS (and therefore CA pinning) is only active when the
    // scheme is exactly "https". An "http://" endpoint silently skips TLS
    // in tonic, exposing the enrollment token and the Node's pinned trust
    // root to a MITM. `IdentityError` auto-converts into `EnrollError::Identity`
    // via the existing `#[from]` impl.
    validate_endpoint_scheme(&endpoint)?;

    Ok(Some(EnrollConfig {
        token,
        endpoint,
        relay_domain: cfg.relay_domain.clone(),
        ca_bundle_path: PathBuf::from(ca_bundle_str),
        state_dir: cfg.state_dir.clone(),
        node_labels: cfg.node_labels.clone(),
        facts: cfg.facts.clone(),
    }))
}

/// Normalizes `http://` to `https://` in a Relay address.
///
/// `https://` passes through unchanged; any other scheme (including bare
/// hostnames and `grpc://`) is also returned as-is. This is a convenience
/// transformation for operators who supply plain `http://` addresses; the
/// authoritative fail-closed guard remains `validate_endpoint_scheme` /
/// `build_channel` (ADR-0005, invariant #6).
pub(crate) fn normalize_scheme(addr: &str) -> String {
    addr.replacen("http://", "https://", 1)
}

/// Returns the Relay address from `--relay <val>` (first occurrence in argv)
/// or `RELAY_ADDR`, falling back to `"http://127.0.0.1:7654"`.
fn relay_addr_from_args_env() -> String {
    let args: Vec<String> = std::env::args().collect();
    for window in args.windows(2) {
        if window[0] == "--relay" {
            return window[1].clone();
        }
    }
    std::env::var("RELAY_ADDR").unwrap_or_else(|_| "http://127.0.0.1:7654".to_string())
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

    // --- Config::from_env defaults ------------------------------------------

    #[test]
    fn config_from_env_defaults() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::remove_var("RELAY_ADDR");
        std::env::remove_var("RELAY_DOMAIN");
        // CI shells commonly set HOSTNAME; remove it so the default fires.
        std::env::remove_var("HOSTNAME");
        std::env::remove_var("RELAY_STATE_DIR");
        std::env::remove_var("RELAY_NODE_LABELS");
        std::env::remove_var("RELAY_POLICY_PATH");

        let cfg = Config::from_env();
        assert_eq!(cfg.relay_addr, "http://127.0.0.1:7654");
        assert_eq!(cfg.endpoint, "https://127.0.0.1:7654");
        assert_eq!(cfg.relay_domain, None);
        assert_eq!(cfg.state_dir, PathBuf::from("/var/lib/relay-daemon"));
        assert_eq!(
            cfg.policy_path,
            PathBuf::from("/etc/relay-daemon/policy.toml")
        );
        assert!(cfg.node_labels.is_empty());
    }

    #[test]
    fn config_policy_path_override() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var("RELAY_POLICY_PATH", "/custom/policy.toml");

        let cfg = Config::from_env();
        assert_eq!(cfg.policy_path, PathBuf::from("/custom/policy.toml"));

        std::env::remove_var("RELAY_POLICY_PATH");
    }

    // --- Config::from_env overrides -----------------------------------------

    #[test]
    fn config_from_env_overrides() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var("RELAY_ADDR", "https://relay:9000");
        std::env::set_var("RELAY_DOMAIN", "relay.internal");

        let cfg = Config::from_env();
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

        let cfg = Config::from_env();
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
    }

    // --- Config::from_env scheme normalization ------------------------------

    #[test]
    fn config_from_env_scheme_normalization() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var("RELAY_ADDR", "http://relay:8080");

        let cfg = Config::from_env();
        // relay_addr retains the raw value; endpoint is normalized.
        assert_eq!(cfg.relay_addr, "http://relay:8080");
        assert_eq!(cfg.endpoint, "https://relay:8080");

        std::env::remove_var("RELAY_ADDR");
    }

    // --- enroll_config smoke tests --------------------------------------------

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

    #[test]
    fn from_config_none_when_token_absent() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::remove_var("RELAY_ENROLLMENT_TOKEN");
        std::env::remove_var("RELAY_CA_BUNDLE_PATH");
        std::env::remove_var("RELAY_ENROLL_ENDPOINT");

        let cfg = fake_config();
        let result = enroll_config(&cfg).expect("enroll_config should not error");
        assert!(
            result.is_none(),
            "enroll_config must return None when RELAY_ENROLLMENT_TOKEN is absent"
        );
    }

    #[test]
    fn from_config_none_when_ca_bundle_absent() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var("RELAY_ENROLLMENT_TOKEN", "tok-test");
        std::env::remove_var("RELAY_CA_BUNDLE_PATH");
        std::env::remove_var("RELAY_ENROLL_ENDPOINT");

        let cfg = fake_config();
        let result = enroll_config(&cfg).expect("enroll_config should not error");
        assert!(
            result.is_none(),
            "enroll_config must return None when RELAY_CA_BUNDLE_PATH is absent"
        );

        std::env::remove_var("RELAY_ENROLLMENT_TOKEN");
    }

    #[test]
    fn from_config_enroll_endpoint_override() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var("RELAY_ENROLLMENT_TOKEN", "tok-test");
        std::env::set_var("RELAY_CA_BUNDLE_PATH", "/some/fake/ca.pem");
        std::env::set_var("RELAY_ENROLL_ENDPOINT", "https://override:9000");

        let cfg = fake_config();
        let ec = enroll_config(&cfg)
            .expect("enroll_config should not error")
            .expect("enroll_config should return Some when all required vars set");

        assert_eq!(
            ec.endpoint, "https://override:9000",
            "RELAY_ENROLL_ENDPOINT must take precedence over cfg.endpoint"
        );

        std::env::remove_var("RELAY_ENROLLMENT_TOKEN");
        std::env::remove_var("RELAY_CA_BUNDLE_PATH");
        std::env::remove_var("RELAY_ENROLL_ENDPOINT");
    }
}
