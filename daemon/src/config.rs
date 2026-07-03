//! The daemon's single environment/config surface, read once at startup and
//! threaded down. Centralizes the previously double-read RELAY_ADDR /
//! RELAY_DOMAIN / HOSTNAME and the http→https scheme normalization.

use std::path::PathBuf;

use crate::enroll::{node_labels_from_env, state_dir_from_env};
use crate::gen::Facts;

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
    /// `RELAY_NODE_LABELS` as bare `(key, value)` pairs; `node:` prefix is
    /// added at send time by `enroll::node_labels_to_proto` (ADR-0006 §7).
    pub node_labels: Vec<(String, String)>,
    /// Facts advertised to the Relay on Hello. Built once here so neither
    /// `EnrollConfig` nor `main` re-reads `HOSTNAME` / `OS` / `ARCH`.
    pub facts: Facts,
}

impl Config {
    /// Reads all shared daemon configuration from the environment.
    ///
    /// Infallible: defaults are applied for every missing or unparsable env
    /// var. The only fallible config step — enroll endpoint scheme validation —
    /// lives in `EnrollConfig::from_config` and returns a typed `EnrollError`.
    pub fn from_env() -> Config {
        let relay_addr = relay_addr_from_args_env();
        let endpoint = normalize_scheme(&relay_addr);
        let relay_domain = std::env::var("RELAY_DOMAIN").ok();
        let state_dir = state_dir_from_env();
        let node_labels = node_labels_from_env();

        // Facts.hostname is the human-readable descriptor, not the
        // Relay-assigned identity UUID (see node_id on Hello, ADR-0006).
        let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown-node".to_string());
        let facts = Facts {
            hostname,
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            kernel: String::new(),
            ip_addresses: vec![],
        };

        Config {
            relay_addr,
            endpoint,
            relay_domain,
            state_dir,
            node_labels,
            facts,
        }
    }
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

        let cfg = Config::from_env();
        assert_eq!(cfg.relay_addr, "http://127.0.0.1:7654");
        assert_eq!(cfg.endpoint, "https://127.0.0.1:7654");
        assert_eq!(cfg.relay_domain, None);
        assert_eq!(cfg.facts.hostname, "unknown-node");
        assert_eq!(cfg.state_dir, PathBuf::from("/var/lib/relay-daemon"));
        assert!(cfg.node_labels.is_empty());
    }

    // --- Config::from_env overrides -----------------------------------------

    #[test]
    fn config_from_env_overrides() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var("RELAY_ADDR", "https://relay:9000");
        std::env::set_var("RELAY_DOMAIN", "relay.internal");
        std::env::set_var("HOSTNAME", "web-01");

        let cfg = Config::from_env();
        assert_eq!(cfg.relay_addr, "https://relay:9000");
        // https:// passes through normalize_scheme unchanged.
        assert_eq!(cfg.endpoint, "https://relay:9000");
        assert_eq!(cfg.relay_domain, Some("relay.internal".to_string()));
        assert_eq!(cfg.facts.hostname, "web-01");

        std::env::remove_var("RELAY_ADDR");
        std::env::remove_var("RELAY_DOMAIN");
        std::env::remove_var("HOSTNAME");
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
}
