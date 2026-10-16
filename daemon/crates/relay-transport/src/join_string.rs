//! The join string codec (ADR-0031). The wire form is `relay.v1.JoinString`, as
//! `glp_join_` followed by its unpadded base64url. Neither an error nor `Debug`
//! renders the input or the Enrollment Token.

use std::fmt;

use base64::Engine as _;
use prost::Message as _;

use crate::gen::JoinString as WireJoinString;

/// Opens the text form of a join string.
pub const PREFIX: &str = "glp_join_";

const FORMAT_VERSION: u32 = 1;

/// Why a join string was refused. No variant holds input, so no rendering of an
/// error can leak it.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
pub enum JoinStringError {
    #[error("join string: missing glp_join_ prefix")]
    MissingPrefix,
    #[error("join string: not unpadded base64url")]
    InvalidEncoding,
    #[error("join string: malformed message")]
    InvalidMessage,
    #[error("join string: unknown format version")]
    UnknownVersion,
    #[error("join string: empty field: {0}")]
    EmptyField(&'static str),
    #[error("join string: CA fingerprint is not 32 bytes")]
    BadFingerprintLength,
}

/// A decoded join string. It has no `Clone`, `Serialize` or `Display`, and its
/// `Debug` redacts the token.
pub struct JoinString {
    relay_address: String,
    ca_fingerprint: [u8; 32],
    enrollment_token: String,
}

impl fmt::Debug for JoinString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinString")
            .field("relay_address", &self.relay_address)
            .field("ca_fingerprint", &HexBytes(&self.ca_fingerprint))
            .field("enrollment_token", &format_args!("[REDACTED]"))
            .finish()
    }
}

struct HexBytes<'a>(&'a [u8]);

impl fmt::Debug for HexBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

fn is_base64url_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

impl JoinString {
    /// Builds a join string from its parts.
    pub fn new(relay_address: String, ca_fingerprint: [u8; 32], enrollment_token: String) -> Self {
        Self {
            relay_address,
            ca_fingerprint,
            enrollment_token,
        }
    }

    /// The host:port the daemon dials to enroll.
    pub fn relay_address(&self) -> &str {
        &self.relay_address
    }

    /// SHA-256 over the Relay CA certificate's DER.
    pub fn ca_fingerprint(&self) -> &[u8; 32] {
        &self.ca_fingerprint
    }

    /// The Enrollment Token plaintext. Handle it as a secret.
    pub fn enrollment_token(&self) -> &str {
        &self.enrollment_token
    }

    /// The text form: `PREFIX` and the unpadded base64url of the serialization.
    pub fn encode(&self) -> Result<String, JoinStringError> {
        if self.relay_address.is_empty() {
            return Err(JoinStringError::EmptyField("relay_address"));
        }
        if self.enrollment_token.is_empty() {
            return Err(JoinStringError::EmptyField("enrollment_token"));
        }
        let bytes = WireJoinString {
            format_version: FORMAT_VERSION,
            relay_address: self.relay_address.clone(),
            ca_fingerprint_sha256: self.ca_fingerprint.to_vec(),
            enrollment_token: self.enrollment_token.clone(),
        }
        .encode_to_vec();
        Ok(format!(
            "{PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
        ))
    }

    /// Parses the text form. The checks run in the same fixed order as the Go codec.
    pub fn decode(s: &str) -> Result<Self, JoinStringError> {
        let payload = s
            .strip_prefix(PREFIX)
            .ok_or(JoinStringError::MissingPrefix)?;
        if !payload.bytes().all(is_base64url_byte) {
            return Err(JoinStringError::InvalidEncoding);
        }
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| JoinStringError::InvalidEncoding)?;
        // prost refuses a known field with the wrong wire type here.
        let msg =
            WireJoinString::decode(raw.as_slice()).map_err(|_| JoinStringError::InvalidMessage)?;
        if msg.format_version != FORMAT_VERSION {
            return Err(JoinStringError::UnknownVersion);
        }
        // prost drops unknown fields, so its re-encode is a fresh four-field message.
        if msg.encode_to_vec() != raw {
            return Err(JoinStringError::InvalidMessage);
        }
        if msg.relay_address.is_empty() {
            return Err(JoinStringError::EmptyField("relay_address"));
        }
        if msg.ca_fingerprint_sha256.is_empty() {
            return Err(JoinStringError::EmptyField("ca_fingerprint_sha256"));
        }
        if msg.enrollment_token.is_empty() {
            return Err(JoinStringError::EmptyField("enrollment_token"));
        }
        let ca_fingerprint = <[u8; 32]>::try_from(msg.ca_fingerprint_sha256.as_slice())
            .map_err(|_| JoinStringError::BadFingerprintLength)?;
        Ok(Self {
            relay_address: msg.relay_address,
            ca_fingerprint,
            enrollment_token: msg.enrollment_token,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../proto/testdata/join_string_vectors.tsv"
    ));

    struct OkRow {
        name: &'static str,
        encoded: &'static str,
        address: &'static str,
        fingerprint: [u8; 32],
        token: &'static str,
    }

    struct RefuseRow {
        name: &'static str,
        reason: &'static str,
        input: &'static str,
    }

    const REASONS: [&str; 6] = [
        "missing_prefix",
        "invalid_encoding",
        "invalid_message",
        "unknown_version",
        "empty_field",
        "bad_fingerprint",
    ];

    fn unhex(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64, "fingerprint hex must be 64 characters");
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex");
        }
        out
    }

    fn load() -> (Vec<OkRow>, Vec<RefuseRow>) {
        let (mut oks, mut refuses) = (Vec::new(), Vec::new());
        for (i, line) in VECTORS.lines().enumerate() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let cols: Vec<&'static str> = line.split('\t').collect();
            match (cols[0], cols.len()) {
                ("ok", 6) => oks.push(OkRow {
                    name: cols[1],
                    encoded: cols[2],
                    address: cols[3],
                    fingerprint: unhex(cols[4]),
                    token: cols[5],
                }),
                ("refuse", 4) => {
                    assert!(REASONS.contains(&cols[2]), "line {}: unknown reason", i + 1);
                    refuses.push(RefuseRow {
                        name: cols[1],
                        reason: cols[2],
                        input: cols[3],
                    });
                }
                _ => panic!("line {}: malformed vectors line", i + 1),
            }
        }
        assert!(oks.len() >= 4, "want at least 4 ok rows");
        for reason in REASONS {
            assert!(
                refuses.iter().any(|r| r.reason == reason),
                "no refuse row for reason {reason}"
            );
        }
        (oks, refuses)
    }

    fn expected(reason: &str) -> JoinStringError {
        match reason {
            "missing_prefix" => JoinStringError::MissingPrefix,
            "invalid_encoding" => JoinStringError::InvalidEncoding,
            "invalid_message" => JoinStringError::InvalidMessage,
            "unknown_version" => JoinStringError::UnknownVersion,
            "empty_field" => JoinStringError::EmptyField(""),
            "bad_fingerprint" => JoinStringError::BadFingerprintLength,
            other => panic!("unknown reason {other}"),
        }
    }

    #[test]
    fn join_string_round_trips_shared_vectors() {
        let (oks, _) = load();
        for row in &oks {
            let got = JoinString::decode(row.encoded)
                .unwrap_or_else(|e| panic!("{}: decode: {e}", row.name));
            assert_eq!(got.relay_address(), row.address, "{}", row.name);
            assert_eq!(got.ca_fingerprint(), &row.fingerprint, "{}", row.name);
            assert_eq!(got.enrollment_token(), row.token, "{}", row.name);
            assert_eq!(got.encode().as_deref(), Ok(row.encoded), "{}", row.name);
            let built = JoinString::new(row.address.into(), row.fingerprint, row.token.into());
            assert_eq!(built.encode().as_deref(), Ok(row.encoded), "{}", row.name);
        }
        assert!(oks.iter().any(|r| r.encoded.contains('-')));
        assert!(oks.iter().any(|r| r.encoded.contains('_')));
    }

    #[test]
    fn join_string_refuses_malformed() {
        let (oks, refuses) = load();
        for row in &refuses {
            let err = JoinString::decode(row.input).expect_err(row.name);
            match (err, expected(row.reason)) {
                (JoinStringError::EmptyField(name), JoinStringError::EmptyField(_)) => {
                    let want = match row.name {
                        "relay_address_missing" => "relay_address",
                        "ca_fingerprint_missing" => "ca_fingerprint_sha256",
                        "enrollment_token_missing" => "enrollment_token",
                        other => panic!("unmapped empty_field row {other}"),
                    };
                    assert_eq!(name, want, "{}", row.name);
                }
                (got, want) => assert_eq!(got, want, "{}", row.name),
            }
        }

        let valid = oks[0].encoded;
        let mid = PREFIX.len() + 10;
        let with = |s: &str| format!("{}{s}{}", &valid[..mid], &valid[mid..]);
        let local: Vec<(&str, String, JoinStringError)> = vec![
            ("empty", String::new(), JoinStringError::MissingPrefix),
            (
                "leading_space",
                format!(" {valid}"),
                JoinStringError::MissingPrefix,
            ),
            (
                "leading_tab",
                format!("\t{valid}"),
                JoinStringError::MissingPrefix,
            ),
            (
                "lf_mid_payload",
                with("\n"),
                JoinStringError::InvalidEncoding,
            ),
            (
                "crlf_appended",
                format!("{valid}\r\n"),
                JoinStringError::InvalidEncoding,
            ),
            (
                "trailing_space",
                format!("{valid} "),
                JoinStringError::InvalidEncoding,
            ),
            (
                "trailing_tab",
                format!("{valid}\t"),
                JoinStringError::InvalidEncoding,
            ),
            (
                "space_mid_payload",
                with(" "),
                JoinStringError::InvalidEncoding,
            ),
        ];
        for (name, input, want) in local {
            assert_eq!(JoinString::decode(&input).expect_err(name), want, "{name}");
        }

        let empty_addr = JoinString::new(String::new(), [0; 32], "tok".into());
        assert_eq!(
            empty_addr.encode(),
            Err(JoinStringError::EmptyField("relay_address"))
        );
        let empty_tok = JoinString::new("host:1".into(), [0; 32], String::new());
        assert_eq!(
            empty_tok.encode(),
            Err(JoinStringError::EmptyField("enrollment_token"))
        );
    }

    #[test]
    fn join_string_never_renders_input_or_token() {
        let (oks, refuses) = load();
        let inputs = oks
            .iter()
            .map(|r| r.encoded)
            .chain(refuses.iter().map(|r| r.input));
        for input in inputs {
            let Err(err) = JoinString::decode(input) else {
                continue;
            };
            let payload = input.strip_prefix(PREFIX).unwrap_or(input);
            for text in [err.to_string(), format!("{err:?}")] {
                assert!(!text.contains(input), "error leaks its input");
                if !payload.is_empty() {
                    assert!(!text.contains(payload), "error leaks its payload");
                }
                for row in &oks {
                    assert!(!text.contains(row.token), "error leaks a token");
                }
            }
        }
        for row in &oks {
            let v = JoinString::decode(row.encoded).expect("ok row decodes");
            for text in [format!("{v:?}"), format!("{v:#?}")] {
                assert!(
                    !text.contains(row.token),
                    "{}: Debug leaks the token",
                    row.name
                );
                assert!(
                    !text.contains(row.encoded),
                    "{}: Debug leaks encoded",
                    row.name
                );
                assert!(text.contains("[REDACTED]"));
            }
        }
    }
}
