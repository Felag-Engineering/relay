//! The one place a caller- or Relay-supplied string becomes a log field.
//!
//! Debug escaping turns `\n`, `\r`, ESC and other non-printables (U+2028
//! included) into visible escapes, so one event is one journald line. The cap
//! bounds how long that line is. Output for a value under the cap is
//! byte-identical to the bare `?` formatting #913 used on the decision events.
//!
//! `tests/log_fields_escaped.rs` fails `cargo test` (and so `make verify`) when
//! a tracing field is neither wrapped here nor a reviewed local-only value.

use std::fmt;

use tracing::Subscriber;
use tracing_subscriber::fmt::format::{DefaultFields, Format, Full};
use tracing_subscriber::fmt::time::SystemTime as LogSystemTime;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::registry::LookupSpan;

#[cfg(feature = "ban-probe")]
#[allow(dead_code)]
#[path = "../ban_probe.rs"]
mod ban_probe;

/// Longest value, counted in chars of the raw value before escaping. Debug
/// expands one char to at most 10, so a line stays bounded.
pub(crate) const LOG_FIELD_MAX_CHARS: usize = 256;
/// Most elements of a list that are rendered.
pub(crate) const LOG_LIST_MAX_ITEMS: usize = 16;

/// A string that came off the wire, rendered quoted and escaped, and cut at
/// [`LOG_FIELD_MAX_CHARS`].
pub struct Untrusted<'a>(&'a str);

impl fmt::Display for Untrusted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.char_indices().nth(LOG_FIELD_MAX_CHARS) {
            None => write!(f, "{:?}", self.0),
            // The marker goes outside the closing quote, so value content
            // cannot forge it.
            Some((cut, _)) => write!(f, "{:?}…", &self.0[..cut]),
        }
    }
}

/// A list of wire strings: each element as [`Untrusted`], at most
/// [`LOG_LIST_MAX_ITEMS`] of them.
pub struct UntrustedList<'a>(&'a [String]);

impl fmt::Display for UntrustedList<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[")?;
        for (i, item) in self.0.iter().take(LOG_LIST_MAX_ITEMS).enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{}", Untrusted(item))?;
        }
        if self.0.len() > LOG_LIST_MAX_ITEMS {
            f.write_str(", …")?;
        }
        f.write_str("]")
    }
}

/// Wraps a wire string as a `tracing` field value. Call sites use no `%`/`?`
/// sigil on the result.
pub fn untrusted(s: &str) -> tracing::field::DisplayValue<Untrusted<'_>> {
    tracing::field::display(Untrusted(s))
}

/// [`untrusted`] for a list of wire strings.
pub fn untrusted_list(v: &[String]) -> tracing::field::DisplayValue<UntrustedList<'_>> {
    tracing::field::display(UntrustedList(v))
}

/// The daemon's one log formatting layer, shared by production and the tests
/// that prove what a journal line looks like.
///
/// ANSI is off unconditionally because the log sink is journald: escape
/// codes split the target from its colon and break the documented `journalctl`
/// pattern. `log_internal_errors(true)` keeps what `fmt()`'s builder set, so a
/// failed write to stdout is still reported on stderr, not dropped silently.
pub fn log_fmt_layer<S, W>(
    make_writer: W,
) -> tracing_subscriber::fmt::Layer<S, DefaultFields, Format<Full, LogSystemTime>, W>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'w> MakeWriter<'w> + 'static,
{
    tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .log_internal_errors(true)
        .with_writer(make_writer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(s: &str) -> String {
        Untrusted(s).to_string()
    }

    #[test]
    fn short_value_matches_debug_exactly() {
        for s in ["t-1", "", "a\"b", "a\\b"] {
            assert_eq!(render(s), format!("{s:?}"));
        }
    }

    #[test]
    fn newline_cr_esc_u2028_are_escaped() {
        let out = render("a\nb\rc\u{1b}d\u{2028}e");
        assert!(!out.contains('\n') && !out.contains('\r'));
        assert!(!out.contains('\u{1b}') && !out.contains('\u{2028}'));
        assert!(out.contains("\\n") && out.contains("\\r"));
    }

    #[test]
    fn value_over_cap_is_cut_on_char_boundary_with_marker_outside_quotes() {
        let out = render(&"é".repeat(300));
        assert_eq!(out, format!("\"{}\"…", "é".repeat(LOG_FIELD_MAX_CHARS)));
    }

    #[test]
    fn value_at_cap_is_not_marked() {
        let s = "a".repeat(LOG_FIELD_MAX_CHARS);
        assert_eq!(render(&s), format!("{s:?}"));
    }

    #[test]
    fn list_matches_slice_debug_under_caps() {
        let v = vec!["a".to_string(), "b\"c".to_string()];
        assert_eq!(UntrustedList(&v).to_string(), format!("{v:?}"));
        assert_eq!(UntrustedList(&[]).to_string(), "[]");
    }

    #[test]
    fn list_over_item_cap_ends_with_ellipsis() {
        let v: Vec<String> = (0..LOG_LIST_MAX_ITEMS + 1).map(|i| i.to_string()).collect();
        let out = UntrustedList(&v).to_string();
        assert!(out.ends_with(", …]"), "{out}");
        assert!(!out.contains(&format!("\"{LOG_LIST_MAX_ITEMS}\"")));
    }

    #[test]
    fn list_elements_are_individually_capped() {
        let v = vec!["x".repeat(LOG_FIELD_MAX_CHARS + 5)];
        assert_eq!(
            UntrustedList(&v).to_string(),
            format!("[\"{}\"…]", "x".repeat(LOG_FIELD_MAX_CHARS))
        );
    }
}
