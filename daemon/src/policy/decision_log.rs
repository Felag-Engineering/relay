//! The Node's own record of Policy decisions (#888).
//!
//! One event per Allow at [`ALLOW_TARGET`] and one per Deny at [`DENY_TARGET`],
//! with shared field names so a single journald query covers both. Nothing here
//! can carry argv: [`DecisionFields`] holds only a digest and a count. The
//! events are shipped by journald and bounded by its `SystemMaxUse`; the daemon
//! writes no file of its own.

use crate::gen::RiskClass;
use crate::policy::Rule;

/// `tracing` target of the one event emitted per Policy Allow.
pub(crate) const ALLOW_TARGET: &str = "relay_daemon::allow";
/// `tracing` target of every Policy Deny event; same field names as Allow.
pub(crate) const DENY_TARGET: &str = "relay_daemon::deny";

/// The pattern the install guide documents for `journalctl -g`. Tests prove it
/// matches real formatted lines and appears verbatim in the guide.
#[cfg(test)]
pub(crate) const JOURNALCTL_PATTERN: &str = "relay_daemon::(allow|deny):";

/// Which execution tier a decision was made for (ADR-0001, ADR-0021).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tier {
    Native,
    Template,
    RawExec,
}

impl Tier {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Tier::Native => "native",
            Tier::Template => "template",
            Tier::RawExec => "raw_exec",
        }
    }
}

pub(crate) fn risk_class_str(risk: RiskClass) -> &'static str {
    match risk {
        RiskClass::Read => "read",
        RiskClass::Mutate => "mutate",
        RiskClass::Unspecified => "unspecified",
    }
}

/// SHA-256 of `parts` joined by a single NUL byte (no trailing NUL), as 64
/// lowercase hex characters.
///
/// An unsalted correlation digest: not a MAC and not a secrecy mechanism, since
/// a low-entropy argument can be recovered by guessing. The NUL join is a
/// framing convention, not an injectivity guarantee, because proto strings may
/// contain NUL.
pub(crate) fn argv_digest<S: AsRef<str>>(parts: &[S]) -> String {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            ctx.update(&[0]);
        }
        ctx.update(part.as_ref().as_bytes());
    }
    let digest = ctx.finish();
    let mut hex = String::with_capacity(64);
    for byte in digest.as_ref() {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// The fields every decision event shares. No field can hold argv.
///
/// `argc` is the number of elements `argv_digest` covers, on every tier.
pub(crate) struct DecisionFields<'a> {
    pub(crate) task_id: &'a str,
    pub(crate) operation: &'a str,
    pub(crate) tier: Tier,
    pub(crate) risk_class: RiskClass,
    pub(crate) argv_digest: String,
    pub(crate) argc: usize,
    pub(crate) policy_fingerprint: &'a str,
}

/// What a Deny adds beyond the shared fields, by tier.
pub(crate) enum DenyDetail<'a> {
    /// A typed Operation's positional arguments, as Policy saw them.
    Args(&'a [String]),
    /// A Raw Exec's `argv[0]`.
    Program(&'a str),
    /// Nothing more: the canonical-path precondition, which runs before Policy.
    None,
}

/// Records a Policy Deny with the same shared field names as [`emit_allow`].
/// `rule` is present only when a specific rule fired. Caller-derived text
/// (`task_id`, `operation`, `reason`, `args`, `program`) is Debug-formatted:
/// Debug escapes a newline, so a hostile value cannot start a forged journal
/// line.
pub(crate) fn emit_deny(
    f: &DecisionFields,
    rule: Option<&Rule>,
    reason: &str,
    detail: DenyDetail,
    message: &str,
) {
    let (args, program) = match detail {
        DenyDetail::Args(args) => (Some(args), None),
        DenyDetail::Program(program) => (None, Some(program)),
        DenyDetail::None => (None, None),
    };
    // An `Option` field is recorded only when `Some`.
    tracing::warn!(
        target: DENY_TARGET,
        task_id = ?f.task_id,
        operation = ?f.operation,
        tier = f.tier.as_str(),
        risk_class = risk_class_str(f.risk_class),
        argv_digest = %f.argv_digest,
        argc = f.argc,
        policy_fingerprint = %f.policy_fingerprint,
        args = args.map(tracing::field::debug),
        program = program.map(tracing::field::debug),
        rule = rule.map(tracing::field::debug),
        reason = ?reason,
        "{message}"
    );
}

/// Records a Policy Allow before invoke or spawn, not a successful spawn:
/// Template slot validation and the `file.read` layer-2 re-check can still
/// refuse afterwards. Caller-derived text is Debug-formatted, as in
/// [`emit_deny`].
pub(crate) fn emit_allow(f: &DecisionFields, rule: &Rule) {
    tracing::info!(
        target: ALLOW_TARGET,
        task_id = ?f.task_id,
        operation = ?f.operation,
        tier = f.tier.as_str(),
        risk_class = risk_class_str(f.risk_class),
        argv_digest = %f.argv_digest,
        argc = f.argc,
        rule = ?rule,
        policy_fingerprint = %f.policy_fingerprint,
        "policy allowed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_digest_joins_with_single_nul_no_trailing() {
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
        ctx.update(b"a\0b");
        let expected: String = ctx
            .finish()
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(argv_digest(&["a", "b"]), expected);
        assert_eq!(expected.len(), 64);
    }

    #[test]
    fn argv_digest_differs_across_split_points() {
        assert_ne!(argv_digest(&["ab", "c"]), argv_digest(&["a", "bc"]));
    }

    #[test]
    fn tier_and_risk_class_strings() {
        assert_eq!(Tier::Native.as_str(), "native");
        assert_eq!(Tier::Template.as_str(), "template");
        assert_eq!(Tier::RawExec.as_str(), "raw_exec");
        assert_eq!(risk_class_str(RiskClass::Read), "read");
        assert_eq!(risk_class_str(RiskClass::Mutate), "mutate");
        assert_eq!(risk_class_str(RiskClass::Unspecified), "unspecified");
    }
}
