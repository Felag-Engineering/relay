//! The wire form of the daemon's Policy decision: the pass, and the rule that
//! decided. One mapping serves the Policy preflight (`PolicyVerdict`) and the apply
//! path (`TaskResult.policy_rule`), so the two cannot drift (ADR-0011).

use crate::gen::{PolicyPass, PolicyRuleRef, PolicyRuleSection};
use crate::policy::{Explained, Pass, RuleSection};

/// Exhaustive on purpose: a new `Pass` does not compile until it is mapped.
pub fn wire_pass(pass: Pass) -> PolicyPass {
    match pass {
        Pass::Precondition => PolicyPass::Precondition,
        Pass::Deny => PolicyPass::Deny,
        Pass::Guard => PolicyPass::Guard,
        Pass::Allow => PolicyPass::Allow,
        Pass::Default => PolicyPass::Default,
    }
}

/// Exhaustive on purpose: a new `RuleSection` does not compile until it is mapped.
pub fn wire_rule_section(section: RuleSection) -> PolicyRuleSection {
    match section {
        RuleSection::Operation => PolicyRuleSection::Operation,
        RuleSection::Deny => PolicyRuleSection::Deny,
        RuleSection::RawExecAllow => PolicyRuleSection::RawExecAllow,
        RuleSection::RawExecDeny => PolicyRuleSection::RawExecDeny,
    }
}

/// The pass and rule reference of a decision, as the wire reports them. The
/// section, index and line are set exactly when a rule decided; an index or
/// line too large for the wire saturates at `u32::MAX`.
pub fn policy_rule_ref(explained: &Explained) -> PolicyRuleRef {
    let rule = explained.rule;
    PolicyRuleRef {
        pass: wire_pass(explained.pass) as i32,
        rule_section: rule.map_or(PolicyRuleSection::Unspecified, |r| {
            wire_rule_section(r.section)
        }) as i32,
        rule_index: rule.map_or(0, |r| u32::try_from(r.index).unwrap_or(u32::MAX)),
        rule_line: rule
            .and_then(|r| r.line)
            .map_or(0, |l| u32::try_from(l).unwrap_or(u32::MAX)),
    }
}
