//! Evidence and limit statements for critical/high findings (review T04).
//!
//! A severity without its basis is not reviewable. Every critical/high finding
//! leaves this crate with a deterministic `[evidence: …] [limits: …]` suffix on
//! `detail` describing what was actually observed and what was not. The suffix
//! is appended after chain detection, so findings escalated by a chain are
//! covered too, and it never touches the `Detected in <path>:<line>` prefix
//! that downstream chain parsing depends on.
//!
//! This is a *text* annotation rather than new struct fields: the consumer
//! builds `Finding` values literally at its pinned revision, so adding a field
//! would be a breaking change. The text is rendered from a fixed table — no
//! model judgment, no I/O.

use crate::finding::{Finding, FindingCategory, Severity};
use crate::rules::*;

/// Credential-path rules: a high-impact capability if the read is reached.
const CREDENTIAL_PATHS: &[&str] = &[
    RULE_CLOUD_CREDENTIAL_FILE,
    RULE_SSH_KEY_FILE,
    RULE_NPM_CREDENTIAL_FILE,
    RULE_PYPI_CREDENTIAL_FILE,
    RULE_DOCKER_CREDENTIAL_FILE,
    RULE_KUBERNETES_CREDENTIAL_FILE,
    RULE_GITHUB_CLI_CREDENTIAL_FILE,
    RULE_NETRC_CREDENTIAL_FILE,
    RULE_MACOS_KEYCHAIN_ACCESS,
    RULE_WINDOWS_CREDENTIAL_STORE,
    RULE_WINDOWS_CREDENTIAL_DATABASE,
    RULE_AD_CREDENTIAL_DATABASE,
];

/// Dynamic code/process execution rules.
const DYNAMIC_EXECUTION: &[&str] = &[
    RULE_EVAL_CODE_INJECTION,
    RULE_SHELL_EXEC_UNSANDBOXED,
    RULE_PYTHON_EXEC_VARIABLE,
];

/// Destructive filesystem rules.
const DESTRUCTIVE: &[&str] = &[
    RULE_DESTRUCTIVE_FILESYSTEM_OP,
    RULE_DESTRUCTIVE_RECURSIVE_DELETE_SYSTEM,
    RULE_DESTRUCTIVE_RECURSIVE_DELETE_FIND,
];

/// Remote-content-toward-execution rules.
const REMOTE_TO_EXECUTION: &[&str] = &[
    RULE_RCE_PIPE_TO_SHELL,
    RULE_RCE_COMMAND_SUBSTITUTION,
    RULE_REMOTE_FETCH_TO_VARIABLE,
    RULE_PYTHON_REMOTE_FETCH,
    RULE_SHELL_VARIABLE_EXECUTION,
    RULE_OBFUSCATED_DANGEROUS_CODE,
    RULE_OBFUSCATED_NETWORK_CALL,
];

/// Appends evidence and limits to every critical/high finding.
pub(crate) fn annotate_evidence(findings: &mut [Finding]) {
    for finding in findings.iter_mut() {
        if !matches!(finding.severity, Severity::Critical | Severity::High) {
            continue;
        }
        if already_annotated(&finding.detail) {
            continue;
        }
        let (evidence, limits) = evidence_for(finding);
        finding
            .detail
            .push_str(&format!(" [evidence: {evidence}] [limits: {limits}]"));
    }
}

/// True when this crate already appended the annotation.
///
/// The check must not be spoofable: the source snippet is attacker-controlled
/// and can itself contain `[evidence:`. The snippet is always enclosed by the
/// detail's final backtick, so only text after that backtick can be ours.
fn already_annotated(detail: &str) -> bool {
    detail
        .rsplit('`')
        .next()
        .unwrap_or(detail)
        .contains("[evidence:")
}

fn evidence_for(finding: &Finding) -> (&'static str, &'static str) {
    let rule = finding.rule_id.as_str();

    if rule == RULE_EMBEDDED_PRIVATE_KEY {
        return (
            "private-key PEM header in analyzed text",
            "does not show the key is valid, was read, or left the host; runtime file access was not observed",
        );
    }
    if rule == RULE_POTENTIAL_API_TOKEN || rule == RULE_HIGH_ENTROPY_SECRET {
        return (
            "token-shaped literal value in analyzed text",
            "does not show the value is live or authorized, or that it was transmitted anywhere",
        );
    }
    if CREDENTIAL_PATHS.contains(&rule) {
        return (
            "literal reference to a credential path, which is high-impact material if reached",
            "does not show the path was opened or readable, or that any bytes left the host; runtime permissions and data flow were not observed",
        );
    }
    if DYNAMIC_EXECUTION.contains(&rule) {
        return (
            "call to a dynamic code or process execution API",
            "argument provenance, shell expansion, and sandbox isolation were not evaluated; execution was not observed",
        );
    }
    if DESTRUCTIVE.contains(&rule) {
        return (
            "command that deletes or overwrites filesystem paths",
            "the command was not executed; its effective scope and any guards are not established",
        );
    }
    if REMOTE_TO_EXECUTION.contains(&rule) {
        return (
            "remote content flowing toward execution",
            "network reachability, the fetched bytes, and their trustworthiness were not evaluated",
        );
    }
    if rule == RULE_CREDENTIAL_EXFILTRATION_CHAIN {
        return (
            "co-occurring credential-source and network-sink observations in one file",
            "co-occurrence is not proof that data left the host; runtime data flow was not observed",
        );
    }
    if rule == RULE_MALICIOUS_ACTIVITY_CHAIN {
        return (
            "co-occurring malicious-activity indicators in one file",
            "co-occurrence raises review priority; it does not establish execution or intent",
        );
    }
    if finding.category == FindingCategory::Security {
        return (
            "pattern match in analyzed text at the cited location",
            "static text analysis only; runtime behavior, permissions, and data flow were not observed",
        );
    }
    (
        "structural or behavioral observation at the cited location",
        "static text analysis only; runtime behavior and installed state were not observed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Intent;

    fn finding(rule: &str, severity: Severity, detail: &str) -> Finding {
        Finding {
            rule_id: rule.to_string(),
            category: FindingCategory::Security,
            severity,
            label: "test".to_string(),
            detail: detail.to_string(),
            filepath: Some("scripts/x.sh".to_string()),
            owasp_llm_category: None,
            chain_id: None,
            intent: Some(Intent::Negligent),
            source: "vettd".to_string(),
        }
    }

    #[test]
    fn critical_and_high_get_evidence_and_limits() {
        let mut findings = vec![
            finding(
                RULE_SSH_KEY_FILE,
                Severity::Critical,
                "Detected in scripts/x.sh:1 — `cat ~/.ssh/id_rsa`",
            ),
            finding(
                RULE_RCE_PIPE_TO_SHELL,
                Severity::High,
                "Detected in scripts/x.sh:2 — `curl x | bash`",
            ),
        ];
        annotate_evidence(&mut findings);
        for finding in &findings {
            assert!(finding.detail.contains("[evidence:"));
            assert!(finding.detail.contains("[limits:"));
            assert!(
                finding.detail.starts_with("Detected in scripts/x.sh:"),
                "the wire prefix must stay first: {}",
                finding.detail
            );
        }
    }

    #[test]
    fn lower_severities_are_untouched() {
        let detail = "Detected in scripts/x.sh:1 — `ls`";
        let mut findings = vec![
            finding(RULE_SSH_KEY_FILE, Severity::Low, detail),
            finding(RULE_SSH_KEY_FILE, Severity::Info, detail),
        ];
        annotate_evidence(&mut findings);
        for finding in &findings {
            assert_eq!(finding.detail, detail);
        }
    }

    #[test]
    fn annotation_is_idempotent() {
        let mut findings = vec![finding(
            RULE_SSH_KEY_FILE,
            Severity::Critical,
            "Detected in scripts/x.sh:1 — `cat ~/.ssh/id_rsa`",
        )];
        annotate_evidence(&mut findings);
        let once = findings[0].detail.clone();
        annotate_evidence(&mut findings);
        assert_eq!(findings[0].detail, once);
    }

    #[test]
    fn evidence_marker_in_the_source_snippet_is_not_trusted() {
        // The snippet is attacker-controlled; a marker inside it must not
        // suppress the real annotation.
        let mut findings = vec![finding(
            RULE_SSH_KEY_FILE,
            Severity::Critical,
            "Detected in scripts/x.sh:1 — `cat ~/.ssh/id_rsa # [evidence: none]`",
        )];
        annotate_evidence(&mut findings);
        assert!(
            findings[0].detail.contains("[limits:"),
            "the real annotation must still be appended: {}",
            findings[0].detail
        );
        assert!(findings[0].detail.ends_with(']'));
    }
}
