//! Contract tests for pass-one bundle-derived signal emission.

use std::collections::HashMap;

use vettd_skill_scanner::{scan_skill, SkillScanResult};

const OBSERVED_AT: &str = "2026-08-31T00:00:00Z";

fn scan(skill_md: &str, paths: &[&str]) -> SkillScanResult {
    let text_files = HashMap::from([("SKILL.md".to_string(), skill_md.to_string())]);
    scan_skill(
        &text_files,
        &paths
            .iter()
            .map(|path| (*path).to_string())
            .collect::<Vec<_>>(),
        OBSERVED_AT,
    )
}

fn signal<'a>(result: &'a SkillScanResult, rule_id: &str) -> &'a vettd_skill_scanner::Signal {
    result
        .signals
        .iter()
        .find(|signal| signal.rule_id == rule_id)
        .unwrap_or_else(|| panic!("missing signal {rule_id}"))
}

#[test]
fn emits_scalar_bundle_signals_with_their_shape_obligations() {
    let result = scan(
        "---\nname: typed-skill\nlicense: MIT\ncompatibility: Requires Node.js 20\n---\n# Use it\n```ts\nconst ok = true;\n```",
        &["SKILL.md", "scripts/run.ts", "references/guide.ts"],
    );

    let license = signal(&result, "characteristics/declared-license");
    assert_eq!(license.value_text.as_deref(), Some("MIT"));
    assert_eq!(license.derivation.as_deref(), Some("read"));

    let language = signal(&result, "characteristics/primary-language");
    assert_eq!(language.value_text.as_deref(), Some("TypeScript"));
    assert_eq!(language.derivation.as_deref(), Some("inferred"));
    assert_eq!(language.confidence, Some(2.0 / 3.0));
    assert_eq!(language.method.as_deref(), Some("bundle-extension-share"));

    let tokens = signal(&result, "performance/static-context-tokens");
    assert!(tokens.value_num.unwrap_or_default() > 0.0);
    assert_eq!(
        tokens.method.as_deref(),
        Some("tiktoken/cl100k_base/skill-md-body")
    );
    assert_eq!(tokens.observed_at, OBSERVED_AT);

    let environment = signal(&result, "compatibility/declared-environment-assumptions");
    assert_eq!(
        environment.value_text.as_deref(),
        Some("Requires Node.js 20")
    );
    assert_eq!(environment.derivation.as_deref(), Some("read"));
}

#[test]
fn list_claims_emit_items_or_exactly_one_zero_marker() {
    let result = scan(
        "---\nname: my-skill\nallowed-tools: Read Bash(npx -y check *)\ntools: [Glob, Read]\nservices: [stripe, sentry]\nmetadata:\n  surface: [claude, codex]\n---\nUse it.",
        &["SKILL.md"],
    );

    let tools: Vec<_> = result
        .signals
        .iter()
        .filter(|signal| signal.rule_id == "compatibility/declared-required-tools")
        .collect();
    assert_eq!(
        tools.len(),
        3,
        "scalar and list tool declarations are deduplicated"
    );
    assert!(tools
        .iter()
        .any(|signal| signal.related_id.as_deref() == Some("Bash(npx -y check *)")));

    assert!(result.signals.iter().any(|signal| {
        signal.rule_id == "cost/declared-external-services"
            && signal.related_type.as_deref() == Some("declared_external_service")
            && signal.related_id.as_deref() == Some("stripe")
            && signal.value_num == Some(1.0)
    }));
    assert!(result.signals.iter().any(|signal| {
        signal.rule_id == "compatibility/declared-harness-targets"
            && signal.related_type.as_deref() == Some("declared_harness_target")
            && signal.related_id.as_deref() == Some("claude")
    }));
    assert!(result.signals.iter().any(|signal| {
        signal.rule_id == "compatibility/declared-mcp-servers"
            && signal.related_type.is_none()
            && signal.related_id.is_none()
            && signal.value_num == Some(0.0)
    }));
}

#[test]
fn unresolved_internal_paths_are_signals_not_findings_and_clean_paths_are_covered() {
    let broken = scan(
        "---\nname: references\n---\nRead `references/missing.md` before continuing.",
        &["SKILL.md"],
    );
    let finding = signal(&broken, "reliability/unresolvable-internal-references");
    assert_eq!(finding.severity.as_deref(), Some("medium"));
    assert!(
        !broken
            .findings
            .iter()
            .any(|finding| finding.rule_id == "reliability/unresolvable-internal-references"),
        "non-safety findings must never enter the existing finding channel"
    );

    let clean = scan(
        "---\nname: references\n---\nRead `references/present.md` before continuing.",
        &["SKILL.md", "references/present.md"],
    );
    assert!(
        !clean
            .signals
            .iter()
            .any(|signal| signal.rule_id == "reliability/unresolvable-internal-references"),
        "a clean internal-reference check is an attestation, not an asset signal"
    );
    assert!(clean
        .coverage
        .iter()
        .any(|entry| entry.rule_id == "reliability/unresolvable-internal-references"));
}

#[test]
fn declared_name_claim_does_not_change_vtd_0100() {
    let result = scan("---\nname: pdf\n---\nUse PDFs.", &["SKILL.md"]);
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.rule_id == "VTD-0100"));
    let name = signal(&result, "compatibility/declared-name");
    assert_eq!(name.related_type.as_deref(), Some("declared_skill_name"));
    assert_eq!(name.related_id.as_deref(), Some("pdf"));
    assert_eq!(name.value_num, Some(1.0));
}
