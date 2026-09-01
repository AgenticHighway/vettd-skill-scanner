//! Contract tests for pass-one bundle-derived signal emission.

use std::collections::HashMap;

use vettd_skill_scanner::{scan_skill, Severity, SkillScanResult};

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
    .expect("valid RFC3339 timestamp")
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
fn external_services_read_env_vars_and_map_shaped_declarations() {
    let result = scan(
        "---\nname: svc\nservices:\n  stripe: true\n  sentry: false\nrequired_environment_variables:\n  - name: USDA_API_KEY\n    prompt: USDA key\n  - name: SHOPIFY_ACCESS_TOKEN\n    required_for: checkout\n---\nUse it.",
        &["SKILL.md"],
    );
    let rows: Vec<_> = result
        .signals
        .iter()
        .filter(|signal| signal.rule_id == "cost/declared-external-services")
        .collect();
    assert_eq!(rows.len(), 4, "map keys and env var names are all items");
    let ids: Vec<_> = rows
        .iter()
        .map(|signal| signal.related_id.as_deref().unwrap_or_default())
        .collect();
    for expected in ["stripe", "sentry", "USDA_API_KEY", "SHOPIFY_ACCESS_TOKEN"] {
        assert!(
            ids.contains(&expected),
            "missing declared service {expected}"
        );
    }
    assert!(rows.iter().all(|signal| {
        signal.related_type.as_deref() == Some("declared_external_service")
            && signal.value_num == Some(1.0)
    }));
}

#[test]
fn explicitly_declared_unknown_name_is_an_item_not_a_marker() {
    let result = scan("---\nname: unknown\n---\nBody.", &["SKILL.md"]);
    let rows: Vec<_> = result
        .signals
        .iter()
        .filter(|signal| signal.rule_id == "compatibility/declared-name")
        .collect();
    assert_eq!(rows.len(), 1, "an explicit name is one claim row");
    assert_eq!(rows[0].related_id.as_deref(), Some("unknown"));
    assert_eq!(rows[0].value_num, Some(1.0));

    // Absence of the key yields the zero marker instead.
    let absent = scan("---\ndescription: no name\n---\nBody.", &["SKILL.md"]);
    let absent_rows: Vec<_> = absent
        .signals
        .iter()
        .filter(|signal| signal.rule_id == "compatibility/declared-name")
        .collect();
    assert_eq!(absent_rows.len(), 1);
    assert_eq!(absent_rows[0].value_num, Some(0.0));
    assert!(absent_rows[0].related_id.is_none());
}

#[test]
fn sentence_period_after_reference_does_not_false_flag() {
    let result = scan(
        "---\nname: refs\n---\nSee references/guide.md. And scripts/run.sh, plus assets/logo.png!",
        &[
            "SKILL.md",
            "references/guide.md",
            "scripts/run.sh",
            "assets/logo.png",
        ],
    );
    assert!(
        !result
            .signals
            .iter()
            .any(|signal| signal.rule_id == "reliability/unresolvable-internal-references"),
        "trailing sentence punctuation must not create a false finding"
    );
    assert!(result
        .coverage
        .iter()
        .any(|entry| entry.rule_id == "reliability/unresolvable-internal-references"));
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
    let collisions: Vec<_> = result
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "VTD-0100")
        .collect();
    assert_eq!(collisions.len(), 1, "exactly one VTD-0100 finding");
    let collision = collisions[0];
    assert_eq!(collision.category.as_str(), "best-practices");
    assert_eq!(collision.severity.as_str(), "medium");
    assert_eq!(collision.label, "Skill name collides with well-known skill");
    assert_eq!(
        collision.detail,
        "\"pdf\" matches a well-known skill name — may cause unintended invocation"
    );
    assert_eq!(collision.source, "vettd");
    assert!(collision.filepath.is_none());

    let name = signal(&result, "compatibility/declared-name");
    assert_eq!(name.related_type.as_deref(), Some("declared_skill_name"));
    assert_eq!(name.related_id.as_deref(), Some("pdf"));
    assert_eq!(name.value_num, Some(1.0));
}

#[test]
fn every_emitted_signal_satisfies_shape_obligations() {
    let result = scan(
        "---\nname: my-skill\nlicense: MIT\ncompatibility: Needs Node 20\nallowed-tools: Read Bash\nservices: [stripe]\nmetadata:\n  surface: [claude]\n---\nRead `references/guide.md`.",
        &["SKILL.md", "scripts/run.ts", "references/guide.md"],
    );
    assert!(!result.signals.is_empty());
    for signal in &result.signals {
        // Wire-required fields present on every row.
        assert!(!signal.data_category.is_empty(), "{signal:?}");
        assert_eq!(signal.source_class, "scan", "{signal:?}");
        assert!(!signal.rule_id.is_empty(), "{signal:?}");
        assert_eq!(signal.observed_at, OBSERVED_AT, "{signal:?}");
        assert!(
            signal
                .rule_id
                .starts_with(&format!("{}/", signal.data_category)),
            "{signal:?}"
        );
        // `unit` is never set anywhere in pass one.
        assert!(signal.unit.is_none(), "unit must be null: {signal:?}");

        // Fact/Classification rows carry valueText; Measurement rows must not.
        match signal.derivation.as_deref() {
            Some("read") => {
                assert!(
                    signal.value_text.is_some(),
                    "fact needs value_text: {signal:?}"
                );
                assert!(
                    signal.value_num.is_none(),
                    "fact must not set value_num: {signal:?}"
                );
                assert!(
                    signal.method.is_none(),
                    "fact must not set method: {signal:?}"
                );
            }
            Some("inferred") => {
                assert!(
                    signal.value_text.is_some(),
                    "classification needs value_text: {signal:?}"
                );
                assert!(
                    signal.confidence.is_some(),
                    "classification needs confidence: {signal:?}"
                );
                assert!(
                    signal.value_num.is_none(),
                    "classification must not set value_num: {signal:?}"
                );
            }
            _ => {}
        }
        // Any row carrying a value_num is a measurement/claim and needs a method.
        if signal.value_num.is_some() {
            assert!(
                signal.method.is_some(),
                "measurement needs method: {signal:?}"
            );
            assert!(
                signal.derivation.is_none(),
                "measurement must not set derivation: {signal:?}"
            );
            assert!(
                signal.confidence.is_none(),
                "measurement must not set confidence: {signal:?}"
            );
            assert!(
                signal.value_text.is_none(),
                "measurement must not set value_text: {signal:?}"
            );
        }
        // The finding-shaped rule is scalar and severity-bearing.
        if signal.severity.is_some() {
            assert!(
                signal.value_num.is_none(),
                "finding must be scalar: {signal:?}"
            );
            assert!(
                signal.related_type.is_none(),
                "finding must be scalar: {signal:?}"
            );
        }
        // List semantics: markers carry the empty identity, items carry a
        // non-empty related identity with value_num 1.
        if signal.value_num == Some(0.0) {
            assert!(
                signal.related_type.is_none() && signal.related_id.is_none(),
                "marker has empty identity: {signal:?}"
            );
        } else if signal.related_type.is_some() {
            assert_eq!(
                signal.value_num,
                Some(1.0),
                "item row is a single claim: {signal:?}"
            );
            assert!(
                signal.related_id.as_deref().map(str::is_empty) == Some(false),
                "item row needs non-empty related_id: {signal:?}"
            );
        }
    }

    // A marker serializes with its related identity omitted, so vettd's
    // normalizeIdentityParticipant lands it on "" — the contract's empty id.
    let marker = result
        .signals
        .iter()
        .find(|signal| signal.rule_id == "compatibility/declared-mcp-servers")
        .expect("mcp-servers marker row");
    assert_eq!(marker.value_num, Some(0.0));
    let json = serde_json::to_value(marker).expect("signal serializes");
    assert!(
        json.get("relatedType").is_none(),
        "marker omits relatedType: {json}"
    );
    assert!(
        json.get("relatedId").is_none(),
        "marker omits relatedId: {json}"
    );
}

#[test]
fn scan_skill_rejects_invalid_observed_at() {
    let text_files = HashMap::from([(
        "SKILL.md".to_string(),
        "---\nname: x\n---\nbody".to_string(),
    )]);
    let paths = ["SKILL.md".to_string()];
    assert!(scan_skill(&text_files, &paths, "").is_err());
    assert!(scan_skill(&text_files, &paths, "not-a-timestamp").is_err());
    assert!(scan_skill(&text_files, &paths, "2026-08-31T00:00:00Z").is_ok());
}

#[test]
fn external_urls_and_prefix_substrings_are_not_internal_references() {
    // A SKILL.md body that cites external URLs and longer identifiers whose
    // tokens merely contain `references/`/`scripts/`/`assets/` must not trip
    // the unresolved-internal-reference signal.
    let result = scan(
        "---\nname: links\n---\nFetch https://example.com/references/guide.md, \
         see myassets/logo.png, and run shellscripts/run.sh.",
        &["SKILL.md"],
    );
    assert!(
        !result
            .signals
            .iter()
            .any(|signal| signal.rule_id == "reliability/unresolvable-internal-references"),
        "external URLs and prefix substrings must not be flagged as internal references"
    );
    assert!(result
        .coverage
        .iter()
        .all(|entry| { entry.rule_id != "reliability/unresolvable-internal-references" }));
}

#[test]
fn path_only_skill_md_does_not_attest_name_validation() {
    // When SKILL.md is only visible through all_paths there is no content and
    // no declared name to validate — the name-validation coverage attestation
    // must not be emitted, even though the VTD-0099 info finding still fires
    // on the fallback sentinel name.
    let text_files = HashMap::new();
    let paths = ["SKILL.md".to_string()];
    let result = scan_skill(&text_files, &paths, OBSERVED_AT).expect("valid RFC3339 timestamp");

    assert!(result.has_skill_md, "path-only SKILL.md sets the flag");
    assert!(result
        .findings
        .iter()
        .any(|finding| finding.rule_id == "VTD-0099" && finding.severity == Severity::Info));
    assert!(
        !result
            .coverage
            .iter()
            .any(|entry| entry.rule_id == "VTD-0099"),
        "name validation was not attested without content or a declared name"
    );
}
