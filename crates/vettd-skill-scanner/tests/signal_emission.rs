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
fn service_keys_stay_services_and_env_var_names_are_a_separate_rule() {
    let result = scan(
        "---\nname: svc\nservices:\n  stripe: true\n  sentry: false\nrequired_environment_variables:\n  - name: USDA_API_KEY\n    prompt: USDA key\n  - name: SHOPIFY_ACCESS_TOKEN\n    required_for: checkout\n---\nUse it.",
        &["SKILL.md"],
    );
    let services: Vec<_> = result
        .signals
        .iter()
        .filter(|signal| signal.rule_id == "cost/declared-external-services")
        .collect();
    assert_eq!(
        services.len(),
        2,
        "map-shaped service keys are the only external-service items"
    );
    let service_ids: Vec<_> = services
        .iter()
        .map(|signal| signal.related_id.as_deref().unwrap_or_default())
        .collect();
    for expected in ["stripe", "sentry"] {
        assert!(
            service_ids.contains(&expected),
            "missing declared service {expected}"
        );
    }
    assert!(services.iter().all(|signal| {
        signal.related_type.as_deref() == Some("declared_external_service")
            && signal.method.as_deref() == Some("frontmatter-declared-services")
            && signal.value_num == Some(1.0)
    }));

    let env_vars: Vec<_> = result
        .signals
        .iter()
        .filter(|signal| signal.rule_id == "cost/declared-required-env-vars")
        .collect();
    assert_eq!(
        env_vars.len(),
        2,
        "required_environment_variables names land on their own rule"
    );
    let env_ids: Vec<_> = env_vars
        .iter()
        .map(|signal| signal.related_id.as_deref().unwrap_or_default())
        .collect();
    for expected in ["USDA_API_KEY", "SHOPIFY_ACCESS_TOKEN"] {
        assert!(
            env_ids.contains(&expected),
            "missing declared required env var {expected}"
        );
    }
    assert!(env_vars.iter().all(|signal| {
        signal.related_type.as_deref() == Some("declared_required_env_var")
            && signal.method.as_deref() == Some("frontmatter-required-env-vars")
            && signal.value_num == Some(1.0)
    }));
}

#[test]
fn runtime_env_vars_are_required_env_vars_not_external_services() {
    // DEBUG and OUTPUT_DIR are environment knobs the skill reads, not external
    // services the cost model bills against — they must never surface under
    // cost/declared-external-services.
    let result = scan(
        "---\nname: svc\nservices: [stripe]\nrequired_environment_variables:\n  - name: DEBUG\n  - name: OUTPUT_DIR\n---\nUse it.",
        &["SKILL.md"],
    );
    let service_ids: Vec<_> = result
        .signals
        .iter()
        .filter(|signal| signal.rule_id == "cost/declared-external-services")
        .map(|signal| signal.related_id.as_deref().unwrap_or_default())
        .collect();
    assert_eq!(service_ids, vec!["stripe"]);
    assert!(
        !service_ids.iter().any(|id| *id == "DEBUG"),
        "DEBUG is an env var, not an external service"
    );
    assert!(
        !service_ids.iter().any(|id| *id == "OUTPUT_DIR"),
        "OUTPUT_DIR is an env var, not an external service"
    );

    let env_var_ids: Vec<_> = result
        .signals
        .iter()
        .filter(|signal| signal.rule_id == "cost/declared-required-env-vars")
        .map(|signal| signal.related_id.as_deref().unwrap_or_default())
        .collect();
    for expected in ["DEBUG", "OUTPUT_DIR"] {
        assert!(
            env_var_ids.contains(&expected),
            "missing declared required env var {expected}"
        );
    }
}

#[test]
fn explicitly_declared_name_is_a_scalar_fact() {
    let result = scan("---\nname: unknown\n---\nBody.", &["SKILL.md"]);
    let rows: Vec<_> = result
        .signals
        .iter()
        .filter(|signal| signal.rule_id == "compatibility/declared-name")
        .collect();
    assert_eq!(rows.len(), 1, "an explicit name is one scalar fact");
    assert_eq!(rows[0].value_text.as_deref(), Some("unknown"));
    assert_eq!(rows[0].derivation.as_deref(), Some("read"));
    assert_eq!(rows[0].value_num, None, "a fact is not a measurement");
    assert_eq!(
        rows[0].related_type, None,
        "a fact has no related identity (not a list item)"
    );
    assert_eq!(
        rows[0].related_id, None,
        "a fact has no related identity (not a list item)"
    );

    // A fact is scalar — absence of the key is simply no row, never a zero
    // marker.
    let absent = scan("---\ndescription: no name\n---\nBody.", &["SKILL.md"]);
    let absent_rows: Vec<_> = absent
        .signals
        .iter()
        .filter(|signal| signal.rule_id == "compatibility/declared-name")
        .collect();
    assert!(absent_rows.is_empty(), "no declared name means no fact row");
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
fn declared_name_fact_does_not_change_vtd_0100() {
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
    assert_eq!(name.value_text.as_deref(), Some("pdf"));
    assert_eq!(name.derivation.as_deref(), Some("read"));
    assert_eq!(name.value_num, None, "a fact is not a measurement");
    assert_eq!(
        name.related_type, None,
        "a fact has no related identity (not a list item)"
    );
    assert_eq!(
        name.related_id, None,
        "a fact has no related identity (not a list item)"
    );
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

#[test]
fn path_only_skill_md_emits_no_frontmatter_derived_signals() {
    // When SKILL.md is only visible through all_paths there is no content and
    // no frontmatter. License/environment facts, declared claims, their zero
    // markers, and the body token measurement would falsely claim declarations
    // were inspected; only the path-derived primary-language signal may remain.
    let text_files = HashMap::new();
    let paths = ["SKILL.md".to_string(), "src/tool.ts".to_string()];
    let result = scan_skill(&text_files, &paths, OBSERVED_AT).expect("valid RFC3339 timestamp");

    for rule_id in [
        "characteristics/declared-license",
        "performance/static-context-tokens",
        "compatibility/declared-environment-assumptions",
        "cost/declared-external-services",
        "cost/declared-required-env-vars",
        "compatibility/declared-required-tools",
        "compatibility/declared-mcp-servers",
        "compatibility/declared-harness-targets",
        "compatibility/declared-name",
    ] {
        assert!(
            !result
                .signals
                .iter()
                .any(|signal| signal.rule_id == rule_id),
            "path-only SKILL.md must not emit {rule_id}"
        );
    }
    assert!(
        !result
            .signals
            .iter()
            .any(|signal| signal.value_num == Some(0.0)),
        "no zero markers when there is no content to inspect"
    );
    assert!(
        result
            .signals
            .iter()
            .any(|signal| { signal.rule_id == "characteristics/primary-language" }),
        "path-derived primary-language is preserved"
    );
}

#[test]
fn nested_internal_paths_resolve_against_the_complete_bundle_path() {
    // `src/references/tips.md` in the body must resolve against the complete
    // nested all_paths entry. Truncating it to `references/tips.md` would
    // falsely report the present file missing as a medium-reliability signal.
    let result = scan(
        "---\nname: nested\n---\nSee src/references/tips.md for notes.",
        &["SKILL.md", "src/references/tips.md"],
    );
    assert!(
        !result
            .signals
            .iter()
            .any(|signal| signal.rule_id == "reliability/unresolvable-internal-references"),
        "a nested path present in the bundle is not an unresolvable reference"
    );
    assert!(
        result
            .coverage
            .iter()
            .any(|entry| entry.rule_id == "reliability/unresolvable-internal-references"),
        "clean nested references are attested on the coverage channel"
    );
}
