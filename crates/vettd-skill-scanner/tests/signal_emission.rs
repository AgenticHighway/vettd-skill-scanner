//! Contract tests for pass-one bundle-derived signal emission.

use std::collections::HashMap;

use vettd_skill_scanner::{scan_skill, scan_skill_with_repo_context, RepoContext, SkillScanResult};

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

fn scan_with_repo(
    skill_md: &str,
    paths: &[&str],
    bundle_path: &str,
    repo_paths: &[&str],
) -> SkillScanResult {
    let text_files = HashMap::from([("SKILL.md".to_string(), skill_md.to_string())]);
    let all_paths: Vec<String> = paths.iter().map(|path| (*path).to_string()).collect();
    let repo_paths: Vec<String> = repo_paths.iter().map(|path| (*path).to_string()).collect();
    scan_skill_with_repo_context(
        &text_files,
        &all_paths,
        &RepoContext {
            bundle_path,
            repo_paths: &repo_paths,
        },
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
            && signal.value_text.as_deref() == Some("stripe")
            && signal.derivation.as_deref() == Some("read")
            && signal.value_num.is_none()
            && signal.method.is_none()
    }));
    assert!(result.signals.iter().any(|signal| {
        signal.rule_id == "compatibility/declared-harness-targets"
            && signal.related_type.as_deref() == Some("declared_harness_target")
            && signal.related_id.as_deref() == Some("claude")
            && signal.value_text.as_deref() == Some("claude")
            && signal.derivation.as_deref() == Some("read")
    }));
    assert!(result.signals.iter().any(|signal| {
        signal.rule_id == "compatibility/declared-mcp-servers"
            && signal.related_type.is_none()
            && signal.related_id.is_none()
            && signal.derivation.as_deref() == Some("read")
            && signal.value_text.is_none()
            && signal.value_num.is_none()
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
            && signal.value_text.as_deref() == signal.related_id.as_deref()
            && signal.derivation.as_deref() == Some("read")
            && signal.value_num.is_none()
            && signal.method.is_none()
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
            && signal.value_text.as_deref() == signal.related_id.as_deref()
            && signal.derivation.as_deref() == Some("read")
            && signal.value_num.is_none()
            && signal.method.is_none()
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
                // A fact-list marker (empty identity with no value columns)
                // is a valid read row, not a malformed fact — scalar facts
                // carry value_text, markers deliberately do not.
                let is_marker = signal.related_type.is_none()
                    && signal.related_id.is_none()
                    && signal.value_text.is_none()
                    && signal.value_num.is_none()
                    && signal.method.is_none();
                if !is_marker {
                    assert!(
                        signal.value_text.is_some(),
                        "fact needs value_text: {signal:?}"
                    );
                }
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
        // Fact-list semantics: markers carry the empty identity with derivation
        // "read" and no value columns; items carry a non-empty related
        // identity with a value_text fact value and derivation "read".
        if signal.related_type.is_some() {
            assert_eq!(
                signal.derivation.as_deref(),
                Some("read"),
                "item row is a read fact: {signal:?}"
            );
            assert!(
                signal.value_text.is_some(),
                "item row needs value_text: {signal:?}"
            );
            assert!(
                signal.related_id.as_deref().map(str::is_empty) == Some(false),
                "item row needs non-empty related_id: {signal:?}"
            );
        }
    }

    // A marker serializes with its related identity and value columns
    // omitted, so vettd's normalizeIdentityParticipant lands it on "" — the
    // contract's empty id — and the fact value stays empty.
    let marker = result
        .signals
        .iter()
        .find(|signal| signal.rule_id == "compatibility/declared-mcp-servers")
        .expect("mcp-servers marker row");
    assert_eq!(marker.derivation.as_deref(), Some("read"));
    assert!(
        marker.value_text.is_none(),
        "marker has no fact value: {marker:?}"
    );
    assert!(
        marker.value_num.is_none(),
        "marker must not be a measurement: {marker:?}"
    );
    let json = serde_json::to_value(marker).expect("signal serializes");
    assert!(
        json.get("relatedType").is_none(),
        "marker omits relatedType: {json}"
    );
    assert!(
        json.get("relatedId").is_none(),
        "marker omits relatedId: {json}"
    );
    assert!(
        json.get("valueNum").is_none(),
        "marker omits valueNum: {json}"
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
    // must not be emitted.
    let text_files = HashMap::new();
    let paths = ["SKILL.md".to_string()];
    let result = scan_skill(&text_files, &paths, OBSERVED_AT).expect("valid RFC3339 timestamp");

    assert!(result.has_skill_md, "path-only SKILL.md sets the flag");
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
    // no frontmatter. License/environment facts, declared claims, their
    // fact-list markers, and the body token measurement would falsely claim
    // declarations were inspected; only the path-derived primary-language
    // signal may remain.
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
        // Reclassified quality/characteristics/compatibility signals — a
        // path-only SKILL.md has no content to analyze, so none may fire.
        "characteristics/repository-link",
        "characteristics/eval-file-format",
        "reliability/description-presence",
        "reliability/description-usage-context",
        "reliability/gotchas-section",
        "reliability/generic-instruction",
        "performance/progressive-disclosure",
        "compatibility/cli-help",
        "compatibility/interactive-prompts",
        "compatibility/structured-output",
        "compatibility/unpinned-dependencies",
        "reliability/eval-test-case-count",
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
        !result.signals.iter().any(|signal| {
            signal.derivation.as_deref() == Some("read")
                && signal.related_type.is_none()
                && signal.related_id.is_none()
                && signal.value_text.is_none()
                && signal.value_num.is_none()
        }),
        "no fact-list markers when there is no content to inspect"
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

#[test]
fn internal_paths_resolve_despite_a_redundant_repo_relative_prefix() {
    // Authors often write a reference as it appears browsing the whole repository
    // (`skills/pdf-tool/references/guide.md`) rather than bundle-root-relative
    // (`references/guide.md`, what `all_paths` uses post-fetch — the fetcher already
    // stripped the skill's own directory). The extra leading segment isn't itself part
    // of the bundle, so a present file must not be reported missing just because the
    // body's copy of the path is longer than the bundle-relative form.
    let result = scan(
        "---\nname: pdf-tool\n---\nSee skills/pdf-tool/references/guide.md for notes.",
        &["SKILL.md", "references/guide.md"],
    );
    assert!(
        !result
            .signals
            .iter()
            .any(|signal| signal.rule_id == "reliability/unresolvable-internal-references"),
        "a redundant repo-relative prefix must not make a present file look missing"
    );
    assert!(
        result
            .coverage
            .iter()
            .any(|entry| entry.rule_id == "reliability/unresolvable-internal-references"),
        "clean redundant-prefix references are attested on the coverage channel"
    );
}

#[test]
fn genuinely_missing_paths_are_still_reported_despite_the_suffix_match() {
    // The suffix-match relief above must not swallow a real miss: a referenced path with
    // no matching bundle entry at all — by exact match or by suffix — is still reported.
    let result = scan(
        "---\nname: pdf-tool\n---\nSee skills/pdf-tool/references/guide.md for notes.",
        &["SKILL.md"],
    );
    let finding = signal(&result, "reliability/unresolvable-internal-references");
    assert_eq!(
        finding.detail.as_deref(),
        Some("Unresolvable internal path(s): skills/pdf-tool/references/guide.md")
    );
}

#[test]
fn an_unrelated_files_matching_basename_does_not_suppress_a_real_miss() {
    // references/guide.md is genuinely missing. The bundle happens to contain an unrelated
    // top-level file that just shares the basename "guide.md" — this must NOT count as a match.
    let result = scan(
        "---\nname: pdf-tool\n---\nSee references/guide.md for notes.",
        &["SKILL.md", "guide.md"],
    );
    assert!(
        result
            .signals
            .iter()
            .any(|signal| signal.rule_id == "reliability/unresolvable-internal-references"),
        "an unrelated file sharing a basename must not suppress a genuinely missing reference"
    );
}

#[test]
fn dot_dot_references_resolve_against_a_shared_repo_root_folder() {
    // A repo-root `references/` folder several skills draw from, reached from
    // `skills/ai-research-explore/` via `../../references/...` — the real shape found in
    // lllllllama/rigorpilot-skills. Bundle-only resolution can never see this file: the fetcher
    // scopes `all_paths` to the skill's own subtree, so it's absent there by construction.
    let result = scan_with_repo(
        "---\nname: ai-research-explore\n---\nLoad `../../references/agent-operating-principles.md` first.",
        &["SKILL.md"],
        "skills/ai-research-explore",
        &[
            "SKILL.md",
            "references/agent-operating-principles.md",
            "skills/ai-research-explore/SKILL.md",
        ],
    );
    assert!(
        !result
            .signals
            .iter()
            .any(|signal| signal.rule_id == "reliability/unresolvable-internal-references"),
        "a `..`-relative reference to a real repo-root file must resolve, not be flagged missing"
    );
}

#[test]
fn bare_paths_resolve_against_the_repo_root_when_absent_from_the_bundle() {
    // A reference written as if relative to the repository root, with no `../` decoration at all
    // — the real shape of `shared/scripts/lessons_store.py` in rigorpilot-skills'
    // ai-research-reproduction skill. Indistinguishable in spelling from a bundle-relative
    // reference, so it's checked against the repo root only after bundle resolution fails.
    let result = scan_with_repo(
        "---\nname: ai-research-reproduction\n---\nRecorded via `shared/scripts/lessons_store.py`.",
        &["SKILL.md"],
        "skills/ai-research-reproduction",
        &["SKILL.md", "shared/scripts/lessons_store.py"],
    );
    assert!(
        !result
            .signals
            .iter()
            .any(|signal| signal.rule_id == "reliability/unresolvable-internal-references"),
        "a bare reference matching a real repo-root path must resolve, not be flagged missing"
    );
}

#[test]
fn repo_context_still_reports_a_reference_missing_from_bundle_and_repo_alike() {
    let result = scan_with_repo(
        "---\nname: ai-research-explore\n---\nLoad `../../references/does-not-exist.md` first.",
        &["SKILL.md"],
        "skills/ai-research-explore",
        &[
            "SKILL.md",
            "references/agent-operating-principles.md",
            "skills/ai-research-explore/SKILL.md",
        ],
    );
    let finding = signal(&result, "reliability/unresolvable-internal-references");
    assert_eq!(
        finding.detail.as_deref(),
        Some("Unresolvable internal path(s): ../../references/does-not-exist.md")
    );
}

#[test]
fn dot_dot_navigating_above_the_repository_root_does_not_panic_or_falsely_resolve() {
    // More `..` segments than the bundle path has — an author error, not a valid reference to
    // anything. Must fail closed (reported missing), not panic on an out-of-bounds pop.
    let result = scan_with_repo(
        "---\nname: root-skill\n---\nLoad `../../references/x.md` first.",
        &["SKILL.md"],
        "skill", // one segment; two ".." exceeds it
        &["SKILL.md", "references/x.md"],
    );
    let finding = signal(&result, "reliability/unresolvable-internal-references");
    assert_eq!(
        finding.detail.as_deref(),
        Some("Unresolvable internal path(s): ../../references/x.md")
    );
}

#[test]
fn default_repo_context_behaves_exactly_like_scan_skill() {
    // RepoContext::default() (bare zip upload, vettd-cli scanning a local directory — no repo
    // concept) must be a true no-op: identical signals to plain scan_skill for the same input.
    let skill_md = "---\nname: pdf-tool\n---\nSee references/guide.md for notes.";
    let paths = &["SKILL.md"];
    let via_scan_skill = scan(skill_md, paths);
    let via_default_context = scan_with_repo(skill_md, paths, "", &[]);
    assert_eq!(
        via_scan_skill.signals.len(),
        via_default_context.signals.len()
    );
    assert!(via_default_context
        .signals
        .iter()
        .any(|signal| signal.rule_id == "reliability/unresolvable-internal-references"));
}

// ---------------------------------------------------------------------------
// Reclassified non-safety signals (VTD-0083, VTD-0102..0123 → signals)
// ---------------------------------------------------------------------------

#[test]
fn body_quality_facts_are_present_absent_states_with_no_grade_effect() {
    // Body rules are facts now, not pass/fail twin findings: one row whose
    // valueText is the state. A body with gotchas/examples/checklist/workflow/
    // validation shows "present" for those and "absent" for what it lacks; an
    // empty body emits none of them (there is no body to describe).
    let result = scan(
        "---\nname: quality\n---\n## Gotchas\nWatch out.\n\n## Examples\n```py\npass\n```\n\n## Checklist\n- [ ] do it\n\n1. First step\n\nRun the validator.\n",
        &["SKILL.md"],
    );
    for (rule_id, expected) in [
        ("reliability/gotchas-section", "present"),
        ("reliability/examples", "present"),
        ("reliability/checklist-pattern", "present"),
        ("reliability/validation-loop", "present"),
        ("reliability/step-by-step-workflow", "present"),
        ("performance/progressive-disclosure", "absent"),
    ] {
        let fact = signal(&result, rule_id);
        assert_eq!(fact.value_text.as_deref(), Some(expected), "{rule_id}");
        assert_eq!(fact.derivation.as_deref(), Some("read"), "{rule_id}");
        assert_eq!(fact.severity, None, "a fact carries no severity: {rule_id}");
        assert_eq!(
            fact.value_num, None,
            "a fact is not a measurement: {rule_id}"
        );
        assert_eq!(fact.method, None, "a fact has no method: {rule_id}");
    }

    let empty = scan("---\nname: empty\n---\n", &["SKILL.md"]);
    for rule_id in [
        "reliability/gotchas-section",
        "reliability/examples",
        "reliability/checklist-pattern",
        "reliability/validation-loop",
        "reliability/step-by-step-workflow",
        "reliability/progressive-disclosure",
    ] {
        assert!(
            !empty.signals.iter().any(|s| s.rule_id == rule_id),
            "an empty body has no body-derived facts: {rule_id}"
        );
    }
}

#[test]
fn description_findings_emit_only_failure_branches_with_preserved_severity() {
    // Missing description → reliability/description-presence (info).
    let missing = scan("---\nname: no-desc\n---\nBody.", &["SKILL.md"]);
    let presence = signal(&missing, "reliability/description-presence");
    assert_eq!(presence.severity.as_deref(), Some("info"));

    // >1024 chars → cost/description-length (info); the within-limit twin is
    // dropped entirely.
    let long = scan(
        &format!(
            "---\nname: long-desc\ndescription: {}\n---\nBody.",
            "a".repeat(1025)
        ),
        &["SKILL.md"],
    );
    let length = signal(&long, "cost/description-length");
    assert_eq!(length.severity.as_deref(), Some("info"));
    assert_eq!(
        length.detail.as_deref(),
        Some("Description is 1025 characters (max: 1024)")
    );

    // <5 words → reliability/description-briefness (info).
    let brief = scan(
        "---\nname: brief-desc\ndescription: Too short\n---\nBody.",
        &["SKILL.md"],
    );
    let brevity = signal(&brief, "reliability/description-briefness");
    assert_eq!(brevity.severity.as_deref(), Some("info"));

    // Broad trigger words → reliability/description-overclaim (low).
    let overclaim = scan(
        "---\nname: overclaim-desc\ndescription: Handles anything and everything.\n---\nBody.",
        &["SKILL.md"],
    );
    let scope = signal(&overclaim, "reliability/description-overclaim");
    assert_eq!(scope.severity.as_deref(), Some("low"));

    // A good description emits none of the failure branches, only the
    // usage-context fact.
    let good = scan(
        "---\nname: good-desc\ndescription: Use this skill when you need to format and validate JSON documents quickly.\n---\nBody.",
        &["SKILL.md"],
    );
    for rule_id in [
        "reliability/description-presence",
        "cost/description-length",
        "reliability/description-briefness",
        "reliability/description-overclaim",
    ] {
        assert!(
            !good.signals.iter().any(|s| s.rule_id == rule_id),
            "clean description must not emit the failure branch: {rule_id}"
        );
    }
    let context = signal(&good, "reliability/description-usage-context");
    assert_eq!(context.value_text.as_deref(), Some("present"));
    assert_eq!(context.derivation.as_deref(), Some("read"));
}

#[test]
fn generic_instruction_collapses_to_one_finding_with_count_in_detail() {
    // VTD-0108 fired once per matched phrase (0-4x); the signal must be a
    // single row whose detail states how many phrases matched.
    let result = scan(
        "---\nname: generic\n---\nFollow best practices and handle errors appropriately. Use proper tooling.",
        &["SKILL.md"],
    );
    let rows: Vec<_> = result
        .signals
        .iter()
        .filter(|s| s.rule_id == "reliability/generic-instruction")
        .collect();
    assert_eq!(rows.len(), 1, "generic-instruction must be a single row");
    assert_eq!(rows[0].severity.as_deref(), Some("info"));
    assert_eq!(
        rows[0].detail.as_deref(),
        Some("3 generic instruction phrase(s) detected")
    );

    let clean = scan(
        "---\nname: specific\n---\nRun `scripts/check.py --strict` then review the diff.\n",
        &["SKILL.md"],
    );
    assert!(
        !clean
            .signals
            .iter()
            .any(|s| s.rule_id == "reliability/generic-instruction"),
        "no generic phrases means no generic-instruction row"
    );
}

#[test]
fn progressive_disclosure_fact_is_present_when_body_references_bundled_dirs() {
    let result = scan(
        "---\nname: progressive\n---\nLoad `references/guide.md` and run `scripts/setup.sh` on demand.",
        &["SKILL.md", "references/guide.md", "scripts/setup.sh"],
    );
    let fact = signal(&result, "performance/progressive-disclosure");
    assert_eq!(fact.value_text.as_deref(), Some("present"));
    assert_eq!(fact.derivation.as_deref(), Some("read"));

    let refs_without_dirs = scan(
        "---\nname: nothing\n---\nLoad `references/guide.md` on demand.",
        &["SKILL.md"],
    );
    let absent = signal(&refs_without_dirs, "performance/progressive-disclosure");
    assert_eq!(
        absent.value_text.as_deref(),
        Some("absent"),
        "referencing a dir that does not exist is not progressive disclosure"
    );
}

#[test]
fn script_signals_aggregate_per_skill_and_skip_when_no_scripts_exist() {
    // One script has argparse + json.dumps; the other prompts and pins an
    // unbounded dependency. Aggregated per-skill: cli-help and structured
    // output are "present" (ANY script), interactive-prompts is a high
    // finding, unpinned-dependencies a low finding.
    let md = "---\nname: cli\n---\nRun the tool.\n";
    let text_files = HashMap::from([
        ("SKILL.md".to_string(), md.to_string()),
        (
            "scripts/a.py".to_string(),
            "import argparse\nparser = argparse.ArgumentParser()\nprint(json.dumps({}))\n"
                .to_string(),
        ),
        (
            "scripts/b.py".to_string(),
            "name = input('name: ')\nimport tool\nFoo >= 1.0\n".to_string(),
        ),
    ]);
    let all_paths = ["SKILL.md", "scripts/a.py", "scripts/b.py"]
        .iter()
        .map(|p| (*p).to_string())
        .collect::<Vec<_>>();
    let result = scan_skill(&text_files, &all_paths, OBSERVED_AT).expect("valid RFC3339 timestamp");

    let cli_help = signal(&result, "compatibility/cli-help");
    assert_eq!(cli_help.value_text.as_deref(), Some("present"));
    assert_eq!(cli_help.derivation.as_deref(), Some("read"));

    let structured = signal(&result, "compatibility/structured-output");
    assert_eq!(structured.value_text.as_deref(), Some("present"));

    let interactive = signal(&result, "compatibility/interactive-prompts");
    assert_eq!(interactive.severity.as_deref(), Some("high"));

    let unpinned = signal(&result, "compatibility/unpinned-dependencies");
    assert_eq!(unpinned.severity.as_deref(), Some("low"));

    // A scripts/ dir whose files are helpers (no CLI markers) describes
    // nothing: no CLI script was analyzed, so the four compatibility signals
    // are skipped, matching the old finding-block gate on `script_files`.
    let helper_files = HashMap::from([
        (
            "SKILL.md".to_string(),
            "---\nname: helper-only\n---\nUse lib.\n".to_string(),
        ),
        (
            "scripts/helpers/util.py".to_string(),
            "def helper(): pass\n".to_string(),
        ),
    ]);
    let helper_paths = ["SKILL.md", "scripts/helpers/util.py"]
        .iter()
        .map(|p| (*p).to_string())
        .collect::<Vec<_>>();
    let helpers =
        scan_skill(&helper_files, &helper_paths, OBSERVED_AT).expect("valid RFC3339 timestamp");
    for rule_id in [
        "compatibility/cli-help",
        "compatibility/interactive-prompts",
        "compatibility/structured-output",
        "compatibility/unpinned-dependencies",
    ] {
        assert!(
            !helpers.signals.iter().any(|s| s.rule_id == rule_id),
            "helper-only scripts/ must not emit script signals: {rule_id}"
        );
    }

    // No scripts/ at all → same skip.
    let no_scripts = scan(
        "---\nname: no-scripts\n---\nNothing to run.\n",
        &["SKILL.md"],
    );
    assert!(
        !no_scripts
            .signals
            .iter()
            .any(|s| s.rule_id == "compatibility/cli-help"),
        "no scripts means no cli-help fact"
    );
}

#[test]
fn eval_signals_carry_measurement_fact_and_sufficiency_finding() {
    // Two cases (below the minimum of 3): the measurement reports 2, the
    // assertions fact reports "present" (case 1 has `expected`), the
    // sufficiency finding fires (info), and the format fact reads "absent"
    // (the evals are JSON, nothing non-JSON).
    let evals_json = r#"{"evals":[{"input":"x","expected":"y"},{"input":"a"}]}"#;
    let text_files = HashMap::from([
        (
            "SKILL.md".to_string(),
            "---\nname: evals\n---\nRun eval.\n".to_string(),
        ),
        ("evals/evals.json".to_string(), evals_json.to_string()),
        ("evals/cases.yaml".to_string(), "case: 1\n".to_string()),
    ]);
    let all_paths = ["SKILL.md", "evals/evals.json", "evals/cases.yaml"]
        .iter()
        .map(|p| (*p).to_string())
        .collect::<Vec<_>>();
    let result = scan_skill(&text_files, &all_paths, OBSERVED_AT).expect("valid RFC3339 timestamp");

    let count = signal(&result, "reliability/eval-test-case-count");
    assert_eq!(count.value_num, Some(2.0));
    assert_eq!(count.method.as_deref(), Some("bundle-evals-case-count"));
    assert_eq!(count.derivation, None, "a measurement has no derivation");
    assert_eq!(count.severity, None, "a measurement is not a finding");

    let assertions = signal(&result, "reliability/eval-assertions");
    assert_eq!(assertions.value_text.as_deref(), Some("present"));
    assert_eq!(assertions.derivation.as_deref(), Some("read"));

    let sufficient = signal(&result, "reliability/eval-test-cases-sufficient");
    assert_eq!(sufficient.severity.as_deref(), Some("info"));

    // eval-file-format is "absent": a JSON eval file exists, and the extra
    // YAML record under evals/ was never reached (JSON wins).
    let format = signal(&result, "characteristics/eval-file-format");
    assert_eq!(format.value_text.as_deref(), Some("absent"));

    // Enough cases → no sufficiency finding, but the measurement still lands.
    let enough_json = r#"{"evals":[{"input":"a"},{"input":"b"},{"input":"c"},{"input":"d"}]}"#;
    let enough_files = HashMap::from([
        (
            "SKILL.md".to_string(),
            "---\nname: evals-ok\n---\nRun eval.\n".to_string(),
        ),
        ("evals/evals.json".to_string(), enough_json.to_string()),
    ]);
    let enough_paths = ["SKILL.md", "evals/evals.json"]
        .iter()
        .map(|p| (*p).to_string())
        .collect::<Vec<_>>();
    let enough =
        scan_skill(&enough_files, &enough_paths, OBSERVED_AT).expect("valid RFC3339 timestamp");
    assert_eq!(
        signal(&enough, "reliability/eval-test-case-count").value_num,
        Some(4.0)
    );
    assert!(
        !enough
            .signals
            .iter()
            .any(|s| s.rule_id == "reliability/eval-test-cases-sufficient"),
        "a sufficient eval suite must not emit the sufficiency finding"
    );
    // Cases with no assertion fields at all → fact reads "absent".
    let no_assertions = scan_skill(
        &HashMap::from([
            (
                "SKILL.md".to_string(),
                "---\nname: evals-bare\n---\nRun.\n".to_string(),
            ),
            (
                "evals/evals.json".to_string(),
                r#"{"evals":[{"input":"a"},{"input":"b"},{"input":"c"}]}"#.to_string(),
            ),
        ]),
        &["SKILL.md".to_string(), "evals/evals.json".to_string()],
        OBSERVED_AT,
    )
    .expect("valid RFC3339 timestamp");
    let bare = signal(&no_assertions, "reliability/eval-assertions");
    assert_eq!(bare.value_text.as_deref(), Some("absent"));
}
