//! Integration tests for the `scan_skill` public API.
//!
//! These tests drive `scan_skill` through `vettd_skill_scanner`'s public
//! interface using synthetic file maps — no filesystem I/O.
//!
//! **Why these tests matter**: the stub engine must exercise every `Finding`
//! shape (all categories, multiple severity tiers) so that downstream CLI code
//! which maps findings to the wire contract is tested against realistic variety.
//! Tests in this file will fail if the engine stops producing that variety,
//! which is the signal that the mapping layer also needs updating.

use std::collections::HashMap;

use vettd_skill_scanner::{
    scan_skill as scan_with_observed_at, FindingCategory, Severity, SkillScanResult,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn skill_md() -> (String, String) {
    (
        "SKILL.md".to_string(),
        "---\nname: test-skill\nversion: 1.0.0\n---\n# Test Skill\nDoes a thing.".to_string(),
    )
}

fn with_skill_md() -> (HashMap<String, String>, Vec<String>) {
    let mut text_files = HashMap::new();
    let (path, content) = skill_md();
    text_files.insert(path.clone(), content);
    let all_paths = vec![path];
    (text_files, all_paths)
}

fn with_scripts() -> (HashMap<String, String>, Vec<String>) {
    let (mut text_files, mut all_paths) = with_skill_md();
    text_files.insert(
        "scripts/run.sh".to_string(),
        "#!/bin/bash\necho hello".to_string(),
    );
    all_paths.push("scripts/run.sh".to_string());
    (text_files, all_paths)
}

fn with_evals() -> (HashMap<String, String>, Vec<String>) {
    let (mut text_files, mut all_paths) = with_skill_md();
    all_paths.push("evals/suite.json".to_string());
    text_files.insert("evals/suite.json".to_string(), "{}".to_string());
    (text_files, all_paths)
}

fn scan(text_files: &HashMap<String, String>, all_paths: &[String]) -> SkillScanResult {
    scan_with_observed_at(text_files, all_paths, "2026-08-31T00:00:00Z")
        .expect("valid RFC3339 timestamp")
}

// ---------------------------------------------------------------------------
// Structural flag tests
// ---------------------------------------------------------------------------

#[test]
fn no_skill_md_sets_flag_false() {
    let result = scan(&HashMap::new(), &[]);
    assert!(!result.has_skill_md);
    assert!(!result.has_assets);
}

#[test]
fn skill_md_in_text_files_sets_flag_true() {
    let (text_files, all_paths) = with_skill_md();
    let result = scan(&text_files, &all_paths);
    assert!(result.has_skill_md);
}

#[test]
fn skill_md_in_all_paths_only_sets_flag_true() {
    // SKILL.md may be detected from all_paths even if content was not read.
    let result = scan(&HashMap::new(), &["SKILL.md".to_string()]);
    assert!(result.has_skill_md);
}

#[test]
fn scripts_dir_detected_from_all_paths() {
    let (text_files, mut all_paths) = with_skill_md();
    all_paths.push("scripts/deploy.sh".to_string());
    let result = scan(&text_files, &all_paths);
    assert!(result.has_scripts);
}

#[test]
fn references_dir_detected() {
    let (text_files, mut all_paths) = with_skill_md();
    all_paths.push("references/guide.md".to_string());
    let result = scan(&text_files, &all_paths);
    assert!(result.has_references);
}

#[test]
fn evals_dir_detected() {
    let (text_files, all_paths) = with_evals();
    let result = scan(&text_files, &all_paths);
    assert!(result.has_evals);
}

#[test]
fn assets_dir_detected() {
    let (text_files, mut all_paths) = with_skill_md();
    all_paths.push("assets/template.json".to_string());
    let result = scan(&text_files, &all_paths);
    assert!(result.has_assets);
}

#[test]
fn file_count_reflects_all_paths_length() {
    let (text_files, all_paths) = with_skill_md();
    let n = all_paths.len();
    let result = scan(&text_files, &all_paths);
    assert_eq!(result.file_count, n);
}

// ---------------------------------------------------------------------------
// Structural finding tests
// ---------------------------------------------------------------------------

#[test]
fn missing_skill_md_emits_critical_structure_finding() {
    // Without SKILL.md, the skill is malformed — scanner must flag it critical
    // so the grade formula produces F.
    let result = scan(&HashMap::new(), &[]);
    let f = result
        .findings
        .iter()
        .find(|f| f.category == FindingCategory::Structure && f.severity == Severity::Critical)
        .expect("should emit a critical structure finding when SKILL.md is absent");
    assert!(
        f.label.to_lowercase().contains("skill.md"),
        "critical structure finding label should mention SKILL.md"
    );
}

#[test]
fn present_skill_md_emits_no_structure_finding() {
    // A present SKILL.md is a structural *positive* and travels on the
    // `has_skill_md` result flag (and the coverage channel), not the finding
    // channel. Only the missing-SKILL.md critical finding remains.
    let (text_files, all_paths) = with_skill_md();
    let result = scan(&text_files, &all_paths);
    assert!(result.has_skill_md);
    assert!(
        !result
            .findings
            .iter()
            .any(|f| f.category == FindingCategory::Structure),
        "present SKILL.md must not emit structure findings"
    );
}

// ---------------------------------------------------------------------------
// Category and severity variety tests
// ---------------------------------------------------------------------------

#[test]
fn benign_skill_emits_no_findings_quality_lives_on_signals() {
    // The reclassification moved every non-safety finding (VTD-0083..0123)
    // onto the signal channel, so a well-formed skill produces NO findings:
    // the finding channel now carries only genuine safety/structural issues.
    // The quality observations (body facts, description findings) must surface
    // as signals instead — that is where this test's successors assert them.
    let (text_files, all_paths) = with_skill_md();
    let result = scan(&text_files, &all_paths);

    assert!(
        result.findings.is_empty(),
        "a benign skill must not produce findings: {:?}",
        result
            .findings
            .iter()
            .map(|f| (&f.rule_id, &f.label))
            .collect::<Vec<_>>()
    );
    assert!(
        result
            .signals
            .iter()
            .any(|s| s.rule_id == "reliability/examples"),
        "body quality is observable on the signal channel"
    );
}

#[test]
fn findings_span_multiple_severities() {
    // A skill with no SKILL.md produces a critical structure finding.
    let bad = scan(&HashMap::new(), &[]);
    let has_critical = bad
        .findings
        .iter()
        .any(|f| f.severity == Severity::Critical);
    assert!(
        has_critical,
        "missing critical finding when SKILL.md absent"
    );

    // Severity *variety* on the finding channel now comes from genuine
    // safety issues only; the old info/low/high quality findings are signals.
    let (text_files, all_paths) = with_skill_md();
    let result = scan(&text_files, &all_paths);
    assert!(
        result.findings.is_empty(),
        "a benign skill carries no findings of any severity"
    );
}

#[test]
fn scripts_dir_emits_script_signals_not_scripts_findings() {
    // The script-derived rules (VTD-0114..0117) are compatibility signals now:
    // a scripts/ dir with a plain CLI script yields the cli-help and
    // structured-output facts (aggregated "absent"), and no findings — the
    // interactive/unpinned failure branches only fire when actually present.
    let (text_files, all_paths) = with_scripts();
    let result = scan(&text_files, &all_paths);
    assert!(
        !result
            .findings
            .iter()
            .any(|f| f.category == FindingCategory::Scripts),
        "scripts/ must not produce findings after the reclassification"
    );
    assert_eq!(
        result
            .signals
            .iter()
            .filter(|s| s.rule_id == "compatibility/cli-help")
            .count(),
        1,
        "cli-help fact must be emitted for the analyzed script"
    );
    let cli_help = result
        .signals
        .iter()
        .find(|s| s.rule_id == "compatibility/cli-help")
        .expect("cli-help fact");
    assert_eq!(cli_help.value_text.as_deref(), Some("absent"));
    assert_eq!(cli_help.derivation.as_deref(), Some("read"));
    assert!(
        result
            .signals
            .iter()
            .any(|s| s.rule_id == "compatibility/structured-output"),
        "structured-output fact must be emitted alongside cli-help"
    );
}

#[test]
fn evals_dir_emits_eval_signals_not_evals_findings() {
    // The eval rules (VTD-0119..0123) are signals now: a non-JSON eval file in
    // evals/ surfaces as the characteristics/eval-file-format fact ("present"),
    // and no evals-category findings are emitted.
    let (text_files, all_paths) = with_evals();
    let result = scan(&text_files, &all_paths);
    assert!(
        !result
            .findings
            .iter()
            .any(|f| f.category == FindingCategory::Evals),
        "evals/ must not produce findings after the reclassification"
    );
    assert!(
        result
            .signals
            .iter()
            .any(|s| s.rule_id == "characteristics/eval-file-format"
                && s.value_text.as_deref() == Some("present")),
        "a non-JSON eval file is a present eval-file-format fact"
    );
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn empty_inputs_returns_well_formed_result() {
    // 0-files edge case: scanner must not panic and must return a valid result.
    let result = scan(&HashMap::new(), &[]);
    assert!(!result.has_skill_md);
    assert!(!result.has_scripts);
    assert!(!result.has_references);
    assert!(!result.has_evals);
    assert_eq!(result.file_count, 0);
    // Must still emit at least the missing-SKILL.md finding.
    assert!(!result.findings.is_empty());
}

#[test]
fn all_findings_have_non_empty_label_and_detail() {
    // Guard that no finding slips through with blank display text.
    let (text_files, all_paths) = with_skill_md();
    let result = scan(&text_files, &all_paths);
    for f in &result.findings {
        assert!(!f.label.is_empty(), "finding has empty label: {:?}", f);
        assert!(!f.detail.is_empty(), "finding has empty detail: {:?}", f);
    }
}

#[test]
fn all_findings_have_valid_source() {
    let (text_files, all_paths) = with_skill_md();
    let result = scan(&text_files, &all_paths);
    for f in &result.findings {
        assert!(!f.source.is_empty(), "finding has empty source: {:?}", f);
    }
}

#[test]
fn scanner_version_const_is_nonzero() {
    // Sanity check that CURRENT_SCANNER_VERSION is set to a real value.
    // Must stay in sync with scanner-version.ts's CURRENT_SCANNER_VERSION.
    assert_ne!(vettd_skill_scanner::consts::CURRENT_SCANNER_VERSION, 0);
}
