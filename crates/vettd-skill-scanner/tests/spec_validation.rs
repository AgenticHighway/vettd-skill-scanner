//! Agent Skills format validation against real producer text.
//!
//! Fixture sources (frontmatter lines verbatim):
//! - tinybirdco/tinybird-agent-skills at 19a3ec18b2270fb82cc3489eabf122da0706e6a0,
//!   `skills/tinybird-best-practices/SKILL.md` (declares `name: tinybird`).
//! - Jlsiles/Consulting-tools at 3e4b5da7638eee78ea963af32a7a3f2f8cbc2675,
//!   `prioritization/SKILL.md` (starts with a heading; no frontmatter).

use std::collections::HashMap;

use vettd_skill_scanner::{scan_skill_with_repo_context, RepoContext, SkillScanResult};

const OBSERVED: &str = "2026-11-18T00:00:00Z";

const TINYBIRD: &str = "---\nname: tinybird\ndescription: Tinybird file formats, SQL rules, optimization patterns, and best practices for datasources, pipes, endpoints, and materialized views.\n---\n\n# Tinybird Best Practices\n\nGuidance for Tinybird file formats, SQL rules, optimization patterns, and data modeling. Use this skill when creating or editing Tinybird datafiles.\n";

const JLSILES: &str = "# PM Prioritization Framework\n\nA comprehensive prioritization skill for product managers to evaluate features, initiatives, and tasks using proven frameworks.\n\n## Overview\n\nThis skill helps PMs make data-driven decisions by applying the right framework for their specific context. All outputs are provided in clean, tabular format for easy sharing with stakeholders.\n";

fn scan(skill_md: &str, bundle_path: &str, dir: Option<&str>) -> SkillScanResult {
    let mut text = HashMap::new();
    text.insert("SKILL.md".to_string(), skill_md.to_string());
    let paths = vec!["SKILL.md".to_string()];
    let ctx = RepoContext {
        bundle_path,
        repo_paths: &[],
        skill_dir_name: dir,
    };
    scan_skill_with_repo_context(&text, &paths, &ctx, OBSERVED).unwrap()
}

fn has_signal(r: &SkillScanResult, rule: &str) -> bool {
    r.signals.iter().any(|s| s.rule_id == rule)
}

fn attested(r: &SkillScanResult) -> bool {
    r.coverage.iter().any(|c| c.rule_id == "VTD-0099")
}

#[test]
fn folder_mismatch_is_signalled_and_not_attested() {
    let r = scan(TINYBIRD, "skills/tinybird-best-practices", None);
    assert!(has_signal(&r, "compatibility/spec-name-folder"));
    assert!(!attested(&r));
    assert!(r.findings.iter().all(|f| f.rule_id != "VTD-0099"));
}

#[test]
fn matching_folder_is_attested_under_the_compatibility_category() {
    let r = scan(TINYBIRD, "skills/tinybird", None);
    assert!(!has_signal(&r, "compatibility/spec-name-folder"));
    let entry = r.coverage.iter().find(|c| c.rule_id == "VTD-0099").unwrap();
    assert_eq!(entry.category.as_deref(), Some("compatibility"));
}

#[test]
fn explicit_dir_name_wins_over_bundle_path() {
    let r = scan(TINYBIRD, "", Some("tinybird"));
    assert!(attested(&r));
}

#[test]
fn no_frontmatter_is_signalled_and_never_attested() {
    let r = scan(JLSILES, "prioritization", None);
    assert!(has_signal(&r, "compatibility/spec-frontmatter"));
    assert!(!attested(&r));
}

#[test]
fn unknown_folder_leaves_the_name_unverified() {
    let r = scan(TINYBIRD, "", None);
    assert!(!has_signal(&r, "compatibility/spec-name-folder"));
    assert!(!attested(&r));
}

#[test]
fn unparseable_frontmatter_is_signalled() {
    let r = scan(
        "---\nname: [unclosed\ndescription: x\n---\nBody.\n",
        "x",
        None,
    );
    assert!(has_signal(&r, "compatibility/spec-frontmatter"));
    assert!(!attested(&r));
}

#[test]
fn missing_name_in_parsed_frontmatter_is_signalled() {
    let r = scan("---\ndescription: Does things.\n---\nBody.\n", "x", None);
    assert!(has_signal(&r, "compatibility/spec-name"));
    assert!(!attested(&r));
}

#[test]
fn uppercase_and_bad_chars_are_info_signals_not_findings() {
    let r = scan(
        "---\nname: My_Skill\ndescription: Does things.\n---\nBody.\n",
        "My_Skill",
        None,
    );
    assert!(has_signal(&r, "compatibility/spec-name"));
    assert!(r.findings.iter().all(|f| f.rule_id != "VTD-0099"));
    assert!(!attested(&r));
}

#[test]
fn spec_signals_are_info_severity() {
    let r = scan(JLSILES, "prioritization", None);
    assert!(r
        .signals
        .iter()
        .filter(|s| s.rule_id.starts_with("compatibility/spec-"))
        .all(|s| s.severity.as_deref() == Some("info")));
}
