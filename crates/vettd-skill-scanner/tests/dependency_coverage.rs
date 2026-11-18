//! Dependency coverage against real producer text.
//!
//! Fixture source: nowork-studio/notfair-plugin at be3a43233c8836525fafcfdb85f78fb08e56a43f,
//! `skills/google-ads-assets/SKILL.md` (frontmatter and the wrapper paragraph, verbatim). The
//! repository holds the canonical workflow outside the wrapper's one-file bundle.

use std::collections::HashMap;

use vettd_skill_scanner::{scan_skill, scan_skill_with_repo_context, RepoContext};

const NOTFAIR_WRAPPER: &str = "---\nname: google-ads-assets\ndescription: Plan, validate, and safely publish Google Ads assets, including sitelinks, callouts, structured snippets, image assets, and Performance Max asset briefs. Use when asked for Google Ads assets, ad extensions, sitelinks, callouts, snippets, image assets, Performance Max assets, PMax creative, or an asset audit.\n---\n\n# Canonical NotFair workflow\n\nRead [`../../google-ads/assets/WORKFLOW.md`](../../google-ads/assets/WORKFLOW.md) completely, then follow it as the active workflow. Normalize that path from the directory containing this wrapper: the canonical file is `<plugin-root>/google-ads/assets/WORKFLOW.md`, not `<plugin-root>/skills/google-ads-assets/assets/SKILL.md`. Resolve every relative reference from the canonical file against `<plugin-root>/google-ads/assets/`. If the canonical file cannot be read, stop and report the packaging error; never substitute a similarly named skill from another plugin.\n";

const OBSERVED: &str = "2026-11-18T00:00:00Z";

fn files() -> (HashMap<String, String>, Vec<String>) {
    let mut text = HashMap::new();
    text.insert("SKILL.md".to_string(), NOTFAIR_WRAPPER.to_string());
    (text, vec!["SKILL.md".to_string()])
}

fn repo(extra: &[&str]) -> Vec<String> {
    let mut paths: Vec<String> = [
        "skills/google-ads-assets/SKILL.md",
        "skills/backlink-audit/SKILL.md",
        "google-ads/assets/WORKFLOW.md",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    paths.extend(extra.iter().map(|s| s.to_string()));
    paths
}

fn partial_entries(
    result: &vettd_skill_scanner::SkillScanResult,
) -> Vec<&vettd_skill_scanner::CoverageEntry> {
    result
        .coverage
        .iter()
        .filter(|c| c.kind == "partial")
        .collect()
}

#[test]
fn wrapper_pointing_at_shared_workflow_is_partial() {
    let (text, paths) = files();
    let repo_paths = repo(&[]);
    let ctx = RepoContext {
        bundle_path: "skills/google-ads-assets",
        repo_paths: &repo_paths,
    };
    let result = scan_skill_with_repo_context(&text, &paths, &ctx, OBSERVED).unwrap();
    let partial = partial_entries(&result);
    assert_eq!(partial.len(), 1);
    assert_eq!(partial[0].rule_id, "reliability/unscanned-dependencies");
    assert!(partial[0].detail.contains("google-ads/assets/WORKFLOW.md"));
    // The closed-resolution claim must not sit beside a partial.
    assert!(!result
        .coverage
        .iter()
        .any(|c| c.label == "Internal reference resolution completed"));
}

#[test]
fn wrapper_without_repo_context_is_unverifiable_partial() {
    let (text, paths) = files();
    let result = scan_skill(&text, &paths, OBSERVED).unwrap();
    let partial = partial_entries(&result);
    assert_eq!(partial.len(), 1);
    assert!(partial[0]
        .detail
        .contains("../../google-ads/assets/WORKFLOW.md"));
}

#[test]
fn target_missing_from_repository_is_not_a_dependency() {
    let (text, paths) = files();
    let repo_paths = vec!["skills/google-ads-assets/SKILL.md".to_string()];
    let ctx = RepoContext {
        bundle_path: "skills/google-ads-assets",
        repo_paths: &repo_paths,
    };
    let result = scan_skill_with_repo_context(&text, &paths, &ctx, OBSERVED).unwrap();
    assert!(partial_entries(&result).is_empty());
}

#[test]
fn skill_with_no_outside_references_has_no_dependency_entry() {
    let mut text = HashMap::new();
    text.insert(
        "SKILL.md".to_string(),
        "---\nname: plain\ndescription: Does a thing. Use when asked.\n---\n\nRead references/guide.md.\n"
            .to_string(),
    );
    text.insert("references/guide.md".to_string(), "Guide.\n".to_string());
    let paths = vec!["SKILL.md".to_string(), "references/guide.md".to_string()];
    let result = scan_skill(&text, &paths, OBSERVED).unwrap();
    assert!(!result
        .coverage
        .iter()
        .any(|c| c.rule_id.starts_with("reliability/unscanned") || c.kind == "partial"));
}
