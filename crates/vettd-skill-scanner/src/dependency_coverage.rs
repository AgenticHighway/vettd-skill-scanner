//! Dependency coverage: which paths the SKILL.md body points at that live outside the scanned
//! bundle, and whether the assessment can honestly call itself complete.
//!
//! Only the skill's own folder is analyzed. A body that tells the agent to follow
//! `../../canonical/WORKFLOW.md` hands behavior to bytes this scan never read, so the result must
//! say so instead of reading as a closed assessment. This module is pure name resolution: it does
//! not read the outside content, it classifies where each reference points.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::Regex;

use crate::coverage::CoverageEntry;
use crate::emission::RepoContext;

pub(crate) const UNSCANNED_DEPENDENCIES: &str = "reliability/unscanned-dependencies";
pub(crate) const SIBLING_SKILL_REFERENCES: &str = "reliability/sibling-skill-references";

/// Upper bounds so a hostile body cannot make the extractor or the entry unbounded.
const MAX_REFERENCES: usize = 200;
const MAX_REFERENCE_LEN: usize = 300;
const MAX_LISTED_PATHS: usize = 5;

/// Repo-level documents that are not behavior: ignored, never a dependency, but only at the
/// repository root. A README or similar inside a subfolder (e.g. `hooks/README.md`) can carry
/// real instructions, so it counts as shared content like any other file.
const ROOT_DOC_STEMS: &[&str] = &[
    "readme",
    "changelog",
    "contributing",
    "code_of_conduct",
    "security",
];
/// Legal notices are never behavior, wherever they sit.
const ANYWHERE_DOC_STEMS: &[&str] = &["license", "notice"];

/// Where one reference points, relative to the scanned bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DependencyClass {
    /// Inside the scanned bundle, a repo doc, or a path that does not exist: not a dependency
    /// concern (missing paths keep their existing handling).
    Ignored,
    /// Another skill's folder: assessed by that skill's own scan.
    SiblingSkill,
    /// Shared non-skill content in the repository that this scan never read.
    SharedContent,
    /// Escapes the bundle with no repository context to check it against.
    Unverifiable,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct DependencyReport {
    /// Repo-root-relative (or as-written, when unverifiable) paths, sorted and deduplicated.
    pub shared: Vec<String>,
    pub unverifiable: Vec<String>,
    pub siblings: Vec<String>,
}

impl DependencyReport {
    /// Whether any reference hands behavior to content this scan did not read.
    pub(crate) fn is_partial(&self) -> bool {
        !self.shared.is_empty() || !self.unverifiable.is_empty()
    }
}

/// Analyze the body's outside references against the bundle and repository context.
pub(crate) fn analyze_dependencies(
    body: &str,
    all_paths: &[String],
    repo_context: &RepoContext<'_>,
) -> DependencyReport {
    let bundle: BTreeSet<&str> = all_paths.iter().map(String::as_str).collect();
    let repo: BTreeSet<&str> = repo_context.repo_paths.iter().map(String::as_str).collect();
    let mut shared = BTreeSet::new();
    let mut unverifiable = BTreeSet::new();
    let mut siblings = BTreeSet::new();
    for reference in extract_references(body) {
        match classify(&reference, &bundle, &repo, repo_context.bundle_path) {
            (DependencyClass::SharedContent, path) => {
                shared.insert(path);
            }
            (DependencyClass::Unverifiable, path) => {
                unverifiable.insert(path);
            }
            (DependencyClass::SiblingSkill, path) => {
                siblings.insert(path);
            }
            (DependencyClass::Ignored, _) => {}
        }
    }
    DependencyReport {
        shared: shared.into_iter().collect(),
        unverifiable: unverifiable.into_iter().collect(),
        siblings: siblings.into_iter().collect(),
    }
}

/// Coverage entries for a report: a partial entry when behavior lives outside the scan, plus a
/// non-incomplete note for sibling-skill references.
///
/// The partial label and detail avoid the words the hosted reason mapper keys on (size, director,
/// unread, error, missing, ...) so the stored reason stays `unanalyzed-content`.
pub(crate) fn dependency_coverage_entries(report: &DependencyReport) -> Vec<CoverageEntry> {
    let mut entries = Vec::new();
    if report.is_partial() {
        let paths: Vec<String> = report
            .shared
            .iter()
            .chain(report.unverifiable.iter())
            .cloned()
            .collect();
        let verifiable = report.unverifiable.is_empty();
        entries.push(CoverageEntry {
            kind: "partial".to_string(),
            rule_id: UNSCANNED_DEPENDENCIES.to_string(),
            label: "Referenced content outside this skill was not assessed".to_string(),
            detail: format!(
                "The instructions point at {} that this assessment did not analyze: {}. {}",
                if verifiable {
                    "shared repository content"
                } else {
                    "content outside the skill folder"
                },
                list_paths(&paths),
                if verifiable {
                    "Findings describe the skill folder only; the referenced content can change without moving this result."
                } else {
                    "No repository context was available to place these references, so they cannot be treated as assessed."
                },
            ),
            category: Some("reliability".to_string()),
        });
    }
    if !report.siblings.is_empty() {
        entries.push(CoverageEntry {
            kind: "coverage".to_string(),
            rule_id: SIBLING_SKILL_REFERENCES.to_string(),
            label: "Referenced sibling skills are assessed separately".to_string(),
            detail: format!(
                "The instructions point into other skills in the same repository ({}); each is assessed by its own scan.",
                list_paths(&report.siblings)
            ),
            category: Some("reliability".to_string()),
        });
    }
    entries
}

fn list_paths(paths: &[String]) -> String {
    let shown: Vec<&str> = paths
        .iter()
        .take(MAX_LISTED_PATHS)
        .map(String::as_str)
        .collect();
    let mut text = shown.join(", ");
    if paths.len() > MAX_LISTED_PATHS {
        text.push_str(&format!(" and {} more", paths.len() - MAX_LISTED_PATHS));
    }
    text
}

/// Markdown link targets and relative path tokens, deduplicated in first-seen order, bounded.
/// URLs, anchors, and absolute paths are skipped.
pub(crate) fn extract_references(body: &str) -> Vec<String> {
    static LINK_RE: OnceLock<Regex> = OnceLock::new();
    static TOKEN_RE: OnceLock<Regex> = OnceLock::new();
    let link_re = LINK_RE
        .get_or_init(|| Regex::new(r"\]\(\s*<?([^)\s>]+)").expect("valid link-target regex"));
    // Explicit `./x` and `../x` paths only. A bare `a/b.ext` in prose is ambiguous between the
    // skill's repository and the user's own project, so only link targets cover that spelling.
    let token_re = TOKEN_RE.get_or_init(|| {
        Regex::new(
            r"(?:\.{1,2}/)+[A-Za-z0-9._/-]+|[A-Za-z0-9_-][A-Za-z0-9._-]*(?:/[A-Za-z0-9._-]+)+",
        )
        .expect("valid path-token regex")
    });

    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let mut push = |candidate: &str| {
        if out.len() >= MAX_REFERENCES {
            return;
        }
        if let Some(clean) = normalize_candidate(candidate) {
            if seen.insert(clean.clone()) {
                out.push(clean);
            }
        }
    };
    for cap in link_re.captures_iter(body) {
        push(&cap[1]);
    }
    for matched in token_re.find_iter(body) {
        if is_inside_url(body, matched.start()) || continues_token(body, matched.start()) {
            continue;
        }
        push(matched.as_str());
    }
    out
}

/// A path token directly preceded by a path character is a tail of a longer token (the regex
/// restarted mid-token), not a separate reference.
fn continues_token(body: &str, start: usize) -> bool {
    body[..start]
        .chars()
        .last()
        .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':'))
}

fn is_inside_url(body: &str, start: usize) -> bool {
    let line_start = body[..start]
        .rfind(['\n', '\r', ' ', '(', '<'])
        .map(|i| i + 1)
        .unwrap_or(0);
    body[line_start..start].contains("://")
}

/// Strip anchors, queries, and trailing punctuation; reject URLs, absolute paths, and anchors.
fn normalize_candidate(raw: &str) -> Option<String> {
    let mut text = raw.trim();
    if let Some(i) = text.find(['#', '?']) {
        text = &text[..i];
    }
    let text = text.trim_end_matches(|c: char| {
        matches!(
            c,
            '.' | ',' | ';' | ':' | '!' | ')' | ']' | '}' | '"' | '\'' | '/'
        )
    });
    if text.is_empty()
        || text.len() > MAX_REFERENCE_LEN
        || text.starts_with('/')
        || text.starts_with('~')
        || text.contains("://")
        || text.contains(':')
        || text.starts_with("mailto")
    {
        return None;
    }
    // A bare `a/b` with no extension and no `.`/`..` lead is prose ("and/or", "input/output").
    let relative_lead = text.starts_with("./") || text.starts_with("../");
    let last = text.rsplit('/').next().unwrap_or(text);
    if !relative_lead && !last.contains('.') {
        return None;
    }
    if last.is_empty() || last == "." || last == ".." {
        return None;
    }
    Some(text.to_string())
}

/// Classify one reference. The returned path is repo-root-relative when resolved, as written
/// otherwise.
fn classify(
    reference: &str,
    bundle: &BTreeSet<&str>,
    repo: &BTreeSet<&str>,
    bundle_path: &str,
) -> (DependencyClass, String) {
    let relative_lead = reference.starts_with("./") || reference.starts_with("../");
    let has_repo = !repo.is_empty();

    if !relative_lead && (bundle.contains(reference) || ends_in_bundle(reference, bundle)) {
        return (DependencyClass::Ignored, reference.to_string());
    }
    if !has_repo {
        // No repository to check against: only an escape out of the bundle is unverifiable.
        let escapes = relative_lead && escapes_bundle(bundle_path, reference);
        return if escapes {
            (DependencyClass::Unverifiable, reference.to_string())
        } else {
            (DependencyClass::Ignored, reference.to_string())
        };
    }

    // Link targets and explicit relative paths are both relative to the SKILL.md.
    let Some(resolved) = resolve(bundle_path, reference) else {
        // Climbs above the repository root: whatever it names is outside every tree this scan
        // can see, so it cannot be treated as assessed.
        return (DependencyClass::Unverifiable, reference.to_string());
    };
    // Files only: a directory reference is not a dependency.
    if !repo.contains(resolved.as_str()) {
        // Does not exist: existing missing-path handling applies, not a dependency.
        return (DependencyClass::Ignored, resolved);
    }
    if within(&resolved, bundle_path) {
        return (DependencyClass::Ignored, resolved);
    }
    if is_repo_doc(&resolved) {
        return (DependencyClass::Ignored, resolved);
    }
    if owning_skill_dir(repo, &resolved).is_some() {
        return (DependencyClass::SiblingSkill, resolved);
    }
    (DependencyClass::SharedContent, resolved)
}

fn ends_in_bundle(reference: &str, bundle: &BTreeSet<&str>) -> bool {
    bundle
        .iter()
        .any(|entry| reference.ends_with(&format!("/{entry}")))
}

/// `path` equals `dir` or sits under it. An empty `dir` (skill at repo root) contains everything.
fn within(path: &str, dir: &str) -> bool {
    dir.is_empty() || path == dir || path.starts_with(&format!("{dir}/"))
}

fn escapes_bundle(bundle_path: &str, reference: &str) -> bool {
    // With no known bundle position, any `..` fails to resolve and counts as an escape.
    resolve(bundle_path, reference).is_none_or(|resolved| !within(&resolved, bundle_path))
}

/// Resolve `reference` against `bundle_path` like a filesystem; `None` if it climbs above root.
fn resolve(bundle_path: &str, reference: &str) -> Option<String> {
    let mut segments: Vec<&str> = bundle_path.split('/').filter(|s| !s.is_empty()).collect();
    for part in reference.split('/') {
        match part {
            ".." => {
                segments.pop()?;
            }
            "." | "" => {}
            other => segments.push(other),
        }
    }
    Some(segments.join("/"))
}

fn is_repo_doc(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    let stem = name.split('.').next().unwrap_or(&name);
    ANYWHERE_DOC_STEMS.contains(&stem) || (!path.contains('/') && ROOT_DOC_STEMS.contains(&stem))
}

/// Nearest ancestor directory of `path` (inclusive of the file's own folder) holding a SKILL.md.
fn owning_skill_dir<'a>(repo: &BTreeSet<&str>, path: &'a str) -> Option<&'a str> {
    let mut dir = path;
    loop {
        dir = match dir.rfind('/') {
            Some(i) => &dir[..i],
            None => "",
        };
        let skill_md = if dir.is_empty() {
            "SKILL.md".to_string()
        } else {
            format!("{dir}/SKILL.md")
        };
        let lower = skill_md.replace("SKILL.md", "skill.md");
        if repo.contains(skill_md.as_str()) || repo.contains(lower.as_str()) {
            return Some(dir);
        }
        if dir.is_empty() {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn report(body: &str, bundle: &[&str], repo: &[&str], bundle_path: &str) -> DependencyReport {
        let all = paths(bundle);
        let repo_paths = paths(repo);
        analyze_dependencies(
            body,
            &all,
            &RepoContext {
                bundle_path,
                repo_paths: &repo_paths,
                skill_dir_name: None,
            },
        )
    }

    #[test]
    fn extractor_skips_urls_anchors_and_absolute_paths() {
        let body = "See [docs](https://example.com/a/b.md), [top](#top), /etc/passwd.x and \
                    https://host.dev/x/y.md plus ../../shared/w.md.";
        assert_eq!(extract_references(body), vec!["../../shared/w.md"]);
    }

    #[test]
    fn extractor_ignores_prose_slashes() {
        assert!(extract_references("use and/or input/output here").is_empty());
    }

    #[test]
    fn extractor_is_bounded() {
        let body = "../x/f0.md ".repeat(10)
            + &(0..500).fold(String::new(), |acc, i| acc + &format!("../x/g{i}.md "));
        assert_eq!(extract_references(&body).len(), MAX_REFERENCES);
        let long = format!("../{}.md", "a".repeat(400));
        assert!(extract_references(&long).is_empty());
    }

    #[test]
    fn shared_content_is_partial() {
        let r = report(
            "Follow [workflow](../../canonical/WORKFLOW.md).",
            &["SKILL.md"],
            &["skills/wrap/SKILL.md", "canonical/WORKFLOW.md"],
            "skills/wrap",
        );
        assert_eq!(r.shared, vec!["canonical/WORKFLOW.md"]);
        assert!(r.is_partial());
    }

    #[test]
    fn sibling_skill_is_noted_not_partial() {
        let r = report(
            "See ../other/references/guide.md",
            &["SKILL.md"],
            &[
                "skills/a/SKILL.md",
                "skills/other/SKILL.md",
                "skills/other/references/guide.md",
            ],
            "skills/a",
        );
        assert!(!r.is_partial());
        assert_eq!(r.siblings, vec!["skills/other/references/guide.md"]);
        let entries = dependency_coverage_entries(&r);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, "coverage");
    }

    #[test]
    fn repo_docs_and_missing_paths_are_ignored() {
        let r = report(
            "Read ../../README.md and ../../LICENSE and ../../nope/gone.md",
            &["SKILL.md"],
            &["skills/a/SKILL.md", "README.md", "LICENSE"],
            "skills/a",
        );
        assert_eq!(r, DependencyReport::default());
    }

    #[test]
    fn subfolder_readme_is_shared_content_but_nested_license_is_not() {
        // Light Ark (lightarktech/founder-coding-skills@e737f2049ac7) skills/model-tiering links
        // ../../hooks/README.md, which documents enforcement hooks: behavior, not boilerplate.
        let r = report(
            "See [hooks](../../hooks/README.md) and ../../hooks/LICENSE",
            &["SKILL.md"],
            &["skills/a/SKILL.md", "hooks/README.md", "hooks/LICENSE"],
            "skills/a",
        );
        assert_eq!(r.shared, vec!["hooks/README.md"]);
        assert!(r.is_partial());
    }

    #[test]
    fn root_escape_is_unverifiable() {
        let r = report(
            "See ../../../../etc/x.md",
            &["SKILL.md"],
            &["skills/a/SKILL.md"],
            "skills/a",
        );
        assert_eq!(r.unverifiable, vec!["../../../../etc/x.md"]);
        assert!(r.is_partial());
    }

    #[test]
    fn bare_prose_root_path_that_exists_is_not_a_dependency() {
        // Ambiguous between the skill's repo and the user's own project.
        let r = report(
            "Run tests/conftest.py and shared/scripts/check.py first",
            &["SKILL.md"],
            &[
                "skills/a/SKILL.md",
                "tests/conftest.py",
                "shared/scripts/check.py",
            ],
            "skills/a",
        );
        assert_eq!(r, DependencyReport::default());
    }

    #[test]
    fn bare_link_target_resolves_relative_to_the_skill() {
        let r = report(
            "See [notes](notes/extra.md) and [up](../shared/x.md)",
            &["SKILL.md"],
            &[
                "skills/a/SKILL.md",
                "skills/a/notes/extra.md",
                "skills/shared/x.md",
            ],
            "skills/a",
        );
        assert_eq!(r.shared, vec!["skills/shared/x.md"]);
    }

    #[test]
    fn directory_reference_is_not_a_dependency() {
        let r = report(
            "Browse ../../shared/ and [dir](../../shared)",
            &["SKILL.md"],
            &["skills/a/SKILL.md", "shared/x.md"],
            "skills/a",
        );
        assert_eq!(r, DependencyReport::default());
    }

    #[test]
    fn in_bundle_references_are_ignored() {
        let r = report(
            "See references/guide.md and ../a/references/guide.md",
            &["SKILL.md", "references/guide.md"],
            &["skills/a/SKILL.md", "skills/a/references/guide.md"],
            "skills/a",
        );
        assert_eq!(r, DependencyReport::default());
    }

    #[test]
    fn no_repo_context_escape_is_unverifiable() {
        let r = report("Follow ../../canonical/WORKFLOW.md", &["SKILL.md"], &[], "");
        assert_eq!(r.unverifiable, vec!["../../canonical/WORKFLOW.md"]);
        assert!(r.is_partial());
    }

    #[test]
    fn no_repo_context_plain_bundle_paths_are_fine() {
        let r = report(
            "See references/guide.md and ./scripts/run.py",
            &["SKILL.md", "references/guide.md", "scripts/run.py"],
            &[],
            "",
        );
        assert_eq!(r, DependencyReport::default());
    }

    #[test]
    fn partial_entry_lists_capped_paths_and_avoids_reason_keywords() {
        let r = DependencyReport {
            shared: (0..8).map(|i| format!("shared/f{i}.md")).collect(),
            ..Default::default()
        };
        let entries = dependency_coverage_entries(&r);
        let entry = &entries[0];
        assert_eq!(entry.kind, "partial");
        assert!(entry.detail.contains("and 3 more"));
        // Mirrors hosted REASON_KEYWORDS: the label must not trigger any specific reason code.
        let banned = Regex::new(
            r"(?i)size|byte|too large|oversize|file.?cap|too many files|file.?count|file.?limit|truncat|director|unread|could not (be )?(read|open)|permission|denied|\bio\b|scanner|crash|timeout|errored|error|missing|no result|absent|not recorded",
        )
        .unwrap();
        assert!(!banned.is_match(&entry.label), "label: {}", entry.label);
    }
}
