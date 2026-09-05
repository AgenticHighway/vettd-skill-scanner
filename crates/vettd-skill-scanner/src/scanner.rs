use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;

use crate::checks::behavioral::scan_behavioral_patterns;
use crate::checks::chains::{detect_exfiltration_chains, detect_malicious_activity_chains};
use crate::checks::description::check_description_behavior_mismatch;
use crate::checks::encoding::{check_base64_payloads, scan_hidden_unicode};
use crate::checks::sensitive::{scan_entropy, scan_env_files, scan_sensitive_patterns};
use crate::checks::typosquat::check_typosquat;
use crate::consts::{DEFAULT_SOURCE, EVAL_JSON_CANDIDATES};
use crate::emission::{
    coverage_entries, emit_signals, has_internal_references, has_unresolvable_internal_references,
    ReclassifiedAnalysis, RepoContext,
};
use crate::finding::{Finding, FindingCategory, Severity};
use crate::result::SkillScanResult;
use crate::rules::*;
use crate::skill_md::body::{
    has_checklist, has_cli_hint, has_examples, has_external_url, has_gotchas, has_usage_context,
    has_validation, has_workflow, is_likely_cli_script,
};
use crate::skill_md::validate::validate_name;
use crate::skill_md::{parse_skill_md, ParsedSkillMd};

/// Error returned when a scan cannot be performed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    /// The caller-supplied `observed_at` is not a valid RFC 3339 timestamp.
    ///
    /// The value is copied onto every emitted signal, where a malformed value
    /// would fail validation of the entire scanner job response. The shim
    /// supplies its own valid timestamp; a first-party CLI supplies its own.
    InvalidObservedAt(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::InvalidObservedAt(value) => {
                write!(
                    f,
                    "observed_at is not a valid RFC 3339 timestamp: {value:?}"
                )
            }
        }
    }
}

impl std::error::Error for ScanError {}

/// Scan a single skill package and return findings.
///
/// # Arguments
///
/// - `text_files` — map of normalized relative paths to decoded UTF-8 content.
///   Binary files must be excluded by the caller. Keyed by the same paths that
///   appear in `all_paths`.
/// - `all_paths` — complete list of normalized relative paths in the package,
///   including binary files. Used for structural presence checks.
/// - `observed_at` — caller-supplied RFC3339 time at which this bundle was
///   observed. Signals carry it unmodified; the pure scanner never reads a clock.
///
/// This function performs no filesystem I/O. The caller is responsible for
/// loading files from disk (or a zip, or a network source) and building the
/// input maps.
///
/// # Ordering guarantee
///
/// Chain detection runs as the final internal step and may mutate `severity` on
/// existing findings. The returned `SkillScanResult.findings` slice already
/// reflects any chain-detection mutations; callers must not reorder this step.
pub fn scan_skill(
    text_files: &HashMap<String, String>,
    all_paths: &[String],
    observed_at: &str,
) -> Result<SkillScanResult, ScanError> {
    scan_skill_with_repo_context(text_files, all_paths, &RepoContext::default(), observed_at)
}

/// Same as [`scan_skill`], but also resolves internal references that fall outside the skill's
/// own bundle against the wider repository (see [`RepoContext`]) — shared content several skills
/// draw from that lives above or alongside the skill's own directory rather than inside it. Use
/// this when the caller knows the skill's position within a larger repository (a GitHub directory
/// import); use [`scan_skill`] when it doesn't (a bare zip upload, a local directory with no repo
/// concept) — passing [`RepoContext::default`] here is equivalent to calling [`scan_skill`].
pub fn scan_skill_with_repo_context(
    text_files: &HashMap<String, String>,
    all_paths: &[String],
    repo_context: &RepoContext<'_>,
    observed_at: &str,
) -> Result<SkillScanResult, ScanError> {
    if !crate::rfc3339::is_valid_rfc3339(observed_at) {
        return Err(ScanError::InvalidObservedAt(observed_at.to_string()));
    }
    let mut findings: Vec<Finding> = Vec::new();
    // Analysis values feeding the reclassified quality/characteristics/
    // compatibility signals — computed where the old finding pushes lived so
    // the emission step stays a pure render of these booleans/counts. All
    // signals gate on content presence at emission time, so the defaults here
    // are harmless for path-only SKILL.md scans.
    let mut reclassified = ReclassifiedAnalysis::default();

    // ── Structural presence flags ────────────────────────────────────────────

    let has_skill_md = text_files.contains_key("SKILL.md")
        || text_files.contains_key("skill.md")
        || all_paths.iter().any(|p| p == "SKILL.md" || p == "skill.md");

    let has_scripts = all_paths.iter().any(|p| p.starts_with("scripts/"));
    let has_references = all_paths.iter().any(|p| p.starts_with("references/"));
    let has_evals = all_paths.iter().any(|p| {
        p.starts_with("evals/")
            || p.starts_with("tests/")
            || p.starts_with("test/")
            || matches!(p.as_str(), "evals.json" | "evals.yaml" | "evals.yml")
    });
    let has_assets = all_paths.iter().any(|p| p.starts_with("assets/"));

    macro_rules! f {
        ($rule:expr, $cat:expr, $sev:expr, $label:expr, $detail:expr) => {
            Finding {
                rule_id: $rule.to_string(),
                category: $cat,
                severity: $sev,
                label: $label.to_string(),
                detail: $detail,
                filepath: None,
                owasp_llm_category: None,
                chain_id: None,
                intent: None,
                source: DEFAULT_SOURCE.to_string(),
            }
        };
    }

    let skill_key = if text_files.contains_key("SKILL.md") {
        "SKILL.md"
    } else {
        "skill.md"
    };
    let parsed = text_files
        .get(skill_key)
        .map(|content| parse_skill_md(content))
        .unwrap_or_else(|| ParsedSkillMd {
            name: "unknown".to_string(),
            description: String::new(),
            repository: String::new(),
            frontmatter: yaml_rust2::Yaml::BadValue,
            body: String::new(),
        });

    // ── Structure checks ─────────────────────────────────────────────────────
    //
    // #941 audit: the pass/info variants of these checks travel on the
    // coverage channel and result flags instead of the finding channel.
    // VTD-0091/0092/0093/0099-pass are attestations emitted as coverage
    // entries below. VTD-0095–0098 and VTD-0118 are structural coverage notices
    // already represented by result flags (has_skill_md / has_scripts /
    // has_references / has_assets / has_evals) and the failures of VTD-0095 /
    // VTD-0099 remain real findings. The duplicated info findings were removed
    // once downstream coverage wiring was validated.

    if !has_skill_md {
        findings.push(f!(
            RULE_SKILL_MD,
            FindingCategory::Structure,
            Severity::Critical,
            "SKILL.md missing",
            "Every skill must contain a SKILL.md file with YAML frontmatter and instructions"
                .to_string()
        ));
    }

    // ── SKILL.md-gated checks ────────────────────────────────────────────────

    if has_skill_md {
        check_typosquat(&parsed.name, &mut findings);

        if let Some(err) = validate_name(&parsed.name) {
            findings.push(f!(
                RULE_SKILL_NAME_VALIDITY,
                FindingCategory::Structure,
                Severity::Critical,
                "Invalid name field",
                err.to_string()
            ));
        }
        // A valid name is a pass attestation on the coverage channel
        // (VTD-0099), not a finding — see coverage_entries().

        // Name collision check (VTD-0100)
        const WELL_KNOWN_SKILL_NAMES: &[&str] = &[
            "frontend-design",
            "pdf",
            "web-perf",
            "web-design-guidelines",
            "find-skills",
            "agent-browser",
            "agent-customization",
            "cloudflare",
            "durable-objects",
            "workers-best-practices",
            "wrangler",
            "sandbox-sdk",
            "next-best-practices",
            "vercel-react-best-practices",
            "rust-best-practices",
            "postgresql-optimization",
            "prisma-postgres",
            "aws-skills",
            "powershell-windows",
            "cosmosdb-best-practices",
            "excel",
            "word",
            "powerpoint",
            "git",
            "docker",
            "kubernetes",
            "terraform",
            "ansible",
        ];
        if WELL_KNOWN_SKILL_NAMES.contains(&parsed.name.as_str()) {
            findings.push(f!(
                RULE_SKILL_NAME_COLLISION,
                FindingCategory::BestPractices,
                Severity::Medium,
                "Skill name collides with well-known skill",
                format!(
                    "{:?} matches a well-known skill name — may cause unintended invocation",
                    parsed.name
                )
            ));
        }

        // Repository link check (VTD-0083 → characteristics/repository-link fact).
        // The absent state ("no repository field") is a fact now, not an info
        // finding — presence itself is characteristic information.
        reclassified.repository_present = !parsed.repository.is_empty();

        // System prompt leakage check (VTD-0085)
        {
            static PROMPT_LEAK_RE: OnceLock<Regex> = OnceLock::new();
            let prompt_leak_re = PROMPT_LEAK_RE.get_or_init(|| {
                Regex::new(r"(?i)\b(?:print|log|echo|output|return|display|show|reveal|dump)\s+(?:the\s+|your\s+|my\s+)?(?:system\s+)?(?:prompt|instructions?|system\s+message|internal\s+(?:prompt|instructions?))\b")
                    .expect("bad prompt leak re")
            });
            let skill_md_raw = text_files.get(skill_key).map(|s| s.as_str()).unwrap_or("");
            if prompt_leak_re.is_match(skill_md_raw) {
                findings.push(Finding {
                    rule_id: RULE_SYSTEM_PROMPT_LEAKAGE.to_string(),
                    category: FindingCategory::Security,
                    severity: Severity::Medium,
                    label: "System prompt leakage risk".to_string(),
                    detail: "Skill instructs agent to output or reveal system prompt/instructions"
                        .to_string(),
                    filepath: None,
                    owasp_llm_category: None,
                    chain_id: None,
                    intent: None,
                    source: DEFAULT_SOURCE.to_string(),
                });
            }
        }

        // Description checks (VTD-0109..0113 → reclassified signals).
        // The analysis still runs here; the emitters consume the results.
        reclassified.description_present = !parsed.description.is_empty();
        if !parsed.description.is_empty() {
            reclassified.description_char_count = parsed.description.chars().count();
            reclassified.description_usage_context = has_usage_context(&parsed.description);
            reclassified.description_word_count = parsed.description.split_whitespace().count();

            {
                static OVERCLAIM_RE: OnceLock<Regex> = OnceLock::new();
                let overclaim_re = OVERCLAIM_RE.get_or_init(|| {
                    Regex::new(r"(?i)\b(?:anything|everything|all\s+(?:files?|data|tasks?|requests?|inputs?|things?)|any\s+(?:file|task|request|input|thing)|whatever)\b")
                        .expect("bad overclaim re")
                });
                reclassified.description_overclaimed = overclaim_re.is_match(&parsed.description);
            }
        }

        // Body quality checks (VTD-0101 removed; VTD-0102..0108 → reclassified
        // signals). Body *line* count (VTD-0101) is superseded by the
        // performance/static-context-tokens measurement, so it is dropped
        // entirely.
        if !parsed.body.trim().is_empty() {
            reclassified.body_present = true;
            reclassified.gotchas_section = has_gotchas(&parsed.body);
            reclassified.examples = has_examples(&parsed.body);
            reclassified.checklist_pattern = has_checklist(&parsed.body);
            reclassified.step_by_step_workflow = has_workflow(&parsed.body);
            reclassified.validation_loop = has_validation(&parsed.body);

            let body_refs_files = parsed.body.contains("references/")
                || parsed.body.contains("scripts/")
                || parsed.body.contains("assets/")
                || {
                    static READ_MD_RE: OnceLock<Regex> = OnceLock::new();
                    let re = READ_MD_RE
                        .get_or_init(|| Regex::new(r"(?i)read.*\.md").expect("bad read md re"));
                    re.is_match(&parsed.body)
                };
            reclassified.progressive_disclosure =
                body_refs_files && (has_references || has_scripts || has_assets);

            const GENERIC_PHRASES: &[&str] = &[
                "follow best practices",
                "handle errors appropriately",
                "use proper",
                "ensure quality",
            ];
            let body_lower = parsed.body.to_lowercase();
            // VTD-0108 fired once per matched phrase (0-4x). The signal is one
            // row whose detail states the count — see emission.
            reclassified.generic_instruction_count = GENERIC_PHRASES
                .iter()
                .filter(|phrase| body_lower.contains(**phrase))
                .count();
        }
    }

    // ── Scripts checks (VTD-0114..0117 → reclassified signals) ───────────────
    // Aggregated per-skill: the script-derived signals describe the scripts/
    // interface as a whole, so "present" means ANY analyzed CLI script has the
    // attribute. When no CLI script exists there is no interface to describe —
    // the four compatibility signals are skipped entirely (`scripts_analyzed`),
    // matching the finding-block structure they replace.

    if has_scripts {
        let mut script_files: Vec<(&str, &str)> = text_files
            .iter()
            .filter(|(p, c)| is_likely_cli_script(p, c))
            .map(|(p, c)| (p.as_str(), c.as_str()))
            .collect();
        script_files.sort_by_key(|(p, _)| *p);

        static INTERACTIVE_RE: OnceLock<Regex> = OnceLock::new();
        static STRUCTURED_RE: OnceLock<Regex> = OnceLock::new();
        let interactive_re = INTERACTIVE_RE.get_or_init(|| {
            Regex::new(r"(?i)input\s*\(|readline|prompt\s*\(|inquirer").expect("bad interactive re")
        });
        let structured_re = STRUCTURED_RE.get_or_init(|| {
            Regex::new(r"(?i)json\.dumps|JSON\.stringify|\.to_json|\.to_csv|csv\.writer")
                .expect("bad structured re")
        });
        static DEP_RE: OnceLock<Regex> = OnceLock::new();
        let dep_re = DEP_RE.get_or_init(|| {
            Regex::new(r"(?i)dependencies\s*=\s*\[|require\(|import\s").expect("bad dep re")
        });

        reclassified.scripts_analyzed = !script_files.is_empty();
        for (_, content) in &script_files {
            reclassified.script_cli_help |= has_cli_hint(content);
            reclassified.script_interactive_prompts |= interactive_re.is_match(content);
            reclassified.script_structured_output |= structured_re.is_match(content);
            let has_pinned_deps = dep_re.is_match(content);
            reclassified.script_unpinned_dependencies |=
                has_pinned_deps && content.contains(">=") && !content.contains('<');
        }
    }

    // ── Security scan ────────────────────────────────────────────────────────

    let (sensitive_findings, secrets_check_failed_pat) = scan_sensitive_patterns(text_files);
    findings.extend(sensitive_findings);

    scan_entropy(text_files, &mut findings);
    scan_env_files(text_files, &mut findings);

    let secrets_check_failed = secrets_check_failed_pat
        || findings.iter().any(|f| {
            f.category == FindingCategory::Security
                && matches!(f.severity, Severity::Critical | Severity::High)
        });

    let (base64_secrets_failed, base64_behavioral_failed) =
        check_base64_payloads(text_files, &mut findings);

    let secrets_check_passed = !secrets_check_failed && !base64_secrets_failed;

    let (behavioral_findings, behavioral_check_failed) = scan_behavioral_patterns(text_files);
    findings.extend(behavioral_findings);

    let behavioral_check_passed = !behavioral_check_failed && !base64_behavioral_failed;

    scan_hidden_unicode(text_files, &mut findings);

    // External URL check. A found external URL stays a Medium finding; a clean
    // scan is a pass attestation on the coverage channel (VTD-0093), not a
    // finding — see coverage_entries().
    let url_target_files: Vec<(&str, &str)> = {
        let mut targets: Vec<(&str, &str)> = Vec::new();
        for name in &["SKILL.md", "skill.md"] {
            if let Some(c) = text_files.get(*name) {
                targets.push((name, c.as_str()));
            }
        }
        let mut refs: Vec<(&str, &str)> = text_files
            .iter()
            .filter(|(p, _)| p.to_lowercase().starts_with("references/"))
            .map(|(p, c)| (p.as_str(), c.as_str()))
            .collect();
        refs.sort_by_key(|(p, _)| *p);
        targets.extend(refs);
        targets
    };

    let external_urls_clean = if url_target_files.is_empty() {
        false
    } else {
        let url_file = url_target_files.iter().find(|(_, c)| has_external_url(c));
        if let Some((path, _)) = url_file {
            findings.push(Finding {
                rule_id: RULE_EXTERNAL_URL_REFERENCE.to_string(),
                category: FindingCategory::Security,
                severity: Severity::Medium,
                label: "References external URL — review for indirect prompt injection risk"
                    .to_string(),
                detail: format!(
                    "External URL(s) detected in {path} — referenced content can change after audit"
                ),
                filepath: Some(path.to_string()),
                owasp_llm_category: None,
                chain_id: None,
                intent: None,
                source: DEFAULT_SOURCE.to_string(),
            });
            false
        } else {
            true
        }
    };

    // ── Evals quality check (VTD-0119..0123 → reclassified signals) ─────────

    if has_evals {
        reclassified.evals_present = true;
        let eval_json_content = EVAL_JSON_CANDIDATES
            .iter()
            .find_map(|&candidate| text_files.get(candidate));

        let eval_json_found = eval_json_content.is_some();

        if let Some(json_str) = eval_json_content {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) {
                let evals = val
                    .get("evals")
                    .or_else(|| val.get("tests"))
                    .or_else(|| val.get("test_cases"))
                    .or_else(|| val.get("scenarios"))
                    .or_else(|| val.get("cases"))
                    .or_else(|| val.get("examples"))
                    .and_then(|v| v.as_array())
                    .or_else(|| val.as_array());

                if let Some(cases) = evals.filter(|a| !a.is_empty()) {
                    reclassified.eval_case_count = Some(cases.len());

                    reclassified.eval_has_assertions = cases.iter().any(|e| {
                        (e.get("assertions")
                            .and_then(|v| v.as_array())
                            .map(|a| !a.is_empty())
                            .unwrap_or(false))
                            || (e
                                .get("criteria")
                                .and_then(|v| v.as_array())
                                .map(|a| !a.is_empty())
                                .unwrap_or(false))
                            || (e
                                .get("pass_criteria")
                                .and_then(|v| v.as_array())
                                .map(|a| !a.is_empty())
                                .unwrap_or(false))
                            || e.get("expected").and_then(|v| v.as_str()).is_some()
                            || e.get("expected_output").and_then(|v| v.as_str()).is_some()
                            || e.get("golden_answer").and_then(|v| v.as_str()).is_some()
                            || e.get("rubric").and_then(|v| v.as_str()).is_some()
                    });
                }
            }
        }

        if !eval_json_found {
            let eval_dir_prefixes = ["evals/", "tests/", "test/"];
            let non_trivial_count = all_paths
                .iter()
                .filter(|p| eval_dir_prefixes.iter().any(|prefix| p.starts_with(prefix)))
                .filter(|p| {
                    let lower = p.to_lowercase();
                    lower.ends_with(".md")
                        || lower.ends_with(".yaml")
                        || lower.ends_with(".yml")
                        || lower.ends_with(".txt")
                        || lower.ends_with(".jsonl")
                        || (lower.ends_with(".json") && text_files.contains_key(p.as_str()))
                })
                .count();

            // `characteristics/eval-file-format` fact: "present" when the
            // skill ships evals in a non-JSON format, "absent" when they are
            // JSON (or no non-JSON files exist).
            reclassified.eval_non_json_files = non_trivial_count > 0;
        }
    }

    // ── Chain detection and mismatch checks ─────────────────────────────────

    detect_exfiltration_chains(&mut findings, text_files);
    detect_malicious_activity_chains(&mut findings);
    let description_for_mismatch = if has_skill_md {
        parsed.description.clone()
    } else {
        String::new()
    };
    check_description_behavior_mismatch(&description_for_mismatch, &mut findings);

    let clean_internal_references = has_internal_references(&parsed.body)
        && !has_unresolvable_internal_references(&parsed.body, all_paths, repo_context);
    let signals = emit_signals(
        &parsed,
        all_paths,
        repo_context,
        observed_at,
        text_files.contains_key(skill_key),
        &reclassified,
    );
    let coverage = coverage_entries(
        has_skill_md,
        text_files.contains_key(skill_key),
        secrets_check_passed,
        behavioral_check_passed,
        external_urls_clean,
        validate_name(&parsed.name).is_none(),
        clean_internal_references,
    );

    Ok(SkillScanResult {
        findings,
        signals,
        coverage,
        has_skill_md,
        has_scripts,
        has_references,
        has_evals,
        has_assets,
        file_count: all_paths.len(),
    })
}
