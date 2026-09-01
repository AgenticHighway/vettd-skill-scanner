//! Bundle-derived signal and coverage emission.

use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

use regex::Regex;
use tiktoken_rs::cl100k_base;
use yaml_rust2::Yaml;

use crate::consts::DEFAULT_SOURCE;
use crate::coverage::CoverageEntry;
use crate::language::language_for_path;
use crate::signal::Signal;
use crate::signal_rules::*;
use crate::skill_md::ParsedSkillMd;

const SCAN_SOURCE_CLASS: &str = "scan";

pub(crate) fn emit_signals(
    parsed: &ParsedSkillMd,
    all_paths: &[String],
    observed_at: &str,
) -> Vec<Signal> {
    let mut signals = vec![
        fact(
            DECLARED_LICENSE,
            "Declared license",
            scalar(&parsed.frontmatter, "license"),
            observed_at,
        ),
        primary_language(all_paths, observed_at),
        static_context_tokens(&parsed.body, observed_at),
        fact(
            DECLARED_ENVIRONMENT_ASSUMPTIONS,
            "Declared environment assumptions",
            scalar(&parsed.frontmatter, "compatibility"),
            observed_at,
        ),
    ];

    signals.extend(list_claims(
        DECLARED_EXTERNAL_SERVICES,
        "Declared external service",
        "declared_external_service",
        FRONTMATTER_DECLARED_SERVICES,
        values_for_keys(
            &parsed.frontmatter,
            &["services", "external-services", "external_services"],
        ),
        observed_at,
    ));
    signals.extend(list_claims(
        DECLARED_REQUIRED_TOOLS,
        "Declared required tool",
        "declared_tool",
        FRONTMATTER_ALLOWED_TOOLS,
        declared_tools(&parsed.frontmatter),
        observed_at,
    ));
    signals.extend(list_claims(
        DECLARED_MCP_SERVERS,
        "Declared MCP server",
        "declared_mcp_server",
        FRONTMATTER_MCP_DECLARATIONS,
        values_for_keys(
            &parsed.frontmatter,
            &["mcp", "mcp-servers", "mcp_servers", "mcpServers"],
        ),
        observed_at,
    ));
    signals.extend(list_claims(
        DECLARED_HARNESS_TARGETS,
        "Declared harness target",
        "declared_harness_target",
        FRONTMATTER_HARNESS_DECLARATIONS,
        yaml_values(&parsed.frontmatter["metadata"]["surface"]),
        observed_at,
    ));
    signals.extend(list_claims(
        DECLARED_NAME,
        "Declared skill name",
        "declared_skill_name",
        FRONTMATTER_NAME,
        non_unknown_name(&parsed.name),
        observed_at,
    ));

    signals.extend(unresolvable_internal_references(
        &parsed.body,
        all_paths,
        observed_at,
    ));
    signals
}

pub(crate) fn coverage_entries(
    findings: &[crate::finding::Finding],
    clean_internal_references: bool,
) -> Vec<CoverageEntry> {
    if findings.iter().any(|finding| {
        finding.rule_id == "VTD-0095" && finding.severity == crate::finding::Severity::Critical
    }) {
        // A package without its required definition is not a completed skill
        // scan. Do not attest partial checks or emit coverage for it.
        return Vec::new();
    }
    let mut entries = Vec::new();
    for (rule_id, label, detail) in [
        (
            "VTD-0091",
            "Secrets scan passed",
            "No secrets or unsafe code patterns were detected.",
        ),
        (
            "VTD-0092",
            "Behavioral scan passed",
            "No prompt-injection or jailbreak signals were detected.",
        ),
        (
            "VTD-0093",
            "External URL scan passed",
            "No external URLs were found in scanned skill text.",
        ),
        (
            "VTD-0099",
            "Name validation passed",
            "The declared skill name follows the supported naming rules.",
        ),
    ] {
        if findings.iter().any(|finding| {
            finding.rule_id == rule_id && finding.severity == crate::finding::Severity::Info
        }) {
            entries.push(CoverageEntry {
                kind: "attestation".to_string(),
                rule_id: rule_id.to_string(),
                label: label.to_string(),
                detail: detail.to_string(),
                category: Some("safety".to_string()),
            });
        }
    }
    if clean_internal_references {
        entries.push(CoverageEntry {
            kind: "coverage".to_string(),
            rule_id: UNRESOLVABLE_INTERNAL_REFERENCES.to_string(),
            label: "Internal reference resolution completed".to_string(),
            detail: "All body-referenced paths under references/, scripts/, and assets/ resolved in the bundle.".to_string(),
            category: Some("reliability".to_string()),
        });
    }
    entries
}

fn base_signal(rule_id: &str, observed_at: &str, label: &str) -> Signal {
    Signal {
        data_category: rule_id.split('/').next().unwrap_or_default().to_string(),
        source_class: SCAN_SOURCE_CLASS.to_string(),
        rule_id: rule_id.to_string(),
        observed_at: observed_at.to_string(),
        source: DEFAULT_SOURCE.to_string(),
        subject_type: None,
        subject_id: None,
        related_type: None,
        related_id: None,
        severity: None,
        label: Some(label.to_string()),
        detail: None,
        value_num: None,
        value_text: None,
        unit: None,
        method: None,
        derivation: None,
        confidence: None,
        sample_size: None,
        synthetic: false,
        payload: None,
    }
}

fn fact(rule_id: &str, label: &str, value: String, observed_at: &str) -> Signal {
    Signal {
        value_text: Some(value),
        derivation: Some("read".to_string()),
        ..base_signal(rule_id, observed_at, label)
    }
}

fn primary_language(all_paths: &[String], observed_at: &str) -> Signal {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for path in all_paths {
        if let Some(language) = language_for_path(path) {
            *counts.entry(language).or_default() += 1;
        }
    }
    let total: usize = counts.values().sum();
    let (language, count) = counts
        .into_iter()
        .max_by_key(|(language, count)| (*count, *language))
        .unwrap_or(("", 0));
    Signal {
        value_text: Some(language.to_string()),
        method: Some(BUNDLE_EXTENSION_SHARE.to_string()),
        derivation: Some("inferred".to_string()),
        confidence: Some(if total == 0 {
            0.0
        } else {
            count as f64 / total as f64
        }),
        ..base_signal(PRIMARY_LANGUAGE, observed_at, "Primary bundle language")
    }
}

fn static_context_tokens(body: &str, observed_at: &str) -> Signal {
    let token_count = cl100k_base()
        .expect("cl100k_base tokenizer must initialise from embedded ranks")
        .encode_with_special_tokens(body)
        .len();
    Signal {
        value_num: Some(token_count as f64),
        method: Some(CL100K_SKILL_MD_BODY.to_string()),
        ..base_signal(STATIC_CONTEXT_TOKENS, observed_at, "Static context tokens")
    }
}

fn list_claims(
    rule_id: &str,
    label: &str,
    related_type: &str,
    method: &str,
    values: Vec<String>,
    observed_at: &str,
) -> Vec<Signal> {
    if values.is_empty() {
        return vec![Signal {
            value_num: Some(0.0),
            method: Some(method.to_string()),
            ..base_signal(rule_id, observed_at, label)
        }];
    }
    values
        .into_iter()
        .map(|value| Signal {
            related_type: Some(related_type.to_string()),
            related_id: Some(value),
            value_num: Some(1.0),
            method: Some(method.to_string()),
            ..base_signal(rule_id, observed_at, label)
        })
        .collect()
}

fn unresolvable_internal_references(
    body: &str,
    all_paths: &[String],
    observed_at: &str,
) -> Vec<Signal> {
    let referenced = internal_references(body);
    let available: BTreeSet<&str> = all_paths.iter().map(String::as_str).collect();
    let missing: Vec<String> = referenced
        .into_iter()
        .filter(|path| !available.contains(path.as_str()))
        .collect();
    if missing.is_empty() {
        return Vec::new();
    }
    vec![Signal {
        severity: Some("medium".to_string()),
        detail: Some(format!(
            "Unresolvable internal path(s): {}",
            missing.join(", ")
        )),
        ..base_signal(
            UNRESOLVABLE_INTERNAL_REFERENCES,
            observed_at,
            "Unresolvable internal references",
        )
    }]
}

pub(crate) fn has_unresolvable_internal_references(body: &str, all_paths: &[String]) -> bool {
    !unresolvable_internal_references(body, all_paths, "").is_empty()
}

pub(crate) fn has_internal_references(body: &str) -> bool {
    !internal_references(body).is_empty()
}

fn internal_references(body: &str) -> Vec<String> {
    static REFERENCE_RE: OnceLock<Regex> = OnceLock::new();
    let re = REFERENCE_RE.get_or_init(|| {
        Regex::new(r"(?:references|scripts|assets)/[A-Za-z0-9._/-]+")
            .expect("valid internal-reference regex")
    });
    re.find_iter(body)
        .map(|matched| matched.as_str().trim_end_matches('/').to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn scalar(frontmatter: &Yaml, key: &str) -> String {
    yaml_scalar(&frontmatter[key]).unwrap_or_default()
}

fn values_for_keys(frontmatter: &Yaml, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .flat_map(|key| yaml_values(&frontmatter[*key]))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn declared_tools(frontmatter: &Yaml) -> Vec<String> {
    ["allowed-tools", "tools"]
        .iter()
        .flat_map(|key| match &frontmatter[*key] {
            Yaml::String(value) => split_tool_scalar(value),
            value => yaml_values(value),
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn yaml_values(value: &Yaml) -> Vec<String> {
    match value {
        Yaml::Array(items) => items
            .iter()
            .filter_map(yaml_scalar)
            .filter(|value| !value.is_empty())
            .collect(),
        value => yaml_scalar(value)
            .filter(|value| !value.is_empty())
            .into_iter()
            .collect(),
    }
}

fn yaml_scalar(value: &Yaml) -> Option<String> {
    match value {
        Yaml::String(value) => Some(value.trim().to_string()),
        Yaml::Integer(value) => Some(value.to_string()),
        Yaml::Real(value) => Some(value.clone()),
        Yaml::Boolean(value) => Some(value.to_string()),
        Yaml::Null => Some(String::new()),
        _ => None,
    }
}

fn split_tool_scalar(value: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    for character in value.chars() {
        match character {
            '(' => {
                depth += 1;
                current.push(character);
            }
            ')' => {
                depth = depth.saturating_sub(1);
                current.push(character);
            }
            ',' if depth == 0 => push_tool(&mut values, &mut current),
            whitespace if whitespace.is_whitespace() && depth == 0 => {
                push_tool(&mut values, &mut current)
            }
            _ => current.push(character),
        }
    }
    push_tool(&mut values, &mut current);
    values
}

fn push_tool(values: &mut Vec<String>, current: &mut String) {
    let value = current.trim();
    if !value.is_empty() {
        values.push(value.to_string());
    }
    current.clear();
}

fn non_unknown_name(name: &str) -> Vec<String> {
    (name != "unknown" && !name.is_empty())
        .then(|| vec![name.to_string()])
        .unwrap_or_default()
}
