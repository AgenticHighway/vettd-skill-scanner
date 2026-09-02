//! Bundle-derived signal and coverage emission.

use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

use regex::Regex;
use tiktoken_rs::cl100k_base_singleton;
use yaml_rust2::Yaml;

use crate::consts::DEFAULT_SOURCE;
use crate::coverage::CoverageEntry;
use crate::finding::Severity;
use crate::language::language_for_path;
use crate::signal::Signal;
use crate::signal_rules::*;
use crate::skill_md::ParsedSkillMd;

const SCAN_SOURCE_CLASS: &str = "scan";

pub(crate) fn emit_signals(
    parsed: &ParsedSkillMd,
    all_paths: &[String],
    observed_at: &str,
    skill_md_content_present: bool,
) -> Vec<Signal> {
    let mut signals = emit_scalar_signals(parsed, all_paths, observed_at, skill_md_content_present);
    if skill_md_content_present {
        signals.extend(emit_declared_claims(parsed, observed_at));
    }
    signals.extend(internal_reference_signal(
        &parsed.body,
        all_paths,
        observed_at,
    ));
    signals
}

fn emit_scalar_signals(
    parsed: &ParsedSkillMd,
    all_paths: &[String],
    observed_at: &str,
    skill_md_content_present: bool,
) -> Vec<Signal> {
    if !skill_md_content_present {
        // A SKILL.md detected only through `all_paths` carries no content, so
        // frontmatter-derived facts and the body token measurement would
        // falsely claim declarations were inspected. The only bundle-derived
        // signal then is the path-derived primary language.
        return vec![primary_language(all_paths, observed_at)];
    }
    vec![
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
    ]
}

fn emit_declared_claims(parsed: &ParsedSkillMd, observed_at: &str) -> Vec<Signal> {
    let claims: [(&str, &str, &str, &str, Vec<String>); 5] = [
        (
            DECLARED_EXTERNAL_SERVICES,
            "Declared external service",
            "declared_external_service",
            FRONTMATTER_DECLARED_SERVICES,
            declared_external_services(&parsed.frontmatter),
        ),
        (
            DECLARED_REQUIRED_ENV_VARS,
            "Declared required environment variable",
            "declared_required_env_var",
            FRONTMATTER_REQUIRED_ENV_VARS,
            env_var_names(&parsed.frontmatter),
        ),
        (
            DECLARED_REQUIRED_TOOLS,
            "Declared required tool",
            "declared_tool",
            FRONTMATTER_ALLOWED_TOOLS,
            declared_tools(&parsed.frontmatter),
        ),
        (
            DECLARED_MCP_SERVERS,
            "Declared MCP server",
            "declared_mcp_server",
            FRONTMATTER_MCP_DECLARATIONS,
            values_for_keys(
                &parsed.frontmatter,
                &["mcp", "mcp-servers", "mcp_servers", "mcpServers"],
            ),
        ),
        (
            DECLARED_HARNESS_TARGETS,
            "Declared harness target",
            "declared_harness_target",
            FRONTMATTER_HARNESS_DECLARATIONS,
            yaml_values(&parsed.frontmatter["metadata"]["surface"]),
        ),
    ];
    let mut signals: Vec<Signal> = claims
        .into_iter()
        .flat_map(|(rule_id, label, related_type, method, values)| {
            list_claims(rule_id, label, related_type, method, values, observed_at)
        })
        .collect();

    // After the list_claims block: the declared name is a scalar fact, not a
    // list item — frontmatter declares at most one name, so there is no list
    // to measure. A name present is one `read` fact row; a name absent is no
    // row at all (no zero marker).
    let name_values = declared_name(parsed);
    if !name_values.is_empty() {
        signals.push(fact(
            DECLARED_NAME,
            "Declared skill name",
            name_values.into_iter().next().unwrap(),
            observed_at,
        ));
    }
    signals
}

/// Attestation entries for the four absence checks whose pass finding is
/// already an `Info` finding. `#941` audit: these are emitted on the coverage
/// channel (they describe the analysis, not the asset) and are duplicated by
/// the existing findings only until the findings are removed in a follow-up.
const ATTESTATIONS: [(&str, &str, &str); 4] = [
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
];

pub(crate) fn coverage_entries(
    findings: &[crate::finding::Finding],
    clean_internal_references: bool,
    skill_md_content_present: bool,
) -> Vec<CoverageEntry> {
    if findings
        .iter()
        .any(|finding| finding.rule_id == "VTD-0095" && finding.severity == Severity::Critical)
    {
        // A package without its required definition is not a completed skill
        // scan. Do not attest partial checks or emit coverage for it.
        return Vec::new();
    }
    let mut entries = Vec::new();
    for (rule_id, label, detail) in ATTESTATIONS {
        if rule_id == "VTD-0099" && !skill_md_content_present {
            // A SKILL.md detected only through `all_paths` carries no content
            // and no declared name; the fallback sentinel name is not a name
            // to validate. Do not attest name validation in that case.
            continue;
        }
        if findings
            .iter()
            .any(|finding| finding.rule_id == rule_id && finding.severity == Severity::Info)
        {
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
    // Reuse the crate-provided, lazily-initialised singleton tokenizer instead
    // of rebuilding the embedded ranks on every scanned skill.
    let token_count = cl100k_base_singleton()
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

fn internal_reference_signal(body: &str, all_paths: &[String], observed_at: &str) -> Vec<Signal> {
    let missing = missing_internal_references(body, all_paths);
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

/// Paths referenced in the SKILL.md body under `references/`, `scripts/`, or
/// `assets/` that are absent from `all_paths`, in deterministic order.
pub(crate) fn missing_internal_references(body: &str, all_paths: &[String]) -> Vec<String> {
    let referenced = internal_references(body);
    let available: BTreeSet<&str> = all_paths.iter().map(String::as_str).collect();
    referenced
        .into_iter()
        .filter(|path| !available.contains(path.as_str()))
        .collect()
}

pub(crate) fn has_unresolvable_internal_references(body: &str, all_paths: &[String]) -> bool {
    !missing_internal_references(body, all_paths).is_empty()
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
        .filter(|matched| is_standalone_internal_reference(body, matched))
        .map(|matched| {
            let start = path_token_start(body, matched.start());
            body[start..matched.end()]
                .trim_end_matches('/')
                .trim_end_matches(|c: char| {
                    matches!(
                        c,
                        '.' | ',' | ';' | ':' | '!' | '?' | ')' | ']' | '}' | '"' | '\''
                    )
                })
                .trim_start_matches("./")
                .trim_start_matches('/')
                .to_string()
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// The start of the path token containing `match_start`. Parent directories
/// (`src/` in `src/references/tips.md`) belong to a nested reference: walking
/// left over path characters recovers the full token instead of truncating the
/// match to its `references`/`scripts`/`assets` segment. A leading `./` or `/`
/// is a relative/absolute marker, not part of the bundle-relative path.
fn path_token_start(body: &str, match_start: usize) -> usize {
    let before = &body[..match_start];
    before
        .char_indices()
        .rev()
        .find(|(_, character)| !is_path_character(*character))
        .map(|(index, character)| index + character.len_utf8())
        .unwrap_or(0)
}

fn is_path_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '/' | '-')
}

/// A regex hit is an internal reference only when it is the whole token and is
/// not part of an external URL:
///
/// - a match that continues a longer identifier (`myassets/logo`,
///   `x-references/guide`) is a substring, not a reference to that path;
/// - a match inside a `scheme://` URL (`https://host/references/guide.md`)
///   belongs to the external resource, not the bundle.
fn is_standalone_internal_reference(body: &str, matched: &regex::Match<'_>) -> bool {
    let before = &body[..matched.start()];
    if let Some(previous) = before.chars().last() {
        if previous.is_ascii_alphanumeric() || previous == '_' || previous == '-' {
            return false;
        }
    }
    let line_start = before
        .rfind(['\n', '\r', ' '])
        .map(|index| index + 1)
        .unwrap_or(0);
    !before[line_start..].contains("://")
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

/// Declared external service dependencies from explicit `services`-family
/// frontmatter keys only. `required_environment_variables` names are a separate
/// claim emitted under `cost/declared-required-env-vars` — an env var a skill
/// needs is not itself an external service the cost model bills against.
fn declared_external_services(frontmatter: &Yaml) -> Vec<String> {
    values_for_keys(
        frontmatter,
        &["services", "external-services", "external_services"],
    )
}

/// Names from `required_environment_variables`, a list of maps each carrying a
/// `name` field (e.g. an API token the skill needs). Bare string entries are
/// accepted too. Emitted as `cost/declared-required-env-vars` items.
fn env_var_names(frontmatter: &Yaml) -> Vec<String> {
    let value = &frontmatter["required_environment_variables"];
    match value {
        Yaml::Array(items) => items
            .iter()
            .filter_map(|item| match item {
                Yaml::Hash(_) => yaml_scalar(&item["name"]),
                other => yaml_scalar(other),
            })
            .filter(|name| !name.is_empty())
            .collect(),
        value => yaml_scalar(value)
            .filter(|name| !name.is_empty())
            .into_iter()
            .collect(),
    }
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
        // Map-shaped declarations: the keys are the declared items (e.g.
        // `services: {stripe: true, sentry: false}`).
        Yaml::Hash(_) => yaml_keys(value),
        value => yaml_scalar(value)
            .filter(|value| !value.is_empty())
            .into_iter()
            .collect(),
    }
}

fn yaml_keys(value: &Yaml) -> Vec<String> {
    match value {
        Yaml::Hash(map) => map
            .keys()
            .filter_map(yaml_scalar)
            .filter(|key| !key.is_empty())
            .collect(),
        _ => Vec::new(),
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

/// The declared skill name, emitted as a scalar fact row. Key presence in real
/// frontmatter is authoritative — even a literal `"unknown"` is a declared
/// name. Only the lenient (invalid-YAML) fallback treats the `"unknown"`
/// sentinel as "absent".
fn declared_name(parsed: &ParsedSkillMd) -> Vec<String> {
    if matches!(parsed.frontmatter, Yaml::Hash(_)) {
        return yaml_scalar(&parsed.frontmatter["name"])
            .filter(|value| !value.is_empty())
            .into_iter()
            .collect();
    }
    non_unknown_name(&parsed.name)
}

fn non_unknown_name(name: &str) -> Vec<String> {
    (name != "unknown" && !name.is_empty())
        .then(|| vec![name.to_string()])
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::internal_references;

    #[test]
    fn internal_references_ignores_external_urls() {
        // `references/` inside an external URL is part of the remote resource,
        // not a bundle path — it must not be flagged as an internal reference.
        for body in [
            "Fetch https://example.com/references/guide.md for context.",
            "See [docs](https://example.com/references/guide.md) for context.",
            "The <https://example.com/assets/logo.png> asset is remote.",
            "Download https://example.com/scripts/setup.sh first.",
        ] {
            assert!(
                internal_references(body).is_empty(),
                "external URL must not yield internal references: {body:?}"
            );
        }
    }

    #[test]
    fn internal_references_ignores_prefix_substrings() {
        // A match continuing a longer identifier is a different token
        // (`myassets/logo`, `x-references/guide`, `shellscripts/run`) — the
        // regex hit is only a substring of it, not a reference to that
        // path. Excluding it prevents false "unresolvable reference" signals.
        for body in [
            "Check myassets/logo.png for the mark.",
            "See x-references/guide.md for details.",
            "Run shellscripts/run.sh to install.",
            "Consult src_assets/template.json.",
        ] {
            assert!(
                internal_references(body).is_empty(),
                "prefix substring must not yield internal references: {body:?}"
            );
        }
    }

    #[test]
    fn internal_references_still_matches_standalone_paths() {
        // Real bundle paths keep resolving, including relative and
        // nested-directory forms, and punctuation-padded sentence positions.
        let referenced = internal_references(
            "Read `references/guide.md`, then run scripts/setup.sh and ./assets/logo.png.",
        );
        for expected in ["references/guide.md", "scripts/setup.sh", "assets/logo.png"] {
            assert!(
                referenced.contains(&expected.to_string()),
                "missing internal reference {expected}: {referenced:?}"
            );
        }
        // A `src/` parent directory belongs to the nested reference — truncating
        // it to `references/tips.md` would falsely report a present file missing.
        let nested = internal_references("See src/references/tips.md for notes.");
        assert_eq!(nested, vec!["src/references/tips.md".to_string()]);
        // A multi-byte character immediately before the match must not panic
        // (byte-offset slicing) and is not an identifier continuation.
        let runic = internal_references("ᚠᛇᚻreferences/guide.md");
        assert_eq!(runic, vec!["references/guide.md".to_string()]);
    }
}
