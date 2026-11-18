//! Agent Skills format checks (https://agentskills.io/specification), reported as compatibility
//! signals. These never feed the grade: a spec violation says the package is not portable or
//! trustworthy as published, not that it is unsafe.

use crate::emission::{base_signal, RepoContext};
use crate::signal::Signal;
use crate::skill_md::validate::validate_name;
use crate::skill_md::{FrontmatterState, ParsedSkillMd};

pub(crate) const SPEC_FRONTMATTER: &str = "compatibility/spec-frontmatter";
pub(crate) const SPEC_NAME: &str = "compatibility/spec-name";
pub(crate) const SPEC_NAME_FOLDER: &str = "compatibility/spec-name-folder";

/// The skill folder's name: the caller's explicit value, else the last `bundle_path` segment.
/// `None` means the folder is unknown, so the name-to-folder check is unverified.
pub(crate) fn skill_dir_name<'a>(repo_context: &RepoContext<'a>) -> Option<&'a str> {
    repo_context
        .skill_dir_name
        .filter(|name| !name.is_empty())
        .or_else(|| {
            repo_context
                .bundle_path
                .rsplit('/')
                .find(|segment| !segment.is_empty())
        })
}

/// Whether "Name validation passed" may be attested: the frontmatter parsed, a name was
/// declared, it is valid, and it matches the verified folder. The `"unknown"` fallback never
/// validates.
pub(crate) fn name_attestable(parsed: &ParsedSkillMd, repo_context: &RepoContext<'_>) -> bool {
    parsed.frontmatter_state == FrontmatterState::Parsed
        && parsed.name_declared
        && validate_name(&parsed.name).is_none()
        && skill_dir_name(repo_context) == Some(parsed.name.as_str())
}

/// Compatibility signals for the spec violations that can be established. A name that cannot be
/// checked against its folder (no folder known) emits nothing: unverified is not a violation.
pub(crate) fn spec_signals(
    parsed: &ParsedSkillMd,
    repo_context: &RepoContext<'_>,
    observed_at: &str,
) -> Vec<Signal> {
    let info = |rule: &str, label: &str, detail: String| Signal {
        severity: Some("info".to_string()),
        detail: Some(detail),
        ..base_signal(rule, observed_at, label)
    };
    match parsed.frontmatter_state {
        FrontmatterState::Absent => {
            return vec![info(
                SPEC_FRONTMATTER,
                "SKILL.md has no YAML frontmatter",
                "The Agent Skills specification requires YAML frontmatter with a name and a description at the top of SKILL.md.".to_string(),
            )];
        }
        FrontmatterState::Unparseable => {
            return vec![info(
                SPEC_FRONTMATTER,
                "SKILL.md frontmatter is not valid YAML",
                "The frontmatter block could not be parsed as YAML, so its fields could not be checked against the Agent Skills specification.".to_string(),
            )];
        }
        FrontmatterState::Parsed => {}
    }
    let mut signals = Vec::new();
    if !parsed.name_declared {
        signals.push(info(
            SPEC_NAME,
            "Skill name is missing",
            "The Agent Skills specification requires a name in the frontmatter.".to_string(),
        ));
        return signals;
    }
    if let Some(problem) = validate_name(&parsed.name) {
        signals.push(info(
            SPEC_NAME,
            "Skill name does not follow the format specification",
            format!("{problem}. The specification allows lowercase letters, digits and single hyphens, up to 64 characters."),
        ));
    }
    if let Some(dir) = skill_dir_name(repo_context) {
        if dir != parsed.name {
            signals.push(info(
                SPEC_NAME_FOLDER,
                "Skill name does not match its folder",
                format!(
                    "The declared name is {:?} but the skill folder is {dir:?}; the specification requires them to match.",
                    parsed.name
                ),
            ));
        }
    }
    signals
}
