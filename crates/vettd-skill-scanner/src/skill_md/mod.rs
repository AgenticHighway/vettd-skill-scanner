pub(crate) mod body;
pub(crate) mod validate;

use yaml_rust2::{Yaml, YamlLoader};

/// frontmatter fields and body extracted from a `SKILL.md` file.
pub(crate) struct ParsedSkillMd {
    /// value of the `name:` field; `"unknown"` if absent or unparseable.
    pub(crate) name: String,
    /// value of the `description:` field; empty string if absent.
    pub(crate) description: String,
    /// value of the `repository:` field; empty string if absent.
    pub(crate) repository: String,
    /// the whole frontmatter document, so nested objects and list values
    /// (`metadata.author`, declared harness targets, required tools) are
    /// reachable. `Yaml::BadValue` when there is no parseable frontmatter;
    /// indexing into it then yields `BadValue` rather than panicking.
    ///
    /// No built-in rule reads this yet — consuming these fields is
    /// explicitly out of scope for the change that introduced it (#11).
    #[allow(dead_code)]
    pub(crate) frontmatter: Yaml,
    /// everything after the closing `---` fence, with leading blank lines stripped.
    pub(crate) body: String,
}

/// Parse a SKILL.md string into its frontmatter fields and body.
///
/// The frontmatter block is parsed as real YAML, so nested objects, list
/// values, block scalars, comments and quoting all behave per the spec.
/// If the block is not valid YAML the parse falls back to a lenient
/// line-scan of `key: value` pairs, which is how every skill was read
/// before real YAML parsing landed — invalid frontmatter keeps yielding
/// whatever scalars can be recovered rather than reading as absent.
pub(crate) fn parse_skill_md(content: &str) -> ParsedSkillMd {
    let empty = ParsedSkillMd {
        name: "unknown".to_string(),
        description: String::new(),
        repository: String::new(),
        frontmatter: Yaml::BadValue,
        body: content.to_string(),
    };

    if !content.starts_with("---\n") {
        return empty;
    }
    let rest = &content[4..]; // skip opening "---\n"

    let close_seq = "\n---";
    let Some(close_pos) = rest.find(close_seq) else {
        return empty;
    };

    let after_dashes = &rest[close_pos + close_seq.len()..];
    let trimmed_after = after_dashes.trim_start_matches([' ', '\t']);
    if !trimmed_after.is_empty()
        && !trimmed_after.starts_with('\n')
        && !trimmed_after.starts_with('\r')
    {
        return empty;
    }

    let raw = &rest[..close_pos];
    let body = if let Some(stripped) = trimmed_after.strip_prefix('\n') {
        stripped.trim_start_matches('\n').to_string()
    } else {
        String::new()
    };

    let doc = match YamlLoader::load_from_str(raw) {
        Ok(mut docs) if !docs.is_empty() => Some(docs.remove(0)),
        // Valid YAML, but an empty frontmatter block — no fields to read.
        Ok(_) => Some(Yaml::Null),
        Err(_) => None,
    };

    let (name, description, repository, frontmatter) = match doc {
        Some(doc) => {
            let field = |key: &str, default: &str| {
                scalar_to_string(&doc[key]).unwrap_or_else(|| default.to_string())
            };
            let name = field("name", "unknown");
            let description = field("description", "");
            let repository = field("repository", "");
            (name, description, repository, doc)
        }
        // Not valid YAML — recover what the pre-YAML line-scan would have
        // found so malformed frontmatter degrades instead of reading as
        // absent. The document itself stays unavailable.
        None => {
            let (name, description, repository) = parse_frontmatter_lenient(raw);
            (name, description, repository, Yaml::BadValue)
        }
    };

    ParsedSkillMd {
        name,
        description,
        repository,
        frontmatter,
        body,
    }
}

/// Render a YAML scalar as the string the frontmatter fields expect.
///
/// Non-scalars (lists, nested maps) and absent keys yield `None` so the
/// caller keeps its default — a list-valued `description:` is not a
/// description. `null` yields the empty string, matching a bare `key:`.
fn scalar_to_string(node: &Yaml) -> Option<String> {
    let s = match node {
        Yaml::String(s) => s.trim().to_string(),
        Yaml::Integer(i) => i.to_string(),
        Yaml::Real(r) => r.clone(),
        Yaml::Boolean(b) => b.to_string(),
        Yaml::Null => String::new(),
        _ => return None,
    };
    Some(s)
}

/// The pre-YAML frontmatter reader, kept as the fallback for blocks that
/// are not valid YAML. Scans top-level `key: value` pairs, joining an
/// indented continuation block into a single space-separated value.
fn parse_frontmatter_lenient(raw: &str) -> (String, String, String) {
    let mut name = "unknown".to_string();
    let mut description = String::new();
    let mut repository = String::new();

    let fm_lines: Vec<&str> = raw.lines().collect();
    let mut idx = 0;
    while idx < fm_lines.len() {
        let line = fm_lines[idx];
        if line.starts_with(' ') || line.starts_with('\t') {
            idx += 1;
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            idx += 1;
            continue;
        }
        let Some(colon_pos) = trimmed.find(':') else {
            idx += 1;
            continue;
        };
        let key = trimmed[..colon_pos].trim();
        let inline_value = trimmed[colon_pos + 1..].trim();
        idx += 1;

        let value: String = if !inline_value.is_empty() {
            strip_quotes(inline_value).to_string()
        } else {
            let indent = line.len() - line.trim_start().len();
            let mut block: Vec<&str> = Vec::new();
            while idx < fm_lines.len() {
                let child = fm_lines[idx];
                if child.trim().is_empty() {
                    block.push(child);
                    idx += 1;
                    continue;
                }
                let child_indent = child.len() - child.trim_start().len();
                if child_indent <= indent {
                    break;
                }
                block.push(child);
                idx += 1;
            }
            block
                .iter()
                .filter(|l| !l.trim().is_empty())
                .map(|l| l.trim())
                .collect::<Vec<_>>()
                .join(" ")
        };

        match key {
            "name" => name = value,
            "description" => description = value,
            "repository" => repository = value,
            _ => {}
        }
    }

    (name, description, repository)
}

fn strip_quotes(s: &str) -> &str {
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_frontmatter_fields() {
        let input = "---\nname: my-skill\ndescription: Does a thing.\nrepository: https://github.com/x/y\n---\n# Body\nSome content.";
        let parsed = parse_skill_md(input);
        assert_eq!(parsed.name, "my-skill");
        assert_eq!(parsed.description, "Does a thing.");
        assert_eq!(parsed.repository, "https://github.com/x/y");
        assert!(parsed.body.contains("Body"));
    }

    #[test]
    fn no_frontmatter_returns_unknown_name() {
        let input = "# Just a plain document\nNo frontmatter here.";
        let parsed = parse_skill_md(input);
        assert_eq!(parsed.name, "unknown");
        assert!(parsed.description.is_empty());
        assert_eq!(parsed.body, input);
    }

    #[test]
    fn strips_leading_blank_lines_from_body() {
        let input = "---\nname: test\n---\n\n\n# Start";
        let parsed = parse_skill_md(input);
        assert!(
            !parsed.body.starts_with('\n'),
            "leading blank lines should be stripped"
        );
    }

    #[test]
    fn quoted_values_are_unquoted() {
        let input = "---\nname: \"my-skill\"\ndescription: 'does stuff'\n---\n";
        let parsed = parse_skill_md(input);
        assert_eq!(parsed.name, "my-skill");
        assert_eq!(parsed.description, "does stuff");
    }

    #[test]
    fn block_scalar_description_joined() {
        let input = "---\nname: test\ndescription:\n  A longer\n  description here.\n---\n";
        let parsed = parse_skill_md(input);
        assert!(parsed.description.contains("A longer"));
        assert!(parsed.description.contains("description here."));
    }

    #[test]
    fn malformed_close_fence_returns_unknown() {
        // "---x" inline with other chars is not a valid close fence.
        let input = "---\nname: test\n---x\n# body";
        let parsed = parse_skill_md(input);
        assert_eq!(parsed.name, "unknown");
    }

    // ── Real YAML frontmatter (#11) ──────────────────────────────────────

    #[test]
    fn nested_objects_are_reachable() {
        // Public catalogs put author/version under `metadata:`. These parsed
        // as unreachable before, so nothing downstream could read them.
        let input =
            "---\nname: test\nmetadata:\n  author: jane\n  version: 1.2\n---\n# Body";
        let parsed = parse_skill_md(input);
        assert_eq!(parsed.frontmatter["metadata"]["author"].as_str(), Some("jane"));
        assert!(
            !parsed.frontmatter["metadata"]["version"].is_badvalue(),
            "nested version must be reachable, not absent"
        );
    }

    #[test]
    fn list_values_parse_as_sequences() {
        // Declared harness targets / required tools are list-shaped; the
        // pre-YAML scan flattened them into a single string.
        let input = "---\nname: test\ntools:\n  - Read\n  - Bash\nflow: [a, b]\n---\n";
        let parsed = parse_skill_md(input);
        let tools = parsed.frontmatter["tools"].as_vec().expect("tools is a list");
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].as_str(), Some("Read"));
        assert_eq!(parsed.frontmatter["flow"].as_vec().map(Vec::len), Some(2));
    }

    #[test]
    fn folded_block_scalar_description_is_read() {
        // The headline defect: `description: >-` made the pre-YAML scan treat
        // ">-" as the whole inline value, so a well-formed skill read as
        // having a 2-character description and tripped the brevity checks.
        let input = "---\nname: test\ndescription: >-\n  Use this skill when\n  reviewing pull requests.\n---\n";
        let parsed = parse_skill_md(input);
        assert_eq!(
            parsed.description,
            "Use this skill when reviewing pull requests."
        );
    }

    #[test]
    fn literal_block_scalar_keeps_line_structure() {
        // `|` is literal: newlines are content, not folded to spaces.
        let input = "---\nname: test\ndescription: |\n  line one\n  line two\n---\n";
        let parsed = parse_skill_md(input);
        assert_eq!(parsed.description, "line one\nline two");
    }

    #[test]
    fn comments_are_not_part_of_scalar_values() {
        let input = "---\nname: my-skill # trailing comment\n---\n";
        let parsed = parse_skill_md(input);
        assert_eq!(parsed.name, "my-skill");
    }

    #[test]
    fn list_valued_description_is_treated_as_absent() {
        // A list is not a description; yielding "" makes the description-present
        // check fire rather than scoring a flattened "- one - two" string.
        let input = "---\nname: test\ndescription:\n  - one\n  - two\n---\n";
        let parsed = parse_skill_md(input);
        assert!(parsed.description.is_empty());
    }

    #[test]
    fn invalid_yaml_degrades_to_lenient_scan() {
        // Invalid frontmatter must keep yielding whatever scalars can be
        // recovered. Reading it as absent would flip these skills to
        // "missing frontmatter" — a regression outside the permitted set.
        let input = "---\nname: my-skill\ndescription: \"unterminated\n---\n# Body";
        let parsed = parse_skill_md(input);
        assert_eq!(parsed.name, "my-skill");
        assert!(
            parsed.frontmatter.is_badvalue(),
            "no document is available when the block is not valid YAML"
        );
        assert!(parsed.body.contains("Body"), "body extraction is unaffected");
    }

    #[test]
    fn body_and_fence_handling_are_independent_of_yaml() {
        // Fence detection is deliberately unchanged: findings that do not
        // depend on frontmatter parsing must stay byte-identical.
        let input = "---\nname: test\nmetadata:\n  author: jane\n---\n\n\n# Start\ntext";
        let parsed = parse_skill_md(input);
        assert_eq!(parsed.body, "# Start\ntext");
    }
}
