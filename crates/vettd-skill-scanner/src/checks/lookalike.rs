//! VTD-0125 (look-alike characters) and VTD-0126 (remote unpinned code
//! execution) — the two supply-chain checks the labelled cohort showed the
//! regex scanner missing (synthesis C20, C23).
//!
//! Both scan every text file: the true cases are inline code inside
//! SKILL.md (confluence) as much as bundled scripts (huggingface). One
//! finding per rule per file, highest severity first, earliest line breaking
//! a tie — mirroring [`crate::checks::sensitive::scan_sensitive_patterns`].

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;

use crate::consts::DEFAULT_SOURCE;
use crate::finding::{Finding, FindingCategory, Intent, Severity};
use crate::rules::{RULE_LOOKALIKE_CHARACTERS, RULE_REMOTE_UNPINNED_EXECUTION};

// ─────────────────────────────── VTD-0125 ────────────────────────────────

/// Letters from scripts confusable with Latin when embedded in ASCII-shaped
/// syntax: Cyrillic, Greek, and fullwidth Latin. Latin letters with
/// diacritics (`café`, `naïve`) are deliberately NOT confusable here — they
/// are ordinary prose in many languages, and flagging them turns every
/// accented doc into a security finding. Combining marks (the NFD halves of
/// accented Latin) and fullwidth PUNCTUATION (`：`, `（`, `＋` — everyday
/// CJK typography) are likewise excluded, so NFC/NFD spellings behave
/// identically and CJK prose stays quiet.
static CONFUSABLE_CLASS: &str = concat!(
    "\\u{0370}-\\u{03FF}", // Greek
    "\\u{0400}-\\u{04FF}", // Cyrillic
    "\\u{FF21}-\\u{FF3A}", // fullwidth Latin uppercase
    "\\u{FF41}-\\u{FF5A}", // fullwidth Latin lowercase
);

fn lookalike_token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let class = format!("[{CONFUSABLE_CLASS}]");
        let pattern =
            format!(r"[A-Za-z0-9_.:/~-]*{class}[0-9A-Za-z_.:/~-]*{class}?[0-9A-Za-z_.:/~-]*");
        Regex::new(&format!("(?u){pattern}")).expect("bad lookalike token re")
    })
}

/// True when `token` is a URL/host/path/identifier-shaped span mixing ASCII
/// alphanumerics with confusable-script letters — Cyrillic `а` inside
/// `assets`, Greek `ο`, or a fullwidth letter in a Latin host.
///
/// Restriction (round 2 review): ordinary prose must never fire. Two gates
/// do that. First, accented Latin is not in the confusable class at all.
/// Second, in prose files the token must carry a URL/host/path marker
/// (`/`, `.`, `:`) — `Python-библиотека`-style hyphenated prose compounds
/// then stay quiet — or sit inside backticked code. Code files and fenced
/// code blocks are identifiers by construction, so any mixed token fires
/// there. All checks run on NFD-stripped spans: combining marks are removed
/// before classification so decomposition cannot change the verdict.
fn is_lookalike_token(token: &str, in_code_context: bool) -> bool {
    let stripped: Vec<char> = token
        .chars()
        .filter(|c| !(0x0300..=0x036F).contains(&(*c as u32)))
        .collect();
    let has_ascii = stripped.iter().any(|c| c.is_ascii_alphanumeric());
    let has_confusable = stripped.iter().any(|c| {
        let v = *c as u32;
        (0x0370..=0x03FF).contains(&v)
            || (0x0400..=0x04FF).contains(&v)
            || (0xFF21..=0xFF3A).contains(&v)
            || (0xFF41..=0xFF5A).contains(&v)
    });
    let has_marker = stripped.iter().any(|c| matches!(c, '/' | '.' | ':' | '_'));
    // 4+ chars keeps a stray single-letter splice in prose out; the
    // labelled evidence cases are hosts, paths and identifiers.
    let long_enough = stripped.len() >= 4;
    has_ascii && has_confusable && long_enough && (in_code_context || has_marker)
}

/// True when `path` holds code rather than prose: by extension, or any line
/// inside a fenced code block / backtick span of a prose file.
fn is_code_file(path: &str) -> bool {
    static CODE_EXT_RE: OnceLock<Regex> = OnceLock::new();
    let re = CODE_EXT_RE.get_or_init(|| {
        Regex::new(r"(?i)\.(?:py|sh|bash|zsh|ts|tsx|js|jsx|mjs|cjs|go|rb|rs|java|kt|php|pl|lua|r|sql|toml|ya?ml|json|cfg|ini|env|ps1|bat|cmd)$").expect("bad code ext re")
    });
    !path.contains(".md") && re.is_match(path)
}

/// The code state of one line of a markdown-ish file: inside a fenced block
/// (``` toggles) or an inline backtick span.
fn line_is_code(line: &str, fence_open: bool) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("```") {
        return true; // the fence line itself is code syntax
    }
    if fence_open {
        return true;
    }
    line.matches('`').count() % 2 == 1
}

/// Folds adjacent quoted fragments (`"do" + "cs-pipe"`) into one string so
/// a host or path split across concatenated literals is still seen. Folding
/// only *reveals* tokens for the existing mixed-script test; plain ASCII
/// concatenation alone never fires the rule.
fn fold_concat(line: &str) -> String {
    static CONCAT_RE: OnceLock<Regex> = OnceLock::new();
    let re = CONCAT_RE
        .get_or_init(|| Regex::new(r#"(?u)"([^"]*)"\s*\+\s*"([^"]*)""#).expect("bad concat re"));
    let mut folded = line.to_string();
    // Bounded: every pass removes at least the ` + ` between two fragments.
    for _ in 0..8 {
        let new = re.replace_all(&folded, "\"$1$2\"").into_owned();
        if new == folded {
            break;
        }
        folded = new;
    }
    folded
}

/// VTD-0125: look-alike or mixed-script characters in a URL, host, path or
/// code identifier, including one hidden across concatenated string
/// literals. Severity Medium: obfuscation of a destination or name is a
/// trust signal, and only a reader can judge intent.
pub(crate) fn scan_lookalike_characters(
    text_files: &HashMap<String, String>,
    findings: &mut Vec<Finding>,
) {
    let mut sorted_files: Vec<(&String, &String)> = text_files.iter().collect();
    sorted_files.sort_by_key(|(p, _)| p.as_str());
    for (path, content) in sorted_files {
        let code_file = is_code_file(path);
        let mut fence_open = false;
        let mut best: Option<usize> = None; // 0-based line of the first hit
        for (i_line, line) in content.split('\n').enumerate() {
            if !code_file && line.trim_start().starts_with("```") {
                fence_open = !fence_open;
            }
            let in_code_context = code_file || line_is_code(line, fence_open);
            // The raw line, and a folded view that rejoins `"a" + "b"`
            // fragments before tokenizing.
            let hit = [line.to_string(), fold_concat(line)]
                .into_iter()
                .any(|view| {
                    lookalike_token_re()
                        .find_iter(&view)
                        .any(|m| is_lookalike_token(m.as_str().trim_matches('"'), in_code_context))
                });
            if hit {
                best = Some(i_line);
                break;
            }
        }
        let Some(i_line) = best else { continue };
        let line = content.split('\n').nth(i_line).unwrap_or("");
        let snippet: String = line
            .chars()
            .map(|c| if c.is_ascii() { c } else { '\u{FFFD}' })
            .take(120)
            .collect();
        findings.push(Finding {
            rule_id: RULE_LOOKALIKE_CHARACTERS.to_string(),
            category: FindingCategory::Security,
            severity: Severity::Medium,
            label: "Look-alike characters in host, path or identifier".to_string(),
            detail: format!(
                "Detected in {path}:{} — mixed-script or confusable characters \
                 (non-ASCII shown as \u{FFFD}): `{snippet}`",
                i_line + 1
            ),
            filepath: Some(path.clone()),
            owasp_llm_category: None,
            chain_id: None,
            intent: Some(Intent::Negligent),
            source: DEFAULT_SOURCE.to_string(),
        });
    }
}

// ─────────────────────────────── VTD-0126 ────────────────────────────────

/// A full commit SHA: exactly 40 hex characters.
fn is_commit_sha(segment: &str) -> bool {
    segment.len() == 40 && segment.chars().all(|c| c.is_ascii_hexdigit())
}

/// A version-tag-shaped ref (`v1.2`, `1.2.3`, `2.0.0-rc1`): the shapes this
/// check treats as a pinned tag. Branch names (`main`, `master`, `develop`,
/// feature branches) never match, because a branch ref keeps moving.
fn is_version_tag(tag: &str) -> bool {
    static TAG_RE: OnceLock<Regex> = OnceLock::new();
    let re = TAG_RE.get_or_init(|| {
        Regex::new(r"^v?\d+(?:\.\d+){1,2}(?:[-.][0-9A-Za-z.-]+)?$").expect("bad tag re")
    });
    re.is_match(tag)
}

/// True when the command line pins the fetched bytes: a full commit SHA or a
/// version-tag ref. `@` only counts as a pin when it directly prefixes such
/// a ref AND is neither URL userinfo (`scheme://user@`) nor inside a
/// comment (`#` onward).
fn line_pins_revision(line: &str) -> bool {
    // Strip the comment part: an `@sha` in a comment is not a pin.
    let before_comment = line.split('#').next().unwrap_or(line);
    for (i, part) in before_comment.split_whitespace().enumerate() {
        if i > 0 && (part == "--tag" || part == "-b" || part == "--branch") {
            continue; // the flag itself; its value is checked below
        }
        if is_commit_sha(part) || is_version_tag(part) {
            return true;
        }
        // `ref@<sha-or-version-tag>`, but never URL userinfo: userinfo has a
        // URL scheme on the left of the `@` (`https://user@host`).
        if let Some(at) = part.rfind('@') {
            let (left, right) = (&part[..at], &part[at + 1..]);
            if !left.is_empty()
                && !left.contains("://")
                && (is_commit_sha(right) || is_version_tag(right))
            {
                return true;
            }
        }
    }
    // `--tag`/`-b`/`--branch` with a version-tag value, or any ref argument
    // that is itself a 40-hex SHA.
    let words: Vec<&str> = before_comment.split_whitespace().collect();
    for (i, w) in words.iter().enumerate() {
        if *w == "--tag" || *w == "-b" || *w == "--branch" {
            if let Some(value) = words.get(i + 1) {
                if is_commit_sha(value) || is_version_tag(value) {
                    return true;
                }
            }
        }
    }
    false
}

/// True when the URL pins its content: any path segment (userinfo stripped)
/// is a full commit SHA.
fn url_pins_revision(line: &str) -> bool {
    static URL_RE: OnceLock<Regex> = OnceLock::new();
    let re = URL_RE.get_or_init(|| Regex::new(r"https?://\S+").expect("bad url re"));
    re.find_iter(line).any(|m| {
        let url = m.as_str();
        // Strip `scheme://user:pass@` userinfo so an `@` in the URL can
        // never masquerade as a pin.
        let after_scheme = url.split("://").nth(1).unwrap_or(url);
        let path = match after_scheme.find('/') {
            Some(i) => &after_scheme[i..],
            None => return false,
        };
        path.split('/')
            .filter(|s| !s.is_empty())
            .any(|seg| is_commit_sha(seg.split('?').next().unwrap_or(seg)))
    })
}

/// True when `block` passes a secret into the same command or job: a
/// token-bearing header or a secret-valued assignment. Only the block
/// containing the remote run is examined — a secret mentioned elsewhere in
/// the file is co-occurrence, not flow.
fn block_passes_secret(block: &str) -> bool {
    static SECRET_RE: OnceLock<Regex> = OnceLock::new();
    let re = SECRET_RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:authorization\s*[:=]|bearer\s|token\s*[=:]|api[_-]?key\s*[=:]|secret\s*[=:]|password\s*[=:]|\bHF_TOKEN\b)"#,
        )
        .expect("bad secret re")
    });
    re.is_match(block)
}

/// The command/job block around `i_line`: the same command line plus the
/// contiguous non-blank, non-fence lines around it, capped at 40 lines. A
/// fenced code block is a job block; a shell one-liner is its own block.
fn enclosing_block(lines: &[&str], i_line: usize) -> String {
    let mut block = String::new();
    for l in lines.iter().take(i_line + 1).rev().take(40) {
        let t = l.trim();
        if t.is_empty() || t.starts_with("```") {
            break;
        }
        block.push_str(l);
        block.push('\n');
    }
    for l in lines.iter().skip(i_line + 1).take(40) {
        let t = l.trim();
        if t.is_empty() || t.starts_with("```") {
            break;
        }
        block.push_str(l);
        block.push('\n');
    }
    block
}

/// VTD-0126: remote, unpinned code execution — running code whose bytes come
/// from a mutable URL rather than a pinned revision (a full commit SHA or a
/// version tag; branch names keep moving and are not pins). High: the code a
/// skill runs can change after review. Critical only when the same command
/// or job block passes a secret: the remote code then runs holding the
/// user's credentials.
pub(crate) fn scan_remote_unpinned_execution(
    text_files: &HashMap<String, String>,
    findings: &mut Vec<Finding>,
) {
    static UV_RUN_RE: OnceLock<Regex> = OnceLock::new();
    static REMOTE_SCRIPT_RE: OnceLock<Regex> = OnceLock::new();
    static CLONE_RE: OnceLock<Regex> = OnceLock::new();
    static PIP_R_RE: OnceLock<Regex> = OnceLock::new();
    let uv_run_re = UV_RUN_RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:uv|uvx)\s+run\s+https?://|\b(?:python3?|node|deno)\s+https?://")
            .expect("bad uv run re")
    });
    let remote_script_re = REMOTE_SCRIPT_RE.get_or_init(|| {
        Regex::new(r#"(?i)(?:curl|wget|fetch)\s+[^\n|;&]*https?://[^\s"']*(?:/raw/|/main/)[^\s"']*\s*(?:\|\s*(?:sudo\s+)?(?:sh|bash|python3?)|-[^\n]*\s*(?:sh|bash|python3?)\b)"#)
            .expect("bad remote script re")
    });
    let clone_re = CLONE_RE
        .get_or_init(|| Regex::new(r"(?i)\bgit\s+clone\s+[^\n]*https?://").expect("bad clone re"));
    let pip_r_re = PIP_R_RE.get_or_init(|| {
        Regex::new(r"(?i)\bpip3?\s+install\s+(?:-r|--requirement)\s").expect("bad pip -r re")
    });

    let mut sorted_files: Vec<(&String, &String)> = text_files.iter().collect();
    sorted_files.sort_by_key(|(p, _)| p.as_str());
    for (path, content) in sorted_files {
        let lines: Vec<&str> = content.split('\n').collect();
        let mut first_hit: Option<(usize, &'static str)> = None;
        for (i_line, line) in lines.iter().enumerate() {
            let uv_or_interpreter = uv_run_re.is_match(line);
            if (uv_or_interpreter || remote_script_re.is_match(line)) && !url_pins_revision(line) {
                first_hit = Some(if uv_or_interpreter {
                    (i_line, "a `uv`/`uvx` or interpreter run of a remote URL")
                } else {
                    (
                        i_line,
                        "a script fetched from a mutable `/raw/` or `/main/` URL and executed",
                    )
                });
                break;
            }
            if clone_re.is_match(line) && !line_pins_revision(line) {
                // Unpinned clone: fire only when requirements from the cloned
                // tree are installed nearby — `git clone` with no ref (or a
                // branch ref), then `pip install -r`. Same-line separators
                // (`&&`, `;`) count as "nearby", matching the newline form.
                let same_line_rest = line
                    .split("&&")
                    .chain(line.split(';'))
                    .any(|part| pip_r_re.is_match(part));
                let window = lines.iter().skip(i_line + 1).take(10);
                if same_line_rest || window.clone().any(|l| pip_r_re.is_match(l)) {
                    first_hit = Some((
                        i_line,
                        "an unpinned `git clone` followed by `pip install -r`",
                    ));
                    break;
                }
            }
        }
        let Some((i_line, shape)) = first_hit else {
            continue;
        };
        // Critical needs a proven same-block secret; co-occurrence anywhere
        // else in the file is not a flow.
        let escalates = block_passes_secret(&enclosing_block(&lines, i_line));
        let severity = if escalates {
            Severity::Critical
        } else {
            Severity::High
        };
        let line = lines[i_line];
        let snippet = line.trim();
        let snippet: String = snippet.chars().take(120).collect();
        findings.push(Finding {
            rule_id: RULE_REMOTE_UNPINNED_EXECUTION.to_string(),
            category: FindingCategory::Security,
            severity,
            label: "Remote unpinned code execution".to_string(),
            detail: format!(
                "Detected in {path}:{} — {shape}: `{snippet}`. The fetched code \
                 is not pinned to an immutable revision (a commit SHA or a \
                 version tag; branch refs keep moving) and can change after \
                 audit{}.",
                i_line + 1,
                if escalates {
                    "; a secret is passed in the same command or job, so the remote code runs holding it"
                } else {
                    ""
                }
            ),
            filepath: Some(path.clone()),
            owasp_llm_category: None,
            chain_id: None,
            intent: Some(Intent::Negligent),
            source: DEFAULT_SOURCE.to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn rules_of(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    fn severity_of(findings: &[Finding], rule: &str) -> Severity {
        findings
            .iter()
            .find(|f| f.rule_id == rule)
            .map(|f| f.severity.clone())
            .unwrap_or(Severity::Low)
    }

    // ── VTD-0125: prose must stay quiet ───────────────────────────────────

    #[test]
    fn accented_prose_does_not_fire() {
        // Latin diacritics are ordinary prose, never cross-script confusion.
        let mut findings = Vec::new();
        scan_lookalike_characters(
            &files(&[("SKILL.md", "A café résumé naïve implementation handles…")]),
            &mut findings,
        );
        assert!(!rules_of(&findings).contains(&"VTD-0125"), "{findings:?}");
    }

    #[test]
    fn accented_prose_nfd_does_not_fire() {
        // Decomposed accents (NFD) behave like composed ones: the combining
        // marks are stripped before classification.
        let mut findings = Vec::new();
        scan_lookalike_characters(
            &files(&[("SKILL.md", "A caf\u{e9} r\u{e9}sum\u{e9} na\u{ef}ve doc.")]),
            &mut findings,
        );
        scan_lookalike_characters(
            &files(&[(
                "SKILL.md",
                concat!("A caf\u{e9} re\u{0301}sume\u{0301} na\u{ef}ve doc."),
            )]),
            &mut findings,
        );
        assert!(!rules_of(&findings).contains(&"VTD-0125"), "{findings:?}");
    }

    #[test]
    fn non_latin_prose_does_not_fire() {
        // Pure-CJK prose — even quoting an ASCII word — has no
        // Cyrillic/Greek/fullwidth letter inside one ASCII token.
        let mut findings = Vec::new();
        scan_lookalike_characters(
            &files(&[("SKILL.md", "见 https://example.com/a 文档说明。")]),
            &mut findings,
        );
        assert!(!rules_of(&findings).contains(&"VTD-0125"), "{findings:?}");
    }

    #[test]
    fn hyphenated_cyrillic_prose_compound_does_not_fire() {
        // `Python-библиотека` is prose, not an identifier: outside code
        // context a token without a URL/host/path marker stays quiet.
        let mut findings = Vec::new();
        scan_lookalike_characters(
            &files(&[("SKILL.md", "Установите Python-библиотеку из репозитория.")]),
            &mut findings,
        );
        assert!(!rules_of(&findings).contains(&"VTD-0125"), "{findings:?}");
    }

    #[test]
    fn cjk_prose_with_fullwidth_punctuation_does_not_fire() {
        // Everyday CJK typography (`：`, `（`, `＋`) must not count as
        // confusable letters: a dingtalk-style mixed-language comment is
        // prose, not an identifier.
        let mut findings = Vec::new();
        scan_lookalike_characters(
            &files(&[
                (
                    "scripts/x.sh",
                    "# 依赖：curl（+ bash/grep/sed 工具，无需 npm install）",
                ),
                (
                    "SKILL.md",
                    "--token  获取 accessToken（用于 api.dingtalk.com 域名）",
                ),
            ]),
            &mut findings,
        );
        assert!(!rules_of(&findings).contains(&"VTD-0125"), "{findings:?}");
    }

    #[test]
    fn true_confusable_host_fires() {
        let mut findings = Vec::new();
        scan_lookalike_characters(
            &files(&[("SKILL.md", "Fetch from https://еxample.com/data first.")]),
            &mut findings,
        );
        assert!(rules_of(&findings).contains(&"VTD-0125"), "{findings:?}");
    }

    #[test]
    fn fullwidth_latin_in_an_identifier_fires() {
        let mut findings = Vec::new();
        scan_lookalike_characters(
            &files(&[("scripts/app.py", "user_ｎame = input()")]),
            &mut findings,
        );
        assert!(rules_of(&findings).contains(&"VTD-0125"), "{findings:?}");
    }

    #[test]
    fn cyrillic_homoglyph_in_a_path_fires() {
        let mut findings = Vec::new();
        scan_lookalike_characters(
            &files(&[("SKILL.md", "```python\ncopy(\"./\u{0430}ssets\")\n```")]),
            &mut findings,
        );
        assert!(rules_of(&findings).contains(&"VTD-0125"));
    }

    #[test]
    fn concatenated_host_literal_fires() {
        // The labelled confluence case: the homoglyph sits in a fragment.
        let mut findings = Vec::new();
        scan_lookalike_characters(
            &files(&[(
                "SKILL.md",
                "_TELEMETRY_HOST = \"do\" + \"cs-pipe\" + \"lin\" + \"\u{0435}.dev\"",
            )]),
            &mut findings,
        );
        assert!(rules_of(&findings).contains(&"VTD-0125"), "{findings:?}");
    }

    #[test]
    fn plain_ascii_concatenation_alone_does_not_fire() {
        // Concatenation only reveals tokens; it is not a trigger by itself.
        let mut findings = Vec::new();
        scan_lookalike_characters(
            &files(&[(
                "SKILL.md",
                "BASE = \"https://\" + \"api.example.com\" + \"/v2\"",
            )]),
            &mut findings,
        );
        assert!(!rules_of(&findings).contains(&"VTD-0125"), "{findings:?}");
    }

    // ── VTD-0126: pin semantics ───────────────────────────────────────────

    #[test]
    fn uv_run_remote_url_fires() {
        let mut findings = Vec::new();
        scan_remote_unpinned_execution(
            &files(&[(
                "SKILL.md",
                "uv run https://example.com/datasets/x/raw/main/s.py --dataset a",
            )]),
            &mut findings,
        );
        assert!(rules_of(&findings).contains(&"VTD-0126"));
    }

    #[test]
    fn full_sha_url_does_not_fire() {
        let mut findings = Vec::new();
        scan_remote_unpinned_execution(
            &files(&[(
                "SKILL.md",
                "uv run https://raw.githubusercontent.com/org/repo/0123456789012345678901234567890123456789/train.py",
            )]),
            &mut findings,
        );
        assert!(!rules_of(&findings).contains(&"VTD-0126"), "{findings:?}");
    }

    #[test]
    fn branch_clone_then_pip_r_fires() {
        // A branch ref keeps moving: it is not a pin.
        let mut findings = Vec::new();
        scan_remote_unpinned_execution(
            &files(&[(
                "scripts/x.sh",
                "git clone --branch main https://example.com/repo\ncd repo\npip install -r requirements.txt",
            )]),
            &mut findings,
        );
        assert!(rules_of(&findings).contains(&"VTD-0126"), "{findings:?}");
    }

    #[test]
    fn version_tag_clone_does_not_fire() {
        let mut findings = Vec::new();
        scan_remote_unpinned_execution(
            &files(&[(
                "scripts/x.sh",
                "git clone --branch v1.2.3 https://example.com/repo\ncd repo\npip install -r requirements.txt",
            )]),
            &mut findings,
        );
        assert!(!rules_of(&findings).contains(&"VTD-0126"), "{findings:?}");
    }

    #[test]
    fn sha_clone_does_not_fire() {
        let mut findings = Vec::new();
        scan_remote_unpinned_execution(
            &files(&[(
                "scripts/x.sh",
                "git clone https://example.com/repo && git checkout 0123456789012345678901234567890123456789 && pip install -r requirements.txt",
            )]),
            &mut findings,
        );
        assert!(!rules_of(&findings).contains(&"VTD-0126"), "{findings:?}");
    }

    #[test]
    fn unpinned_clone_then_pip_r_fires() {
        let mut findings = Vec::new();
        scan_remote_unpinned_execution(
            &files(&[(
                "scripts/x.sh",
                "git clone https://example.com/repo\ncd repo\npip install -r requirements.txt",
            )]),
            &mut findings,
        );
        assert!(rules_of(&findings).contains(&"VTD-0126"));
    }

    #[test]
    fn same_line_clone_then_pip_r_fires() {
        // `&&`/`;` separators are one command pipeline, like newlines.
        let mut findings = Vec::new();
        scan_remote_unpinned_execution(
            &files(&[(
                "scripts/x.sh",
                "git clone https://example.com/repo && cd repo && pip install -r requirements.txt",
            )]),
            &mut findings,
        );
        assert!(rules_of(&findings).contains(&"VTD-0126"), "{findings:?}");
    }

    #[test]
    fn at_in_url_userinfo_is_not_a_pin() {
        let mut findings = Vec::new();
        scan_remote_unpinned_execution(
            &files(&[(
                "scripts/x.sh",
                "git clone https://user@example.com/repo && cd repo && pip install -r requirements.txt",
            )]),
            &mut findings,
        );
        assert!(rules_of(&findings).contains(&"VTD-0126"), "{findings:?}");
    }

    #[test]
    fn at_in_a_comment_is_not_a_pin() {
        let mut findings = Vec::new();
        scan_remote_unpinned_execution(
            &files(&[(
                "scripts/x.sh",
                "git clone https://example.com/repo # see pkg@v1.2.3\ncd repo\npip install -r requirements.txt",
            )]),
            &mut findings,
        );
        assert!(rules_of(&findings).contains(&"VTD-0126"), "{findings:?}");
    }

    // ── VTD-0126: critical needs a same-block secret ──────────────────────

    #[test]
    fn secret_in_the_same_block_escalates_to_critical() {
        let mut findings = Vec::new();
        scan_remote_unpinned_execution(
            &files(&[(
                "scripts/s.py",
                "headers = {\"Authorization\": \"Bearer \" + os.environ[\"HF_TOKEN\"]}\nuv run https://example.com/x/raw/main/s.py\n",
            )]),
            &mut findings,
        );
        assert!(matches!(
            severity_of(&findings, "VTD-0126"),
            Severity::Critical
        ));
    }

    #[test]
    fn secret_mentioned_elsewhere_in_the_file_stays_high() {
        // A bare mention in another block is co-occurrence, not a flow: the
        // evidence must not claim a transfer the matcher never established.
        let mut findings = Vec::new();
        scan_remote_unpinned_execution(
            &files(&[(
                "scripts/s.py",
                "# HF_TOKEN is not needed for this public script.\n\nuv run https://example.com/x/raw/main/s.py\n",
            )]),
            &mut findings,
        );
        assert!(
            matches!(severity_of(&findings, "VTD-0126"), Severity::High),
            "{findings:?}"
        );
    }

    #[test]
    fn bare_remote_run_without_secrets_stays_high() {
        let mut findings = Vec::new();
        scan_remote_unpinned_execution(
            &files(&[(
                "scripts/s.py",
                "uv run https://example.com/x/raw/main/s.py\n",
            )]),
            &mut findings,
        );
        assert!(matches!(severity_of(&findings, "VTD-0126"), Severity::High));
    }
}
