//! Call-context classification for sensitive-pattern matches (review T04).
//!
//! A lexical match is an observation, not automatically a vulnerability. This
//! module classifies the *small set of contexts the scanner can decide
//! lexically* — a defensive comment, an import with no call, a call with fixed
//! literal arguments — and the severity policy turns that classification into
//! an output severity.
//!
//! It deliberately does not guess at runtime role, taint flow, sanitisers, or
//! isolation: those stay unresolved and are reported as limits. Documentation
//! and tests are not blanket-ignored; only a comment that *forbids* the
//! operation is treated as a defensive reference, and a test file's executable
//! code is still evidence.

use std::sync::OnceLock;

use regex::Regex;

use crate::finding::Severity;
use crate::rules::{
    RULE_AD_CREDENTIAL_DATABASE, RULE_CLOUD_CREDENTIAL_FILE, RULE_DOCKER_CREDENTIAL_FILE,
    RULE_GITHUB_CLI_CREDENTIAL_FILE, RULE_KUBERNETES_CREDENTIAL_FILE, RULE_MACOS_KEYCHAIN_ACCESS,
    RULE_NETRC_CREDENTIAL_FILE, RULE_NPM_CREDENTIAL_FILE, RULE_PYPI_CREDENTIAL_FILE,
    RULE_SHELL_EXEC_UNSANDBOXED, RULE_SSH_KEY_FILE, RULE_WINDOWS_CREDENTIAL_DATABASE,
    RULE_WINDOWS_CREDENTIAL_STORE,
};

/// Rules a defensive comment may downgrade.
///
/// Only rules that describe an *operation on data* qualify. A secret literal or
/// a PEM header is a leak in the analyzed text itself, so no surrounding prose
/// can make it harmless; those rules keep their severity.
const DEFENSIVE_ELIGIBLE: &[&str] = &[
    RULE_CLOUD_CREDENTIAL_FILE,
    RULE_SSH_KEY_FILE,
    RULE_NPM_CREDENTIAL_FILE,
    RULE_PYPI_CREDENTIAL_FILE,
    RULE_DOCKER_CREDENTIAL_FILE,
    RULE_KUBERNETES_CREDENTIAL_FILE,
    RULE_GITHUB_CLI_CREDENTIAL_FILE,
    RULE_NETRC_CREDENTIAL_FILE,
    RULE_MACOS_KEYCHAIN_ACCESS,
    RULE_WINDOWS_CREDENTIAL_STORE,
    RULE_WINDOWS_CREDENTIAL_DATABASE,
    RULE_AD_CREDENTIAL_DATABASE,
    RULE_SHELL_EXEC_UNSANDBOXED,
];

/// What the matched text is doing, as far as bounded lexical inspection can say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MatchKind {
    /// Executable position with no fixed-argument evidence; base severity.
    Runtime,
    /// A comment that states the operation is forbidden.
    DefensiveComment,
    /// A process-execution module imported, with no call observed.
    CapabilityOnly,
    /// A process call whose arguments are literals with no interpolation.
    FixedArgument,
}

/// Severity policy for a classified match.
///
/// **This match is the single change point for the T04 severity policy.** The
/// values below were chosen so a benign comment, import, or fixed-argv call
/// cannot produce a critical/high finding (and therefore cannot drive a
/// failing grade or a failed secrets attestation) while dynamic calls keep
/// their existing severity.
pub(crate) fn policy_severity(base: Severity, kind: MatchKind) -> Severity {
    match kind {
        MatchKind::DefensiveComment => Severity::Low,
        MatchKind::CapabilityOnly => Severity::Info,
        MatchKind::FixedArgument => Severity::Low,
        MatchKind::Runtime => base,
    }
}

/// Classifies a matched line for `rule_id`.
///
/// `match_start` is the match's byte offset in the original `line`; callers
/// that only have a folded view pass `usize::MAX`, which never qualifies as a
/// defensive reference (the offset cannot be trusted).
pub(crate) fn classify(path: &str, line: &str, rule_id: &str, match_start: usize) -> MatchKind {
    if is_defensive_comment(path, line, rule_id, match_start) {
        return MatchKind::DefensiveComment;
    }
    if rule_id == RULE_SHELL_EXEC_UNSANDBOXED {
        if is_capability_import(line) && !has_invocation(line) {
            return MatchKind::CapabilityOnly;
        }
        if is_fixed_argument_call(line) {
            return MatchKind::FixedArgument;
        }
    }
    MatchKind::Runtime
}

/// Human-readable reason appended to a classified finding's detail.
pub(crate) fn context_note(kind: MatchKind) -> Option<&'static str> {
    match kind {
        MatchKind::DefensiveComment => Some(
            " [context: defensive reference — the text forbids this operation; no runtime access is evidenced]",
        ),
        MatchKind::CapabilityOnly => Some(
            " [capability only — the module is imported; no call matched by this rule]",
        ),
        MatchKind::FixedArgument => {
            Some(" [capability only — literal arguments; no dynamic input is observed]")
        }
        MatchKind::Runtime => None,
    }
}

/// Comment markers for the file's language, or a conservative default.
fn comment_markers(path: &str) -> &'static [&'static str] {
    let extension = path
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .unwrap_or_default();
    match extension.as_str() {
        "sh" | "bash" | "zsh" | "ksh" | "dash" | "py" | "rb" | "pl" | "pm" | "yaml" | "yml"
        | "toml" | "r" | "ini" | "cfg" | "conf" | "properties" | "tf" | "hcl" => &["#"],
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" | "c" | "h" | "cc" | "cpp" | "hpp" | "cs"
        | "go" | "rs" | "java" | "kt" | "kts" | "swift" | "php" | "scala" | "m" => {
            &["//", "/*", "*"]
        }
        "html" | "htm" | "xml" | "svg" | "md" | "markdown" => &["<!--"],
        "sql" => &["--"],
        _ => &["#", "//", "/*", "<!--"],
    }
}

/// True when the line is a comment whose prohibition governs the matched
/// operation.
fn is_defensive_comment(path: &str, line: &str, rule_id: &str, match_start: usize) -> bool {
    if !DEFENSIVE_ELIGIBLE.contains(&rule_id) || match_start > line.len() {
        return false;
    }
    let trimmed = line.trim_start();
    if !comment_markers(path)
        .iter()
        .any(|marker| trimmed.starts_with(marker))
    {
        return false;
    }
    let Some(prohibition) = prohibition_re().find(line) else {
        return false;
    };
    // The prohibition has to come first: "the agent should run: cat ~/.ssh/…"
    // is an instruction, not a defense, even when it contains "avoid".
    if prohibition.end() > match_start {
        return false;
    }
    // Only the clause that follows the prohibition can be governed by it. A
    // clause break or a modal instruction starts a new, imperative sentence.
    let governed = &line[prohibition.end()..match_start];
    !governed.contains([':', ';']) && !modal_re().is_match(governed)
}

fn prohibition_re() -> &'static Regex {
    static PROHIBITION_RE: OnceLock<Regex> = OnceLock::new();
    PROHIBITION_RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:never|do\s+not|don'?t|does\s+not|must\s+not|should\s+not|shall\s+not|avoid|forbid(?:den)?|prohibit(?:ed)?|not\s+allowed|no\s+need\s+to|refuse|nunca|jamais|niemals)\b",
        )
        .expect("bad prohibition regex")
    })
}

/// Words that turn the rest of a comment into an instruction.
fn modal_re() -> &'static Regex {
    static MODAL_RE: OnceLock<Regex> = OnceLock::new();
    MODAL_RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:should|must|then|please|now|always|first)\b")
            .expect("bad modal regex")
    })
}

/// True when the line imports a process-execution module without invoking it.
fn is_capability_import(line: &str) -> bool {
    static IMPORT_RE: OnceLock<Regex> = OnceLock::new();
    let re = IMPORT_RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:^\s*import\s+subprocess\b|^\s*from\s+subprocess\s+import\b|require\s*\(\s*['"](?:node:)?child_process['"]\s*\)|from\s+['"](?:node:)?child_process['"])"#,
        )
        .expect("bad capability import regex")
    });
    re.is_match(line)
}

/// True when the line contains any process-invocation call, import or not.
fn has_invocation(line: &str) -> bool {
    static CALL_RE: OnceLock<Regex> = OnceLock::new();
    let re = CALL_RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:exec|spawn|execSync|spawnSync|execFile|execFileSync)\s*\(")
            .expect("bad invocation regex")
    });
    re.is_match(line)
}

/// Upper bound on the argument text inspected for one call.
const MAX_ARG_CHARS: usize = 4096;

/// True when every argument, and every array element, is a literal.
///
/// A first literal is not enough: `execFile("sh", ["-c", argv])` and
/// `spawn('bash', ['-c', x])` still hand runtime input to a process. Options
/// objects are accepted when their values are literals (`{cwd: "/tmp"}`),
/// since keys are not arguments.
fn is_fixed_argument_call(line: &str) -> bool {
    // Find the invocation's own paren, not an earlier call on the same line
    // (`require('child_process').exec(cmd)` must inspect `exec`'s argument).
    static CALL_OPEN_RE: OnceLock<Regex> = OnceLock::new();
    let re = CALL_OPEN_RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:exec|spawn|execSync|spawnSync|execFile|execFileSync)\s*\(")
            .expect("bad call-open regex")
    });
    let Some(call) = re.find(line) else {
        return false;
    };
    let rest = &line[call.end()..];

    // Any of these means the argument is built at runtime or handed to a
    // shell/format engine, so a literal reading is not justified.
    if rest.contains("shell=True") || rest.contains("shell: true") {
        return false;
    }

    let Some(args) = balanced_arguments(rest) else {
        return false;
    };
    arguments_are_literals(args)
}

/// Returns the text between the call's parentheses.
fn balanced_arguments(rest: &str) -> Option<&str> {
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (i, c) in rest.char_indices().take(MAX_ARG_CHARS) {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' | '`' => quote = Some(c),
            '(' | '[' | '{' => depth += 1,
            ')' => {
                if depth == 0 {
                    return Some(&rest[..i]);
                }
                depth -= 1;
            }
            ']' | '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    None
}

fn arguments_are_literals(args: &str) -> bool {
    split_top_level(args)
        .into_iter()
        .all(|arg| arg.trim().is_empty() || argument_is_literal(arg.trim()))
}

fn argument_is_literal(arg: &str) -> bool {
    if let Some(inner) = arg.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return split_top_level(inner).into_iter().all(|element| {
            let element = element.trim();
            element.is_empty() || literal_scalar(element)
        });
    }
    if let Some(inner) = arg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
        return split_top_level(inner).into_iter().all(|pair| {
            let pair = pair.trim();
            pair.is_empty()
                || pair.split_once(':').is_some_and(|(key, value)| {
                    is_option_key(key.trim()) && literal_scalar(value.trim())
                })
        });
    }
    literal_scalar(arg)
}

fn literal_scalar(s: &str) -> bool {
    strip_literal(s).is_some()
        || matches!(s, "true" | "false" | "null" | "None" | "True" | "False")
        || s.parse::<f64>().is_ok()
}

/// Returns the body of a quoted literal when `s` is exactly one literal.
fn strip_literal(s: &str) -> Option<&str> {
    let quote = s.chars().next()?;
    if !matches!(quote, '"' | '\'' | '`') || s.len() < 2 || !s.ends_with(quote) {
        return None;
    }
    let inner = &s[1..s.len() - 1];
    // An inner delimiter would have ended the literal earlier; a template
    // interpolation makes it dynamic.
    if inner.contains(quote) || (quote == '`' && inner.contains("${")) {
        return None;
    }
    Some(inner)
}

fn is_option_key(s: &str) -> bool {
    strip_literal(s).is_some()
        || (!s.is_empty()
            && s.chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
}

fn split_top_level(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut start = 0usize;
    for (i, c) in s.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' | '`' => quote = Some(c),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: &str = RULE_SHELL_EXEC_UNSANDBOXED;

    #[test]
    fn prohibition_is_only_defensive_inside_a_comment() {
        let line = "# Never read ~/.ssh/id_rsa";
        let start = line.find(".ssh").expect("path in line");
        assert_eq!(
            classify("x.py", line, RULE, start),
            MatchKind::DefensiveComment
        );
        assert_eq!(
            classify("x.py", "print('never read ~/.ssh/id_rsa')", RULE, 30),
            MatchKind::Runtime,
            "prose in executable code is not a defense"
        );
    }

    #[test]
    fn prohibition_must_govern_the_matched_operation() {
        let line = "# to avoid prompts the agent should run: cat ~/.ssh/id_rsa";
        let start = line.find(".ssh").expect("path in line");
        assert_eq!(
            classify("x.sh", line, RULE, start),
            MatchKind::Runtime,
            "an imperative after the prohibition is an instruction, not a defense"
        );
    }

    #[test]
    fn secret_literals_are_never_defensive() {
        let line = "# do not commit: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012";
        let start = line.find("ghp_").expect("token in line");
        assert_eq!(
            classify("x.sh", line, crate::rules::RULE_POTENTIAL_API_TOKEN, start),
            MatchKind::Runtime,
            "a literal secret is a leak regardless of surrounding prose"
        );
    }

    #[test]
    fn import_without_a_call_is_capability_only() {
        assert_eq!(
            classify("x.py", "import subprocess", RULE, 0),
            MatchKind::CapabilityOnly
        );
        assert_eq!(
            classify("x.js", "const cp = require('child_process');", RULE, 0),
            MatchKind::CapabilityOnly
        );
        assert_eq!(
            classify("x.js", "import * as cp from 'node:child_process';", RULE, 0),
            MatchKind::CapabilityOnly
        );
    }

    #[test]
    fn fixed_literal_call_is_a_capability() {
        assert_eq!(
            classify("x.js", "execSync(\"ls -la\")", RULE, 0),
            MatchKind::FixedArgument
        );
        assert_eq!(
            classify("x.py", "subprocess.run([\"ls\", \"-la\"])", RULE, 0),
            MatchKind::Runtime,
            "the process-exec pattern does not claim Python run(); do not invent a classification"
        );
    }

    #[test]
    fn every_argument_must_be_a_literal() {
        for line in [
            "execFile(\"sh\", [\"-c\", process.argv[2]])",
            "spawn('bash', ['-c', userInput])",
            "execSync('ls', userOpts)",
            "execSync(\"ls \" + user_dir)",
            "exec(cmd)",
            "exec(`ls ${dir}`)",
            "subprocess.run(\"ls\", shell=True)",
        ] {
            assert_eq!(
                classify("x.js", line, RULE, 0),
                MatchKind::Runtime,
                "{line}"
            );
        }
        assert_eq!(
            classify(
                "x.js",
                "execFile(\"ls\", [\"-la\"], {cwd: \"/tmp\"})",
                RULE,
                0
            ),
            MatchKind::FixedArgument,
            "literal arguments and a literal-valued options object are fixed"
        );
    }

    #[test]
    fn require_then_exec_inspects_the_exec_argument() {
        assert_eq!(
            classify("x.js", "require('child_process').exec(cmd)", RULE, 0),
            MatchKind::Runtime,
            "the require() argument must not be mistaken for exec's argument"
        );
    }
}
