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
use crate::rules::RULE_SHELL_EXEC_UNSANDBOXED;

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
pub(crate) fn classify(path: &str, line: &str, rule_id: &str) -> MatchKind {
    if is_defensive_comment(path, line) {
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
        MatchKind::CapabilityOnly => {
            Some(" [capability only — the module is imported; no execution call is observed]")
        }
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

/// True when the line is a comment and reads as a prohibition.
fn is_defensive_comment(path: &str, line: &str) -> bool {
    let trimmed = line.trim_start();
    if !comment_markers(path)
        .iter()
        .any(|marker| trimmed.starts_with(marker))
    {
        return false;
    }
    prohibition_re().is_match(line)
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

/// True when the line imports a process-execution module without invoking it.
fn is_capability_import(line: &str) -> bool {
    static IMPORT_RE: OnceLock<Regex> = OnceLock::new();
    let re = IMPORT_RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:^\s*import\s+subprocess\b|^\s*from\s+subprocess\s+import\b|require\s*\(\s*['"]child_process['"]\s*\)|from\s+['"]child_process['"])"#,
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

/// True when the first argument (or first array element) is a quoted literal
/// and the call shows no interpolation or explicit shell opt-in.
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
    if rest.contains(['$', '`', '+', '{', '%'])
        || rest.contains("shell=True")
        || rest.contains("shell: true")
    {
        return false;
    }

    let trimmed = rest.trim_start();
    let starts_with_literal = trimmed.starts_with('"') || trimmed.starts_with('\'');
    let starts_with_literal_array = trimmed.strip_prefix('[').is_some_and(|inner| {
        let inner = inner.trim_start();
        inner.starts_with('"') || inner.starts_with('\'')
    });
    starts_with_literal || starts_with_literal_array
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: &str = RULE_SHELL_EXEC_UNSANDBOXED;

    #[test]
    fn prohibition_is_only_defensive_inside_a_comment() {
        assert_eq!(
            classify("x.py", "# Never read ~/.ssh/id_rsa", RULE),
            MatchKind::DefensiveComment
        );
        assert_eq!(
            classify("x.py", "print('never read ~/.ssh/id_rsa')", RULE),
            MatchKind::Runtime,
            "prose in executable code is not a defense"
        );
    }

    #[test]
    fn import_without_a_call_is_capability_only() {
        assert_eq!(
            classify("x.py", "import subprocess", RULE),
            MatchKind::CapabilityOnly
        );
        assert_eq!(
            classify("x.js", "const cp = require('child_process');", RULE),
            MatchKind::CapabilityOnly
        );
    }

    #[test]
    fn fixed_literal_call_is_a_capability() {
        assert_eq!(
            classify("x.js", "execSync(\"ls -la\")", RULE),
            MatchKind::FixedArgument
        );
        assert_eq!(
            classify("x.py", "subprocess.run([\"ls\", \"-la\"])", RULE),
            MatchKind::Runtime,
            "the process-exec pattern does not claim Python run(); do not invent a classification"
        );
    }

    #[test]
    fn dynamic_or_shell_call_stays_runtime() {
        for line in [
            "exec(cmd)",
            "execSync(\"ls \" + user_dir)",
            "exec(`ls ${dir}`)",
            "subprocess.run(\"ls\", shell=True)",
        ] {
            assert_eq!(classify("x.js", line, RULE), MatchKind::Runtime, "{line}");
        }
    }

    #[test]
    fn require_then_exec_inspects_the_exec_argument() {
        assert_eq!(
            classify("x.js", "require('child_process').exec(cmd)", RULE),
            MatchKind::Runtime,
            "the require() argument must not be mistaken for exec's argument"
        );
    }
}
