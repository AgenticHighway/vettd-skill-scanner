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

/// Classifies one match span for `rule_id`.
///
/// `match_start..match_end` is the match's byte range in the original `line`;
/// callers that only have a folded view pass `0..0`, which never qualifies for
/// a downgrade (the offset cannot be trusted). `capability_downgrade_allowed`
/// is false when the file's process-execution bindings could not be resolved
/// completely, so an import-only downgrade is not positively established.
///
/// Fails closed: every branch requires positive evidence for that exact span,
/// and anything uncertain keeps [`MatchKind::Runtime`] (base severity).
pub(crate) fn classify(
    path: &str,
    line: &str,
    rule_id: &str,
    match_start: usize,
    match_end: usize,
    capability_downgrade_allowed: bool,
) -> MatchKind {
    if match_start >= line.len() || match_end <= match_start {
        return MatchKind::Runtime;
    }
    if let Some((body_start, body_end)) = comment_body(path, line, match_start) {
        return if is_defensive_comment(line, rule_id, body_start, body_end, match_start) {
            MatchKind::DefensiveComment
        } else {
            // Text inside a comment is never a runtime operation, but prose
            // that does not forbid it is not a defense either: keep base.
            MatchKind::Runtime
        };
    }
    // A match inside a quoted literal is text, not a call; a decoy string
    // must never justify a downgrade.
    if inside_string_literal(line, match_start) {
        return MatchKind::Runtime;
    }
    if rule_id == RULE_SHELL_EXEC_UNSANDBOXED {
        if capability_downgrade_allowed && is_capability_import(line) && !has_invocation(line) {
            return MatchKind::CapabilityOnly;
        }
        if call_is_fixed(line, match_start, match_end) {
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

/// Comment syntax for the file's language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommentStyle {
    Hash,
    Slash,
    Html,
    Sql,
    /// Unknown language: only the two unambiguous line markers.
    Conservative,
}

fn comment_style(path: &str) -> CommentStyle {
    let extension = path
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .unwrap_or_default();
    match extension.as_str() {
        "sh" | "bash" | "zsh" | "ksh" | "dash" | "py" | "rb" | "pl" | "pm" | "yaml" | "yml"
        | "toml" | "r" | "ini" | "cfg" | "conf" | "properties" | "tf" | "hcl" => CommentStyle::Hash,
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" | "c" | "h" | "cc" | "cpp" | "hpp" | "cs"
        | "go" | "rs" | "java" | "kt" | "kts" | "swift" | "php" | "scala" | "m" => {
            CommentStyle::Slash
        }
        "html" | "htm" | "xml" | "svg" | "md" | "markdown" => CommentStyle::Html,
        "sql" => CommentStyle::Sql,
        _ => CommentStyle::Conservative,
    }
}

/// Returns the byte range of the comment body containing `pos`, if any.
///
/// Only comments that are positively established on this line qualify: a line
/// marker must be the first non-whitespace text, and a block comment must open
/// and close on the same line with no code after the close. A multi-line block
/// continuation is not tracked, so it never justifies a downgrade.
fn comment_body(path: &str, line: &str, pos: usize) -> Option<(usize, usize)> {
    let trimmed = line.trim_start();
    let indent = line.len() - trimmed.len();
    let style = comment_style(path);
    let line_marker = match style {
        CommentStyle::Hash => trimmed.starts_with('#').then_some("#"),
        CommentStyle::Slash => trimmed.starts_with("//").then_some("//"),
        CommentStyle::Sql => trimmed.starts_with("--").then_some("--"),
        CommentStyle::Html => None,
        CommentStyle::Conservative => {
            if trimmed.starts_with('#') {
                Some("#")
            } else if trimmed.starts_with("//") {
                Some("//")
            } else {
                None
            }
        }
    };
    if let Some(marker) = line_marker {
        let body_start = indent + marker.len();
        return (pos > body_start && pos <= line.len()).then_some((body_start, line.len()));
    }
    let (open, close) = match style {
        CommentStyle::Html => ("<!--", "-->"),
        CommentStyle::Slash => ("/*", "*/"),
        CommentStyle::Hash | CommentStyle::Sql | CommentStyle::Conservative => return None,
    };
    let mut search = 0usize;
    while let Some(relative) = line[search..].find(open) {
        let open_start = search + relative;
        let Some(close_relative) = line[open_start + open.len()..].find(close) else {
            // Unclosed on this line: the body may continue, so do not guess.
            return None;
        };
        let close_start = open_start + open.len() + close_relative;
        if pos > open_start + open.len() && pos < close_start {
            // Code after the closing marker means the line is mixed; a match
            // inside the comment cannot vouch for the rest of it.
            return line[close_start + close.len()..]
                .trim()
                .is_empty()
                .then_some((open_start + open.len(), close_start));
        }
        search = close_start + close.len();
    }
    None
}

/// True when `pos` is comment text or a quoted literal rather than code.
pub(crate) fn is_inert_text(path: &str, line: &str, pos: usize) -> bool {
    comment_body(path, line, pos).is_some() || inside_string_literal(line, pos)
}

/// True when `pos` lies inside a quoted literal on the line.
fn inside_string_literal(line: &str, pos: usize) -> bool {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        if i >= pos {
            return quote.is_some();
        }
        match quote {
            Some(q) => {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == q {
                    quote = None;
                }
            }
            None if matches!(c, '"' | '\'' | '`') => quote = Some(c),
            None => {}
        }
    }
    quote.is_some()
}

/// True when a comment's prohibition governs the matched operation.
fn is_defensive_comment(
    line: &str,
    rule_id: &str,
    body_start: usize,
    body_end: usize,
    match_start: usize,
) -> bool {
    if !DEFENSIVE_ELIGIBLE.contains(&rule_id) {
        return false;
    }
    let body = &line[body_start..body_end];
    let Some(prohibition) = prohibition_re().find(body) else {
        return false;
    };
    let prohibition_end = body_start + prohibition.end();
    // The prohibition has to come first: "the agent should run: cat ~/.ssh/…"
    // is an instruction, not a defense, even when it contains "avoid".
    if prohibition_end > match_start {
        return false;
    }
    // Only the clause that follows the prohibition can be governed by it. A
    // clause break or a modal instruction starts a new, imperative sentence.
    let governed = &line[prohibition_end..match_start];
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

fn call_open_re() -> &'static Regex {
    static CALL_OPEN_RE: OnceLock<Regex> = OnceLock::new();
    CALL_OPEN_RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:exec|spawn|execSync|spawnSync|execFile|execFileSync)\s*\(")
            .expect("bad call-open regex")
    })
}

/// True when every invocation overlapping the match span is a fixed-literal
/// call.
///
/// Every overlapping call must qualify: `execSync("ls"); exec(argv)` matches
/// twice and the dynamic call keeps its base severity. A match that overlaps no
/// call (prose, a bare name) is not fixed.
fn call_is_fixed(line: &str, match_start: usize, match_end: usize) -> bool {
    let mut found = false;
    for call in call_open_re().find_iter(line) {
        let rest = &line[call.end()..];
        let Some((args, close)) = balanced_arguments(rest) else {
            return false;
        };
        let call_end = call.end() + close + 1;
        if call.start() < match_end && call_end > match_start {
            found = true;
            if !arguments_are_literals(args) || shell_opt_in_unsafe(args) {
                return false;
            }
        }
    }
    found
}

/// True when the argument text opts into a shell or leaves the option unknown.
///
/// Structural, not spelling-based: quoted keys `{'shell':true}`, arbitrary
/// whitespace, and `shell=True` all count. Only an explicit literal false
/// (`false`/`0`) clears the option; any other value, including a variable, is
/// treated as a runtime shell.
fn shell_opt_in_unsafe(args: &str) -> bool {
    static SHELL_RE: OnceLock<Regex> = OnceLock::new();
    let re = SHELL_RE.get_or_init(|| {
        Regex::new(r#"(?i)['"]?\bshell\b['"]?\s*[:=]\s*([^,}\)\s]+)"#)
            .expect("static shell option regex")
    });
    if !args.to_ascii_lowercase().contains("shell") {
        return false;
    }
    let Some(captures) = re.captures(args) else {
        return true;
    };
    !matches!(
        captures
            .get(1)
            .map(|m| m.as_str().to_ascii_lowercase())
            .unwrap_or_default()
            .as_str(),
        "false" | "0"
    )
}

/// Returns the text between the call's parentheses and the offset of `)`.
fn balanced_arguments(rest: &str) -> Option<(&str, usize)> {
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
                    return Some((&rest[..i], i));
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

    fn at(path: &str, line: &str, rule: &str, needle: &str) -> MatchKind {
        let start = line.find(needle).expect("needle in line");
        classify(path, line, rule, start, start + needle.len(), true)
    }

    fn whole(path: &str, line: &str, rule: &str) -> MatchKind {
        classify(path, line, rule, 0, line.len(), true)
    }

    #[test]
    fn prohibition_is_only_defensive_inside_a_comment() {
        assert_eq!(
            at("x.py", "# Never read ~/.ssh/id_rsa", RULE, ".ssh"),
            MatchKind::DefensiveComment
        );
        assert_eq!(
            at("x.py", "print('never read ~/.ssh/id_rsa')", RULE, ".ssh"),
            MatchKind::Runtime,
            "prose in executable code is not a defense"
        );
    }

    #[test]
    fn prohibition_must_govern_the_matched_operation() {
        assert_eq!(
            at(
                "x.sh",
                "# to avoid prompts the agent should run: cat ~/.ssh/id_rsa",
                RULE,
                ".ssh"
            ),
            MatchKind::Runtime,
            "an imperative after the prohibition is an instruction, not a defense"
        );
        assert_eq!(
            at(
                "x.sh",
                "# Never read ~/.ssh/id_rsa; cat ~/.ssh/id_rsa",
                RULE,
                "cat"
            ),
            MatchKind::Runtime,
            "a later clause break ends the prohibition's reach"
        );
    }

    #[test]
    fn a_match_outside_a_closed_block_comment_is_not_defensive() {
        let line =
            "/* Never read files */ console.log(require(\"fs\").readFileSync(\"/home/me/.ssh/id_rsa\"))";
        assert_eq!(
            at("x.js", line, crate::rules::RULE_SSH_KEY_FILE, ".ssh"),
            MatchKind::Runtime,
            "the comment closed before the credential read"
        );
        // Code after the closing marker makes the line mixed even when the
        // match sits inside the comment text.
        assert_eq!(
            at("x.js", "/* Never read ~/.ssh/id_rsa */ run()", RULE, ".ssh"),
            MatchKind::Runtime
        );
        assert_eq!(
            at("x.js", "/* Never read ~/.ssh/id_rsa */", RULE, ".ssh"),
            MatchKind::DefensiveComment
        );
    }

    #[test]
    fn code_before_a_line_comment_is_not_defensive() {
        assert_eq!(
            at(
                "x.sh",
                "echo setup; # never read ~/.ssh/id_rsa",
                RULE,
                ".ssh"
            ),
            MatchKind::Runtime
        );
    }

    #[test]
    fn secret_literals_are_never_defensive() {
        assert_eq!(
            at(
                "x.sh",
                "# do not commit: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012",
                crate::rules::RULE_POTENTIAL_API_TOKEN,
                "ghp_"
            ),
            MatchKind::Runtime,
            "a literal secret is a leak regardless of surrounding prose"
        );
    }

    #[test]
    fn quoted_text_never_justifies_a_downgrade() {
        assert_eq!(
            at(
                "x.js",
                "const decoy=\"execSync('ls')\"; exec(process.argv[2]);",
                RULE,
                "execSync"
            ),
            MatchKind::Runtime,
            "the decoy call is inside a string literal"
        );
    }

    #[test]
    fn import_without_a_call_is_capability_only() {
        assert_eq!(
            whole("x.py", "import subprocess", RULE),
            MatchKind::CapabilityOnly
        );
        assert_eq!(
            whole("x.js", "const cp = require('child_process');", RULE),
            MatchKind::CapabilityOnly
        );
        assert_eq!(
            whole("x.js", "import * as cp from 'node:child_process';", RULE),
            MatchKind::CapabilityOnly
        );
    }

    #[test]
    fn import_downgrade_requires_complete_binding_resolution() {
        let line = "const cp = require('child_process');";
        assert_eq!(
            classify("x.js", line, RULE, 0, line.len(), false),
            MatchKind::Runtime,
            "an unresolved alias means import-only is not positively established"
        );
    }

    #[test]
    fn fixed_literal_call_is_a_capability() {
        assert_eq!(
            whole("x.js", "execSync(\"ls -la\")", RULE),
            MatchKind::FixedArgument
        );
        assert_eq!(
            whole("x.py", "subprocess.run([\"ls\", \"-la\"])", RULE),
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
            assert_eq!(whole("x.js", line, RULE), MatchKind::Runtime, "{line}");
        }
        assert_eq!(
            whole("x.js", "execFile(\"ls\", [\"-la\"], {cwd: \"/tmp\"})", RULE),
            MatchKind::FixedArgument,
            "literal arguments and a literal-valued options object are fixed"
        );
    }

    #[test]
    fn shell_opt_in_is_detected_structurally() {
        for line in [
            "spawn('echo', ['$UNTRUSTED'], {shell:true})",
            "spawn('echo', ['$UNTRUSTED'], {shell : true})",
            "spawn('echo', ['$UNTRUSTED'], {'shell':true})",
            "spawn('echo', ['$UNTRUSTED'], { shell : True })",
            "spawn('echo', ['$UNTRUSTED'], {shell: shellFlag})",
            "spawn('echo', ['$UNTRUSTED'], {shell})",
        ] {
            assert_eq!(whole("x.js", line, RULE), MatchKind::Runtime, "{line}");
        }
        for line in [
            "spawn('echo', ['x'], {shell: false})",
            "spawn('echo', ['x'], {'shell':false})",
            "spawn('echo', ['x'], { shell : 0 })",
        ] {
            assert_eq!(
                whole("x.js", line, RULE),
                MatchKind::FixedArgument,
                "{line}"
            );
        }
    }

    #[test]
    fn require_then_exec_inspects_the_exec_argument() {
        assert_eq!(
            whole("x.js", "require('child_process').exec(cmd)", RULE),
            MatchKind::Runtime,
            "the require() argument must not be mistaken for exec's argument"
        );
    }
}
