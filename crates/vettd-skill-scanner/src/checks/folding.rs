//! Bounded, deterministic constant folding for trivial source obfuscation.
//!
//! The sensitive-pattern check is a literal matcher. Its documented weakness is
//! that a value split with string concatenation or routed through a local
//! variable reads as absent. This module produces an *additional* line view so
//! those trivial constructions remain visible, without pretending to be a
//! semantic analyser:
//!
//! * adjacent, `+`-joined, and pathlib-`/`-joined string literals are merged;
//! * a local bound to a plain literal is substituted for that name (`$V`,
//!   `${V}`, or a bare identifier in value position);
//! * a short base64 literal passed to an explicit decoder is decoded.
//!
//! Every step is bounded (binding count, literal size, fold passes, decode
//! size) and purely lexical, so the result is reproducible: no model judgment,
//! no I/O. What this cannot decide — dynamic construction at runtime, other
//! languages, non-literal multilingual instructions — is stated in the scan's
//! coverage output rather than silently claimed.

use std::sync::OnceLock;

use regex::Regex;

/// Upper bound on distinct literal bindings resolved per file.
const MAX_BINDINGS: usize = 64;
/// Upper bound on a bound literal's length; longer values are left alone.
const MAX_LITERAL: usize = 256;
/// Upper bound on fold iterations per line; each iteration is one merge.
const MAX_FOLD_PASSES: usize = 8;

/// Names that are syntax, not user bindings, and must never be substituted.
const RESERVED: &[&str] = &[
    "if", "for", "while", "return", "function", "const", "let", "var", "export", "import", "from",
    "class", "def", "else", "elif", "match", "case", "switch", "new", "true", "false", "null",
    "none", "None", "True", "False", "self", "this", "await", "async", "yield", "lambda",
];

/// Collects `name = "literal"` bindings from `content`.
///
/// Only plain, unescaped, non-interpolating literals qualify; a later literal
/// assignment to the same name replaces an earlier one. The result is a small,
/// bounded look-up table, not a data-flow analysis.
pub(crate) fn literal_bindings(content: &str) -> Vec<(String, String)> {
    static ASSIGN_RE: OnceLock<Regex> = OnceLock::new();
    // `export`/`const`/`let`/`var` prefixes cover the common declaration forms;
    // the trailing `;` and comment-free line anchor keep this to whole
    // statements rather than fragments of an expression.
    let re = ASSIGN_RE.get_or_init(|| {
        Regex::new(
            r#"(?m)^\s*(?:export\s+)?(?:const\s+|let\s+|var\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:"([^"\r\n]*)"|'([^'\r\n]*)')\s*;?\s*$"#,
        )
        .expect("bad literal binding regex")
    });

    let mut bindings: Vec<(String, String)> = Vec::new();
    for cap in re.captures_iter(content) {
        if bindings.len() >= MAX_BINDINGS {
            break;
        }
        let name = &cap[1];
        if RESERVED.contains(&name) {
            continue;
        }
        let Some(captured) = cap.get(2).or_else(|| cap.get(3)) else {
            continue;
        };
        // Store the literal with its original quotes: a bare-identifier
        // substitution re-inserts valid source, while `$NAME` substitutes the
        // inner text (shell expansion does not carry quotes).
        let quote = if cap.get(2).is_some() { '"' } else { '\'' };
        let inner = captured.as_str();
        if inner.is_empty() || inner.len() > MAX_LITERAL || inner == name {
            continue;
        }
        // `$`, backticks, and backslashes introduce shell/JS interpolation or
        // escapes; a value the scanner cannot read literally is not folded.
        if inner.contains(['$', '`', '\\']) {
            continue;
        }
        let value = format!("{quote}{inner}{quote}");
        if let Some(slot) = bindings.iter_mut().find(|(n, _)| n == name) {
            slot.1 = value;
        } else {
            bindings.push((name.to_string(), value));
        }
    }
    bindings
}

/// Removes the surrounding quotes from a stored literal.
fn unquote(literal: &str) -> &str {
    literal
        .strip_prefix('"')
        .or_else(|| literal.strip_prefix('\''))
        .and_then(|s| s.strip_suffix('"').or_else(|| s.strip_suffix('\'')))
        .unwrap_or(literal)
}

/// Returns an expanded view of one line, or `None` when nothing changed.
///
/// The original line keeps its identity: callers report the unchanged line
/// number and the original text, so a folded match never invents a location.
pub(crate) fn expand_line(line: &str, bindings: &[(String, String)]) -> Option<String> {
    let mut expanded = line.to_string();

    // Bare identifiers first, so a substituted value is never re-substituted
    // by a later pass (the scanner advances past each replacement).
    for (name, value) in bindings {
        expanded = substitute_identifier(&expanded, name, value);
    }
    for (name, value) in bindings {
        expanded = expanded.replace(&format!("${{{name}}}"), unquote(value));
        expanded = expanded.replace(&format!("${name}"), unquote(value));
    }

    expanded = fold_literals(&expanded);
    if let Some(decoded) = decode_short_base64(&expanded) {
        expanded.push(' ');
        expanded.push_str(&decoded);
    }

    (expanded != line).then_some(expanded)
}

/// Substitutes a bare `name` only where it is a value, never where it is a
/// property (`.name`), a shell expansion (`$name`, `${name}`), a call
/// (`name(`), a keyword argument (`name:`), or an assignment target (`name =`).
fn substitute_identifier(src: &str, name: &str, value: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    let mut consumed = 0usize;

    while let Some(pos) = rest.find(name) {
        let abs = consumed + pos;
        let after = pos + name.len();
        out.push_str(&rest[..pos]);

        let prev_ok = abs == 0 || {
            let b = src.as_bytes()[abs - 1];
            !(b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'$' | b'{'))
        };
        let next_ok = abs + name.len() == src.len() || {
            let b = src.as_bytes()[abs + name.len()];
            !(b.is_ascii_alphanumeric() || matches!(b, b'_' | b'(' | b'=' | b':'))
        };

        if prev_ok && next_ok {
            out.push_str(value);
        } else {
            out.push_str(name);
        }

        consumed = abs + name.len();
        rest = &rest[after..];
    }
    out.push_str(rest);
    out
}

/// Merges trivia-joined, `+`-joined, and pathlib-`/`-joined string literals.
fn fold_literals(line: &str) -> String {
    static DOUBLE_PLUS: OnceLock<Regex> = OnceLock::new();
    static SINGLE_PLUS: OnceLock<Regex> = OnceLock::new();
    static DOUBLE_PATH: OnceLock<Regex> = OnceLock::new();
    static SINGLE_PATH: OnceLock<Regex> = OnceLock::new();
    static DOUBLE_ADJACENT: OnceLock<Regex> = OnceLock::new();
    static SINGLE_ADJACENT: OnceLock<Regex> = OnceLock::new();

    let double_plus = DOUBLE_PLUS
        .get_or_init(|| Regex::new(r#""([^"\r\n]*)"\s*\+\s*"([^"\r\n]*)""#).expect("bad fold re"));
    let single_plus = SINGLE_PLUS
        .get_or_init(|| Regex::new(r#"'([^'\r\n]*)'\s*\+\s*'([^'\r\n]*)'"#).expect("bad fold re"));
    let double_path = DOUBLE_PATH
        .get_or_init(|| Regex::new(r#""([^"\r\n]*)"\s*/\s*"([^"\r\n]*)""#).expect("bad fold re"));
    let single_path = SINGLE_PATH
        .get_or_init(|| Regex::new(r#"'([^'\r\n]*)'\s*/\s*'([^'\r\n]*)'"#).expect("bad fold re"));
    let double_adjacent = DOUBLE_ADJACENT
        .get_or_init(|| Regex::new(r#""([^"\r\n]*)"\s+"([^"\r\n]*)""#).expect("bad fold re"));
    let single_adjacent = SINGLE_ADJACENT
        .get_or_init(|| Regex::new(r#"'([^'\r\n]*)'\s+'([^'\r\n]*)'"#).expect("bad fold re"));

    let mut current = line.to_string();
    for _ in 0..MAX_FOLD_PASSES {
        let next = double_plus.replace_all(&current, "\"$1$2\"").into_owned();
        let next = single_plus.replace_all(&next, "'$1$2'").into_owned();
        let next = double_path.replace_all(&next, "\"$1/$2\"").into_owned();
        let next = single_path.replace_all(&next, "'$1/$2'").into_owned();
        let next = double_adjacent.replace_all(&next, "\"$1$2\"").into_owned();
        let next = single_adjacent.replace_all(&next, "'$1$2'").into_owned();
        if next == current {
            break;
        }
        current = next;
    }
    current
}

/// Decodes a short base64 literal only when an explicit decoder marker is
/// present. Longer candidates are handled by the existing obfuscation pass;
/// this closes its short-literal gap without duplicating that work.
fn decode_short_base64(line: &str) -> Option<String> {
    use base64::{engine::general_purpose, Engine as _};

    static B64_RE: OnceLock<Regex> = OnceLock::new();
    let re = B64_RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:base64\s+(?:-d|--decode)|b64decode\s*\(\s*)["']?([A-Za-z0-9+/]{16,31}={0,2})"#,
        )
        .expect("bad short base64 regex")
    });
    let encoded = re.captures(line)?.get(1)?.as_str();
    let padded = match encoded.len() % 4 {
        0 => encoded.to_string(),
        2 => format!("{encoded}=="),
        3 => format!("{encoded}="),
        _ => return None,
    };
    let bytes = general_purpose::STANDARD.decode(padded).ok()?;
    let decoded = String::from_utf8(bytes).ok()?;
    decoded
        .chars()
        .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        .then_some(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_concatenated_literals() {
        let bindings = literal_bindings("");
        let expanded = expand_line(r#"path = "/home/user/" + ".ssh/id_rsa""#, &bindings).unwrap();
        assert!(expanded.contains("/home/user/.ssh/id_rsa"), "{expanded}");
    }

    #[test]
    fn resolves_literal_binding_through_variable() {
        let bindings = literal_bindings("home = \"/home/user\"\nkey = home + \"/.ssh/id_rsa\"\n");
        let expanded = expand_line("key = home + \"/.ssh/id_rsa\"", &bindings).unwrap();
        assert!(expanded.contains("/home/user/.ssh/id_rsa"), "{expanded}");
    }

    #[test]
    fn folds_pathlib_style_join() {
        let bindings = literal_bindings("");
        let expanded = expand_line(r#"p = Path.home() / ".ssh" / "id_rsa""#, &bindings).unwrap();
        assert!(expanded.contains(".ssh/id_rsa"), "{expanded}");
    }

    #[test]
    fn decodes_short_explicit_base64_literal() {
        let bindings = literal_bindings("");
        let expanded =
            expand_line(r#"p = base64.b64decode("fi8uc3NoL2lkX3JzYQ==")"#, &bindings).unwrap();
        assert!(expanded.contains("~/.ssh/id_rsa"), "{expanded}");
    }

    #[test]
    fn leaves_unrelated_lines_unchanged() {
        let bindings = literal_bindings("name = \"world\"\n");
        assert_eq!(expand_line("print(\"hello\")", &bindings), None);
    }

    #[test]
    fn interpolating_values_are_not_bound() {
        // A shell-expanded value is dynamic; folding it would invent a literal.
        let bindings = literal_bindings("key=\"$HOME/.ssh/id_rsa\"\n");
        assert!(bindings.is_empty());
    }
}
