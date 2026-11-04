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
/// Upper bound on a folded view. A larger view is dropped: the scan then sees
/// only the original line, which is safe, rather than analysing unbounded
/// attacker-controlled text.
const MAX_EXPANDED: usize = 4096;

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
///
/// Substitution is a single pass over the *original* line, never over its own
/// output, and never inside a quoted literal. A bound value therefore cannot
/// trigger another substitution, and the result is capped by [`MAX_EXPANDED`].
pub(crate) fn expand_line(line: &str, bindings: &[(String, String)]) -> Option<String> {
    if line.len() > MAX_EXPANDED {
        return None;
    }

    let mut expanded = substitute_bindings(line, bindings)?;
    if expanded.len() > MAX_EXPANDED {
        return None;
    }

    expanded = fold_literals(&expanded);
    if expanded.len() > MAX_EXPANDED {
        return None;
    }

    if let Some(decoded) = decode_short_base64(&expanded) {
        if expanded.len() + 1 + decoded.len() > MAX_EXPANDED {
            return None;
        }
        expanded.push(' ');
        expanded.push_str(&decoded);
    }

    (expanded != line).then_some(expanded)
}

/// One left-to-right pass over `src`, replacing bound names in value position.
///
/// A name is only replaced where it is a value: never inside a quoted literal,
/// a property (`.name`), a call (`name(`), a keyword argument (`name:`), or an
/// assignment target (`name =`). The replacement text is emitted verbatim and
/// is not rescanned, so bindings cannot expand into one another.
fn substitute_bindings(src: &str, bindings: &[(String, String)]) -> Option<String> {
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    let mut consumed = 0usize;
    let mut quote: Option<char> = None;

    while let Some(c) = rest.chars().next() {
        if out.len() > MAX_EXPANDED {
            return None;
        }
        // Inside a literal nothing is substituted; only the closing quote and
        // an escape keep the scanner's place.
        if let Some(q) = quote {
            out.push(c);
            rest = &rest[c.len_utf8()..];
            consumed += c.len_utf8();
            if c == '\\' {
                if let Some(next) = rest.chars().next() {
                    out.push(next);
                    rest = &rest[next.len_utf8()..];
                    consumed += next.len_utf8();
                }
            } else if c == q {
                quote = None;
            }
            continue;
        }

        match c {
            '"' | '\'' => {
                quote = Some(c);
                out.push(c);
                rest = &rest[c.len_utf8()..];
                consumed += c.len_utf8();
            }
            '$' => {
                let after_dollar = &rest[1..];
                let braced = after_dollar
                    .strip_prefix('{')
                    .and_then(|s| s.split_once('}'))
                    .filter(|(n, _)| !n.is_empty() && n.chars().all(is_ident_char));
                let (name, consumed_inner): (String, usize) = match braced {
                    // `$`, `{`, name, `}`.
                    Some((n, _)) => (n.to_string(), n.len() + 3),
                    None => {
                        let name: String = after_dollar
                            .chars()
                            .take_while(|c| is_ident_char(*c))
                            .collect();
                        if name.is_empty() || !is_ident_start(name.chars().next().unwrap_or('_')) {
                            out.push(c);
                            rest = after_dollar;
                            consumed += 1;
                            continue;
                        }
                        let len = name.len();
                        // `$` and the name.
                        (name, len + 1)
                    }
                };
                match lookup(bindings, &name) {
                    Some(value) => out.push_str(unquote(value)),
                    None => {
                        out.push('$');
                        out.push_str(&name);
                    }
                }
                rest = &rest[consumed_inner..];
                consumed += consumed_inner;
            }
            c if is_ident_start(c) => {
                let name: String = rest.chars().take_while(|c| is_ident_char(*c)).collect();
                let abs = consumed;
                let next = rest[name.len()..].chars().next();
                let value_position = prev_allows(src, abs) && next_allows(next);
                match lookup(bindings, &name) {
                    Some(value) if value_position => out.push_str(value),
                    _ => out.push_str(&name),
                }
                rest = &rest[name.len()..];
                consumed += name.len();
            }
            _ => {
                out.push(c);
                rest = &rest[c.len_utf8()..];
                consumed += c.len_utf8();
            }
        }
    }

    Some(out)
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn lookup<'a>(bindings: &'a [(String, String)], name: &str) -> Option<&'a str> {
    bindings
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, value)| value.as_str())
}

/// True when the character before `name` lets it be a value, not a property,
/// shell expansion, or the tail of a longer identifier.
fn prev_allows(src: &str, abs: usize) -> bool {
    if abs == 0 {
        return true;
    }
    let b = src.as_bytes()[abs - 1];
    !(b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'$' | b'{'))
}

/// True when the character after `name` lets it be a value, not a call,
/// keyword argument, or assignment target.
fn next_allows(next: Option<char>) -> bool {
    match next {
        None => true,
        Some(c) => !(c.is_ascii_alphanumeric() || matches!(c, '_' | '(' | '=' | ':')),
    }
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

    #[test]
    fn substitution_does_not_recurse_into_bound_values() {
        // Each value names the next binding. A recursive expansion would grow
        // multiplicatively; a single pass over the original line may only
        // replace the names the line itself contains.
        let content = "\
v0 = \"v1 v1 v1 v1\"\n\
v1 = \"v2 v2 v2 v2\"\n\
v2 = \"v3 v3 v3 v3\"\n\
v3 = \"v4 v4 v4 v4\"\n\
v4 = \"v5 v5 v5 v5\"\n\
v5 = \"xxxxxxxxxxxxxxxx\"\n";
        let bindings = literal_bindings(content);
        let line = "x = v0 v0 v0 v0";
        let expanded = expand_line(line, &bindings).expect("v0 is bound");
        assert!(
            expanded.len() <= MAX_EXPANDED,
            "expansion must stay bounded, got {} bytes",
            expanded.len()
        );
        assert!(
            !expanded.contains("xxxxxxxxxxxxxxxx"),
            "a bound value must not be expanded again: {expanded}"
        );
    }

    #[test]
    fn oversized_expansion_is_dropped() {
        let big = "a".repeat(MAX_LITERAL);
        let bindings = literal_bindings(&format!("big = \"{big}\"\n"));
        let line = format!("x = {}", "big ".repeat(30));
        assert!(
            expand_line(&line, &bindings).is_none(),
            "an expansion past the cap must be dropped, not analysed"
        );
    }

    #[test]
    fn names_inside_quoted_literals_are_not_substituted() {
        let bindings = literal_bindings("name = \"/home/user/.ssh/id_rsa\"\n");
        assert_eq!(expand_line("print(\"name\")", &bindings), None);
    }
}
