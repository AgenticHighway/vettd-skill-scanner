use std::sync::OnceLock;

use regex::Regex;

// Mirrors vettd's hasChecklist: /- \[ \]/ || /##?\s*checklist/i
pub(crate) fn has_checklist(body: &str) -> bool {
    if body.contains("- [ ]") {
        return true;
    }
    static CHECKLIST_RE: OnceLock<Regex> = OnceLock::new();
    let re = CHECKLIST_RE
        .get_or_init(|| Regex::new(r"(?im)^##?\s*checklist").expect("bad checklist re"));
    re.is_match(body)
}
pub(crate) fn has_external_url(content: &str) -> bool {
    content.contains("http://") || content.contains("https://")
}

pub(crate) fn has_cli_hint(content: &str) -> bool {
    let lower = content.to_lowercase();
    lower.contains("argparse")
        || content.contains("--help")
        || lower.contains("argumentparser")
        || lower.contains(".option(")
        || lower.contains("yargs")
        || lower.contains("commander")
        || lower.contains("process.argv")
        || lower.contains("deno.args")
        || lower.contains("sys.argv")
        || lower.contains("click.command")
        || lower.contains("click.group")
        || lower.contains("typer.")
        || content.contains("if __name__ == '__main__'")
        || content.contains("if __name__ == \"__main__\"")
}

/// heuristically determines whether a script is a CLI entry point rather than a library or helper.
///
/// uses path depth, file extension, basename/subdirectory blocklists, and CLI indicator
/// detection to distinguish runnable scripts from support files. shell scripts directly under
/// `scripts/` always return `true`; files in helper subdirectories require a positive
/// `has_cli_hint` result.
///
/// # Parameters
/// - `path` — normalized relative path within the skill package.
/// - `content` — decoded file content.
pub(crate) fn is_likely_cli_script(path: &str, content: &str) -> bool {
    if !path.starts_with("scripts/") {
        return false;
    }
    let lower = path.to_lowercase();
    let basename = lower.rsplit('/').next().unwrap_or("");
    const NON_CLI_BASENAMES: &[&str] = &[
        "__init__.py",
        "utils.py",
        "helper.py",
        "helpers.py",
        "base.py",
        "constants.py",
    ];
    if NON_CLI_BASENAMES.contains(&basename) {
        return false;
    }
    let ext = lower.rsplit('.').next().unwrap_or("");

    const NON_CLI_EXTS: &[&str] = &[
        "json", "xml", "xsd", "yaml", "yml", "toml", "txt", "md", "csv", "tsv",
    ];
    if NON_CLI_EXTS.contains(&ext) {
        return false;
    }

    if lower.contains("/schemas/")
        || lower.contains("/templates/")
        || lower.contains("/fixtures/")
        || lower.contains("/examples/")
        || lower.contains("/testdata/")
    {
        return false;
    }

    if lower.contains("/helpers/") || lower.contains("/lib/") || lower.contains("/validators/") {
        return has_cli_hint(content);
    }

    if matches!(ext, "sh" | "bash" | "zsh") {
        return true;
    }

    let depth = path.split('/').count();
    depth <= 2 || has_cli_hint(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- has_checklist ---
    #[test]
    fn has_checklist_detects_task_item() {
        assert!(has_checklist("- [ ] step one\n- [ ] step two"));
    }
    #[test]
    fn has_checklist_detects_heading() {
        assert!(has_checklist("## Checklist\nDo the thing."));
    }
    #[test]
    fn has_checklist_false_when_absent() {
        assert!(!has_checklist("No checklist here."));
    }

    // --- has_external_url ---
    #[test]
    fn has_external_url_detects_https() {
        assert!(has_external_url("See https://example.com for more."));
    }
    #[test]
    fn has_external_url_false_when_absent() {
        assert!(!has_external_url("No links here."));
    }

    // --- is_likely_cli_script ---
    #[test]
    fn shell_script_directly_under_scripts_is_cli() {
        assert!(is_likely_cli_script("scripts/run.sh", "#!/bin/bash"));
    }
    #[test]
    fn non_scripts_path_is_not_cli() {
        assert!(!is_likely_cli_script("src/main.py", "import sys"));
    }
    #[test]
    fn data_file_in_scripts_is_not_cli() {
        assert!(!is_likely_cli_script("scripts/config.json", "{}"));
    }
    #[test]
    fn helper_subdir_without_cli_hint_is_not_cli() {
        assert!(!is_likely_cli_script(
            "scripts/helpers/util.py",
            "def helper(): pass"
        ));
    }
    #[test]
    fn helper_subdir_with_cli_hint_is_cli() {
        assert!(is_likely_cli_script(
            "scripts/helpers/main.py",
            "import argparse\nparser = argparse.ArgumentParser()"
        ));
    }
}
