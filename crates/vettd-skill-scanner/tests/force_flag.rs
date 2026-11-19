//! `--force` precision.
//!
//! Real-data fixture: Kilo-Org/skills at a30ff33da809171784aca50d1b5978cebc2185f1,
//! `skills/jupyter-notebook/scripts/new_notebook.py` lines 17-28 (verbatim): `--force` is an
//! explicit-overwrite option of a notebook generator, not a bypass of an authorization boundary.

use std::collections::HashMap;

use vettd_skill_scanner::{scan_skill, Finding, Severity};

const OBSERVED: &str = "2026-11-18T00:00:00Z";

const KILO_DEFINITION: &str = "    parser.add_argument(\"--kind\", choices=(\"experiment\", \"tutorial\"), default=\"experiment\")\n    parser.add_argument(\"--title\", required=True)\n    parser.add_argument(\"--out\", type=Path)\n    parser.add_argument(\"--force\", action=\"store_true\")\n    args = parser.parse_args()\n";

const KILO_REFUSAL: &str = "    if output.exists() and not args.force:\n        raise SystemExit(f\"Refusing to overwrite existing notebook without --force: {output}\")\n";

fn bypass_findings(script: &str) -> Vec<Finding> {
    let mut text = HashMap::new();
    text.insert(
        "SKILL.md".to_string(),
        "---\nname: x\ndescription: Does a thing. Use when asked.\n---\n\nRun scripts/run.py.\n"
            .to_string(),
    );
    text.insert("scripts/run.py".to_string(), script.to_string());
    let paths = vec!["SKILL.md".to_string(), "scripts/run.py".to_string()];
    scan_skill(&text, &paths, OBSERVED)
        .unwrap()
        .findings
        .into_iter()
        .filter(|f| f.rule_id == "VTD-0028")
        .collect()
}

#[test]
fn option_definition_alone_does_not_fire() {
    assert!(bypass_findings(KILO_DEFINITION).is_empty());
}

#[test]
fn definition_split_across_lines_does_not_fire() {
    let script = "parser.add_argument(\n    \"--force\",\n    action=\"store_true\",\n)\n";
    assert!(bypass_findings(script).is_empty());
    assert!(bypass_findings("@click.option(\"--force\", is_flag=True)\n").is_empty());
}

#[test]
fn force_with_lease_does_not_fire() {
    assert!(bypass_findings("subprocess.run(['git', 'push', '--force-with-lease'])\n").is_empty());
}

#[test]
fn overwrite_use_is_low_and_labelled_as_overwrite() {
    let findings = bypass_findings(KILO_REFUSAL);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Low);
    assert!(!findings[0].label.to_lowercase().contains("safety bypass"));
}

#[test]
fn git_push_force_still_fires() {
    let findings =
        bypass_findings("subprocess.run(['git', 'push', '--force', 'origin', 'main'])\n");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Low);
}

#[test]
fn no_verify_is_unchanged() {
    let findings = bypass_findings("subprocess.run(['git', 'commit', '--no-verify'])\n");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Critical);
    assert_eq!(findings[0].label, "Safety bypass flag detected");
}

#[test]
fn no_verify_beside_a_force_definition_keeps_the_critical_label() {
    let script = format!("{KILO_DEFINITION}subprocess.run(['git', 'commit', '--no-verify'])\n");
    let findings = bypass_findings(&script);
    assert_eq!(findings[0].severity, Severity::Critical);
}
