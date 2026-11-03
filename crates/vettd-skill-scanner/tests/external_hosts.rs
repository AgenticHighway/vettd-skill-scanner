//! External-host assessment regressions (review T07).
//!
//! An expected-host assessment records an association: which exact
//! destinations were seen and under which policy version. It is explicitly not
//! an egress permission, not proof that redirects are benign, and not proof
//! that referenced content is safe. Unsafe-looking authorities (userinfo,
//! explicit ports, private IPs, lookalikes) stay unexpected.

use std::collections::HashMap;

use vettd_skill_scanner::{scan_skill as scan_with_observed_at, SkillScanResult};

const HEAD: &str = "---\nname: external-hosts\ndescription: External host fixtures.\n---\n";

fn scan(body: &str) -> SkillScanResult {
    let mut text_files = HashMap::new();
    text_files.insert("SKILL.md".to_string(), format!("{HEAD}{body}"));
    let all_paths: Vec<String> = text_files.keys().cloned().collect();
    scan_with_observed_at(&text_files, &all_paths, "2026-11-02T00:00:00Z")
        .expect("valid RFC3339 timestamp")
}

fn finding<'a>(
    result: &'a SkillScanResult,
    rule: &str,
) -> Option<&'a vettd_skill_scanner::Finding> {
    result.findings.iter().find(|f| f.rule_id == rule)
}

fn coverage<'a>(result: &'a SkillScanResult, rule: &str) -> Option<&'a str> {
    result
        .coverage
        .iter()
        .find(|c| c.rule_id == rule)
        .map(|c| c.detail.as_str())
}

// ---------------------------------------------------------------------------
// Association is recorded; permission is not implied.
// ---------------------------------------------------------------------------

#[test]
fn expected_only_attests_association_not_permission() {
    let result = scan("See https://learn.microsoft.com/azure/aks/ for details.");
    assert!(
        finding(&result, "VTD-0088").is_none(),
        "an expected host is not a finding"
    );
    let detail = coverage(&result, "VTD-0124").expect("association attestation");
    assert!(
        detail.contains("https://learn.microsoft.com (expected host)"),
        "the exact destination must be recorded: {detail}"
    );
    assert!(
        detail.contains("host policy 2026-11-02"),
        "the policy version must be recorded: {detail}"
    );
    assert!(
        detail.contains("Association only") && detail.contains("not authorization"),
        "the attestation must not read as an egress permission: {detail}"
    );
}

#[test]
fn redirect_safety_is_a_stated_limit_not_an_assertion() {
    let result = scan("See https://learn.microsoft.com/redirect for details.");
    let detail = coverage(&result, "VTD-0124").expect("association attestation");
    assert!(
        detail.contains("follow redirects"),
        "redirects are not evaluated; the result must say so: {detail}"
    );
}

#[test]
fn scheme_is_recorded_exactly() {
    let result = scan("See http://learn.microsoft.com/azure/ for details.");
    let detail = coverage(&result, "VTD-0124").expect("association attestation");
    assert!(
        detail.contains("http://learn.microsoft.com (expected host)"),
        "the scheme is part of the destination identity: {detail}"
    );
}

// ---------------------------------------------------------------------------
// Unrecognized and unsafe destinations stay visible, with exact evidence.
// ---------------------------------------------------------------------------

#[test]
fn third_party_doc_link_records_destination_and_policy() {
    let result = scan("See https://unrecognized.example/docs for details.");
    let hit = finding(&result, "VTD-0088").expect("unrecognized host is reviewable");
    assert!(
        hit.detail
            .contains("https://unrecognized.example (unexpected)"),
        "{}",
        hit.detail
    );
    assert!(
        hit.detail.contains("host policy 2026-11-02"),
        "{}",
        hit.detail
    );
    assert!(
        coverage(&result, "VTD-0124").is_none(),
        "an unexpected host must never receive the association attestation"
    );
}

#[test]
fn mixed_expected_and_unexpected_lists_both() {
    let result =
        scan("See https://learn.microsoft.com/azure/ and https://unrecognized.example/docs.");
    let hit = finding(&result, "VTD-0088").expect("mixed references are reviewable");
    assert!(
        hit.detail
            .contains("https://learn.microsoft.com (expected host)"),
        "{}",
        hit.detail
    );
    assert!(
        hit.detail
            .contains("https://unrecognized.example (unexpected)"),
        "{}",
        hit.detail
    );
    assert!(coverage(&result, "VTD-0124").is_none());
}

#[test]
fn private_ip_destination_is_unexpected() {
    let result = scan("See https://192.168.1.10/admin for details.");
    let hit = finding(&result, "VTD-0088").expect("private IP is not a trusted destination");
    assert!(
        hit.detail.contains("192.168.1.10 (unexpected)"),
        "{}",
        hit.detail
    );
}

#[test]
fn userinfo_and_explicit_port_fail_closed() {
    for url in [
        "https://learn.microsoft.com@unrecognized.example/",
        "https://learn.microsoft.com:8443/",
    ] {
        let result = scan(&format!("See {url} for details."));
        let hit = finding(&result, "VTD-0088")
            .unwrap_or_else(|| panic!("{url} must count as unexpected"));
        assert!(hit.detail.contains("(unexpected)"), "{url}: {}", hit.detail);
        assert!(coverage(&result, "VTD-0124").is_none(), "{url}");
    }
}

#[test]
fn every_distinct_destination_is_named_in_the_finding() {
    let mut body = String::from("See:\n");
    for i in 0..12 {
        body.push_str(&format!("- https://host{i}.invalid/page\n"));
    }
    let result = scan(&body);
    let hit = finding(&result, "VTD-0088").expect("unexpected hosts are flagged");
    for i in 0..12 {
        assert!(
            hit.detail.contains(&format!("https://host{i}.invalid")),
            "destination {i} missing from the record: {}",
            hit.detail
        );
    }
    assert!(!hit.detail.contains("more"));
}
