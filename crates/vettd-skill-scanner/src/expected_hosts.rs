//! Curated expected hosts for the external URL check (VTD-0088, #24).
//!
//! An interim allowlist: a reference whose host is on this list emits no
//! VTD-0088 finding. Every other reference is flagged exactly as before.
//! The list is compiled-in data so the suite (http-shim) and vettd-cli scan
//! against the same set with no network I/O.
//!
//! Matching fails closed: a host that cannot be read as a plain DNS name
//! (explicit port, userinfo, IP literal, non-ASCII, percent-encoding, empty)
//! is unexpected.

use std::sync::OnceLock;

use regex::Regex;

/// Result of the external URL check over SKILL.md and `references/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExternalUrlOutcome {
    /// No target files, so the check did not run.
    NotChecked,
    /// No external URLs (VTD-0093).
    NoUrls,
    /// URLs found, all on expected hosts (VTD-0094).
    ExpectedHostsOnly,
    /// A URL to an unexpected host; VTD-0088 was emitted.
    Flagged,
}

/// One allowlist entry.
// Production builds construct no entries until the seed set lands (#24).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum HostEntry {
    /// Matches exactly this lowercase host.
    Exact(&'static str),
    /// Regex that must match the whole lowercase host; the loader anchors
    /// it. `example` is a host it must match, used to test for lookalikes.
    Pattern {
        regex: &'static str,
        example: &'static str,
    },
}

/// The curated set. Each entry is a host owned or operated by a cohort
/// producer; the justification for every entry is recorded in the PR that
/// adds it.
const EXPECTED_HOSTS: &[HostEntry] = &[];

/// Fixture entries on the reserved `.test` TLD (RFC 2606), so tests never
/// depend on the production set.
#[cfg(test)]
const TEST_HOSTS: &[HostEntry] = &[
    HostEntry::Exact("expected.test"),
    HostEntry::Pattern {
        regex: r"[a-z0-9-]+\.docs\.expected\.test",
        example: "api.docs.expected.test",
    },
];

fn entries() -> impl Iterator<Item = &'static HostEntry> {
    #[cfg(test)]
    let extra = TEST_HOSTS.iter();
    #[cfg(not(test))]
    let extra = [].iter();
    EXPECTED_HOSTS.iter().chain(extra)
}

fn compiled_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        entries()
            .filter_map(|e| match e {
                HostEntry::Pattern { regex, .. } => Some(anchored(regex)),
                HostEntry::Exact(_) => None,
            })
            .collect()
    })
}

fn anchored(regex: &str) -> Regex {
    Regex::new(&format!("^(?:{regex})$")).expect("bad expected-host pattern")
}

/// Normalizes a URL authority to a plain lowercase host, or `None` when it
/// is not one.
fn plain_host(authority: &str) -> Option<String> {
    let host = authority.to_ascii_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host);
    let labels: Vec<&str> = host.split('.').collect();
    let valid_labels = labels
        .iter()
        .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    // An all-numeric final label is an IPv4 literal (or a shorthand of one).
    let is_ip = labels
        .last()
        .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()));
    (valid_labels && !is_ip).then(|| host.to_string())
}

/// Yields the host of every `http(s)://` reference in `content`, or `None`
/// for a reference whose authority is not a plain host.
fn extract_hosts(content: &str) -> impl Iterator<Item = Option<String>> + '_ {
    static SCHEME_RE: OnceLock<Regex> = OnceLock::new();
    let re = SCHEME_RE.get_or_init(|| Regex::new(r"(?i)https?://").expect("bad scheme re"));
    re.find_iter(content).map(|m| {
        let rest = &content[m.end()..];
        // Characters that can belong to an authority are consumed (including
        // ones `plain_host` rejects, like `@`, `:` and non-ASCII), so they
        // fail closed rather than truncating to a trusted-looking prefix.
        let end = rest
            .find(|c: char| {
                !(c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '@' | '[' | ']' | '%'))
            })
            .unwrap_or(rest.len());
        plain_host(&rest[..end])
    })
}

fn is_expected_host(host: &str) -> bool {
    entries().any(|e| matches!(e, HostEntry::Exact(h) if *h == host))
        || compiled_patterns().iter().any(|re| re.is_match(host))
}

/// True when `content` references any host outside the expected set.
pub(crate) fn has_unexpected_external_url(content: &str) -> bool {
    extract_hosts(content).any(|host| !host.is_some_and(|h| is_expected_host(&h)))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::scanner::scan_skill;

    fn unexpected(url: &str) -> bool {
        has_unexpected_external_url(&format!("See {url} for details."))
    }

    #[test]
    fn exact_host_is_expected() {
        assert!(!unexpected("https://expected.test/guide"));
        assert!(!unexpected("http://expected.test"));
    }

    #[test]
    fn host_match_ignores_case_and_trailing_dot() {
        assert!(!unexpected("HTTPS://Expected.TEST/guide"));
        assert!(!unexpected("https://expected.test./guide"));
    }

    #[test]
    fn exact_entry_does_not_cover_subdomains() {
        // Subdomain coverage must be opted into per entry; otherwise a
        // producer-owned apex would vouch for hosts it may not control.
        assert!(unexpected("https://evil.expected.test/"));
    }

    #[test]
    fn pattern_entry_covers_its_subdomains_only() {
        assert!(!unexpected("https://api.docs.expected.test/v1"));
        assert!(unexpected("https://docs.expected.test/"));
        assert!(unexpected("https://a.b.docs.expected.test/"));
    }

    #[test]
    fn non_plain_authorities_fail_closed() {
        // Each of these could resolve somewhere other than the allowlisted
        // name, so none may suppress the finding.
        for url in [
            "https://expected.test:8443/",
            "https://expected.test:443/",
            "https://expected.test@evil.test/",
            "https://user:pw@expected.test/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://expécted.test/",
            "https://expected%2etest/",
            "https:///path",
            "https://",
        ] {
            assert!(unexpected(url), "{url} must count as unexpected");
        }
    }

    #[test]
    fn markdown_punctuation_ends_the_host() {
        assert!(!has_unexpected_external_url(
            "[guide](https://expected.test/guide) and <https://expected.test>, **https://expected.test**"
        ));
    }

    #[test]
    fn one_unexpected_reference_among_expected_ones_is_flagged() {
        assert!(has_unexpected_external_url(
            "https://expected.test/a then https://evil.test/b"
        ));
    }

    #[test]
    fn entries_are_lowercase_plain_hosts() {
        // A non-normalized entry or example could never match, silently
        // dropping a host.
        for e in entries() {
            let h = match e {
                HostEntry::Exact(h) => h,
                HostEntry::Pattern { example, .. } => example,
            };
            assert_eq!(plain_host(h).as_deref(), Some(*h), "bad entry {h}");
        }
    }

    #[test]
    fn patterns_reject_lookalikes_of_their_example() {
        // Catches unescaped dots and patterns broad enough to match hosts
        // outside the producer's domain, e.g. `.*expected\.test` matching
        // `evilexpected.test`.
        for e in entries() {
            let HostEntry::Pattern { regex, example } = e else {
                continue;
            };
            let re = anchored(regex);
            assert!(re.is_match(example), "{regex} must match its example");
            let mut lookalikes = vec![format!("{example}.evil.test")];
            for (i, _) in example.match_indices('.') {
                lookalikes.push(format!("{}{}", &example[..i], &example[i + 1..]));
                lookalikes.push(format!("{}x{}", &example[..i], &example[i + 1..]));
            }
            for lookalike in lookalikes {
                assert!(!re.is_match(&lookalike), "{regex} matched {lookalike}");
            }
        }
    }

    fn scan_files(files: &[(&str, &str)]) -> crate::SkillScanResult {
        let text_files: HashMap<String, String> = files
            .iter()
            .map(|(p, c)| (p.to_string(), c.to_string()))
            .collect();
        let all_paths: Vec<String> = text_files.keys().cloned().collect();
        scan_skill(&text_files, &all_paths, "2026-08-31T00:00:00Z").expect("valid timestamp")
    }

    fn has_rule(result: &crate::SkillScanResult, rule_id: &str) -> (bool, bool) {
        (
            result.findings.iter().any(|f| f.rule_id == rule_id),
            result.coverage.iter().any(|c| c.rule_id == rule_id),
        )
    }

    const SKILL_HEAD: &str = "---\nname: links\ndescription: Links.\n---\n";

    #[test]
    fn expected_only_scan_attests_instead_of_flagging() {
        // Expected hosts must not dock the grade, yet the report still has to
        // say the check ran and found URLs: VTD-0094, distinct from VTD-0093.
        let result = scan_files(&[(
            "SKILL.md",
            &format!("{SKILL_HEAD}See https://expected.test."),
        )]);
        assert_eq!(has_rule(&result, "VTD-0088"), (false, false));
        assert_eq!(has_rule(&result, "VTD-0094"), (false, true));
        assert_eq!(has_rule(&result, "VTD-0093"), (false, false));
    }

    #[test]
    fn no_url_scan_keeps_vtd_0093_only() {
        let result = scan_files(&[("SKILL.md", &format!("{SKILL_HEAD}No links."))]);
        assert_eq!(has_rule(&result, "VTD-0093"), (false, true));
        assert_eq!(has_rule(&result, "VTD-0094"), (false, false));
    }

    #[test]
    fn unexpected_reference_keeps_todays_finding_and_no_attestation() {
        let result = scan_files(&[
            (
                "SKILL.md",
                &format!("{SKILL_HEAD}See https://expected.test."),
            ),
            ("references/a.md", "https://evil.test/payload"),
        ]);
        let finding = result
            .findings
            .iter()
            .find(|f| f.rule_id == "VTD-0088")
            .expect("unexpected host must still be flagged");
        assert_eq!(finding.filepath.as_deref(), Some("references/a.md"));
        assert_eq!(
            finding.detail,
            "External URL(s) detected in references/a.md — referenced content can change after audit"
        );
        assert_eq!(has_rule(&result, "VTD-0093"), (false, false));
        assert_eq!(has_rule(&result, "VTD-0094"), (false, false));
    }
}
