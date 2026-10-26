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
// The production set has no `Pattern` entries yet.
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
    /// Matches `github.com/<org>/...` for this lowercase org. GitHub is
    /// multi-tenant, so only the org path identifies the producer.
    GitHubOrg(&'static str),
}

use HostEntry::{Exact, GitHubOrg};

/// The curated set, derived from the provider-associated URLs in the
/// 2026-10-26 cohort security reports (#24). The PR records the per-entry
/// evidence.
const EXPECTED_HOSTS: &[HostEntry] = &[
    // awesome-claude-skills (ComposioHQ)
    Exact("composio.dev"),
    Exact("platform.composio.dev"),
    Exact("rube.app"),
    // better-auth
    Exact("better-auth.com"),
    GitHubOrg("better-auth"),
    // browserbase
    Exact("browserbase.com"),
    Exact("api.browserbase.com"),
    Exact("docs.browserbase.com"),
    GitHubOrg("browserbase"),
    // cloudflare-skills
    Exact("developers.cloudflare.com"),
    Exact("challenges.cloudflare.com"),
    Exact("dash.cloudflare.com"),
    GitHubOrg("cloudflare"),
    // firecrawl
    Exact("www.firecrawl.dev"),
    Exact("api.firecrawl.dev"),
    Exact("docs.firecrawl.dev"),
    GitHubOrg("firecrawl"),
    // microsoft-skills
    Exact("microsoft.com"),
    Exact("learn.microsoft.com"),
    Exact("azure.microsoft.com"),
    Exact("azuremarketplace.microsoft.com"),
    Exact("graph.microsoft.com"),
    Exact("mcr.microsoft.com"),
    Exact("portal.azure.com"),
    Exact("management.azure.com"),
    Exact("cognitiveservices.azure.com"),
    Exact("your-resource.cognitiveservices.azure.com"),
    Exact("your-resource.openai.azure.com"),
    Exact("my-resource.openai.azure.com"),
    Exact("xxx.in.applicationinsights.azure.com"),
    Exact("js.monitor.azure.com"),
    Exact("mcp.ai.azure.com"),
    Exact("documentintelligence.ai.azure.com"),
    Exact("auth.msft.communication.azure.com"),
    Exact("api.loganalytics.azure.cn"),
    Exact("management.chinacloudapi.cn"),
    GitHubOrg("microsoft"),
    GitHubOrg("azure"),
    GitHubOrg("azure-samples"),
    // neondatabase
    Exact("neon.com"),
    Exact("console.neon.tech"),
    GitHubOrg("neondatabase"),
    // obra-superpowers
    Exact("api.github.com"),
    GitHubOrg("obra"),
    // openai-skills
    Exact("developers.openai.com"),
    Exact("platform.openai.com"),
    GitHubOrg("openai"),
    // remotion-dev
    Exact("www.remotion.dev"),
    GitHubOrg("remotion-dev"),
    // resend
    Exact("resend.com"),
    GitHubOrg("resend"),
    // sentry-skills
    Exact("develop.sentry.dev"),
    Exact("sentry.sentry.io"),
    Exact("us.sentry.io"),
    // supabase
    Exact("supabase.com"),
    Exact("mcp.supabase.com"),
    GitHubOrg("supabase"),
    // trailofbits-skills
    Exact("blog.trailofbits.com"),
    GitHubOrg("trailofbits"),
    // vercel-agent-skills
    Exact("vercel.com"),
];

/// Fixture entries on the reserved `.test` TLD (RFC 2606), so tests never
/// depend on the production set.
#[cfg(test)]
const TEST_HOSTS: &[HostEntry] = &[
    Exact("expected.test"),
    HostEntry::Pattern {
        regex: r"[a-z0-9-]+\.docs\.expected\.test",
        example: "api.docs.expected.test",
    },
    GitHubOrg("expected-org"),
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
                _ => None,
            })
            .collect()
    })
}

fn anchored(regex: &str) -> Regex {
    Regex::new(&format!("^(?:{regex})$")).expect("bad expected-host pattern")
}

/// A parsed reference: its plain host and, when the path is safe to read,
/// its lowercase first path segment.
struct UrlRef {
    host: String,
    first_segment: Option<String>,
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

/// The lowercase first segment of `path` (text after the authority's `/`),
/// or `None` when the path could resolve elsewhere: dot segments,
/// backslashes and percent-encoding are rejected rather than normalized.
fn first_segment(path: &str) -> Option<String> {
    let end = path
        .find(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    '?' | '#' | ')' | ']' | '>' | '<' | '"' | '\'' | '`' | '*' | '|'
                )
        })
        .unwrap_or(path.len());
    let path = path[..end].trim_end_matches(['.', ',']);
    if path.contains("..") || path.contains('\\') || path.contains('%') {
        return None;
    }
    let segment = path.split('/').next()?;
    (!segment.is_empty()
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-'))
    .then(|| segment.to_ascii_lowercase())
}

/// Yields every `http(s)://` reference in `content`, or `None` for a
/// reference whose authority is not a plain host.
fn extract_refs(content: &str) -> impl Iterator<Item = Option<UrlRef>> + '_ {
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
        let host = plain_host(&rest[..end])?;
        let first_segment = rest[end..].strip_prefix('/').and_then(first_segment);
        Some(UrlRef {
            host,
            first_segment,
        })
    })
}

fn is_expected(r: &UrlRef) -> bool {
    entries().any(|e| match e {
        Exact(h) => *h == r.host,
        GitHubOrg(org) => r.host == "github.com" && r.first_segment.as_deref() == Some(*org),
        HostEntry::Pattern { .. } => false,
    }) || compiled_patterns().iter().any(|re| re.is_match(&r.host))
}

/// True when `content` references any URL outside the expected set.
pub(crate) fn has_unexpected_external_url(content: &str) -> bool {
    extract_refs(content).any(|r| !r.is_some_and(|r| is_expected(&r)))
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
            match e {
                Exact(h) | HostEntry::Pattern { example: h, .. } => {
                    assert_eq!(plain_host(h).as_deref(), Some(*h), "bad entry {h}")
                }
                GitHubOrg(org) => {
                    assert_eq!(first_segment(org).as_deref(), Some(*org), "bad org {org}")
                }
            }
        }
    }

    #[test]
    fn github_org_entry_matches_only_that_org() {
        // github.com hosts every account, so only the org segment may vouch
        // for a link; lookalike orgs and other hosts stay flagged.
        assert!(!unexpected(
            "https://github.com/expected-org/repo/blob/main/x.md"
        ));
        assert!(!unexpected("https://github.com/Expected-Org"));
        assert!(!unexpected("https://github.com/expected-org."));
        for url in [
            "https://github.com/",
            "https://github.com",
            "https://github.com/expected-org-evil/repo",
            "https://github.com/evil/expected-org",
            "https://gitlab.com/expected-org/repo",
            "https://api.github.com.evil.test/expected-org",
        ] {
            assert!(unexpected(url), "{url} must count as unexpected");
        }
    }

    #[test]
    fn github_org_paths_that_could_resolve_elsewhere_fail_closed() {
        // Browsers normalize these to a different org's path.
        for url in [
            "https://github.com/expected-org/../evil/repo",
            "https://github.com/expected-org/%2e%2e/evil",
            "https://github.com/expected-org\\..\\evil",
        ] {
            assert!(unexpected(url), "{url} must count as unexpected");
        }
    }

    #[test]
    fn production_set_covers_report_examples() {
        // One provider-associated URL per entry kind from the cohort reports.
        assert!(!unexpected("https://learn.microsoft.com/azure/aks/"));
        assert!(!unexpected("https://composio.dev/toolkits/_21risk"));
        assert!(!unexpected(
            "https://github.com/Azure/azure-sdk-for-net/tree/main"
        ));
        assert!(unexpected("https://github.com/microsoft-evil/skills"));
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
