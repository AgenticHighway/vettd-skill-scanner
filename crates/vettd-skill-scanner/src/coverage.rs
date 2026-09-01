//! Scan coverage and attestation entries kept separate from asset findings.

use serde::{Deserialize, Serialize};

/// A fact about which scanner check ran, or what it established.
///
/// This mirrors vettd's open `SkillCoverageEntry` wire contract. `kind` stays
/// an open string so a newly-emitted Rust value degrades gracefully downstream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageEntry {
    pub kind: String,
    pub rule_id: String,
    pub label: String,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}
