//! Output type for a single skill scan.

use crate::coverage::CoverageEntry;
use crate::finding::Finding;
use crate::signal::Signal;

/// The result of scanning one skill package.
///
/// Mirrors `SkillAnalysisResult` from the vettd web app's `skill-analyzer.ts`,
/// minus `overallGrade` and `overallScore` — grade computation is the caller's
/// responsibility and lives outside this crate.
#[derive(Debug, Clone)]
pub struct SkillScanResult {
    /// All findings produced by the scanner, including structural checks,
    /// security detections, and chain synthesis findings.
    ///
    /// **Important**: chain detection may mutate `severity` on existing entries.
    /// If the caller computes a grade, it must do so *after* receiving this result
    /// (chain detection runs as the final step inside `scan_skill`).
    pub findings: Vec<Finding>,

    /// Non-finding signals emitted by the engine (e.g. license, declared
    /// capabilities). Travel separately from `findings`; empty for now — the
    /// first engine-hosted signal rule (#915/#916) fills this.
    pub signals: Vec<Signal>,

    /// Scan attestations and coverage notices. These describe the analysis,
    /// rather than the asset, so they never travel in `findings` or `signals`.
    pub coverage: Vec<CoverageEntry>,

    /// Whether a `SKILL.md` or `skill.md` file exists at the package root.
    pub has_skill_md: bool,

    /// Whether a `scripts/` directory exists in the package.
    pub has_scripts: bool,

    /// Whether a `references/` directory exists in the package.
    pub has_references: bool,

    /// Whether an `evals/` directory or `evals.json` exists in the package.
    pub has_evals: bool,

    /// Whether an `assets/` directory exists in the package.
    pub has_assets: bool,

    /// Total number of paths in the package (text + binary).
    pub file_count: usize,
}
