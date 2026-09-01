//! `vettd-skill-scanner` — pure, I/O-free skill scanner for the vettd pipeline.
//!
//! ## Contract
//!
//! This crate performs **no filesystem I/O, no network access, and no stdout/stderr
//! output**. All inputs are pre-loaded by the caller. This boundary is intentional:
//! the scanner is designed to be extracted into a standalone service or container
//! without modification.
//!
//! ## Entry point
//!
//! ```ignore
//! use vettd_skill_scanner::{scan_skill, SkillScanResult};
//! use std::collections::HashMap;
//!
//! let text_files: HashMap<String, String> = /* caller loads from disk or zip */;
//! let all_paths: Vec<String>              = /* all paths including binaries */;
//!
//! let result: SkillScanResult = scan_skill(&text_files, &all_paths, "2026-08-31T00:00:00Z")
//!     .expect("caller-supplied timestamp is valid RFC3339");
//! ```
//!
//! See [`scan_skill`] for full documentation.

pub mod consts;

/// The scanner crate's own semantic version (from Cargo.toml), e.g. "0.1.4".
///
/// Distinct from [`consts::CURRENT_SCANNER_VERSION`], which is the findings
/// *schema* version (currently `9`) used to detect stale scan results. This
/// `VERSION` reports the crate's release so consumers like vettd-cli can surface
/// it in `vettd --version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

mod checks;
mod coverage;
mod emission;
mod finding;
mod language;
mod result;
mod rfc3339;
mod rules;
mod scanner;
mod signal;
mod signal_rules;
mod skill_md;

pub use coverage::CoverageEntry;
pub use finding::{Finding, FindingCategory, Intent, Severity};
pub use result::SkillScanResult;
pub use rfc3339::{is_valid_rfc3339, now_utc_rfc3339};
pub use scanner::{scan_skill, ScanError};
pub use signal::Signal;
