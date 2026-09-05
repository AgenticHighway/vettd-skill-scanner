//! Router and handlers for the shim.
//!
//! The wire contract: the request is `{"textFiles": {...}, "allPaths": [...]}`
//! (camelCase) and the response carries the structural flags and scanner
//! version alongside `{"findings"}`. `bundlePath` and `repoPaths` are
//! optional additions (vettd#1011 follow-up) that let a GitHub-directory
//! import resolve internal references against the wider repository, not
//! just the skill's own subtree — omitting them is equivalent to a bare zip
//! upload with no repository context, and behaves exactly as before they
//! existed.

use std::collections::HashMap;

use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use vettd_skill_scanner::consts::CURRENT_SCANNER_VERSION;
use vettd_skill_scanner::{
    now_utc_rfc3339, scan_skill_with_repo_context, CoverageEntry, Finding, RepoContext, Signal,
};

// axum's Json extractor defaults to a 2 MiB request body cap, which real
// skill directories blow past easily (e.g. pbakaus/impeccable bundles ~3 MiB
// of detector scripts per skill.md, duplicated across ~20 agent-CLI path
// conventions — every one 413'd). The suite's GitHub fetcher already caps
// total text content at 10 MiB (vettd packages/api github-skill-fetcher), so
// 100 MiB leaves generous headroom without removing the cap altogether.
const MAX_SCAN_BODY_BYTES: usize = 100 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScanRequest {
    text_files: HashMap<String, String>,
    all_paths: Vec<String>,
    /// This skill's own directory, relative to the repository root. Absent (or omitted) for a
    /// caller with no repository concept — a bare zip upload.
    #[serde(default)]
    bundle_path: String,
    /// Every path in the repository, relative to the repository root. Absent (or omitted) makes
    /// internal-reference resolution behave exactly as it did before this field existed.
    #[serde(default)]
    repo_paths: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanResponse {
    findings: Vec<Finding>,
    /// Non-finding signals. Omitted when empty so a zero-signal run is
    /// byte-identical to the pre-signals response shape.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    signals: Vec<Signal>,
    /// Coverage and attestation facts about the scanner run, omitted when
    /// empty so existing response bytes remain unchanged.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    coverage: Vec<CoverageEntry>,
    has_skill_md: bool,
    has_scripts: bool,
    has_references: bool,
    has_evals: bool,
    has_assets: bool,
    file_count: usize,
    scanner_version: u32,
}

#[derive(Serialize)]
struct ErrorBody {
    ok: bool,
    error: String,
}

pub fn router() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/scan", post(scan))
        .layer(DefaultBodyLimit::max(MAX_SCAN_BODY_BYTES))
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok": true, "scannerVersion": CURRENT_SCANNER_VERSION}))
}

async fn scan(
    Json(req): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, (StatusCode, Json<ErrorBody>)> {
    // scan_skill is CPU-bound; spawn_blocking keeps the runtime responsive and
    // converts a panic into a JoinError, which becomes a clean 500 instead of
    // a hung connection. The timestamp the shim supplies is always valid, so
    // the inner ScanError arm is defensive only.
    let observed_at = now_utc_rfc3339();
    let result = tokio::task::spawn_blocking(move || {
        let repo_context = RepoContext {
            bundle_path: &req.bundle_path,
            repo_paths: &req.repo_paths,
        };
        scan_skill_with_repo_context(&req.text_files, &req.all_paths, &repo_context, &observed_at)
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                ok: false,
                error: format!("scan panicked: {e}"),
            }),
        )
    })?
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                ok: false,
                error: format!("scan failed: {e}"),
            }),
        )
    })?;
    Ok(Json(ScanResponse {
        findings: result.findings,
        signals: result.signals,
        coverage: result.coverage,
        has_skill_md: result.has_skill_md,
        has_scripts: result.has_scripts,
        has_references: result.has_references,
        has_evals: result.has_evals,
        has_assets: result.has_assets,
        file_count: result.file_count,
        scanner_version: CURRENT_SCANNER_VERSION,
    }))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::router;

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body read")
            .to_bytes();
        serde_json::from_slice(&bytes).expect("json body")
    }

    fn scan_request(body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/scan")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("request")
    }

    #[tokio::test]
    async fn health_reports_ok_and_scanner_version() {
        let response = router()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["ok"], true);
        assert_eq!(json["scannerVersion"], super::CURRENT_SCANNER_VERSION);
    }

    #[tokio::test]
    async fn scan_returns_findings_and_structural_flags() {
        let response = router()
            .oneshot(scan_request(serde_json::json!({
                "textFiles": {"SKILL.md": "# My Skill"},
                "allPaths": ["SKILL.md"],
            })))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["hasSkillMd"], true);
        assert_eq!(json["fileCount"], 1);
        assert_eq!(json["scannerVersion"], super::CURRENT_SCANNER_VERSION);
        assert!(json["findings"].is_array());
    }

    // Wire parity: first-party findings omit `source` (serde skips the
    // default "vettd") — the suite's adapter relies on this and fills the
    // field itself. If this test breaks, that adapter contract changed.
    // A package with no SKILL.md at all is used so the finding channel is
    // guaranteed non-empty: the reclassification moved the quality findings
    // (VTD-0083..0123) onto the signal channel, so a minimal well-formed
    // skill no longer produces findings by itself.
    #[tokio::test]
    async fn first_party_findings_omit_source_on_the_wire() {
        let response = router()
            .oneshot(scan_request(serde_json::json!({
                "textFiles": {},
                "allPaths": [],
            })))
            .await
            .expect("response");
        let json = body_json(response).await;
        let findings = json["findings"].as_array().expect("findings array");
        assert!(
            !findings.is_empty(),
            "expected findings for a minimal frontmatter-less skill"
        );
        for finding in findings {
            assert!(
                finding.get("source").is_none(),
                "source should be omitted on the wire: {finding}"
            );
        }
    }

    #[tokio::test]
    async fn scan_emits_signals_for_every_asset() {
        let response = router()
            .oneshot(scan_request(serde_json::json!({
                "textFiles": {"SKILL.md": "# My Skill"},
                "allPaths": ["SKILL.md"],
            })))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert!(
            json["signals"].is_array(),
            "every scanned asset has signals"
        );
    }

    #[tokio::test]
    async fn scan_omits_coverage_key_when_empty() {
        let response = router()
            .oneshot(scan_request(serde_json::json!({
                "textFiles": {"config.txt": "api_key = \"xK9mP2qRzT8wLvN3sY6cB1jH4dF7gA0eUiOhWkMnS5tX\""},
                "allPaths": ["config.txt"],
            })))
            .await
            .expect("response");
        let json = body_json(response).await;
        assert!(
            json.get("coverage").is_none(),
            "the coverage key must be absent when the scanner produced none"
        );
    }

    // vettd#1011 follow-up: a `../`-relative reference absent from the skill's own subtree
    // resolves once `bundlePath`/`repoPaths` supply the wider repository.
    #[tokio::test]
    async fn scan_resolves_internal_references_against_repo_context() {
        let response = router()
            .oneshot(scan_request(serde_json::json!({
                "textFiles": {"SKILL.md": "---\nname: pdf-tool\n---\nLoad `../../references/shared.md` first."},
                "allPaths": ["SKILL.md"],
                "bundlePath": "skills/pdf-tool",
                "repoPaths": ["SKILL.md", "references/shared.md", "skills/pdf-tool/SKILL.md"],
            })))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        let signals = json["signals"].as_array().cloned().unwrap_or_default();
        assert!(
            !signals
                .iter()
                .any(|s| s["ruleId"] == "reliability/unresolvable-internal-references"),
            "a real repo-root file reached via `..` must resolve: {signals:?}"
        );
    }

    // Omitting bundlePath/repoPaths entirely (a bare zip upload, or any pre-existing caller) must
    // behave exactly as before this wire addition existed — same reference, still unresolvable.
    #[tokio::test]
    async fn scan_without_repo_context_still_flags_the_same_dot_dot_reference() {
        let response = router()
            .oneshot(scan_request(serde_json::json!({
                "textFiles": {"SKILL.md": "---\nname: pdf-tool\n---\nLoad `../../references/shared.md` first."},
                "allPaths": ["SKILL.md"],
            })))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        let signals = json["signals"].as_array().cloned().unwrap_or_default();
        assert!(
            signals
                .iter()
                .any(|s| s["ruleId"] == "reliability/unresolvable-internal-references"),
            "without repo context, an out-of-bundle reference is still reported missing: {signals:?}"
        );
    }

    #[tokio::test]
    async fn scan_rejects_invalid_json() {
        let response = router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/scan")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{not json"))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert!(response.status().is_client_error());
    }

    // scan_skill is total — an empty submission still scans (and reports the
    // missing SKILL.md) rather than erroring.
    #[tokio::test]
    async fn scan_handles_empty_input() {
        let response = router()
            .oneshot(scan_request(serde_json::json!({
                "textFiles": {},
                "allPaths": [],
            })))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["hasSkillMd"], false);
        assert_eq!(json["fileCount"], 0);
    }

    // Regression test for a real-world 413: pbakaus/impeccable's skill
    // bundles are ~3 MiB of detector scripts, well past axum's 2 MiB
    // default Json body limit. A single oversized file here reproduces
    // that failure mode without needing the full multi-file payload.
    #[tokio::test]
    async fn scan_accepts_payloads_larger_than_axum_default_body_limit() {
        let big_file = "x".repeat(3 * 1024 * 1024); // 3 MiB, exceeds axum's 2 MiB default
        let response = router()
            .oneshot(scan_request(serde_json::json!({
                "textFiles": {"scripts/big.mjs": big_file},
                "allPaths": ["scripts/big.mjs"],
            })))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["fileCount"], 1);
    }
}
