//! Router and handlers for the shim.
//!
//! The wire contract extends the parity-adapter envelope: the request is
//! `{"textFiles": {...}, "allPaths": [...]}` (camelCase) and the response
//! adds the structural flags and scanner version on top of `{"findings"}`.

use std::collections::HashMap;

use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use vettd_skill_scanner::consts::CURRENT_SCANNER_VERSION;
use vettd_skill_scanner::{scan_skill, Finding};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScanRequest {
    text_files: HashMap<String, String>,
    all_paths: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanResponse {
    findings: Vec<Finding>,
    has_skill_md: bool,
    has_scripts: bool,
    has_references: bool,
    has_evals: bool,
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
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok": true, "scannerVersion": CURRENT_SCANNER_VERSION}))
}

async fn scan(
    Json(req): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, (StatusCode, Json<ErrorBody>)> {
    // scan_skill is CPU-bound and infallible by signature; spawn_blocking
    // keeps the runtime responsive and converts a panic into a JoinError,
    // which becomes a clean 500 instead of a hung connection.
    let result = tokio::task::spawn_blocking(move || scan_skill(&req.text_files, &req.all_paths))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    ok: false,
                    error: format!("scan panicked: {e}"),
                }),
            )
        })?;
    Ok(Json(ScanResponse {
        findings: result.findings,
        has_skill_md: result.has_skill_md,
        has_scripts: result.has_scripts,
        has_references: result.has_references,
        has_evals: result.has_evals,
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
        assert_eq!(json["scannerVersion"], 9);
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
        assert_eq!(json["scannerVersion"], 9);
        assert!(json["findings"].is_array());
    }

    // Wire parity: first-party findings omit `source` (serde skips the
    // default "vettd") — the suite's adapter relies on this and fills the
    // field itself. If this test breaks, that adapter contract changed.
    #[tokio::test]
    async fn first_party_findings_omit_source_on_the_wire() {
        let response = router()
            .oneshot(scan_request(serde_json::json!({
                "textFiles": {"SKILL.md": "# Skill"},
                "allPaths": ["SKILL.md"],
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
}
