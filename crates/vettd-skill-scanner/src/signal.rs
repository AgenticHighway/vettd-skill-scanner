//! Canonical `Signal` type emitted by the scanner.
//!
//! Signals travel separately from `findings` and represent non-finding
//! observations (e.g. a declared license, a declared capability). They mirror
//! the vettd web app's `AssetSignal` model. Serde attributes on every field are
//! part of the public wire contract — do not change them without a
//! corresponding wire-format version bump.

use serde::{Deserialize, Serialize};

use crate::consts::DEFAULT_SOURCE;

fn default_source() -> String {
    DEFAULT_SOURCE.to_string()
}

// The crate's signal emitters never set `source` on first-party signals, so
// the field is omitted from the wire format when it carries the default
// "vettd" value, matching the `Finding.source` pattern.
fn is_default_source(s: &str) -> bool {
    s == DEFAULT_SOURCE
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// A single non-finding signal produced by the skill scanner for one asset.
///
/// Mirrors the wire `AssetSignal` model (vettd `packages/types` +
/// `AssetSignal` Prisma model). All strings are open — there are **no closed
/// enums**: `severity` is a plain `String`, deliberately not the crate's
/// `Severity` enum, so signal values can evolve without a schema version bump.
///
/// Four fields are REQUIRED on the wire: `dataCategory`, `sourceClass`,
/// `ruleId`, `observedAt`. Subject identity (`subjectType`, `subjectId`,
/// `relatedType`, `relatedId`) is OPTIONAL — the emitter cannot fill it; vettd
/// stamps it later. `observedAt` is a caller-supplied observation time carried
/// unmodified as an ISO-8601 string; it represents "when observed", not write
/// time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Signal {
    /// Data category the signal belongs to (e.g. `"characteristics"`).
    /// REQUIRED.
    pub data_category: String,

    /// Source class within the category (e.g. `"scan"`). REQUIRED.
    pub source_class: String,

    /// Rule identifier that produced this signal (e.g.
    /// `"characteristics/declared-license"`). REQUIRED.
    pub rule_id: String,

    /// Caller-supplied observation time, ISO-8601. Carried unmodified;
    /// represents "when observed", not write time. REQUIRED.
    pub observed_at: String,

    /// Emitter of the signal. Defaults to `"vettd"` and is omitted from the
    /// wire format when set to that default (mirrors `Finding.source`).
    #[serde(default = "default_source", skip_serializing_if = "is_default_source")]
    pub source: String,

    /// Optional subject identity — vettd stamps these server-side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_type: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_id: Option<String>,

    /// Severity. **Open string**, NOT the crate's `Severity` enum.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,

    /// Human-readable label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// Extended detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,

    /// Numeric value for measurable signals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_num: Option<f64>,

    /// Text value for non-numeric signals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_text: Option<String>,

    /// Unit of `value_num`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,

    /// Method used to derive the signal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// Derivation of the signal value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derivation: Option<String>,

    /// Confidence in the signal, 0.0–1.0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,

    /// Sample size the signal is based on (Prisma `Int`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_size: Option<i64>,

    /// Whether this is a synthetic/derived signal. Omitted when false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub synthetic: bool,

    /// Arbitrary structured payload (JSON object only, per the wire contract).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Map<String, serde_json::Value>>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_signal() -> Signal {
        Signal {
            data_category: "characteristics".to_string(),
            source_class: "scan".to_string(),
            rule_id: "characteristics/declared-license".to_string(),
            observed_at: "2026-08-24T00:00:00Z".to_string(),
            source: default_source(),
            subject_type: None,
            subject_id: None,
            related_type: None,
            related_id: None,
            severity: None,
            label: None,
            detail: None,
            value_num: None,
            value_text: None,
            unit: None,
            method: None,
            derivation: None,
            confidence: None,
            sample_size: None,
            synthetic: false,
            payload: None,
        }
    }

    #[test]
    fn signal_serialises_to_camel_case() {
        let s = Signal {
            label: Some("Declared license".to_string()),
            value_text: Some("MIT".to_string()),
            ..minimal_signal()
        };
        let v = serde_json::to_value(&s).unwrap();
        assert!(v.get("dataCategory").is_some(), "dataCategory key must be camelCase");
        assert!(v.get("sourceClass").is_some(), "sourceClass key must be camelCase");
        assert!(v.get("ruleId").is_some(), "ruleId key must be camelCase");
        assert!(v.get("observedAt").is_some(), "observedAt key must be camelCase");
        assert!(v.get("valueText").is_some(), "valueText key must be camelCase");
        assert!(v.get("data_category").is_none(), "snake_case must not appear");
        assert!(v.get("source_class").is_none(), "snake_case must not appear");
        assert!(v.get("rule_id").is_none(), "snake_case must not appear");
        assert!(v.get("observed_at").is_none(), "snake_case must not appear");
    }

    #[test]
    fn optional_fields_are_omitted_when_none() {
        let s = minimal_signal();
        let v = serde_json::to_value(&s).unwrap();
        let obj = v.as_object().expect("signal is an object");
        let mut keys: Vec<&String> = obj.keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            vec!["dataCategory", "observedAt", "ruleId", "sourceClass"],
            "only the four REQUIRED keys may be present on a minimal signal"
        );
    }

    #[test]
    fn source_defaults_to_vettd_on_missing_input() {
        let json = r#"{"dataCategory":"characteristics","sourceClass":"scan","ruleId":"characteristics/declared-license","observedAt":"2026-08-24T00:00:00Z"}"#;
        let s: Signal = serde_json::from_str(json).unwrap();
        assert_eq!(s.source, "vettd");
    }

    #[test]
    fn severity_is_open_string_round_trip() {
        let s = Signal {
            severity: Some("blocker".to_string()),
            ..minimal_signal()
        };
        let json = serde_json::to_string(&s).unwrap();
        let restored: Signal = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.severity.as_deref(), Some("blocker"));
    }

    #[test]
    fn observed_at_survives_unmodified() {
        let s = Signal {
            observed_at: "2024-06-15T10:00:00.000Z".to_string(),
            ..minimal_signal()
        };
        let json = serde_json::to_string(&s).unwrap();
        let restored: Signal = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.observed_at, "2024-06-15T10:00:00.000Z");
    }
}