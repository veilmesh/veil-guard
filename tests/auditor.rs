//! Auditor snapshot and diff logic — SPEC.md §1 (Tier 0).
//!
//! The network path is exercised by `tests/cross_language.rs` and by driving the
//! CLI against a local server; these tests cover the pure logic that decides what
//! a divergence is.

#![cfg(feature = "audit")]

use std::collections::BTreeMap;
use veil_guard::auditor::*;

fn snap(
    label: &str,
    manifest_hash: &str,
    assets: &[(&str, &str)],
    findings: Vec<Finding>,
) -> Snapshot {
    let mut observed = BTreeMap::new();
    for (path, digest) in assets {
        observed.insert(
            path.to_string(),
            ObservedAsset {
                http_status: 200,
                sha256: Some(digest.to_string()),
                size: Some(1),
                content_type: Some("text/javascript".into()),
                matched: true,
            },
        );
    }
    Snapshot {
        spec: SNAPSHOT_SPEC.into(),
        url: "https://example.invalid".into(),
        observed_at: 1_780_000_000,
        label: Some(label.into()),
        manifest_state: "VALID".into(),
        manifest_sha256: Some(manifest_hash.into()),
        manifest_version: Some(1_780_000_000),
        trust_root_id: "aa".repeat(32),
        assets_in_manifest: assets.len(),
        assets_probed: assets.len(),
        observed,
        findings,
    }
}

fn finding(kind: &str, subject: &str) -> Finding {
    serde_json::from_value(serde_json::json!({
        "severity": "critical",
        "kind": kind,
        "subject": subject,
        "detail": "d",
    }))
    .unwrap()
}

#[test]
fn identical_snapshots_do_not_diverge() {
    let a = snap("eu", "aa", &[("/a.js", "11")], vec![]);
    let b = snap("us", "aa", &[("/a.js", "11")], vec![]);
    assert!(diff(&a, &b).is_empty());
}

#[test]
fn differing_bytes_are_a_divergence() {
    let a = snap("eu", "aa", &[("/a.js", "11")], vec![]);
    let b = snap("us", "aa", &[("/a.js", "22")], vec![]);
    let d = diff(&a, &b);
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].kind, "content-differs");
    assert_eq!(d[0].subject, "/a.js");
}

#[test]
fn a_different_manifest_is_a_divergence() {
    let a = snap("eu", "aa", &[], vec![]);
    let b = snap("us", "bb", &[], vec![]);
    assert_eq!(diff(&a, &b)[0].kind, "manifest-differs");
}

/// The case the byte comparison alone would miss: an injected script is not in the
/// manifest, so it is never probed and never appears in `observed`.
#[test]
fn an_injected_unmanifested_script_shows_up_via_findings() {
    let a = snap("eu", "aa", &[("/a.js", "11")], vec![]);
    let b = snap(
        "victim",
        "aa",
        &[("/a.js", "11")],
        vec![finding("unmanifested-subresource", "/assets/evil.js")],
    );
    let d = diff(&a, &b);
    assert_eq!(
        d.len(),
        1,
        "byte comparison alone would report nothing here"
    );
    assert_eq!(d[0].kind, "finding-only-in-right:unmanifested-subresource");
    assert_eq!(d[0].subject, "/assets/evil.js");
}

#[test]
fn findings_present_on_both_sides_are_not_divergences() {
    let f = || vec![finding("content-type-mismatch", "/x.yaml")];
    let a = snap("eu", "aa", &[], f());
    let b = snap("us", "aa", &[], f());
    assert!(
        diff(&a, &b).is_empty(),
        "a shared quirk is not selective delivery"
    );
}

#[test]
fn assets_seen_by_only_one_vantage_point_are_reported() {
    let a = snap("eu", "aa", &[("/a.js", "11"), ("/b.js", "22")], vec![]);
    let b = snap("us", "aa", &[("/a.js", "11")], vec![]);
    let d = diff(&a, &b);
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].kind, "only-in-left");
    assert_eq!(d[0].subject, "/b.js");
}

#[test]
fn severity_threshold_controls_cleanliness() {
    let critical = snap("x", "aa", &[], vec![finding("content-mismatch", "/a.js")]);
    assert!(!critical.is_clean());
    assert!(!critical.is_clean_at(Severity::Critical));

    let mut warn = snap(
        "x",
        "aa",
        &[],
        vec![finding("content-type-mismatch", "/a.yaml")],
    );
    warn.findings[0].severity = Severity::Warning;
    assert!(!warn.is_clean(), "warnings fail by default");
    assert!(
        warn.is_clean_at(Severity::Critical),
        "--fail-on critical must tolerate a warning"
    );

    let clean = snap("x", "aa", &[], vec![]);
    assert!(clean.is_clean() && clean.is_clean_at(Severity::Info));
}

#[test]
fn snapshots_round_trip_through_json() {
    let a = snap("eu", "aa", &[("/a.js", "11")], vec![finding("k", "/s")]);
    let text = serde_json::to_string(&a).unwrap();
    let back: Snapshot = serde_json::from_str(&text).unwrap();
    assert_eq!(back.spec, SNAPSHOT_SPEC);
    assert_eq!(back.observed["/a.js"].sha256.as_deref(), Some("11"));
    assert_eq!(back.findings[0].kind, "k");
    assert!(diff(&a, &back).is_empty());
}
