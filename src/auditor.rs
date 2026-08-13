//! Out-of-band auditor — SPEC.md §1 (Tier 0) and §7.2.
//!
//! This is the part of veil-guard that is not circular. Everything the Service
//! Worker does is delivered by the origin it is checking; this is not. It runs on
//! a machine the origin does not control, it takes its trust root from a local
//! file, and it compares what a real HTTP client is actually served against what
//! was signed.
//!
//! # The one rule this module exists to enforce
//!
//! The trust root is a [`TrustRoot`] value passed in by the caller, loaded from a
//! local path. There is deliberately no code path here that fetches a key, a trust
//! root, or a pin from the audited site — a convenient default of that shape would
//! quietly turn an out-of-band audit back into an in-band one.

use crate::crypto::{sha256, SUPPORTED_ALGS};
use crate::generators::sri_value;
use crate::html::scan;
use crate::manifest::{
    verify_manifest_with_revocation, verify_revocation, Manifest, ManifestState,
    RevocationStatement, RevocationVerdict,
};

use crate::paths::{content_type_matches, request_key};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

pub const SNAPSHOT_SPEC: &str = "veil-guard/audit/1";

// ---------------------------------------------------------------- findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// The deployment does not match what was signed.
    Critical,
    /// Suspicious, or a policy gap that weakens the guarantee.
    Warning,
    /// Worth recording, not worth alarm.
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub kind: String,
    pub subject: String,
    pub detail: String,
}

impl Finding {
    fn new(
        severity: Severity,
        kind: &str,
        subject: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Finding {
            severity,
            kind: kind.to_string(),
            subject: subject.into(),
            detail: detail.into(),
        }
    }
}

// ---------------------------------------------------------------- snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedAsset {
    pub http_status: u16,
    pub sha256: Option<String>,
    pub size: Option<u64>,
    pub content_type: Option<String>,
    pub matched: bool,
}

/// One observation of one deployment, from one vantage point, at one time.
///
/// A single snapshot proves very little on its own. Its value is comparative: two
/// snapshots taken from different regions, or from the same region at different
/// times, are what make selective delivery visible. See [`diff`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub spec: String,
    pub url: String,
    pub observed_at: u64,
    /// Free-form vantage-point label, e.g. `eu-west`, `residential-de`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub manifest_state: String,
    pub manifest_sha256: Option<String>,
    pub manifest_version: Option<u64>,
    pub trust_root_id: String,
    pub assets_in_manifest: usize,
    pub assets_probed: usize,
    pub observed: BTreeMap<String, ObservedAsset>,
    pub findings: Vec<Finding>,
}

impl Snapshot {
    pub fn worst(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).min()
    }

    /// Whether the snapshot is free of findings at or above `threshold`.
    pub fn is_clean_at(&self, threshold: Severity) -> bool {
        // Severity orders Critical < Warning < Info, so "at or above" is `<=`.
        !self.findings.iter().any(|f| f.severity <= threshold)
    }

    pub fn is_clean(&self) -> bool {
        self.is_clean_at(Severity::Warning)
    }
}

// ---------------------------------------------------------------- http
#[derive(Debug)]
pub enum AuditError {
    Http(String),
    Io(std::io::Error),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditError::Http(e) => write!(f, "{e}"),
            AuditError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AuditError {}

struct Fetched {
    status: u16,
    body: Vec<u8>,
    content_type: Option<String>,
    location: Option<String>,
}

struct Client {
    agent: ureq::Agent,
    max_body: u64,
}

impl Client {
    fn new(timeout: Duration, max_body: u64) -> Self {
        // SPEC §7.2: redirects are never followed. A server that answers a request
        // for one manifested path with a redirect to another would otherwise let one
        // entry's bytes be validated against another entry's hash.
        let config = ureq::Agent::config_builder()
            .max_redirects(0)
            .timeout_global(Some(timeout))
            .user_agent(concat!(
                "veil-guard/",
                env!("CARGO_PKG_VERSION"),
                " (auditor)"
            ))
            .build();
        Client {
            agent: config.into(),
            max_body,
        }
    }

    fn get(&self, url: &str) -> Result<Fetched, AuditError> {
        // Cache-busting is deliberate: an audit must see what the origin serves now,
        // not what an intermediary cached earlier.
        let call = self
            .agent
            .get(url)
            .header("Cache-Control", "no-cache")
            .header("Pragma", "no-cache")
            .call();

        let mut response = match call {
            Ok(r) => r,
            // A non-2xx is data, not a transport failure: record and carry on.
            Err(ureq::Error::StatusCode(code)) => {
                return Ok(Fetched {
                    status: code,
                    body: Vec::new(),
                    content_type: None,
                    location: None,
                })
            }
            Err(e) => return Err(AuditError::Http(format!("{url}: {e}"))),
        };

        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        let body = response
            .body_mut()
            .with_config()
            .limit(self.max_body)
            .read_to_vec()
            .map_err(|e| AuditError::Http(format!("{url}: {e}")))?;

        Ok(Fetched {
            status,
            body,
            content_type,
            location,
        })
    }
}

// ---------------------------------------------------------------- audit
pub struct AuditOptions {
    pub label: Option<String>,
    pub pinned_version: u64,
    /// Skip byte-for-byte probing of every manifested asset; only walk the HTML graph.
    pub graph_only: bool,
    pub timeout: Duration,
    pub max_body: u64,
    pub rekor_verify: bool,
    pub rekor_url: String,
}

impl Default for AuditOptions {
    fn default() -> Self {
        AuditOptions {
            label: None,
            pinned_version: 0,
            graph_only: false,
            timeout: Duration::from_secs(30),
            max_body: 64 * 1024 * 1024,
            rekor_verify: false,
            rekor_url: "https://rekor.sigstore.dev".to_string(),
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Audit a live deployment against a trust root the caller supplies.
///
/// `trust_root` must have been loaded from local storage. Nothing in this function
/// reads key material from `base_url`.
pub fn audit(
    base_url: &str,
    trust_root: &crate::crypto::TrustRoot,
    opts: &AuditOptions,
) -> Result<Snapshot, AuditError> {
    let base = base_url.trim_end_matches('/').to_string();
    let client = Client::new(opts.timeout, opts.max_body);
    let mut findings = Vec::new();
    let mut observed = BTreeMap::new();

    let manifest_res = client.get(&format!("{base}/veil-guard-manifest.json"))?;
    let sig_res = client.get(&format!("{base}/veil-guard-manifest.sig"))?;

    let mut snapshot = Snapshot {
        spec: SNAPSHOT_SPEC.to_string(),
        url: base.clone(),
        observed_at: now_unix(),
        label: opts.label.clone(),
        manifest_state: "UNAVAILABLE".to_string(),
        manifest_sha256: None,
        manifest_version: None,
        trust_root_id: trust_root.id_hex().unwrap_or_default(),
        assets_in_manifest: 0,
        assets_probed: 0,
        observed: BTreeMap::new(),
        findings: Vec::new(),
    };

    if manifest_res.status != 200 || sig_res.status != 200 {
        findings.push(Finding::new(
            Severity::Critical,
            "manifest-unavailable",
            format!("{base}/veil-guard-manifest.json"),
            format!(
                "manifest HTTP {}, signature HTTP {}",
                manifest_res.status, sig_res.status
            ),
        ));
        snapshot.findings = findings;
        return Ok(snapshot);
    }

    snapshot.manifest_sha256 = Some(hex::encode(sha256(&manifest_res.body)));

    // Fetch and verify out-of-band revocation statement if present (SPEC §9.2)
    let mut revoked_keys = Vec::new();
    if let (Ok(rev_res), Ok(rev_sig_res)) = (
        client.get(&format!("{base}/veil-guard-revocation.json")),
        client.get(&format!("{base}/veil-guard-revocation.sig")),
    ) {
        if rev_res.status == 200 && rev_sig_res.status == 200 {
            let now = now_unix();
            if verify_revocation(
                &rev_res.body,
                &rev_sig_res.body,
                trust_root,
                0,
                now,
                SUPPORTED_ALGS,
            ) == RevocationVerdict::Accept
            {
                if let Ok(rev_stmt) = serde_json::from_slice::<RevocationStatement>(&rev_res.body) {
                    revoked_keys = rev_stmt.revoked_keys;
                    findings.push(Finding::new(
                        Severity::Info,
                        "revocation-active",
                        base.clone(),
                        format!(
                            "Out-of-band revocation statement active: {} key(s) revoked ({:?})",
                            revoked_keys.len(),
                            revoked_keys
                        ),
                    ));
                }
            }
        }
    }

    let state = verify_manifest_with_revocation(
        &manifest_res.body,
        &sig_res.body,
        trust_root,
        opts.pinned_version,
        now_unix(),
        SUPPORTED_ALGS,
        &revoked_keys,
    );
    snapshot.manifest_state = state.as_str().to_string();

    if state.is_hard_failure() {
        findings.push(Finding::new(
            Severity::Critical,
            "manifest-verification-failed",
            base.clone(),
            format!(
                "manifest verifies as {} against the supplied trust root",
                state.as_str()
            ),
        ));
        snapshot.findings = findings;
        return Ok(snapshot);
    }
    if state == ManifestState::Expired {
        findings.push(Finding::new(
            Severity::Warning,
            "manifest-expired",
            base.clone(),
            "signature is valid but past not_after; the deployment needs re-signing",
        ));
    }

    let Ok(manifest) = serde_json::from_slice::<Manifest>(&manifest_res.body) else {
        findings.push(Finding::new(
            Severity::Critical,
            "manifest-unparseable",
            base.clone(),
            "signature verified but the payload did not parse",
        ));
        snapshot.findings = findings;
        return Ok(snapshot);
    };
    snapshot.manifest_version = Some(manifest.version);
    snapshot.assets_in_manifest = manifest.assets.len();

    if opts.rekor_verify || manifest.source.get("rekor").is_some() {
        #[cfg(feature = "rekor")]
        {
            if let Some(rekor_val) = manifest.source.get("rekor") {
                if let (Some(log_idx), Some(int_time)) = (
                    rekor_val["log_index"].as_u64(),
                    rekor_val["integrated_time"].as_u64(),
                ) {
                    let entry = crate::rekor::RekorEntry {
                        log_index: log_idx,
                        integrated_time: int_time,
                        log_id: rekor_val["log_id"].as_str().unwrap_or_default().to_string(),
                        entry_id: rekor_val["entry_id"]
                            .as_str()
                            .unwrap_or_default()
                            .to_string(),
                    };
                    match crate::rekor::verify_rekor_entry(
                        &manifest_res.body,
                        &entry,
                        &opts.rekor_url,
                    ) {
                        Ok(true) => {
                            findings.push(Finding::new(
                                Severity::Info,
                                "rekor-verified",
                                base.clone(),
                                format!("manifest hash verified in Rekor log_index={log_idx}"),
                            ));
                        }
                        Ok(false) => {
                            findings.push(Finding::new(
                                Severity::Critical,
                                "rekor-hash-mismatch",
                                base.clone(),
                                format!("manifest hash does not match Rekor record at log_index={log_idx}"),
                            ));
                        }
                        Err(e) => {
                            findings.push(Finding::new(
                                Severity::Warning,
                                "rekor-verification-failed",
                                base.clone(),
                                format!("failed to query Rekor log_index={log_idx}: {e}"),
                            ));
                        }
                    }
                }
            } else if opts.rekor_verify {
                findings.push(Finding::new(
                    Severity::Warning,
                    "rekor-not-found",
                    base.clone(),
                    "--rekor-verify requested but manifest source contains no Rekor entry",
                ));
            }
        }
        #[cfg(not(feature = "rekor"))]
        {
            if opts.rekor_verify {
                findings.push(Finding::new(
                    Severity::Warning,
                    "rekor-disabled",
                    base.clone(),
                    "Rekor verification requested but veil-guard was built without feature `rekor`",
                ));
            }
        }
    }

    // ---- walk the served HTML graph -------------------------------------------
    // Limited by construction: this sees the static graph only. Route chunks that a
    // router loads at runtime never appear in served markup, so their absence from
    // this list is not evidence of anything.
    for entry in manifest
        .assets
        .iter()
        .filter(|a| a.content_type == "text/html")
    {
        let url = format!("{base}{}", entry.path);
        let page = client.get(&url)?;
        if page.status != 200 {
            continue;
        }
        let Ok(tags) = scan(&page.body) else {
            findings.push(Finding::new(
                Severity::Warning,
                "html-unparseable",
                entry.path.clone(),
                "served markup could not be scanned for subresources",
            ));
            continue;
        };

        for tag in tags {
            let url_attr = match tag.name.as_str() {
                "script" => tag.attr("src"),
                "link" => tag.attr("href"),
                _ => None,
            };
            let Some(reference) = url_attr else { continue };
            let Some(key) = resolve_same_origin(reference, &entry.path) else {
                continue; // cross-origin: CSP's problem, not the manifest's
            };

            match manifest.lookup(&key) {
                None => {
                    // The signal worth having. Something is being loaded that nobody
                    // signed — SRI would not catch it, because SRI only constrains
                    // tags that carry an integrity attribute.
                    let severity = if tag.name == "script" {
                        Severity::Critical
                    } else {
                        Severity::Warning
                    };
                    findings.push(Finding::new(
                        severity,
                        "unmanifested-subresource",
                        key.clone(),
                        format!(
                            "<{}> on {} references an asset absent from the manifest",
                            tag.name, entry.path
                        ),
                    ));
                }
                Some(asset) => {
                    if let Some(attr) = tag.attr("integrity") {
                        let expected = sri_value(&asset.sha384).unwrap_or_default();
                        if !attr.split_ascii_whitespace().any(|v| v == expected) {
                            findings.push(Finding::new(
                                Severity::Critical,
                                "sri-mismatch",
                                key.clone(),
                                format!(
                                    "integrity attribute on {} does not match the signed digest",
                                    entry.path
                                ),
                            ));
                        }
                    } else if tag.name == "script"
                        || tag.attr("rel").is_some_and(|r| r.contains("stylesheet"))
                    {
                        findings.push(Finding::new(
                            Severity::Warning,
                            "missing-integrity",
                            key.clone(),
                            format!("{} loads this without an integrity attribute", entry.path),
                        ));
                    }
                }
            }
        }
    }

    // ---- probe every manifested asset -----------------------------------------
    if !opts.graph_only {
        for entry in &manifest.assets {
            let url = format!("{base}{}", entry.path);
            let res = client.get(&url)?;
            let mut record = ObservedAsset {
                http_status: res.status,
                sha256: None,
                size: None,
                content_type: res.content_type.clone(),
                matched: false,
            };

            if (300..400).contains(&res.status) {
                findings.push(Finding::new(
                    Severity::Critical,
                    "redirected-asset",
                    entry.path.clone(),
                    format!(
                        "answered with HTTP {} to {}; a redirect would let one entry's bytes \
                         be checked against another's hash",
                        res.status,
                        res.location.unwrap_or_else(|| "?".into())
                    ),
                ));
            } else if res.status != 200 {
                findings.push(Finding::new(
                    Severity::Critical,
                    "asset-unavailable",
                    entry.path.clone(),
                    format!("HTTP {}", res.status),
                ));
            } else {
                let digest = hex::encode(sha256(&res.body));
                record.sha256 = Some(digest.clone());
                record.size = Some(res.body.len() as u64);
                record.matched = digest == entry.sha256;

                if !record.matched {
                    findings.push(Finding::new(
                        Severity::Critical,
                        "content-mismatch",
                        entry.path.clone(),
                        format!(
                            "served bytes hash to {digest}, manifest says {}",
                            entry.sha256
                        ),
                    ));
                } else if let Some(ct) = &res.content_type {
                    if !content_type_matches(&entry.content_type, ct) {
                        findings.push(Finding::new(
                            Severity::Warning,
                            "content-type-mismatch",
                            entry.path.clone(),
                            format!("served as `{ct}`, manifest says `{}`", entry.content_type),
                        ));
                    }
                }
            }

            observed.insert(entry.path.clone(), record);
        }
        snapshot.assets_probed = observed.len();
    }

    findings.sort_by(|a, b| a.severity.cmp(&b.severity).then(a.subject.cmp(&b.subject)));
    snapshot.observed = observed;
    snapshot.findings = findings;
    Ok(snapshot)
}

/// Same as the generator's resolution, but for references seen in served markup.
fn resolve_same_origin(reference: &str, page_key: &str) -> Option<String> {
    let trimmed = reference.trim();
    if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with('#') {
        return None;
    }
    if let Some(colon) = trimmed.find(':') {
        let before = &trimmed[..colon];
        if !before.contains('/') && !before.contains('?') && !before.is_empty() {
            return None;
        }
    }
    let without_query = trimmed.split(['?', '#']).next().unwrap_or("");
    let absolute = if without_query.starts_with('/') {
        without_query.to_string()
    } else {
        let dir = page_key.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
        let mut parts: Vec<&str> = dir.split('/').filter(|s| !s.is_empty()).collect();
        for component in without_query.split('/') {
            match component {
                "" | "." => {}
                ".." => {
                    parts.pop()?;
                }
                other => parts.push(other),
            }
        }
        format!("/{}", parts.join("/"))
    };
    request_key(&absolute)
}

// ---------------------------------------------------------------- diff
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Divergence {
    pub kind: String,
    pub subject: String,
    pub left: String,
    pub right: String,
}

/// Compare two snapshots of the same deployment.
///
/// This is the only mechanism in veil-guard that can surface selective delivery: a
/// signature stays valid when an attacker with the signing key serves a different
/// bundle to one visitor, and only comparing what different vantage points were
/// actually served makes that visible. Two snapshots that disagree on the manifest
/// hash, or on any asset's bytes, are the finding.
pub fn diff(left: &Snapshot, right: &Snapshot) -> Vec<Divergence> {
    let mut out = Vec::new();

    if left.manifest_sha256 != right.manifest_sha256 {
        out.push(Divergence {
            kind: "manifest-differs".into(),
            subject: "veil-guard-manifest.json".into(),
            left: left
                .manifest_sha256
                .clone()
                .unwrap_or_else(|| "absent".into()),
            right: right
                .manifest_sha256
                .clone()
                .unwrap_or_else(|| "absent".into()),
        });
    }
    if left.manifest_state != right.manifest_state {
        out.push(Divergence {
            kind: "state-differs".into(),
            subject: "manifest".into(),
            left: left.manifest_state.clone(),
            right: right.manifest_state.clone(),
        });
    }

    // Findings are compared as well as bytes. An asset that is not in the manifest
    // is never probed, so a script injected for one visitor only would be invisible
    // in `observed` — it shows up here, as a finding one side has and the other
    // does not.
    let key_of = |f: &Finding| format!("{}\u{0}{}", f.kind, f.subject);
    let left_findings: BTreeMap<String, &Finding> =
        left.findings.iter().map(|f| (key_of(f), f)).collect();
    let right_findings: BTreeMap<String, &Finding> =
        right.findings.iter().map(|f| (key_of(f), f)).collect();

    for (k, f) in &left_findings {
        if !right_findings.contains_key(k) {
            out.push(Divergence {
                kind: format!("finding-only-in-left:{}", f.kind),
                subject: f.subject.clone(),
                left: f.detail.clone(),
                right: "not observed".into(),
            });
        }
    }
    for (k, f) in &right_findings {
        if !left_findings.contains_key(k) {
            out.push(Divergence {
                kind: format!("finding-only-in-right:{}", f.kind),
                subject: f.subject.clone(),
                left: "not observed".into(),
                right: f.detail.clone(),
            });
        }
    }

    let mut keys: Vec<&String> = left.observed.keys().chain(right.observed.keys()).collect();
    keys.sort();
    keys.dedup();

    for key in keys {
        match (left.observed.get(key), right.observed.get(key)) {
            (Some(a), Some(b)) if a.sha256 != b.sha256 => out.push(Divergence {
                kind: "content-differs".into(),
                subject: key.clone(),
                left: a
                    .sha256
                    .clone()
                    .unwrap_or_else(|| format!("HTTP {}", a.http_status)),
                right: b
                    .sha256
                    .clone()
                    .unwrap_or_else(|| format!("HTTP {}", b.http_status)),
            }),
            (Some(a), None) => out.push(Divergence {
                kind: "only-in-left".into(),
                subject: key.clone(),
                left: a
                    .sha256
                    .clone()
                    .unwrap_or_else(|| format!("HTTP {}", a.http_status)),
                right: "not observed".into(),
            }),
            (None, Some(b)) => out.push(Divergence {
                kind: "only-in-right".into(),
                subject: key.clone(),
                left: "not observed".into(),
                right: b
                    .sha256
                    .clone()
                    .unwrap_or_else(|| format!("HTTP {}", b.http_status)),
            }),
            _ => {}
        }
    }
    out
}

// ---------------------------------------------------------------- daemon & state machine
#[derive(Debug, Clone)]
pub struct TargetStatus {
    pub is_failing: bool,
    pub since: u64,
    pub last_alert: u64,
}

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub urls: Vec<String>,
    pub trust_root: crate::crypto::TrustRoot,
    pub interval_secs: u64,
    pub fail_on_severity: Severity,
    pub label: Option<String>,
    pub pinned_version: u64,
    pub graph_only: bool,
    pub rekor_verify: bool,
    pub rekor_url: String,
    pub relay_push: Option<String>,
    pub relay_token: Option<String>,
    pub webhook_url: Option<String>,
    pub webhook_format: crate::alerting::AlertFormat,
    pub heartbeat_interval_secs: u64,
}

pub async fn run_daemon(config: DaemonConfig) -> Result<(), Box<dyn std::error::Error>> {
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .user_agent("veil-guard (audit-daemon)")
        .build()?;

    let mut state: BTreeMap<String, TargetStatus> = BTreeMap::new();
    let mut interval = tokio::time::interval(Duration::from_secs(config.interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    println!(
        "veil-guard audit daemon started monitoring {} target(s) every {}s",
        config.urls.len(),
        config.interval_secs
    );

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                for url in &config.urls {
                    let opts = AuditOptions {
                        label: config.label.clone(),
                        pinned_version: config.pinned_version,
                        graph_only: config.graph_only,
                        rekor_verify: config.rekor_verify,
                        rekor_url: config.rekor_url.clone(),
                        ..Default::default()
                    };

                    let snapshot_res = std::panic::catch_unwind(|| {
                        audit(
                            url,
                            &config.trust_root,
                            &opts,
                        )
                    });


                    let snapshot = match snapshot_res {
                        Ok(Ok(snap)) => snap,
                        Ok(Err(e)) => {
                            println!("daemon probe error for {url}: {e}");
                            continue;
                        }
                        Err(_) => {
                            println!("daemon probe panicked for {url}");
                            continue;
                        }
                    };

                    let has_failures = snapshot.findings.iter().any(|f| f.severity <= config.fail_on_severity);

                    if let Some(relay_url) = &config.relay_push {
                        let snap_val = serde_json::to_value(&snapshot).unwrap_or_default();
                        let _ = crate::relay::push_snapshot(relay_url, &snap_val, config.relay_token.as_deref());
                    }

                    let status = state.entry(url.clone()).or_insert(TargetStatus {
                        is_failing: false,
                        since: 0,
                        last_alert: 0,
                    });

                    if has_failures {
                        if !status.is_failing {
                            status.is_failing = true;
                            status.since = now;
                            status.last_alert = now;

                            if let Some(wh) = &config.webhook_url {
                                let alert = crate::alerting::AlertPayload {
                                    event_type: "TRIGGER".into(),
                                    target_url: url.clone(),
                                    label: config.label.clone(),
                                    timestamp: now,
                                    severity: format!("{:?}", config.fail_on_severity),
                                    summary: format!("Audit findings exceeded severity threshold for {url}"),
                                    findings_count: snapshot.findings.len(),
                                    details: serde_json::to_value(&snapshot).unwrap_or_default(),
                                };
                                let _ = crate::alerting::send_alert(&http_client, wh, config.webhook_format, &alert, config.relay_token.as_deref()).await;
                            }
                        } else if config.heartbeat_interval_secs > 0 && now.saturating_sub(status.last_alert) >= config.heartbeat_interval_secs {
                            status.last_alert = now;
                            if let Some(wh) = &config.webhook_url {
                                let alert = crate::alerting::AlertPayload {
                                    event_type: "TRIGGER".into(),
                                    target_url: url.clone(),
                                    label: config.label.clone(),
                                    timestamp: now,
                                    severity: format!("{:?}", config.fail_on_severity),
                                    summary: format!("Sustained audit failure heartbeat for {url}"),
                                    findings_count: snapshot.findings.len(),
                                    details: serde_json::to_value(&snapshot).unwrap_or_default(),
                                };
                                let _ = crate::alerting::send_alert(&http_client, wh, config.webhook_format, &alert, config.relay_token.as_deref()).await;
                            }
                        }
                    } else if status.is_failing {
                        status.is_failing = false;
                        status.last_alert = now;

                        if let Some(wh) = &config.webhook_url {
                            let alert = crate::alerting::AlertPayload {
                                event_type: "RESOLVE".into(),
                                target_url: url.clone(),
                                label: config.label.clone(),
                                timestamp: now,
                                severity: "info".into(),
                                summary: format!("Audit status recovered for {url}"),
                                findings_count: 0,
                                details: serde_json::json!({ "status": "resolved" }),
                            };
                            let _ = crate::alerting::send_alert(&http_client, wh, config.webhook_format, &alert, config.relay_token.as_deref()).await;
                        }
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                println!("Shutting down veil-guard audit daemon gracefully...");
                break;
            }
        }
    }

    Ok(())
}
