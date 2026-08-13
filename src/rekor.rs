//! Sigstore / Rekor Transparency Log integration.
//!
//! Enabled under the `rekor` feature flag.

#![cfg(feature = "rekor")]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorEntry {
    pub log_index: u64,
    pub integrated_time: u64,
    pub log_id: String,
    pub entry_id: String,
}

/// Convert a 32-byte Ed25519 public key (raw bytes) into PEM format for Rekor `hashedrekord`.
pub fn ed25519_pubkey_to_pem(pubkey_bytes: &[u8; 32]) -> String {
    // SubjectPublicKeyInfo header for Ed25519 (RFC 8410):
    // 30 2a 30 05 06 03 2b 65 70 03 21 00 || 32_bytes_pubkey
    let mut spki = Vec::with_capacity(44);
    spki.extend_from_slice(&[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ]);
    spki.extend_from_slice(pubkey_bytes);

    let b64 = BASE64.encode(&spki);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

/// Submit manifest hash and signature bundle to Rekor log as a `hashedrekord` entry.
pub fn upload_manifest(
    manifest_bytes: &[u8],
    sig_bytes: &[u8],
    public_key_pem: &str,
    rekor_url: &str,
) -> Result<RekorEntry, Box<dyn Error>> {
    let manifest_sha256 = hex::encode(Sha256::digest(manifest_bytes));
    let sig_b64 = BASE64.encode(sig_bytes);
    let pub_b64 = BASE64.encode(public_key_pem.as_bytes());

    let payload = serde_json::json!({
        "kind": "hashedrekord",
        "apiVersion": "0.0.1",
        "spec": {
            "data": {
                "hash": {
                    "algorithm": "sha256",
                    "value": manifest_sha256
                }
            },
            "signature": {
                "content": sig_b64,
                "publicKey": {
                    "content": pub_b64
                }
            }
        }
    });

    let payload_bytes = serde_json::to_vec(&payload)?;

    let url = format!("{}/api/v1/log/entries", rekor_url.trim_end_matches('/'));

    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(15)))
        .user_agent("veil-guard (rekor-client)")
        .build();
    let agent: ureq::Agent = config.into();

    let mut resp = agent
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .send(&payload_bytes)
        .map_err(|e| format!("Rekor upload request to {url} failed: {e}"))?;

    let resp_str = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("Failed to read Rekor response body: {e}"))?;

    let json: serde_json::Value = serde_json::from_str(&resp_str)
        .map_err(|e| format!("Failed to parse Rekor response JSON: {e}"))?;

    // Rekor returns a map keyed by entry_id: `{"<entry_id>": { "logIndex": ..., "integratedTime": ..., "logID": ... }}`
    let obj = json
        .as_object()
        .ok_or("Rekor response is not a JSON object")?;
    let (entry_id, entry_val) = obj.iter().next().ok_or("Rekor response object is empty")?;

    let log_index = entry_val["logIndex"]
        .as_u64()
        .ok_or("Rekor response missing logIndex")?;
    let integrated_time = entry_val["integratedTime"]
        .as_u64()
        .ok_or("Rekor response missing integratedTime")?;
    let log_id = entry_val["logID"].as_str().unwrap_or_default().to_string();

    Ok(RekorEntry {
        log_index,
        integrated_time,
        log_id,
        entry_id: entry_id.clone(),
    })
}

/// Verify a Rekor entry by log_index or entry_id.
pub fn lookup_rekor_entry(
    manifest_bytes: &[u8],
    rekor_entry: &RekorEntry,
    rekor_url: &str,
) -> Result<bool, Box<dyn Error>> {
    let payload_bytes = if let Ok(mut manifest) =
        serde_json::from_slice::<crate::manifest::Manifest>(manifest_bytes)
    {
        if let Some(source) = manifest.source.as_object_mut() {
            if source.remove("rekor").is_some() {
                (serde_json::to_string_pretty(&manifest).unwrap_or_default() + "\n").into_bytes()
            } else {
                manifest_bytes.to_vec()
            }
        } else {
            manifest_bytes.to_vec()
        }
    } else if let Ok(mut val) = serde_json::from_slice::<serde_json::Value>(manifest_bytes) {
        if let Some(source) = val.get_mut("source").and_then(|s| s.as_object_mut()) {
            if source.remove("rekor").is_some() {
                if source.is_empty() {
                    val.as_object_mut().unwrap().remove("source");
                }
                (serde_json::to_string_pretty(&val).unwrap_or_default() + "\n").into_bytes()
            } else {
                manifest_bytes.to_vec()
            }
        } else {
            manifest_bytes.to_vec()
        }
    } else {
        manifest_bytes.to_vec()
    };

    let manifest_sha256 = hex::encode(Sha256::digest(&payload_bytes));

    let url = format!(
        "{}/api/v1/log/entries?logIndex={}",
        rekor_url.trim_end_matches('/'),
        rekor_entry.log_index
    );

    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(15)))
        .user_agent("veil-guard (rekor-lookup)")
        .build();
    let agent: ureq::Agent = config.into();

    let mut resp = agent
        .get(&url)
        .header("Accept", "application/json")
        .call()
        .map_err(|e| format!("Rekor query request to {url} failed: {e}"))?;

    let resp_str = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("Failed to read Rekor response body: {e}"))?;

    let json: serde_json::Value = serde_json::from_str(&resp_str)
        .map_err(|e| format!("Failed to parse Rekor response JSON: {e}"))?;

    let obj = json
        .as_object()
        .ok_or("Rekor response is not a JSON object")?;
    let (_, entry_val) = obj.iter().next().ok_or("Rekor response object is empty")?;

    // Check payload hash inside `body` field (which is base64 encoded JSON)
    let body_b64 = entry_val["body"]
        .as_str()
        .ok_or("Rekor entry missing body")?;
    let body_bytes = BASE64
        .decode(body_b64)
        .map_err(|e| format!("Failed to decode Rekor body base64: {e}"))?;

    let body_json: serde_json::Value = serde_json::from_slice(&body_bytes)
        .map_err(|e| format!("Failed to parse Rekor body JSON: {e}"))?;

    let logged_hash = body_json["spec"]["data"]["hash"]["value"]
        .as_str()
        .unwrap_or_default();

    Ok(logged_hash.eq_ignore_ascii_case(&manifest_sha256))
}
