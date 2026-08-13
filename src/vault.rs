//! Remote Ed25519 signing integration via HashiCorp Vault Transit Engine.
//!
//! Enabled under the `vault` feature flag.

#![cfg(feature = "vault")]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use std::error::Error;
use std::time::Duration;

/// Sign a domain-separated message under Ed25519 using HashiCorp Vault's transit engine.
///
/// The Vault key must be of type `ed25519`. Token is taken from `token_override`
/// or the `VAULT_TOKEN` environment variable.
pub fn sign_vault_transit(
    msg: &[u8],
    vault_addr: &str,
    vault_key_name: &str,
    token_override: Option<&str>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let token = match token_override {
        Some(t) if !t.is_empty() => t.to_string(),
        _ => std::env::var("VAULT_TOKEN").map_err(|_| {
            "Vault token not provided and VAULT_TOKEN environment variable is not set"
        })?,
    };

    let url = format!(
        "{}/v1/transit/sign/{}",
        vault_addr.trim_end_matches('/'),
        vault_key_name
    );

    let input_b64 = BASE64.encode(msg);

    let body = serde_json::json!({
        "input": input_b64,
    });

    let body_bytes = serde_json::to_vec(&body)?;

    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .user_agent("veil-guard (vault-transit)")
        .build();
    let agent: ureq::Agent = config.into();

    let mut resp = agent
        .post(&url)
        .header("X-Vault-Token", &token)
        .header("Content-Type", "application/json")
        .send(&body_bytes)
        .map_err(|e| format!("Vault HTTP request to {url} failed: {e}"))?;

    let resp_str = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("Failed to read Vault response body: {e}"))?;

    let json: serde_json::Value = serde_json::from_str(&resp_str)
        .map_err(|e| format!("Failed to parse Vault response JSON: {e}"))?;

    let sig_str = json["data"]["signature"]
        .as_str()
        .ok_or("Vault response missing data.signature field")?;

    // Vault transit returns "vault:v<N>:<base64>". Require that shape rather than
    // taking whatever follows the last colon: `rsplit(':').next()` yields the whole
    // string when there is no colon at all, so the guard below used to be
    // unreachable and any 64 base64 bytes from any endpoint would have been accepted
    // as a signature. Being strict here is how a misconfigured URL fails loudly.
    let raw_b64 = sig_str
        .strip_prefix("vault:")
        .and_then(|rest| rest.split_once(':'))
        .map(|(_version, b64)| b64)
        .ok_or_else(|| {
            format!("Invalid Vault signature format, expected `vault:v<N>:<base64>`: {sig_str}")
        })?;

    let sig_bytes = BASE64
        .decode(raw_b64)
        .map_err(|e| format!("Failed to decode Vault base64 signature: {e}"))?;

    if sig_bytes.len() != 64 {
        return Err(format!(
            "Vault returned Ed25519 signature of length {}, expected 64",
            sig_bytes.len()
        )
        .into());
    }

    Ok(sig_bytes)
}
