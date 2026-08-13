//! Relay client operations: push, pull, and diff snapshots from audit relay endpoints.

#![cfg(feature = "relay-client")]

use std::error::Error;
use std::fs;
use std::path::Path;
use std::time::Duration;
use ureq::Agent;

pub fn push_snapshot(
    relay_url: &str,
    snapshot_json: &serde_json::Value,
    token: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let url = format!("{}/snapshots", relay_url.trim_end_matches('/'));
    let payload = serde_json::to_vec(snapshot_json)?;

    let config = Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .user_agent("veil-guard (relay-push)")
        .build();
    let agent: Agent = config.into();

    let mut req = agent.post(&url).header("Content-Type", "application/json");
    if let Some(t) = token {
        req = req.header("Authorization", &format!("Bearer {t}"));
    }

    let resp = req
        .send(&payload)
        .map_err(|e| format!("Relay push to {url} failed: {e}"))?;

    let status = resp.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(format!("Relay push failed with HTTP status {status}").into());
    }
    Ok(())
}

pub fn pull_snapshots(
    relay_url: &str,
    domain: &str,
    since: Option<u64>,
    out_dir: &Path,
    token: Option<&str>,
) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
    let mut url = format!(
        "{}/snapshots?domain={}",
        relay_url.trim_end_matches('/'),
        domain
    );
    if let Some(ts) = since {
        url.push_str(&format!("&since={ts}"));
    }

    let config = Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .user_agent("veil-guard (relay-pull)")
        .build();
    let agent: Agent = config.into();

    let mut req = agent.get(&url).header("Accept", "application/json");
    if let Some(t) = token {
        req = req.header("Authorization", &format!("Bearer {t}"));
    }

    let mut resp = req
        .call()
        .map_err(|e| format!("Relay pull from {url} failed: {e}"))?;

    let status = resp.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(format!("Relay pull failed with HTTP status {status}").into());
    }

    let resp_str = resp.body_mut().read_to_string()?;
    let json_array: Vec<serde_json::Value> = serde_json::from_str(&resp_str)?;

    fs::create_dir_all(out_dir)?;
    for (idx, snap) in json_array.iter().enumerate() {
        let label = snap["label"].as_str().unwrap_or("unknown");
        let fname = format!("{label}_{idx}.json");
        let file_path = out_dir.join(fname);
        fs::write(file_path, serde_json::to_string_pretty(snap)? + "\n")?;
    }

    Ok(json_array)
}
