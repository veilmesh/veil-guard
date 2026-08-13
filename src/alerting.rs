//! Async Alert Notification Engine for veil-guard.
//!
//! Dispatches structured security alerts to Generic Webhooks, Slack, PagerDuty,
//! or Datadog using a shared non-blocking `reqwest::Client`.

#![cfg(feature = "audit")]

use serde::{Deserialize, Serialize};
use std::error::Error;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertFormat {
    Generic,
    Slack,
    PagerDuty,
    Datadog,
}

impl std::str::FromStr for AlertFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "generic" | "json" => Ok(AlertFormat::Generic),
            "slack" => Ok(AlertFormat::Slack),
            "pagerduty" | "pd" => Ok(AlertFormat::PagerDuty),
            "datadog" | "dd" => Ok(AlertFormat::Datadog),
            _ => Err(format!(
                "Unknown alert format: {s}. Supported: generic, slack, pagerduty, datadog"
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertPayload {
    pub event_type: String, // "TRIGGER" or "RESOLVE"
    pub target_url: String,
    pub label: Option<String>,
    pub timestamp: u64,
    pub severity: String,
    pub summary: String,
    pub findings_count: usize,
    pub details: serde_json::Value,
}

pub async fn send_alert(
    client: &reqwest::Client,
    webhook_url: &str,
    format: AlertFormat,
    payload: &AlertPayload,
    token: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let body = format_payload(format, payload);
    let mut req = client
        .post(webhook_url)
        .header("Content-Type", "application/json");

    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {t}"));
    }

    let body_bytes = serde_json::to_vec(&body)?;

    let mut attempts = 0;
    let mut backoff_ms = 500;

    loop {
        attempts += 1;
        match req
            .try_clone()
            .unwrap()
            .body(body_bytes.clone())
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            Ok(resp) => {
                let status = resp.status();
                if attempts >= 3 || (400..500).contains(&status.as_u16()) {
                    return Err(format!("Alert webhook returned HTTP status {status}").into());
                }
            }
            Err(e) => {
                if attempts >= 3 {
                    return Err(
                        format!("Alert webhook failed after {attempts} attempts: {e}").into(),
                    );
                }
            }
        }
        #[cfg(feature = "audit")]
        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        backoff_ms *= 2;
    }
}

fn format_payload(format: AlertFormat, payload: &AlertPayload) -> serde_json::Value {
    let is_trigger = payload.event_type == "TRIGGER";
    let color = if is_trigger { "#ff0000" } else { "#36a64f" };

    match format {
        AlertFormat::Generic => serde_json::to_value(payload).unwrap_or_default(),

        AlertFormat::Slack => {
            let title = format!(
                "[{}] veil-guard Alert: {} ({})",
                payload.event_type, payload.summary, payload.target_url
            );

            serde_json::json!({
                "text": title,
                "attachments": [
                    {
                        "color": color,
                        "fields": [
                            { "title": "Event Type", "value": payload.event_type, "short": true },
                            { "title": "Target URL", "value": payload.target_url, "short": true },
                            { "title": "Severity", "value": payload.severity, "short": true },
                            { "title": "Label", "value": payload.label.as_deref().unwrap_or("default"), "short": true },
                            { "title": "Findings Count", "value": payload.findings_count.to_string(), "short": true },
                            { "title": "Timestamp", "value": payload.timestamp.to_string(), "short": true }
                        ]
                    }
                ]
            })
        }

        AlertFormat::PagerDuty => {
            let action = if is_trigger { "trigger" } else { "resolve" };
            let dedup_key = format!("veil-guard-{}", payload.target_url.replace(['/', ':'], "-"));

            serde_json::json!({
                "routing_key": "veil-guard-alerts",
                "event_action": action,
                "dedup_key": dedup_key,
                "payload": {
                    "summary": payload.summary,
                    "severity": if is_trigger { "error" } else { "info" },
                    "source": payload.target_url,
                    "custom_details": payload.details
                }
            })
        }

        AlertFormat::Datadog => {
            let alert_type = if is_trigger { "error" } else { "success" };

            serde_json::json!({
                "title": format!("veil-guard [{}] {}", payload.event_type, payload.summary),
                "text": serde_json::to_string_pretty(&payload.details).unwrap_or_default(),
                "alert_type": alert_type,
                "source_type_name": "veil-guard",
                "tags": [
                    format!("target:{}", payload.target_url),
                    format!("severity:{}", payload.severity)
                ]
            })
        }
    }
}
