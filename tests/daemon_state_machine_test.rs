//! Integration test for auditor daemon state machine and alerting.

#![cfg(all(feature = "audit", feature = "telemetry-server"))]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use veil_guard::alerting::{send_alert, AlertFormat, AlertPayload};
use veil_guard::auditor::TargetStatus;

#[test]
fn test_daemon_alert_state_machine() {
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async {
        let client = reqwest::Client::builder().build().unwrap();

        let alert_history: Arc<Mutex<Vec<AlertPayload>>> = Arc::new(Mutex::new(Vec::new()));
        let history_clone = alert_history.clone();

        // Spin up mock webhook server
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let webhook_url = format!("http://127.0.0.1:{}/webhook", addr.port());

        tokio::spawn(async move {
            let app = axum::Router::new().route(
                "/webhook",
                axum::routing::post(move |body: axum::body::Bytes| {
                    let history = history_clone.clone();
                    async move {
                        let payload: AlertPayload = serde_json::from_slice(&body).unwrap();
                        history.lock().unwrap().push(payload);
                        axum::Json(serde_json::json!({ "status": "ok" }))
                    }
                }),
            );
            axum::serve(listener, app).await.unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut state: BTreeMap<String, TargetStatus> = BTreeMap::new();
        let target_url = "https://app.example.com".to_string();

        // 1. Initial State: OK -> FAIL (Trigger alert)
        let now = 1000u64;
        let status = state.entry(target_url.clone()).or_insert(TargetStatus {
            is_failing: false,
            since: 0,
            last_alert: 0,
        });

        assert!(!status.is_failing);
        status.is_failing = true;
        status.since = now;
        status.last_alert = now;

        let trigger_payload = AlertPayload {
            event_type: "TRIGGER".into(),
            target_url: target_url.clone(),
            label: Some("eu-west".into()),
            timestamp: now,
            severity: "Critical".into(),
            summary: "Tamper detected".into(),
            findings_count: 1,
            details: serde_json::json!({}),
        };

        send_alert(
            &client,
            &webhook_url,
            AlertFormat::Generic,
            &trigger_payload,
            None,
        )
        .await
        .expect("send trigger alert");

        assert_eq!(alert_history.lock().unwrap().len(), 1);
        assert_eq!(alert_history.lock().unwrap()[0].event_type, "TRIGGER");

        // 2. Recovery State: FAIL -> OK (Resolve alert)
        let now_recovered = 1050u64;
        let status = state.get_mut(&target_url).unwrap();
        assert!(status.is_failing);
        status.is_failing = false;
        status.last_alert = now_recovered;

        let resolve_payload = AlertPayload {
            event_type: "RESOLVE".into(),
            target_url: target_url.clone(),
            label: Some("eu-west".into()),
            timestamp: now_recovered,
            severity: "info".into(),
            summary: "Recovered".into(),
            findings_count: 0,
            details: serde_json::json!({}),
        };

        send_alert(
            &client,
            &webhook_url,
            AlertFormat::Generic,
            &resolve_payload,
            None,
        )
        .await
        .expect("send resolve alert");

        assert_eq!(alert_history.lock().unwrap().len(), 2);
        assert_eq!(alert_history.lock().unwrap()[1].event_type, "RESOLVE");
    });
}
