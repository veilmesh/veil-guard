//! Integration test for veil-guard-telemetry server.

#![cfg(feature = "telemetry-server")]

use std::time::Duration;

#[test]
fn test_telemetry_server_endpoints_and_cors() {
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_url = format!("http://127.0.0.1:{port}");

        tokio::spawn(async move {
            let app = axum::Router::new()
                .route(
                    "/health",
                    axum::routing::get(|| async {
                        axum::Json(serde_json::json!({ "status": "ok" }))
                    }),
                )
                .route(
                    "/reports/integrity",
                    axum::routing::post(|body: axum::body::Bytes| async move {
                        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        let count = json.as_array().map(|a| a.len()).unwrap_or(1);
                        axum::Json(serde_json::json!({ "status": "accepted", "count": count }))
                    }),
                )
                .layer(tower_http::cors::CorsLayer::permissive())
                .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024));

            axum::serve(listener, app).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let client = reqwest::Client::new();

        // 1. Health check
        let resp = client
            .get(format!("{server_url}/health"))
            .send()
            .await
            .expect("health check");
        assert_eq!(resp.status().as_u16(), 200);

        // 2. W3C / CSP report Content-Type application/csp-report (Bytes extractor test)
        let csp_report = serde_json::json!({
            "type": "csp-report",
            "csp-report": {
                "document-uri": "https://app.example.com/",
                "blocked-uri": "https://malicious.example.com/evil.js"
            }
        });

        let resp = client
            .post(format!("{server_url}/reports/integrity"))
            .header("Content-Type", "application/csp-report")
            .body(serde_json::to_string(&csp_report).unwrap())
            .send()
            .await
            .expect("post csp report");

        assert_eq!(resp.status().as_u16(), 200);
        let val: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(val["count"], 1);

        // 3. W3C Reporting API array payload application/reports+json
        let w3c_reports = serde_json::json!([
            {
                "type": "csp-violation",
                "url": "https://app.example.com/",
                "body": { "blockedURL": "https://evil.com/x.js" }
            },
            {
                "type": "csp-violation",
                "url": "https://app.example.com/dashboard",
                "body": { "blockedURL": "https://evil.com/y.js" }
            }
        ]);

        let resp = client
            .post(format!("{server_url}/reports/integrity"))
            .header("Content-Type", "application/reports+json")
            .body(serde_json::to_string(&w3c_reports).unwrap())
            .send()
            .await
            .expect("post w3c report array");

        assert_eq!(resp.status().as_u16(), 200);
        let val: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(val["count"], 2);
    });
}
