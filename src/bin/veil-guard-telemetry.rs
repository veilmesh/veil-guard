//! Reference W3C and Guardian Telemetry Ingestion Server for veil-guard.

#![cfg(feature = "telemetry-server")]

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower_http::cors::CorsLayer;

#[derive(Parser, Debug)]
#[command(name = "veil-guard-telemetry")]
#[command(about = "Reference W3C & Guardian telemetry ingestion server for veil-guard")]
struct Args {
    #[arg(short, long, default_value_t = 8081)]
    port: u16,

    /// Directory for persistent storage of received violation report JSON files
    #[arg(short, long)]
    out_dir: Option<PathBuf>,

    /// Optional bearer token or query token for report authorization
    #[arg(short, long, env = "VEIL_TELEMETRY_TOKEN")]
    token: Option<String>,

    /// Webhook URL to forward received violation reports
    #[arg(long, env = "VEIL_WEBHOOK_URL")]
    webhook_url: Option<String>,
}

#[derive(Clone)]
struct AppState {
    reports: Arc<Mutex<Vec<Value>>>,
    out_dir: Option<PathBuf>,
    token: Option<String>,
    webhook_url: Option<String>,
    http_client: reqwest::Client,
}

#[derive(Deserialize)]
struct AuthQuery {
    token: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .user_agent("veil-guard (telemetry-server)")
        .build()?;

    let state = AppState {
        reports: Arc::new(Mutex::new(Vec::new())),
        out_dir: args.out_dir.clone(),
        token: args.token,
        webhook_url: args.webhook_url,
        http_client,
    };

    if let Some(dir) = &args.out_dir {
        fs::create_dir_all(dir)?;
        let mut loaded = Vec::new();
        if let Ok(entries) = fs::read_dir(dir) {
            let mut paths: Vec<_> = entries.flatten().map(|e| e.path()).collect();
            paths.sort();
            for path in paths {
                if path.extension().and_then(|e| e.to_str()) == Some("json") {
                    if let Ok(content) = fs::read(&path) {
                        if let Ok(json) = serde_json::from_slice::<Value>(&content) {
                            loaded.push(json);
                        }
                    }
                }
            }
        }
        println!(
            "Loaded {} existing report(s) from {}",
            loaded.len(),
            dir.display()
        );
        *state.reports.lock().unwrap() = loaded;
    }

    let app = Router::new()
        .route("/reports/integrity", post(handle_integrity_report))
        .route("/reports/guardian", post(handle_guardian_report))
        .route("/health", get(handle_health))
        .layer(CorsLayer::permissive())
        .layer(DefaultBodyLimit::max(1024 * 1024)) // 1MB cap
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    println!("veil-guard telemetry server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    println!("Shutting down telemetry server gracefully...");
}

fn check_auth(
    headers: &HeaderMap,
    query_token: Option<&str>,
    required_token: Option<&str>,
) -> bool {
    let Some(expected) = required_token else {
        return true;
    };

    if let Some(qt) = query_token {
        if qt == expected {
            return true;
        }
    }

    let auth_header = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();

    auth_header == format!("Bearer {expected}")
}

async fn handle_integrity_report(
    State(state): State<AppState>,
    Query(query): Query<AuthQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<Value>) {
    if !check_auth(&headers, query.token.as_deref(), state.token.as_deref()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Unauthorized" })),
        );
    }

    let payload: Value = match serde_json::from_slice(&body) {
        Ok(val) => val,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("Invalid JSON body: {e}") })),
            );
        }
    };

    process_report(state, payload).await
}

async fn handle_guardian_report(
    State(state): State<AppState>,
    Query(query): Query<AuthQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<Value>) {
    if !check_auth(&headers, query.token.as_deref(), state.token.as_deref()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Unauthorized" })),
        );
    }

    let payload: Value = match serde_json::from_slice(&body) {
        Ok(val) => val,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("Invalid JSON body: {e}") })),
            );
        }
    };

    process_report(state, payload).await
}

async fn process_report(state: AppState, payload: Value) -> (StatusCode, Json<Value>) {
    let mut reports = state.reports.lock().unwrap();
    let items = if let Some(arr) = payload.as_array() {
        arr.clone()
    } else {
        vec![payload]
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    for item in &items {
        let idx = reports.len();
        reports.push(item.clone());

        if let Some(dir) = &state.out_dir {
            let fname = format!("report_{now}_{idx}.json");
            let file_path = dir.join(fname);
            if let Err(e) = fs::write(
                &file_path,
                serde_json::to_string_pretty(item).unwrap_or_default() + "\n",
            ) {
                eprintln!("Failed to write report to {}: {e}", file_path.display());
            }
        }

        if let Some(webhook) = &state.webhook_url {
            let client = state.http_client.clone();
            let wh_url = webhook.clone();
            let body = item.clone();
            tokio::spawn(async move {
                if let Err(e) = client.post(&wh_url).json(&body).send().await {
                    eprintln!("Failed to forward telemetry report to webhook {wh_url}: {e}");
                }
            });
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": "accepted", "count": items.len() })),
    )
}

async fn handle_health() -> Json<Value> {
    Json(serde_json::json!({ "status": "ok", "service": "veil-guard-telemetry" }))
}
