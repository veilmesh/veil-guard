//! Reference Audit Relay Server implementation using Axum.

#![cfg(feature = "relay-server")]

use axum::{
    extract::{Query, State},
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

#[derive(Parser, Debug)]
#[command(name = "veil-guard-relay")]
#[command(about = "Reference third-party audit relay server for veil-guard")]
struct Args {
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    /// Directory for persistent storage of snapshot JSON files
    #[arg(short, long)]
    out_dir: Option<PathBuf>,

    /// Bearer authentication token for push and pull authorization
    #[arg(short, long, env = "VEIL_RELAY_TOKEN")]
    token: Option<String>,
}

#[derive(Clone, Default)]
struct AppState {
    snapshots: Arc<Mutex<Vec<Value>>>,
    out_dir: Option<PathBuf>,
    token: Option<String>,
}

#[derive(Deserialize)]
struct SnapshotQuery {
    domain: Option<String>,
    since: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let state = AppState {
        snapshots: Arc::new(Mutex::new(Vec::new())),
        out_dir: args.out_dir.clone(),
        token: args.token,
    };

    // Load persisted snapshots if out_dir is provided
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
            "Loaded {} persisted snapshot(s) from {}",
            loaded.len(),
            dir.display()
        );
        *state.snapshots.lock().unwrap() = loaded;
    }

    let app = Router::new()
        .route("/snapshots", post(push_snapshot))
        .route("/snapshots", get(list_snapshots))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    println!("veil-guard audit relay server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn check_auth(headers: &HeaderMap, required_token: Option<&str>) -> bool {
    let Some(expected) = required_token else {
        return true;
    };
    let auth_header = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();

    let expected_header = format!("Bearer {expected}");
    auth_header == expected_header
}

async fn push_snapshot(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !check_auth(&headers, state.token.as_deref()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Unauthorized" })),
        );
    }

    let mut snapshots = state.snapshots.lock().unwrap();
    let idx = snapshots.len();
    snapshots.push(payload.clone());

    if let Some(dir) = &state.out_dir {
        let label = payload["label"]
            .as_str()
            .or_else(|| payload["url"].as_str())
            .unwrap_or("snapshot");
        let safe_label = label.replace(['/', ':', '?'], "_");
        let fname = format!("{safe_label}_{idx}.json");
        let file_path = dir.join(fname);
        let _ = fs::write(
            file_path,
            serde_json::to_string_pretty(&payload).unwrap_or_default() + "\n",
        );
    }

    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "status": "ok" })),
    )
}

async fn list_snapshots(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SnapshotQuery>,
) -> (StatusCode, Json<Value>) {
    if !check_auth(&headers, state.token.as_deref()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "Unauthorized" })),
        );
    }

    let snapshots = state.snapshots.lock().unwrap();
    let filtered: Vec<Value> = snapshots
        .iter()
        .filter(|s| {
            if let Some(domain) = &query.domain {
                let url = s["url"].as_str().unwrap_or_default();
                if !url.contains(domain) {
                    return false;
                }
            }
            if let Some(since) = query.since {
                let ts = s["timestamp"]
                    .as_u64()
                    .or_else(|| s["observed_at"].as_u64())
                    .or_else(|| s["created_at"].as_u64())
                    .unwrap_or(0);
                if ts < since {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect();

    (StatusCode::OK, Json(Value::Array(filtered)))
}
