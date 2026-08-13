//! Reference Audit Relay Server implementation using Axum.

#![cfg(feature = "relay-server")]

use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use serde::Deserialize;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

#[derive(Parser, Debug)]
#[command(name = "veil-guard-relay")]
#[command(about = "Reference third-party audit relay server for veil-guard")]
struct Args {
    #[arg(short, long, default_value_t = 8080)]
    port: u16,
}

#[derive(Clone, Default)]
struct AppState {
    snapshots: Arc<Mutex<Vec<Value>>>,
}

#[derive(Deserialize)]
struct SnapshotQuery {
    domain: Option<String>,
    since: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let state = AppState::default();

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

async fn push_snapshot(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let mut snapshots = state.snapshots.lock().unwrap();
    snapshots.push(payload);
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "status": "ok" })),
    )
}

async fn list_snapshots(
    State(state): State<AppState>,
    Query(query): Query<SnapshotQuery>,
) -> Json<Value> {
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

    Json(Value::Array(filtered))
}
