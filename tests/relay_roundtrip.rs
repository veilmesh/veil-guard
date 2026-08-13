//! Integration test for Third-Party Audit Relay push, pull, and diff.

#![cfg(all(feature = "relay-client", feature = "audit"))]

use std::fs;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use veil_guard::auditor::{diff, Snapshot};
use veil_guard::relay::{pull_snapshots, push_snapshot};

#[test]
fn test_relay_push_pull_diff_roundtrip() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp listener");
    let port = listener.local_addr().unwrap().port();
    let relay_url = format!("http://127.0.0.1:{port}");

    let snapshots_store: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
    let store_clone = snapshots_store.clone();

    let server_handle = thread::spawn(move || {
        // Handle 2 requests: 1 POST, 1 GET
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept connection");
            let mut request_bytes = Vec::new();
            let mut temp_buf = [0u8; 1024];
            let mut body_start = None;
            let mut content_len = 0;

            loop {
                let n = stream.read(&mut temp_buf).expect("read request");
                if n == 0 {
                    break;
                }
                request_bytes.extend_from_slice(&temp_buf[..n]);

                let req_str = String::from_utf8_lossy(&request_bytes);
                if body_start.is_none() {
                    if let Some(pos) = req_str.find("\r\n\r\n") {
                        body_start = Some(pos + 4);
                        for line in req_str[..pos].lines() {
                            let l = line.to_lowercase();
                            if l.starts_with("content-length:") {
                                content_len = l["content-length:".len()..]
                                    .trim()
                                    .parse::<usize>()
                                    .unwrap_or(0);
                            }
                        }
                    }
                }
                if let Some(start) = body_start {
                    if request_bytes.len() - start >= content_len {
                        break;
                    }
                }
            }

            let req_str = String::from_utf8_lossy(&request_bytes);
            if req_str.starts_with("POST") {
                let start = body_start.expect("found body start");
                let snap_val: serde_json::Value =
                    serde_json::from_slice(&request_bytes[start..start + content_len]).unwrap();
                store_clone.lock().unwrap().push(snap_val);

                let response = "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 16\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}";
                stream.write_all(response.as_bytes()).unwrap();
            } else if req_str.starts_with("GET") {
                let list = store_clone.lock().unwrap().clone();
                let resp_json = serde_json::to_string(&list).unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp_json.len(),
                    resp_json
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
            stream.flush().unwrap();
        }
    });

    let mock_snapshot = serde_json::json!({
        "spec": "veil-guard/audit/1",
        "url": "https://app.example.com",
        "label": "eu-west-1",

        "trust_root_id": "a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890",
        "manifest_state": "VALID",
        "manifest_version": 1754726400,
        "manifest_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "assets_in_manifest": 5,
        "assets_probed": 5,
        "observed_at": 1754726400,
        "observed": {},
        "findings": []
    });

    // 1. Push
    push_snapshot(&relay_url, &mock_snapshot, Some("secret_token")).expect("push snapshot");

    // 2. Pull
    let tmp_dir = std::env::temp_dir().join("veil_guard_relay_test");
    let _ = fs::remove_dir_all(&tmp_dir);
    let list =
        pull_snapshots(&relay_url, "app.example.com", None, &tmp_dir).expect("pull snapshots");

    assert_eq!(list.len(), 1);
    let pulled_snap: Snapshot = serde_json::from_value(list[0].clone()).expect("parse snapshot");
    let orig_snap: Snapshot = serde_json::from_value(mock_snapshot.clone()).expect("parse mock");

    // 3. Diff
    let divergences = diff(&pulled_snap, &orig_snap);
    assert!(
        divergences.is_empty(),
        "pulled snapshot diverges from pushed snapshot!"
    );

    let _ = fs::remove_dir_all(&tmp_dir);
    server_handle.join().unwrap();
}
