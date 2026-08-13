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
                            if let Some(stripped) = l.strip_prefix("content-length:") {
                                content_len = stripped.trim().parse::<usize>().unwrap_or(0);
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

            let req_str = String::from_utf8_lossy(&request_bytes).to_lowercase();
            assert!(req_str.contains("authorization: bearer secret_token"));

            let raw_req = String::from_utf8_lossy(&request_bytes);
            if raw_req.starts_with("POST") {
                let start = body_start.expect("found body start");
                let snap_val: serde_json::Value =
                    serde_json::from_slice(&request_bytes[start..start + content_len]).unwrap();
                store_clone.lock().unwrap().push(snap_val);

                let response = "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 16\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}";
                stream.write_all(response.as_bytes()).unwrap();
            } else if raw_req.starts_with("GET") {
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
    let list = pull_snapshots(
        &relay_url,
        "app.example.com",
        None,
        &tmp_dir,
        Some("secret_token"),
    )
    .expect("pull snapshots");

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

// ------------------------------------------------------------------ negative paths
//
// The relay is how several vantage points compare notes, and `diff` between them is
// the only signal that reveals a bundle served to some visitors and not others. A
// relay that is down, or that answers with something other than snapshots, must stop
// the audit rather than look like agreement.

use std::net::TcpListener as L;
use std::thread as T;

fn respond(body: &'static str, status: &'static str) -> String {
    let l = L::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().unwrap().port();
    T::spawn(move || {
        if let Ok((mut s, _)) = l.accept() {
            let mut b = [0u8; 8192];
            let _ = s.read(&mut b);
            let _ = s.write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
        }
    });
    format!("http://127.0.0.1:{port}")
}

#[test]
fn pushing_to_an_unreachable_relay_is_an_error() {
    let snap = serde_json::json!({ "url": "https://example.invalid" });
    assert!(
        push_snapshot("http://127.0.0.1:1", &snap, None).is_err(),
        "a relay that is not listening must not look like a successful push"
    );
}

#[test]
fn a_rejected_push_is_an_error() {
    let addr = respond(r#"{"error":"unauthorized"}"#, "401 Unauthorized");
    let snap = serde_json::json!({ "url": "https://example.invalid" });
    assert!(
        push_snapshot(&addr, &snap, Some("wrong-token")).is_err(),
        "a 401 must surface; a snapshot nobody stored is not a snapshot"
    );
}

#[test]
fn pulling_from_an_unreachable_relay_is_an_error() {
    assert!(
        pull_snapshots(
            "http://127.0.0.1:1",
            "example.invalid",
            None,
            &std::env::temp_dir(),
            None
        )
        .is_err(),
        "an unreachable relay must not read as zero divergences"
    );
}

#[test]
fn a_relay_answering_with_junk_is_an_error() {
    let addr = respond("not json at all", "200 OK");
    assert!(
        pull_snapshots(&addr, "example.invalid", None, &std::env::temp_dir(), None).is_err(),
        "an unparseable body must not read as zero divergences"
    );
}
