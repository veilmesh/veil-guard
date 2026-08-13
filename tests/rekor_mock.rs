//! Integration test for Rekor upload and verification mock.

#![cfg(feature = "rekor")]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use sha2::Digest;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use veil_guard::rekor::{ed25519_pubkey_to_pem, lookup_rekor_entry, upload_manifest};

#[test]
fn test_rekor_mock_flow() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp listener");
    let port = listener.local_addr().unwrap().port();
    let rekor_url = format!("http://127.0.0.1:{port}");

    let pubkey = [7u8; 32];
    let pem = ed25519_pubkey_to_pem(&pubkey);

    let server_handle = thread::spawn(move || {
        // Handle 1: POST /api/v1/log/entries
        {
            let (mut stream, _) = listener.accept().expect("accept connection 1");
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

            let start = body_start.expect("found body start");
            let body_json: serde_json::Value =
                serde_json::from_slice(&request_bytes[start..start + content_len]).unwrap();
            assert_eq!(body_json["kind"], "hashedrekord");

            let resp_json = serde_json::json!({
                "entry_42_key": {
                    "logIndex": 42,
                    "integratedTime": 1754726400u64,
                    "logID": "test_log_id_hash"
                }
            })
            .to_string();

            let response = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                resp_json.len(),
                resp_json
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        }

        // Handle 2 & 3: GET /api/v1/log/entries?logIndex=42 (for basic verify and B1 verify)
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept connection 2");
            let mut buffer = [0u8; 2048];
            let n = stream.read(&mut buffer).expect("read request");
            let req_str = String::from_utf8_lossy(&buffer[..n]);
            assert!(req_str.contains("logIndex=42"));

            let manifest_obj = serde_json::json!({ "test": "manifest" });
            let manifest_bytes =
                (serde_json::to_string_pretty(&manifest_obj).unwrap() + "\n").into_bytes();
            let manifest_sha256 = hex::encode(sha2::Sha256::digest(&manifest_bytes));

            let body_obj = serde_json::json!({
                "kind": "hashedrekord",
                "spec": {
                    "data": {
                        "hash": {
                            "algorithm": "sha256",
                            "value": manifest_sha256
                        }
                    }
                }
            });
            let body_b64 = BASE64.encode(body_obj.to_string());

            let resp_json = serde_json::json!({
                "entry_42_key": {
                    "logIndex": 42,
                    "integratedTime": 1754726400u64,
                    "body": body_b64
                }
            })
            .to_string();

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                resp_json.len(),
                resp_json
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        }
    });

    let manifest_obj = serde_json::json!({ "test": "manifest" });
    let manifest_bytes = (serde_json::to_string_pretty(&manifest_obj).unwrap() + "\n").into_bytes();
    let sig_bytes = b"mock_vgsig1_bundle";

    let entry = upload_manifest(&manifest_bytes, sig_bytes, &pem, &rekor_url)
        .expect("upload manifest to rekor mock");

    assert_eq!(entry.log_index, 42);
    assert_eq!(entry.integrated_time, 1754726400);

    let is_valid =
        lookup_rekor_entry(&manifest_bytes, &entry, &rekor_url).expect("verify rekor entry");

    assert!(is_valid);

    // Verify B1 fix: lookup_rekor_entry when manifest_bytes has source.rekor attached
    let manifest_with_rekor = serde_json::json!({
        "test": "manifest",

        "source": {
            "rekor": {
                "log_index": 42,
                "integrated_time": 1754726400u64,
                "log_id": "test_log_id_hash",
                "entry_id": "entry_42_key"
            }
        }
    });
    let manifest_with_rekor_bytes =
        (serde_json::to_string_pretty(&manifest_with_rekor).unwrap() + "\n").into_bytes();

    let is_valid_with_rekor = lookup_rekor_entry(&manifest_with_rekor_bytes, &entry, &rekor_url)
        .expect("verify rekor entry with source.rekor");

    assert!(
        is_valid_with_rekor,
        "B1 fix: lookup_rekor_entry must strip source.rekor before computing hash!"
    );

    server_handle.join().unwrap();
}

// ------------------------------------------------------------------ negative paths
//
// `lookup_rekor_entry` is a lookup, not a proof — it trusts whatever the endpoint at
// `--rekor-url` returns. That makes its failure modes the only thing standing between
// a wrong answer and an INFO finding that reads like reassurance, so each one gets a
// test: a log that records a different hash, a log that answers with nothing useful,
// and a log that is not there at all.

use std::net::TcpListener as Listener;
use std::thread as th;

fn serve_json(body: String, status: &'static str) -> String {
    let listener = Listener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    th::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    format!("http://127.0.0.1:{port}")
}

/// A Rekor `entries?logIndex=` response whose body records `hash`.
fn rekor_response_recording(hash: &str) -> String {
    let body = serde_json::json!({
        "kind": "hashedrekord",
        "apiVersion": "0.0.1",
        "spec": { "data": { "hash": { "algorithm": "sha256", "value": hash } } }
    });
    let b64 = BASE64.encode(serde_json::to_vec(&body).unwrap());
    format!(r#"{{"someuuid":{{"logIndex":42,"body":"{b64}"}}}}"#)
}

fn entry() -> veil_guard::rekor::RekorEntry {
    veil_guard::rekor::RekorEntry {
        log_index: 42,
        integrated_time: 1_754_726_400,
        log_id: "log".into(),
        entry_id: "someuuid".into(),
    }
}

#[test]
fn a_log_recording_a_different_hash_is_not_a_match() {
    // The whole point of the lookup. If this returned true, a manifest could be
    // published once and then swapped, and the audit would still say "recorded".
    let addr = serve_json(rekor_response_recording(&"11".repeat(32)), "200 OK");
    let matched = lookup_rekor_entry(br#"{"spec":"veil-guard/1"}"#, &entry(), &addr)
        .expect("the query itself succeeds");
    assert!(!matched, "a mismatched hash must not report as recorded");
}

#[test]
fn a_response_without_an_entry_body_is_an_error_not_a_match() {
    let addr = serve_json(r#"{"someuuid":{"logIndex":42}}"#.to_string(), "200 OK");
    assert!(
        lookup_rekor_entry(b"{}", &entry(), &addr).is_err(),
        "a body-less entry must be an error, never a silent false"
    );
}

#[test]
fn an_empty_response_object_is_an_error() {
    let addr = serve_json("{}".to_string(), "200 OK");
    assert!(lookup_rekor_entry(b"{}", &entry(), &addr).is_err());
}

#[test]
fn an_unreachable_log_is_an_error_not_a_match() {
    // Nothing listening. An audit must report that it could not check, rather than
    // quietly deciding the entry is absent.
    assert!(
        lookup_rekor_entry(b"{}", &entry(), "http://127.0.0.1:1").is_err(),
        "an unreachable log must surface as an error"
    );
}
