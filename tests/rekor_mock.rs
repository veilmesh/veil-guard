//! Integration test for Rekor upload and verification mock.

#![cfg(feature = "rekor")]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use sha2::Digest;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use veil_guard::rekor::{ed25519_pubkey_to_pem, upload_manifest, verify_rekor_entry};

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
    let manifest_bytes =
        (serde_json::to_string_pretty(&manifest_obj).unwrap() + "\n").into_bytes();
    let sig_bytes = b"mock_vgsig1_bundle";

    let entry = upload_manifest(&manifest_bytes, sig_bytes, &pem, &rekor_url)
        .expect("upload manifest to rekor mock");

    assert_eq!(entry.log_index, 42);
    assert_eq!(entry.integrated_time, 1754726400);

    let is_valid =
        verify_rekor_entry(&manifest_bytes, &entry, &rekor_url).expect("verify rekor entry");

    assert!(is_valid);

    // Verify B1 fix: verify_rekor_entry when manifest_bytes has source.rekor attached
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

    let is_valid_with_rekor =
        verify_rekor_entry(&manifest_with_rekor_bytes, &entry, &rekor_url)
            .expect("verify rekor entry with source.rekor");

    assert!(is_valid_with_rekor, "B1 fix: verify_rekor_entry must strip source.rekor before computing hash!");

    server_handle.join().unwrap();
}

