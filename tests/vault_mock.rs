//! Integration test for Vault transit engine Ed25519 signing mock.

#![cfg(feature = "vault")]

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use veil_guard::vault::sign_vault_transit;

#[test]
fn test_vault_transit_mock() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp listener");
    let port = listener.local_addr().unwrap().port();
    let vault_addr = format!("http://127.0.0.1:{port}");

    // Local keypair for mock server to produce valid Ed25519 signatures
    let seed = [42u8; 32];
    let mock_signing_key = SigningKey::from_bytes(&seed);
    let mock_verifying_key: VerifyingKey = mock_signing_key.verifying_key();

    let server_handle = thread::spawn(move || {
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
                    // Extract Content-Length
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

        let req_str = String::from_utf8_lossy(&request_bytes);
        let req_lower = req_str.to_lowercase();
        assert!(
            req_lower.contains("x-vault-token: test-vault-token"),
            "Got request:\n{req_str}"
        );
        assert!(req_str.contains("/v1/transit/sign/ci-ed25519"));

        let start = body_start.expect("found body start");
        let body_json: serde_json::Value =
            serde_json::from_slice(&request_bytes[start..start + content_len]).expect("parse json");

        let input_b64 = body_json["input"].as_str().expect("input b64");
        let msg = BASE64.decode(input_b64).expect("decode input b64");

        let ed_sig = mock_signing_key.sign(&msg);
        let sig_b64 = BASE64.encode(ed_sig.to_bytes());

        let response_payload = serde_json::json!({
            "data": {
                "signature": format!("vault:v1:{sig_b64}")
            }
        });

        let resp_bytes = response_payload.to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            resp_bytes.len(),
            resp_bytes
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    });

    let msg = b"veil-guard/manifest/v1\x00test_payload";
    let sig_bytes = sign_vault_transit(
        &msg[..],
        &vault_addr,
        "ci-ed25519",
        Some("test-vault-token"),
    )
    .expect("sign_vault_transit succeeded");

    assert_eq!(sig_bytes.len(), 64);
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
    mock_verifying_key
        .verify_strict(msg, &sig)
        .expect("vault mock signature verified against mock verifying key");

    server_handle.join().unwrap();
}
