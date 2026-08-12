//! Remote KMS signing integration (AWS KMS and GCP Cloud KMS).
//!
//! Enabled under the `kms` feature flag.

#![cfg(feature = "kms")]

use sha2::{Digest, Sha256};
use std::error::Error;

/// Sign the domain-separated message under P-256 using AWS KMS.
///
/// The digest is computed here rather than by KMS. `MessageType::Raw` would have
/// KMS do the hashing, but its `Message` parameter is capped at 4096 bytes and a
/// manifest passes that at a few dozen assets — a real build would fail with a
/// validation error while the test fixtures kept passing. Hashing locally also
/// makes this path identical to the GCP one, and to what the local P-256 signer
/// does: ECDSA over SHA-256 of the same domain-separated bytes.
pub fn sign_aws_kms(msg: &[u8], key_id: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let sdk_config = aws_config::load_from_env().await;
        let client = aws_sdk_kms::Client::new(&sdk_config);

        let digest = Sha256::digest(msg);
        let resp = client
            .sign()
            .key_id(key_id)
            .message(aws_sdk_kms::primitives::Blob::new(digest.to_vec()))
            .message_type(aws_sdk_kms::types::MessageType::Digest)
            .signing_algorithm(aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha256)
            .send()
            .await?;

        let signature_blob = resp.signature().ok_or("no signature in AWS KMS response")?;

        // SPEC §2.1: WebCrypto accepts only raw `r||s`, and KMS returns ASN.1 DER.
        let der_sig = p256::ecdsa::Signature::from_der(signature_blob.as_ref())?;
        Ok(der_sig.to_bytes().to_vec())
    })
}

/// Sign the domain-separated message under P-256 using GCP Cloud KMS.
pub fn sign_gcp_kms(msg: &[u8], key_id: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        // Create KMS client config and authenticate via ADC
        let client_config = google_cloud_kms::client::ClientConfig::default()
            .with_auth()
            .await?;
        let client = google_cloud_kms::client::Client::new(client_config).await?;

        // Calculate SHA-256 of the message as required by GCP KMS
        let digest = Sha256::digest(msg);

        let req = google_cloud_googleapis::cloud::kms::v1::AsymmetricSignRequest {
            name: key_id.to_string(),
            digest: Some(google_cloud_googleapis::cloud::kms::v1::Digest {
                digest: Some(
                    google_cloud_googleapis::cloud::kms::v1::digest::Digest::Sha256(
                        digest.to_vec(),
                    ),
                ),
            }),
            ..Default::default()
        };

        let resp = client.asymmetric_sign(req, None).await?;
        let der_bytes = resp.signature;

        // Convert ASN.1 DER signature to raw 64-byte r||s
        let der_sig = p256::ecdsa::Signature::from_der(&der_bytes)?;
        Ok(der_sig.to_bytes().to_vec())
    })
}

/// Dispatch signing to the appropriate KMS provider based on key ID or provider flag.
pub fn sign_with_kms(
    msg: &[u8],
    kms_key_id: &str,
    kms_provider: Option<&str>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let provider = kms_provider.unwrap_or_else(|| {
        if kms_key_id.starts_with("projects/") {
            "gcp"
        } else {
            "aws"
        }
    });
    match provider {
        "aws" => sign_aws_kms(msg, kms_key_id),
        "gcp" => sign_gcp_kms(msg, kms_key_id),
        _ => Err(format!("unknown KMS provider: {provider}").into()),
    }
}
