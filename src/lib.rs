//! veil-guard — web asset integrity and attestation.
//!
//! The wire protocol is defined by `SPEC.md` in the repository root, which is
//! normative: where this crate and that document disagree, this crate is wrong.
//! `tests/conformance.rs` checks both against the shared golden vectors in
//! `testdata/conformance_vectors.json`, which the JavaScript reference verifier
//! in `testdata/verify_vectors.mjs` also consumes.

#[cfg(feature = "audit")]
pub mod auditor;
pub mod crypto;
pub mod generators;
pub mod html;
#[cfg(feature = "kms")]
pub mod kms;
pub mod manifest;
pub mod paths;
#[cfg(feature = "rekor")]
pub mod rekor;
#[cfg(feature = "relay-client")]
pub mod relay;
pub mod runtime;
pub mod scanner;
#[cfg(feature = "vault")]
pub mod vault;
