//! Rust signs, JavaScript verifies.
//!
//! `tests/conformance.rs` covers the other direction: frozen vectors produced in
//! Node, verified in Rust. This closes the loop on real output — a manifest built
//! by the signing pipeline in this crate, handed to the reference WebCrypto
//! verifier that Tier 1 is derived from.
//!
//! Skipped with a notice if `node` is not on PATH.

use std::path::{Path, PathBuf};
use std::process::Command;
use veil_guard::crypto::{
    build_bundle, SigAlg, SignerKeys, TrustRoot, TrustedKey, PREFIX_MANIFEST,
};
use veil_guard::manifest::{AssetEntry, Manifest, Scope, SPEC_MANIFEST};
use veil_guard::scanner::scan_dist;

fn node_available() -> bool {
    Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn testdata(file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(file)
}

struct Fixture {
    dir: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Build a small signed dist with a 2-of-3 trust root, exactly as `sign` does.
fn build_signed_fixture(name: &str) -> Fixture {
    let dir = std::env::temp_dir().join(format!("vg-xlang-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let dist = dir.join("dist");
    std::fs::create_dir_all(dist.join("assets")).unwrap();

    std::fs::write(dist.join("index.html"), b"<!doctype html>\n<html></html>\n").unwrap();
    std::fs::write(dist.join("assets/app.js"), b"export const x = 1;\n").unwrap();
    std::fs::write(dist.join("assets/style.css"), b":root{}\n").unwrap();
    // A non-ASCII name, so the NFC rules are exercised on a real filesystem.
    std::fs::write(
        dist.join("assets/café.js"),
        b"export default 'caf\xc3\xa9';\n",
    )
    .unwrap();

    let signers: Vec<SignerKeys> = (0..3).map(|_| SignerKeys::generate()).collect();
    let mut keys: Vec<TrustedKey> = signers
        .iter()
        .enumerate()
        .map(|(i, s)| s.as_trusted_key(if i < 2 { "build" } else { "recovery" }))
        .collect();
    keys.sort_by(|a, b| a.key_id.cmp(&b.key_id));

    let root = TrustRoot {
        threshold: 2,
        sigalgs: vec![SigAlg::Ed25519, SigAlg::P256],
        keys,
    };
    root.validate().unwrap();

    let assets = scan_dist(&dist).unwrap();
    let version = 1_780_000_000u64;
    let manifest = Manifest {
        spec: SPEC_MANIFEST.into(),
        version,
        not_after: version + 180 * 86_400,
        sigalgs: root.sigalgs.clone(),
        trust_root_id: root.id_hex().unwrap(),
        trust_root: root.clone(),
        scope: Scope {
            include: vec!["/".into()],
            exclude: vec![],
        },
        source: serde_json::json!({}),
        assets: assets
            .iter()
            .map(|a| AssetEntry {
                path: a.key.clone(),
                sha256: a.sha256.clone(),
                sha384: a.sha384.clone(),
                size: a.size,
                content_type: a.content_type.clone(),
            })
            .collect(),
    };

    let payload = (serde_json::to_string_pretty(&manifest).unwrap() + "\n").into_bytes();
    let mut entries = Vec::new();
    for s in signers.iter().take(2) {
        entries.extend(s.sign(PREFIX_MANIFEST, &payload));
    }

    std::fs::write(dist.join("veil-guard-manifest.json"), &payload).unwrap();
    std::fs::write(dist.join("veil-guard-manifest.sig"), build_bundle(&entries)).unwrap();
    std::fs::write(
        dir.join("trust-root.json"),
        serde_json::to_string_pretty(&root).unwrap(),
    )
    .unwrap();

    Fixture { dir }
}

fn run_js_verifier(fixture: &Fixture, expected: &str) -> (bool, String) {
    let out = Command::new("node")
        .arg(testdata("verify_manifest.mjs"))
        .arg(fixture.dir.join("dist"))
        .arg(fixture.dir.join("trust-root.json"))
        .arg(expected)
        .output()
        .expect("node runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

#[test]
fn javascript_verifies_a_rust_signed_build() {
    if !node_available() {
        eprintln!("skipping: node not on PATH");
        return;
    }
    let fixture = build_signed_fixture("valid");
    let (ok, output) = run_js_verifier(&fixture, "VALID");
    assert!(
        ok,
        "JS verifier rejected a valid Rust-signed build:\n{output}"
    );
    assert!(output.contains("assets matching : 4/4"), "{output}");
}

#[test]
fn javascript_detects_a_tampered_asset() {
    if !node_available() {
        eprintln!("skipping: node not on PATH");
        return;
    }
    let fixture = build_signed_fixture("tampered");
    let target = fixture.dir.join("dist/assets/app.js");
    let mut bytes = std::fs::read(&target).unwrap();
    bytes.push(b'\n');
    std::fs::write(&target, bytes).unwrap();

    // The manifest itself is untouched, so it still verifies; the asset does not.
    let (ok, output) = run_js_verifier(&fixture, "VALID");
    assert!(!ok, "a modified asset must fail the JS check:\n{output}");
    assert!(
        output.contains("sha256 mismatch  /assets/app.js"),
        "{output}"
    );
}

#[test]
fn javascript_detects_a_tampered_manifest() {
    if !node_available() {
        eprintln!("skipping: node not on PATH");
        return;
    }
    let fixture = build_signed_fixture("badmanifest");
    let path = fixture.dir.join("dist/veil-guard-manifest.json");
    let text = std::fs::read_to_string(&path).unwrap();

    let patched = text.replacen("\"size\": 20", "\"size\": 21", 1);
    assert_ne!(patched, text, "fixture must actually change");
    std::fs::write(&path, patched).unwrap();

    let (ok, output) = run_js_verifier(&fixture, "TAMPERED");
    assert!(ok, "JS verifier should report TAMPERED:\n{output}");
}

/// SPEC §6.1 in one test: the signature covers bytes, not JSON semantics. Adding a
/// byte that every JSON parser ignores must still fail verification — that is what
/// makes a canonicalization scheme unnecessary.
#[test]
fn javascript_rejects_a_semantically_identical_manifest() {
    if !node_available() {
        eprintln!("skipping: node not on PATH");
        return;
    }
    let fixture = build_signed_fixture("whitespace");
    let path = fixture.dir.join("dist/veil-guard-manifest.json");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.push(b' '); // trailing whitespace: identical JSON, different bytes
    std::fs::write(&path, bytes).unwrap();

    let (ok, output) = run_js_verifier(&fixture, "TAMPERED");
    assert!(
        ok,
        "one ignorable byte must still break the signature:\n{output}"
    );
}

#[test]
fn javascript_rejects_an_unrelated_trust_root() {
    if !node_available() {
        eprintln!("skipping: node not on PATH");
        return;
    }
    let fixture = build_signed_fixture("wrongroot");

    let others: Vec<SignerKeys> = (0..3).map(|_| SignerKeys::generate()).collect();
    let mut keys: Vec<TrustedKey> = others.iter().map(|s| s.as_trusted_key("build")).collect();
    keys.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    let stranger = TrustRoot {
        threshold: 2,
        sigalgs: vec![SigAlg::Ed25519, SigAlg::P256],
        keys,
    };
    std::fs::write(
        fixture.dir.join("trust-root.json"),
        serde_json::to_string_pretty(&stranger).unwrap(),
    )
    .unwrap();

    let (ok, output) = run_js_verifier(&fixture, "UNTRUSTED_ROOT");
    assert!(
        ok,
        "a foreign trust root must yield UNTRUSTED_ROOT:\n{output}"
    );
}
