//! Tier 1 runtime: bundling, and the JavaScript suites.
//!
//! The JS test scripts are driven from here so that `cargo test` is the single
//! command that checks both implementations. Without this they drift: a change to
//! the Rust verifier would pass CI while the Service Worker built from the same
//! spec quietly disagreed.
//!
//! Skipped with a notice if `node` is not on PATH.

use std::path::{Path, PathBuf};
use std::process::Command;
use veil_guard::crypto::{SigAlg, SignerKeys, TrustRoot, TrustedKey};
use veil_guard::runtime::{bundle_service_worker, strip_module_syntax, LOADER_JS};

fn node_available() -> bool {
    Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn repo(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn run_node(script: &str, args: &[&Path]) -> (bool, String) {
    let out = Command::new("node")
        .arg(repo(script))
        .args(args)
        .current_dir(repo("."))
        .output()
        .expect("node runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

fn sample_trust_root() -> TrustRoot {
    let signers: Vec<SignerKeys> = (0..3).map(|_| SignerKeys::generate()).collect();
    let mut keys: Vec<TrustedKey> = signers
        .iter()
        .enumerate()
        .map(|(i, s)| s.as_trusted_key(if i < 2 { "build" } else { "recovery" }))
        .collect();
    keys.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    TrustRoot {
        threshold: 2,
        sigalgs: vec![SigAlg::Ed25519, SigAlg::P256],
        keys,
    }
}

// ------------------------------------------------------------------ bundling
#[test]
fn bundle_carries_the_trust_root_and_drops_module_syntax() {
    let root = sample_trust_root();
    let bundle = bundle_service_worker(&root).unwrap();

    assert!(
        bundle.contains(&root.keys[0].ed25519),
        "keys must be baked in"
    );
    assert!(bundle.contains("self.VEIL_GUARD_TRUST_ROOT = "));
    for line in bundle.lines() {
        let t = line.trim_start();
        assert!(!t.starts_with("import "), "leftover import: {line}");
        assert!(!t.starts_with("export "), "leftover export: {line}");
    }
    // Calling importScripts would mean executing unverified code in order to decide
    // whether code is verified. The bundle discusses it in a comment; it must never
    // actually call it.
    assert!(
        !bundle.contains("importScripts("),
        "the worker must stay self-contained"
    );
}

#[test]
fn bundle_includes_every_module_and_the_lifecycle_handlers() {
    let bundle = bundle_service_worker(&sample_trust_root()).unwrap();
    for needle in [
        "function verifyManifest", // verify core
        "function decideRequest",  // policy
        "function decideResponse",
        "function applyRotationChain",
        "addEventListener('install'",
        "addEventListener('activate'",
        "addEventListener('fetch'",
    ] {
        assert!(bundle.contains(needle), "missing from bundle: {needle}");
    }
}

#[test]
fn loader_is_shipped_as_authored() {
    assert!(LOADER_JS.contains("navigator.serviceWorker"));
    // The overlay reports on attacker-influenced strings; it must build DOM nodes
    // with textContent rather than parsing markup.
    assert!(
        !LOADER_JS.contains("innerHTML"),
        "the loader must not assign innerHTML"
    );
}

#[test]
fn strip_transform_only_touches_top_level_declarations() {
    // Indented occurrences are data, not module syntax, and survive intact.
    let indented = "const a = `\n  export const notCode = 1;\n`;\n";
    assert_eq!(strip_module_syntax(indented).unwrap(), indented);

    // The documented residual hazard: a template continuation line starting at
    // column zero with `export` would be rewritten. No bundled source contains one,
    // and this test pins the behaviour so the limitation stays visible rather than
    // being rediscovered later.
    let flush = "const a = `\nexport const notCode = 1;`;\n";
    assert_eq!(
        strip_module_syntax(flush).unwrap(),
        "const a = `\nconst notCode = 1;`;\n"
    );
}

/// Guard for the hazard above: assert the real runtime sources have no template
/// literal spanning a line that begins with `export` or `import` at column zero.
#[test]
fn runtime_sources_avoid_the_transform_hazard() {
    for name in [
        "runtime/veilguard-verify.mjs",
        "runtime/veilguard-policy.mjs",
        "runtime/veil-guard-sw.js",
    ] {
        let src = std::fs::read_to_string(repo(name)).unwrap();
        let mut open_template = false;
        for (i, line) in src.lines().enumerate() {
            if open_template && (line.starts_with("export ") || line.starts_with("import ")) {
                panic!(
                    "{name}:{}: module keyword at column 0 inside a template literal",
                    i + 1
                );
            }
            // Backticks in `//` comments are prose, not code.
            let code = line.split("//").next().unwrap_or("");
            if code.matches('`').count() % 2 == 1 {
                open_template = !open_template;
            }
        }
    }
}

// ------------------------------------------------------------------ JS suites
#[test]
fn javascript_conformance_vectors_pass() {
    if !node_available() {
        eprintln!("skipping: node not on PATH");
        return;
    }
    let (ok, out) = run_node("testdata/verify_vectors.mjs", &[]);
    assert!(ok, "conformance vectors failed in JavaScript:\n{out}");
    assert!(out.contains("0 failed"), "{out}");
}

#[test]
fn javascript_tier1_policy_passes() {
    if !node_available() {
        eprintln!("skipping: node not on PATH");
        return;
    }
    let (ok, out) = run_node("testdata/verify_policy.mjs", &[]);
    assert!(ok, "Tier 1 policy tests failed:\n{out}");
    assert!(out.contains("0 failed"), "{out}");
}

#[test]
fn bundled_worker_evaluates_and_registers_handlers() {
    if !node_available() {
        eprintln!("skipping: node not on PATH");
        return;
    }
    let dir = std::env::temp_dir().join(format!("vg-sw-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("veil-guard-sw.js");
    std::fs::write(&path, bundle_service_worker(&sample_trust_root()).unwrap()).unwrap();

    let (ok, out) = run_node("testdata/run_sw_smoke.mjs", &[&path]);
    let _ = std::fs::remove_dir_all(&dir);

    assert!(ok, "the bundled worker did not evaluate cleanly:\n{out}");
    assert!(out.contains("activate, fetch, install, message"), "{out}");
}
