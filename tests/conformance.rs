//! Cross-language conformance: the Rust implementation must reach the same verdict
//! as `testdata/verify_vectors.mjs` on every vector in
//! `testdata/conformance_vectors.json`. See SPEC.md §11.

use serde_json::Value;
use veil_guard::crypto::*;
use veil_guard::manifest::*;
use veil_guard::paths::*;

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/conformance_vectors.json"
    );
    serde_json::from_slice(&std::fs::read(path).expect("vectors present")).expect("vectors parse")
}

fn h(v: &Value) -> Vec<u8> {
    unhex(v.as_str().expect("hex string")).expect("valid lowercase hex")
}

fn pinned_root(v: &Value) -> TrustRoot {
    let payload = h(&v["manifest"]["payload_utf8_hex"]);
    let m: Manifest = serde_json::from_slice(&payload).expect("manifest parses");
    m.trust_root
}

// ------------------------------------------------------------------ SPEC §2, §3
#[test]
fn domain_prefixes_match_the_spec() {
    let v = vectors();
    let p = &v["prefixes"];
    assert_eq!(h(&p["manifest"]), PREFIX_MANIFEST);
    assert_eq!(h(&p["rotation"]), PREFIX_ROTATION);
    assert_eq!(h(&p["revocation"]), PREFIX_REVOCATION);
    assert_eq!(h(&p["keyid"]), PREFIX_KEYID);
    assert_eq!(h(&p["trustroot"]), PREFIX_TRUSTROOT);
}

#[test]
fn hex_decoding_is_strict() {
    assert!(unhex("00ff").is_ok());
    assert!(
        unhex("00FF").is_err(),
        "uppercase must be rejected, not normalized"
    );
    assert!(unhex("0f0").is_err(), "odd length must be rejected");
    assert!(unhex("zz").is_err());
}

// ------------------------------------------------------------------ SPEC §4.2, §4.5
#[test]
fn key_id_derivation() {
    let v = vectors();
    for (i, d) in v["derivations"]["key_id"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let s = &v["signers"][i];
        let ed: [u8; 32] = h(&s["ed25519_public"]).try_into().unwrap();
        let p: [u8; 65] = h(&s["p256_public_sec1_uncompressed"]).try_into().unwrap();
        assert_eq!(
            hex::encode(key_id(&ed, &p)),
            d["expect_key_id"].as_str().unwrap(),
            "key_id[{i}]"
        );
    }
}

#[test]
fn trust_root_id_derivation() {
    let v = vectors();
    let root = pinned_root(&v);
    root.validate().expect("fixture trust root is valid");
    assert_eq!(
        root.id_hex().unwrap(),
        v["derivations"]["trust_root"]["expect_trust_root_id"]
            .as_str()
            .unwrap()
    );
}

#[test]
fn trust_root_rejects_unknown_members() {
    // SPEC §12: the ID is a binary hash, so a member it does not cover must not be
    // silently accepted.
    let json = r#"{"threshold":1,"sigalgs":["ed25519"],"keys":[],"extra":true}"#;
    assert!(serde_json::from_str::<TrustRoot>(json).is_err());
}

#[test]
fn trust_root_validation_rules() {
    let v = vectors();
    let base = pinned_root(&v);

    let mut unsorted = base.clone();
    unsorted.keys.reverse();
    assert!(
        unsorted.validate().is_err(),
        "keys must be sorted by key_id"
    );

    let mut too_high = base.clone();
    too_high.threshold = (base.keys.len() + 1) as u8;
    assert!(too_high.validate().is_err(), "threshold above key count");

    let mut zero = base.clone();
    zero.threshold = 0;
    assert!(zero.validate().is_err(), "threshold must be at least 1");

    let mut forged = base.clone();
    forged.keys[0].key_id = "0000000000000000".into();
    assert!(
        forged.validate().is_err(),
        "key_id must match its key material"
    );

    let mut dup_alg = base.clone();
    dup_alg.sigalgs = vec![SigAlg::Ed25519, SigAlg::Ed25519];
    assert!(
        dup_alg.validate().is_err(),
        "sigalgs must be sorted and unique"
    );
}

// ------------------------------------------------------------------ SPEC §2.1
#[test]
fn hashes_and_sri_match() {
    let v = vectors();
    for a in v["hashes"].as_array().unwrap() {
        let body = h(&a["body_hex"]);
        assert_eq!(
            hex::encode(sha256(&body)),
            a["expect_sha256"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(sha384(&body)),
            a["expect_sha384"].as_str().unwrap()
        );
    }
}

#[test]
fn p256_rejects_compressed_points_and_der_signatures() {
    let v = vectors();
    let root = pinned_root(&v);
    let key = &root.keys[0];

    let mut compressed = key.clone();
    compressed.p256 = format!("02{}", &key.p256[2..66]); // 0x02 prefix, 33 bytes worth
    assert!(
        compressed.p256_bytes().is_err(),
        "compressed SEC1 must be rejected"
    );

    // A DER-wrapped signature is 70-72 bytes; the raw r||s form is exactly 64.
    let der_ish = vec![0x30u8; 70];
    let pub_key: [u8; 65] = h(&serde_json::json!(key.p256)).try_into().unwrap();
    assert!(!verify_p256(&pub_key, &der_ish, b"anything"));
}

// ------------------------------------------------------------------ SPEC §5
#[test]
fn malformed_bundles_are_all_rejected() {
    let v = vectors();
    for (name, bundle) in v["manifest"]["malformed_bundles"].as_object().unwrap() {
        assert!(
            parse_bundle(&h(bundle)).is_err(),
            "bundle `{name}` must fail to parse"
        );
    }
}

#[test]
fn bundle_round_trips() {
    let v = vectors();
    let bytes = h(&v["manifest"]["cases"][0]["bundle_hex"]);
    let entries = parse_bundle(&bytes).expect("valid bundle parses");
    assert_eq!(
        build_bundle(&entries),
        bytes,
        "re-encoding must be byte-identical"
    );
}

#[test]
fn unknown_alg_id_is_skipped_not_rejected() {
    let v = vectors();
    let case = v["manifest"]["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "unknown_alg_id_is_skipped")
        .expect("vector present");
    let entries = parse_bundle(&h(&case["bundle_hex"])).expect("parses despite unknown alg");
    assert!(entries
        .iter()
        .any(|e| SigAlg::from_alg_id(e.alg_id).is_none()));
}

// ------------------------------------------------------------------ SPEC §8.1
#[test]
fn manifest_state_machine_matches_vectors() {
    let v = vectors();
    let payload = h(&v["manifest"]["payload_utf8_hex"]);
    let root = pinned_root(&v);
    let m: Manifest = serde_json::from_slice(&payload).unwrap();

    for case in v["manifest"]["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let pinned_version = if name == "rollback" {
            m.version + 1
        } else {
            v["manifest"]["pinned_version"].as_u64().unwrap()
        };
        let now = if name == "expired_at_now_expired" {
            v["manifest"]["now_expired"].as_u64().unwrap()
        } else {
            v["manifest"]["now_valid"].as_u64().unwrap()
        };

        let got = verify_manifest(
            &payload,
            &h(&case["bundle_hex"]),
            &root,
            pinned_version,
            now,
            SUPPORTED_ALGS,
        );
        assert_eq!(
            got.as_str(),
            case["expect"].as_str().unwrap(),
            "case `{name}`"
        );
    }
}

#[test]
fn malformed_bundles_yield_tampered_not_a_panic() {
    let v = vectors();
    let payload = h(&v["manifest"]["payload_utf8_hex"]);
    let root = pinned_root(&v);
    for (name, bundle) in v["manifest"]["malformed_bundles"].as_object().unwrap() {
        let got = verify_manifest(&payload, &h(bundle), &root, 0, 0, SUPPORTED_ALGS);
        assert_eq!(got, ManifestState::Tampered, "case `{name}`");
    }
}

/// The downgrade defense, and the residual weakness SPEC §8.1 documents.
#[test]
fn restricted_algorithm_sets() {
    let v = vectors();
    let payload = h(&v["manifest"]["payload_utf8_hex"]);
    let root = pinned_root(&v);
    let cases = v["manifest"]["cases"].as_array().unwrap();
    let find = |n: &str| h(&cases.iter().find(|c| c["name"] == n).unwrap()["bundle_hex"]);
    let valid = find("valid_quorum");
    let stripped = find("stripped_p256_half");
    let now = v["manifest"]["now_valid"].as_u64().unwrap();
    let pv = v["manifest"]["pinned_version"].as_u64().unwrap();

    let run =
        |bundle: &[u8], algs: &[SigAlg]| verify_manifest(&payload, bundle, &root, pv, now, algs);

    assert_eq!(run(&valid, &[SigAlg::P256]), ManifestState::Valid);
    assert_eq!(run(&valid, &[SigAlg::Ed25519]), ManifestState::Valid);
    assert_eq!(run(&valid, &[]), ManifestState::Unsupported);

    // An attacker holding only the ed25519 halves cannot reach the threshold on a
    // verifier that also implements p256.
    assert_eq!(
        run(&stripped, &[SigAlg::Ed25519, SigAlg::P256]),
        ManifestState::UntrustedRoot
    );
    assert_eq!(
        run(&stripped, &[SigAlg::P256]),
        ManifestState::UntrustedRoot
    );

    // Documented and asserted so it can never become accidental: a verifier that
    // implements only ed25519 is protected only by ed25519.
    assert_eq!(run(&stripped, &[SigAlg::Ed25519]), ManifestState::Valid);
}

// ------------------------------------------------------------------ SPEC §9.1
#[test]
fn rotation_matches_vectors() {
    let v = vectors();
    let payload = h(&v["rotation"]["payload_utf8_hex"]);
    let bundle = h(&v["rotation"]["bundle_hex"]);
    let root = pinned_root(&v);

    assert_eq!(
        verify_rotation(&payload, &bundle, &root, 0, SUPPORTED_ALGS),
        RotationVerdict::Accept
    );

    let replay_at = v["rotation"]["replay_pinned_rotation_version"]
        .as_u64()
        .unwrap();
    assert_eq!(
        verify_rotation(&payload, &bundle, &root, replay_at, SUPPORTED_ALGS),
        RotationVerdict::Reject,
        "replaying a rotation at its own version must not walk the pin back"
    );

    // SPEC §3: manifest-prefixed signatures must not verify as a rotation.
    assert_eq!(
        verify_rotation(
            &payload,
            &h(&v["rotation"]["wrong_prefix_bundle_hex"]),
            &root,
            0,
            SUPPORTED_ALGS
        ),
        RotationVerdict::Reject
    );

    let rot: RotationStatement = serde_json::from_slice(&payload).unwrap();
    assert_eq!(
        rot.to_trust_root.id_hex().unwrap(),
        v["rotation"]["expect_new_trust_root_id"].as_str().unwrap()
    );
}

// ------------------------------------------------------------------ SPEC §9.2
#[test]
fn revocation_matches_vectors() {
    let v = vectors();
    let payload = h(&v["revocation"]["payload_utf8_hex"]);
    let bundle = h(&v["revocation"]["bundle_hex"]);
    let root = pinned_root(&v);
    let now = 1754500100u64;

    assert_eq!(
        verify_revocation(&payload, &bundle, &root, 0, now, SUPPORTED_ALGS),
        RevocationVerdict::Accept
    );

    let rev: RevocationStatement = serde_json::from_slice(&payload).unwrap();
    assert_eq!(
        rev.revoked_keys[0],
        v["revocation"]["revoked_key_id"].as_str().unwrap()
    );
}

// ------------------------------------------------------------------ SPEC §7
#[test]
fn nfc_normalization() {
    let v = vectors();
    let c = &v["paths"]["nfc"][0];
    let nfd = String::from_utf8(h(&c["input_nfd_hex"])).unwrap();
    let nfc = String::from_utf8(h(&c["expect_nfc_hex"])).unwrap();
    assert_ne!(
        nfd.as_bytes(),
        nfc.as_bytes(),
        "the vector must actually differ"
    );
    assert_eq!(to_nfc(&nfd), nfc);
    assert_eq!(request_key(&nfd).as_deref(), Some(nfc.as_str()));
}

/// Regression, found by running Tier 1 in a browser: `/` was treated as an illegal
/// path, so the worker blocked the home page of the site it was protecting.
#[test]
fn directory_style_urls_are_legal() {
    assert_eq!(request_key("/").as_deref(), Some("/"));
    assert_eq!(request_key("/blog/").as_deref(), Some("/blog/"));
    assert_eq!(request_key("/a/b/").as_deref(), Some("/a/b/"));

    // An interior empty component is still illegal — a server may collapse it and
    // serve something the manifest never described.
    assert!(request_key("/a//b.js").is_none());
    assert!(request_key("//a.js").is_none());

    assert_eq!(index_alias("/").as_deref(), Some("/index.html"));
    assert_eq!(index_alias("/blog/").as_deref(), Some("/blog/index.html"));
    assert_eq!(index_alias("/a.js"), None);
}

#[test]
fn scanned_paths_never_end_in_a_slash() {
    // A directory URL is a legal *request*, but a manifest lists files.
    assert!(manifest_key_from_relative("assets/").is_none());
    assert_eq!(
        manifest_key_from_relative("assets/app.js").as_deref(),
        Some("/assets/app.js")
    );
}

#[test]
fn path_rejections() {
    let v = vectors();
    for group in ["reject_before_decoding", "reject_after_canonicalization"] {
        for p in v["paths"][group].as_array().unwrap() {
            let p = p.as_str().unwrap();
            assert!(request_key(p).is_none(), "`{p}` must be rejected ({group})");
        }
    }
}

#[test]
fn manifest_lookup_finds_the_normalized_path() {
    let v = vectors();
    let payload = h(&v["manifest"]["payload_utf8_hex"]);
    let m: Manifest = serde_json::from_slice(&payload).unwrap();
    let nfc = String::from_utf8(h(&v["paths"]["nfc"][0]["expect_nfc_hex"])).unwrap();
    assert!(
        m.lookup(&nfc).is_some(),
        "binary search must find the NFC path"
    );
    assert!(m.lookup("/nope.js").is_none());
}

#[test]
fn content_type_equivalence() {
    let v = vectors();
    for (canonical, aliases) in v["content_type_equivalence"].as_object().unwrap() {
        for alias in aliases.as_array().unwrap() {
            assert!(
                content_type_matches(canonical, alias.as_str().unwrap()),
                "{canonical} should accept {alias}"
            );
        }
    }
    assert!(content_type_matches(
        "text/javascript",
        "text/javascript; charset=utf-8"
    ));
    assert!(!content_type_matches("application/wasm", "text/javascript"));
    assert!(!content_type_matches("text/css", "text/javascript"));

    // Regression: a `vite-ssg` build signs sitemap.xml as `application/xml` and
    // `vite preview` serves it as `text/xml`. Before these classes existed, Tier 1
    // called that BLOCK_TAMPER and refused a file nobody had touched.
    assert!(content_type_matches("application/xml", "text/xml"));
    assert!(content_type_matches(
        "application/yaml",
        "text/yaml; charset=utf-8"
    ));

    // Loosening the table must not let an executable type in through the side door.
    assert!(!content_type_matches("application/xml", "text/javascript"));
    assert!(!content_type_matches(
        "application/yaml",
        "application/json"
    ));
    assert!(!content_type_matches("application/xml", "application/yaml"));
}

// ------------------------------------------------------------------ signing side
/// Ed25519 is deterministic (RFC 8032), so signing the golden payload with the
/// golden seed must reproduce the golden signature exactly. This is the direction
/// the JS verifier cannot check: Rust signs, and the frozen vector confirms it.
#[test]
fn rust_signing_reproduces_the_golden_ed25519_signatures() {
    let v = vectors();
    let payload = h(&v["manifest"]["payload_utf8_hex"]);
    let expected = parse_bundle(&h(&v["manifest"]["cases"][0]["bundle_hex"])).unwrap();

    for i in 0..2 {
        let s = &v["signers"][i];
        let signer = SignerKeys::from_parts(
            &unhex_array::<32>(s["ed25519_seed"].as_str().unwrap()).unwrap(),
            &h(&s["p256_private_pkcs8"]),
        )
        .expect("signer loads");

        assert_eq!(
            hex::encode(signer.key_id()),
            s["key_id"].as_str().unwrap(),
            "signer {i} key_id"
        );
        assert_eq!(
            hex::encode(signer.p256_public()),
            s["p256_public_sec1_uncompressed"].as_str().unwrap(),
            "signer {i} must export an uncompressed SEC1 point"
        );

        let produced = signer.sign(PREFIX_MANIFEST, &payload);
        let ed = produced
            .iter()
            .find(|e| e.alg_id == SigAlg::Ed25519.alg_id())
            .unwrap();
        let golden = expected
            .iter()
            .find(|e| e.key_id == signer.key_id() && e.alg_id == SigAlg::Ed25519.alg_id())
            .expect("golden entry present");
        assert_eq!(ed.sig, golden.sig, "signer {i} ed25519 signature");
    }
}

/// P-256 signing is randomized, so the golden signature cannot be reproduced —
/// but a freshly produced one must verify, and must be the raw 64-byte form.
#[test]
fn rust_p256_signatures_are_raw_and_verify() {
    let v = vectors();
    let payload = h(&v["manifest"]["payload_utf8_hex"]);
    let s = &v["signers"][0];
    let signer = SignerKeys::from_parts(
        &unhex_array::<32>(s["ed25519_seed"].as_str().unwrap()).unwrap(),
        &h(&s["p256_private_pkcs8"]),
    )
    .unwrap();

    let entry = signer
        .sign(PREFIX_MANIFEST, &payload)
        .into_iter()
        .find(|e| e.alg_id == SigAlg::P256.alg_id())
        .unwrap();

    assert_eq!(entry.sig.len(), 64, "must be raw r||s, not DER");

    let mut msg = PREFIX_MANIFEST.to_vec();
    msg.extend_from_slice(&payload);
    assert!(verify_p256(&signer.p256_public(), &entry.sig, &msg));

    // And it must not verify under a different domain prefix.
    let mut wrong = PREFIX_ROTATION.to_vec();
    wrong.extend_from_slice(&payload);
    assert!(!verify_p256(&signer.p256_public(), &entry.sig, &wrong));
}

#[test]
fn generated_signers_produce_a_usable_trust_root() {
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
    root.validate().expect("generated root is valid");

    let payload = br#"{"spec":"veil-guard/1"}"#;
    let mut entries = Vec::new();
    for s in signers.iter().take(2) {
        entries.extend(s.sign(PREFIX_MANIFEST, payload));
    }
    let bundle = build_bundle(&entries);
    let parsed = parse_bundle(&bundle).expect("self-built bundle parses");

    assert_eq!(
        check_threshold(payload, &parsed, &root, PREFIX_MANIFEST, SUPPORTED_ALGS),
        ThresholdOutcome::Qualifying(2)
    );
    assert_eq!(
        check_threshold(payload, &parsed, &root, PREFIX_ROTATION, SUPPORTED_ALGS),
        ThresholdOutcome::Tampered,
        "the same signatures must not count under another domain prefix"
    );
}

#[test]
fn revocation_statement_verifies_and_rejects_replay() {
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
    root.validate().expect("generated root is valid");

    let revoked_key_id = root.keys[0].key_id.clone();
    let now = 1750000000u64;

    let statement = veil_guard::manifest::RevocationStatement {
        spec: veil_guard::manifest::SPEC_REVOCATION.into(),
        version: now,
        trust_root_id: root.id_hex().unwrap(),
        revoked_keys: vec![revoked_key_id],
        not_after: now + 86400 * 30,
        reason: Some("compromised key".into()),
    };
    let payload = serde_json::to_vec(&statement).unwrap();

    let mut entries = Vec::new();
    for s in signers.iter().take(2) {
        entries.extend(s.sign(PREFIX_REVOCATION, &payload));
    }
    let bundle = build_bundle(&entries);

    assert_eq!(
        veil_guard::manifest::verify_revocation(&payload, &bundle, &root, 0, now, SUPPORTED_ALGS),
        veil_guard::manifest::RevocationVerdict::Accept
    );

    // Replay at same version must reject.
    assert_eq!(
        veil_guard::manifest::verify_revocation(&payload, &bundle, &root, now, now, SUPPORTED_ALGS),
        veil_guard::manifest::RevocationVerdict::Reject
    );

    // Expired timestamp must reject.
    assert_eq!(
        veil_guard::manifest::verify_revocation(
            &payload,
            &bundle,
            &root,
            0,
            now + 86400 * 31,
            SUPPORTED_ALGS
        ),
        veil_guard::manifest::RevocationVerdict::Reject
    );

    // Verify manifest threshold drop when keys are revoked below threshold.
    let m_payload = br#"{"spec":"veil-guard/1"}"#;
    let m_state = veil_guard::manifest::verify_manifest_with_revocation(
        m_payload,
        &bundle,
        &root,
        0,
        now,
        SUPPORTED_ALGS,
        &[root.keys[0].key_id.clone(), root.keys[1].key_id.clone()],
    );
    assert_eq!(
        m_state,
        veil_guard::manifest::ManifestState::UntrustedRoot,
        "revoking keys below threshold must evaluate to UntrustedRoot"
    );
}
