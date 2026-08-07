//! veil-guard CLI.
//!
//! Step 1 of the roadmap ships the key and rotation engine. `sign` and `verify`
//! arrive with the asset scanner and generators in Step 2; they are deliberately
//! absent rather than present and half-working.

use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};

use veil_guard::crypto::{
    build_bundle, SigAlg, SignerKeys, TrustRoot, TrustedKey, PREFIX_MANIFEST, PREFIX_ROTATION,
    SUPPORTED_ALGS,
};
use veil_guard::manifest::{
    verify_manifest, verify_rotation, AssetEntry, Manifest, ManifestState, RotationStatement,
    RotationVerdict, Scope, SPEC_MANIFEST, SPEC_ROTATION,
};

#[derive(Parser)]
#[command(name = "veil-guard", version, about = "Web asset integrity and attestation")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate one signer identity (an Ed25519 keypair and a P-256 keypair)
    Keygen {
        /// Directory to write the key file into
        #[arg(short, long, default_value = ".keys")]
        out_dir: PathBuf,
        /// Identity name, used for the filename
        #[arg(short, long)]
        name: String,
        /// Advisory role: a `recovery` key must never live on a build machine
        #[arg(short, long, default_value = "build", value_parser = ["build", "recovery"])]
        role: String,
    },

    /// Assemble a trust root from signer key files
    TrustRoot {
        /// Signer key files (private or public); repeat the flag per signer
        #[arg(short, long = "key", required = true)]
        keys: Vec<PathBuf>,
        /// Signatures required to accept a manifest
        #[arg(short, long, default_value_t = 2)]
        threshold: u8,
        #[arg(short, long, default_value = "trust-root.json")]
        out: PathBuf,
    },

    /// Sign a build: inject SRI, hash every asset, emit a threshold-signed manifest
    ///
    /// This rewrites the HTML files in `--dist` in place, adding `integrity`
    /// attributes. Run it against a build directory, never against sources.
    Sign {
        #[arg(short, long)]
        dist: PathBuf,
        /// Trust root the manifest will declare
        #[arg(long)]
        trust_root: PathBuf,
        /// Private key files, enough of them to meet the trust root's threshold
        #[arg(short, long = "key", required = true)]
        keys: Vec<PathBuf>,
        /// Override the version (defaults to SOURCE_DATE_EPOCH, else the clock)
        #[arg(long)]
        version: Option<u64>,
        /// Validity window; expiry is a soft warning, never a tamper alert
        #[arg(long, default_value_t = 180)]
        not_after_days: u64,
        /// Skip SRI injection and leave the HTML untouched
        #[arg(long)]
        no_sri: bool,
        /// Directory to write server header snippets into
        #[arg(long)]
        headers_out: Option<PathBuf>,
        /// Recorded in the manifest as a claim by the signer, not as proof
        #[arg(long)]
        source_commit: Option<String>,
    },

    /// Check a build directory against its signed manifest
    Verify {
        #[arg(short, long)]
        dist: PathBuf,
        /// Trust root to verify against. Must come from out of band — never from
        /// the deployment being checked.
        #[arg(long)]
        trust_root: PathBuf,
        /// Reject a manifest older than this version
        #[arg(long, default_value_t = 0)]
        pinned_version: u64,
    },

    /// Produce a rotation statement moving the pin from one trust root to another
    Rotate {
        #[arg(long)]
        from: PathBuf,
        #[arg(long)]
        to: PathBuf,
        /// Private key files of the OLD root, enough of them to meet its threshold
        #[arg(short, long = "key", required = true)]
        keys: Vec<PathBuf>,
        #[arg(short, long, default_value = "veil-guard-rotation.json")]
        out: PathBuf,
        /// Override the statement version (defaults to the current Unix time)
        #[arg(long)]
        version: Option<u64>,
    },
}

/// On-disk signer identity.
///
/// NOTE: written unencrypted with mode 0600. Passphrase encryption is not
/// implemented yet — do not put a `recovery` key on a machine where that matters.
#[derive(serde::Serialize, serde::Deserialize)]
struct KeyFile {
    spec: String,
    role: String,
    key_id: String,
    ed25519_public: String,
    p256_public: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ed25519_seed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p256_private_pkcs8: Option<String>,
}

impl Drop for KeyFile {
    /// The private halves sit in this struct as plain hex `String`s once a key file
    /// has been read, so they are cleared rather than left in freed heap memory.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(s) = self.ed25519_seed.as_mut() {
            s.zeroize();
        }
        if let Some(s) = self.p256_private_pkcs8.as_mut() {
            s.zeroize();
        }
    }
}

impl KeyFile {
    fn trusted_key(&self) -> TrustedKey {
        TrustedKey {
            key_id: self.key_id.clone(),
            role: self.role.clone(),
            ed25519: self.ed25519_public.clone(),
            p256: self.p256_public.clone(),
        }
    }

    fn signer(&self) -> Result<SignerKeys, Box<dyn std::error::Error>> {
        let seed = self
            .ed25519_seed
            .as_ref()
            .ok_or("key file has no private material")?;
        let pkcs8 = self
            .p256_private_pkcs8
            .as_ref()
            .ok_or("key file has no private material")?;
        Ok(SignerKeys::from_parts(
            &veil_guard::crypto::unhex_array::<32>(seed)?,
            &veil_guard::crypto::unhex(pkcs8)?,
        )?)
    }
}

fn read_key_file(path: &Path) -> Result<KeyFile, Box<dyn std::error::Error>> {
    let kf: KeyFile = serde_json::from_slice(&fs::read(path)?)?;
    if kf.spec != "veil-guard/key/1" {
        return Err(format!("{}: unrecognized key file spec {}", path.display(), kf.spec).into());
    }
    Ok(kf)
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Commands::Keygen { out_dir, name, role } => {
            fs::create_dir_all(&out_dir)?;
            let signer = SignerKeys::generate();
            let kf = KeyFile {
                spec: "veil-guard/key/1".into(),
                role: role.clone(),
                key_id: hex::encode(signer.key_id()),
                ed25519_public: hex::encode(signer.ed25519_public()),
                p256_public: hex::encode(signer.p256_public()),
                ed25519_seed: Some(hex::encode(signer.ed25519_seed())),
                p256_private_pkcs8: Some(hex::encode(signer.p256_pkcs8_der()?)),
            };

            let priv_path = out_dir.join(format!("{name}.key.json"));
            write_private(&priv_path, serde_json::to_string_pretty(&kf)?.as_bytes())?;

            // Built field by field rather than with `..kf`: KeyFile implements Drop
            // so that its secrets get zeroized, and Drop types cannot be moved out of.
            let pub_kf = KeyFile {
                spec: kf.spec.clone(),
                role: kf.role.clone(),
                key_id: kf.key_id.clone(),
                ed25519_public: kf.ed25519_public.clone(),
                p256_public: kf.p256_public.clone(),
                ed25519_seed: None,
                p256_private_pkcs8: None,
            };
            let pub_path = out_dir.join(format!("{name}.pub.json"));
            fs::write(&pub_path, serde_json::to_string_pretty(&pub_kf)? + "\n")?;

            println!("signer   {}  ({role})", pub_kf.key_id);
            println!("private  {}  (mode 0600, UNENCRYPTED)", priv_path.display());
            println!("public   {}", pub_path.display());
            if role == "recovery" {
                println!("\nThis is a recovery key. It must not be stored on a build machine");
                println!("or in CI — its whole purpose is to survive their compromise.");
            }
        }

        Commands::TrustRoot { keys, threshold, out } => {
            let mut trusted: Vec<TrustedKey> = keys
                .iter()
                .map(|p| read_key_file(p).map(|k| k.trusted_key()))
                .collect::<Result<_, _>>()?;
            // SPEC §4.4: sorted by key_id, and the ID derivation depends on it.
            trusted.sort_by(|a, b| a.key_id.cmp(&b.key_id));

            let root = TrustRoot {
                threshold,
                sigalgs: vec![SigAlg::Ed25519, SigAlg::P256],
                keys: trusted,
            };
            root.validate()?;

            fs::write(&out, serde_json::to_string_pretty(&root)? + "\n")?;
            println!("trust root   {}", out.display());
            println!("id           {}", root.id_hex()?);
            println!("policy       {}-of-{}", root.threshold, root.keys.len());
            for k in &root.keys {
                println!("  {}  {}", k.key_id, k.role);
            }
        }

        Commands::Sign {
            dist,
            trust_root,
            keys,
            version,
            not_after_days,
            no_sri,
            headers_out,
            source_commit,
        } => {
            let root: TrustRoot = serde_json::from_slice(&fs::read(&trust_root)?)?;
            root.validate()?;

            // SPEC §10 step 1–2.
            let mut assets = veil_guard::scanner::scan_dist(&dist)?;
            println!("scanned      {} assets in {}", assets.len(), dist.display());

            // SPEC §10 steps 3–5. HTML is rewritten first, then re-hashed, because
            // the manifest hashes the files that actually ship.
            let mut pages = Vec::new();
            if !no_sri {
                let digests: std::collections::HashMap<String, String> = assets
                    .iter()
                    .filter(|a| !a.is_html())
                    .map(|a| (a.key.clone(), a.sha384.clone()))
                    .collect();

                let html_keys: Vec<String> =
                    assets.iter().filter(|a| a.is_html()).map(|a| a.key.clone()).collect();

                let mut applied = 0usize;
                let mut cross_origin: Vec<String> = Vec::new();
                let mut unresolved: Vec<String> = Vec::new();

                for key in &html_keys {
                    let idx = assets.iter().position(|a| &a.key == key).expect("present");
                    let original = fs::read(&assets[idx].abs)?;
                    let (rewritten, report) =
                        veil_guard::generators::inject_sri(&original, key, &digests)?;

                    applied += report.applied.len();
                    cross_origin.extend(report.cross_origin);
                    unresolved.extend(report.unresolved);

                    if rewritten != original {
                        fs::write(&assets[idx].abs, &rewritten)?;
                    }
                    veil_guard::scanner::rehash(&mut assets[idx], &rewritten);

                    // SPEC §10 step 6: hashed from the post-splice bytes.
                    let hashes = veil_guard::generators::inline_script_hashes(&rewritten)?;
                    pages.push(veil_guard::generators::PageHeaders {
                        path: key.clone(),
                        csp: veil_guard::generators::csp_script_src(&hashes),
                    });
                }

                println!("sri          {applied} integrity attributes across {} pages", html_keys.len());
                cross_origin.sort();
                cross_origin.dedup();
                if !cross_origin.is_empty() {
                    println!("\ncross-origin subresources — SRI cannot cover these, CSP must:");
                    for u in &cross_origin {
                        println!("  {u}");
                    }
                }
                unresolved.sort();
                unresolved.dedup();
                if !unresolved.is_empty() {
                    println!("\nreferenced but not found in dist:");
                    for u in &unresolved {
                        println!("  {u}");
                    }
                }
            }

            // SPEC §6.5: SOURCE_DATE_EPOCH makes the output reproducible.
            let version = version
                .or_else(|| std::env::var("SOURCE_DATE_EPOCH").ok()?.parse().ok())
                .unwrap_or_else(now_unix);

            let manifest = Manifest {
                spec: SPEC_MANIFEST.into(),
                version,
                not_after: version + not_after_days * 86_400,
                sigalgs: root.sigalgs.clone(),
                trust_root_id: root.id_hex()?,
                trust_root: root.clone(),
                scope: Scope { include: vec!["/".into()], exclude: vec![] },
                source: serde_json::json!({
                    "commit": source_commit.unwrap_or_default(),
                    "toolchain": { "veil_guard": env!("CARGO_PKG_VERSION") },
                }),
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

            let payload = (serde_json::to_string_pretty(&manifest)? + "\n").into_bytes();
            let mut entries = Vec::new();
            for path in &keys {
                entries.extend(read_key_file(path)?.signer()?.sign(PREFIX_MANIFEST, &payload));
            }
            let bundle = build_bundle(&entries);

            // Refuse to ship a manifest this build would itself reject.
            let state = verify_manifest(&payload, &bundle, &root, 0, version, SUPPORTED_ALGS);
            if state != ManifestState::Valid {
                return Err(format!(
                    "refusing to write a manifest that verifies as {}: {} signer(s) supplied, \
                     trust root needs {}",
                    state.as_str(),
                    keys.len(),
                    root.threshold
                )
                .into());
            }

            let manifest_path = dist.join("veil-guard-manifest.json");
            fs::write(&manifest_path, &payload)?;
            fs::write(dist.join("veil-guard-manifest.sig"), &bundle)?;

            println!("\nmanifest     {}", manifest_path.display());
            println!("version      {version}");
            println!("trust root   {}  ({}-of-{})", manifest.trust_root_id, root.threshold, root.keys.len());
            println!("signers      {}", keys.len());

            if let Some(dir) = headers_out {
                fs::create_dir_all(&dir)?;
                use veil_guard::generators::{headers_caddy, headers_netlify, headers_nginx};
                fs::write(dir.join("_headers"), headers_netlify(&pages, false))?;
                fs::write(dir.join("veil-guard.nginx.conf"), headers_nginx(&pages, false))?;
                fs::write(dir.join("veil-guard.Caddyfile"), headers_caddy(&pages, false))?;
                println!("headers      {} (report-only; flip to enforcing once clean)", dir.display());
            }
        }

        Commands::Verify { dist, trust_root, pinned_version } => {
            let root: TrustRoot = serde_json::from_slice(&fs::read(&trust_root)?)?;
            root.validate()?;

            let payload = fs::read(dist.join("veil-guard-manifest.json"))?;
            let bundle = fs::read(dist.join("veil-guard-manifest.sig"))?;

            let state =
                verify_manifest(&payload, &bundle, &root, pinned_version, now_unix(), SUPPORTED_ALGS);
            println!("signature    {}", state.as_str());
            if state.is_hard_failure() {
                return Err(format!("manifest verification failed: {}", state.as_str()).into());
            }

            let manifest: Manifest = serde_json::from_slice(&payload)?;
            let on_disk = veil_guard::scanner::scan_dist(&dist)?;

            let mut mismatched = Vec::new();
            let mut missing = Vec::new();
            for entry in &manifest.assets {
                match on_disk.iter().find(|a| a.key == entry.path) {
                    None => missing.push(entry.path.clone()),
                    Some(a) if a.sha256 != entry.sha256 => mismatched.push(entry.path.clone()),
                    Some(_) => {}
                }
            }
            // The interesting signal: files the server would serve that nothing signed.
            let unmanifested: Vec<&str> = on_disk
                .iter()
                .filter(|a| manifest.lookup(&a.key).is_none())
                .map(|a| a.key.as_str())
                .collect();

            println!("assets       {} in manifest, {} on disk", manifest.assets.len(), on_disk.len());
            for p in &mismatched {
                println!("  TAMPERED   {p}");
            }
            for p in &missing {
                println!("  MISSING    {p}");
            }
            for p in &unmanifested {
                println!("  UNSIGNED   {p}");
            }

            if mismatched.is_empty() && missing.is_empty() && unmanifested.is_empty() {
                println!("\nall {} assets match the signed manifest", manifest.assets.len());
            } else {
                return Err(format!(
                    "{} tampered, {} missing, {} unsigned",
                    mismatched.len(),
                    missing.len(),
                    unmanifested.len()
                )
                .into());
            }
        }

        Commands::Rotate { from, to, keys, out, version } => {
            let old: TrustRoot = serde_json::from_slice(&fs::read(&from)?)?;
            let new: TrustRoot = serde_json::from_slice(&fs::read(&to)?)?;
            old.validate()?;
            new.validate()?;

            let statement = RotationStatement {
                spec: SPEC_ROTATION.into(),
                version: version.unwrap_or_else(now_unix),
                from_trust_root_id: old.id_hex()?,
                to_trust_root: new.clone(),
            };
            let payload = (serde_json::to_string_pretty(&statement)? + "\n").into_bytes();

            let mut entries = Vec::new();
            for path in &keys {
                entries.extend(read_key_file(path)?.signer()?.sign(PREFIX_ROTATION, &payload));
            }
            let bundle = build_bundle(&entries);

            // Refuse to emit a statement that would not be accepted. Discovering a
            // short quorum here beats discovering it once clients are pinned.
            if verify_rotation(&payload, &bundle, &old, 0, SUPPORTED_ALGS) != RotationVerdict::Accept
            {
                return Err(format!(
                    "rotation would be rejected: {} signer(s) supplied, old root needs {}",
                    keys.len(),
                    old.threshold
                )
                .into());
            }

            fs::write(&out, &payload)?;
            let sig_path = out.with_extension("sig");
            fs::write(&sig_path, &bundle)?;

            println!("rotation     {}", out.display());
            println!("signatures   {}", sig_path.display());
            println!("from         {}", statement.from_trust_root_id);
            println!("to           {}", new.id_hex()?);
            println!("version      {}", statement.version);
            println!("\nThis statement only moves clients that already trust the OLD root.");
            println!("It is not a revocation: see SPEC.md §9.2.");
        }
    }
    Ok(())
}
