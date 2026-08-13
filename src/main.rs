//! veil-guard CLI.
//!
//! Three verifiers share one protocol: this binary at build time, this binary
//! again over the network (`audit`, behind the `audit` feature), and the Service
//! Worker that `runtime` emits. `SPEC.md` is normative for all three.
//!
//! The commands here are ordered the way a deployment uses them: `keygen` and
//! `trust-root` once, `runtime` whenever the trust root changes, `sign` on every
//! build, `verify` and `audit` after, `rotate` when a key moves.

use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};

use veil_guard::crypto::{
    build_bundle, SigAlg, SigEntry, SignerKeys, TrustRoot, TrustedKey, PREFIX_MANIFEST,
    PREFIX_REVOCATION, PREFIX_ROTATION, SUPPORTED_ALGS,
};
use veil_guard::manifest::{
    verify_manifest, verify_manifest_with_revocation, verify_revocation, verify_rotation,
    AssetEntry, Manifest, ManifestState, RevocationStatement, RevocationVerdict, RotationStatement,
    RotationVerdict, Scope, SPEC_MANIFEST, SPEC_REVOCATION, SPEC_ROTATION,
};

#[derive(Parser)]
#[command(
    name = "veil-guard",
    version,
    about = "Web asset integrity and attestation"
)]
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

        /// Build a signer whose P-256 half stays in a KMS (SPEC §4.6).
        ///
        /// Takes the public key as DER SubjectPublicKeyInfo — what both clouds
        /// hand back. No P-256 private key is written, and `sign` will delegate
        /// this signer's P-256 signature to `--kms-key-id`, which becomes
        /// required alongside this flag.
        ///
        ///   aws kms get-public-key --key-id "$ARN" \
        ///     --query PublicKey --output text | base64 -d > p256.der
        ///
        ///   gcloud kms keys versions get-public-key 1 --key … --output-file p256.pem
        ///   openssl ec -pubin -in p256.pem -outform DER -out p256.der
        #[arg(long, value_name = "PATH")]
        p256_public_der: Option<PathBuf>,

        /// KMS key this signer's P-256 half lives in; recorded in the key file
        #[arg(long, requires = "p256_public_der")]
        kms_key_id: Option<String>,

        /// Provider for `--kms-key-id`; inferred from the key ID when omitted
        #[arg(long, value_parser = ["aws", "gcp"], requires = "kms_key_id")]
        kms_provider: Option<String>,

        /// Address of HashiCorp Vault server for remote Ed25519 signing (SPEC §4.6)
        #[arg(long)]
        vault_addr: Option<String>,

        /// Key name in HashiCorp Vault transit engine
        #[arg(long, requires = "vault_addr")]
        vault_key_name: Option<String>,

        /// Hex-encoded 32-byte Ed25519 public key (required if --vault-addr is used)
        #[arg(long, requires = "vault_addr")]
        ed25519_public_hex: Option<String>,
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
        /// Emit an enforcing Integrity-Policy instead of report-only. Flip this
        /// only once `veil-guard audit` reports no missing-integrity findings.
        #[arg(long)]
        enforce_headers: bool,
        /// Recorded in the manifest as a claim by the signer, not as proof
        #[arg(long)]
        source_commit: Option<String>,
        /// Let the worker resolve `/faq` against the signed `/faq.html` (SPEC §7.1.1).
        ///
        /// Without this, a navigation to a path with no file of that exact name
        /// matches nothing and is passed through unverified — which is most pages of
        /// a static site generator that emits flat `.html` files. Turn it on only if
        /// the host really does serve `/faq` from `faq.html`: under a single-page-app
        /// fallback the host answers with `index.html`, and the worker would then
        /// compare those bytes against `faq.html` and block a healthy deployment.
        #[arg(long)]
        navigation_html_fallback: bool,

        /// Extra `script-src` source to allow, beyond `'self'` and this page's own
        /// inline-script hashes; repeat per source.
        ///
        /// A build directory cannot reveal that an inline bootstrap will inject a
        /// script from a third-party host — a tag manager is exactly this shape — so
        /// those hosts have to be named. Each one widens the policy:
        /// `--csp-source https://www.googletagmanager.com`.
        #[arg(long = "csp-source")]
        csp_sources: Vec<String>,

        /// Path prefix the Service Worker must leave alone; repeat per prefix.
        ///
        /// Everything same-origin is an allowlist, so any path the app requests
        /// that is not a signed file is refused. Dynamic endpoints have no file to
        /// sign, and so must be carved out here: `--exclude /api/`.
        #[arg(long = "exclude")]
        excludes: Vec<String>,

        /// Path to a JSON file containing SLSA provenance metadata to embed inside manifest source
        #[arg(long)]
        provenance_json: Option<PathBuf>,

        /// AWS KMS Key ARN or GCP Key Resource ID for P-256 signing
        #[arg(long)]
        kms_key_id: Option<String>,

        /// KMS provider to use
        #[arg(long, value_parser = ["aws", "gcp"])]
        kms_provider: Option<String>,

        /// Upload manifest hash and signature to Sigstore Rekor transparency log
        #[arg(long)]
        rekor_upload: bool,

        /// Rekor log server URL
        #[arg(long, default_value = "https://rekor.sigstore.dev")]
        rekor_url: String,
    },

    /// Emit the Tier 1 runtime with a trust root baked in
    ///
    /// Writes a self-contained Service Worker and the page-side loader. Run this
    /// into the directory your build tool copies verbatim (`public/` for Vite), so
    /// that the worker ends up at the site root and can claim the whole scope.
    Runtime {
        #[arg(long)]
        trust_root: PathBuf,
        #[arg(short, long, default_value = "public")]
        out: PathBuf,
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

    /// Audit a live deployment from outside it
    ///
    /// The trust root is read from a local file and never from the audited site;
    /// that is the whole point of this command.
    #[cfg(feature = "audit")]
    Audit {
        /// Base URL of the deployment, e.g. https://app.example.com
        #[arg(short, long)]
        url: String,
        /// Local trust root. Must have reached this machine out of band.
        #[arg(long)]
        trust_root: PathBuf,
        /// Vantage-point label recorded in the snapshot, e.g. `eu-west`
        #[arg(long)]
        label: Option<String>,
        /// Reject a manifest older than this version
        #[arg(long, default_value_t = 0)]
        pinned_version: u64,
        /// Only walk the served HTML graph; do not re-download every asset
        #[arg(long)]
        graph_only: bool,
        /// Lowest severity that makes the command exit non-zero
        #[arg(long, default_value = "warning", value_parser = ["critical", "warning", "info"])]
        fail_on: String,
        /// Write the snapshot here, for later `veil-guard diff`
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Print the snapshot as JSON on stdout
        #[arg(long)]
        json: bool,
        /// Verify Rekor transparency log inclusion proof if present in manifest source
        #[arg(long)]
        rekor_verify: bool,
        /// Rekor log server URL
        #[arg(long, default_value = "https://rekor.sigstore.dev")]
        rekor_url: String,
        /// Automatically push snapshot to relay server URL after audit completes
        #[arg(long)]
        relay_push: Option<String>,
        /// Bearer token for relay push
        #[arg(long, env = "VEIL_RELAY_TOKEN")]
        relay_token: Option<String>,
    },

    /// Manage third-party audit relay: push or pull snapshots across vantage points
    #[cfg(feature = "relay-client")]
    Relay {
        #[command(subcommand)]
        action: RelayAction,
    },

    /// Compare two audit snapshots
    ///
    /// Divergence between vantage points is the only signal that reveals a bundle
    /// served to some visitors and not others.
    #[cfg(feature = "audit")]
    Diff {
        left: PathBuf,
        right: PathBuf,
        #[arg(long)]
        json: bool,
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

    /// Produce a revocation statement marking specific keys in a trust root as revoked
    Revoke {
        /// Trust root to target
        #[arg(long)]
        trust_root: PathBuf,
        /// 16-hex key_ids to revoke
        #[arg(long = "revoke-key", required = true)]
        revoked_keys: Vec<String>,
        /// Private key files of remaining non-revoked signers, enough to meet the root's threshold
        #[arg(short, long = "key", required = true)]
        keys: Vec<PathBuf>,
        #[arg(short, long, default_value = "veil-guard-revocation.json")]
        out: PathBuf,
        /// Override the statement version (defaults to current Unix time)
        #[arg(long)]
        version: Option<u64>,
        /// Validity period in days (defaults to 365)
        #[arg(long, default_value_t = 365)]
        not_after_days: u64,
        /// Optional reason for revocation
        #[arg(long)]
        reason: Option<String>,
    },
}

#[cfg(feature = "relay-client")]
#[derive(clap::Subcommand, Debug)]
pub enum RelayAction {
    /// Push an audit snapshot to a relay server
    Push {
        /// Local snapshot JSON file to push
        #[arg(short, long)]
        snapshot: PathBuf,
        /// Relay server URL
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        relay_url: String,
        /// Bearer authentication token
        #[arg(long, env = "VEIL_RELAY_TOKEN")]
        token: Option<String>,
    },
    /// Pull snapshots for a domain from a relay server
    Pull {
        /// Audited domain name (e.g. app.example.com)
        #[arg(short, long)]
        domain: String,
        /// Relay server URL
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        relay_url: String,
        /// Output directory to write fetched snapshot JSON files into
        #[arg(short, long, default_value = "relay-snapshots")]
        out_dir: PathBuf,
        /// Filter snapshots created after this Unix timestamp
        #[arg(long)]
        since: Option<u64>,
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
    /// Where this signer's P-256 half lives, when it is not in this file.
    ///
    /// Recorded per signer rather than passed on the command line, because a
    /// threshold needs several signers and each has its own key in the service.
    /// A single global `--kms-key-id` would sign every remote signer's entry with
    /// one key, producing a bundle that fails its own verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    kms_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kms_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vault_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vault_key_name: Option<String>,
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

    fn sign(
        &self,
        prefix: &[u8],
        payload: &[u8],
        kms_key_id: Option<&str>,
        kms_provider: Option<&str>,
    ) -> Result<Vec<SigEntry>, Box<dyn std::error::Error>> {
        use ed25519_dalek::Signer as _;

        let mut msg = Vec::with_capacity(prefix.len() + payload.len());
        msg.extend_from_slice(prefix);
        msg.extend_from_slice(payload);

        let mut entries = Vec::new();
        let key_id_bytes = veil_guard::crypto::unhex_array::<8>(&self.key_id)?;

        // 1. Ed25519 signature
        if self.ed25519_seed.is_some() && self.vault_key_name.is_some() {
            return Err(format!(
                "signer {} has both a local Ed25519 seed and a vault_key_name; \
                 remove one — as written, the local key would be used and Vault ignored",
                self.key_id
            )
            .into());
        }

        if let Some(seed) = &self.ed25519_seed {
            let seed_bytes = veil_guard::crypto::unhex_array::<32>(seed)?;
            let ed_signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);
            let ed_sig = ed_signing_key.sign(&msg);
            entries.push(SigEntry {
                key_id: key_id_bytes,
                alg_id: SigAlg::Ed25519.alg_id(),
                sig: ed_sig.to_bytes().to_vec(),
            });
        } else if let Some(v_key) = &self.vault_key_name {
            let v_addr = self.vault_addr.as_deref().ok_or_else(|| {
                format!(
                    "signer {} has vault_key_name but missing vault_addr",
                    self.key_id
                )
            })?;
            let sig_bytes = sign_with_vault(&msg, v_addr, v_key)?;
            entries.push(SigEntry {
                key_id: key_id_bytes,
                alg_id: SigAlg::Ed25519.alg_id(),
                sig: sig_bytes,
            });
        } else {
            return Err(format!(
                "signer {} has no Ed25519 private seed and no Vault key to sign with.",
                self.key_id
            )
            .into());
        }

        // 2. P-256 signature
        //
        // Both at once is a hand-edited file, and it would sign locally while its
        // author believed the key never left the KMS. Refuse rather than pick.
        if self.p256_private_pkcs8.is_some() && self.kms_key_id.is_some() {
            return Err(format!(
                "signer {} has both a local P-256 private key and a kms_key_id; \
                 remove one — as written, the local key would be used and the KMS ignored",
                self.key_id
            )
            .into());
        }

        if let Some(pkcs8_hex) = &self.p256_private_pkcs8 {
            use p256::pkcs8::DecodePrivateKey as _;
            let pkcs8_bytes = veil_guard::crypto::unhex(pkcs8_hex)?;
            let p256_signing_key = p256::ecdsa::SigningKey::from_pkcs8_der(&pkcs8_bytes)?;
            let p_sig: p256::ecdsa::Signature = p256_signing_key.sign(&msg);
            entries.push(SigEntry {
                key_id: key_id_bytes,
                alg_id: SigAlg::P256.alg_id(),
                sig: p_sig.to_bytes().to_vec(),
            });
        } else {
            // The key file wins over the command line. With several remote signers
            // there is one KMS key each, and a single global flag could only ever
            // be right for one of them.
            let kms_id = self.kms_key_id.as_deref().or(kms_key_id).ok_or_else(|| {
                format!(
                    "signer {} has no P-256 private key and no KMS key to sign with. \
                         Regenerate it with `keygen --p256-public-der … --kms-key-id …`, \
                         or pass --kms-key-id for this one signer.",
                    self.key_id
                )
            })?;
            let provider = self.kms_provider.as_deref().or(kms_provider);
            let sig_bytes = sign_with_kms(&msg, kms_id, provider)?;
            entries.push(SigEntry {
                key_id: key_id_bytes,
                alg_id: SigAlg::P256.alg_id(),
                sig: sig_bytes,
            });
        }

        Ok(entries)
    }
}

/// Read a P-256 public key from a DER SubjectPublicKeyInfo file.
///
/// SPKI is what `aws kms get-public-key` and `gcloud kms … get-public-key` return,
/// and it is not what goes into a trust root: SPEC §2.1 wants the 65-byte
/// uncompressed SEC1 point, and rejects everything else. Converting here means the
/// operator never has to.
fn read_p256_public_der(path: &Path) -> Result<[u8; 65], Box<dyn std::error::Error>> {
    use p256::elliptic_curve::sec1::ToEncodedPoint as _;
    use p256::pkcs8::DecodePublicKey as _;

    let bytes = fs::read(path)?;
    if bytes.starts_with(b"-----BEGIN") {
        return Err(format!(
            "{} is PEM, not DER. Convert it first:\n  \
             openssl ec -pubin -in {} -outform DER -out p256.der",
            path.display(),
            path.display()
        )
        .into());
    }

    let key = p256::PublicKey::from_public_key_der(&bytes).map_err(|e| {
        format!(
            "{} is not a P-256 SubjectPublicKeyInfo: {e}",
            path.display()
        )
    })?;
    let point = key.to_encoded_point(false);
    point
        .as_bytes()
        .try_into()
        .map_err(|_| "public key did not encode to a 65-byte uncompressed point".into())
}

fn sign_with_kms(
    _msg: &[u8],
    _kms_key_id: &str,
    _kms_provider: Option<&str>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    #[cfg(feature = "kms")]
    {
        veil_guard::kms::sign_with_kms(_msg, _kms_key_id, _kms_provider)
    }
    #[cfg(not(feature = "kms"))]
    {
        Err("KMS support is disabled. Rebuild with --features kms to enable.".into())
    }
}

fn sign_with_vault(
    _msg: &[u8],
    _vault_addr: &str,
    _vault_key_name: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    #[cfg(feature = "vault")]
    {
        veil_guard::vault::sign_vault_transit(_msg, _vault_addr, _vault_key_name, None)
    }
    #[cfg(not(feature = "vault"))]
    {
        Err("Vault support is disabled. Rebuild with --features vault to enable.".into())
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
        Commands::Keygen {
            out_dir,
            name,
            role,
            p256_public_der,
            kms_key_id,
            kms_provider,
            vault_addr,
            vault_key_name,
            ed25519_public_hex,
        } => {
            fs::create_dir_all(&out_dir)?;

            let signer = SignerKeys::generate();

            let (ed_public, ed_seed) = match &vault_addr {
                Some(_v_addr) => {
                    let _v_key = vault_key_name
                        .clone()
                        .ok_or("--vault-addr requires --vault-key-name")?;
                    let hex_str = ed25519_public_hex.as_ref().ok_or(
                        "--vault-addr requires --ed25519-public-hex (32-byte hex Ed25519 public key)",
                    )?;
                    let pub_bytes = veil_guard::crypto::unhex_array::<32>(hex_str)?;
                    (pub_bytes, None)
                }
                None => (
                    signer.ed25519_public(),
                    Some(hex::encode(signer.ed25519_seed())),
                ),
            };

            let (p256_public, p256_priv_pkcs8, kms_id, kms_prov) = match &p256_public_der {
                None => (
                    signer.p256_public(),
                    Some(hex::encode(signer.p256_pkcs8_der()?)),
                    None,
                    None,
                ),
                Some(der_path) => {
                    let kms_id = kms_key_id
                        .clone()
                        .ok_or("--p256-public-der needs --kms-key-id: without it nothing can sign this signer's P-256 half")?;
                    let p256_pub = read_p256_public_der(der_path)?;
                    (p256_pub, None, Some(kms_id), kms_provider.clone())
                }
            };

            let key_id = veil_guard::crypto::key_id(&ed_public, &p256_public);

            let kf = KeyFile {
                spec: "veil-guard/key/1".into(),
                role: role.clone(),
                key_id: hex::encode(key_id),
                ed25519_public: hex::encode(ed_public),
                p256_public: hex::encode(p256_public),
                ed25519_seed: ed_seed,
                p256_private_pkcs8: p256_priv_pkcs8,
                kms_key_id: kms_id,
                kms_provider: kms_prov,
                vault_addr: vault_addr.clone(),
                vault_key_name: vault_key_name.clone(),
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
                // Not secret, and the trust root is assembled from these files —
                // carrying it through keeps a remote signer recognisable there.
                kms_key_id: kf.kms_key_id.clone(),
                kms_provider: kf.kms_provider.clone(),
                vault_addr: kf.vault_addr.clone(),
                vault_key_name: kf.vault_key_name.clone(),
            };
            let pub_path = out_dir.join(format!("{name}.pub.json"));
            fs::write(&pub_path, serde_json::to_string_pretty(&pub_kf)? + "\n")?;

            println!("signer   {}  ({role})", pub_kf.key_id);
            if let Some(id) = &kf.kms_key_id {
                println!("p256     remote — {id}");
            }
            if let Some(key) = &kf.vault_key_name {
                println!("ed25519  remote — Vault key {key}");
            }
            println!("private  {}", priv_path.display());
            println!("public   {}", pub_path.display());

            if kf.kms_key_id.is_some() {
                println!("\nThe P-256 half of this signer never existed on this machine. The");
                println!("Ed25519 half did, and still sits in the file above — SPEC.md §4.6");
                println!("calls that partial custody, not the finished article.");
            }
            if role == "recovery" {
                println!("\nThis is a recovery key, and it has just been written to this disk");
                println!("unencrypted. SPEC.md §4.6 says it MUST NOT stay there: its whole");
                println!("purpose is to survive the compromise of the machines that hold the");
                println!("build keys, which it cannot do while sitting next to them.");
                println!("\nMove both files to offline media and delete them here.");
            }
        }

        Commands::TrustRoot {
            keys,
            threshold,
            out,
        } => {
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
            enforce_headers,
            source_commit,
            navigation_html_fallback,
            csp_sources,
            excludes,
            provenance_json,
            kms_key_id,
            kms_provider,
            rekor_upload,
            rekor_url,
        } => {
            let root: TrustRoot = serde_json::from_slice(&fs::read(&trust_root)?)?;
            root.validate()?;
            let _ = &rekor_url;

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

                let html_keys: Vec<String> = assets
                    .iter()
                    .filter(|a| a.is_html())
                    .map(|a| a.key.clone())
                    .collect();

                let mut applied = 0usize;
                let mut cross_origin: Vec<String> = Vec::new();
                let mut unresolved: Vec<String> = Vec::new();

                for key in &html_keys {
                    let idx = assets.iter().position(|a| &a.key == key).expect("present");
                    let original = fs::read(&assets[idx].abs)?;
                    let (rewritten, report) =
                        veil_guard::generators::inject_sri(&original, key, &digests)?;

                    // SPEC §10 step 4 (Faza 2): inject "integrity" into Import Maps.
                    let (rewritten, im_count) =
                        veil_guard::generators::inject_importmap_integrity(&rewritten, &digests)?;
                    applied += im_count;

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
                        csp: veil_guard::generators::csp_script_src(&hashes, &csp_sources),
                    });
                }

                println!(
                    "sri          {applied} integrity attributes across {} pages",
                    html_keys.len()
                );
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

            let mut source_val = serde_json::json!({
                "commit": source_commit.unwrap_or_default(),
                "toolchain": { "veil_guard": env!("CARGO_PKG_VERSION") },
            });

            if let Some(prov_path) = &provenance_json {
                let prov_bytes = fs::read(prov_path)?;

                // The manifest is re-fetched by every Service Worker on every cold
                // start with `cache: 'no-store'`, so anything embedded here is paid
                // for on the critical path of every visit. Provenance is metadata,
                // not payload; a cap keeps a runaway CI variable from turning the
                // control plane into a download.
                const MAX_PROVENANCE_BYTES: usize = 16 * 1024;
                if prov_bytes.len() > MAX_PROVENANCE_BYTES {
                    return Err(format!(
                        "{} is {} bytes; the limit is {MAX_PROVENANCE_BYTES}. \
                         The manifest is fetched by every client on every cold start.",
                        prov_path.display(),
                        prov_bytes.len()
                    )
                    .into());
                }

                let prov: serde_json::Value = serde_json::from_slice(&prov_bytes)?;
                let prov_obj = prov
                    .as_object()
                    .ok_or_else(|| format!("{} must contain a JSON object", prov_path.display()))?;
                source_val
                    .as_object_mut()
                    .expect("source is built as an object above")
                    .insert(
                        "slsa_provenance".into(),
                        serde_json::Value::Object(prov_obj.clone()),
                    );
            }

            let manifest = Manifest {
                spec: SPEC_MANIFEST.into(),
                version,
                not_after: version + not_after_days * 86_400,
                sigalgs: root.sigalgs.clone(),
                trust_root_id: root.id_hex()?,
                trust_root: root.clone(),
                scope: Scope {
                    include: vec!["/".into()],
                    exclude: excludes.clone(),
                    html_extension: navigation_html_fallback,
                },
                source: source_val,
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
                entries.extend(read_key_file(path)?.sign(
                    PREFIX_MANIFEST,
                    &payload,
                    kms_key_id.as_deref(),
                    kms_provider.as_deref(),
                )?);
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

            #[cfg(feature = "rekor")]
            if rekor_upload {
                let first_kf = read_key_file(&keys[0])?;
                let ed_bytes = veil_guard::crypto::unhex_array::<32>(&first_kf.ed25519_public)?;
                let pem = veil_guard::rekor::ed25519_pubkey_to_pem(&ed_bytes);

                match veil_guard::rekor::upload_manifest(&payload, &bundle, &pem, &rekor_url) {
                    Ok(entry) => {
                        println!(
                            "rekor        uploaded log_index={} entry_id={}",
                            entry.log_index, entry.entry_id
                        );
                        let mut manifest_val: serde_json::Value = serde_json::from_slice(&payload)?;
                        manifest_val["source"]["rekor"] = serde_json::json!({
                            "log_index": entry.log_index,
                            "integrated_time": entry.integrated_time,
                            "log_id": entry.log_id,
                            "entry_id": entry.entry_id
                        });
                        let updated_payload =
                            (serde_json::to_string_pretty(&manifest_val)? + "\n").into_bytes();
                        fs::write(&manifest_path, &updated_payload)?;
                    }
                    Err(e) => {
                        println!("rekor warning: upload failed: {e}");
                    }
                }
            }
            #[cfg(not(feature = "rekor"))]
            if rekor_upload {
                println!("rekor warning: --rekor-upload requested but veil-guard was built without feature `rekor`");
            }

            println!("\nmanifest     {}", manifest_path.display());
            println!("version      {version}");
            println!(
                "trust root   {}  ({}-of-{})",
                manifest.trust_root_id,
                root.threshold,
                root.keys.len()
            );
            println!("signers      {}", keys.len());
            if excludes.is_empty() {
                println!(
                    "\nScope is the whole origin, so the worker refuses every same-origin request\n\
                     that is not a signed file. If this app calls its own backend, carve those\n\
                     paths out — for example `--exclude /api/` — or those calls will be blocked."
                );
            } else {
                println!("excluded     {}", excludes.join(", "));
            }

            if let Some(dir) = headers_out {
                fs::create_dir_all(&dir)?;
                use veil_guard::generators::{headers_caddy, headers_netlify, headers_nginx};
                fs::write(
                    dir.join("_headers"),
                    headers_netlify(&pages, enforce_headers),
                )?;
                fs::write(
                    dir.join("veil-guard.nginx.conf"),
                    headers_nginx(&pages, enforce_headers),
                )?;
                fs::write(
                    dir.join("veil-guard.Caddyfile"),
                    headers_caddy(&pages, enforce_headers),
                )?;
                let mode = if enforce_headers {
                    "enforcing"
                } else {
                    "report-only; add --enforce-headers once `audit` is clean"
                };
                println!("headers      {} ({mode})", dir.display());
            }
        }

        Commands::Runtime { trust_root, out } => {
            let root: TrustRoot = serde_json::from_slice(&fs::read(&trust_root)?)?;
            root.validate()?;
            fs::create_dir_all(&out)?;

            let sw = veil_guard::runtime::bundle_service_worker(&root)?;
            let sw_path = out.join("veil-guard-sw.js");
            let loader_path = out.join("veil-guard-loader.js");
            fs::write(&sw_path, &sw)?;
            fs::write(&loader_path, veil_guard::runtime::LOADER_JS)?;

            println!(
                "worker       {}  ({} KiB)",
                sw_path.display(),
                sw.len() / 1024
            );
            println!("loader       {}", loader_path.display());
            println!(
                "trust root   {}  ({}-of-{})",
                root.id_hex()?,
                root.threshold,
                root.keys.len()
            );
            println!(
                "\nAdd to every page, ideally as the first script:\n  \
                 <script src=\"/veil-guard-loader.js\"></script>\n\n\
                 The worker must be served from the site root with a `Service-Worker-Allowed`\n\
                 scope of `/`, or it cannot see requests outside its own directory."
            );
        }

        Commands::Verify {
            dist,
            trust_root,
            pinned_version,
        } => {
            let root: TrustRoot = serde_json::from_slice(&fs::read(&trust_root)?)?;
            root.validate()?;

            let payload = fs::read(dist.join("veil-guard-manifest.json"))?;
            let bundle = fs::read(dist.join("veil-guard-manifest.sig"))?;

            // Check for out-of-band revocation statement in dist directory (§9.2)
            let mut revoked_keys = Vec::new();
            let rev_path = dist.join("veil-guard-revocation.json");
            let rev_sig_path = dist.join("veil-guard-revocation.sig");
            if rev_path.exists() && rev_sig_path.exists() {
                if let (Ok(rev_payload), Ok(rev_bundle)) =
                    (fs::read(&rev_path), fs::read(&rev_sig_path))
                {
                    let now = now_unix();
                    if verify_revocation(&rev_payload, &rev_bundle, &root, 0, now, SUPPORTED_ALGS)
                        == RevocationVerdict::Accept
                    {
                        if let Ok(rev_stmt) =
                            serde_json::from_slice::<RevocationStatement>(&rev_payload)
                        {
                            revoked_keys = rev_stmt.revoked_keys;
                            println!(
                                "revocation   {} key(s) revoked ({:?})",
                                revoked_keys.len(),
                                revoked_keys
                            );
                        }
                    }
                }
            }

            let state = verify_manifest_with_revocation(
                &payload,
                &bundle,
                &root,
                pinned_version,
                now_unix(),
                SUPPORTED_ALGS,
                &revoked_keys,
            );
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

            println!(
                "assets       {} in manifest, {} on disk",
                manifest.assets.len(),
                on_disk.len()
            );
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
                println!(
                    "\nall {} assets match the signed manifest",
                    manifest.assets.len()
                );
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

        #[cfg(feature = "audit")]
        Commands::Audit {
            url,
            trust_root,
            label,
            pinned_version,
            graph_only,
            fail_on,
            out,
            json,
            rekor_verify,
            rekor_url,
            relay_push,
            relay_token,
        } => {
            use veil_guard::auditor::{audit, AuditOptions, Severity};

            let root: TrustRoot = serde_json::from_slice(&fs::read(&trust_root)?)?;
            root.validate()?;

            let snapshot = audit(
                &url,
                &root,
                &AuditOptions {
                    label,
                    pinned_version,
                    graph_only,
                    rekor_verify,
                    rekor_url,
                    ..Default::default()
                },
            )?;

            if json {
                println!("{}", serde_json::to_string_pretty(&snapshot)?);
            } else {
                println!("url          {}", snapshot.url);
                if let Some(l) = &snapshot.label {
                    println!("vantage      {l}");
                }
                println!(
                    "trust root   {}  (local file, not fetched)",
                    snapshot.trust_root_id
                );
                println!("manifest     {}", snapshot.manifest_state);
                if let Some(v) = snapshot.manifest_version {
                    println!("version      {v}");
                }
                if let Some(h) = &snapshot.manifest_sha256 {
                    println!("payload      sha256:{h}");
                }
                println!(
                    "assets       {} in manifest, {} probed",
                    snapshot.assets_in_manifest, snapshot.assets_probed
                );

                if snapshot.findings.is_empty() {
                    println!("\nno findings");
                    println!(
                        "\nA single clean audit shows this deployment matches what was signed.\n\
                         It cannot show the same bundle is served to everyone — compare snapshots\n\
                         from several vantage points with `veil-guard diff` for that."
                    );
                } else {
                    println!();
                    for f in &snapshot.findings {
                        let tag = match f.severity {
                            Severity::Critical => "CRITICAL",
                            Severity::Warning => "WARNING ",
                            Severity::Info => "INFO    ",
                        };
                        println!("  {tag} {:<28} {}", f.kind, f.subject);
                        println!("           {}", f.detail);
                    }
                }
            }

            if let Some(path) = out {
                fs::write(&path, serde_json::to_string_pretty(&snapshot)? + "\n")?;
                if !json {
                    println!("snapshot     {}", path.display());
                }
            }

            if let Some(r_url) = &relay_push {
                #[cfg(feature = "relay-client")]
                {
                    let snap_val = serde_json::to_value(&snapshot)?;
                    match veil_guard::relay::push_snapshot(r_url, &snap_val, relay_token.as_deref())
                    {
                        Ok(()) => println!("relay        pushed snapshot to {r_url}"),
                        Err(e) => println!("relay warning: failed to push snapshot: {e}"),
                    }
                }
                #[cfg(not(feature = "relay-client"))]
                {
                    println!("relay warning: --relay-push requested but veil-guard was built without feature `relay-client`");
                }
            }

            let threshold = match fail_on.as_str() {
                "critical" => Severity::Critical,
                "info" => Severity::Info,
                _ => Severity::Warning,
            };
            if !snapshot.is_clean_at(threshold) {
                std::process::exit(1);
            }
        }

        #[cfg(feature = "relay-client")]
        Commands::Relay { action } => match action {
            RelayAction::Push {
                snapshot,
                relay_url,
                token,
            } => {
                let snap_bytes = fs::read(&snapshot)?;
                let snap_val: serde_json::Value = serde_json::from_slice(&snap_bytes)?;
                veil_guard::relay::push_snapshot(&relay_url, &snap_val, token.as_deref())?;
                println!("pushed snapshot {} to {relay_url}", snapshot.display());
            }
            RelayAction::Pull {
                domain,
                relay_url,
                out_dir,
                since,
            } => {
                let list = veil_guard::relay::pull_snapshots(&relay_url, &domain, since, &out_dir)?;
                println!(
                    "pulled {} snapshot(s) into {}",
                    list.len(),
                    out_dir.display()
                );
            }
        },

        #[cfg(feature = "audit")]
        Commands::Diff { left, right, json } => {
            use veil_guard::auditor::{diff, Snapshot};

            let a: Snapshot = serde_json::from_slice(&fs::read(&left)?)?;
            let b: Snapshot = serde_json::from_slice(&fs::read(&right)?)?;
            let divergences = diff(&a, &b);

            if json {
                println!("{}", serde_json::to_string_pretty(&divergences)?);
            } else {
                let name = |s: &Snapshot| s.label.clone().unwrap_or_else(|| s.url.clone());
                println!("left         {}  @{}", name(&a), a.observed_at);
                println!("right        {}  @{}", name(&b), b.observed_at);

                if divergences.is_empty() {
                    println!("\nidentical: both vantage points were served the same bytes");
                } else {
                    println!("\n{} divergence(s):", divergences.len());
                    for d in &divergences {
                        println!("  {:<20} {}", d.kind, d.subject);
                        println!("    left  {}", d.left);
                        println!("    right {}", d.right);
                    }
                    println!(
                        "\nIf both snapshots are of the same deployment at the same version,\n\
                         divergence means different visitors are being served different code."
                    );
                }
            }

            if !divergences.is_empty() {
                std::process::exit(1);
            }
        }

        Commands::Rotate {
            from,
            to,
            keys,
            out,
            version,
        } => {
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
                entries.extend(
                    read_key_file(path)?
                        .signer()?
                        .sign(PREFIX_ROTATION, &payload),
                );
            }
            let bundle = build_bundle(&entries);

            // Refuse to emit a statement that would not be accepted. Discovering a
            // short quorum here beats discovering it once clients are pinned.
            if verify_rotation(&payload, &bundle, &old, 0, SUPPORTED_ALGS)
                != RotationVerdict::Accept
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

        Commands::Revoke {
            trust_root,
            revoked_keys,
            keys,
            out,
            version,
            not_after_days,
            reason,
        } => {
            let root: TrustRoot = serde_json::from_slice(&fs::read(&trust_root)?)?;
            root.validate()?;

            let max_revocable = root.keys.len().saturating_sub(root.threshold as usize);
            if revoked_keys.len() > max_revocable {
                return Err(format!(
                    "cannot revoke {} key(s): threshold is {} and root has {} keys. At most {} key(s) can be revoked without invalidating the root.",
                    revoked_keys.len(),
                    root.threshold,
                    root.keys.len(),
                    max_revocable
                )
                .into());
            }

            let now = now_unix();

            let statement_version = version.unwrap_or(now);
            let not_after = statement_version + not_after_days * 86400;

            let statement = RevocationStatement {
                spec: SPEC_REVOCATION.into(),
                version: statement_version,
                trust_root_id: root.id_hex()?,
                revoked_keys: revoked_keys.clone(),
                not_after,
                reason,
            };
            let payload = (serde_json::to_string_pretty(&statement)? + "\n").into_bytes();

            let mut entries = Vec::new();
            for path in &keys {
                entries.extend(
                    read_key_file(path)?
                        .signer()?
                        .sign(PREFIX_REVOCATION, &payload),
                );
            }
            let bundle = build_bundle(&entries);

            if verify_revocation(&payload, &bundle, &root, 0, now, SUPPORTED_ALGS)
                != RevocationVerdict::Accept
            {
                return Err(format!(
                    "revocation would be rejected: {} signer(s) supplied, trust root needs {}",
                    keys.len(),
                    root.threshold
                )
                .into());
            }

            fs::write(&out, &payload)?;
            let sig_path = out.with_extension("sig");
            fs::write(&sig_path, &bundle)?;

            println!("revocation   {}", out.display());
            println!("signatures   {}", sig_path.display());
            println!("trust_root   {}", statement.trust_root_id);
            println!("revoked_keys {:?}", statement.revoked_keys);
            println!("version      {}", statement.version);
            println!("not_after    {}", statement.not_after);
        }
    }
    Ok(())
}
