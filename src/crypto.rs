//! Core cryptography for the veil-guard protocol.
//!
//! Implements SPEC.md §2 (primitives and encodings), §3 (domain separation),
//! §4 (keys, identity, trust root) and §5 (signature bundle). The verification
//! state machine that consumes these lives in [`crate::manifest`].
//!
//! Every function here is checked against `testdata/conformance_vectors.json`;
//! the JavaScript reference verifier must reach identical verdicts.

// `signature::Signer`/`Verifier` are the same traits both crates re-export, so one
// import covers Ed25519 and P-256 alike.
use ed25519_dalek::{Signer as _, Verifier as _};
use p256::pkcs8::DecodePrivateKey as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------- SPEC §3
pub const PREFIX_MANIFEST: &[u8] = b"veil-guard/manifest/v1\0";
pub const PREFIX_ROTATION: &[u8] = b"veil-guard/rotation/v1\0";
pub const PREFIX_REVOCATION: &[u8] = b"veil-guard/revocation/v1\0";
pub const PREFIX_KEYID: &[u8] = b"veil-guard/keyid/v1\0";
pub const PREFIX_TRUSTROOT: &[u8] = b"veil-guard/trustroot/v1\0";

/// SPEC §2: JSON integers must round-trip exactly through an IEEE-754 double.
pub const MAX_SAFE_INT: u64 = 9_007_199_254_740_991;

/// SPEC §4.4: an implementation limit that bounds trust-root parsing work.
pub const MAX_TRUST_ROOT_KEYS: usize = 16;
/// SPEC §5: bounds signature-bundle parsing work.
pub const MAX_BUNDLE_ENTRIES: usize = 64;
pub const MAX_SIG_LEN: usize = 128;

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// Hex that is not lowercase, not even-length, or not `[0-9a-f]`.
    BadHex,
    BadLength,
    /// A compressed SEC1 point, or a point that is not 65 bytes starting with 0x04.
    BadP256Point,
    TrustRootInvalid(&'static str),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::BadHex => write!(f, "malformed hex (must be lowercase, even length)"),
            CryptoError::BadLength => write!(f, "unexpected byte length"),
            CryptoError::BadP256Point => {
                write!(
                    f,
                    "P-256 public key must be 65-byte uncompressed SEC1 (0x04 || X || Y)"
                )
            }
            CryptoError::TrustRootInvalid(why) => write!(f, "invalid trust root: {why}"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// SPEC §2: hex is lowercase only. Uppercase is rejected rather than normalized,
/// so that a manifest has exactly one valid spelling of every byte string.
pub fn unhex(s: &str) -> Result<Vec<u8>, CryptoError> {
    if !s.len().is_multiple_of(2)
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CryptoError::BadHex);
    }
    hex::decode(s).map_err(|_| CryptoError::BadHex)
}

pub fn unhex_array<const N: usize>(s: &str) -> Result<[u8; N], CryptoError> {
    let v = unhex(s)?;
    v.try_into().map_err(|_| CryptoError::BadLength)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn sha384(data: &[u8]) -> [u8; 48] {
    sha2::Sha384::digest(data).into()
}

// ---------------------------------------------------------------- algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SigAlg {
    Ed25519,
    P256,
}

impl SigAlg {
    pub fn alg_id(self) -> u8 {
        match self {
            SigAlg::Ed25519 => 0x01,
            SigAlg::P256 => 0x02,
        }
    }

    pub fn from_alg_id(id: u8) -> Option<Self> {
        match id {
            0x01 => Some(SigAlg::Ed25519),
            0x02 => Some(SigAlg::P256),
            _ => None,
        }
    }

    pub fn mask_bit(self) -> u8 {
        match self {
            SigAlg::Ed25519 => 0x01,
            SigAlg::P256 => 0x02,
        }
    }
}

/// Every algorithm this build can verify. SPEC §8.1 calls this the "supported" set.
pub const SUPPORTED_ALGS: &[SigAlg] = &[SigAlg::Ed25519, SigAlg::P256];

// ---------------------------------------------------------------- SPEC §4.2
pub type KeyId = [u8; 8];

pub fn key_id(ed25519_pub: &[u8; 32], p256_pub: &[u8; 65]) -> KeyId {
    let mut h = Sha256::new();
    h.update(PREFIX_KEYID);
    h.update(ed25519_pub);
    h.update(p256_pub);
    let d: [u8; 32] = h.finalize().into();
    d[..8].try_into().expect("8 bytes")
}

// ---------------------------------------------------------------- SPEC §4.4
/// SPEC §12: unknown members inside the trust root must be rejected, because the
/// trust root ID is computed over a binary encoding that would not cover them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedKey {
    pub key_id: String,
    pub role: String,
    pub ed25519: String,
    pub p256: String,
}

impl TrustedKey {
    pub fn ed25519_bytes(&self) -> Result<[u8; 32], CryptoError> {
        unhex_array::<32>(&self.ed25519)
    }

    pub fn p256_bytes(&self) -> Result<[u8; 65], CryptoError> {
        let b = unhex_array::<65>(&self.p256)?;
        if b[0] != 0x04 {
            return Err(CryptoError::BadP256Point);
        }
        Ok(b)
    }

    pub fn key_id_bytes(&self) -> Result<KeyId, CryptoError> {
        unhex_array::<8>(&self.key_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRoot {
    pub threshold: u8,
    pub sigalgs: Vec<SigAlg>,
    pub keys: Vec<TrustedKey>,
}

impl TrustRoot {
    /// SPEC §4.4. Called before any signature work; a trust root that fails this
    /// is never used, even to reject something.
    pub fn validate(&self) -> Result<(), CryptoError> {
        use CryptoError::TrustRootInvalid as E;

        if self.keys.is_empty() || self.keys.len() > MAX_TRUST_ROOT_KEYS {
            return Err(E("key count out of range"));
        }
        if self.threshold < 1 || self.threshold as usize > self.keys.len() {
            return Err(E("threshold out of range"));
        }
        if self.sigalgs.is_empty() {
            return Err(E("sigalgs must not be empty"));
        }
        // Canonical order, no duplicates: ed25519 before p256 (SPEC §4.4).
        if self.sigalgs.windows(2).any(|w| w[0] >= w[1]) {
            return Err(E("sigalgs must be sorted and unique"));
        }

        let mut prev: Option<KeyId> = None;
        for k in &self.keys {
            let ed = k.ed25519_bytes().map_err(|_| E("bad ed25519 key"))?;
            let p = k.p256_bytes().map_err(|_| E("bad p256 key"))?;
            let stated = k.key_id_bytes().map_err(|_| E("bad key_id"))?;
            if stated != key_id(&ed, &p) {
                return Err(E("key_id does not match its key material"));
            }
            if let Some(p0) = prev {
                if stated <= p0 {
                    return Err(E("keys must be sorted by key_id, without duplicates"));
                }
            }
            prev = Some(stated);
        }
        Ok(())
    }

    fn tr_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let mask = self.sigalgs.iter().fold(0u8, |m, a| m | a.mask_bit());
        let mut out = Vec::with_capacity(3 + self.keys.len() * 105);
        out.push(self.threshold);
        out.push(self.keys.len() as u8);
        out.push(mask);
        for k in &self.keys {
            out.extend_from_slice(&k.key_id_bytes()?);
            out.extend_from_slice(&k.ed25519_bytes()?);
            out.extend_from_slice(&k.p256_bytes()?);
        }
        Ok(out)
    }

    /// SPEC §4.5. Computed over a binary encoding, so it never depends on how the
    /// surrounding JSON happened to be serialized.
    pub fn id(&self) -> Result<[u8; 32], CryptoError> {
        let mut h = Sha256::new();
        h.update(PREFIX_TRUSTROOT);
        h.update(self.tr_bytes()?);
        Ok(h.finalize().into())
    }

    pub fn id_hex(&self) -> Result<String, CryptoError> {
        Ok(hex::encode(self.id()?))
    }

    pub fn find(&self, id: &KeyId) -> Option<&TrustedKey> {
        self.keys
            .iter()
            .find(|k| k.key_id_bytes().is_ok_and(|k| &k == id))
    }
}

// ---------------------------------------------------------------- SPEC §5
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigEntry {
    pub key_id: KeyId,
    pub alg_id: u8,
    pub sig: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BundleError {
    ShortHeader,
    BadMagic,
    BadFormatVersion,
    ReservedSet,
    EntryCountOutOfRange,
    BadSigLen,
    Truncated,
    NotSorted,
    DuplicateEntry,
    TrailingBytes,
}

const BUNDLE_MAGIC: &[u8; 6] = b"VGSIG1";
const BUNDLE_FORMAT_VERSION: u8 = 0x01;

/// SPEC §5. Any violation here is `TAMPERED` at the caller — never a warning.
pub fn parse_bundle(bytes: &[u8]) -> Result<Vec<SigEntry>, BundleError> {
    if bytes.len() < 10 {
        return Err(BundleError::ShortHeader);
    }
    if &bytes[0..6] != BUNDLE_MAGIC {
        return Err(BundleError::BadMagic);
    }
    if bytes[6] != BUNDLE_FORMAT_VERSION {
        return Err(BundleError::BadFormatVersion);
    }
    if bytes[7] != 0x00 {
        return Err(BundleError::ReservedSet);
    }

    let count = u16::from_le_bytes([bytes[8], bytes[9]]) as usize;
    if !(1..=MAX_BUNDLE_ENTRIES).contains(&count) {
        return Err(BundleError::EntryCountOutOfRange);
    }

    let mut entries = Vec::with_capacity(count);
    let mut off = 10usize;
    for _ in 0..count {
        if off + 12 > bytes.len() {
            return Err(BundleError::Truncated);
        }
        let key_id: KeyId = bytes[off..off + 8].try_into().expect("8 bytes");
        let alg_id = bytes[off + 8];
        if bytes[off + 9] != 0x00 {
            return Err(BundleError::ReservedSet);
        }
        let sig_len = u16::from_le_bytes([bytes[off + 10], bytes[off + 11]]) as usize;

        // A known algorithm has a fixed signature length; an unknown one is skipped
        // later, and sig_len is what makes skipping it unambiguous (SPEC §5 rule 3).
        if SigAlg::from_alg_id(alg_id).is_some() && sig_len != 64 {
            return Err(BundleError::BadSigLen);
        }
        if sig_len > MAX_SIG_LEN {
            return Err(BundleError::BadSigLen);
        }
        if off + 12 + sig_len > bytes.len() {
            return Err(BundleError::Truncated);
        }

        entries.push(SigEntry {
            key_id,
            alg_id,
            sig: bytes[off + 12..off + 12 + sig_len].to_vec(),
        });
        off += 12 + sig_len;
    }

    if off != bytes.len() {
        return Err(BundleError::TrailingBytes);
    }

    for w in entries.windows(2) {
        match (w[0].key_id.cmp(&w[1].key_id), w[0].alg_id.cmp(&w[1].alg_id)) {
            (std::cmp::Ordering::Equal, std::cmp::Ordering::Equal) => {
                return Err(BundleError::DuplicateEntry)
            }
            (std::cmp::Ordering::Greater, _) => return Err(BundleError::NotSorted),
            (std::cmp::Ordering::Equal, std::cmp::Ordering::Greater) => {
                return Err(BundleError::NotSorted)
            }
            _ => {}
        }
    }

    Ok(entries)
}

pub fn build_bundle(entries: &[SigEntry]) -> Vec<u8> {
    let mut sorted: Vec<&SigEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.key_id.cmp(&b.key_id).then(a.alg_id.cmp(&b.alg_id)));

    let mut out = Vec::with_capacity(10 + sorted.len() * 76);
    out.extend_from_slice(BUNDLE_MAGIC);
    out.push(BUNDLE_FORMAT_VERSION);
    out.push(0x00);
    out.extend_from_slice(&(sorted.len() as u16).to_le_bytes());
    for e in sorted {
        out.extend_from_slice(&e.key_id);
        out.push(e.alg_id);
        out.push(0x00);
        out.extend_from_slice(&(e.sig.len() as u16).to_le_bytes());
        out.extend_from_slice(&e.sig);
    }
    out
}

// ---------------------------------------------------------------- verification
/// SPEC §4.3: strict verification, so that dalek and WebCrypto agree on the
/// RFC 8032 edge cases where a cofactored verifier would differ.
pub fn verify_ed25519(pub_key: &[u8; 32], sig: &[u8], msg: &[u8]) -> bool {
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(pub_key) else {
        return false;
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig) else {
        return false;
    };
    vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sig_arr))
        .is_ok()
}

/// SPEC §2.1: uncompressed SEC1 public key in, raw `r||s` signature in. Neither
/// DER signatures nor SPKI keys are accepted, because WebCrypto accepts neither.
pub fn verify_p256(pub_key: &[u8; 65], sig: &[u8], msg: &[u8]) -> bool {
    if pub_key[0] != 0x04 || sig.len() != 64 {
        return false;
    }
    let Ok(vk) = p256::ecdsa::VerifyingKey::from_sec1_bytes(pub_key) else {
        return false;
    };
    let Ok(signature) = p256::ecdsa::Signature::from_slice(sig) else {
        return false;
    };
    vk.verify(msg, &signature).is_ok()
}

pub fn verify_with(alg: SigAlg, key: &TrustedKey, sig: &[u8], msg: &[u8]) -> bool {
    match alg {
        SigAlg::Ed25519 => key
            .ed25519_bytes()
            .map(|k| verify_ed25519(&k, sig, msg))
            .unwrap_or(false),
        SigAlg::P256 => key
            .p256_bytes()
            .map(|k| verify_p256(&k, sig, msg))
            .unwrap_or(false),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ThresholdOutcome {
    /// Number of trust-root keys that signed under *every* active algorithm.
    Qualifying(usize),
    /// A signature was present for an active algorithm and did not verify.
    Tampered,
    /// The verifier implements none of the trust root's algorithms.
    Unsupported,
}

/// SPEC §8.1 step 3.
///
/// A present-but-invalid signature is fatal; an absent one merely fails to count.
/// That asymmetry is the downgrade defense: holding one algorithm's private key
/// for a signer does not let an attacker drop the other algorithm and still have
/// that signer contribute to the threshold.
pub fn check_threshold(
    payload: &[u8],
    entries: &[SigEntry],
    pinned: &TrustRoot,
    prefix: &[u8],
    supported: &[SigAlg],
) -> ThresholdOutcome {
    let active: Vec<SigAlg> = pinned
        .sigalgs
        .iter()
        .copied()
        .filter(|a| supported.contains(a))
        .collect();
    if active.is_empty() {
        return ThresholdOutcome::Unsupported;
    }

    let mut msg = Vec::with_capacity(prefix.len() + payload.len());
    msg.extend_from_slice(prefix);
    msg.extend_from_slice(payload);

    let mut qualifying = 0usize;
    for key in &pinned.keys {
        let Ok(kid) = key.key_id_bytes() else {
            return ThresholdOutcome::Tampered;
        };
        let mut present = 0usize;
        for &alg in &active {
            let Some(entry) = entries
                .iter()
                .find(|e| e.key_id == kid && e.alg_id == alg.alg_id())
            else {
                continue;
            };
            if !verify_with(alg, key, &entry.sig, &msg) {
                return ThresholdOutcome::Tampered;
            }
            present += 1;
        }
        if present == active.len() {
            qualifying += 1;
        }
    }
    ThresholdOutcome::Qualifying(qualifying)
}

// ---------------------------------------------------------------- signing side
/// A signer identity: one Ed25519 keypair and one P-256 keypair, bound together
/// by [`key_id`]. SPEC §4.1 — there is no single-algorithm signer.
///
/// Both inner types zeroize their own secret material on drop, so this struct
/// deliberately has no `Drop` of its own: a hand-written one could only reach
/// copies, which would look like protection without being any.
pub struct SignerKeys {
    ed: ed25519_dalek::SigningKey,
    p256: p256::ecdsa::SigningKey,
}

impl SignerKeys {
    pub fn generate() -> Self {
        let mut rng = rand_core::OsRng;
        SignerKeys {
            ed: ed25519_dalek::SigningKey::generate(&mut rng),
            p256: p256::ecdsa::SigningKey::random(&mut rng),
        }
    }

    pub fn from_parts(ed_seed: &[u8; 32], p256_pkcs8_der: &[u8]) -> Result<Self, CryptoError> {
        Ok(SignerKeys {
            ed: ed25519_dalek::SigningKey::from_bytes(ed_seed),
            p256: p256::ecdsa::SigningKey::from_pkcs8_der(p256_pkcs8_der)
                .map_err(|_| CryptoError::BadLength)?,
        })
    }

    pub fn ed25519_seed(&self) -> [u8; 32] {
        self.ed.to_bytes()
    }

    pub fn p256_pkcs8_der(&self) -> Result<Vec<u8>, CryptoError> {
        use p256::pkcs8::EncodePrivateKey as _;
        Ok(self
            .p256
            .to_pkcs8_der()
            .map_err(|_| CryptoError::BadLength)?
            .as_bytes()
            .to_vec())
    }

    pub fn ed25519_public(&self) -> [u8; 32] {
        self.ed.verifying_key().to_bytes()
    }

    /// Uncompressed SEC1, 65 bytes — the encoding WebCrypto imports (SPEC §2.1).
    pub fn p256_public(&self) -> [u8; 65] {
        let point = self.p256.verifying_key().to_encoded_point(false);
        point
            .as_bytes()
            .try_into()
            .expect("uncompressed point is 65 bytes")
    }

    pub fn key_id(&self) -> KeyId {
        key_id(&self.ed25519_public(), &self.p256_public())
    }

    pub fn as_trusted_key(&self, role: &str) -> TrustedKey {
        TrustedKey {
            key_id: hex::encode(self.key_id()),
            role: role.to_string(),
            ed25519: hex::encode(self.ed25519_public()),
            p256: hex::encode(self.p256_public()),
        }
    }

    /// Produces one entry per algorithm, both over the same domain-separated bytes.
    pub fn sign(&self, prefix: &[u8], payload: &[u8]) -> Vec<SigEntry> {
        let mut msg = Vec::with_capacity(prefix.len() + payload.len());
        msg.extend_from_slice(prefix);
        msg.extend_from_slice(payload);

        let ed_sig = self.ed.sign(&msg);
        let p_sig: p256::ecdsa::Signature = self.p256.sign(&msg);

        vec![
            SigEntry {
                key_id: self.key_id(),
                alg_id: SigAlg::Ed25519.alg_id(),
                sig: ed_sig.to_bytes().to_vec(),
            },
            SigEntry {
                key_id: self.key_id(),
                alg_id: SigAlg::P256.alg_id(),
                // to_bytes() is raw r||s. to_der() would be the wrong encoding here.
                sig: p_sig.to_bytes().to_vec(),
            },
        ]
    }
}
