//! Manifest and rotation types, and the verification state machine.
//!
//! Implements SPEC.md §6 (manifest), §8.1 (verification algorithm) and §9.1
//! (rotation). The Rust CLI and the JavaScript Service Worker must return the same
//! state for every input; `tests/conformance.rs` pins that against the shared
//! golden vectors.

use crate::crypto::{
    check_threshold, parse_bundle, SigAlg, ThresholdOutcome, TrustRoot, MAX_SAFE_INT,
    PREFIX_MANIFEST, PREFIX_ROTATION,
};
use crate::paths::to_nfc;
use serde::{Deserialize, Serialize};

pub const SPEC_MANIFEST: &str = "veil-guard/1";
pub const SPEC_ROTATION: &str = "veil-guard/rotation/1";

/// SPEC §9.1: a bound on how far a client will walk a rotation chain in one session.
pub const MAX_ROTATION_CHAIN: usize = 8;

// ---------------------------------------------------------------- SPEC §8.2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestState {
    Valid,
    /// Soft. Serve, warn quietly, revalidate on next navigation. Never an alert.
    Expired,
    Rollback,
    Tampered,
    UntrustedRoot,
    Unsupported,
}

impl ManifestState {
    /// Whether this state blocks every in-scope request.
    pub fn is_hard_failure(self) -> bool {
        matches!(
            self,
            ManifestState::Tampered
                | ManifestState::Rollback
                | ManifestState::UntrustedRoot
                | ManifestState::Unsupported
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ManifestState::Valid => "VALID",
            ManifestState::Expired => "EXPIRED",
            ManifestState::Rollback => "ROLLBACK",
            ManifestState::Tampered => "TAMPERED",
            ManifestState::UntrustedRoot => "UNTRUSTED_ROOT",
            ManifestState::Unsupported => "UNSUPPORTED",
        }
    }
}

// ---------------------------------------------------------------- SPEC §6.2
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetEntry {
    pub path: String,
    pub sha256: String,
    pub sha384: String,
    pub size: u64,
    pub content_type: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Scope {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// SPEC §12: unknown members outside `trust_root` are ignored, so additive fields
/// do not require a spec bump. `TrustRoot` itself denies them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub spec: String,
    pub version: u64,
    pub not_after: u64,
    pub sigalgs: Vec<SigAlg>,
    pub trust_root_id: String,
    pub trust_root: TrustRoot,
    #[serde(default)]
    pub scope: Scope,
    #[serde(default)]
    pub source: serde_json::Value,
    pub assets: Vec<AssetEntry>,
}

impl Manifest {
    /// Structural rules from SPEC §6.3 and §7 that do not depend on any pin.
    fn structurally_valid(&self) -> bool {
        if self.spec != SPEC_MANIFEST {
            return false;
        }
        if self.version > MAX_SAFE_INT || self.not_after > MAX_SAFE_INT {
            return false;
        }
        if self.not_after <= self.version {
            return false;
        }
        if self.sigalgs != self.trust_root.sigalgs {
            return false;
        }
        if self.trust_root.validate().is_err() {
            return false;
        }
        for (i, a) in self.assets.iter().enumerate() {
            if a.size > MAX_SAFE_INT {
                return false;
            }
            if to_nfc(&a.path) != a.path {
                return false;
            }
            if crate::paths::request_key(&a.path).as_deref() != Some(a.path.as_str()) {
                return false;
            }
            // Sorted ascending, bytewise, without duplicates.
            if i > 0 && self.assets[i - 1].path.as_bytes() >= a.path.as_bytes() {
                return false;
            }
        }
        true
    }

    pub fn lookup(&self, key: &str) -> Option<&AssetEntry> {
        self.assets
            .binary_search_by(|a| a.path.as_bytes().cmp(key.as_bytes()))
            .ok()
            .map(|i| &self.assets[i])
    }
}

/// SPEC §8.1.
///
/// `payload` is the exact byte content of `veil-guard-manifest.json` as served.
/// It is verified before it is parsed — that ordering is what removes the entire
/// class of signer/verifier JSON disagreements.
pub fn verify_manifest(
    payload: &[u8],
    bundle: &[u8],
    pinned: &TrustRoot,
    pinned_version: u64,
    now: u64,
    supported: &[SigAlg],
) -> ManifestState {
    if pinned.validate().is_err() {
        return ManifestState::UntrustedRoot;
    }

    let Ok(entries) = parse_bundle(bundle) else {
        return ManifestState::Tampered;
    };

    match check_threshold(payload, &entries, pinned, PREFIX_MANIFEST, supported) {
        ThresholdOutcome::Unsupported => return ManifestState::Unsupported,
        ThresholdOutcome::Tampered => return ManifestState::Tampered,
        ThresholdOutcome::Qualifying(n) if n < pinned.threshold as usize => {
            return ManifestState::UntrustedRoot
        }
        ThresholdOutcome::Qualifying(_) => {}
    }

    // Only now is it safe to look at the contents.
    let Ok(text) = std::str::from_utf8(payload) else {
        return ManifestState::Tampered;
    };
    let Ok(manifest) = serde_json::from_str::<Manifest>(text) else {
        return ManifestState::Tampered;
    };

    if !manifest.structurally_valid() {
        return ManifestState::Tampered;
    }

    let Ok(stated) = manifest.trust_root.id_hex() else {
        return ManifestState::Tampered;
    };
    if stated != manifest.trust_root_id {
        return ManifestState::Tampered;
    }
    let Ok(pinned_id) = pinned.id_hex() else {
        return ManifestState::UntrustedRoot;
    };
    if manifest.trust_root_id != pinned_id {
        return ManifestState::UntrustedRoot;
    }

    if manifest.version < pinned_version {
        return ManifestState::Rollback;
    }
    if now > manifest.not_after {
        return ManifestState::Expired;
    }
    ManifestState::Valid
}

// ---------------------------------------------------------------- SPEC §9.1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationStatement {
    pub spec: String,
    pub version: u64,
    pub from_trust_root_id: String,
    pub to_trust_root: TrustRoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationVerdict {
    Accept,
    Reject,
}

/// SPEC §9.1. Signed with the rotation prefix and by the *old* root's threshold.
///
/// The strictly-greater version check is what stops an attacker from replaying an
/// older rotation to walk the pin back to a superseded root.
pub fn verify_rotation(
    payload: &[u8],
    bundle: &[u8],
    pinned: &TrustRoot,
    pinned_rotation_version: u64,
    supported: &[SigAlg],
) -> RotationVerdict {
    if pinned.validate().is_err() {
        return RotationVerdict::Reject;
    }

    let Ok(entries) = parse_bundle(bundle) else {
        return RotationVerdict::Reject;
    };

    match check_threshold(payload, &entries, pinned, PREFIX_ROTATION, supported) {
        ThresholdOutcome::Qualifying(n) if n >= pinned.threshold as usize => {}
        _ => return RotationVerdict::Reject,
    }

    let Ok(text) = std::str::from_utf8(payload) else {
        return RotationVerdict::Reject;
    };
    let Ok(rot) = serde_json::from_str::<RotationStatement>(text) else {
        return RotationVerdict::Reject;
    };

    if rot.spec != SPEC_ROTATION || rot.version > MAX_SAFE_INT {
        return RotationVerdict::Reject;
    }
    let Ok(pinned_id) = pinned.id_hex() else {
        return RotationVerdict::Reject;
    };
    if rot.from_trust_root_id != pinned_id {
        return RotationVerdict::Reject;
    }
    if rot.version <= pinned_rotation_version {
        return RotationVerdict::Reject;
    }
    if rot.to_trust_root.validate().is_err() {
        return RotationVerdict::Reject;
    }
    RotationVerdict::Accept
}
