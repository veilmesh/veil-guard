//! Asset scanning — SPEC.md §7 and §10 steps 1–2.

use crate::crypto::{sha256, sha384};
use crate::paths::{manifest_key_from_relative, to_nfc};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Files that are build residue rather than served assets. Note that dotfiles are
/// *not* excluded wholesale: `/.well-known/` is a legitimate served path.
pub const DEFAULT_EXCLUDES: &[&str] = &[
    ".DS_Store",
    "Thumbs.db",
    "veil-guard-manifest.json",
    "veil-guard-manifest.sig",
];

/// Directories that hold build residue.
pub const DEFAULT_EXCLUDE_DIRS: &[&str] = &[".vite", ".git"];

#[derive(Debug, Clone)]
pub struct ScannedAsset {
    pub key: String,
    pub abs: PathBuf,
    pub sha256: String,
    pub sha384: String,
    pub size: u64,
    pub content_type: String,
}

impl ScannedAsset {
    pub fn is_html(&self) -> bool {
        self.content_type == "text/html"
    }
}

#[derive(Debug)]
pub enum ScanError {
    Io(std::io::Error),
    Symlink(PathBuf),
    BadPath(PathBuf),
    /// Two files whose manifest keys differ only by ASCII case. Works on a
    /// case-insensitive macOS filesystem, breaks on a case-sensitive server.
    CaseCollision(String, String),
    DuplicateKey(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::Io(e) => write!(f, "{e}"),
            ScanError::Symlink(p) => write!(
                f,
                "{}: symbolic links are not followed and must not appear in dist",
                p.display()
            ),
            ScanError::BadPath(p) => write!(f, "{}: path cannot be canonicalized", p.display()),
            ScanError::CaseCollision(a, b) => write!(
                f,
                "`{a}` and `{b}` differ only by case; this works on a case-insensitive \
                 filesystem and breaks on a case-sensitive server"
            ),
            ScanError::DuplicateKey(k) => write!(f, "two files normalize to the same key `{k}`"),
        }
    }
}

impl std::error::Error for ScanError {}

impl From<std::io::Error> for ScanError {
    fn from(e: std::io::Error) -> Self {
        ScanError::Io(e)
    }
}

/// Walk `dist` and produce the manifest's asset set, sorted by key.
pub fn scan_dist(dist: &Path) -> Result<Vec<ScannedAsset>, ScanError> {
    let root = dist.canonicalize().map_err(ScanError::Io)?;
    let mut assets: Vec<ScannedAsset> = Vec::new();
    let mut seen: HashMap<String, String> = HashMap::new();

    for entry in WalkDir::new(&root).follow_links(false) {
        let entry = entry.map_err(|e| {
            ScanError::Io(e.into_io_error().unwrap_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::Other, "walk failed")
            }))
        })?;

        if entry.file_type().is_symlink() {
            return Err(ScanError::Symlink(entry.path().to_path_buf()));
        }
        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if DEFAULT_EXCLUDES.contains(&name) {
            continue;
        }
        let relative = path
            .strip_prefix(&root)
            .map_err(|_| ScanError::BadPath(path.to_path_buf()))?;
        let relative_str = relative
            .to_str()
            .ok_or_else(|| ScanError::BadPath(path.to_path_buf()))?;
        if relative_str
            .split(['/', '\\'])
            .any(|c| DEFAULT_EXCLUDE_DIRS.contains(&c))
        {
            continue;
        }

        let key = manifest_key_from_relative(relative_str)
            .ok_or_else(|| ScanError::BadPath(path.to_path_buf()))?;

        let folded = key.to_lowercase();
        if let Some(prev) = seen.get(&folded) {
            if prev == &key {
                return Err(ScanError::DuplicateKey(key));
            }
            return Err(ScanError::CaseCollision(prev.clone(), key));
        }
        seen.insert(folded, key.clone());

        let bytes = std::fs::read(path)?;
        assets.push(ScannedAsset {
            sha256: hex::encode(sha256(&bytes)),
            sha384: hex::encode(sha384(&bytes)),
            size: bytes.len() as u64,
            content_type: content_type_for(&key).to_string(),
            key,
            abs: path.to_path_buf(),
        });
    }

    // SPEC §6.3: sorted bytewise over the NFC-normalized UTF-8 encoding.
    assets.sort_by(|a, b| a.key.as_bytes().cmp(b.key.as_bytes()));
    Ok(assets)
}

/// Recompute one asset's digests after its bytes changed on disk (SPEC §10 step 5).
pub fn rehash(asset: &mut ScannedAsset, bytes: &[u8]) {
    asset.sha256 = hex::encode(sha256(bytes));
    asset.sha384 = hex::encode(sha384(bytes));
    asset.size = bytes.len() as u64;
}

/// Media type by extension. The canonical spellings match SPEC §6.4.
pub fn content_type_for(key: &str) -> &'static str {
    let ext = key.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html",
        "js" | "mjs" => "text/javascript",
        "css" => "text/css",
        "wasm" => "application/wasm",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "ttf" => "font/ttf",
        "xml" => "application/xml",
        "txt" => "text/plain",
        "md" => "text/markdown",
        "yaml" | "yml" => "application/yaml",
        "pdf" => "application/pdf",
        "webmanifest" => "application/manifest+json",
        _ => "application/octet-stream",
    }
}

/// Normalize a path the way a scan would, for comparing against a manifest key.
pub fn key_for_relative(relative: &str) -> Option<String> {
    manifest_key_from_relative(&to_nfc(relative))
}
