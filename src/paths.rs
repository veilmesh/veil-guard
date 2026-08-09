//! Path canonicalization — SPEC.md §7.
//!
//! Both sides of the protocol must agree byte-for-byte on what a path is, so the
//! scanning side (turning a file location into a manifest key) and the verifying
//! side (turning a request URL into a lookup key) live together here.

use unicode_normalization::UnicodeNormalization;

/// SPEC §7 step 3. macOS APFS hands back NFD, browsers send NFC; without this
/// every non-ASCII filename silently fails to match.
pub fn to_nfc(s: &str) -> String {
    s.nfc().collect()
}

/// SPEC §7: derive a manifest key from a path relative to the dist root.
///
/// Returns `None` for anything that must not appear in a manifest at all.
pub fn manifest_key_from_relative(relative: &str) -> Option<String> {
    let mut parts = Vec::new();
    for component in relative.split(['/', '\\']) {
        if component.is_empty() || component == "." || component == ".." {
            return None;
        }
        parts.push(to_nfc(component));
    }
    if parts.is_empty() {
        return None;
    }
    let joined = format!("/{}", parts.join("/"));
    if joined.contains('\\') || joined.contains("//") || joined.contains('\0') {
        return None;
    }
    Some(joined)
}

/// SPEC §7.1: derive a lookup key from a request URL's pathname.
///
/// The query string and fragment are ignored by the caller before this is reached:
/// content is bound by hash, so a query string cannot smuggle different bytes past
/// the check, and ignoring it keeps cache-busting parameters working.
pub fn request_key(raw_pathname: &str) -> Option<String> {
    // Rejected *before* decoding. Decoding these would manufacture path structure
    // that was not present in the URL the browser actually requested.
    let lower = raw_pathname.to_ascii_lowercase();
    for forbidden in ["%2f", "%5c", "%2e%2e", "%00"] {
        if lower.contains(forbidden) {
            return None;
        }
    }

    let decoded = percent_decode(raw_pathname)?;
    let normalized = to_nfc(&decoded);

    if normalized.contains('\\') || normalized.contains("//") || normalized.contains('\0') {
        return None;
    }
    if !normalized.starts_with('/') {
        return None;
    }
    // A trailing slash is a directory-style URL — `/` and `/blog/` are ordinary,
    // legal paths that every static site serves. Only an *interior* empty
    // component is illegal, and the `//` check above already rejects that.
    let components: Vec<&str> = normalized.split('/').collect();
    for (i, component) in components.iter().enumerate() {
        if i == 0 {
            continue; // the empty string before the leading slash
        }
        if *component == "." || *component == ".." {
            return None;
        }
        if component.is_empty() && i != components.len() - 1 {
            return None;
        }
    }
    Some(normalized)
}

/// Resolve a request key to the manifest path that serves it.
///
/// A directory-style URL is served from its index document by essentially every
/// static host, and a manifest lists files, so `/blog/` has to be looked up as
/// `/blog/index.html`.
pub fn index_alias(key: &str) -> Option<String> {
    key.ends_with('/').then(|| format!("{key}index.html"))
}

/// Percent-decoding that fails closed: invalid escapes and non-UTF-8 results are
/// rejected rather than replaced.
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi = (bytes[i + 1] as char).to_digit(16)?;
            let lo = (bytes[i + 2] as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// SPEC §6.4 content-type equivalence classes. Compared on the essence only —
/// media type and subtype, lowercased, parameters stripped.
pub fn content_type_matches(expected: &str, actual: &str) -> bool {
    let e = essence(expected);
    let a = essence(actual);
    if e == a {
        return true;
    }
    const CLASSES: &[&[&str]] = &[
        &[
            "text/javascript",
            "application/javascript",
            "application/x-javascript",
            "text/ecmascript",
            "application/ecmascript",
        ],
        &["application/json", "text/json"],
        &["application/xml", "text/xml"],
        &[
            "application/yaml",
            "text/yaml",
            "application/x-yaml",
            "text/x-yaml",
        ],
    ];
    CLASSES
        .iter()
        .any(|class| class.contains(&e.as_str()) && class.contains(&a.as_str()))
}

fn essence(ct: &str) -> String {
    ct.split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}
