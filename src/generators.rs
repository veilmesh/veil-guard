//! SRI injection, CSP hashes, and server header snippets — SPEC.md §10.

use crate::crypto::sha256;
use crate::html::{scan, splice, HtmlError, Tag};
use crate::paths::request_key;
use std::collections::HashMap;

// ---------------------------------------------------------------- base64
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard alphabet with padding, as the SRI grammar requires.
pub fn base64(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

pub fn sri_value(sha384_hex: &str) -> Result<String, hex::FromHexError> {
    Ok(format!("sha384-{}", base64(&hex::decode(sha384_hex)?)))
}

// ---------------------------------------------------------------- SRI injection
#[derive(Debug, Default)]
pub struct SriReport {
    /// (tag name, resolved manifest key)
    pub applied: Vec<(String, String)>,
    /// Absolute URLs on another origin. SRI cannot cover them; CSP must.
    pub cross_origin: Vec<String>,
    /// Same-origin references that do not correspond to any scanned asset.
    pub unresolved: Vec<String>,
    /// Tags that already carried an `integrity` attribute; left untouched.
    pub preexisting: usize,
}

/// Rewrite one HTML document, adding `integrity` to every same-origin subresource
/// that supports it.
///
/// `page_key` is the document's own manifest key, used to resolve relative URLs.
/// `digests` maps manifest key to SHA-384 hex.
///
/// Every byte outside the inserted attributes is copied through unchanged — the
/// document is never re-serialized (SPEC §10.1).
pub fn inject_sri(
    html: &[u8],
    page_key: &str,
    digests: &HashMap<String, String>,
) -> Result<(Vec<u8>, SriReport), HtmlError> {
    let tags = scan(html)?;
    let mut report = SriReport::default();
    let mut insertions: Vec<(usize, String)> = Vec::new();

    for tag in &tags {
        let Some(url) = sri_target_url(tag) else {
            continue;
        };
        if tag.has_attr("integrity") {
            report.preexisting += 1;
            continue;
        }
        let Some(key) = resolve_same_origin(&url, page_key) else {
            report.cross_origin.push(url);
            continue;
        };
        let Some(hex_digest) = digests.get(&key) else {
            report.unresolved.push(key);
            continue;
        };
        let Ok(value) = sri_value(hex_digest) else {
            report.unresolved.push(key);
            continue;
        };

        insertions.push((tag.gt, format!(" integrity=\"{value}\"")));
        report.applied.push((tag.name.clone(), key));
    }

    Ok((splice(html, &mut insertions), report))
}

/// The subresource URL of a tag that supports `integrity`, if it has one.
///
/// SRI applies to `<script src>` and to `<link>` with `rel` of `stylesheet`,
/// `modulepreload`, or `preload` with `as=script`/`as=style`. Everything else —
/// icons, canonical links, preconnect — is not an integrity-checked subresource.
fn sri_target_url(tag: &Tag) -> Option<String> {
    match tag.name.as_str() {
        "script" => tag.attr("src").map(str::to_string),
        "link" => {
            let rel = tag.attr("rel")?.to_ascii_lowercase();
            let rels: Vec<&str> = rel.split_ascii_whitespace().collect();
            let eligible = rels.contains(&"stylesheet")
                || rels.contains(&"modulepreload")
                || (rels.contains(&"preload")
                    && matches!(
                        tag.attr("as").map(|a| a.to_ascii_lowercase()).as_deref(),
                        Some("script") | Some("style")
                    ));
            if eligible {
                tag.attr("href").map(str::to_string)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Resolve a URL reference to a manifest key, or `None` if it is not same-origin.
fn resolve_same_origin(url: &str, page_key: &str) -> Option<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with('#') {
        return None;
    }
    if let Some(colon) = trimmed.find(':') {
        // A scheme, unless the colon appears after a path separator or query.
        let before = &trimmed[..colon];
        if !before.contains('/') && !before.contains('?') && !before.is_empty() {
            return None;
        }
    }

    let without_query = trimmed
        .split(['?', '#'])
        .next()
        .unwrap_or("");

    let absolute = if let Some(rest) = without_query.strip_prefix('/') {
        format!("/{rest}")
    } else {
        // Relative to the directory holding the page.
        let dir = page_key.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
        let mut parts: Vec<&str> = dir.split('/').filter(|s| !s.is_empty()).collect();
        for component in without_query.split('/') {
            match component {
                "" | "." => {}
                ".." => {
                    parts.pop()?;
                }
                other => parts.push(other),
            }
        }
        format!("/{}", parts.join("/"))
    };

    request_key(&absolute)
}

// ---------------------------------------------------------------- CSP
/// Inline `<script>` types that are data blocks, never executed, and therefore not
/// subject to `script-src`. Everything else gets a hash — including unknown types,
/// because an unnecessary hash is harmless while a missing one breaks the page.
const INERT_SCRIPT_TYPES: &[&str] = &[
    "application/ld+json",
    "application/json",
    "text/plain",
    "text/template",
    "text/x-template",
];

/// SHA-256 hashes of every executable inline script, as CSP `script-src` sources.
///
/// SPEC §10 step 6: computed from the post-splice bytes, so that what is hashed is
/// what actually ships.
pub fn inline_script_hashes(html: &[u8]) -> Result<Vec<String>, HtmlError> {
    let mut out = Vec::new();
    for tag in scan(html)? {
        if tag.name != "script" || tag.has_attr("src") {
            continue;
        }
        let Some((start, end)) = tag.content else {
            continue;
        };
        let ty = tag
            .attr("type")
            .map(|t| t.trim().to_ascii_lowercase())
            .unwrap_or_default();
        if INERT_SCRIPT_TYPES.contains(&ty.as_str()) {
            continue;
        }
        let body = &html[start..end];
        if body.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }
        let value = format!("'sha256-{}'", base64(&sha256(body)));
        if !out.contains(&value) {
            out.push(value);
        }
    }
    Ok(out)
}

/// A `script-src` directive for one page.
pub fn csp_script_src(inline_hashes: &[String]) -> String {
    let mut parts = vec!["'self'".to_string()];
    parts.extend(inline_hashes.iter().cloned());
    format!("script-src {}", parts.join(" "))
}

// ---------------------------------------------------------------- headers
#[derive(Debug, Clone)]
pub struct PageHeaders {
    pub path: String,
    pub csp: String,
}

/// SPEC §2 note: `Integrity-Policy` is header-only — there is no `<meta>` form —
/// so a deployment that cannot set response headers cannot use it at all.
pub const INTEGRITY_POLICY: &str = "Integrity-Policy: blocked-destinations=(script)";
pub const INTEGRITY_POLICY_REPORT_ONLY: &str =
    "Integrity-Policy-Report-Only: blocked-destinations=(script)";

/// Netlify / Cloudflare Pages `_headers`.
pub fn headers_netlify(pages: &[PageHeaders], enforce: bool) -> String {
    let policy = if enforce { INTEGRITY_POLICY } else { INTEGRITY_POLICY_REPORT_ONLY };
    let (name, value) = policy.split_once(": ").expect("well-formed policy");
    let mut out = String::from("# Generated by veil-guard. Start in report-only mode.\n");
    for p in pages {
        out.push_str(&format!("\n{}\n", p.path));
        out.push_str(&format!("  Content-Security-Policy: {}\n", p.csp));
        out.push_str(&format!("  {name}: {value}\n"));
    }
    out
}

pub fn headers_nginx(pages: &[PageHeaders], enforce: bool) -> String {
    let policy = if enforce { INTEGRITY_POLICY } else { INTEGRITY_POLICY_REPORT_ONLY };
    let (name, value) = policy.split_once(": ").expect("well-formed policy");
    let mut out = String::from("# Generated by veil-guard. Include inside the server block.\n");
    for p in pages {
        out.push_str(&format!("\nlocation = {} {{\n", p.path));
        out.push_str(&format!("    add_header Content-Security-Policy \"{}\" always;\n", p.csp));
        out.push_str(&format!("    add_header {name} \"{value}\" always;\n"));
        out.push_str("}\n");
    }
    out
}

pub fn headers_caddy(pages: &[PageHeaders], enforce: bool) -> String {
    let policy = if enforce { INTEGRITY_POLICY } else { INTEGRITY_POLICY_REPORT_ONLY };
    let (name, value) = policy.split_once(": ").expect("well-formed policy");
    let mut out = String::from("# Generated by veil-guard.\n");
    for p in pages {
        out.push_str(&format!("\n@page{} path {}\nheader @page{} {{\n", sanitize(&p.path), p.path, sanitize(&p.path)));
        out.push_str(&format!("    Content-Security-Policy \"{}\"\n", p.csp));
        out.push_str(&format!("    {name} \"{value}\"\n"));
        out.push_str("}\n");
    }
    out
}

fn sanitize(path: &str) -> String {
    path.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}
