//! Scanner, HTML locator and generator tests — SPEC.md §7, §10.

use std::collections::HashMap;
use veil_guard::generators::*;
use veil_guard::html::*;
use veil_guard::scanner::*;

fn digests(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

const D: &str =
    "aa00bb11cc22dd33ee44ff5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677";

// ------------------------------------------------------------------ html locator
#[test]
fn finds_script_and_link_tags() {
    let html = br#"<html><head><link rel="stylesheet" href="/a.css"><script type="module" src="/a.js"></script></head></html>"#;
    let tags = scan(html).unwrap();
    assert_eq!(tags.len(), 2);
    assert_eq!(tags[0].name, "link");
    assert_eq!(tags[0].attr("href"), Some("/a.css"));
    assert_eq!(tags[1].attr("src"), Some("/a.js"));
    assert_eq!(tags[1].attr("type"), Some("module"));
}

#[test]
fn ignores_tags_inside_comments() {
    let html = br#"<head><!-- <script src="/evil.js"></script> --><link rel="stylesheet" href="/a.css"></head>"#;
    let tags = scan(html).unwrap();
    assert_eq!(
        tags.len(),
        1,
        "the commented-out script must not be reported"
    );
    assert_eq!(tags[0].name, "link");
}

#[test]
fn ignores_markup_inside_script_bodies() {
    // A '<' inside a JavaScript string is not markup. Reading it as markup would
    // put a splice offset in the middle of someone's code.
    let html = br#"<script>const s = "<link rel=stylesheet href=/evil.css>"; if (a<b) {}</script><link rel="stylesheet" href="/real.css">"#;
    let tags = scan(html).unwrap();
    assert_eq!(tags.len(), 2);
    assert_eq!(tags[0].name, "script");
    assert_eq!(tags[1].attr("href"), Some("/real.css"));
}

#[test]
fn quoted_attribute_values_may_contain_gt() {
    let html = br#"<link rel="stylesheet" title="a > b" href="/a.css">"#;
    let tags = scan(html).unwrap();
    assert_eq!(tags.len(), 1);
    assert_eq!(tags[0].attr("title"), Some("a > b"));
    assert_eq!(tags[0].attr("href"), Some("/a.css"));
    assert_eq!(tags[0].end, html.len(), "the tag must end at the real '>'");
}

#[test]
fn close_tag_must_match_exactly() {
    let html = br#"<script>var x = "</scriptfoo>";</script><link rel="stylesheet" href="/a.css">"#;
    let tags = scan(html).unwrap();
    assert_eq!(tags.len(), 2, "`</scriptfoo` must not terminate a script");
}

#[test]
fn handles_quoting_styles_and_entities() {
    let html = br#"<link rel=stylesheet href='/a.css?x=1&amp;y=2'><script src=/b.js></script>"#;
    let tags = scan(html).unwrap();
    assert_eq!(tags[0].attr("rel"), Some("stylesheet"));
    assert_eq!(tags[0].attr("href"), Some("/a.css?x=1&y=2"));
    assert_eq!(tags[1].attr("src"), Some("/b.js"));
}

#[test]
fn malformed_input_fails_closed() {
    assert!(matches!(
        scan(br#"<link rel="stylesheet" href="/a.css""#),
        Err(HtmlError::UnterminatedTag(_))
    ));
    assert!(matches!(
        scan(br#"<!-- never closed"#),
        Err(HtmlError::UnterminatedComment(_))
    ));
    assert!(matches!(
        scan(br#"<script>forever"#),
        Err(HtmlError::UnterminatedRawText(_))
    ));
}

#[test]
fn doctype_and_bare_angle_brackets_are_not_tags() {
    let html = b"<!DOCTYPE html><p>5 < 6 and 7 > 4</p><link rel=\"stylesheet\" href=\"/a.css\">";
    let tags = scan(html).unwrap();
    assert_eq!(tags.len(), 1);
}

#[test]
fn splice_only_inserts() {
    let original = b"<a><b><c>";
    let mut ins = vec![(3usize, " X".to_string()), (6usize, " Y".to_string())];
    let out = splice(original, &mut ins);
    assert_eq!(out, b"<a> X<b> Y<c>");
    // Removing the insertions restores the original exactly.
    let restored: Vec<u8> = String::from_utf8(out)
        .unwrap()
        .replace(" X", "")
        .replace(" Y", "")
        .into_bytes();
    assert_eq!(restored, original);
}

// ------------------------------------------------------------------ SRI targeting
#[test]
fn targets_only_integrity_capable_subresources() {
    let html = br#"<head>
<link rel="icon" href="/favicon.svg">
<link rel="canonical" href="/">
<link rel="preconnect" href="https://fonts.example">
<link rel="stylesheet" href="/a.css">
<link rel="modulepreload" href="/m.js">
<link rel="preload" as="script" href="/p.js">
<link rel="preload" as="font" href="/f.woff2">
<script src="/a.js"></script>
<script>inline()</script>
</head>"#;
    let d = digests(&[
        ("/favicon.svg", D),
        ("/a.css", D),
        ("/m.js", D),
        ("/p.js", D),
        ("/f.woff2", D),
        ("/a.js", D),
    ]);
    let (_, report) = inject_sri(html, "/index.html", &d).unwrap();
    let keys: Vec<&str> = report.applied.iter().map(|(_, k)| k.as_str()).collect();
    assert_eq!(keys, vec!["/a.css", "/m.js", "/p.js", "/a.js"]);
    assert!(report.cross_origin.is_empty());
}

#[test]
fn cross_origin_is_reported_not_rewritten() {
    let html = br#"<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">
<link rel="stylesheet" href="//cdn.example/x.css">"#;
    let (out, report) = inject_sri(html, "/index.html", &digests(&[])).unwrap();
    assert_eq!(out, html, "cross-origin references must be left alone");
    assert_eq!(report.cross_origin.len(), 2);
    assert!(report.applied.is_empty());
}

#[test]
fn relative_urls_resolve_against_the_page() {
    let html =
        br#"<script src="../assets/app.js"></script><link rel="stylesheet" href="./local.css">"#;
    let d = digests(&[("/assets/app.js", D), ("/blog/local.css", D)]);
    let (_, report) = inject_sri(html, "/blog/post.html", &d).unwrap();
    let keys: Vec<&str> = report.applied.iter().map(|(_, k)| k.as_str()).collect();
    assert_eq!(keys, vec!["/assets/app.js", "/blog/local.css"]);
}

#[test]
fn existing_integrity_is_left_alone() {
    let html = br#"<script src="/a.js" integrity="sha384-existing"></script>"#;
    let (out, report) = inject_sri(html, "/index.html", &digests(&[("/a.js", D)])).unwrap();
    assert_eq!(out, html);
    assert_eq!(report.preexisting, 1);
    assert!(report.applied.is_empty());
}

#[test]
fn unresolved_same_origin_reference_is_reported() {
    let html = br#"<script src="/missing.js"></script>"#;
    let (out, report) = inject_sri(html, "/index.html", &digests(&[])).unwrap();
    assert_eq!(out, html);
    assert_eq!(report.unresolved, vec!["/missing.js"]);
}

#[test]
fn query_strings_are_stripped_when_resolving() {
    let html = br#"<script src="/a.js?v=2"></script>"#;
    let (_, report) = inject_sri(html, "/index.html", &digests(&[("/a.js", D)])).unwrap();
    assert_eq!(report.applied.len(), 1);
}

#[test]
fn injection_is_a_pure_insertion() {
    let html = br#"<!doctype html>
<html><head><link rel="stylesheet" crossorigin="" href="/a.css">
<script type="module" crossorigin="" src="/a.js"></script></head>
<body><div id="app">hydrated content</div></body></html>"#;
    let (out, _) = inject_sri(
        html,
        "/index.html",
        &digests(&[("/a.css", D), ("/a.js", D)]),
    )
    .unwrap();

    let sri = sri_value(D).unwrap();
    let stripped = String::from_utf8(out)
        .unwrap()
        .replace(&format!(" integrity=\"{sri}\""), "");
    assert_eq!(
        stripped.as_bytes(),
        html,
        "every byte outside the inserted attributes must be untouched"
    );
}

// ------------------------------------------------------------------ CSP
#[test]
fn inline_hashes_skip_data_blocks_and_empty_scripts() {
    let html = br#"<script type="application/ld+json">{"@type":"WebSite"}</script>
<script>real()</script>
<script type="module">alsoReal()</script>
<script src="/external.js"></script>
<script>   </script>"#;
    let hashes = inline_script_hashes(html).unwrap();
    assert_eq!(
        hashes.len(),
        2,
        "ld+json, external and whitespace-only are excluded"
    );
    assert!(hashes
        .iter()
        .all(|h| h.starts_with("'sha256-") && h.ends_with('\'')));
}

#[test]
fn unknown_script_types_are_hashed_conservatively() {
    // An unnecessary hash is harmless; a missing one breaks the page under CSP.
    let html = br#"<script type="importmap">{"imports":{}}</script>"#;
    assert_eq!(inline_script_hashes(html).unwrap().len(), 1);
}

#[test]
fn identical_inline_scripts_are_deduplicated() {
    let html = br#"<script>same()</script><script>same()</script>"#;
    assert_eq!(inline_script_hashes(html).unwrap().len(), 1);
}

#[test]
fn base64_and_sri_encoding() {
    assert_eq!(base64(b""), "");
    assert_eq!(base64(b"f"), "Zg==");
    assert_eq!(base64(b"fo"), "Zm8=");
    assert_eq!(base64(b"foo"), "Zm9v");
    assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    assert!(sri_value(D).unwrap().starts_with("sha384-"));
}

#[test]
fn csp_directive_shape() {
    let csp = csp_script_src(&["'sha256-abc'".into()], &[]);
    assert_eq!(csp, "script-src 'self' 'sha256-abc'");
}

#[test]
fn csp_extra_sources_are_appended_and_deduplicated() {
    // A tag manager: the inline bootstrap is hashed from the built page, but the
    // host it injects from appears nowhere in dist and has to be named.
    let csp = csp_script_src(
        &["'sha256-abc'".into()],
        &[
            "https://www.googletagmanager.com".into(),
            "https://www.googletagmanager.com".into(),
            "'self'".into(),
        ],
    );
    assert_eq!(
        csp,
        "script-src 'self' 'sha256-abc' https://www.googletagmanager.com"
    );
}

// ------------------------------------------------------------------ scanner
#[test]
fn content_types_match_the_spec_spellings() {
    assert_eq!(content_type_for("/a.js"), "text/javascript");
    assert_eq!(content_type_for("/a.mjs"), "text/javascript");
    assert_eq!(content_type_for("/a.wasm"), "application/wasm");
    assert_eq!(content_type_for("/a.css"), "text/css");
    assert_eq!(content_type_for("/a.html"), "text/html");
    assert_eq!(content_type_for("/a.unknown"), "application/octet-stream");
    assert_eq!(content_type_for("/NoExtension"), "application/octet-stream");
}

#[test]
fn scan_normalizes_excludes_and_sorts() {
    let tmp = std::env::temp_dir().join(format!("vg-scan-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("assets")).unwrap();
    std::fs::create_dir_all(tmp.join(".vite")).unwrap();
    std::fs::write(tmp.join("index.html"), b"<html></html>").unwrap();
    std::fs::write(tmp.join("assets/app.js"), b"x").unwrap();
    std::fs::write(tmp.join(".DS_Store"), b"junk").unwrap();
    std::fs::write(tmp.join(".vite/ssr-manifest.json"), b"{}").unwrap();

    let assets = scan_dist(&tmp).unwrap();
    let keys: Vec<&str> = assets.iter().map(|a| a.key.as_str()).collect();
    assert_eq!(
        keys,
        vec!["/assets/app.js", "/index.html"],
        "sorted, residue excluded"
    );
    assert!(assets[0].sha256.len() == 64 && assets[0].sha384.len() == 96);

    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn scan_rejects_symlinks() {
    #[cfg(unix)]
    {
        let tmp = std::env::temp_dir().join(format!("vg-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("real.js"), b"x").unwrap();
        std::os::unix::fs::symlink(tmp.join("real.js"), tmp.join("link.js")).unwrap();

        assert!(
            matches!(scan_dist(&tmp), Err(ScanError::Symlink(_))),
            "a symlink in dist must stop the build, not be silently followed"
        );
        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
