//! A fail-closed byte-offset locator for `<script>` and `<link>` tags.
//!
//! SPEC.md §10.1 requires that HTML be modified by splicing into the original byte
//! buffer, never by parsing to a tree and serializing back. This module therefore
//! reports *offsets* and never produces markup of its own.
//!
//! It is deliberately not a general HTML parser. It understands exactly the
//! constructs that a generated document contains, and returns an error — rather
//! than a guess — for anything else. A wrong offset here would splice bytes into
//! the middle of someone's markup, so ambiguity must stop the build.

#[derive(Debug, PartialEq, Eq)]
pub enum HtmlError {
    UnterminatedTag(usize),
    UnterminatedComment(usize),
    UnterminatedRawText(usize),
    MalformedAttribute(usize),
}

impl std::fmt::Display for HtmlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (what, at) = match self {
            HtmlError::UnterminatedTag(o) => ("unterminated tag", o),
            HtmlError::UnterminatedComment(o) => ("unterminated comment", o),
            HtmlError::UnterminatedRawText(o) => ("unterminated script/style element", o),
            HtmlError::MalformedAttribute(o) => ("malformed attribute", o),
        };
        write!(f, "{what} at byte {at}")
    }
}

impl std::error::Error for HtmlError {}

#[derive(Debug, Clone)]
pub struct Attr {
    /// Lowercased attribute name.
    pub name: String,
    /// Attribute value with character references resolved.
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct Tag {
    /// Lowercased element name; only `script` and `link` are reported.
    pub name: String,
    /// Offset of the opening `<`.
    pub start: usize,
    /// Offset just past the closing `>` of the start tag.
    pub end: usize,
    /// Offset of the `>` that closes the start tag — the splice point.
    pub gt: usize,
    pub attrs: Vec<Attr>,
    /// For `<script>` without `src`: the byte span of its raw text content.
    pub content: Option<(usize, usize)>,
}

impl Tag {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.value.as_str())
    }

    pub fn has_attr(&self, name: &str) -> bool {
        self.attrs.iter().any(|a| a.name == name)
    }
}

/// Locate every `<script>` and `<link>` start tag in `html`.
///
/// Comments and the raw-text content of `<script>`/`<style>` are skipped, so a
/// `<link>` written inside a JavaScript string or an HTML comment is not reported.
pub fn scan(html: &[u8]) -> Result<Vec<Tag>, HtmlError> {
    let mut tags = Vec::new();
    let mut i = 0usize;

    while i < html.len() {
        if html[i] != b'<' {
            i += 1;
            continue;
        }

        // Comment, doctype, CDATA, or other markup declaration.
        if html[i..].starts_with(b"<!--") {
            let end = find(html, i + 4, b"-->").ok_or(HtmlError::UnterminatedComment(i))?;
            i = end + 3;
            continue;
        }
        if html[i..].starts_with(b"<!") || html[i..].starts_with(b"<?") {
            let end = memchr(html, i, b'>').ok_or(HtmlError::UnterminatedTag(i))?;
            i = end + 1;
            continue;
        }
        // Closing tag.
        if html[i..].starts_with(b"</") {
            let end = memchr(html, i, b'>').ok_or(HtmlError::UnterminatedTag(i))?;
            i = end + 1;
            continue;
        }

        let Some(name) = element_name(html, i + 1) else {
            i += 1; // a bare '<' in text
            continue;
        };

        let (attrs, gt, self_closing) = parse_attributes(html, i + 1 + name.len())?;
        let mut tag = Tag {
            name: name.clone(),
            start: i,
            end: gt + 1,
            gt,
            attrs,
            content: None,
        };

        // script and style hold raw text: their content must be skipped wholesale,
        // or a '<' inside a JavaScript string would be read as markup.
        let is_raw_text = name == "script" || name == "style";
        if is_raw_text && !self_closing {
            let close =
                find_close_tag(html, gt + 1, &name).ok_or(HtmlError::UnterminatedRawText(i))?;
            if name == "script" {
                tag.content = Some((gt + 1, close));
            }
            i = close;
        } else {
            i = gt + 1;
        }

        if name == "script" || name == "link" {
            tags.push(tag);
        }
    }

    Ok(tags)
}

fn element_name(html: &[u8], at: usize) -> Option<String> {
    let mut end = at;
    while end < html.len() && (html[end].is_ascii_alphanumeric() || html[end] == b'-') {
        end += 1;
    }
    if end == at || !html[at].is_ascii_alphabetic() {
        return None;
    }
    Some(String::from_utf8_lossy(&html[at..end]).to_ascii_lowercase())
}

/// Returns the attributes, the offset of the closing `>`, and whether the tag was
/// written as self-closing.
fn parse_attributes(html: &[u8], mut i: usize) -> Result<(Vec<Attr>, usize, bool), HtmlError> {
    let start = i;
    let mut attrs = Vec::new();
    let mut self_closing = false;

    loop {
        while i < html.len() && html[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= html.len() {
            return Err(HtmlError::UnterminatedTag(start));
        }
        if html[i] == b'>' {
            return Ok((attrs, i, self_closing));
        }
        if html[i] == b'/' {
            self_closing = true;
            i += 1;
            continue;
        }

        let name_start = i;
        while i < html.len()
            && !html[i].is_ascii_whitespace()
            && !matches!(html[i], b'=' | b'>' | b'/')
        {
            i += 1;
        }
        if i == name_start {
            return Err(HtmlError::MalformedAttribute(i));
        }
        let name = String::from_utf8_lossy(&html[name_start..i]).to_ascii_lowercase();

        while i < html.len() && html[i].is_ascii_whitespace() {
            i += 1;
        }

        let value = if i < html.len() && html[i] == b'=' {
            i += 1;
            while i < html.len() && html[i].is_ascii_whitespace() {
                i += 1;
            }
            if i >= html.len() {
                return Err(HtmlError::UnterminatedTag(start));
            }
            match html[i] {
                q @ (b'"' | b'\'') => {
                    // A quoted value may legitimately contain '>', which is exactly
                    // why this cannot be done by searching for the next '>'.
                    let vs = i + 1;
                    let ve = memchr(html, vs, q).ok_or(HtmlError::UnterminatedTag(start))?;
                    i = ve + 1;
                    decode_entities(&html[vs..ve])
                }
                _ => {
                    let vs = i;
                    while i < html.len() && !html[i].is_ascii_whitespace() && html[i] != b'>' {
                        i += 1;
                    }
                    decode_entities(&html[vs..i])
                }
            }
        } else {
            String::new()
        };

        attrs.push(Attr { name, value });
    }
}

/// Find the matching `</name` for a raw-text element, returning the offset of `<`.
fn find_close_tag(html: &[u8], from: usize, name: &str) -> Option<usize> {
    let needle = format!("</{name}");
    let n = needle.as_bytes();
    let mut i = from;
    while i + n.len() <= html.len() {
        if html[i] == b'<' && html[i..i + n.len()].eq_ignore_ascii_case(n) {
            // Must be followed by whitespace or '>', so that `</scriptfoo` does not
            // terminate a `<script>`.
            let after = html.get(i + n.len());
            if matches!(after, Some(b'>') | Some(b'/') | None)
                || after.is_some_and(|c| c.is_ascii_whitespace())
            {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Resolve the character references a generated document can actually contain.
fn decode_entities(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    if !s.contains('&') {
        return s.into_owned();
    }
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        // Ampersand last, so that "&amp;lt;" does not become "<".
        .replace("&amp;", "&")
}

fn memchr(hay: &[u8], from: usize, needle: u8) -> Option<usize> {
    hay.iter()
        .skip(from)
        .position(|&b| b == needle)
        .map(|p| p + from)
}

fn find(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if from >= hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// Splice `insertions` — `(offset, text)` pairs — into `original`.
///
/// This is the only way this crate is permitted to modify HTML: every byte that is
/// not at an insertion point is copied through unchanged.
pub fn splice(original: &[u8], insertions: &mut [(usize, String)]) -> Vec<u8> {
    insertions.sort_by_key(|(at, _)| *at);
    let added: usize = insertions.iter().map(|(_, s)| s.len()).sum();
    let mut out = Vec::with_capacity(original.len() + added);
    let mut cursor = 0usize;
    for (at, text) in insertions.iter() {
        out.extend_from_slice(&original[cursor..*at]);
        out.extend_from_slice(text.as_bytes());
        cursor = *at;
    }
    out.extend_from_slice(&original[cursor..]);
    out
}
