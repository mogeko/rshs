//! WebDAV protocol types (locks, properties, depth, conditions), XML parsing
//! helpers, `If`/`Lock-Token`/`Timeout`/`Depth` header parsers, and filesystem
//! traversal utilities.

pub mod fs;
pub mod ls;
pub mod method;
pub mod xml;

use std::collections::HashMap;
use std::fmt;
use std::fs::Metadata;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::HeaderMap;
use percent_encoding::percent_decode_str;
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

use crate::scandir::DirEntryMeta;

pub use ls::{IfCondition, IfList, parse_if_header};
pub use method::Method;
pub use xml::{El, XmlWriter, XmlWriterExt};

/// Per-resource dead property store: resource path → (prop name → value).
pub type DeadPropertyStore = HashMap<PathBuf, HashMap<String, String>>;

/// A single PROPPATCH action: property name and optional new value
/// (`None` indicates removal).
#[derive(Debug, Clone)]
pub struct PropPatchAction(pub String, pub Option<String>);

/// A parsed PROPPATCH request body containing a sequence of set/remove actions.
#[derive(Debug, Clone)]
pub struct PropPatchOp {
    pub actions: Vec<PropPatchAction>,
}

/// PROPFIND traversal depth.
///
/// ```
/// use rshs::webdav::Depth;
///
/// assert_eq!(Depth::Zero.to_string(), "0");
/// assert_eq!(Depth::Infinity.to_string(), "infinity");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Depth {
    /// Only the resource itself.
    Zero,
    /// The resource and its immediate children.
    One,
    /// The resource and all descendants.
    Infinity,
}

impl fmt::Display for Depth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => "0".fmt(f),
            Self::One => "1".fmt(f),
            Self::Infinity => "infinity".fmt(f),
        }
    }
}

/// Body of a PROPFIND request.
///
/// ```
/// use rshs::webdav::PropRequest;
///
/// let all = PropRequest::AllProp;
/// let named = PropRequest::Named(vec!["getcontentlength".into(), "getetag".into()]);
/// ```
#[derive(Debug, Clone)]
pub enum PropRequest {
    /// `<D:allprop/>` — request all live properties.
    AllProp,
    /// `<D:propname/>` — request property names only.
    PropName,
    /// Request specific named properties (as Clark-notation keys).
    Named(Vec<String>),
}

/// A single resource entry in a PROPFIND multistatus response.
///
/// Holds the resource href, live property values, optional dead properties,
/// and optional active lock information.
///
/// ```
/// use std::time::UNIX_EPOCH;
/// use rshs::webdav::PropEntry;
///
/// let e = PropEntry {
///     href: "/docs/readme.md".into(),
///     modified: UNIX_EPOCH,
///     created: None,
///     size: 1024,
///     is_dir: false,
///     content_type: Some("text/markdown".into()),
///     dead_props: None,
///     active_locks: None,
///     canonical_path: None,
/// };
/// assert!(!e.is_dir);
/// assert_eq!(e.size, 1024);
/// ```
#[derive(Debug, Clone)]
pub struct PropEntry {
    pub href: String,
    pub modified: SystemTime,
    pub created: Option<SystemTime>,
    pub size: u64,
    pub is_dir: bool,
    pub content_type: Option<String>,
    pub dead_props: Option<HashMap<String, String>>,
    pub active_locks: Option<Vec<LockInfo>>,
    pub canonical_path: Option<PathBuf>,
}

impl PropEntry {
    /// Create a `PropEntry` from `std::fs::Metadata`.
    ///
    /// ```
    /// use std::fs;
    /// use rshs::webdav::PropEntry;
    ///
    /// let meta = fs::metadata("Cargo.toml").unwrap();
    /// let entry = PropEntry::from_meta(&meta, "/Cargo.toml".into(), false);
    /// assert!(entry.size > 0);
    /// ```
    pub fn from_meta(meta: &Metadata, href: String, is_dir: bool) -> Self {
        PropEntry {
            href,
            modified: meta.modified().unwrap_or(UNIX_EPOCH),
            created: meta.created().ok(),
            size: meta.len(),
            is_dir,
            content_type: None,
            dead_props: None,
            active_locks: None,
            canonical_path: None,
        }
    }

    /// Create a `PropEntry` from a [`scandir::DirEntryMeta`] and an href.
    ///
    /// The remaining WebDAV fields (`content_type`, `dead_props`,
    /// `active_locks`, `canonical_path`) are left at `None` — callers
    /// set them afterwards as needed.
    pub(crate) fn from_dirent(meta: &DirEntryMeta, href: String) -> Self {
        PropEntry {
            href,
            modified: meta.modified,
            created: meta.created,
            size: meta.size,
            is_dir: meta.is_dir,
            content_type: None,
            dead_props: None,
            active_locks: None,
            canonical_path: None,
        }
    }
}

/// In-memory lock store: resource path → active locks.
pub type LockStore = HashMap<PathBuf, Vec<LockInfo>>;

/// A WebDAV lock (RFC 4918 §6).
///
/// ```
/// use std::time::{SystemTime, Duration};
/// use rshs::webdav::{LockInfo, LockScope, Depth};
///
/// let lock = LockInfo {
///     scope: LockScope::Exclusive,
///     token: "opaquelocktoken:abc123".into(),
///     owner: Some("user@example.com".into()),
///     created: SystemTime::now(),
///     timeout: Some(Duration::from_secs(3600)),
///     depth: Depth::Zero,
/// };
/// assert!(lock.is_exclusive());
/// assert!(!lock.is_expired());
/// ```
#[derive(Debug, Clone)]
pub struct LockInfo {
    pub scope: LockScope,
    pub token: String,
    pub owner: Option<String>,
    pub created: SystemTime,
    pub timeout: Option<Duration>,
    pub depth: Depth,
}

impl LockInfo {
    /// Whether the lock has expired.
    ///
    /// A lock without a timeout never expires.
    ///
    /// ```
    /// use std::time::{SystemTime, Duration};
    /// use rshs::webdav::{LockInfo, LockScope, Depth};
    ///
    /// let active = LockInfo {
    ///     scope: LockScope::Exclusive,
    ///     token: "t1".into(),
    ///     owner: None,
    ///     created: SystemTime::now(),
    ///     timeout: Some(Duration::from_secs(3600)),
    ///     depth: Depth::Zero,
    /// };
    /// assert!(!active.is_expired());
    ///
    /// let no_timeout = LockInfo {
    ///     scope: LockScope::Exclusive,
    ///     token: "t2".into(),
    ///     owner: None,
    ///     created: SystemTime::now() - Duration::from_secs(99999),
    ///     timeout: None,
    ///     depth: Depth::Zero,
    /// };
    /// assert!(!no_timeout.is_expired());
    /// ```
    pub fn is_expired(&self) -> bool {
        let Some(timeout) = self.timeout else {
            return false;
        };
        self.created.elapsed().unwrap_or_default() >= timeout
    }

    /// Whether the lock has exclusive scope.
    ///
    /// ```
    /// use std::time::SystemTime;
    /// use rshs::webdav::{LockInfo, LockScope, Depth};
    ///
    /// let lock = LockInfo {
    ///     scope: LockScope::Shared,
    ///     token: "t".into(),
    ///     owner: None,
    ///     created: SystemTime::now(),
    ///     timeout: None,
    ///     depth: Depth::Zero,
    /// };
    /// assert!(!lock.is_exclusive());
    /// ```
    pub fn is_exclusive(&self) -> bool {
        matches!(self.scope, LockScope::Exclusive)
    }
}

/// Lock scope: exclusive (write) or shared (read).
///
/// ```
/// use rshs::webdav::LockScope;
///
/// let s = LockScope::Shared;
/// let e = LockScope::Exclusive;
/// ```
#[derive(Debug, Clone, Copy)]
pub enum LockScope {
    Exclusive,
    Shared,
}

/// Generate a new unique lock token string (`opaquelocktoken:`-prefixed hex).
///
/// ```
/// use rshs::webdav::generate_lock_token;
///
/// let t = generate_lock_token();
/// assert!(t.starts_with("opaquelocktoken:"));
/// ```
pub fn generate_lock_token() -> String {
    use std::hash::{Hash, Hasher};
    use std::time::UNIX_EPOCH;
    let nanos = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    nanos.hash(&mut h);
    format!("opaquelocktoken:{:016x}", h.finish())
}

/// Extract a lock token from the `Lock-Token` header.
///
/// Returns the bare token string (without `<` `>` brackets).
///
/// ```
/// use axum::http::HeaderMap;
/// use rshs::webdav::parse_lock_token_header;
///
/// let mut h = HeaderMap::new();
/// h.insert("lock-token", "<opaquelocktoken:abc>".parse().unwrap());
/// assert_eq!(parse_lock_token_header(&h).unwrap(), "opaquelocktoken:abc");
/// ```
pub fn parse_lock_token_header(headers: &HeaderMap) -> Option<String> {
    let value = headers.get("lock-token")?.to_str().ok()?;
    value
        .trim_matches('<')
        .trim_matches('>')
        .trim()
        .to_string()
        .into()
}

/// Parse the `Timeout` header to a `Duration`.
///
/// Recognises the `Second-<N>` syntax (RFC 4918 §10.7).
///
/// ```
/// use axum::http::HeaderMap;
/// use std::time::Duration;
/// use rshs::webdav::parse_timeout;
///
/// let mut h = HeaderMap::new();
/// h.insert("timeout", "Second-3600".parse().unwrap());
/// assert_eq!(parse_timeout(&h), Some(Duration::from_secs(3600)));
/// ```
pub fn parse_timeout(headers: &HeaderMap) -> Option<std::time::Duration> {
    let value = headers.get("timeout")?.to_str().ok()?;
    let seconds = value
        .strip_prefix("Second-")
        .and_then(|s| s.parse::<u64>().ok())?;
    Some(std::time::Duration::from_secs(seconds))
}

/// Parse the `Depth` header.
///
/// ```
/// use axum::http::HeaderMap;
/// use rshs::webdav::{parse_depth, Depth};
///
/// let h = HeaderMap::new();
/// assert_eq!(parse_depth(&h), Depth::Infinity); // default
///
/// let mut h = HeaderMap::new();
/// h.insert("depth", "0".parse().unwrap());
/// assert_eq!(parse_depth(&h), Depth::Zero);
///
/// let mut h = HeaderMap::new();
/// h.insert("depth", "1".parse().unwrap());
/// assert_eq!(parse_depth(&h), Depth::One);
/// ```
pub fn parse_depth(headers: &HeaderMap) -> Depth {
    let depth = headers.get("depth");
    match depth.and_then(|v| v.to_str().ok()).unwrap_or("infinity") {
        "0" => Depth::Zero,
        "1" => Depth::One,
        _ => Depth::Infinity,
    }
}

/// Errors returned by WebDAV XML body parsing functions.
#[derive(Debug)]
pub enum ParseError {
    InvalidBody(&'static str),
    Xml(quick_xml::Error),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Xml(e) => write!(f, "XML parse error: {e}"),
            Self::InvalidBody(s) => write!(f, "invalid body: {s}"),
        }
    }
}

impl From<quick_xml::Error> for ParseError {
    fn from(e: quick_xml::Error) -> Self {
        Self::Xml(e)
    }
}

/// Build a Clark notation key from namespace and local name.
///
/// ```
/// use rshs::webdav::clark_key;
///
/// assert_eq!(clark_key("http://example.com", "prop0"), "{http://example.com}prop0");
/// assert_eq!(clark_key("", "prop0"), "prop0");
/// ```
pub fn clark_key(ns: &str, local: &str) -> String {
    if ns.is_empty() {
        local.to_string()
    } else {
        format!("{{{}}}{}", ns, local)
    }
}

/// Parse a Clark notation key into (namespace, localname).
///
/// ```
/// use rshs::webdav::parse_clark;
///
/// assert_eq!(
///     parse_clark("{http://example.com}prop0"),
///     Some(("http://example.com", "prop0"))
/// );
/// assert_eq!(parse_clark("prop0"), Some(("", "prop0")));
/// assert_eq!(parse_clark("{broken"), None);
/// ```
pub fn parse_clark(key: &str) -> Option<(&str, &str)> {
    if let Some(rest) = key.strip_prefix('{') {
        let (ns, local) = rest.split_once('}')?;
        Some((ns, local))
    } else {
        Some(("", key))
    }
}

fn extract_element_ns(e: &BytesStart) -> Result<(String, String), ParseError> {
    let qname = e.name();
    let name = qname.as_ref();
    let (prefix, local) = match name.iter().position(|&b| b == b':') {
        Some(pos) => (
            Some(String::from_utf8_lossy(&name[..pos]).to_string()),
            String::from_utf8_lossy(&name[pos + 1..]).to_string(),
        ),
        None => (None, String::from_utf8_lossy(name).to_string()),
    };
    let ns = match prefix {
        Some(ref p) => {
            let key = format!("xmlns:{}", p);
            let attr = e
                .attributes()
                .flatten()
                .find(|a| String::from_utf8_lossy(a.key.as_ref()) == key);
            match attr {
                Some(a) => {
                    let value = String::from_utf8_lossy(&a.value);
                    if value.is_empty() {
                        return Err(ParseError::InvalidBody(
                            "invalid namespace declaration: empty URI",
                        ));
                    }
                    value.to_string()
                }
                None => String::new(),
            }
        }
        None => e
            .attributes()
            .flatten()
            .find(|a| a.key.as_ref() == b"xmlns")
            .map(|a| String::from_utf8_lossy(&a.value).to_string())
            .unwrap_or_default(),
    };
    Ok((ns, local))
}

/// Parse a PROPFIND request body.
///
/// Detects `<allprop/>`, `<propname/>`, or named `<prop>` elements and returns
/// the appropriate `PropRequest` variant.
///
/// # Errors
///
/// Returns a [`ParseError`] if the XML is malformed, contains invalid UTF-8,
/// or has an unsupported document structure.
///
/// ```
/// use rshs::webdav::{parse_propfind_request, PropRequest};
///
/// let all = parse_propfind_request(
///     br#"<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>"#
/// ).unwrap();
/// assert!(matches!(all, PropRequest::AllProp));
///
/// let named = parse_propfind_request(
///     br#"<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop><D:getcontentlength/></D:prop></D:propfind>"#
/// ).unwrap();
/// assert!(matches!(named, PropRequest::Named(_)));
/// ```
pub fn parse_propfind_request(xml: &[u8]) -> Result<PropRequest, ParseError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);

    let mut props = Vec::new();
    let mut in_prop = false;
    let mut found_allprop = false;
    let mut found_propname = false;
    let mut seen_element = false;

    loop {
        match reader.read_event()? {
            Event::Start(e) | Event::Empty(e) => {
                seen_element = true;
                let (ns, local) = extract_element_ns(&e)?;
                let name = local.as_bytes();
                match name {
                    b"prop" => in_prop = true,
                    b"allprop" => found_allprop = true,
                    b"propname" => found_propname = true,
                    _ if in_prop => {
                        props.push(clark_key(&ns, &local));
                    }
                    _ => {}
                }
            }
            Event::End(e) => {
                let local_name = e.local_name();
                let local = String::from_utf8_lossy(local_name.as_ref());
                if local == "prop" {
                    in_prop = false;
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    if found_allprop || (props.is_empty() && !seen_element) {
        Ok(PropRequest::AllProp)
    } else if props.is_empty() && seen_element {
        Err(ParseError::InvalidBody("invalid PROPFIND request body"))
    } else if found_propname {
        Ok(PropRequest::PropName)
    } else {
        Ok(PropRequest::Named(props))
    }
}

/// Extract the path from a `Destination` header (full URL → decoded path).
///
/// Trailing slashes are stripped for COPY/MOVE compatibility with litmus.
///
/// ```
/// use axum::http::HeaderMap;
/// use rshs::webdav::parse_destination;
///
/// let mut h = HeaderMap::new();
/// h.insert("destination", "http://localhost:8080/docs/file.txt".parse().unwrap());
/// assert_eq!(parse_destination(&h).unwrap(), "/docs/file.txt");
///
/// let mut h = HeaderMap::new();
/// h.insert("destination", "/docs/".parse().unwrap());
/// assert_eq!(parse_destination(&h).unwrap(), "/docs");
/// ```
pub fn parse_destination(headers: &HeaderMap) -> Option<String> {
    let value = headers.get("destination")?.to_str().ok()?;
    let mut path = if let Some(pos) = value.find("://") {
        let after_scheme = &value[pos + 3..];
        if let Some(slash_pos) = after_scheme.find('/') {
            percent_decode_str(&after_scheme[slash_pos..])
                .decode_utf8_lossy()
                .to_string()
        } else {
            return None;
        }
    } else if value.starts_with('/') {
        percent_decode_str(value).decode_utf8_lossy().to_string()
    } else {
        return None;
    };
    path.truncate(path.trim_end_matches('/').len());
    Some(path)
}

/// Parse the `Overwrite` header (`"T"` → `true`, `"F"` → `false`).
///
/// Defaults to `true` when the header is absent.
///
/// ```
/// use axum::http::HeaderMap;
/// use rshs::webdav::parse_overwrite;
///
/// assert!(parse_overwrite(&HeaderMap::new())); // default
///
/// let mut h = HeaderMap::new();
/// h.insert("overwrite", "F".parse().unwrap());
/// assert!(!parse_overwrite(&h));
/// ```
pub fn parse_overwrite(headers: &HeaderMap) -> bool {
    headers
        .get("overwrite")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_uppercase())
        .unwrap_or_else(|| "T".into())
        != "F"
}

fn decode_xml_char_refs(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find("&#") {
        result.push_str(&rest[..pos]);
        rest = &rest[pos + 2..];
        let hex = rest.starts_with('x') || rest.starts_with('X');
        if hex {
            rest = &rest[1..];
        }
        if let Some(end) = rest.find(';') {
            let num_str = &rest[..end];
            let radix = if hex { 16 } else { 10 };
            if let Ok(n) = u32::from_str_radix(num_str, radix)
                && let Some(c) = char::from_u32(n)
            {
                result.push(c);
            }
            rest = &rest[end + 1..];
        } else {
            break;
        }
    }
    result.push_str(rest);
    result
}

/// Parse a PROPPATCH request body into a sequence of set/remove actions.
///
/// # Errors
///
/// Returns a [`ParseError`] if the XML is malformed, contains invalid UTF-8,
/// or has no valid actions.
///
/// # Panics
///
/// Panics if the XML parser encounters an unexpected state (e.g. a text
/// event with no current property name). In practice this only occurs on
/// structurally invalid input that bypasses the parser's normal error paths.
///
/// ```
/// use rshs::webdav::{parse_proppatch_request, PropPatchAction};
///
/// let op = parse_proppatch_request(
///     br#"<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><X:p>val</X:p></D:prop></D:set><D:remove><D:prop><X:q/></D:prop></D:remove></D:propertyupdate>"#
/// ).unwrap();
/// assert_eq!(op.actions.len(), 2);
/// // First action: set X:p = "val"
/// assert_eq!(op.actions[0].0, "p");
/// assert_eq!(op.actions[0].1.as_deref(), Some("val"));
/// // Second action: remove X:q
/// assert_eq!(op.actions[1].0, "q");
/// assert!(op.actions[1].1.is_none());
/// ```
pub fn parse_proppatch_request(xml: &[u8]) -> Result<PropPatchOp, ParseError> {
    let decoded = decode_xml_char_refs(&String::from_utf8_lossy(xml));
    let mut reader = Reader::from_reader(decoded.as_bytes());
    reader.config_mut().trim_text(true);

    let mut actions = Vec::new();
    let mut in_set = false;
    let mut in_remove = false;
    let mut current_name: Option<String> = None;

    loop {
        match reader.read_event()? {
            Event::Start(e) => {
                let (ns, local) = extract_element_ns(&e)?;
                match &*local {
                    "set" => in_set = true,
                    "remove" => in_remove = true,
                    "prop" => {}
                    _ if in_set => {
                        current_name = Some(clark_key(&ns, &local));
                    }
                    _ if in_remove => {
                        actions.push(PropPatchAction(clark_key(&ns, &local), None));
                    }
                    _ => {}
                }
            }
            Event::Empty(e) => {
                let (ns, local) = extract_element_ns(&e)?;
                if in_remove && local != "prop" {
                    actions.push(PropPatchAction(clark_key(&ns, &local), None));
                } else if in_set && local != "prop" {
                    actions.push(PropPatchAction(clark_key(&ns, &local), Some(String::new())));
                }
            }
            Event::Text(t) if in_set && current_name.is_some() => {
                let raw = String::from_utf8_lossy(t.as_ref());
                let val = decode_xml_char_refs(&raw);
                actions.push(PropPatchAction(current_name.take().unwrap(), Some(val)));
            }
            Event::End(e) => {
                let local_name = e.local_name();
                let local = String::from_utf8_lossy(local_name.as_ref());
                match &*local {
                    "set" => in_set = false,
                    "remove" => in_remove = false,
                    _ if in_set && current_name.is_some() => {
                        actions.push(PropPatchAction(
                            current_name.take().unwrap(),
                            Some(String::new()),
                        ));
                    }
                    _ => {}
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    if actions.is_empty() {
        return Err(ParseError::InvalidBody("invalid PROPPATCH body"));
    }

    Ok(PropPatchOp { actions })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests for extract_element_ns — a private function that cannot be
    // exercised via doc-tests.

    #[test]
    fn test_extract_element_ns_default_ns() {
        let mut elem = BytesStart::new("prop0");
        elem.push_attribute(("xmlns", "http://example.com/neon/litmus/"));
        let (ns, local) = extract_element_ns(&elem).unwrap();
        assert_eq!(ns, "http://example.com/neon/litmus/");
        assert_eq!(local, "prop0");
    }

    #[test]
    fn test_extract_element_ns_no_ns() {
        let elem = BytesStart::new("prop0");
        let (ns, local) = extract_element_ns(&elem).unwrap();
        assert_eq!(ns, "");
        assert_eq!(local, "prop0");
    }

    #[test]
    fn test_extract_element_ns_prefixed() {
        let mut elem = BytesStart::new("X:prop0");
        elem.push_attribute(("xmlns:X", "http://example.com/ns"));
        let (ns, local) = extract_element_ns(&elem).unwrap();
        assert_eq!(ns, "http://example.com/ns");
        assert_eq!(local, "prop0");
    }

    #[test]
    fn test_extract_element_ns_invalid_empty_uri() {
        let mut elem = BytesStart::new("bar:foo");
        elem.push_attribute(("xmlns:bar", ""));
        assert!(extract_element_ns(&elem).is_err());
    }
}
