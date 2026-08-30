//! Lock system evaluation — `If` header types, condition parsing, ancestor walk, and lock evaluation.

use std::path::Path;
use std::time::SystemTime;

use axum::http::{HeaderMap, StatusCode};

use super::{Depth, LockInfo, LockStore};

// ---------------------------------------------------------------------------
// If header types (RFC 4918 §10.4)
// ---------------------------------------------------------------------------

/// A single condition in an `If` header (RFC 4918 §10.4).
///
/// ```
/// use rshs::webdav::IfCondition;
///
/// let token = IfCondition::StateToken("opaquelocktoken:abc".into());
/// let not = IfCondition::Not(Box::new(token.clone()));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IfCondition {
    /// `<token>` — match a specific lock token.
    StateToken(String),
    /// `Not <condition>` — negate a condition.
    Not(Box<IfCondition>),
}

impl IfCondition {
    /// Evaluate this condition against a raw lock slice.
    ///
    /// Filters out expired locks internally, then delegates to
    /// [`eval_active`](IfCondition::eval_active). For evaluating
    /// multiple conditions against the same lock set, use
    /// [`eval_if`] which filters once and calls `eval_active`.
    ///
    /// - `StateToken("DAV:no-lock")`: true if no active locks exist.
    /// - `StateToken(t)`: true if any active lock has token `t`.
    /// - `Not(inner)`: negates the inner condition.
    pub fn eval(&self, infos: &[LockInfo]) -> bool {
        let active: Vec<&LockInfo> = active_slice(infos).collect();
        self.eval_active(&active)
    }

    /// Evaluate this condition against a pre-filtered active lock slice.
    ///
    /// The caller is responsible for filtering out expired locks before
    /// calling this method — use [`active_slice`] to obtain an active
    /// iterator and `collect` into `Vec<&LockInfo>`. This is the inner
    /// variant called by [`eval_if`] after filtering once for all
    /// conditions.
    pub fn eval_active(&self, active: &[&LockInfo]) -> bool {
        match self {
            IfCondition::StateToken(t) if t == "DAV:no-lock" => active.is_empty(),
            IfCondition::StateToken(t) => active.iter().any(|l| l.token == *t),
            IfCondition::Not(inner) => !inner.eval_active(active),
        }
    }
}

/// One list of conditions in an `If` header, optionally scoped to a resource.
///
/// Multiple lists are OR'd; multiple conditions within a list are AND'd.
///
/// ```
/// use rshs::webdav::{IfList, IfCondition};
///
/// let list = IfList {
///     resource_tag: None,
///     conditions: vec![
///         IfCondition::StateToken("opaquelocktoken:t1".into()),
///         IfCondition::Not(Box::new(IfCondition::StateToken("DAV:no-lock".into()))),
///     ],
/// };
/// assert!(list.has_lock_token());
/// assert_eq!(list.positive_tokens(), vec!["opaquelocktoken:t1"]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfList {
    pub resource_tag: Option<String>,
    pub conditions: Vec<IfCondition>,
}

impl IfList {
    /// Create a new `IfList` with the given resource tag and conditions.
    pub fn new(resource_tag: Option<String>, conditions: Vec<IfCondition>) -> Self {
        Self {
            resource_tag,
            conditions,
        }
    }

    /// Collect all non-negated state tokens.
    ///
    /// ```
    /// use rshs::webdav::{IfList, IfCondition};
    ///
    /// let list = IfList {
    ///     resource_tag: None,
    ///     conditions: vec![
    ///         IfCondition::StateToken("t1".into()),
    ///         IfCondition::Not(Box::new(IfCondition::StateToken("t2".into()))),
    ///         IfCondition::StateToken("t3".into()),
    ///     ],
    /// };
    /// assert_eq!(list.positive_tokens(), vec!["t1", "t3"]);
    /// ```
    pub fn positive_tokens(&self) -> Vec<&str> {
        self.positive_tokens_iter().collect()
    }

    /// Iterator over non-negated state tokens.
    pub fn positive_tokens_iter(&self) -> impl Iterator<Item = &str> + '_ {
        self.conditions.iter().filter_map(|c| match c {
            IfCondition::StateToken(t) => Some(t.as_str()),
            _ => None,
        })
    }

    /// Whether this list contains any actual lock token (excluding `DAV:no-lock`).
    ///
    /// ```
    /// use rshs::webdav::{IfList, IfCondition};
    ///
    /// let no_lock = IfList {
    ///     resource_tag: None,
    ///     conditions: vec![IfCondition::StateToken("DAV:no-lock".into())],
    /// };
    /// assert!(!no_lock.has_lock_token());
    ///
    /// let has_token = IfList {
    ///     resource_tag: None,
    ///     conditions: vec![IfCondition::StateToken("opaquelocktoken:xyz".into())],
    /// };
    /// assert!(has_token.has_lock_token());
    /// ```
    pub fn has_lock_token(&self) -> bool {
        self.conditions.iter().any(|c| match c {
            IfCondition::StateToken(t) => t != "DAV:no-lock",
            IfCondition::Not(inner) => {
                matches!(inner.as_ref(), IfCondition::StateToken(t) if t != "DAV:no-lock")
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Header parsers
// ---------------------------------------------------------------------------

/// Parse the `If` header into a list of `IfList`s (RFC 4918 §10.4).
///
/// ```
/// use axum::http::HeaderMap;
/// use rshs::webdav::{parse_if_header, IfCondition, IfList};
///
/// let mut h = HeaderMap::new();
/// h.insert("if", "(<opaquelocktoken:t1>)".parse().unwrap());
///
/// let lists = parse_if_header(&h);
/// assert_eq!(lists.len(), 1);
/// assert_eq!(lists[0].conditions.len(), 1);
/// assert_eq!(lists[0].conditions[0], IfCondition::StateToken("opaquelocktoken:t1".into()));
///
/// // Not condition
/// let mut h = HeaderMap::new();
/// h.insert("if", "(Not <DAV:no-lock>)".parse().unwrap());
/// let lists = parse_if_header(&h);
/// assert_eq!(lists[0].conditions[0], IfCondition::Not(Box::new(IfCondition::StateToken("DAV:no-lock".into()))));
///
/// // Resource tags
/// let mut h = HeaderMap::new();
/// h.insert("if", "</path> (<opaquelocktoken:t1>)".parse().unwrap());
/// let lists = parse_if_header(&h);
/// assert_eq!(lists[0].resource_tag, Some("/path".into()));
/// ```
pub fn parse_if_header(headers: &HeaderMap) -> Vec<IfList> {
    let value = match headers.get("if").and_then(|v| v.to_str().ok()) {
        Some(v) => v,
        None => return Vec::new(),
    };

    let bytes = value.as_bytes();
    let mut pos = 0;
    let mut lists = Vec::new();

    while pos < bytes.len() {
        pos = skip_ws(bytes, pos);
        if pos >= bytes.len() {
            break;
        }

        match bytes[pos] {
            b'<' => {
                let Some((tag, new_pos)) = read_angle_bracket(bytes, pos) else {
                    break;
                };
                pos = skip_ws(bytes, new_pos);

                if pos < bytes.len() && bytes[pos] == b'(' {
                    let resource_tag = tag;
                    while pos < bytes.len() && bytes[pos] == b'(' {
                        let (conditions, new_pos) = read_list(bytes, pos);
                        pos = skip_ws(bytes, new_pos);
                        lists.push(IfList::new(Some(resource_tag.clone()), conditions));
                    }
                } else {
                    lists.push(IfList::new(None, vec![IfCondition::StateToken(tag)]));
                }
            }
            b'(' => {
                let (conditions, new_pos) = read_list(bytes, pos);
                pos = skip_ws(bytes, new_pos);
                lists.push(IfList::new(None, conditions));
            }
            _ => {
                pos += 1;
            }
        }
    }

    lists
}

fn skip_ws(bytes: &[u8], mut p: usize) -> usize {
    while p < bytes.len() && bytes[p].is_ascii_whitespace() {
        p += 1;
    }
    p
}

fn read_angle_bracket(bytes: &[u8], p: usize) -> Option<(String, usize)> {
    debug_assert!(bytes.get(p) == Some(&b'<'));
    let start = p + 1;
    let end = bytes[start..].iter().position(|&b| b == b'>')?;
    Some((
        std::str::from_utf8(&bytes[start..start + end])
            .ok()?
            .to_string(),
        start + end + 1,
    ))
}

fn read_list(bytes: &[u8], mut p: usize) -> (Vec<IfCondition>, usize) {
    debug_assert!(bytes.get(p) == Some(&b'('));
    p += 1;
    let mut conditions = Vec::new();
    loop {
        p = skip_ws(bytes, p);
        if p >= bytes.len() || bytes[p] == b')' {
            if p < bytes.len() {
                p += 1;
            }
            break;
        }

        let mut negated = false;
        if bytes[p..].starts_with(b"Not") {
            let after = p + 3;
            if after >= bytes.len()
                || bytes[after].is_ascii_whitespace()
                || bytes[after] == b'<'
                || bytes[after] == b'('
            {
                negated = true;
                p = skip_ws(bytes, after);
            }
        }

        if p < bytes.len() && bytes[p] == b'<' {
            let Some((token, new_p)) = read_angle_bracket(bytes, p) else {
                break;
            };
            p = new_p;
            let cond = IfCondition::StateToken(token);
            conditions.push(if negated {
                IfCondition::Not(Box::new(cond))
            } else {
                cond
            });
        } else {
            p += 1;
        }
    }
    (conditions, p)
}

// ---------------------------------------------------------------------------
// Lock evaluation
// ---------------------------------------------------------------------------

/// Filter a lock slice to only active (non-expired) locks.
///
/// This is used internally by the lock evaluation engine to lazily skip
/// expired locks without modifying the store. Expired locks are pruned
/// separately by the periodic cleanup task in `start_server`.
pub fn active_slice(infos: &[LockInfo]) -> impl Iterator<Item = &LockInfo> + '_ {
    infos.iter().filter(|l| !l.is_expired())
}

/// Walk up the ancestor chain of `target` within `root_canonical`, calling
/// `f` with the lock slice at each ancestor directory.
///
/// When there are few depth:infinity locks (≤ 10), iterates locks directly
/// and checks ancestry via prefix comparison. Falls back to per-ancestor
/// HashMap walk when many depth:infinity locks exist.
///
/// Stops at the first ancestor where `f` returns `true`, or when the walk
/// reaches the root boundary.
///
/// Re-exported from [`crate::webdav::ls`].
pub fn walk_locked_ancestors<'a>(
    locks: &'a LockStore, target: &Path, root_canonical: &Path,
    mut f: impl FnMut(&'a [LockInfo]) -> bool,
) -> bool {
    if locks.is_empty() {
        return false;
    }

    let inf_entries: Vec<_> = locks
        .iter()
        .filter(|(_, infos)| infos.iter().any(|l| l.depth == Depth::Infinity))
        .collect();

    if inf_entries.is_empty() {
        return false;
    }

    if inf_entries.len() <= 10 {
        for (lock_path, infos) in inf_entries {
            if is_ancestor_of(lock_path, target) && f(infos) {
                return true;
            }
        }
        false
    } else {
        let mut current = target.parent();
        while let Some(parent) = current {
            if !parent.starts_with(root_canonical) {
                break;
            }
            if let Some(infos) = locks.get(parent)
                && f(infos)
            {
                return true;
            }
            current = parent.parent();
        }
        false
    }
}

/// Returns `true` if `ancestor` is a proper ancestor directory of `target`.
///
/// A path `/a/b` is an ancestor of `/a/b/c/file.txt` — the byte immediately
/// after the ancestor prefix is `/`. Root `/` is always an ancestor.
fn is_ancestor_of(ancestor: &Path, target: &Path) -> bool {
    let an = ancestor.as_os_str().as_encoded_bytes();
    let ta = target.as_os_str().as_encoded_bytes();
    if an.is_empty() || an.len() >= ta.len() {
        return false;
    }
    if !target.starts_with(ancestor) {
        return false;
    }
    if an == b"/" {
        return true;
    }
    ta[an.len()] == b'/'
}

/// Find the first ancestor lock matching a predicate, walking from
/// `target` up to the root.
///
/// Only considers locks with `Depth::Infinity`. Used by the lock middleware
/// and the LOCK handler for lock discovery and refresh.
///
/// Re-exported from [`crate::webdav::ls`].
pub fn find_ancestor_lock<'a>(
    locks: &'a LockStore, target: &Path, root_canonical: &Path,
    predicate: impl Fn(&LockInfo) -> bool,
) -> Option<&'a LockInfo> {
    let mut result: Option<&'a LockInfo> = None;
    walk_locked_ancestors(locks, target, root_canonical, |infos| {
        for lock in infos {
            if lock.depth == Depth::Infinity && !lock.is_expired() && predicate(lock) {
                result = Some(lock);
                return true;
            }
        }
        false
    });
    result
}

/// Find and refresh the timeout of an ancestor `Depth::Infinity` lock
/// matching a predicate.
///
/// Walks ancestor directories of `target` within `root_canonical`,
/// finds the first active infinity lock that satisfies `predicate`,
/// updates its `created` timestamp to the current time (refreshing
/// the timeout), and returns a clone of the refreshed lock.
///
/// Returns `None` if no matching active ancestor lock exists.
///
/// Used by [`handle_lock`](crate::handlers::locks::handle_lock) to
/// refresh depth:infinity ancestor locks when a client submits a
/// LOCK request with a matching `If` header token.
pub fn find_and_refresh_ancestor_lock(
    locks: &mut LockStore, target: &Path, predicate: impl Fn(&LockInfo) -> bool,
) -> Option<LockInfo> {
    // Two-pass approach to avoid borrow conflicts:
    // 1. Collect candidate paths (immutable iteration)
    // 2. Mutate the matching lock (mutable access)
    let candidate_paths: Vec<std::path::PathBuf> = locks
        .iter()
        .filter(|(path, infos)| {
            infos
                .iter()
                .any(|l| l.depth == Depth::Infinity && !l.is_expired())
                && is_ancestor_of(path, target)
        })
        .map(|(path, _)| path.clone())
        .collect();

    for path in candidate_paths {
        if let Some(infos) = locks.get_mut(&path) {
            for lock in infos.iter_mut() {
                if lock.depth == Depth::Infinity && !lock.is_expired() && predicate(lock) {
                    lock.created = SystemTime::now();
                    return Some(lock.clone());
                }
            }
        }
    }
    None
}

/// Evaluate a full `If` header (list of `IfList`s) against an active lock
/// slice for a given request path.
///
/// - Empty list: passes only if no active locks exist.
/// - Resource-tagged lists: skipped if the tag doesn't match `request_path`.
/// - All applicable lists must pass (AND); within a list, all conditions
///   must pass (AND); across lists the result is AND semantics.
pub fn eval_if(lists: &[IfList], infos: &[LockInfo], request_path: &str) -> bool {
    if lists.is_empty() {
        return active_slice(infos).next().is_none();
    }

    let mut applicable = lists
        .iter()
        .filter(|l| match &l.resource_tag {
            Some(tag) => tag == request_path,
            None => true,
        })
        .peekable();

    if applicable.peek().is_none() {
        return true;
    }

    let active: Vec<&LockInfo> = active_slice(infos).collect();
    applicable.all(|l| l.conditions.iter().all(|c| c.eval_active(&active)))
}

/// Check whether an existing exclusive lock blocks a request.
///
/// Returns:
/// - `Ok(None)` if no exclusive lock exists (or it's expired / shared-only).
/// - `Ok(Some(token))` if `if_tokens` contains the matching lock token.
/// - `Err(LOCKED)` if an exclusive lock exists and `if_tokens` doesn't match.
///
/// Used by the lock enforcement middleware.
///
/// # Errors
///
/// Returns `Err(StatusCode::LOCKED)` when an active exclusive lock exists
/// and the request does not present a matching lock token.
pub fn check_existing_exclusive(
    entry: &[LockInfo], if_tokens: &[String],
) -> Result<Option<String>, StatusCode> {
    let token_info = active_slice(entry).find(|l| l.is_exclusive());
    match token_info.map(|l| l.token.clone()) {
        Some(t) if if_tokens.contains(&t) => Ok(Some(t)),
        Some(_) => Err(StatusCode::LOCKED),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::webdav::LockScope;

    fn make_lock(scope: LockScope, token: &str) -> LockInfo {
        LockInfo {
            scope,
            token: token.into(),
            owner: None,
            created: SystemTime::now(),
            timeout: None,
            depth: Depth::Zero,
        }
    }

    fn make_expired_lock(token: &str) -> LockInfo {
        LockInfo {
            scope: LockScope::Exclusive,
            token: token.into(),
            owner: None,
            created: SystemTime::now() - Duration::from_secs(2),
            timeout: Some(Duration::from_secs(1)),
            depth: Depth::Zero,
        }
    }

    #[test]
    fn test_eval_condition_state_token_match() {
        let infos = vec![make_lock(LockScope::Exclusive, "t1")];
        let cond = IfCondition::StateToken("t1".into());
        assert!(cond.eval(&infos));
    }

    #[test]
    fn test_eval_condition_state_token_no_match() {
        let infos = vec![make_lock(LockScope::Exclusive, "t1")];
        let cond = IfCondition::StateToken("t2".into());
        assert!(!cond.eval(&infos));
    }

    #[test]
    fn test_eval_condition_dav_no_lock_unlocked() {
        let infos: Vec<LockInfo> = vec![];
        let cond = IfCondition::StateToken("DAV:no-lock".into());
        assert!(cond.eval(&infos));
    }

    #[test]
    fn test_eval_condition_dav_no_lock_locked() {
        let infos = vec![make_lock(LockScope::Exclusive, "t1")];
        let cond = IfCondition::StateToken("DAV:no-lock".into());
        assert!(!cond.eval(&infos));
    }

    #[test]
    fn test_eval_condition_not_token() {
        let infos = vec![make_lock(LockScope::Exclusive, "t1")];
        let cond = IfCondition::Not(Box::new(IfCondition::StateToken("t2".into())));
        assert!(cond.eval(&infos));
    }

    #[test]
    fn test_eval_condition_not_token_reject() {
        let infos = vec![make_lock(LockScope::Exclusive, "t1")];
        let cond = IfCondition::Not(Box::new(IfCondition::StateToken("t1".into())));
        assert!(!cond.eval(&infos));
    }

    #[test]
    fn test_eval_if_no_lists_unlocked() {
        let lists: Vec<IfList> = vec![];
        let infos: Vec<LockInfo> = vec![];
        assert!(eval_if(&lists, &infos, "/a"));
    }

    #[test]
    fn test_eval_if_no_lists_locked() {
        let lists: Vec<IfList> = vec![];
        let infos = vec![make_lock(LockScope::Exclusive, "t1")];
        assert!(!eval_if(&lists, &infos, "/a"));
    }

    #[test]
    fn test_eval_if_matched_token() {
        let lists = vec![IfList::new(
            None,
            vec![IfCondition::StateToken("t1".into())],
        )];
        let infos = vec![make_lock(LockScope::Exclusive, "t1")];
        assert!(eval_if(&lists, &infos, "/a"));
    }

    #[test]
    fn test_eval_if_wrong_token() {
        let lists = vec![IfList::new(
            None,
            vec![IfCondition::StateToken("t2".into())],
        )];
        let infos = vec![make_lock(LockScope::Exclusive, "t1")];
        assert!(!eval_if(&lists, &infos, "/a"));
    }

    #[test]
    fn test_eval_if_not_no_lock_locked() {
        let lists = vec![IfList::new(
            None,
            vec![IfCondition::Not(Box::new(IfCondition::StateToken(
                "DAV:no-lock".into(),
            )))],
        )];
        let infos = vec![make_lock(LockScope::Exclusive, "t1")];
        assert!(eval_if(&lists, &infos, "/a"));
    }

    #[test]
    fn test_eval_if_not_no_lock_unlocked() {
        let lists = vec![IfList::new(
            None,
            vec![IfCondition::Not(Box::new(IfCondition::StateToken(
                "DAV:no-lock".into(),
            )))],
        )];
        let infos: Vec<LockInfo> = vec![];
        assert!(!eval_if(&lists, &infos, "/a"));
    }

    #[test]
    fn test_eval_if_resource_tag_mismatch() {
        let lists = vec![IfList::new(
            Some("/b".into()),
            vec![IfCondition::StateToken("t2".into())],
        )];
        let infos = vec![make_lock(LockScope::Exclusive, "t1")];
        assert!(eval_if(&lists, &infos, "/a"));
    }

    #[test]
    fn test_eval_if_resource_tag_match() {
        let lists = vec![IfList::new(
            Some("/a".into()),
            vec![IfCondition::StateToken("t1".into())],
        )];
        let infos = vec![make_lock(LockScope::Exclusive, "t1")];
        assert!(eval_if(&lists, &infos, "/a"));
    }

    #[test]
    fn test_eval_if_no_lists_expired_ignored() {
        let lists: Vec<IfList> = vec![];
        let infos = vec![make_expired_lock("t1")];
        assert!(eval_if(&lists, &infos, "/a"));
    }

    #[test]
    fn test_dav_no_lock_expired_ignored() {
        let infos = vec![make_expired_lock("t1")];
        let cond = IfCondition::StateToken("DAV:no-lock".into());
        assert!(cond.eval(&infos));
    }

    #[test]
    fn test_token_match_expired_rejected() {
        let infos = vec![make_expired_lock("t1")];
        let cond = IfCondition::StateToken("t1".into());
        assert!(!cond.eval(&infos));
    }

    #[test]
    fn test_eval_if_dav_no_lock_unlocked() {
        let lists = vec![IfList::new(
            None,
            vec![IfCondition::StateToken("DAV:no-lock".into())],
        )];
        let infos: Vec<LockInfo> = vec![];
        assert!(eval_if(&lists, &infos, "/a"));
    }

    #[test]
    fn test_check_existing_exclusive_empty() {
        let entry: Vec<LockInfo> = vec![];
        let tokens: Vec<String> = vec![];
        assert_eq!(check_existing_exclusive(&entry, &tokens), Ok(None));
    }

    #[test]
    fn test_check_existing_exclusive_matching_token() {
        let entry = vec![make_lock(LockScope::Exclusive, "t1")];
        let tokens = vec!["t1".into()];
        assert_eq!(
            check_existing_exclusive(&entry, &tokens),
            Ok(Some("t1".into()))
        );
    }

    #[test]
    fn test_check_existing_exclusive_wrong_token() {
        let entry = vec![make_lock(LockScope::Exclusive, "t1")];
        let tokens = vec!["t2".into()];
        assert_eq!(
            check_existing_exclusive(&entry, &tokens),
            Err(StatusCode::LOCKED)
        );
    }

    #[test]
    fn test_check_existing_exclusive_expired_ignored() {
        let entry = vec![make_expired_lock("t1")];
        let tokens: Vec<String> = vec![];
        assert_eq!(check_existing_exclusive(&entry, &tokens), Ok(None));
    }

    #[test]
    fn test_check_existing_exclusive_shared_only() {
        let entry = vec![make_lock(LockScope::Shared, "t1")];
        let tokens: Vec<String> = vec![];
        assert_eq!(check_existing_exclusive(&entry, &tokens), Ok(None));
    }

    #[test]
    fn test_eval_if_dav_no_lock_locked() {
        let lists = vec![IfList::new(
            None,
            vec![IfCondition::StateToken("DAV:no-lock".into())],
        )];
        let infos = vec![make_lock(LockScope::Exclusive, "t1")];
        assert!(!eval_if(&lists, &infos, "/a"));
    }

    // -- walk_locked_ancestors tests ------------------------------------------

    use std::collections::HashMap;
    use std::path::PathBuf;

    fn lock_store(entries: Vec<(&str, LockInfo)>) -> LockStore {
        let mut store = LockStore::new();
        for (path, info) in entries {
            store.entry(PathBuf::from(path)).or_default().push(info);
        }
        store
    }

    fn make_infinity_lock(scope: LockScope, token: &str) -> LockInfo {
        LockInfo {
            scope,
            token: token.into(),
            owner: None,
            created: SystemTime::now(),
            timeout: None,
            depth: Depth::Infinity,
        }
    }

    #[test]
    fn test_walk_locked_ancestors_empty_store() {
        let store: LockStore = HashMap::new();
        let target = Path::new("/a/b/c/file.txt");
        let root = Path::new("/a");
        assert!(!walk_locked_ancestors(&store, target, root, |_| true));
    }

    #[test]
    fn test_walk_locked_ancestors_no_infinity() {
        let store = lock_store(vec![("/a/b", make_lock(LockScope::Exclusive, "t1"))]);
        let target = Path::new("/a/b/c/file.txt");
        let root = Path::new("/a");
        assert!(!walk_locked_ancestors(&store, target, root, |_| true));
    }

    #[test]
    fn test_walk_locked_ancestors_ancestor_match() {
        let store = lock_store(vec![(
            "/a/b",
            make_infinity_lock(LockScope::Exclusive, "t1"),
        )]);
        let target = Path::new("/a/b/c/file.txt");
        let root = Path::new("/a");
        assert!(walk_locked_ancestors(&store, target, root, |_| true));
    }

    #[test]
    fn test_walk_locked_ancestors_no_match() {
        let store = lock_store(vec![(
            "/x/y",
            make_infinity_lock(LockScope::Exclusive, "t1"),
        )]);
        let target = Path::new("/a/b/c/file.txt");
        let root = Path::new("/a");
        assert!(!walk_locked_ancestors(&store, target, root, |_| true));
    }

    #[test]
    fn test_walk_locked_ancestors_path_boundary() {
        let store = lock_store(vec![(
            "/a/b",
            make_infinity_lock(LockScope::Exclusive, "t1"),
        )]);
        // /a/bc/file.txt starts_with /a/b but /a/b is NOT an ancestor
        let target = Path::new("/a/bc/file.txt");
        let root = Path::new("/a");
        assert!(!walk_locked_ancestors(&store, target, root, |_| true));
    }

    #[test]
    fn test_walk_locked_ancestors_root_lock() {
        let store = lock_store(vec![("/", make_infinity_lock(LockScope::Exclusive, "t1"))]);
        let target = Path::new("/anything/deep/file.txt");
        let root = Path::new("/");
        assert!(walk_locked_ancestors(&store, target, root, |_| true));
    }

    #[test]
    fn test_walk_locked_ancestors_many_locks() {
        let mut store = LockStore::new();
        for i in 0..15 {
            store
                .entry(PathBuf::from(format!("/level_{i}")))
                .or_default()
                .push(make_infinity_lock(LockScope::Exclusive, &format!("t{i}")));
        }
        // One of the locks matches an ancestor: /level_0
        let target = Path::new("/level_0/sub/file.txt");
        let root = Path::new("/");
        assert!(walk_locked_ancestors(&store, target, root, |_| true));
    }

    #[test]
    fn test_is_ancestor_of_boundary_cases() {
        // Normal
        assert!(is_ancestor_of(
            Path::new("/a/b"),
            Path::new("/a/b/c/file.txt")
        ));
        // Boundary: prefix trap
        assert!(!is_ancestor_of(
            Path::new("/a/b"),
            Path::new("/a/bc/file.txt")
        ));
        // Root
        assert!(is_ancestor_of(Path::new("/"), Path::new("/a")));
        assert!(is_ancestor_of(Path::new("/"), Path::new("/file.txt")));
        // Same path is not an ancestor
        assert!(!is_ancestor_of(Path::new("/a/b"), Path::new("/a/b")));
        // Ancestor longer than target
        assert!(!is_ancestor_of(Path::new("/a/b/c"), Path::new("/a/b")));
        // Empty ancestor
        assert!(!is_ancestor_of(Path::new(""), Path::new("/a")));
    }

    #[test]
    fn test_find_ancestor_lock_ignores_expired() {
        let store = lock_store(vec![(
            "/a",
            LockInfo {
                scope: LockScope::Exclusive,
                token: "expired-token".into(),
                owner: None,
                created: SystemTime::now() - Duration::from_secs(10),
                timeout: Some(Duration::from_secs(1)),
                depth: Depth::Infinity,
            },
        )]);
        let target = Path::new("/a/b/file.txt");
        let root = Path::new("/");
        let found = find_ancestor_lock(&store, target, root, |l| l.token == "expired-token");
        assert!(found.is_none(), "expired ancestor lock should not be found");
    }

    #[test]
    fn test_find_and_refresh_ancestor_lock_updates_created() {
        let old_time = SystemTime::now() - Duration::from_secs(3600);
        let mut store = lock_store(vec![(
            "/a",
            LockInfo {
                scope: LockScope::Exclusive,
                token: "t1".into(),
                owner: None,
                created: old_time,
                timeout: Some(Duration::from_secs(7200)),
                depth: Depth::Infinity,
            },
        )]);
        let target = Path::new("/a/b/file.txt");

        let refreshed = find_and_refresh_ancestor_lock(&mut store, target, |l| l.token == "t1");
        assert!(refreshed.is_some());

        let new_created = store.get(Path::new("/a")).unwrap()[0].created;
        let elapsed = new_created.duration_since(old_time).unwrap();
        assert!(elapsed >= Duration::from_secs(3599));
    }

    #[test]
    fn test_find_and_refresh_ancestor_lock_ignores_expired() {
        let mut store = lock_store(vec![(
            "/a",
            LockInfo {
                scope: LockScope::Exclusive,
                token: "expired".into(),
                owner: None,
                created: SystemTime::now() - Duration::from_secs(10),
                timeout: Some(Duration::from_secs(1)),
                depth: Depth::Infinity,
            },
        )]);
        let target = Path::new("/a/b/file.txt");
        let result = find_and_refresh_ancestor_lock(&mut store, target, |l| l.token == "expired");
        assert!(result.is_none());
    }

    #[test]
    fn test_find_and_refresh_ancestor_lock_no_match() {
        let mut store = lock_store(vec![(
            "/a",
            LockInfo {
                scope: LockScope::Exclusive,
                token: "t1".into(),
                owner: None,
                created: SystemTime::now(),
                timeout: None,
                depth: Depth::Infinity,
            },
        )]);
        let target = Path::new("/a/b/file.txt");
        let result =
            find_and_refresh_ancestor_lock(&mut store, target, |l| l.token == "wrong-token");
        assert!(result.is_none());
    }
}
