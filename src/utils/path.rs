//! URI path resolution with percent-decoding and traversal guards (`..` / `.` / `#`).

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use axum::http::StatusCode;
use percent_encoding::percent_decode_str;

/// Errors returned by `resolve_and_guard`.
#[derive(Debug)]
pub enum ResolveTargetError {
    /// Path contains `..`, `.`, or is a directory path.
    InvalidPath,
    /// Canonicalize of parent directory failed (doesn't exist, I/O error).
    ParentCanonicalizeFailed(std::io::Error),
    /// Canonical parent is outside the root directory.
    TraversalBlocked,
}

impl fmt::Display for ResolveTargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath => write!(f, "invalid path"),
            Self::ParentCanonicalizeFailed(e) => write!(f, "parent not found: {e}"),
            Self::TraversalBlocked => write!(f, "path traversal blocked"),
        }
    }
}

impl ResolveTargetError {
    /// Map the error variant to an HTTP status code.
    ///
    /// `on_invalid` is used for [`InvalidPath`](Self::InvalidPath);
    /// [`ParentCanonicalizeFailed`](Self::ParentCanonicalizeFailed) always
    /// returns `409 Conflict`, and [`TraversalBlocked`](Self::TraversalBlocked)
    /// always returns `403 Forbidden`.
    pub fn status(&self, on_invalid: StatusCode) -> StatusCode {
        match self {
            Self::InvalidPath => on_invalid,
            Self::ParentCanonicalizeFailed(_) => StatusCode::CONFLICT,
            Self::TraversalBlocked => StatusCode::FORBIDDEN,
        }
    }
}

/// Resolve a path for read operations (GET/HEAD).
/// Canonicalizes and verifies the target is within the root directory.
/// Returns `None` if the path doesn't exist or is outside the root.
pub async fn resolve_existing(
    root_dir: &Path, root_canonical: &Path, request_path: &str,
) -> Option<PathBuf> {
    let decoded = percent_decode_str(request_path).decode_utf8_lossy();

    let fs_path = root_dir.join(decoded.trim_start_matches('/'));

    let fs_path = tokio::fs::canonicalize(&fs_path).await.ok()?;

    if !fs_path.starts_with(root_canonical) {
        return None;
    }

    Some(fs_path)
}

/// Resolve a path for write operations (PUT, DELETE, MKCOL).
/// The target may not exist yet — validates path safety via segment checks.
/// Returns `None` if the path contains traversal attempts.
pub fn resolve_write_target(root_dir: &Path, request_path: &str) -> Option<PathBuf> {
    let decoded = percent_decode_str(request_path).decode_utf8_lossy();
    let trimmed = decoded.trim_start_matches('/');

    if trimmed.is_empty() || trimmed.ends_with('/') {
        return None;
    }

    for segment in trimmed.split('/') {
        if segment == ".." || segment == "." {
            return None;
        }
    }

    Some(root_dir.join(trimmed))
}

/// Resolves a write target: validates path, canonicalizes parent,
/// verifies traversal safety. Uses a cache to avoid redundant `canonicalize`
/// syscalls for the same parent directory.
///
/// Returns the canonical target `PathBuf`.
///
/// # Panics
///
/// Panics if `resolve_write_target` returned a path with no file name
/// component. In practice this never occurs — `resolve_write_target`
/// rejects empty paths and directory paths (trailing `/`).
pub async fn resolve_and_guard(
    root_dir: &Path, root_canonical: &Path, request_path: &str,
    canonical_cache: &Mutex<HashMap<PathBuf, PathBuf>>,
) -> Result<PathBuf, ResolveTargetError> {
    let fs_path = match resolve_write_target(root_dir, request_path) {
        Some(p) => p,
        None => return Err(ResolveTargetError::InvalidPath),
    };

    let parent = fs_path.parent().unwrap_or(root_dir);

    let parent_canonical = {
        if let Some(cached) = lock_or_recover(canonical_cache).get(parent) {
            cached.clone()
        } else {
            let pc = tokio::fs::canonicalize(parent)
                .await
                .map_err(ResolveTargetError::ParentCanonicalizeFailed)?;
            lock_or_recover(canonical_cache).insert(parent.to_path_buf(), pc.clone());
            pc
        }
    };

    if !parent_canonical.starts_with(root_canonical) {
        return Err(ResolveTargetError::TraversalBlocked);
    }

    Ok(parent_canonical.join(fs_path.file_name().unwrap()))
}

/// Helper to lock a mutex, recovering from poisoning by returning the inner value.
fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[tokio::test]
    async fn test_resolve_existing_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("test.txt")).unwrap();
        f.write_all(b"hello").unwrap();
        let canonical = dir.path().canonicalize().unwrap();

        let result = resolve_existing(dir.path(), &canonical, "/test.txt").await;
        assert!(result.is_some());
        assert!(result.unwrap().ends_with("test.txt"));
    }

    #[tokio::test]
    async fn test_resolve_existing_nonexistent() {
        let dir = tempfile::TempDir::new().unwrap();
        let canonical = dir.path().canonicalize().unwrap();

        let result = resolve_existing(dir.path(), &canonical, "/nonexistent.txt").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_resolve_existing_traversal_blocked() {
        let dir = tempfile::TempDir::new().unwrap();
        let canonical = dir.path().canonicalize().unwrap();

        let result = resolve_existing(dir.path(), &canonical, "/../../../etc/passwd").await;
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_write_target_normal() {
        let dir = Path::new("/tmp/myserve");
        let result = resolve_write_target(dir, "/test.txt");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), PathBuf::from("/tmp/myserve/test.txt"));
    }

    #[test]
    fn test_resolve_write_target_nested() {
        let dir = Path::new("/tmp/myserve");
        let result = resolve_write_target(dir, "/subdir/test.txt");
        assert!(result.is_some());
        assert_eq!(
            result.unwrap(),
            PathBuf::from("/tmp/myserve/subdir/test.txt")
        );
    }

    #[test]
    fn test_resolve_write_target_traversal_dotdot() {
        let dir = Path::new("/tmp/myserve");
        let result = resolve_write_target(dir, "/../etc/passwd");
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_write_target_traversal_dot() {
        let dir = Path::new("/tmp/myserve");
        let result = resolve_write_target(dir, "/./file.txt");
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_write_target_empty() {
        let dir = Path::new("/tmp/myserve");
        let result = resolve_write_target(dir, "/");
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_write_target_dir_path() {
        let dir = Path::new("/tmp/myserve");
        let result = resolve_write_target(dir, "/subdir/");
        assert!(result.is_none());
    }
}
