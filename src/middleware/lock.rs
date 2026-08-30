//! WebDAV lock enforcement middleware.
//! Intercepts write requests (`PUT`, `DELETE`, `MKCOL`, `PROPPATCH`, `MOVE`, `COPY`)
//! and rejects them with `423 Locked` unless the request presents a matching lock token.

use std::path::Path;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;

use crate::server::{AppResult, AppState};
use crate::webdav::{self, Method};

/// Rejects write requests (`PUT`, `DELETE`, `MKCOL`, `PROPPATCH`, `MOVE`, `COPY`)
/// with `423 Locked` if the target resource or an ancestor with `Depth::Infinity` is
/// locked and the request does not present a valid lock token.
///
/// Evaluates `If` header conditions against the lock store. For `COPY`/`MOVE`, both
/// the source and destination paths are checked. If an `If` header with non-token
/// conditions is present and no `Lock-Token` is provided, returns `412 Precondition Failed`.
///
/// # Errors
///
/// Returns `423 Locked` when the target is locked without a matching token,
/// or `412 Precondition Failed` when an `If` header is present without a
/// `Lock-Token` and without lock-token conditions.
pub async fn lock_enforce(
    State(state): State<Arc<AppState>>, req: Request, next: Next,
) -> AppResult {
    let Ok(method) = Method::try_from(req.method()) else {
        return Ok(next.run(req).await);
    };

    if method != Method::PUT
        && method != Method::DELETE
        && method != Method::MKCOL
        && method != Method::PROPPATCH
        && method != Method::MOVE
        && method != Method::COPY
    {
        return Ok(next.run(req).await);
    }

    let request_path = req.uri().path().trim_end_matches('/').to_owned();
    let lists = webdav::parse_if_header(req.headers());

    if !lists.is_empty()
        && !lists.iter().any(|l| l.has_lock_token())
        && !req.headers().contains_key("lock-token")
    {
        return Err(StatusCode::PRECONDITION_FAILED);
    }

    let locks = state.locks.read().await;

    // Source check (skip for COPY — source is read-only)
    if method != Method::COPY
        && let Ok(src) = state.resolve_and_guard(&request_path).await
        && is_path_locked(&locks, &src, &lists, &state.root_canonical, &request_path)
    {
        tracing::debug!(path = %src.display(), "source locked, rejecting write");
        return Err(StatusCode::LOCKED);
    }

    // Destination check (COPY/MOVE only)
    if (method == Method::COPY || method == Method::MOVE)
        && let Some(dest) = webdav::parse_destination(req.headers())
    {
        let dest_norm = dest.trim_end_matches('/');
        if let Ok(dest_path) = state.resolve_and_guard(dest_norm).await
            && is_path_locked(&locks, &dest_path, &lists, &state.root_canonical, dest_norm)
        {
            tracing::debug!(path = %dest_norm, "destination locked, rejecting COPY/MOVE");
            return Err(StatusCode::LOCKED);
        }
    }

    drop(locks);
    Ok(next.run(req).await)
}

fn is_path_locked(
    locks: &webdav::LockStore, path: &Path, lists: &[webdav::IfList], root_canonical: &Path,
    request_path: &str,
) -> bool {
    let infos = match locks.get(path) {
        Some(v) => v.as_slice(),
        None => &[],
    };

    if !webdav::ls::eval_if(lists, infos, request_path) {
        return true;
    }

    webdav::ls::walk_locked_ancestors(locks, path, root_canonical, |infos| {
        webdav::ls::active_slice(infos).any(|l| l.depth == webdav::Depth::Infinity)
            && !webdav::ls::eval_if(lists, infos, request_path)
    })
}
