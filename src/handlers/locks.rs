//! LOCK and UNLOCK WebDAV protocol handlers.

use std::io::Cursor;
use std::sync::Arc;

use axum::body::{self, Body};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use quick_xml::Writer;
use quick_xml::events::{BytesEnd, BytesStart, Event};

use crate::server::{AppResult, AppState};
use crate::utils::error::{IntoResolved, OrStatus};
use crate::webdav::{self, El, XmlWriterExt};

/// Result of conflict checking before lock-null resource creation.
enum TryAcquire {
    /// Lock acquired under the write guard — the entry has been modified.
    /// No file I/O needed. The token is returned.
    Acquired(String),
    /// Entry was empty — caller should drop the lock guard, create the
    /// lock-null resource, reacquire, re-verify the entry is still empty,
    /// then commit the new lock entry.
    NeedsLockNull,
}

/// LOCK handler — creates or refreshes a WebDAV lock (RFC 4918 §9.10).
///
/// Supports exclusive and shared locks. Handles lock-null resource creation
/// for locking non-existent URLs. Refreshes existing locks when the same
/// token is presented. Returns the `Lock-Token` header and activelock XML.
///
/// # Panics
///
/// Panics if constructing the lock response XML or HTTP response fails.
/// In practice this never occurs — the XML is always valid UTF-8 from an
/// in-memory buffer, and the response builder is always fresh.
pub async fn handle_lock(State(state): State<Arc<AppState>>, req: Request) -> AppResult {
    let request_path = req.uri().path().trim_end_matches('/').to_owned();

    let target = state.resolve_and_guard(&request_path).await;
    let target = target.or_invalid(StatusCode::FORBIDDEN)?;

    let timeout = webdav::parse_timeout(req.headers()).or_else(|| {
        if state.lock_timeout == std::time::Duration::ZERO {
            None
        } else {
            Some(state.lock_timeout)
        }
    });
    let depth = webdav::parse_depth(req.headers());
    let if_entries = webdav::parse_if_header(req.headers());
    let if_tokens: Vec<String> = if_entries
        .iter()
        .flat_map(|e| e.positive_tokens_iter())
        .map(|t| t.to_string())
        .collect();
    let body_bytes = body::to_bytes(req.into_body(), 65536).await;
    let body_bytes = body_bytes.or_400("failed to read LOCK body")?;

    let (owner, lock_scope) = parse_lock_body(&body_bytes);

    let mut locks = state.locks.write().await;

    if let Some(refreshed) = webdav::ls::find_and_refresh_ancestor_lock(&mut locks, &target, |l| {
        if_tokens.contains(&l.token)
    }) {
        let xml = build_lock_response(&refreshed);

        tracing::debug!(
            path = %target.display(), token = %refreshed.token, timeout = ?refreshed.timeout,
            ancestor = true, "LOCK refreshed on ancestor lock"
        );

        return Ok(lock_response(&refreshed.token, xml, StatusCode::OK));
    }

    let entry = locks.entry(target.clone()).or_default();

    // Common prefix: check for existing exclusive lock matching our tokens
    let decision = if let Some(token) = webdav::ls::check_existing_exclusive(entry, &if_tokens)? {
        // Matching exclusive lock found — scope determines refresh behavior
        entry.retain(|l| !l.is_exclusive());
        let token = match lock_scope {
            webdav::LockScope::Exclusive => token, // refresh: keep same token
            webdav::LockScope::Shared => webdav::generate_lock_token(), // downgrade: new token
        };
        TryAcquire::Acquired(token)
    } else {
        // No exclusive lock matched — try new lock acquisition
        match lock_scope {
            webdav::LockScope::Exclusive => try_new_exclusive(entry, &if_tokens)?,
            webdav::LockScope::Shared => try_new_shared(entry, &if_tokens)?,
        }
    };

    match decision {
        TryAcquire::Acquired(token) => {
            let lock = webdav::LockInfo {
                scope: lock_scope,
                token: token.clone(),
                owner,
                created: std::time::SystemTime::now(),
                timeout,
                depth,
            };
            let xml = build_lock_response(&lock);

            entry.push(lock);

            tracing::debug!(
                path = %target.display(), token = %token,timeout = ?timeout, is_refresh = true,
                "LOCK completed"
            );

            Ok(lock_response(&token, xml, StatusCode::OK))
        }
        TryAcquire::NeedsLockNull => {
            drop(locks);

            let created = ensure_lock_null_resource(&target).await?;

            let mut locks = state.locks.write().await;
            let entry = locks.entry(target.clone()).or_default();

            if !entry.is_empty() {
                return Err(StatusCode::LOCKED);
            }

            let token = webdav::generate_lock_token();
            let lock = webdav::LockInfo {
                scope: lock_scope,
                token: token.clone(),
                owner,
                created: std::time::SystemTime::now(),
                timeout,
                depth,
            };
            let xml = build_lock_response(&lock);

            entry.push(lock);

            tracing::debug!(
                path = %target.display(), token = %token, timeout = ?timeout, is_refresh = false,
                "LOCK completed (lock-null)"
            );

            let status = if created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };

            Ok(lock_response(&token, xml, status))
        }
    }
}

/// Build an HTTP response for LOCK with the lock-token header and XML body.
fn lock_response(token: &str, xml: String, status: StatusCode) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "application/xml; charset=utf-8")
        .header("lock-token", format!("<{token}>"))
        .body(Body::from(xml))
        .unwrap()
}

fn parse_lock_body(xml: &[u8]) -> (Option<String>, webdav::LockScope) {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);
    let mut in_owner = false;
    let mut in_lockscope = false;
    let mut owner = None;
    let mut scope = webdav::LockScope::Exclusive;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let local = e.local_name();
                let name = local.as_ref();
                match name {
                    b"owner" => in_owner = true,
                    b"lockscope" => in_lockscope = true,
                    b"shared" if in_lockscope => scope = webdav::LockScope::Shared,
                    b"exclusive" if in_lockscope => {}
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                let local = e.local_name();
                let name = local.as_ref();
                match name {
                    b"owner" => in_owner = false,
                    b"lockscope" => in_lockscope = false,
                    _ => {}
                }
            }
            Ok(Event::Text(t)) if in_owner => {
                owner = Some(String::from_utf8_lossy(t.as_ref()).to_string());
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    (owner, scope)
}

fn build_lock_response(lock: &webdav::LockInfo) -> String {
    let mut writer = Writer::new(Cursor::new(Vec::new()));

    let mut prop = BytesStart::new(El::PROP);
    prop.push_attribute(("xmlns:D", "DAV:"));
    writer.ev(Event::Start(prop));

    writer.ev(Event::Start(BytesStart::new(El::LOCK_DISCOVERY)));

    webdav::xml::write_activelock(&mut writer, lock);

    writer.ev(Event::End(BytesEnd::new(El::LOCK_DISCOVERY)));
    writer.ev(Event::End(BytesEnd::new(El::PROP)));

    String::from_utf8(writer.into_inner().into_inner()).unwrap()
}

async fn ensure_lock_null_resource(target: &std::path::Path) -> Result<bool, StatusCode> {
    match tokio::fs::File::create_new(target).await {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => {
            tracing::error!(
                error = %e, path = %target.display(), "failed to create lock-null resource"
            );
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Try to create a new exclusive lock when no matching exclusive exists.
///
/// Precondition: caller has already verified that no exclusive lock
/// matched `if_tokens` (via [`check_existing_exclusive`](check_existing_exclusive)).
fn try_new_exclusive(
    entry: &mut Vec<webdav::LockInfo>, if_tokens: &[String],
) -> AppResult<TryAcquire> {
    if entry.is_empty() {
        return Ok(TryAcquire::NeedsLockNull);
    }
    // Only shared locks remain — check if we own all of them
    if entry.iter().all(|l| if_tokens.contains(&l.token)) {
        entry.clear();
        Ok(TryAcquire::Acquired(webdav::generate_lock_token()))
    } else {
        Err(StatusCode::LOCKED)
    }
}

/// Try to create or refresh a shared lock when no matching exclusive exists.
///
/// Precondition: caller has already verified that no exclusive lock
/// matched `if_tokens` (via [`check_existing_exclusive`](ls::check_existing_exclusive)).
fn try_new_shared(
    entry: &mut Vec<webdav::LockInfo>, if_tokens: &[String],
) -> AppResult<TryAcquire> {
    // Refresh an existing shared lock with matching token
    if let Some(existing) = entry.iter().find(|l| if_tokens.contains(&l.token)) {
        let token = existing.token.clone();
        entry.retain(|l| l.token != token);
        return Ok(TryAcquire::Acquired(token));
    }
    if entry.is_empty() {
        return Ok(TryAcquire::NeedsLockNull);
    }
    // Compatible shared locks exist — create a new one
    Ok(TryAcquire::Acquired(webdav::generate_lock_token()))
}

/// UNLOCK handler — removes a WebDAV lock (RFC 4918 §9.11).
///
/// Requires the `Lock-Token` header. Returns `204 No Content` on success.
/// Returns `403 Forbidden` if the token does not match any existing lock.
pub async fn handle_unlock(State(state): State<Arc<AppState>>, req: Request) -> AppResult {
    let request_path = req.uri().path().to_owned();

    let token = webdav::parse_lock_token_header(req.headers());
    let token = token.or_400("missing or invalid lock-token header for UNLOCK")?;

    let fs_path = state.resolve_existing(&request_path).await;
    let fs_path = fs_path.or_404("resource not found for UNLOCK")?;

    let mut locks = state.locks.write().await;
    if let Some(entry) = locks.get_mut(&fs_path) {
        let before = entry.len();
        entry.retain(|l| l.token != token);
        if entry.len() < before {
            tracing::debug!(path = %fs_path.display(), token = %token, "UNLOCK completed");
            drop(locks);
            return Ok(StatusCode::NO_CONTENT.into_response());
        }
    }
    drop(locks);
    Err(StatusCode::FORBIDDEN)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{Router, body::Body, extract::Request, routing::any};
    use tower::ServiceExt;

    use crate::{AppState, AuthState};

    fn make_app(dir: &tempfile::TempDir) -> Router {
        Router::new()
            .fallback(any(super::handle_lock))
            .with_state(std::sync::Arc::new(AppState::new(
                dir.path().to_path_buf(),
                AuthState::new(),
                std::time::Duration::from_secs(300),
            )))
    }

    fn make_app_unlock(dir: &tempfile::TempDir) -> Router {
        Router::new()
            .fallback(any(super::handle_unlock))
            .with_state(std::sync::Arc::new(AppState::new(
                dir.path().to_path_buf(),
                AuthState::new(),
                std::time::Duration::from_secs(300),
            )))
    }

    #[tokio::test]
    async fn test_lock_file() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("f.txt"), b"data").unwrap();
        let app = make_app(&dir);

        let body = Body::from(
            r#"<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>"#,
        );
        let req = Request::builder()
            .method(axum::http::Method::from_bytes(b"LOCK").unwrap())
            .uri("/f.txt")
            .body(body)
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        assert!(
            resp.headers()
                .get("lock-token")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("opaquelocktoken")
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("activelock"));
    }

    #[tokio::test]
    async fn test_lock_creates_locknull() {
        let dir = tempfile::TempDir::new().unwrap();
        let app = make_app(&dir);

        let body = Body::from(
            r#"<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>"#,
        );
        let req = Request::builder()
            .method(axum::http::Method::from_bytes(b"LOCK").unwrap())
            .uri("/ghost.txt")
            .body(body)
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // RFC 4918 §7.3: LOCK on non-existent URL creates lock-null resource
        assert_eq!(resp.status(), axum::http::StatusCode::CREATED);
        assert!(dir.path().join("ghost.txt").exists());
    }

    #[tokio::test]
    async fn test_lock_refresh() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("f.txt"), b"data").unwrap();
        let app = make_app(&dir);

        let body = Body::from(
            r#"<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>"#,
        );
        let req = Request::builder()
            .method(axum::http::Method::from_bytes(b"LOCK").unwrap())
            .uri("/f.txt")
            .body(body)
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        // Re-create app and send LOCK again (refresh)
        let app = make_app(&dir);
        let body = Body::from(
            r#"<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>"#,
        );
        let req = Request::builder()
            .method(axum::http::Method::from_bytes(b"LOCK").unwrap())
            .uri("/f.txt")
            .body(body)
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_unlock() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("f.txt"), b"data").unwrap();

        let state = Arc::new(AppState::new(
            dir.path().to_path_buf(),
            AuthState::new(),
            std::time::Duration::from_secs(300),
        ));
        let lock_app = Router::new()
            .fallback(any(super::handle_lock))
            .with_state(state.clone());
        let unlock_app = Router::new()
            .fallback(any(super::handle_unlock))
            .with_state(state);

        // Lock
        let body = Body::from(
            r#"<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>"#,
        );
        let req = Request::builder()
            .method(axum::http::Method::from_bytes(b"LOCK").unwrap())
            .uri("/f.txt")
            .body(body)
            .unwrap();
        let resp = lock_app.oneshot(req).await.unwrap();
        let token = resp
            .headers()
            .get("lock-token")
            .unwrap()
            .to_str()
            .unwrap()
            .trim_matches('<')
            .trim_matches('>')
            .to_string();

        // Unlock
        let req = Request::builder()
            .method(axum::http::Method::from_bytes(b"UNLOCK").unwrap())
            .uri("/f.txt")
            .header("lock-token", format!("<{token}>"))
            .body(Body::empty())
            .unwrap();
        let resp = unlock_app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_unlock_wrong_token() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("f.txt"), b"data").unwrap();
        let app = make_app_unlock(&dir);

        let req = Request::builder()
            .method(axum::http::Method::from_bytes(b"UNLOCK").unwrap())
            .uri("/f.txt")
            .header("lock-token", "<opaquelocktoken:bad>")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_lock_shared() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("f.txt"), b"data").unwrap();
        let app = make_app(&dir);

        let body = Body::from(
            r#"<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:shared/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>"#,
        );
        let req = Request::builder()
            .method(axum::http::Method::from_bytes(b"LOCK").unwrap())
            .uri("/f.txt")
            .body(body)
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(text.contains("<D:shared"));
    }

    #[tokio::test]
    async fn test_shared_lock_blocks_exclusive() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("f.txt"), b"data").unwrap();

        let state = Arc::new(AppState::new(
            dir.path().to_path_buf(),
            AuthState::new(),
            std::time::Duration::from_secs(300),
        ));
        let app = Router::new()
            .fallback(any(super::handle_lock))
            .with_state(state.clone());
        let app2 = Router::new()
            .fallback(any(super::handle_lock))
            .with_state(state);

        // Shared lock
        let body = Body::from(
            r#"<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:shared/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>"#,
        );
        let req = Request::builder()
            .method(axum::http::Method::from_bytes(b"LOCK").unwrap())
            .uri("/f.txt")
            .body(body)
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        // Exclusive lock from different client → 423
        let body = Body::from(
            r#"<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>"#,
        );
        let req = Request::builder()
            .method(axum::http::Method::from_bytes(b"LOCK").unwrap())
            .uri("/f.txt")
            .body(body)
            .unwrap();
        let resp = app2.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::LOCKED);
    }

    #[tokio::test]
    async fn test_exclusive_lock_blocks_shared() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("f.txt"), b"data").unwrap();

        let state = Arc::new(AppState::new(
            dir.path().to_path_buf(),
            AuthState::new(),
            std::time::Duration::from_secs(300),
        ));
        let app = Router::new()
            .fallback(any(super::handle_lock))
            .with_state(state.clone());
        let app2 = Router::new()
            .fallback(any(super::handle_lock))
            .with_state(state);

        // Exclusive lock
        let body = Body::from(
            r#"<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>"#,
        );
        let req = Request::builder()
            .method(axum::http::Method::from_bytes(b"LOCK").unwrap())
            .uri("/f.txt")
            .body(body)
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        // Shared lock from different client → 423
        let body = Body::from(
            r#"<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:shared/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>"#,
        );
        let req = Request::builder()
            .method(axum::http::Method::from_bytes(b"LOCK").unwrap())
            .uri("/f.txt")
            .body(body)
            .unwrap();
        let resp = app2.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::LOCKED);
    }

    #[tokio::test]
    async fn test_double_shared_lock() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("f.txt"), b"data").unwrap();

        let state = Arc::new(AppState::new(
            dir.path().to_path_buf(),
            AuthState::new(),
            std::time::Duration::from_secs(300),
        ));
        let app = Router::new()
            .fallback(any(super::handle_lock))
            .with_state(state.clone());
        let app2 = Router::new()
            .fallback(any(super::handle_lock))
            .with_state(state);

        let shared_body = r#"<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:shared/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>"#;

        // First shared lock
        let resp = app
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::from_bytes(b"LOCK").unwrap())
                    .uri("/f.txt")
                    .body(Body::from(shared_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        // Second shared lock from different client → should succeed
        let resp = app2
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::from_bytes(b"LOCK").unwrap())
                    .uri("/f.txt")
                    .body(Body::from(shared_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_shared_lock_refresh() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("f.txt"), b"data").unwrap();

        let state = Arc::new(AppState::new(
            dir.path().to_path_buf(),
            AuthState::new(),
            std::time::Duration::from_secs(300),
        ));
        let app = Router::new()
            .fallback(any(super::handle_lock))
            .with_state(state.clone());

        let shared_body = r#"<?xml version="1.0" encoding="utf-8"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:shared/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>"#;

        // First shared lock
        let resp = app
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::from_bytes(b"LOCK").unwrap())
                    .uri("/f.txt")
                    .body(Body::from(shared_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let token = resp
            .headers()
            .get("lock-token")
            .unwrap()
            .to_str()
            .unwrap()
            .trim_matches('<')
            .trim_matches('>')
            .to_string();

        // Refresh with token
        let app2 = Router::new()
            .fallback(any(super::handle_lock))
            .with_state(state);
        let resp = app2
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::from_bytes(b"LOCK").unwrap())
                    .uri("/f.txt")
                    .header("if", format!("(<{token}>)"))
                    .body(Body::from(shared_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        // Same token returned on refresh
        let refreshed = resp
            .headers()
            .get("lock-token")
            .unwrap()
            .to_str()
            .unwrap()
            .trim_matches('<')
            .trim_matches('>');
        assert_eq!(refreshed, token);
    }
}
