//! HTTP Basic Authentication middleware.
//! Automatically becomes a no-op when no users are configured in `AuthState`.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose;

use crate::auth::{AuthState, hash_auth_header};
use crate::server::AppResult;

/// Validates HTTP Basic Authentication credentials against the configured `AuthState`.
/// Skips authentication entirely when no users are configured (backward compatible).
///
/// For SHA-512 crypt credentials, uses an auth cache to avoid re-verifying the
/// expensive password hash on every request. See [`AuthState::validate_cached`].
///
/// Returns `401 Unauthorized` with `WWW-Authenticate: Basic realm="rshs"` on failure.
///
/// # Panics
///
/// Panics if constructing the `401 Unauthorized` response fails.
/// This only occurs when the response builder is in an invalid state,
/// which cannot happen with a fresh builder.
pub async fn auth_middleware(
    State(state): State<Arc<AuthState>>, req: Request, next: Next,
) -> AppResult<Response, Response> {
    if state.is_empty() {
        return Ok(next.run(req).await);
    }

    let Some((username, passwd, hash)) = parse_basic_auth(req.headers()) else {
        return Err(unauthorized());
    };

    if state.validate_cached(&username, &passwd, hash).await {
        tracing::debug!(user = %username, "authentication succeeded");
        Ok(next.run(req).await)
    } else {
        tracing::warn!(user = %username, "authentication failed");
        Err(unauthorized())
    }
}

/// Decodes the `Authorization: Basic <base64>` header into username, password, and a
/// [`hash_auth_header`] cache key. Returns [`None`] if the header is missing, malformed,
/// or not Basic auth.
fn parse_basic_auth(headers: &axum::http::HeaderMap) -> Option<(String, String, u64)> {
    let header = headers.get("authorization")?.to_str().ok()?;
    let stripped = header.strip_prefix("Basic ")?;
    let header_hash = hash_auth_header(stripped);
    let decoded = general_purpose::STANDARD.decode(stripped).ok()?;
    let decoded = std::str::from_utf8(&decoded).ok()?;
    let (user, pass) = decoded.split_once(':')?;
    Some((user.to_string(), pass.to_string(), header_hash))
}

fn unauthorized() -> Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("www-authenticate", r#"Basic realm="rshs""#)
        .body(Body::empty())
        .unwrap()
}
