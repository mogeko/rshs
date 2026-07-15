//! Tailscale identity authentication middleware.
//!
//! Trusts the `Tailscale-User-Login` header that `tailscale serve` injects on
//! proxied requests (see
//! <https://tailscale.com/docs/features/tailscale-serve#identity-headers>).
//! Tailscale populates this header only for traffic it proxies from
//! user-owned tailnet devices, and it strips any client-supplied copy of the
//! header before adding its own — so as long as rshs is bound to loopback
//! and reached only via `tailscale serve`, the header cannot be spoofed by
//! anything except Tailscale itself.
//!
//! Automatically becomes a no-op when no `--accept-tailscale-serve-auth`
//! allow-list (CLI or file) is configured, exactly like the Basic Auth
//! middleware.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;

use crate::server::AppResult;

const IDENTITY_HEADER: &str = "tailscale-user-login";

/// Configured behavior for the Tailscale identity gate, built from
/// `--accept-tailscale-serve-auth` and/or `--tailscale-users-file`.
#[derive(Debug, Clone, Default)]
pub enum TailscaleAuthState {
    /// No flag/file given: middleware is a complete no-op (backward compatible).
    #[default]
    Disabled,
    /// `all` (via CLI or a bare `all` line in the users file): require a
    /// valid identity header (i.e. traffic proxied by `tailscale serve` from
    /// a user-owned tailnet device) but accept any login.
    AllowAll,
    /// A specific set of logins is allowed. Require a valid identity header
    /// AND the login must be a key in this map. The value is an optional
    /// mapped local identity (e.g. a display name or a local username to
    /// attribute writes/logs to) parsed from a users file; `None` when the
    /// login came from the plain CLI list with no mapping.
    AllowList(HashMap<String, Option<String>>),
}

impl TailscaleAuthState {
    pub fn new() -> Self {
        Self::Disabled
    }

    /// Parse the `--accept-tailscale-serve-auth` value: `"all"` (case
    /// insensitive) or a comma-separated list of logins (no mapping —
    /// use [`TailscaleAuthState::from_file`] for login-to-name mapping).
    /// Whitespace around entries is trimmed. Returns `Disabled` for an
    /// empty string.
    pub fn from_arg(raw: &str) -> Self {
        let raw = raw.trim();
        if raw.is_empty() {
            return Self::Disabled;
        }
        if raw.eq_ignore_ascii_case("all") {
            return Self::AllowAll;
        }
        let logins: HashMap<String, Option<String>> = raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(|login| (login, None))
            .collect();
        if logins.is_empty() {
            Self::Disabled
        } else {
            Self::AllowList(logins)
        }
    }

    /// Load a users file: one entry per line, `#`-prefixed comments and
    /// blank lines ignored. Each line is either:
    ///
    /// - `all` (case insensitive) — allow any authenticated tailnet login
    /// - `login@example.com` — allow this login with no mapped name
    /// - `login@example.com mapped-name` — allow this login and record
    ///   `mapped-name` (whitespace-separated, name may not itself contain
    ///   whitespace) as its local identity for downstream use
    ///
    /// A bare `all` line anywhere in the file makes the whole file behave
    /// as [`TailscaleAuthState::AllowAll`], regardless of other lines.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn from_file(path: &Path) -> io::Result<Self> {
        let content = fs::read_to_string(path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("cannot read tailscale users file {}: {e}", path.display()),
            )
        })?;

        let mut logins: HashMap<String, Option<String>> = HashMap::new();

        for (line_no, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.eq_ignore_ascii_case("all") {
                return Ok(Self::AllowAll);
            }

            let mut parts = line.split_whitespace();
            let Some(login) = parts.next() else {
                tracing::warn!(
                    path = %path.display(), line = line_no + 1, "malformed entry, skipping"
                );
                continue;
            };
            let mapped = parts.next().map(str::to_string);
            logins.insert(login.to_string(), mapped);
        }

        if logins.is_empty() {
            Ok(Self::Disabled)
        } else {
            Ok(Self::AllowList(logins))
        }
    }

    /// Merge another state into this one. `AllowAll` dominates: if either
    /// side is `AllowAll`, the result is `AllowAll`. Two `AllowList`s union
    /// their entries (later/`other` wins on mapped-name conflicts). Merging
    /// with `Disabled` is a no-op for that side.
    pub fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Self::AllowAll, _) | (_, Self::AllowAll) => Self::AllowAll,
            (Self::Disabled, x) | (x, Self::Disabled) => x,
            (Self::AllowList(mut a), Self::AllowList(b)) => {
                a.extend(b);
                Self::AllowList(a)
            }
        }
    }

    /// Whether the middleware should be skipped entirely.
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Disabled)
    }

    pub fn user_count(&self) -> usize {
        match self {
            Self::Disabled => 0,
            Self::AllowAll => usize::MAX,
            Self::AllowList(map) => map.len(),
        }
    }

    /// Whether the given login is permitted. Only meaningful when
    /// `!is_empty()` — callers should check [`is_empty`] first.
    pub fn validate(&self, login: &str) -> bool {
        match self {
            Self::Disabled => false,
            Self::AllowAll => true,
            Self::AllowList(map) => map.contains_key(login),
        }
    }

    /// The mapped local identity for `login`, if the allow-list defines one.
    /// Always `None` for `Disabled`/`AllowAll`, or for a login with no
    /// mapping configured.
    pub fn mapped_name(&self, login: &str) -> Option<&str> {
        match self {
            Self::AllowList(map) => map.get(login).and_then(|v| v.as_deref()),
            _ => None,
        }
    }
}

/// Validates the `Tailscale-User-Login` header against the configured
/// [`TailscaleAuthState`] allow-list. Skips entirely when the allow-list is
/// empty (backward compatible, matches [`crate::middleware::auth::auth_middleware`]).
///
/// Returns `403 Forbidden` when:
/// - the header is absent (request did not arrive via `tailscale serve` from
///   a user-owned device — e.g. a tagged device, a LAN client hitting the
///   port directly, or Tailscale Funnel traffic, which never carries
///   identity headers), or
/// - the header is present but the login is not in the allow-list.
///
/// # Panics
///
/// Panics if constructing the `403 Forbidden` response fails. This only
/// occurs when the response builder is in an invalid state, which cannot
/// happen with a fresh builder.
pub async fn tailscale_auth_middleware(
    State(state): State<Arc<TailscaleAuthState>>,
    req: Request,
    next: Next,
) -> AppResult<Response, Response> {
    if state.is_empty() {
        return Ok(next.run(req).await);
    }

    let Some(login) = req
        .headers()
        .get(IDENTITY_HEADER)
        .and_then(|v| v.to_str().ok())
    else {
        tracing::warn!("tailscale auth rejected: no identity header on request");
        return Err(forbidden("no Tailscale identity header on this request"));
    };

    if state.validate(login) {
        let mapped = state.mapped_name(login);
        tracing::debug!(user = %login, mapped = ?mapped, "tailscale authentication succeeded");
        Ok(next.run(req).await)
    } else {
        tracing::warn!(user = %login, "tailscale authentication failed: not in allow-list");
        Err(forbidden(&format!(
            "{login} is not authorized for this server"
        )))
    }
}

fn forbidden(msg: &str) -> Response {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Body::from(format!("403 Forbidden: {msg}\n")))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AppState, AuthState};
    use axum::http::header::{HeaderName, HeaderValue};
    use axum::middleware::from_fn_with_state;
    use axum::{Router, body::Body, extract::Request};
    use tower::ServiceExt;

    fn make_app(ts_state: TailscaleAuthState) -> (Router, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("hello.txt"), b"hi").unwrap();

        let app_state = Arc::new(AppState::new(
            dir.path().to_path_buf(),
            AuthState::new(),
            std::time::Duration::from_secs(300),
        ));
        let ts_state = Arc::new(ts_state);

        let router = Router::new()
            .fallback(crate::handlers::http::handle_get_head)
            .layer(from_fn_with_state(ts_state, tailscale_auth_middleware))
            .with_state(app_state);
        (router, dir)
    }

    #[tokio::test]
    async fn empty_allow_list_is_noop() {
        let (app, _dir) = make_app(TailscaleAuthState::new());

        let req = Request::builder()
            .uri("/hello.txt")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        if !status.is_success() {
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            panic!("status={status} body={:?}", String::from_utf8_lossy(&body));
        }
    }

    #[tokio::test]
    async fn missing_header_rejected_when_configured() {
        let state = TailscaleAuthState::from_arg("alice@example.com");
        let (app, _dir) = make_app(state);

        let req = Request::builder()
            .uri("/hello.txt")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn wrong_user_rejected() {
        let state = TailscaleAuthState::from_arg("alice@example.com");
        let (app, _dir) = make_app(state);

        let req = Request::builder()
            .uri("/hello.txt")
            .header(
                HeaderName::from_static(IDENTITY_HEADER),
                HeaderValue::from_static("mallory@evil.com"),
            )
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn allowed_user_passes() {
        let state = TailscaleAuthState::from_arg("alice@example.com");
        let (app, _dir) = make_app(state);

        let req = Request::builder()
            .uri("/hello.txt")
            .header(
                HeaderName::from_static(IDENTITY_HEADER),
                HeaderValue::from_static("alice@example.com"),
            )
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        if !status.is_success() {
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            panic!("status={status} body={:?}", String::from_utf8_lossy(&body));
        }
    }

    #[tokio::test]
    async fn allow_all_accepts_any_login_but_requires_header() {
        let state = TailscaleAuthState::from_arg("all");
        let (app, _dir) = make_app(state.clone());

        let req = Request::builder()
            .uri("/hello.txt")
            .header(
                HeaderName::from_static(IDENTITY_HEADER),
                HeaderValue::from_static("literally-anyone@example.com"),
            )
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert!(resp.status().is_success());

        let (app2, _dir2) = make_app(state);
        let req2 = Request::builder()
            .uri("/hello.txt")
            .body(Body::empty())
            .unwrap();
        let resp2 = app2.oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn from_arg_parses_all_case_insensitive() {
        assert!(matches!(
            TailscaleAuthState::from_arg("ALL"),
            TailscaleAuthState::AllowAll
        ));
        assert!(matches!(
            TailscaleAuthState::from_arg("all"),
            TailscaleAuthState::AllowAll
        ));
    }

    #[test]
    fn from_arg_parses_comma_separated_logins() {
        let state = TailscaleAuthState::from_arg("devuser@example.com, teammate@example.com");
        assert!(state.validate("devuser@example.com"));
        assert!(state.validate("teammate@example.com"));
        assert!(!state.validate("mallory@evil.com"));
    }

    #[test]
    fn from_arg_empty_is_disabled() {
        assert!(TailscaleAuthState::from_arg("").is_empty());
        assert!(TailscaleAuthState::from_arg("   ").is_empty());
    }

    #[test]
    fn from_file_parses_logins_and_mapped_names() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("tailscale-users");
        fs::write(
            &path,
            "# comment\n\ndevuser@example.com admin\nteammate@example.com\n",
        )
        .unwrap();

        let state = TailscaleAuthState::from_file(&path).unwrap();
        assert!(state.validate("devuser@example.com"));
        assert_eq!(state.mapped_name("devuser@example.com"), Some("admin"));
        assert!(state.validate("teammate@example.com"));
        assert_eq!(state.mapped_name("teammate@example.com"), None);
        assert!(!state.validate("mallory@evil.com"));
    }

    #[test]
    fn from_file_bare_all_line_wins() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("tailscale-users");
        fs::write(&path, "devuser@example.com\nall\nteammate@example.com\n").unwrap();

        let state = TailscaleAuthState::from_file(&path).unwrap();
        assert!(matches!(state, TailscaleAuthState::AllowAll));
    }

    #[test]
    fn from_file_missing_file_errors() {
        let result = TailscaleAuthState::from_file(Path::new("/nonexistent/path/does-not-exist"));
        assert!(result.is_err());
    }

    #[test]
    fn merge_allow_all_dominates() {
        let a = TailscaleAuthState::from_arg("devuser@example.com");
        let b = TailscaleAuthState::AllowAll;
        assert!(matches!(a.merge(b), TailscaleAuthState::AllowAll));
    }

    #[test]
    fn merge_disabled_is_noop() {
        let a = TailscaleAuthState::from_arg("devuser@example.com");
        let merged = a.clone().merge(TailscaleAuthState::Disabled);
        assert!(merged.validate("devuser@example.com"));

        let merged2 = TailscaleAuthState::Disabled.merge(a);
        assert!(merged2.validate("devuser@example.com"));
    }

    #[test]
    fn merge_allow_lists_union() {
        let a = TailscaleAuthState::from_arg("devuser@example.com");
        let b = TailscaleAuthState::from_arg("teammate@example.com");
        let merged = a.merge(b);
        assert!(merged.validate("devuser@example.com"));
        assert!(merged.validate("teammate@example.com"));
        assert!(!merged.validate("mallory@evil.com"));
    }
}
