//! Router construction, request dispatch, and server startup for both HTTP and HTTPS.

pub(crate) mod cleanup;
pub(crate) mod shutdown;
pub(crate) mod tls;

use std::collections::HashMap;
use std::fs;
use std::io::{self, Error, ErrorKind};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use derive_new::new;
use tokio::sync::RwLock;

use crate::auth::AuthState;
use crate::handlers::{http, locks, webdav as webdav_handler};
use crate::middleware::tailscale::TailscaleAuthState;
use crate::utils::path::{self, ResolveTargetError};
use crate::webdav::{DeadPropertyStore, LockStore, Method};

/// Shared application state passed to every handler and middleware.
///
/// Holds the root directory, auth config, WebDAV dead property store, and lock store.
/// All fields are behind `Arc` for cheap cloning.
#[derive(Clone)]
pub struct AppState {
    pub auth_state: Arc<AuthState>,
    pub tailscale_auth_state: Arc<TailscaleAuthState>,
    pub root_dir: PathBuf,
    pub root_canonical: PathBuf,
    pub dead_props: Arc<RwLock<DeadPropertyStore>>,
    pub locks: Arc<RwLock<LockStore>>,
    pub canonical_cache: Arc<Mutex<HashMap<PathBuf, PathBuf>>>,
    pub lock_timeout: Duration,
}

impl AppState {
    pub fn new(root: PathBuf, auth_state: AuthState, lock_timeout: Duration) -> Self {
        Self::with_tailscale_auth(root, auth_state, TailscaleAuthState::new(), lock_timeout)
    }

    pub fn with_tailscale_auth(
        root: PathBuf,
        auth_state: AuthState,
        tailscale_auth_state: TailscaleAuthState,
        lock_timeout: Duration,
    ) -> Self {
        let root_canonical = fs::canonicalize(&root).unwrap_or_else(|_| root.clone());
        Self {
            auth_state: Arc::new(auth_state),
            tailscale_auth_state: Arc::new(tailscale_auth_state),
            root_dir: root,
            root_canonical,
            dead_props: Arc::new(RwLock::new(DeadPropertyStore::new())),
            locks: Arc::new(RwLock::new(LockStore::new())),
            canonical_cache: Arc::new(Mutex::new(HashMap::new())),
            lock_timeout,
        }
    }

    pub(crate) async fn resolve_existing(&self, request_path: &str) -> Option<PathBuf> {
        path::resolve_existing(&self.root_dir, &self.root_canonical, request_path).await
    }

    pub(crate) fn resolve_write_target(&self, request_path: &str) -> Option<PathBuf> {
        path::resolve_write_target(&self.root_dir, request_path)
    }

    pub(crate) async fn resolve_and_guard(
        &self,
        request_path: &str,
    ) -> Result<PathBuf, ResolveTargetError> {
        path::resolve_and_guard(
            &self.root_dir,
            &self.root_canonical,
            request_path,
            &self.canonical_cache,
        )
        .await
    }
}

/// Result type alias for handlers, with [`Response`] success and [`StatusCode`] error by default.
pub type AppResult<T = Response, E = StatusCode> = Result<T, E>;

/// Configuration for starting the server — root directory, bind address,
/// optional TLS, authentication, and default lock timeout.
#[derive(Clone, new)]
pub struct ServerConfig {
    pub root_dir: PathBuf,
    pub host: String,
    pub port: u16,
    pub tls_config: Option<tls::TlsConfig>,
    pub auth_state: AuthState,
    pub tailscale_auth_state: TailscaleAuthState,
    pub lock_timeout: u64,
}

/// Builds the axum router with all middleware layers, then starts the HTTP or HTTPS
/// server. Also spawns a background task to prune expired locks and auth cache entries
/// every 30 seconds.
///
/// # Errors
///
/// Returns an error if the address cannot be parsed, the server fails to bind
/// (port already in use, permission denied), or TLS loading fails.
pub async fn start_server(config: ServerConfig) -> io::Result<()> {
    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .map_err(|e| Error::new(ErrorKind::InvalidInput, e))?;

    let auth_state = config.auth_state;
    let tailscale_auth_state = config.tailscale_auth_state;
    let root = config.root_dir;
    let lock_timeout = if config.lock_timeout == 0 {
        Duration::ZERO // A zero lock timeout means locks never expire
    } else {
        Duration::from_secs(config.lock_timeout)
    };

    let state = Arc::new(AppState::with_tailscale_auth(
        root,
        auth_state,
        tailscale_auth_state,
        lock_timeout,
    ));

    let router = make_router(state.clone());

    let cleanup_notify = Arc::new(tokio::sync::Notify::new());
    let task = cleanup::cleanup_task(
        state.locks.clone(),
        state.auth_state.auth_cache.clone(),
        cleanup_notify.clone(),
    );
    let cleanup_handle = tokio::spawn(task);

    match &config.tls_config {
        Some(tls_config) => {
            let listener = tls::TlsListener::bind(addr, tls_config.load()?).await?;
            tracing::info!(
                addr = %addr, cert = %tls_config.cert_path, key = %tls_config.key_path,
                "starting HTTPS server"
            );
            axum::serve(listener, router)
                .with_graceful_shutdown(shutdown::shutdown_signal())
                .await
                .map_err(Error::other)?;
        }
        None => {
            let listener = tokio::net::TcpListener::bind(addr).await?;
            tracing::info!(addr = %addr, "starting HTTP server");
            axum::serve(listener, router)
                .with_graceful_shutdown(shutdown::shutdown_signal())
                .await
                .map_err(Error::other)?;
        }
    }

    cleanup_notify.notify_one();

    let _ = cleanup_handle.await;

    Ok(())
}

/// Build the full middleware stack and request dispatch router from shared state.
///
/// This produces the same Router used by [`start_server`], enabling integration
/// testing without binding a TCP port. Layers are applied from inside out:
/// `HealthCheck` (outermost) -> `Auth` -> `LockEnforce` -> `TraceLayer` -> dispatch.
pub fn make_router(state: Arc<AppState>) -> Router {
    use crate::middleware::{auth, health, lock, tailscale};
    use axum::middleware::from_fn_with_state;
    use tower_http::trace::TraceLayer;

    let auth_mw = from_fn_with_state(state.auth_state.clone(), auth::auth_middleware);
    let tailscale_auth_mw = from_fn_with_state(
        state.tailscale_auth_state.clone(),
        tailscale::tailscale_auth_middleware,
    );
    let lock_mw = from_fn_with_state(state.clone(), lock::lock_enforce);
    let health_check_mw = health::HealthCheck;

    Router::new()
        .fallback(any(dispatch))
        .layer(TraceLayer::new_for_http())
        .layer(lock_mw)
        .layer(auth_mw)
        .layer(tailscale_auth_mw)
        .layer(health_check_mw)
        .with_state(state)
}

async fn dispatch(State(state): State<Arc<AppState>>, req: Request) -> impl IntoResponse {
    match Method::try_from(req.method()) {
        Ok(Method::GET) | Ok(Method::HEAD) => http::handle_get_head(State(state), req).await,
        Ok(Method::PUT) => http::handle_put(State(state), req).await,
        Ok(Method::DELETE) => http::handle_delete(State(state), req).await,
        Ok(Method::OPTIONS) => http::handle_options().await,
        Ok(Method::PROPFIND) => webdav_handler::handle_propfind(State(state), req).await,
        Ok(Method::MKCOL) => webdav_handler::handle_mkcol(State(state), req).await,
        Ok(Method::COPY) => webdav_handler::handle_copy(State(state), req).await,
        Ok(Method::MOVE) => webdav_handler::handle_move(State(state), req).await,
        Ok(Method::PROPPATCH) => webdav_handler::handle_proppatch(State(state), req).await,
        Ok(Method::LOCK) => locks::handle_lock(State(state), req).await,
        Ok(Method::UNLOCK) => locks::handle_unlock(State(state), req).await,
        _ => Err(StatusCode::NOT_IMPLEMENTED),
    }
}
