# AGENTS.md

## Build & Run

```sh
# Build
cargo check                 # fast (no codegen), use during iteration
cargo build                 # debug
cargo build --release       # optimized

# Run
cargo run                   # serve current directory
cargo run --release -- ./data -v

# Pre-commit checklist (must produce zero warnings)
cargo fmt
cargo clippy -- -D warnings
cargo test

# Run specific tests
cargo test -- utils::scandir            # unit test module
cargo test --test webdav_tests          # integration test file
cargo test PROPFIND                     # filter by test name

# Benchmarks
cargo bench                             # all 6 suites
cargo bench --bench webdav              # WebDAV protocol only
cargo bench -- "PROPFIND/depth1_dir"    # filter by name

# Litmus compliance (see Testing section)
cargo run --release -- ./data -vv       # start server
TESTS="basic http copymove locks props" TESTROOT=. ./litmus http://localhost:8080
```

## Architecture

- Single crate `rshs` with both binary (`src/main.rs`) and library (`src/lib.rs`) targets
- Library root `src/lib.rs` declares modules and re-exports public API
- Tests live in `tests/` directory (integration tests)
- Edition 2024 — requires Rust 1.88+

### Module Map

```
src/
  main.rs                       # Entry point: CLI parse, logging init, start server
  lib.rs                        # Module declarations, public re-exports

  cli.rs                        # clap-derived CLI args (Cli, ShadowFileArg)

  auth.rs                       # AuthState, Credential, shadow file mgmt, auth cache

  scandir.rs                    # Batch statx via io_uring (Linux) or std::fs::read_dir (fallback)

  html.rs                       # HTML directory listing (DirEntry, rendering)

  handlers/
    mod.rs
    http.rs                     # GET/HEAD/PUT/DELETE/OPTIONS handler
    webdav.rs                   # PROPFIND/MKCOL/COPY/MOVE/PROPPATCH handler
    locks.rs                    # LOCK/UNLOCK handler

  webdav/
    mod.rs                      # Lock types (LockInfo/LockStore/LockScope), property types
                                #   (PropEntry/PropRequest/DeadPropertyStore), Depth, general
                                #   parsers (parse_destination, parse_depth, parse_timeout,
                                #   parse_lock_token_header, parse_overwrite), ParseError
    ls.rs                       # If header types (IfCondition/IfList), If header parser,
                                #   lock evaluation (ancestor walk, eval/eval_active,
                                #   exclusive-lock check, active_slice, find_and_refresh_ancestor_lock)
    method.rs                   # Method type (enum-like struct for HTTP/WebDAV method constants)
    xml.rs                      # Multistatus XML generation, write_activelock (shared lock XML)
    fs.rs                       # Filesystem traversal + href encoding

  middleware/
    mod.rs
    health.rs                   # Health check middleware (tower Layer)
    auth.rs                     # Basic Auth middleware (auto-skips when no users configured)
    lock.rs                     # Lock enforcement middleware — uses webdav::ls for evaluation

  server/
    mod.rs                      # AppState, ServerConfig, Router construction, serve
    cleanup.rs                  # Background task: prune expired locks + auth cache entries
    shutdown.rs                 # Graceful shutdown signal handling (Ctrl+C, SIGTERM)
    tls.rs                      # TlsConfig (PEM + fingerprint + ALPN), TlsListener

  utils/
    mod.rs
    error.rs                    # OrStatus + IntoResolved traits (error-to-status-code conversion)
    path.rs                     # Path resolution (resolve_existing, resolve_write_target, resolve_and_guard)
    time.rs                     # Calendar formatting for directory listings
```

### Dependencies

| Crate                    | Features                               | Purpose                             |
| ------------------------ | -------------------------------------- | ----------------------------------- |
| `axum` 0.8               | `http2`                                | HTTP server framework               |
| `base64` 0.22            | —                                      | Basic Auth header decoding          |
| `clap` 4.6               | `derive`, `env`                        | CLI args + env var support          |
| `futures-util` 0.3       | —                                      | Stream combinators (TryStreamExt)   |
| `mime_guess` 2           | —                                      | MIME type detection                 |
| `percent-encoding` 2     | —                                      | URI percent-encode/decode           |
| `quick-xml` 0.40         | —                                      | XML parsing + generation (WebDAV)   |
| `rustls` 0.23            | —                                      | TLS protocol implementation         |
| `rustls-pemfile` 2.2     | —                                      | PEM certificate/key parsing         |
| `sha-crypt` 0.6          | `getrandom`                            | SHA-512 crypt hash verification     |
| `sha2` 0.11              | —                                      | Certificate fingerprint             |
| `tokio` 1.52             | `rt-multi-thread,net,macros,fs,signal` | Async runtime + graceful shutdown   |
| `tokio-rustls` 0.26      | —                                      | TLS acceptor for axum               |
| `tokio-util` 0.7         | `io`                                   | StreamReader for PUT body streaming |
| `tower` 0.5              | —                                      | Middleware traits (Layer, Service)  |
| `tower-http` 0.6         | `trace`                                | Request tracing middleware          |
| `tracing` 0.1            | —                                      | Structured logging facade           |
| `tracing-subscriber` 0.3 | `env-filter`, `fmt`                    | Log output + filter engine          |

**Linux-only**

| Crate          | Features | Purpose                     |
| -------------- | -------- | --------------------------- |
| `io-uring` 0.6 | —        | Batch statx for PROPFIND    |
| `libc` 0.2     | —        | `statx` struct for io_uring |

**Dev**

| Crate           | Features                      | Purpose                        |
| --------------- | ----------------------------- | ------------------------------ |
| `criterion` 0.8 | `async_tokio`, `html_reports` | Benchmarking                   |
| `rcgen` 0.14    | —                             | TLS cert generation in tests   |
| `tempfile` 3.27 | —                             | Temporary directories in tests |

**Dev (Unix-only)**

| Crate      | Features | Purpose                          |
| ---------- | -------- | -------------------------------- |
| `libc` 0.2 | —        | SIGINT/SIGTERM in shutdown tests |

### Key Patterns

- **App state**: Shared state via `AppState` struct wrapped in `Arc`, accessed by handlers
  via `axum::extract::State<Arc<AppState>>`. Fields: `root_dir` (serve root path),
  `root_canonical` (cached canonical form for path traversal checks), `auth_state`,
  `dead_props` (WebDAV dead property store), `locks` (lock store),
  `lock_timeout` (default lock duration when client omits `Timeout` header),
  `auth_cache` (successful auth result cache for SHA-512 credentials),
  `auth_cache_ttl` (cache lifetime, 0 = disabled).
  Router built with `make_router(Arc::new(state))` — also exposed as a public API
  for integration testing without binding a TCP port.
  `AppState` also provides convenience methods delegates to `utils::path`:
  `state.resolve_existing(path)`, `state.resolve_write_target(path)`,
  `state.resolve_and_guard(path)` (resolves the target, verifies the
  parent is canonical and within the root, but does NOT create parent
  directories — callers are responsible for ensuring parents exist).
- **File I/O**: Hot-path file operations (GET/HEAD serving, directory listing) use
  `tokio::fs` to offload blocking syscalls from async worker threads onto the blocking
  thread pool. Startup-only I/O (TLS cert/key loading, shadow file reads) uses
  synchronous `std::fs` since it runs before the server accepts connections and does
  not compete for worker threads.
- **Middleware via tower Layer**: Middleware is applied with `Router::layer(L)`. Tower Layers
  compose from inside out — the last `.layer()` in the chain runs first.
  Example: `Router::new().layer(TraceLayer).layer(LockEnforce).layer(Auth).layer(HealthCheck)`
  produces runtime order `HealthCheck` → `Auth` → `LockEnforce` → `TraceLayer` → handler.
- **Middleware order**: `HealthCheck` (outermost) → `Auth` → `LockEnforce` → `TraceLayer` → handler.
  HealthCheck intercepts any request with `x-health-check: true` header
  (header name matched case-insensitively; value matched as the exact ASCII bytes `true`).
  Auth middleware authenticates the request (auto-skips when no users configured).
  LockEnforce intercepts write methods: PUT, DELETE, MKCOL, PROPPATCH, MOVE, COPY.
  For COPY, only the destination is checked (source is read-only).
- **Request dispatch**: `.fallback(any(dispatch))` routes all requests through a single
  `dispatch` function that converts `req.method()` to `webdav::Method` via
  `Method::try_from()` and matches on type-safe constants:
  `Ok(Method::GET)` | `Ok(Method::HEAD)` → `http::handle_get_head`,
  `Ok(Method::PUT)` → `http::handle_put`,
  `Ok(Method::DELETE)` → `http::handle_delete`,
  `Ok(Method::OPTIONS)` → `http::handle_options`,
  `Ok(Method::PROPFIND)` → `webdav::handle_propfind`,
  `Ok(Method::MKCOL)` → `webdav::handle_mkcol`,
  `Ok(Method::COPY)` → `webdav::handle_copy`,
  `Ok(Method::MOVE)` → `webdav::handle_move`,
  `Ok(Method::PROPPATCH)` → `webdav::handle_proppatch`,
  `Ok(Method::LOCK)` → `locks::handle_lock`,
  `Ok(Method::UNLOCK)` → `locks::handle_unlock`,
  unknown → `501 Not Implemented`.
- **Path resolution**: `utils::path` provides three functions + one error type:
  - `resolve_existing()` — canonicalize + traversal check for read ops (GET/HEAD) and delete ops (DELETE)
  - `resolve_write_target()` — segment check + traversal guard for write ops (PUT/DELETE/MKCOL)
  - `resolve_and_guard(path, canonical_cache)` — resolves target, canonicalizes parent
    (using a cache), and verifies traversal safety; does NOT create parent directories —
    callers must ensure the parent exists before calling
  - `ResolveTargetError` — tagged error type with `InvalidPath`, `ParentCanonicalizeFailed`, `TraversalBlocked`;
    implements `Display` + `status(on_invalid) -> StatusCode` for handler use.
    All percent-decode the URI path via `percent_encoding::percent_decode_str`.
    If percent-decoding yields invalid UTF-8, the helpers return
    `ResolveTargetError::InvalidPath`; handlers map this to `400 Bad Request`
    via `ResolveTargetError::status(on_invalid)`.
- **Error handling**: `utils::error::OrStatus` trait extends `Result<T, E: Display>` with
  `.or_400(msg)` and `.or_500(msg)` methods that map errors to `Result<T, StatusCode>`
  with tracing log. Handlers return `Result<Response, StatusCode>`,
  using the `?` operator to propagate errors (axum auto-converts via its blanket
  `IntoResponse` impl for `Result<T: IntoResponse, E: IntoResponse>`).
  `IntoResolved` trait converts `ResolveTargetError` to `Result<T, StatusCode>`.
  Most middleware returns `AppResult` (`Result<Response, StatusCode>`).
  The auth middleware returns `Result<Response, Response>` so it can attach
  `WWW-Authenticate` headers to 401 responses.
- **XML generation**: `webdav/xml.rs` defines `XmlWriterExt` trait (adds `.ev(event)` to
  `Writer<Cursor<Vec<u8>>>` as shorthand for `.write_event(event).unwrap()`).
  `write_activelock(lock)` is the shared function for LOCK response + PROPFIND lockdiscovery XML.
  Helper functions: `multistatus(xml)` → `207 Multi-Status`.
  DAV: element name constants are grouped in the `El` zero-sized struct
  (`El::PROP`, `El::LOCKDISCOVERY`, etc.) — accessed via `rshs::webdav::xml::El`.
- **Lock system**: In-memory lock support via `LockStore` (`Arc<RwLock<HashMap<PathBuf, Vec<LockInfo>>>>`).
  Shared and exclusive locks with conflict resolution (shared+shared ok, exclusive blocks all).
  Full RFC 4918 §10.4 conditional `If` header evaluation: `Not`, `DAV:no-lock`, resource-tags, AND semantics.
  Core lock logic lives in `webdav::ls`:
  — **Types**: `IfCondition` (with `eval`/`eval_active` methods), `IfList`.
  — **Evaluation**: `parse_if_header`, `walk_locked_ancestors`, `find_ancestor_lock`,
  `find_and_refresh_ancestor_lock` (refreshes lock timeout), `eval_if`,
  `check_existing_exclusive`.
  — **Filtering**: `active_slice` (lazy expired-lock skip, used by all eval paths).
  Depth:infinity ancestor chain enforcement in `lock_enforce` + indirect refresh via
  ancestor lock discovery in `handle_lock`. Lock enforcement via tower Layer middleware
  (`middleware::lock::lock_enforce`), which converts the request method to `webdav::Method`
  via `Method::try_from()` and intercepts `Method::PUT/DELETE/MKCOL/PROPPATCH/MOVE/COPY`
  with `423 Locked` unless the request carries a matching condition.
  Expired locks and auth cache entries pruned every 30s by background task in `start_server()`.
  Default lock timeout is 300s (`--lock-timeout` / `AppState.lock_timeout`);
  `0` means unlimited. Lock enforcement filters expired locks lazily via the
  `active_slice` helper (`infos.iter().filter(|l| !l.is_expired())`),
  short-circuiting on first unexpired lock.
  `write_activelock` outputs the lock's actual `depth` value (`"0"`, `"1"`, or `"infinity"`)
  for correct litmus depth:infinity lock semantics.
  Locks are ephemeral (lost on restart).
- **Auth**: `AuthState` holds `HashMap<String, Credential>`. Auth middleware is always present
  in the chain but becomes a no-op when `is_empty()`. 401 responses include
  `WWW-Authenticate: Basic realm="rshs"` for browser password dialog support.
  SHA-512 crypt verification results are cached via `AuthCache` with configurable TTL
  (`--auth-cache-ttl`, default 60s). Cache hits refresh the expiry (sliding
  TTL), so frequently-used credentials never expire while the horizon resets on
  each request. Cache misses offload the hash verification to
  `tokio::task::spawn_blocking` to prevent blocking async worker threads.
  Failed attempts are never cached, maintaining brute-force resistance.
  Set `--auth-cache-ttl 0` to disable caching entirely (still uses `spawn_blocking`).
- **Shadow file**: Persistent credential store (`username:$hash$...` format).
  CLI credentials (`--user`) can be merged in and optionally written back to disk.
- **TLS**: `TlsListener` implements `axum::serve::Listener` wrapping a `tokio-rustls` acceptor.
  Both HTTP and HTTPS branches call `axum::serve(listener, router)` — fully symmetric.
- **Semantic completeness**: Trait methods are provided for all status codes with defined
  semantics (`or_400`, `or_404`, `or_409`, `or_500`, `or_503` + generic `or_status`),
  even if not all are currently invoked. `or_status` auto-selects log level based on
  `is_server_error()` (4xx → `debug!`, 5xx → `error!`). Handlers should use these methods
  instead of ad-hoc `StatusCode::X.into_response()` calls.

### Supported Methods

| Method    | Handler            | Module      |
| --------- | ------------------ | ----------- |
| GET/HEAD  | `handle_get_head`  | `http.rs`   |
| PUT       | `handle_put`       | `http.rs`   |
| DELETE    | `handle_delete`    | `http.rs`   |
| OPTIONS   | `handle_options`   | `http.rs`   |
| PROPFIND  | `handle_propfind`  | `webdav.rs` |
| MKCOL     | `handle_mkcol`     | `webdav.rs` |
| COPY      | `handle_copy`      | `webdav.rs` |
| MOVE      | `handle_move`      | `webdav.rs` |
| PROPPATCH | `handle_proppatch` | `webdav.rs` |
| LOCK      | `handle_lock`      | `locks.rs`  |
| UNLOCK    | `handle_unlock`    | `locks.rs`  |

### Body Streaming Pattern

PUT handler uses `StreamReader` + `tokio::io::copy` for zero-copy streaming from HTTP body to file:

```rust
let stream = body.into_data_stream().map_err(std::io::Error::other);
let mut reader = StreamReader::new(stream);
let bytes_written = tokio::io::copy(&mut reader, &mut file).await?;
```

`TryStreamExt::map_err` bridges `axum::Error` → `io::Error` for `StreamReader` compatibility.

### Known Limitations

| Item                      | Status   | Description                                                                                                                                                                                |
| ------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Dead property persistence | Accepted | In-memory only (`DeadPropertyStore`), lost on restart. Accepted as architectural trade-off; sidecar persistence deferred                                                                   |
| `getetag` format          | Accepted | Uses mtime+size hex hash (Nginx-style). Cannot detect same-second changes with identical file size. Deliberate trade-off — inodes are not portable across platforms or restart-persistent. |
| HTML directory listing    | Accepted | Unindented HTML (no cosmetic whitespace) to reduce transfer size. Fully structured with DOCTYPE, semantic elements, and navigable links.                                                   |
| Fragment in request URI   | Accepted | The HTTP library (hyper/axum) strips `#fragment` before routing per RFC 7230 §5.1. Cannot reject at application layer — client responsibility. Litmus issues a warning, not a failure.     |

## Conventions

- Standard Rust conventions; no custom formatter or lint config overrides
- Run `cargo fmt` then `cargo clippy` before committing — both must produce zero warnings
- Types accessible via crate root are re-exported from `src/lib.rs`; other public types
  are accessed via module paths (e.g. `rshs::handlers::http::handle_get_head`)
- Update `AGENTS.md`, `README.md` and `docs/` accordingly when new features are added or existing ones are changed

## Defensive Programming

Use `debug_assert!` to encode internal call-site invariants in private helper functions.
These assertions catch contract violations in dev/debug builds and compile away entirely
in release mode (zero overhead).

- **When to use**: When a private function expects the caller to have already performed a
  guard check (e.g. `read_angle_bracket` asserts `bytes[p] == b'<'` because `parse_if_header`
  already branched on `<`). An assertion is better than a comment — it enforces itself.

- **When to avoid**: Public-API input validation. `debug_assert!` is stripped in release;
  use regular `assert!`, `expect()`, or `Result` errors at API boundaries. Also avoid for
  security-critical checks that must never be removed.

- **Pattern**:
  ```rust
  fn read_angle_bracket(bytes: &[u8], p: usize) -> Option<(String, usize)> {
      debug_assert!(bytes.get(p) == Some(&b'<'), "caller must position cursor at '<'");
      // …
  }
  ```

## Documentation

All `pub` and `pub(crate)` items must have `///` doc comments. Module-level
docs use `//!`.

### Requirements

| Item type                           | Doc?  | Doc-test?   | Rationale                                   |
| ----------------------------------- | ----- | ----------- | ------------------------------------------- |
| Struct, enum, trait                 | `///` | If feasible | Show construction / typical usage           |
| Function, method (pure)             | `///` | ` ``` `     | Doc-test replaces happy-path unit test      |
| Function, method (async handler)    | `///` | No          | Too complex to set up; unit test stays      |
| Function, method (async middleware) | `///` | No          | Same reason; unit test stays                |
| `pub(crate)` module items           | `///` | No          | Not accessible from doc-test crate boundary |
| Constant, type alias                | `///` | No          | Trivial; prose example if useful            |
| Struct field                        | `///` | No          | Covered by struct-level docs                |

### Doc-test style

````rust
/// One or two sentences explaining what this does.
///
/// ```
/// use rshs::module::Item;
///
/// let result = Item::do_thing();
/// assert_eq!(result, expected);
/// ```
pub fn do_thing() -> ...
````

### Test layer strategy

| Layer             | Location              | Scope                                   | When to prioritize                             |
| ----------------- | --------------------- | --------------------------------------- | ---------------------------------------------- |
| Doc-tests         | Inline `/// ``` `     | API usage examples                      | Pure functions, simple constructors            |
| Unit tests        | `src/` `#[cfg(test)]` | Edge cases, error paths, filesystem I/O | Internal logic not reachable via public API    |
| Integration tests | `tests/`              | Full middleware-chain happy paths       | Every HTTP/WebDAV method through `make_router` |

- Doc-tests replace happy-path unit test cases where feasible (reducing
  duplication). Refer to the doc-test table above for constraints.
- Unit tests are kept for scenarios that can't be doc-tested: async handlers,
  middleware, filesystem ops, private functions, error paths.
- Integration tests exercise the complete middleware stack via
  [`make_router`](src/server/mod.rs). They verify middleware ordering
  (HealthCheck → LockEnforce → Auth → dispatch) and cross-cutting behaviour.
- When adding a new feature, first write the doc-test (if feasible), then the
  integration test for the happy path, then unit tests for edge cases.

## Visibility Guidelines

| Visibility       | When to use                                                          | Example                                               |
| ---------------- | -------------------------------------------------------------------- | ----------------------------------------------------- |
| `pub`            | External consumers: `main.rs`, integration tests, library re-export  | Handlers, `AuthState`, `AppState`, `HealthCheck`      |
| `pub(crate)`     | Used across `src/` modules but not by external callers               | `utils/*`, `DEFAULT_LOG_LEVEL`, `AppState::resolve_*` |
| `pub(crate) mod` | Module items are re-exported at crate root (no need for direct path) | `cli`, `server`, `utils`                              |
| `pub mod`        | Items accessed directly via public path (`rshs::module::Item`)       | `handlers`, `middleware`, `webdav`, `auth`            |
| Private          | Used only within the defining module                                 | Internal helpers, parser internals                    |

### Decision flow

1. Does the item need to be accessible from `main.rs`, integration tests, or
   library consumers? → **`pub`**
2. Is the item used across modules within `src/` but not needed externally?
   → **`pub(crate)`**
3. Is the item used only within its own module? → **private**

### Module-level visibility

- Module is `pub` if any item inside needs to be accessed via a public path
  (e.g. `rshs::handlers::http::handle_get_head`).
- Module is `pub(crate)` if items are re-exported at crate root (e.g.
  `server` → `pub use server::{AppState, ServerConfig, ...}`).
- Sub-modules can be `pub(crate)` even when the parent module is `pub` (e.g.
  `webdav::ls` is `pub(crate)` within `pub mod webdav`). Items within are
  accessible crate-wide but not externally.

## Testing

- Unit tests in `src/` modules, integration tests in `tests/` — all run with `cargo test`
- External crates in tests reference via the `rshs` crate (not by relative module paths)
- Use `#[cfg(test)]` for test-only code in the library crate
- Add or update tests for the code you change, even if nobody asked

### Litmus compliance testing

The [litmus](https://github.com/notroj/litmus) WebDAV test suite can be run against the server
to verify protocol compliance.

```sh
# Start server
cargo run --release -- ./data -vv

# Run litmus (from another terminal)
TESTS="basic http copymove locks props" TESTROOT=. ./litmus http://localhost:8080
```

### Benchmarking

Performance benchmarks use [Criterion.rs](https://github.com/bheisler/criterion.rs) 0.5
with `async_tokio` and `html_reports` features. Benchmarks are defined under `benches/`
and compiled as separate executables (`harness = false`).

```
benches/
  common/mod.rs                   # Shared setup: routers, file trees, request builders
  micro.rs                        # Pure CPU functions (parsing, XML gen, auth, lock eval)
  fileserver.rs                   # GET/PUT/DELETE, dir listing, throughput
  webdav.rs                       # PROPFIND, MKCOL, COPY, MOVE, LOCK/UNLOCK, PROPPATCH
  middleware.rs                   # HealthCheck, Auth, LockEnforce overhead
  path_resolve.rs                 # Path resolution depth, cold/hot cache
  scenarios.rs                    # End-to-end: browser, sync, lock-edit-unlock, mixed
```

```sh
cargo bench                      # Run all 6 suites (52 benchmarks total)
cargo bench --bench fileserver   # File server only
cargo bench -- "GET/tiny"        # Filter by benchmark name
```

Results are written to `target/criterion/report/index.html`.

**Pattern**: All benchmarks use `tower::ServiceExt::oneshot()` against the production
`make_router()` — no TCP binding. Async benchmarks use `tokio::runtime::Runtime::block_on()`
inside a sync `b.iter()` closure. Benchmarks that mutate filesystem state (DELETE, MKCOL,
PUT create) recreate a fresh `TempDir` per iteration.

**Conventions**:

- Benchmarks are compiled with `bench` profile (optimized, no debug assertions).
- Each bench file declares `mod common` and imports from `benches/common/mod.rs`.
- Shared helpers (`make_get`, `create_files`, etc.) live in `common`; suppress
  `dead_code` warnings per-file via `#![allow(dead_code)]`.
- Run `cargo bench` before pushing changes that affect hot-path code.
- Update `docs/benchmark-report.md` when results change meaningfully.

## Authentication

Basic HTTP Authentication (RFC 7617) is supported via `--user` / `-u` and `RSHS_USERS` env var.

```sh
rshs --user admin:secret --user viewer:public ./data
RSHS_USERS="admin:secret;viewer:public" rshs ./data
```

- Credentials format: `username:password`, multiple pairs separated by `;`
- CLI values take precedence over env var values for the same username
- If no users are configured, the server runs without authentication (backward compatible)

Shadow files provide persistent credential storage in SHA-512 crypt format:

```sh
rshs -S ./shadow --user admin:secret ./data
rshs -S /etc/rshs/shadow:rw -W --user admin:newpass ./data
RSHS_SHADOW_FILE=./shadow:ro rshs ./data
```

- Shadow file path can be suffixed with `:rw` (default) or `:ro` to control write access.
  If `--shadow-write` is passed but the configured shadow file is `:ro`, the server
  exits with an error: `error: shadow file is read-only; cannot write '--shadow-write'`.
- `-W` / `--shadow-write` writes CLI credentials into the shadow file after merge
  (requires shadow file to be writable — `:rw` or no explicit suffix)
- Shadow files store passwords hashed with SHA-512 crypt (`$6$...`)

Auth caching reduces the overhead of repeated SHA-512 verification for returning clients:

```sh
rshs --auth-cache-ttl 120 ./data               # 120s TTL
rshs --auth-cache-ttl 0 ./data                  # disable caching
RSHS_AUTH_CACHE_TTL=120 rshs ./data             # via env var
```

- Default TTL is 60 seconds; set `--auth-cache-ttl 0` to disable
- Only successful authentications are cached — failed attempts always go through full SHA-512 verification
- Cache hits refresh the TTL (sliding expiration): each successful lookup resets expiry to `now + auth_cache_ttl`
- Cache entries are pruned by the background cleanup task every 30s when expired
- Password changes take effect after at most `auth_cache_ttl` seconds

## TLS

TLS/HTTPS is enabled by providing both a certificate and private key file in PEM format:

```sh
rshs --tls-cert cert.pem --tls-key key.pem ./data
RSHS_TLS_CERT=cert.pem RSHS_TLS_KEY=key.pem rshs ./data
```

- Default port switches from 8080 to 8443 when TLS is enabled (unless `--port` is explicitly set)
- Certificate SHA-256 fingerprint is logged at startup (colon-separated uppercase hex)
- HTTP/2 negotiation enabled via ALPN (`h2` + `http/1.1`)
- PEM loading failures are logged at `error` level before exiting
- TLS is _not_ auto-detected — both cert and key must be explicitly provided

## Modes

The server always runs in HTTP + WebDAV hybrid mode:

```sh
rshs ./data                # Serve files in ./data
rshs                       # Default: serve current directory
RSHS_ROOT_DIR=./data rshs  # Set root via env var
```

- **Browser**: GET/HEAD → HTML directory listing, file serving
- **WebDAV client**: PROPFIND/PUT/DELETE/MKCOL… → WebDAV protocol

## Health Check

Header-based health check via the `HealthCheck` middleware (sits outermost in the chain, before auth).
Any request with header `x-health-check: true` returns `200 OK` with body `OK`,
regardless of path. Does not require authentication.

```sh
curl -H "x-health-check: true" http://localhost:8080/
# → 200 OK, body: OK
```

- The middleware uses `tower::Layer` pattern for body-type-agnostic interception
- Placed as outermost `.layer()` so it runs before auth and tracing
- Health check requests are logged at `debug` level: `tracing::debug!(%peer, "health check")`

## Logging

Uses the `tracing` ecosystem (structured, span-based) with `tracing-subscriber` as the output backend.

Log level is determined by the following priority (highest first):

1. `-q` / `--quiet` — suppress all logs (`off`)
2. `-vv` / `--verbose --verbose` — trace level
3. `-v` / `--verbose` — debug level
4. `RSHS_LOG` env var — `EnvFilter` string (e.g. `info`, `rshs=debug`, `rshs[status=500]=trace`)
5. Default — `info` level

```sh
rshs -v                                 # debug
rshs -vv                                # trace
rshs -q                                 # silent
rshs                                    # info (or RSHS_LOG if set)
RSHS_LOG="rshs[status=500]=debug" rshs  # only 500 errors at debug
RSHS_LOG="warn,rshs=debug" rshs         # global warn, rshs debug
```

`RSHS_LOG_STYLE` controls ANSI color output (`auto`, `always`, `never`).

## Environment Variables

| Env Var               | Description                                           |
| --------------------- | ----------------------------------------------------- |
| `RSHS_ROOT_DIR`       | Root directory (default: `.`)                         |
| `RSHS_HOST`           | Bind address                                          |
| `RSHS_PORT`           | Bind port                                             |
| `RSHS_TLS_CERT`       | TLS certificate file path (PEM format)                |
| `RSHS_TLS_KEY`        | TLS private key file path (PEM format)                |
| `RSHS_USERS`          | Basic Auth credentials                                |
| `RSHS_LOG`            | Logging level (e.g. `info`)                           |
| `RSHS_LOG_STYLE`      | Log output style (e.g. `auto`, `always`, `never`)     |
| `RSHS_SHADOW_FILE`    | Shadow file path with optional `:rw`/`:ro` suffix     |
| `RSHS_LOCK_TIMEOUT`   | Default WebDAV lock timeout in seconds (default: 300) |
| `RSHS_AUTH_CACHE_TTL` | Auth cache TTL in seconds (default: 60, 0 = disabled) |
