//! Authentication types, shadow file management, and the `build_auth_state` entry point.

use std::collections::HashMap;
use std::fs;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use sha_crypt::{PasswordHasher, PasswordVerifier, ShaCrypt};

use crate::cli::Cli;

/// Maps hashed Authorization header values to their cache expiry time.
/// Presence of a key indicates a previous successful SHA-512 crypt verification;
/// the value is the [`Instant`] at which the entry should be evicted.
pub(crate) type AuthCache = HashMap<u64, Instant>;

/// A stored credential for Basic HTTP authentication.
///
/// ```
/// use rshs::auth::Credential;
///
/// let pw = Credential::Plaintext("secret".into());
/// let hash = Credential::Sha512Crypt("$6$...".into());
/// ```
#[derive(Debug, Clone)]
pub enum Credential {
    Plaintext(String),
    Sha512Crypt(String),
}

/// Parsed shadow file argument from CLI.
///
/// Determines the shadow file path and whether it is writable (`:rw` or `:ro`).
///
/// ```
/// use rshs::auth::ShadowFileArg;
///
/// let a = ShadowFileArg::from_arg("/etc/rshs/shadow:rw");
/// assert_eq!(a.path, "/etc/rshs/shadow");
/// assert!(a.writable);
///
/// let a = ShadowFileArg::from_arg("/etc/rshs/shadow:ro");
/// assert!(!a.writable);
///
/// let a = ShadowFileArg::from_arg("/etc/rshs/shadow");
/// assert!(a.writable); // default
/// ```
#[derive(Debug, Clone)]
pub struct ShadowFileArg {
    pub path: String,
    pub writable: bool,
}

impl ShadowFileArg {
    /// Create a new shadow file argument with the given path and writability.
    pub fn new(path: String, writable: bool) -> Self {
        Self { path, writable }
    }

    /// Parse a shadow file spec string: `PATH[:rw|:ro]`. Defaults to `:rw`.
    pub fn from_arg(s: &str) -> Self {
        if let Some(path) = s.strip_suffix(":rw") {
            ShadowFileArg::new(path.to_string(), true)
        } else if let Some(path) = s.strip_suffix(":ro") {
            ShadowFileArg::new(path.to_string(), false)
        } else {
            ShadowFileArg::new(s.to_string(), true)
        }
    }
}

/// In-memory collection of HTTP Basic Auth credentials.
///
/// Holds usernames mapped to either plaintext or SHA-512 crypt hashed
/// passwords. Supports loading from a shadow file, merging CLI-provided
/// credentials, and validating authentication attempts.
///
/// ```
/// use rshs::auth::AuthState;
///
/// let mut config = AuthState::new();
/// assert!(config.is_empty());
///
/// config.add_user("admin", "secret");
/// assert_eq!(config.user_count(), 1);
/// assert!(config.validate("admin", "secret"));
/// assert!(!config.validate("admin", "wrong"));
/// assert!(!config.validate("nobody", "secret"));
/// ```
#[derive(Debug, Clone, Default)]
pub struct AuthState {
    pub users: HashMap<String, Credential>,
    pub auth_cache: Arc<RwLock<AuthCache>>,
    pub auth_cache_ttl: Duration,
}

impl AuthState {
    /// Create an empty configuration with an auth cache defaulting to 60s TTL.
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            auth_cache: Arc::new(RwLock::new(AuthCache::new())),
            auth_cache_ttl: Duration::from_secs(60),
        }
    }

    /// Add a user with a plaintext password.
    ///
    /// The password is stored as-is; hashing happens on write to shadow file
    /// via [`write_to_shadow_file`](Self::write_to_shadow_file).
    pub fn add_user(&mut self, username: &str, password: &str) {
        self.users.insert(
            username.to_string(),
            Credential::Plaintext(password.to_string()),
        );
    }

    /// Whether no users are configured (auth middleware is skipped).
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    /// Number of configured users.
    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    /// Validate a username/password pair against stored credentials.
    ///
    /// Supports both plaintext and SHA-512 crypt hash comparison.
    ///
    /// ```
    /// use rshs::auth::{AuthState, Credential};
    /// use std::collections::HashMap;
    ///
    /// let mut config = AuthState::new();
    /// config.users.insert("admin".into(), Credential::Sha512Crypt(
    ///     "$6$rounds=5000$abc$XyZ...".into()
    /// ));
    /// // Validation logic is tested in the unit test suite with real hashes.
    /// ```
    pub fn validate(&self, username: &str, password: &str) -> bool {
        match self.users.get(username) {
            Some(Credential::Plaintext(expected)) => expected == password,
            Some(Credential::Sha512Crypt(hash)) => ShaCrypt::default()
                .verify_password(password.as_bytes(), hash.as_str())
                .is_ok(),
            None => false,
        }
    }

    /// Validate with auth caching for SHA-512 credentials.
    ///
    /// For [`Credential::Plaintext`], uses inline comparison (no cache overhead).
    /// For [`Credential::Sha512Crypt`], first checks the cache keyed by `header_hash`.
    /// On cache miss, offloads the expensive password verify to
    /// [`tokio::task::spawn_blocking`] so async worker threads are not blocked,
    /// then writes successful results back into the cache.
    ///
    /// Cache TTL is controlled by `self.auth_cache_ttl`; set to [`Duration::ZERO`]
    /// to disable caching entirely (re-verify every call, but still uses `spawn_blocking`).
    pub async fn validate_cached(&self, username: &str, password: &str, header_hash: u64) -> bool {
        match self.users.get(username) {
            Some(Credential::Plaintext(expected)) => expected == password,
            Some(Credential::Sha512Crypt(hash)) => {
                let cache_enabled = self.auth_cache_ttl.as_secs() > 0;

                if cache_enabled
                    && if let Ok(g) = self.auth_cache.read() {
                        g.get(&header_hash).is_some_and(|e| *e > Instant::now())
                    } else {
                        false
                    }
                {
                    let expiry = Instant::now() + self.auth_cache_ttl;
                    if let Ok(mut guard) = self.auth_cache.write() {
                        guard.entry(header_hash).and_modify(|e| *e = expiry);
                    }
                    return true;
                }

                let pw = password.to_string();
                let hash = hash.clone();
                let ok = tokio::task::spawn_blocking(move || {
                    ShaCrypt::default()
                        .verify_password(pw.as_bytes(), hash.as_str())
                        .is_ok()
                })
                .await
                .unwrap_or(false);

                if ok && cache_enabled {
                    let expiry = Instant::now() + self.auth_cache_ttl;
                    if let Ok(mut guard) = self.auth_cache.write() {
                        guard.insert(header_hash, expiry);
                    }
                }

                ok
            }
            None => false,
        }
    }

    /// Merge CLI-provided credentials into this config.
    ///
    /// Existing users with the same username are overwritten.
    ///
    /// ```
    /// use rshs::auth::AuthState;
    ///
    /// let mut base = AuthState::new();
    /// base.add_user("admin", "old");
    ///
    /// let mut cli = AuthState::new();
    /// cli.add_user("admin", "new");
    /// cli.add_user("viewer", "view");
    ///
    /// base.merge_cli(&cli);
    /// assert_eq!(base.user_count(), 2);
    /// assert!(base.validate("admin", "new"));
    /// assert!(base.validate("viewer", "view"));
    /// ```
    pub fn merge_cli(&mut self, other: &AuthState) {
        for (username, credential) in &other.users {
            self.users.insert(username.clone(), credential.clone());
        }
    }

    /// Load credentials from a shadow file.
    ///
    /// Each line must be in `username:$hash$...` format (SHA-512 crypt).
    /// Empty lines and malformed entries are skipped with a warning.
    ///
    /// # Errors
    ///
    /// Returns an error if the shadow file cannot be read (missing,
    /// permission denied, or not valid UTF-8).
    pub fn load_from_shadow_file(path: &Path) -> io::Result<Self> {
        let content = fs::read_to_string(path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("cannot read shadow file {}: {e}", path.display()),
            )
        })?;
        let mut config = AuthState::new();

        for (line_no, line) in content.lines().enumerate() {
            let line = line.trim();

            if line.is_empty() {
                continue;
            }

            match line.split_once(':') {
                Some((username, rest)) if !username.is_empty() => {
                    let hash = if let Some((h, _)) = rest.split_once(':') {
                        h
                    } else {
                        rest
                    };

                    if hash.is_empty() || !hash.starts_with('$') {
                        tracing::warn!(
                            path = %path.display(), line = line_no + 1, "unsupported hash format, skipping"
                        );
                        continue;
                    }

                    config.users.insert(
                        username.to_string(),
                        Credential::Sha512Crypt(hash.to_string()),
                    );
                }
                _ => {
                    tracing::warn!(
                        path = %path.display(), line = line_no + 1, "malformed entry, skipping"
                    );
                }
            }
        }

        Ok(config)
    }

    /// Write credentials to a shadow file.
    ///
    /// Plaintext passwords are hashed with SHA-512 crypt before writing.
    /// If `create` is true, the file is created with `0600` permissions.
    ///
    /// # Errors
    ///
    /// Returns an error if parent directory creation fails, the shadow file
    /// cannot be created, permissions cannot be set, or password hashing fails.
    pub fn write_to_shadow_file(&self, path: &Path, create: bool) -> io::Result<()> {
        if create {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!("cannot create parent dir {}: {e}", parent.display()),
                    )
                })?;
            }

            let file = fs::File::create_new(path).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("cannot create shadow file {}: {e}", path.display()),
                )
            })?;

            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!("cannot set permissions on {}: {e}", path.display()),
                    )
                })?;
        }

        let mut content = String::new();
        for (username, credential) in &self.users {
            let hash = match credential {
                Credential::Sha512Crypt(h) => h.clone(),
                Credential::Plaintext(p) => ShaCrypt::default()
                    .hash_password(p.as_bytes())
                    .map_err(|e| io::Error::other(format!("cannot hash password: {e}")))?
                    .to_string(),
            };
            content.push_str(username);
            content.push(':');
            content.push_str(&hash);
            content.push('\n');
        }

        fs::write(path, &content).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("cannot write shadow file {}: {e}", path.display()),
            )
        })?;

        Ok(())
    }
}

/// Deterministic SipHash-2-4 of a raw Basic Auth base64 credential string.
///
/// Same input always produces the same `u64` within a single process lifetime.
/// Used as the cache key for [`AuthState::validate_cached`].
pub(crate) fn hash_auth_header(value: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// Build the authentication configuration from CLI arguments.
///
/// Merges credentials from `--user` flags and a shadow file (if specified),
/// and optionally writes the merged result back to disk via `--shadow-write`.
pub fn build_auth_state(cli: &Cli) -> AuthState {
    let cli_creds = cli.to_auth_state();

    let Some(shadow) = cli.to_shadow_file_arg() else {
        return cli_creds;
    };

    let shadow_path = Path::new(&shadow.path);

    if cli.shadow_write && !shadow.writable {
        tracing::warn!(
            path = %shadow.path, "shadow file is read-only (:ro), ignoring --shadow-write"
        );
    }

    if let Some(parent) = shadow_path.parent() {
        let parent_str = parent.as_os_str();
        if !parent_str.is_empty() && !parent.exists() {
            if let Err(e) = fs::create_dir_all(parent) {
                tracing::error!(path = %parent.display(), error = %e, "failed to create directory");
            } else {
                tracing::info!(path = %parent.display(), "created directory");
            }
        }
    }

    let file_exists = shadow_path.exists();

    if !file_exists {
        match create_shadow_file(shadow_path) {
            Ok(()) => tracing::info!(path = %shadow.path, "created shadow file (mode 600)"),
            Err(e) => {
                tracing::error!(path = %shadow.path, error = %e, "failed to create shadow file")
            }
        }
    }

    let mut auth_state = match AuthState::load_from_shadow_file(shadow_path) {
        Ok(cfg) => {
            if cfg.user_count() > 0 {
                tracing::info!(
                    count = cfg.user_count(), path = %shadow.path, "loaded users from shadow file"
                );
            }
            cfg
        }
        Err(e) => {
            tracing::error!(error = %e, path = %shadow.path, "failed to load shadow file");
            AuthState::new()
        }
    };

    if !cli_creds.is_empty() {
        auth_state.merge_cli(&cli_creds);
    }

    if cli.shadow_write {
        if !is_path_writable(shadow_path) {
            tracing::warn!(
                path = %shadow.path, "shadow file is read-only (OS), ignoring --shadow-write"
            );
        } else {
            match auth_state.write_to_shadow_file(shadow_path, false) {
                Ok(()) => {
                    tracing::info!(
                        count = auth_state.user_count(), path = %shadow.path, "wrote users to shadow file"
                    );
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to write shadow file");
                }
            }
        }
    } else if shadow.writable && shadow_path.exists() && !is_path_writable(shadow_path) {
        tracing::warn!(
            path = %shadow.path, "shadow file is declared :rw but file is read-only at OS level"
        );
    }

    auth_state.auth_cache_ttl = if cli.auth_cache_ttl == 0 {
        Duration::ZERO
    } else {
        Duration::from_secs(cli.auth_cache_ttl)
    };

    auth_state
}

fn is_path_writable(path: &Path) -> bool {
    if let Ok(meta) = fs::metadata(path) {
        !meta.permissions().readonly()
    } else if let Some(parent) = path.parent() {
        fs::metadata(parent)
            .map(|m| !m.permissions().readonly())
            .unwrap_or(true)
    } else {
        true
    }
}

fn create_shadow_file(path: &Path) -> std::io::Result<()> {
    fs::File::create_new(path)?.set_permissions(fs::Permissions::from_mode(0o600))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn make_hashed_entry(username: &str, password: &str) -> String {
        let hash = ShaCrypt::default()
            .hash_password(password.as_bytes())
            .unwrap()
            .to_string();
        format!("{username}:{hash}\n")
    }

    #[test]
    fn test_validate_sha512_crypt() {
        let hash = ShaCrypt::default()
            .hash_password("mypassword".as_bytes())
            .unwrap()
            .to_string();
        let mut config = AuthState::new();
        config
            .users
            .insert("admin".to_string(), Credential::Sha512Crypt(hash));
        assert!(config.validate("admin", "mypassword"));
        assert!(!config.validate("admin", "wrong"));
    }

    #[test]
    fn test_validate_mixed_credentials() {
        let hash = ShaCrypt::default()
            .hash_password("hashedpass".as_bytes())
            .unwrap()
            .to_string();
        let mut config = AuthState::new();
        config.add_user("cli_user", "plainpass");
        config
            .users
            .insert("file_user".to_string(), Credential::Sha512Crypt(hash));
        assert!(config.validate("cli_user", "plainpass"));
        assert!(!config.validate("cli_user", "wrong"));
        assert!(config.validate("file_user", "hashedpass"));
        assert!(!config.validate("file_user", "wrong"));
    }

    #[test]
    fn test_load_shadow_file_single_user() {
        let content = make_hashed_entry("admin", "adminpass");
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &content).unwrap();

        let config = AuthState::load_from_shadow_file(file.path()).unwrap();
        assert!(!config.is_empty());
        assert_eq!(config.user_count(), 1);
        assert!(config.validate("admin", "adminpass"));
        assert!(!config.validate("admin", "wrong"));
    }

    #[test]
    fn test_load_shadow_file_multiple_users() {
        let mut content = make_hashed_entry("alice", "alicepass");
        content.push_str(&make_hashed_entry("bob", "bobpass"));
        content.push_str(&make_hashed_entry("carol", "carolpass"));
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &content).unwrap();

        let config = AuthState::load_from_shadow_file(file.path()).unwrap();
        assert_eq!(config.user_count(), 3);
        assert!(config.validate("alice", "alicepass"));
        assert!(config.validate("bob", "bobpass"));
        assert!(config.validate("carol", "carolpass"));
    }

    #[test]
    fn test_load_shadow_file_skips_empty_lines() {
        let mut content = String::new();
        content.push('\n');
        content.push_str(&make_hashed_entry("admin", "adminpass"));
        content.push_str("\n\n");
        content.push_str(&make_hashed_entry("viewer", "viewerpass"));
        content.push('\n');
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &content).unwrap();

        let config = AuthState::load_from_shadow_file(file.path()).unwrap();
        assert_eq!(config.user_count(), 2);
        assert!(config.validate("admin", "adminpass"));
        assert!(config.validate("viewer", "viewerpass"));
    }

    #[test]
    fn test_load_shadow_file_skips_malformed_lines() {
        let mut content = String::new();
        content.push_str(&make_hashed_entry("admin", "adminpass"));
        content.push_str("malformed_line_without_colon\n");
        content.push_str(":nousername\n");
        content.push_str(&make_hashed_entry("viewer", "viewerpass"));
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &content).unwrap();

        let config = AuthState::load_from_shadow_file(file.path()).unwrap();
        assert_eq!(config.user_count(), 2);
        assert!(config.validate("admin", "adminpass"));
        assert!(config.validate("viewer", "viewerpass"));
    }

    #[test]
    fn test_load_shadow_file_nonexistent() {
        let result = AuthState::load_from_shadow_file(Path::new("/nonexistent/shadow/file"));
        assert!(result.is_err());
    }

    #[test]
    fn test_write_to_shadow_file_roundtrip() {
        let mut config = AuthState::new();
        config.add_user("admin", "adminpass");
        config.add_user("viewer", "viewerpass");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shadow");

        config.write_to_shadow_file(&path, true).unwrap();

        let loaded = AuthState::load_from_shadow_file(&path).unwrap();
        assert_eq!(loaded.user_count(), 2);
        assert!(loaded.validate("admin", "adminpass"));
        assert!(loaded.validate("viewer", "viewerpass"));
        assert!(!loaded.validate("admin", "wrong"));
    }

    #[test]
    fn test_write_to_shadow_file_hashes_plaintext() {
        let mut config = AuthState::new();
        config.add_user("admin", "secret123");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shadow");

        config.write_to_shadow_file(&path, true).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("admin:$6$"));

        let loaded = AuthState::load_from_shadow_file(&path).unwrap();
        assert!(loaded.validate("admin", "secret123"));
        assert!(!loaded.validate("admin", "wrong"));
    }

    #[test]
    fn test_create_file_with_mode_600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shadow");

        let mut config = AuthState::new();
        config.add_user("admin", "secret");

        config.write_to_shadow_file(&path, true).unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn test_is_path_writable_existing_file() {
        let file = NamedTempFile::new().unwrap();
        assert!(is_path_writable(file.path()));
    }

    #[test]
    fn test_is_path_writable_readonly_file() {
        let file = NamedTempFile::new().unwrap();
        let mut perms = fs::metadata(file.path()).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(file.path(), perms).unwrap();
        assert!(!is_path_writable(file.path()));
    }

    #[test]
    fn test_is_path_writable_nonexistent_in_writable_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent");
        assert!(is_path_writable(&path));
    }

    #[tokio::test]
    async fn test_validate_cached_cache_hit_refreshes_ttl() {
        let hash = ShaCrypt::default()
            .hash_password("mypassword".as_bytes())
            .unwrap()
            .to_string();
        let mut config = AuthState::new();
        config
            .users
            .insert("admin".into(), Credential::Sha512Crypt(hash));
        config.auth_cache_ttl = Duration::from_secs(60);

        let creds = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "admin:mypassword",
        );
        let header_hash = hash_auth_header(&creds);

        assert!(
            config
                .validate_cached("admin", "mypassword", header_hash)
                .await
        );

        let expiry1 = config
            .auth_cache
            .read()
            .unwrap()
            .get(&header_hash)
            .copied()
            .unwrap();

        assert!(
            config
                .validate_cached("admin", "mypassword", header_hash)
                .await
        );

        let expiry2 = config
            .auth_cache
            .read()
            .unwrap()
            .get(&header_hash)
            .copied()
            .unwrap();

        assert!(expiry2 > expiry1, "TTL should be refreshed on cache hit");
    }

    #[tokio::test]
    async fn test_validate_cached_cache_hit_returns_true() {
        let hash = ShaCrypt::default()
            .hash_password("mypassword".as_bytes())
            .unwrap()
            .to_string();
        let mut config = AuthState::new();
        config
            .users
            .insert("admin".into(), Credential::Sha512Crypt(hash));
        config.auth_cache_ttl = Duration::from_secs(60);

        let creds = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "admin:mypassword",
        );
        let header_hash = hash_auth_header(&creds);

        // First call — cache miss
        assert!(
            config
                .validate_cached("admin", "mypassword", header_hash)
                .await
        );

        // Subsequent calls — cache hits
        for _ in 0..5 {
            assert!(
                config
                    .validate_cached("admin", "mypassword", header_hash)
                    .await
            );
        }
    }

    #[tokio::test]
    async fn test_validate_cached_wrong_password_not_cached() {
        let hash = ShaCrypt::default()
            .hash_password("mypassword".as_bytes())
            .unwrap()
            .to_string();
        let mut config = AuthState::new();
        config
            .users
            .insert("admin".into(), Credential::Sha512Crypt(hash));
        config.auth_cache_ttl = Duration::from_secs(60);

        let creds = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "admin:wrongpass",
        );
        let wrong_hash = hash_auth_header(&creds);

        assert!(
            !config
                .validate_cached("admin", "wrongpass", wrong_hash)
                .await
        );

        assert!(
            config.auth_cache.read().unwrap().get(&wrong_hash).is_none(),
            "failed auth should not be cached"
        );
    }

    #[tokio::test]
    async fn test_validate_cached_ttl_disabled_skips_cache() {
        let hash = ShaCrypt::default()
            .hash_password("mypassword".as_bytes())
            .unwrap()
            .to_string();
        let mut config = AuthState::new();
        config
            .users
            .insert("admin".into(), Credential::Sha512Crypt(hash));
        config.auth_cache_ttl = Duration::ZERO;

        let creds = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "admin:mypassword",
        );
        let header_hash = hash_auth_header(&creds);

        assert!(
            config
                .validate_cached("admin", "mypassword", header_hash)
                .await
        );

        assert!(
            config
                .auth_cache
                .read()
                .unwrap()
                .get(&header_hash)
                .is_none(),
            "TTL=0 should not write to cache"
        );
    }
}
