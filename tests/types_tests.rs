use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use rshs::webdav::{Depth, IfCondition, IfList, LockInfo, LockScope, Method};
use rshs::{AuthState, ServerConfig, TailscaleAuthState, TlsConfig};

#[test]
fn test_server_config_new() {
    let config = ServerConfig::new(
        PathBuf::from("/tmp/test"),
        "127.0.0.1".into(),
        3000,
        None,
        AuthState::new(),
        TailscaleAuthState::new(),
        300,
    );
    assert_eq!(config.host, "127.0.0.1");
    assert_eq!(config.port, 3000);
    assert_eq!(config.root_dir, PathBuf::from("/tmp/test"));
}

#[test]
fn test_lock_info_is_expired() {
    let active = LockInfo {
        scope: LockScope::Exclusive,
        token: "t1".into(),
        owner: None,
        created: SystemTime::now(),
        timeout: Some(Duration::from_secs(3600)),
        depth: Depth::Zero,
    };
    assert!(!active.is_expired());

    let no_timeout = LockInfo {
        scope: LockScope::Exclusive,
        token: "t2".into(),
        owner: None,
        created: SystemTime::now(),
        timeout: None,
        depth: Depth::Zero,
    };
    assert!(!no_timeout.is_expired());

    let expired = LockInfo {
        scope: LockScope::Exclusive,
        token: "t3".into(),
        owner: None,
        created: SystemTime::now() - Duration::from_secs(10),
        timeout: Some(Duration::from_secs(1)),
        depth: Depth::Zero,
    };
    assert!(expired.is_expired());
}

#[test]
fn test_lock_info_is_exclusive() {
    let ex = LockInfo {
        scope: LockScope::Exclusive,
        token: "t".into(),
        owner: None,
        created: SystemTime::now(),
        timeout: None,
        depth: Depth::Zero,
    };
    assert!(ex.is_exclusive());

    let sh = LockInfo {
        scope: LockScope::Shared,
        token: "t".into(),
        owner: None,
        created: SystemTime::now(),
        timeout: None,
        depth: Depth::Zero,
    };
    assert!(!sh.is_exclusive());
}

#[test]
fn test_method_try_from_http_method() {
    let m = Method::try_from(&axum::http::Method::GET).unwrap();
    assert!(matches!(m, Method::GET));

    let m = Method::try_from(&axum::http::Method::from_bytes(b"PROPFIND").unwrap()).unwrap();
    assert!(matches!(m, Method::PROPFIND));

    let m = Method::try_from(&axum::http::Method::from_bytes(b"LOCK").unwrap()).unwrap();
    assert!(matches!(m, Method::LOCK));
}

#[test]
fn test_method_try_from_unknown_returns_err() {
    assert!(Method::try_from(&axum::http::Method::POST).is_err());
}

#[test]
fn test_depth_display() {
    assert_eq!(Depth::Zero.to_string(), "0");
    assert_eq!(Depth::One.to_string(), "1");
    assert_eq!(Depth::Infinity.to_string(), "infinity");
}

#[test]
fn test_iflist_positive_tokens() {
    let list = IfList {
        resource_tag: None,
        conditions: vec![
            IfCondition::StateToken("t1".into()),
            IfCondition::Not(Box::new(IfCondition::StateToken("t2".into()))),
            IfCondition::StateToken("t3".into()),
        ],
    };
    assert_eq!(list.positive_tokens(), vec!["t1", "t3"]);
}

#[test]
fn test_iflist_has_lock_token() {
    let no_lock = IfList {
        resource_tag: None,
        conditions: vec![IfCondition::StateToken("DAV:no-lock".into())],
    };
    assert!(!no_lock.has_lock_token());

    let has_token = IfList {
        resource_tag: None,
        conditions: vec![IfCondition::StateToken("opaquelocktoken:xyz".into())],
    };
    assert!(has_token.has_lock_token());
}

#[test]
fn test_tls_config_new() {
    let cfg = TlsConfig::new("cert.pem".into(), "key.pem".into());
    assert_eq!(cfg.cert_path, "cert.pem");
    assert_eq!(cfg.key_path, "key.pem");
}
