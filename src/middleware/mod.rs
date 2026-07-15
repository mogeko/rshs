//! Tower middleware layers — authentication, lock enforcement, and health checks.

pub mod auth;
pub mod health;
pub mod lock;
pub mod tailscale;
