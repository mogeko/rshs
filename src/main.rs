use std::io::{self, IsTerminal};
use std::path::PathBuf;

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cli = rshs::Cli::parse();

    let filter = EnvFilter::new(cli.log_level());

    let ansi = match std::env::var("RSHS_LOG_STYLE").as_deref() {
        Ok("always") => true,
        Ok("never") => false,
        _ => io::stderr().is_terminal(),
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(ansi)
        .with_writer(io::stderr)
        .init();

    let auth_state = rshs::build_auth_state(&cli);
    let tailscale_auth_state = cli.to_tailscale_auth_state();

    let port = cli.effective_port();
    let tls_config = cli.to_tls_config();
    let host = cli.host;
    let root_dir = PathBuf::from(cli.root_dir);

    rshs::start_server(rshs::ServerConfig::new(
        root_dir,
        host,
        port,
        tls_config,
        auth_state,
        tailscale_auth_state,
        cli.lock_timeout,
    ))
    .await
}
