//! `amesh` binary entry point.
//!
//! Initializes tracing to stderr, parses the [`Cli`](agent_mesh_cli::Cli)
//! definition, then hands off to [`agent_mesh_cli::dispatch`].

use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let cli = agent_mesh_cli::Cli::parse();
    agent_mesh_cli::dispatch(cli).await
}
