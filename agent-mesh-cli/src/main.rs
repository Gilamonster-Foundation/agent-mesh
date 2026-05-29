//! `amesh` binary entry point — real implementation lands in a
//! later commit.

use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = agent_mesh_cli::Cli::parse();
    agent_mesh_cli::dispatch(cli).await
}
