//! `amesh` CLI library — implementation lands in a later commit.

use clap::Parser;

/// Stub CLI used to keep the workspace buildable while the scaffold
/// lands first. Replaced with the real argument tree in a follow-up
/// commit.
#[derive(Parser, Debug)]
#[command(name = "amesh", version)]
pub struct Cli {}

/// Stub dispatch — exits successfully without doing anything.
pub async fn dispatch(_cli: Cli) -> anyhow::Result<()> {
    Ok(())
}
