//! `amesh` CLI library — argument definitions and dispatch.
//!
//! The binary at `src/main.rs` is a tiny wrapper around
//! [`Cli::parse`] + [`dispatch`]. Tests drive the same library via
//! `assert_cmd::Command::cargo_bin("amesh")`, so the surface area
//! tested matches the surface area shipped.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod bind;
mod keygen;
mod verify;
mod whoami;

/// Top-level CLI definition. Each subcommand maps to a module above.
#[derive(Parser, Debug)]
#[command(name = "amesh", version, about = "agent-mesh CLI")]
pub struct Cli {
    /// Override the default config dir (`~/.agent-mesh`).
    #[arg(long, global = true, env = "AMESH_HOME")]
    pub home: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

/// All top-level subcommands.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Generate a new user key.
    Keygen {
        /// Path to write the key (defaults to `<home>/user.key`).
        #[arg(long)]
        path: Option<PathBuf>,
    },
    /// Bind your agent-mesh identity to an external key system.
    Bind {
        #[command(subcommand)]
        target: BindTarget,
    },
    /// Print the local user identity.
    Whoami,
    /// Verify a peer's GitHub binding by fetching their public keys.
    Verify {
        /// Path to the binding JSON file to verify.
        #[arg(long)]
        binding: PathBuf,
        /// GitHub username to fetch keys from.
        #[arg(long)]
        github_user: String,
    },
}

/// External key systems an agent-mesh identity can be bound to.
#[derive(Subcommand, Debug)]
pub enum BindTarget {
    /// Cross-sign with your GitHub SSH key.
    Github {
        /// Path to your SSH private key (defaults to `~/.ssh/id_ed25519`).
        #[arg(long)]
        ssh_key: Option<PathBuf>,
        /// GitHub username (stored as a hint; verification fetches
        /// from this name).
        #[arg(long)]
        username: Option<String>,
    },
}

/// Resolve `home` and dispatch to the matching subcommand handler.
pub async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    let home = cli.home.unwrap_or_else(default_home);
    match cli.command {
        Command::Keygen { path } => keygen::run(home, path),
        Command::Bind { target } => match target {
            BindTarget::Github { ssh_key, username } => bind::github(home, ssh_key, username),
        },
        Command::Whoami => whoami::run(home),
        Command::Verify {
            binding,
            github_user,
        } => verify::run(binding, github_user).await,
    }
}

/// Default config directory: `~/.agent-mesh`. Falls back to
/// `./.agent-mesh` if `$HOME` is unset (mostly for CI shells).
fn default_home() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".agent-mesh"))
        .unwrap_or_else(|| PathBuf::from(".agent-mesh"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_home_is_under_user_home_or_fallback() {
        let p = default_home();
        assert!(p.ends_with(".agent-mesh"));
    }

    #[test]
    fn cli_parses_keygen() {
        let cli = Cli::try_parse_from(["amesh", "keygen"]).unwrap();
        assert!(matches!(cli.command, Command::Keygen { path: None }));
    }

    #[test]
    fn cli_parses_keygen_with_path() {
        let cli = Cli::try_parse_from(["amesh", "keygen", "--path", "/tmp/k"]).unwrap();
        match cli.command {
            Command::Keygen { path: Some(p) } => assert_eq!(p, PathBuf::from("/tmp/k")),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn cli_parses_bind_github() {
        let cli = Cli::try_parse_from(["amesh", "bind", "github", "--username", "alice"]).unwrap();
        match cli.command {
            Command::Bind {
                target: BindTarget::Github { username, .. },
            } => {
                assert_eq!(username.as_deref(), Some("alice"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn cli_parses_whoami_with_home_override() {
        let cli = Cli::try_parse_from(["amesh", "--home", "/tmp/amh", "whoami"]).unwrap();
        assert_eq!(cli.home.as_deref(), Some(std::path::Path::new("/tmp/amh")));
        assert!(matches!(cli.command, Command::Whoami));
    }

    #[test]
    fn cli_parses_verify() {
        let cli = Cli::try_parse_from([
            "amesh",
            "verify",
            "--binding",
            "/tmp/b.json",
            "--github-user",
            "bob",
        ])
        .unwrap();
        match cli.command {
            Command::Verify {
                binding,
                github_user,
            } => {
                assert_eq!(binding, PathBuf::from("/tmp/b.json"));
                assert_eq!(github_user, "bob");
            }
            _ => panic!("wrong variant"),
        }
    }
}
