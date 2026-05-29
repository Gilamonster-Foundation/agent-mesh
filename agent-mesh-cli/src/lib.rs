//! `amesh` CLI library — argument definitions and dispatch.
//!
//! The binary at `src/main.rs` is a tiny wrapper around
//! [`Cli::parse`] + [`dispatch`]. Tests drive the same library via
//! `assert_cmd::Command::cargo_bin("amesh")`, so the surface area
//! tested matches the surface area shipped.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod announce;
mod bind;
mod keygen;
mod peers;
mod util;
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
    /// Announce this agent on the LAN via mDNS.
    Announce {
        /// Capabilities to advertise (repeatable, e.g.
        /// `--capability ollama --capability vllm`).
        #[arg(long = "capability")]
        capabilities: Vec<String>,
        /// Role to claim (defaults to `amesh-cli`).
        #[arg(long, default_value = "amesh-cli")]
        role: String,
        /// Host hint (defaults to the system hostname).
        #[arg(long)]
        host: Option<String>,
        /// How long to keep announcing, e.g. `30s`, `5m`. Defaults
        /// to forever (until Ctrl-C).
        #[arg(long)]
        duration: Option<String>,
    },
    /// List peers seen on the LAN via mDNS.
    Peers {
        /// How long to listen for peers before listing, e.g. `5s`.
        #[arg(long, default_value = "5s")]
        listen: String,
        /// Only show peers that match our user fingerprint.
        #[arg(long)]
        same_user: bool,
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
        Command::Announce {
            capabilities,
            role,
            host,
            duration,
        } => announce::run(home, capabilities, role, host, duration).await,
        Command::Peers { listen, same_user } => peers::run(home, listen, same_user).await,
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

    #[test]
    fn cli_parses_announce_with_capabilities() {
        let cli = Cli::try_parse_from([
            "amesh",
            "announce",
            "--capability",
            "ollama",
            "--capability",
            "vllm",
            "--role",
            "worker",
            "--host",
            "myhost",
            "--duration",
            "30s",
        ])
        .unwrap();
        match cli.command {
            Command::Announce {
                capabilities,
                role,
                host,
                duration,
            } => {
                assert_eq!(capabilities, vec!["ollama", "vllm"]);
                assert_eq!(role, "worker");
                assert_eq!(host.as_deref(), Some("myhost"));
                assert_eq!(duration.as_deref(), Some("30s"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn cli_parses_announce_with_defaults() {
        let cli = Cli::try_parse_from(["amesh", "announce"]).unwrap();
        match cli.command {
            Command::Announce {
                capabilities,
                role,
                host,
                duration,
            } => {
                assert!(capabilities.is_empty());
                assert_eq!(role, "amesh-cli");
                assert!(host.is_none());
                assert!(duration.is_none());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn cli_parses_peers_with_defaults() {
        let cli = Cli::try_parse_from(["amesh", "peers"]).unwrap();
        match cli.command {
            Command::Peers { listen, same_user } => {
                assert_eq!(listen, "5s");
                assert!(!same_user);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn cli_parses_peers_with_flags() {
        let cli =
            Cli::try_parse_from(["amesh", "peers", "--listen", "10s", "--same-user"]).unwrap();
        match cli.command {
            Command::Peers { listen, same_user } => {
                assert_eq!(listen, "10s");
                assert!(same_user);
            }
            _ => panic!("wrong variant"),
        }
    }
}
